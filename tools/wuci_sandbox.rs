use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::raw::{c_int, c_long, c_ulong};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitCode};

const CLONE_NEWUTS: c_int = 0x0400_0000;
const CLONE_NEWIPC: c_int = 0x0800_0000;
const CLONE_NEWUSER: c_int = 0x1000_0000;
const CLONE_NEWNET: c_int = 0x4000_0000;
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_SET_SECCOMP: c_int = 22;
const SECCOMP_MODE_FILTER: c_ulong = 2;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const EPERM: u32 = 1;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;
const SYS_CLOSE: c_long = 3;
const SYS_SOCKET: u32 = 41;
const SYS_CONNECT: u32 = 42;
const SYS_ACCEPT: u32 = 43;
const SYS_SENDTO: u32 = 44;
const SYS_RECVFROM: u32 = 45;
const SYS_SENDMSG: u32 = 46;
const SYS_RECVMSG: u32 = 47;
const SYS_SHUTDOWN: u32 = 48;
const SYS_BIND: u32 = 49;
const SYS_LISTEN: u32 = 50;
const SYS_GETSOCKNAME: u32 = 51;
const SYS_GETPEERNAME: u32 = 52;
const SYS_SOCKETPAIR: u32 = 53;
const SYS_SETSOCKOPT: u32 = 54;
const SYS_GETSOCKOPT: u32 = 55;
const SYS_ACCEPT4: u32 = 288;
const SYS_RECVMMSG: u32 = 299;
const SYS_SENDMMSG: u32 = 307;
const SYS_CLOSE_RANGE: c_long = 436;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

extern "C" {
    fn getuid() -> u32;
    fn getgid() -> u32;
    fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn unshare(flags: c_int) -> c_int;
}

fn last_error(context: &str) -> String {
    format!("{context}: {}", io::Error::last_os_error())
}

fn syscall_ok(value: c_int, context: &str) -> Result<(), String> {
    if value == 0 {
        Ok(())
    } else {
        Err(last_error(context))
    }
}

fn write_proc(path: &str, value: &str) -> Result<(), String> {
    fs::write(path, value).map_err(|err| format!("{path}: {err}"))
}

fn deny_syscall(syscall_number: u32) -> [SockFilter; 2] {
    [
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: syscall_number,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | EPERM,
        },
    ]
}

fn install_network_seccomp_filter() -> Result<(), String> {
    let denied = [
        SYS_SOCKET,
        SYS_CONNECT,
        SYS_ACCEPT,
        SYS_SENDTO,
        SYS_RECVFROM,
        SYS_SENDMSG,
        SYS_RECVMSG,
        SYS_SHUTDOWN,
        SYS_BIND,
        SYS_LISTEN,
        SYS_GETSOCKNAME,
        SYS_GETPEERNAME,
        SYS_SOCKETPAIR,
        SYS_SETSOCKOPT,
        SYS_GETSOCKOPT,
        SYS_ACCEPT4,
        SYS_RECVMMSG,
        SYS_SENDMMSG,
    ];
    let mut filter = Vec::with_capacity(5 + denied.len() * 2);
    filter.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH,
    });
    filter.push(SockFilter {
        code: BPF_JMP_JEQ_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH_X86_64,
    });
    filter.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    filter.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR,
    });
    for syscall_number in denied {
        filter.extend_from_slice(&deny_syscall(syscall_number));
    }
    filter.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    let program = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };
    unsafe {
        syscall_ok(
            prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &program as *const SockFprog as c_ulong,
                0,
                0,
            ),
            "PR_SET_SECCOMP",
        )
    }
}

fn close_extra_fds() {
    unsafe {
        if syscall(SYS_CLOSE_RANGE, 3 as c_long, u32::MAX as c_long, 0 as c_long) == 0 {
            return;
        }
        for fd in 3..1024 {
            let _ = syscall(SYS_CLOSE, fd as c_long);
        }
    }
}

fn enter_no_network_namespace() -> Result<(), String> {
    unsafe {
        syscall_ok(
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
            "PR_SET_NO_NEW_PRIVS",
        )?;

        syscall_ok(unshare(CLONE_NEWUSER), "unshare(CLONE_NEWUSER)")?;

        let uid = getuid();
        let gid = getgid();
        let _ = write_proc("/proc/self/setgroups", "deny\n");
        write_proc("/proc/self/uid_map", &format!("0 {uid} 1\n"))?;
        write_proc("/proc/self/gid_map", &format!("0 {gid} 1\n"))?;

        syscall_ok(
            unshare(CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS),
            "unshare(CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS)",
        )?;
    }
    Ok(())
}

fn usage() -> String {
    "usage: wuci-sandbox --no-network -- <command> [args...]".to_string()
}

fn parse_args() -> Result<Vec<OsString>, String> {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    if args.len() < 3 {
        return Err(usage());
    }
    if args[0] != "--no-network" || args[1] != "--" {
        return Err("wuci-sandbox requires --no-network and a -- separator".to_string());
    }
    Ok(args[2..].to_vec())
}

fn run() -> Result<i32, String> {
    let command = parse_args()?;
    enter_no_network_namespace()?;
    close_extra_fds();
    install_network_seccomp_filter()?;
    let status = Command::new(&command[0])
        .args(&command[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .status()
        .map_err(|err| format!("exec failed: {err}"))?;
    if let Some(code) = status.code() {
        return Ok(code);
    }
    Ok(128 + status.signal().unwrap_or(0))
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from((code & 0xff) as u8),
        Err(err) => {
            eprintln!("wuci-sandbox: {err}");
            ExitCode::from(1)
        }
    }
}
