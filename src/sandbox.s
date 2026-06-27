.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global run_sandbox_net_deny_probe
.global run_sandbox_seccomp_net_deny_selftest
.extern usage_exit
.extern write_all
.extern exit_process

run_sandbox_net_deny_probe:
    cmp qword ptr [rsp], 2
    jne usage_exit

    mov eax, SYS_SOCKET
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    syscall
    cmp rax, -1
    je .Lsandbox_net_probe_denied

    mov rdi, rax
    mov eax, SYS_CLOSE
    syscall

    mov rdi, STDERR
    lea rsi, [rip + sandbox_net_probe_fail_msg]
    mov edx, OFFSET FLAT:sandbox_net_probe_fail_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

.Lsandbox_net_probe_denied:
    mov rdi, STDOUT
    lea rsi, [rip + sandbox_net_probe_pass_msg]
    mov edx, OFFSET FLAT:sandbox_net_probe_pass_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

run_sandbox_seccomp_net_deny_selftest:
    cmp qword ptr [rsp], 2
    jne usage_exit

    mov eax, SYS_PRCTL
    mov edi, PR_SET_NO_NEW_PRIVS
    mov esi, 1
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    syscall
    test rax, rax
    jne .Lsandbox_seccomp_fail

    mov eax, SYS_PRCTL
    mov edi, PR_SET_SECCOMP
    mov esi, SECCOMP_MODE_FILTER
    lea rdx, [rip + sandbox_seccomp_fprog]
    xor r10d, r10d
    xor r8d, r8d
    syscall
    test rax, rax
    jne .Lsandbox_seccomp_fail

    mov eax, SYS_SOCKET
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    syscall
    cmp rax, -1
    je .Lsandbox_seccomp_pass

    test rax, rax
    js .Lsandbox_seccomp_fail
    mov rdi, rax
    mov eax, SYS_CLOSE
    syscall
    jmp .Lsandbox_seccomp_fail

.Lsandbox_seccomp_pass:
    mov rdi, STDOUT
    lea rsi, [rip + sandbox_seccomp_pass_msg]
    mov edx, OFFSET FLAT:sandbox_seccomp_pass_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

.Lsandbox_seccomp_fail:
    mov rdi, STDERR
    lea rsi, [rip + sandbox_seccomp_fail_msg]
    mov edx, OFFSET FLAT:sandbox_seccomp_fail_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

.section .rodata
sandbox_net_probe_pass_msg:
    .ascii "wuci sandbox net-deny probe: PASS\n"
.set sandbox_net_probe_pass_msg_len, . - sandbox_net_probe_pass_msg

sandbox_net_probe_fail_msg:
    .ascii "wuci sandbox net-deny probe: FAIL\n"
.set sandbox_net_probe_fail_msg_len, . - sandbox_net_probe_fail_msg

sandbox_seccomp_pass_msg:
    .ascii "wuci sandbox seccomp net-deny selftest: PASS\n"
.set sandbox_seccomp_pass_msg_len, . - sandbox_seccomp_pass_msg

sandbox_seccomp_fail_msg:
    .ascii "wuci sandbox seccomp net-deny selftest: FAIL\n"
.set sandbox_seccomp_fail_msg_len, . - sandbox_seccomp_fail_msg

.align 8
sandbox_seccomp_filter:
    .short 0x20
    .byte 0
    .byte 0
    .long 4
    .short 0x15
    .byte 1
    .byte 0
    .long 0xc000003e
    .short 0x06
    .byte 0
    .byte 0
    .long 0x80000000
    .short 0x20
    .byte 0
    .byte 0
    .long 0
    .short 0x15
    .byte 0
    .byte 1
    .long 41
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 42
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 43
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 44
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 45
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 46
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 47
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 48
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 49
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 50
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 51
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 52
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 53
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 54
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 55
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 288
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 299
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x15
    .byte 0
    .byte 1
    .long 307
    .short 0x06
    .byte 0
    .byte 0
    .long 0x00050001
    .short 0x06
    .byte 0
    .byte 0
    .long 0x7fff0000
.set sandbox_seccomp_filter_len, (. - sandbox_seccomp_filter) / 8

sandbox_seccomp_fprog:
    .short sandbox_seccomp_filter_len
    .zero 6
    .quad sandbox_seccomp_filter

.section .note.GNU-stack,"",@progbits
