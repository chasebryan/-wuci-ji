use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process;

use wuci_penumbra::{
    inspect, open, seal, FileTranscriptVerifier, Mode, OpenRequest, SealRequest,
    DEFAULT_CANON_DESCRIPTOR,
};
use zeroize::{Zeroize, Zeroizing};

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("{message}");
            1
        }
    };
    process::exit(code);
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(usage());
    };
    let rest: Vec<String> = args.collect();
    match command.as_str() {
        "seal" => cmd_seal(&rest),
        "open" => cmd_open(&rest),
        "inspect" => cmd_inspect(&rest),
        "help" | "--help" | "-h" => Err(usage()),
        _ => Err(usage()),
    }
}

fn cmd_seal(args: &[String]) -> Result<(), String> {
    let opts = Options::parse(args)?;
    let policy = read_required(&opts, "--policy")?;
    let witness = read_required(&opts, "--witness")?;
    let plaintext = read_required(&opts, "--in")?;
    let out = path_required(&opts, "--out")?;
    let mode = match value_required(&opts, "--mode")?.as_str() {
        "secret" => Mode::SealedSecret,
        "public" => Mode::SealedPublic,
        _ => return Err("mode must be secret or public".to_string()),
    };
    let mut secret = match opts.value("--secret") {
        Some(path) => Some(Zeroizing::new(read_file(path)?)),
        None => None,
    };
    let asserted_entropy_bits = match opts.value("--asserted-entropy-bits") {
        Some(value) => Some(
            value
                .parse::<u16>()
                .map_err(|_| "asserted entropy bits must be a u16".to_string())?,
        ),
        None => None,
    };
    let secret_ref = secret.as_ref().map(|buf| buf.as_slice());
    let envelope = seal(
        &plaintext,
        SealRequest {
            policy: &policy,
            canon_descriptor: DEFAULT_CANON_DESCRIPTOR,
            mode,
            public_witness: &witness,
            secret_component: secret_ref,
            asserted_entropy_bits,
            seal_salt: None,
            nonce: None,
        },
        &FileTranscriptVerifier,
    )
    .map_err(|err| format!("seal refused: {err}"))?;
    write_new_file(&out, &envelope).map_err(|err| format!("write failed: {err}"))?;
    if let Some(secret) = secret.as_mut() {
        secret.zeroize();
    }
    Ok(())
}

fn cmd_open(args: &[String]) -> Result<(), String> {
    let opts = Options::parse(args)?;
    let envelope = read_required(&opts, "--in")?;
    let witness = read_required(&opts, "--witness")?;
    let out = path_required(&opts, "--out")?;
    let mut secret = match opts.value("--secret") {
        Some(path) => Some(Zeroizing::new(read_file(path)?)),
        None => None,
    };
    let secret_ref = secret.as_ref().map(|buf| buf.as_slice());
    let plaintext = open(
        OpenRequest {
            envelope: &envelope,
            public_witness: &witness,
            secret_component: secret_ref,
        },
        &FileTranscriptVerifier,
    )
    .map_err(|_| "open refused".to_string())?;
    write_new_file(&out, &plaintext).map_err(|_| "open refused".to_string())?;
    if let Some(secret) = secret.as_mut() {
        secret.zeroize();
    }
    Ok(())
}

fn cmd_inspect(args: &[String]) -> Result<(), String> {
    let opts = Options::parse(args)?;
    let envelope = read_required(&opts, "--in")?;
    let report = inspect(&envelope).map_err(|err| format!("inspect failed: {err}"))?;
    print!("{}", report.to_text());
    Ok(())
}

fn usage() -> String {
    [
        "usage:",
        "  penumbra seal --policy <file> --mode secret|public --witness <file> [--secret <file>] [--asserted-entropy-bits <n>] --in <plaintext> --out <envelope.wjseal>",
        "  penumbra open --witness <file> [--secret <file>] --in <envelope.wjseal> --out <plaintext>",
        "  penumbra inspect --in <envelope.wjseal>",
    ]
    .join("\n")
}

struct Options {
    pairs: Vec<(String, String)>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut pairs = Vec::new();
        let mut index = 0;
        while index < args.len() {
            let key = &args[index];
            if !key.starts_with("--") {
                return Err(usage());
            }
            let value = args.get(index + 1).ok_or_else(usage)?;
            if value.starts_with("--") {
                return Err(usage());
            }
            pairs.push((key.clone(), value.clone()));
            index += 2;
        }
        Ok(Self { pairs })
    }

    fn value(&self, key: &str) -> Option<String> {
        self.pairs
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.clone())
    }
}

fn value_required(opts: &Options, key: &str) -> Result<String, String> {
    opts.value(key).ok_or_else(usage)
}

fn path_required(opts: &Options, key: &str) -> Result<PathBuf, String> {
    value_required(opts, key).map(PathBuf::from)
}

fn read_required(opts: &Options, key: &str) -> Result<Vec<u8>, String> {
    let path = path_required(opts, key)?;
    read_file(path)
}

fn read_file(path: impl Into<PathBuf>) -> Result<Vec<u8>, String> {
    let path = path.into();
    reject_symlink_ancestors(&path)?;
    let before = fs::symlink_metadata(&path)
        .map_err(|err| format!("read {} failed: {err}", path.display()))?;
    if before.file_type().is_symlink() {
        return Err(format!("read {} failed: symlink rejected", path.display()));
    }
    if !before.is_file() {
        return Err(format!("read {} failed: not a regular file", path.display()));
    }
    if before.nlink() > 1 {
        return Err(format!("read {} failed: hardlink rejected", path.display()));
    }
    let mut file = fs::File::open(&path)
        .map_err(|err| format!("read {} failed: {err}", path.display()))?;
    let after = file
        .metadata()
        .map_err(|err| format!("read {} failed: {err}", path.display()))?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(format!("read {} failed: file changed while opening", path.display()));
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|err| format!("read {} failed: {err}", path.display()))?;
    Ok(data)
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let mut current = parent;
    while let Some(next) = current.parent() {
        if current.exists() {
            let metadata = fs::symlink_metadata(current)
                .map_err(|err| format!("inspect {} failed: {err}", current.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!("path parent symlink rejected: {}", current.display()));
            }
        }
        if current == next {
            break;
        }
        current = next;
    }
    Ok(())
}

fn write_new_file(path: &Path, data: &[u8]) -> Result<(), String> {
    reject_symlink_ancestors(path)?;
    if path.exists() || fs::symlink_metadata(path).is_ok() {
        return Err(format!("refusing to overwrite output: {}", path.display()));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    file.write_all(data)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("{}: {err}", path.display()))
}
