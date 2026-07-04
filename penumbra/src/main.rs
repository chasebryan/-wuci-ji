use std::env;
use std::fs;
use std::path::PathBuf;
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
    fs::write(out, envelope).map_err(|err| format!("write failed: {err}"))?;
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
    fs::write(out, plaintext).map_err(|_| "open refused".to_string())?;
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
    fs::read(&path).map_err(|err| format!("read {} failed: {err}", path.display()))
}
