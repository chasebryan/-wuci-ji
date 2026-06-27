use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const IMPLEMENTATION_NAME: &str = "wuci-pq-fips204-verify";
const IMPLEMENTATION_VERSION: &str = "0.1.0-fips204-0.4.6-ml-dsa-65";
const KAT_KEY_SEED: [u8; 32] = [
    0x57, 0x55, 0x43, 0x49, 0x2d, 0x4d, 0x4c, 0x44, 0x53, 0x41, 0x2d, 0x36, 0x35, 0x2d, 0x4b, 0x45,
    0x59, 0x2d, 0x53, 0x45, 0x45, 0x44, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
];
const KAT_SIGN_SEED: [u8; 32] = [
    0x57, 0x55, 0x43, 0x49, 0x2d, 0x4d, 0x4c, 0x44, 0x53, 0x41, 0x2d, 0x36, 0x35, 0x2d, 0x53, 0x49,
    0x47, 0x2d, 0x53, 0x45, 0x45, 0x44, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
];
const KAT_MESSAGE: &[u8] = b"wuci fips204 ml-dsa-65 verifier kat v1\n";

fn main() {
    if let Err(message) = run() {
        eprintln!("wuci-pq-fips204-verify: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return Err(usage());
    }
    let command = args.remove(0);
    match command.as_str() {
        "verify" => run_verify(&args),
        "write-kat" => run_write_kat(&args),
        "selftest" => run_selftest(),
        "version" => {
            println!("{IMPLEMENTATION_NAME} {IMPLEMENTATION_VERSION}");
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: wuci-pq-fips204-verify verify --algorithm ML-DSA --public-key <file> --message <file> --signature <file>"
        .to_string()
}

fn value_arg(args: &[String], name: &str) -> Result<String, String> {
    let index = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("missing {name}"))?;
    args.get(index + 1)
        .filter(|value| !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn run_verify(args: &[String]) -> Result<(), String> {
    let algorithm = value_arg(args, "--algorithm")?;
    if algorithm != "ML-DSA" {
        return Err("only --algorithm ML-DSA is supported".to_string());
    }
    let public_key = fs::read(value_arg(args, "--public-key")?).map_err(|err| err.to_string())?;
    let message = fs::read(value_arg(args, "--message")?).map_err(|err| err.to_string())?;
    let signature = fs::read(value_arg(args, "--signature")?).map_err(|err| err.to_string())?;
    verify_mldsa65(&public_key, &message, &signature)
}

fn verify_mldsa65(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let public_key_array: [u8; ml_dsa_65::PK_LEN] = public_key
        .try_into()
        .map_err(|_| format!("ML-DSA-65 public key must be {} bytes", ml_dsa_65::PK_LEN))?;
    let signature_array: [u8; ml_dsa_65::SIG_LEN] = signature
        .try_into()
        .map_err(|_| format!("ML-DSA-65 signature must be {} bytes", ml_dsa_65::SIG_LEN))?;
    let public_key = ml_dsa_65::PublicKey::try_from_bytes(public_key_array)
        .map_err(|err| format!("invalid ML-DSA-65 public key: {err}"))?;
    if public_key.verify(message, &signature_array, &[]) {
        Ok(())
    } else {
        Err("ML-DSA-65 signature rejected".to_string())
    }
}

fn kat() -> Result<([u8; ml_dsa_65::PK_LEN], Vec<u8>, [u8; ml_dsa_65::SIG_LEN]), String> {
    let (public_key, private_key) = ml_dsa_65::KG::keygen_from_seed(&KAT_KEY_SEED);
    let signature = private_key
        .try_sign_with_seed(&KAT_SIGN_SEED, KAT_MESSAGE, &[])
        .map_err(|err| format!("could not sign KAT: {err}"))?;
    let public_key_bytes = public_key.clone().into_bytes();
    if !public_key.verify(KAT_MESSAGE, &signature, &[]) {
        return Err("generated KAT does not verify".to_string());
    }
    Ok((public_key_bytes, KAT_MESSAGE.to_vec(), signature))
}

fn run_write_kat(args: &[String]) -> Result<(), String> {
    let out_dir = PathBuf::from(value_arg(args, "--out-dir")?);
    fs::create_dir_all(&out_dir).map_err(|err| err.to_string())?;
    let (public_key, message, signature) = kat()?;
    write_new(&out_dir.join("mldsa65-public.key"), &public_key)?;
    write_new(&out_dir.join("mldsa65-message.bin"), &message)?;
    write_new(&out_dir.join("mldsa65-signature.bin"), &signature)?;
    println!("{}", out_dir.display());
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.exists() {
        return Err(format!("refusing to overwrite {}", path.display()));
    }
    fs::write(path, bytes).map_err(|err| err.to_string())
}

fn run_selftest() -> Result<(), String> {
    let (public_key, message, signature) = kat()?;
    verify_mldsa65(&public_key, &message, &signature)?;
    let mut bad_signature = signature;
    bad_signature[0] ^= 0x80;
    if verify_mldsa65(&public_key, &message, &bad_signature).is_ok() {
        return Err("bad KAT signature accepted".to_string());
    }
    println!("wuci-pq-fips204-verify selftest: PASS");
    Ok(())
}
