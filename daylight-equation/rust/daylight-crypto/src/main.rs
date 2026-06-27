use daylight_crypto::{
    daylight_hash, dhkem_p384_hkdf_sha384_decaps, dhkem_p384_hkdf_sha384_derive_keypair,
    dhkem_p384_hkdf_sha384_encaps_from_ikm, digest_vector, hex_lower, mldsa87_kat_fixture,
    mlkem1024_kat_fixture, primitive_statuses, slhdsa_shake_256s_kat_fixture, verify_mldsa87,
    verify_slhdsa_shake_256s, DAYLIGHT_AUTH_CONTEXT,
};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;

fn main() {
    if let Err(message) = run() {
        eprintln!("daylight-crypto: {message}");
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
        "status" => run_status(),
        "digest" => run_digest(&args),
        "dhkem-p384-selftest" => run_dhkem_p384_selftest(),
        "mlkem1024-selftest" => run_mlkem1024_selftest(),
        "mldsa87-verify" => run_mldsa87_verify(&args),
        "mldsa87-selftest" => run_mldsa87_selftest(),
        "slhdsa-shake-256s-selftest" => run_slhdsa_shake_256s_selftest(),
        "v4-reference-vector" => run_v4_reference_vector(),
        "v6-schema-vector" => run_v6_schema_vector(),
        "v6-provider-kem-evidence" => run_v6_provider_kem_evidence(),
        "v6-provider-private-roundtrip-evidence" => run_v6_provider_private_roundtrip_evidence(),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: daylight-crypto <status|digest|dhkem-p384-selftest|mlkem1024-selftest|mldsa87-verify|mldsa87-selftest|slhdsa-shake-256s-selftest|v4-reference-vector|v6-schema-vector|v6-provider-kem-evidence|v6-provider-private-roundtrip-evidence>".to_string()
}

fn run_status() -> Result<(), String> {
    for status in primitive_statuses() {
        let state = if status.implemented {
            "implemented"
        } else {
            "fail-closed"
        };
        println!("{state}: {} - {}", status.name, status.note);
    }
    Ok(())
}

fn run_digest(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(value_arg(args, "--file")?);
    let bytes = read_regular_file(&path)?;
    let vector = digest_vector(&bytes);
    let daylight = daylight_hash(&bytes).map_err(|err| format!("{err:?}"))?;
    println!("sha2-512: {}", hex_lower(&vector.sha2_512));
    println!("sha3-512: {}", hex_lower(&vector.sha3_512));
    println!("shake256-512: {}", hex_lower(&vector.shake256_512));
    println!("daylight-h-d: {}", hex_lower(&daylight));
    Ok(())
}

fn run_mldsa87_verify(args: &[String]) -> Result<(), String> {
    let public_key = read_regular_file(&PathBuf::from(value_arg(args, "--public-key")?))?;
    let message = read_regular_file(&PathBuf::from(value_arg(args, "--message")?))?;
    let signature = read_regular_file(&PathBuf::from(value_arg(args, "--signature")?))?;
    let context = optional_value_arg(args, "--context-file")
        .map(|path| read_regular_file(&PathBuf::from(path)))
        .transpose()?
        .unwrap_or_else(|| DAYLIGHT_AUTH_CONTEXT.to_vec());
    verify_mldsa87(&public_key, &message, &signature, &context)
        .map_err(|err| format!("{err:?}"))?;
    println!("mldsa87-verify: PASS");
    Ok(())
}

fn run_mlkem1024_selftest() -> Result<(), String> {
    let kat = mlkem1024_kat_fixture().map_err(|err| format!("{err:?}"))?;
    if kat.shared_secret
        != daylight_crypto::mlkem1024_decaps(&kat.decaps_key, &kat.ciphertext)
            .map_err(|err| format!("{err:?}"))?
    {
        return Err("ML-KEM-1024 KAT decapsulation mismatch".to_string());
    }
    println!("mlkem1024-selftest: PASS");
    Ok(())
}

fn run_dhkem_p384_selftest() -> Result<(), String> {
    let recipient =
        dhkem_p384_hkdf_sha384_derive_keypair(b"wuci daylight dhkem p384 recipient ikm v1")
            .map_err(|err| format!("{err:?}"))?;
    let encapsulation = dhkem_p384_hkdf_sha384_encaps_from_ikm(
        &recipient.public_key,
        b"wuci daylight dhkem p384 ephemeral ikm v1",
    )
    .map_err(|err| format!("{err:?}"))?;
    let decapped =
        dhkem_p384_hkdf_sha384_decaps(&recipient.private_key, &encapsulation.encapped_key)
            .map_err(|err| format!("{err:?}"))?;
    if decapped != encapsulation.shared_secret {
        return Err("DHKEM(P-384,HKDF-SHA384) shared secret mismatch".to_string());
    }
    let mut bad_encapped_key = encapsulation.encapped_key;
    bad_encapped_key[0] = 0x00;
    if dhkem_p384_hkdf_sha384_decaps(&recipient.private_key, &bad_encapped_key).is_ok() {
        return Err("bad DHKEM(P-384,HKDF-SHA384) encapsulated key accepted".to_string());
    }
    println!("dhkem-p384-selftest: PASS");
    Ok(())
}

fn run_mldsa87_selftest() -> Result<(), String> {
    let kat = mldsa87_kat_fixture().map_err(|err| format!("{err:?}"))?;
    verify_mldsa87(
        &kat.public_key,
        &kat.message,
        &kat.signature,
        DAYLIGHT_AUTH_CONTEXT,
    )
    .map_err(|err| format!("{err:?}"))?;
    let mut bad_signature = kat.signature;
    bad_signature[0] ^= 0x80;
    if verify_mldsa87(
        &kat.public_key,
        &kat.message,
        &bad_signature,
        DAYLIGHT_AUTH_CONTEXT,
    )
    .is_ok()
    {
        return Err("bad ML-DSA-87 KAT signature accepted".to_string());
    }
    println!("mldsa87-selftest: PASS");
    Ok(())
}

fn run_slhdsa_shake_256s_selftest() -> Result<(), String> {
    let kat = slhdsa_shake_256s_kat_fixture().map_err(|err| format!("{err:?}"))?;
    verify_slhdsa_shake_256s(
        &kat.public_key,
        &kat.message,
        &kat.signature,
        DAYLIGHT_AUTH_CONTEXT,
    )
    .map_err(|err| format!("{err:?}"))?;
    let mut bad_signature = kat.signature;
    bad_signature[0] ^= 0x80;
    if verify_slhdsa_shake_256s(
        &kat.public_key,
        &kat.message,
        &bad_signature,
        DAYLIGHT_AUTH_CONTEXT,
    )
    .is_ok()
    {
        return Err("bad SLH-DSA-SHAKE-256s KAT signature accepted".to_string());
    }
    println!("slhdsa-shake-256s-selftest: PASS");
    Ok(())
}

fn run_v4_reference_vector() -> Result<(), String> {
    let vector =
        daylight_crypto::daylight_v4_reference_vector().map_err(|err| format!("{err:?}"))?;
    let envelope_digest = digest_vector(&vector.envelope_bytes);
    let header_digest = digest_vector(&vector.header_bytes);
    let t0_digest = digest_vector(&vector.t0);
    let t1_digest = digest_vector(&vector.t1);
    let enc_q_digest = digest_vector(&vector.envelope.enc_q);
    println!("version=daylight-v4-reference-vector-v1");
    println!("artifact_hex={}", hex_lower(&vector.artifact));
    println!(
        "envelope_sha3_512_hex={}",
        hex_lower(&envelope_digest.sha3_512)
    );
    println!("envelope_hex={}", hex_lower(&vector.envelope_bytes));
    println!("header_sha3_512_hex={}", hex_lower(&header_digest.sha3_512));
    println!("header_hex={}", hex_lower(&vector.header_bytes));
    println!("t0_sha3_512_hex={}", hex_lower(&t0_digest.sha3_512));
    println!("t0_hex={}", hex_lower(&vector.t0));
    println!("t1_sha3_512_hex={}", hex_lower(&t1_digest.sha3_512));
    println!("t1_hex={}", hex_lower(&vector.t1));
    println!("auth_msg_hex={}", hex_lower(&vector.auth_msg));
    println!(
        "suite_id_hex={}",
        hex_lower(&vector.envelope.header.suite_id)
    );
    println!("enc_q_sha3_512_hex={}", hex_lower(&enc_q_digest.sha3_512));
    println!("enc_q_hex={}", hex_lower(&vector.envelope.enc_q));
    println!("enc_c_hex={}", hex_lower(&vector.envelope.enc_c));
    println!("ciphertext_hex={}", hex_lower(&vector.envelope.ciphertext));
    println!("commitment_hex={}", hex_lower(&vector.envelope.commitment));
    println!("record_index={}", vector.envelope.record_index);
    Ok(())
}

fn run_v6_schema_vector() -> Result<(), String> {
    let vector =
        daylight_crypto::v6::daylight_v6_schema_vector().map_err(|err| format!("{err:?}"))?;
    println!("version=daylight-v6-schema-vector-v1");
    println!("conformance_level=C1-OPEN");
    println!("expected_result=bottom");
    println!(
        "expected_rejection_stage={}",
        vector.expected_rejection_stage.as_str()
    );
    println!("private_kem_allowed={}", vector.private_kem_allowed);
    println!("aead_dec_allowed={}", vector.aead_dec_allowed);
    println!("omega_cbor_hex={}", hex_lower(&vector.omega));
    println!("header_cbor_hex={}", hex_lower(&vector.header_bytes));
    println!("kem_block_cbor_hex={}", hex_lower(&vector.kem_block_bytes));
    println!(
        "auth_block_cbor_hex={}",
        hex_lower(&vector.auth_block_bytes)
    );
    println!("aux_block_cbor_hex={}", hex_lower(&vector.aux_block_bytes));
    println!("T0_hex={}", hex_lower(&vector.transcript.t0));
    println!("h0_hex={}", hex_lower(&vector.transcript.h0));
    println!("kem_hash_hex={}", hex_lower(&vector.transcript.kem_hash));
    println!(
        "cipher_hash_hex={}",
        hex_lower(&vector.transcript.cipher_hash)
    );
    println!(
        "review_receipt_hash_hex={}",
        hex_lower(&vector.transcript.review_receipt_hash)
    );
    println!("T1_hex={}", hex_lower(&vector.transcript.t1));
    println!("h1_hex={}", hex_lower(&vector.transcript.h1));
    println!("AuthMsg_hex={}", hex_lower(&vector.transcript.auth_msg));
    Ok(())
}

fn run_v6_provider_kem_evidence() -> Result<(), String> {
    let evidence = daylight_crypto::v6::daylight_v6_provider_kem_evidence()
        .map_err(|err| format!("{err:?}"))?;
    println!("version=daylight-v6-provider-kem-evidence-v1");
    println!("profile=fixture-only-provider-kem");
    println!("expected_result=not_open");
    println!("provider_backed_kem={}", evidence.provider_backed_kem);
    println!(
        "provider_backed_reference_seal_open={}",
        evidence.provider_backed_reference_seal_open
    );
    println!("production_allowed={}", evidence.production_allowed);
    println!(
        "schema_expected_rejection_stage={}",
        evidence.schema_vector.expected_rejection_stage.as_str()
    );
    println!(
        "schema_private_kem_allowed={}",
        evidence.schema_vector.private_kem_allowed
    );
    println!(
        "schema_aead_dec_allowed={}",
        evidence.schema_vector.aead_dec_allowed
    );
    println!(
        "mlkem1024_decaps_matches={}",
        evidence.mlkem1024_decaps_matches
    );
    println!(
        "dhkem_p384_decaps_matches={}",
        evidence.dhkem_p384_decaps_matches
    );
    println!(
        "h0_hex={}",
        hex_lower(&evidence.schema_vector.transcript.h0)
    );
    println!(
        "kem_hash_hex={}",
        hex_lower(&evidence.schema_vector.transcript.kem_hash)
    );
    println!(
        "kem_context_sha3_512_hex={}",
        hex_lower(&evidence.kem_context_hash)
    );
    println!("ss_q_sha3_512_hex={}", hex_lower(&evidence.ss_q_hash));
    println!("ss_c_sha3_512_hex={}", hex_lower(&evidence.ss_c_hash));
    println!(
        "envelope_key_sha3_512_hex={}",
        hex_lower(&evidence.envelope_key_hash)
    );
    println!(
        "commitment_key_sha3_512_hex={}",
        hex_lower(&evidence.commitment_key_hash)
    );
    println!(
        "base_nonce_sha3_512_hex={}",
        hex_lower(&evidence.base_nonce_hash)
    );
    println!("enc_q_sha3_512_hex={}", hex_lower(&evidence.enc_q_hash));
    println!("enc_c_sha3_512_hex={}", hex_lower(&evidence.enc_c_hash));
    Ok(())
}

fn run_v6_provider_private_roundtrip_evidence() -> Result<(), String> {
    let evidence = daylight_crypto::v6::daylight_v6_provider_private_roundtrip_evidence()
        .map_err(|err| format!("{err:?}"))?;
    println!("version=daylight-v6-provider-private-roundtrip-evidence-v1");
    println!("profile=fixture-only-provider-private-roundtrip");
    println!("expected_result=private_roundtrip_only");
    println!(
        "provider_backed_private_roundtrip={}",
        evidence.provider_backed_private_roundtrip
    );
    println!(
        "provider_backed_reference_seal_open={}",
        evidence.provider_backed_reference_seal_open
    );
    println!("production_allowed={}", evidence.production_allowed);
    println!(
        "public_precheck_rejection_stage={}",
        evidence.public_precheck_rejection_stage.as_str()
    );
    println!(
        "opened_artifact_matches={}",
        evidence.opened_artifact_matches
    );
    println!("commitment_matches={}", evidence.commitment_matches);
    println!("aead_roundtrip_matches={}", evidence.aead_roundtrip_matches);
    println!(
        "artifact_sha3_512_hex={}",
        hex_lower(&evidence.artifact_hash)
    );
    println!(
        "opened_artifact_sha3_512_hex={}",
        hex_lower(&evidence.opened_artifact_hash)
    );
    println!(
        "private_payload_cbor_sha3_512_hex={}",
        hex_lower(&evidence.private_payload_hash)
    );
    println!(
        "ciphertext_sha3_512_hex={}",
        hex_lower(&evidence.ciphertext_hash)
    );
    println!("nonce_sha3_512_hex={}", hex_lower(&evidence.nonce_hash));
    println!("com_a_hex={}", hex_lower(&evidence.envelope.com_a));
    println!("com_a_sha3_512_hex={}", hex_lower(&evidence.com_a_hash));
    println!("h1_hex={}", hex_lower(&evidence.transcript.h1));
    println!("AuthMsg_hex={}", hex_lower(&evidence.transcript.auth_msg));
    Ok(())
}

fn value_arg(args: &[String], name: &str) -> Result<String, String> {
    optional_value_arg(args, name).ok_or_else(|| format!("missing {name}"))
}

fn optional_value_arg(args: &[String], name: &str) -> Option<String> {
    let index = args.iter().position(|value| value == name)?;
    args.get(index + 1)
        .filter(|value| !value.starts_with("--"))
        .cloned()
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|err| format!("{}: {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("refusing symlink input: {}", path.display()));
    }
    if !metadata.is_file() {
        return Err(format!("not a regular file: {}", path.display()));
    }
    if metadata.len() > MAX_READ_BYTES {
        return Err(format!(
            "input too large: {} has {} bytes, max is {}",
            path.display(),
            metadata.len(),
            MAX_READ_BYTES
        ));
    }
    fs::read(path).map_err(|err| format!("{}: {err}", path.display()))
}
