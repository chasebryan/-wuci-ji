#![forbid(unsafe_code)]

pub const AAD_DOMAIN: &str = "WUCIJI-ZP1-AAD-v1";

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn coupling_aad(
    artifact_sha256: &str,
    receipt_sha256: &str,
    gate_policy_sha256: &str,
) -> Result<Vec<u8>, &'static str> {
    if !is_lower_hex_64(artifact_sha256) {
        return Err("artifact_sha256 must be exactly 64 lowercase hex chars");
    }
    if !is_lower_hex_64(receipt_sha256) {
        return Err("receipt_sha256 must be exactly 64 lowercase hex chars");
    }
    if !is_lower_hex_64(gate_policy_sha256) {
        return Err("gate_policy_sha256 must be exactly 64 lowercase hex chars");
    }

    let aad = format!(
        "WUCIJI-ZP1-AAD-v1\n\
artifact_sha256={artifact_sha256}\n\
receipt_sha256={receipt_sha256}\n\
gate_policy_sha256={gate_policy_sha256}\n\
wuciji_claim_boundary=research_proof_not_production\n\
zp1_provider_boundary=test_utils_only_until_real_provider_reviewed\n"
    );

    Ok(aad.into_bytes())
}
