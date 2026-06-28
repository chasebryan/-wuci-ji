//! Wuci-Ji envelope bridge for the Daylight v0.6 research boundary.
//!
//! This module binds existing WJSEAL envelope bytes to the Daylight v0.6
//! written-code boundary. It does not decrypt, verify AEAD tags, accept keys,
//! or create production authority.

use daylight_model::{DaylightV06ClaimBoundary, DAYLIGHT_V06_8250_RESEARCH_BOUNDARY};
use sha2::{Digest, Sha256};
use sha3::Sha3_512;

const WJSEAL_V1_PREFIX: &[u8; 8] = b"WJSEAL\x01\x01";
const WJSEAL_V2_PREFIX: &[u8; 8] = b"WJSEAL\x02\x01";
const WJSEAL_V3_PREFIX: &[u8; 8] = b"WJSEAL\x03\x01";
const WJSEAL_PREFIX_LEN: usize = 8;
const WJSEAL_KEY_ID_LEN: usize = 16;
const WJSEAL_X25519_PUBLIC_LEN: usize = 32;
const WJSEAL_NONCE_LEN: usize = 12;
const WJSEAL_TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WuciEnvelopeVersion {
    V1,
    V2,
    V3,
}

impl WuciEnvelopeVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            WuciEnvelopeVersion::V1 => "WJSEAL-v1",
            WuciEnvelopeVersion::V2 => "WJSEAL-v2",
            WuciEnvelopeVersion::V3 => "WJSEAL-v3",
        }
    }

    pub const fn key_agreement(self) -> &'static str {
        match self {
            WuciEnvelopeVersion::V1 | WuciEnvelopeVersion::V2 => "pre-shared-symmetric-key",
            WuciEnvelopeVersion::V3 => "X25519-recipient-envelope",
        }
    }

    const fn header_len(self) -> usize {
        match self {
            WuciEnvelopeVersion::V1 => WJSEAL_PREFIX_LEN + WJSEAL_NONCE_LEN,
            WuciEnvelopeVersion::V2 => WJSEAL_PREFIX_LEN + WJSEAL_KEY_ID_LEN + WJSEAL_NONCE_LEN,
            WuciEnvelopeVersion::V3 => {
                WJSEAL_PREFIX_LEN + WJSEAL_X25519_PUBLIC_LEN + WJSEAL_KEY_ID_LEN + WJSEAL_NONCE_LEN
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WuciDaylightError {
    TruncatedEnvelope,
    UnknownEnvelopeVersion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WuciDaylightEnvelopeBoundary {
    pub schema: &'static str,
    pub envelope_version: WuciEnvelopeVersion,
    pub encryption_system: &'static str,
    pub aead_algorithm: &'static str,
    pub key_agreement: &'static str,
    pub envelope_len: usize,
    pub header_len: usize,
    pub ciphertext_len: usize,
    pub tag_len: usize,
    pub envelope_sha256: [u8; 32],
    pub envelope_sha3_512: [u8; 64],
    pub header_sha256: [u8; 32],
    pub ciphertext_sha256: [u8; 32],
    pub tag_sha256: [u8; 32],
    pub key_id: Option<[u8; WJSEAL_KEY_ID_LEN]>,
    pub ephemeral_public: Option<[u8; WJSEAL_X25519_PUBLIC_LEN]>,
    pub tag_verified: bool,
    pub daylight_authorized_state_required: bool,
    pub daylight_private_open_authorized: bool,
    pub wuci_gate_required_for_plaintext_release: bool,
    pub claim_boundary: DaylightV06ClaimBoundary,
}

impl WuciDaylightEnvelopeBoundary {
    pub fn zero_claims_hold(&self) -> bool {
        self.claim_boundary.zero_claims_hold()
            && !self.tag_verified
            && self.daylight_authorized_state_required
            && !self.daylight_private_open_authorized
            && self.wuci_gate_required_for_plaintext_release
    }
}

pub fn wuci_daylight_envelope_boundary(
    envelope: &[u8],
) -> Result<WuciDaylightEnvelopeBoundary, WuciDaylightError> {
    let version = classify_wjseal(envelope)?;
    let header_len = version.header_len();
    if envelope.len() < header_len + WJSEAL_TAG_LEN {
        return Err(WuciDaylightError::TruncatedEnvelope);
    }

    let header = &envelope[..header_len];
    let ciphertext = &envelope[header_len..envelope.len() - WJSEAL_TAG_LEN];
    let tag = &envelope[envelope.len() - WJSEAL_TAG_LEN..];
    let (key_id, ephemeral_public) = parse_public_header_fields(version, header);

    Ok(WuciDaylightEnvelopeBoundary {
        schema: "wuci-daylight-envelope-boundary-v1",
        envelope_version: version,
        encryption_system: "Wuci-Ji WJSEAL envelope under Daylight v0.6 research boundary",
        aead_algorithm: "ChaCha20-Poly1305",
        key_agreement: version.key_agreement(),
        envelope_len: envelope.len(),
        header_len,
        ciphertext_len: ciphertext.len(),
        tag_len: WJSEAL_TAG_LEN,
        envelope_sha256: sha256(envelope),
        envelope_sha3_512: sha3_512(envelope),
        header_sha256: sha256(header),
        ciphertext_sha256: sha256(ciphertext),
        tag_sha256: sha256(tag),
        key_id,
        ephemeral_public,
        tag_verified: false,
        daylight_authorized_state_required: true,
        daylight_private_open_authorized: false,
        wuci_gate_required_for_plaintext_release: true,
        claim_boundary: DAYLIGHT_V06_8250_RESEARCH_BOUNDARY,
    })
}

fn classify_wjseal(envelope: &[u8]) -> Result<WuciEnvelopeVersion, WuciDaylightError> {
    if envelope.len() < WJSEAL_PREFIX_LEN {
        return Err(WuciDaylightError::TruncatedEnvelope);
    }
    if envelope.starts_with(WJSEAL_V1_PREFIX) {
        return Ok(WuciEnvelopeVersion::V1);
    }
    if envelope.starts_with(WJSEAL_V2_PREFIX) {
        return Ok(WuciEnvelopeVersion::V2);
    }
    if envelope.starts_with(WJSEAL_V3_PREFIX) {
        return Ok(WuciEnvelopeVersion::V3);
    }
    Err(WuciDaylightError::UnknownEnvelopeVersion)
}

fn parse_public_header_fields(
    version: WuciEnvelopeVersion,
    header: &[u8],
) -> (
    Option<[u8; WJSEAL_KEY_ID_LEN]>,
    Option<[u8; WJSEAL_X25519_PUBLIC_LEN]>,
) {
    match version {
        WuciEnvelopeVersion::V1 => (None, None),
        WuciEnvelopeVersion::V2 => {
            let key_id_start = WJSEAL_PREFIX_LEN;
            let key_id_end = key_id_start + WJSEAL_KEY_ID_LEN;
            (Some(copy_array(&header[key_id_start..key_id_end])), None)
        }
        WuciEnvelopeVersion::V3 => {
            let public_start = WJSEAL_PREFIX_LEN;
            let public_end = public_start + WJSEAL_X25519_PUBLIC_LEN;
            let key_id_start = public_end;
            let key_id_end = key_id_start + WJSEAL_KEY_ID_LEN;
            (
                Some(copy_array(&header[key_id_start..key_id_end])),
                Some(copy_array(&header[public_start..public_end])),
            )
        }
    }
}

fn copy_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn sha3_512(bytes: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&Sha3_512::digest(bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(version: WuciEnvelopeVersion) -> Vec<u8> {
        let mut out = Vec::new();
        match version {
            WuciEnvelopeVersion::V1 => {
                out.extend_from_slice(WJSEAL_V1_PREFIX);
            }
            WuciEnvelopeVersion::V2 => {
                out.extend_from_slice(WJSEAL_V2_PREFIX);
                out.extend_from_slice(&[0x22; WJSEAL_KEY_ID_LEN]);
            }
            WuciEnvelopeVersion::V3 => {
                out.extend_from_slice(WJSEAL_V3_PREFIX);
                out.extend_from_slice(&[0x33; WJSEAL_X25519_PUBLIC_LEN]);
                out.extend_from_slice(&[0x44; WJSEAL_KEY_ID_LEN]);
            }
        }
        out.extend_from_slice(&[0x55; WJSEAL_NONCE_LEN]);
        out.extend_from_slice(b"ciphertext");
        out.extend_from_slice(&[0x66; WJSEAL_TAG_LEN]);
        out
    }

    #[test]
    fn wuci_daylight_bridge_accepts_wjseal_versions_without_private_open_claim() {
        for version in [
            WuciEnvelopeVersion::V1,
            WuciEnvelopeVersion::V2,
            WuciEnvelopeVersion::V3,
        ] {
            let boundary = wuci_daylight_envelope_boundary(&sample(version)).unwrap();
            assert_eq!(boundary.schema, "wuci-daylight-envelope-boundary-v1");
            assert_eq!(boundary.envelope_version, version);
            assert_eq!(boundary.aead_algorithm, "ChaCha20-Poly1305");
            assert_eq!(boundary.ciphertext_len, b"ciphertext".len());
            assert!(!boundary.tag_verified);
            assert!(!boundary.daylight_private_open_authorized);
            assert!(boundary.daylight_authorized_state_required);
            assert!(boundary.wuci_gate_required_for_plaintext_release);
            assert_eq!(boundary.claim_boundary.final_score(), 8250);
            assert!(boundary.zero_claims_hold());
        }
    }

    #[test]
    fn wuci_daylight_bridge_extracts_public_v2_v3_header_fields() {
        let v2 = wuci_daylight_envelope_boundary(&sample(WuciEnvelopeVersion::V2)).unwrap();
        assert_eq!(v2.key_id, Some([0x22; WJSEAL_KEY_ID_LEN]));
        assert_eq!(v2.ephemeral_public, None);

        let v3 = wuci_daylight_envelope_boundary(&sample(WuciEnvelopeVersion::V3)).unwrap();
        assert_eq!(v3.key_id, Some([0x44; WJSEAL_KEY_ID_LEN]));
        assert_eq!(v3.ephemeral_public, Some([0x33; WJSEAL_X25519_PUBLIC_LEN]));
    }

    #[test]
    fn wuci_daylight_bridge_rejects_bad_or_truncated_envelopes() {
        assert_eq!(
            wuci_daylight_envelope_boundary(b""),
            Err(WuciDaylightError::TruncatedEnvelope)
        );
        assert_eq!(
            wuci_daylight_envelope_boundary(b"WJSEAL\x09\x01"),
            Err(WuciDaylightError::UnknownEnvelopeVersion)
        );
        assert_eq!(
            wuci_daylight_envelope_boundary(WJSEAL_V1_PREFIX),
            Err(WuciDaylightError::TruncatedEnvelope)
        );
    }
}
