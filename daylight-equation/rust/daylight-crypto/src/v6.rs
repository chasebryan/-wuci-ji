//! Daylight Envelope v0.5.1/2 byte-level hardening layer.
//!
//! This module implements the v6 schema, transcript, hash, KDF, and vector
//! surfaces needed for M1-style byte-level analysis. It deliberately does not
//! implement a successful production Open path. Certificate, revocation, log,
//! install, witness, and FROST authority are still absent, so public precheck
//! rejects before any private KEM or AEAD operation would be allowed.

use crate::{
    aead_open, aead_seal, derive_nonce, dhkem_p384_hkdf_sha384_decaps,
    dhkem_p384_hkdf_sha384_derive_keypair, dhkem_p384_hkdf_sha384_encaps_from_ikm,
    mldsa87_kat_fixture, mlkem1024_decaps, mlkem1024_encaps_from_seed, mlkem1024_kat_fixture,
    AeadAlgorithm, DaylightCryptoError, DaylightOpenFailure, DHKEM_P384_ENCAPSULATED_KEY_LEN,
    DHKEM_P384_PRIVATE_KEY_LEN, DHKEM_P384_PUBLIC_KEY_LEN, DHKEM_P384_SHARED_SECRET_LEN,
};
use daylight_model::{action_allowed, mode_ok, Action, Mode, Profile};
use fips203::ml_kem_1024;
use fips204::ml_dsa_87;
use fips205::slh_dsa_shake_256s;
use hkdf::Hkdf;
use sha2::Sha512;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_512, Shake256};

pub const DAYLIGHT_V6_MAGIC: &str = "DAYLIGHT-ENVELOPE-v6";
pub const DAYLIGHT_AUTH_CONTEXT_V6: &[u8] = b"WUCI-DAYLIGHT:AUTH:v6";
pub const DAYLIGHT_REVIEW_CONTEXT_V6: &[u8] = b"WUCI-DAYLIGHT:REVIEW:v6";
const DAYLIGHT_V6_SCHEMA_DHKEM_RECIPIENT_IKM: &[u8] = b"daylight v6 schema recipient";
const DAYLIGHT_V6_SCHEMA_DHKEM_EPHEMERAL_IKM: &[u8] = b"daylight v6 schema ephemeral";
const DAYLIGHT_V6_SCHEMA_ARTIFACT: &[u8] = b"daylight v6 schema vector artifact";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CborValue {
    UInt(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(u64, CborValue)>),
    Bool(bool),
    Null,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaylightContentScopeV6 {
    MetadataOnly,
    PublicCommitment,
    ReviewedContent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaylightLeakValueV6 {
    MetadataOnly {
        artifact_len: u64,
    },
    PublicCommitment {
        artifact_len: u64,
        artifact_hash: [u8; 64],
    },
    ReviewedContent {
        artifact_len: u64,
        review_commit: [u8; 64],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum DaylightConformanceLevelV6 {
    C1Open,
    C2Root,
    C3Audit,
    C4Install,
    C5Frost,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightHeaderV6 {
    pub version: u8,
    pub suite_id: [u8; 64],
    pub profile: Profile,
    pub release_level: u8,
    pub mode: Mode,
    pub action: Action,
    pub content_scope: DaylightContentScopeV6,
    pub leak_value: DaylightLeakValueV6,
    pub aead: AeadAlgorithm,
    pub policy_id: String,
    pub policy_hash: [u8; 64],
    pub keyset_hash: [u8; 64],
    pub prev_log_head: Option<[u8; 64]>,
    pub provenance_hash: [u8; 64],
    pub install_manifest_hash: [u8; 64],
    pub claims_hash: [u8; 64],
    pub key_epoch: u64,
    pub conformance_min: DaylightConformanceLevelV6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightKemBlockV6 {
    pub q_kem_key_id: [u8; 64],
    pub c_kem_key_id: [u8; 64],
    pub enc_q: Vec<u8>,
    pub enc_c: [u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightQSigV6 {
    pub key_id: [u8; 64],
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightFrostAuthV6 {
    pub sig_f: Vec<u8>,
    pub frost_transcript: CborValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightAuthBlockV6 {
    pub q_sigs: Vec<DaylightQSigV6>,
    pub h_sig: Option<Vec<u8>>,
    pub frost_auth: Option<DaylightFrostAuthV6>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightAuxBlockV6 {
    pub policy_obj: CborValue,
    pub keyset_obj: CborValue,
    pub claims_obj: CborValue,
    pub provenance_obj: Option<CborValue>,
    pub review_receipt: Option<CborValue>,
    pub log_proof: Option<CborValue>,
    pub install_manifest: Option<CborValue>,
    pub witness_evidence: Option<CborValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightEnvelopeV6 {
    pub header: DaylightHeaderV6,
    pub kem_block: DaylightKemBlockV6,
    pub ciphertext: Vec<u8>,
    pub com_a: [u8; 32],
    pub auth_block: DaylightAuthBlockV6,
    pub aux_block: DaylightAuxBlockV6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightTranscriptV6 {
    pub t0: Vec<u8>,
    pub h0: [u8; 64],
    pub kem_hash: [u8; 64],
    pub cipher_hash: [u8; 64],
    pub review_receipt_hash: [u8; 64],
    pub t1: Vec<u8>,
    pub h1: [u8; 64],
    pub auth_msg: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightKeyScheduleV6 {
    pub envelope_key: [u8; 32],
    pub commitment_key: [u8; 32],
    pub base_nonce: [u8; 12],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaylightRejectionStageV6 {
    RejectParse,
    RejectSchema,
    RejectSuite,
    RejectAuxHash,
    RejectPolicy,
    RejectClaims,
    RejectKemBlock,
    RejectAuthBlock,
    RejectAuthSignature,
    RejectReview,
    RejectDowngrade,
    RejectLog,
    RejectInstall,
    RejectWitness,
    RejectDecap,
    RejectAead,
    RejectPayload,
    RejectCommit,
    RejectLeak,
}

impl DaylightRejectionStageV6 {
    pub const fn as_str(self) -> &'static str {
        match self {
            DaylightRejectionStageV6::RejectParse => "REJECT_PARSE",
            DaylightRejectionStageV6::RejectSchema => "REJECT_SCHEMA",
            DaylightRejectionStageV6::RejectSuite => "REJECT_SUITE",
            DaylightRejectionStageV6::RejectAuxHash => "REJECT_AUX_HASH",
            DaylightRejectionStageV6::RejectPolicy => "REJECT_POLICY",
            DaylightRejectionStageV6::RejectClaims => "REJECT_CLAIMS",
            DaylightRejectionStageV6::RejectKemBlock => "REJECT_KEM_BLOCK",
            DaylightRejectionStageV6::RejectAuthBlock => "REJECT_AUTH_BLOCK",
            DaylightRejectionStageV6::RejectAuthSignature => "REJECT_AUTH_SIGNATURE",
            DaylightRejectionStageV6::RejectReview => "REJECT_REVIEW",
            DaylightRejectionStageV6::RejectDowngrade => "REJECT_DOWNGRADE",
            DaylightRejectionStageV6::RejectLog => "REJECT_LOG",
            DaylightRejectionStageV6::RejectInstall => "REJECT_INSTALL",
            DaylightRejectionStageV6::RejectWitness => "REJECT_WITNESS",
            DaylightRejectionStageV6::RejectDecap => "REJECT_DECAP",
            DaylightRejectionStageV6::RejectAead => "REJECT_AEAD",
            DaylightRejectionStageV6::RejectPayload => "REJECT_PAYLOAD",
            DaylightRejectionStageV6::RejectCommit => "REJECT_COMMIT",
            DaylightRejectionStageV6::RejectLeak => "REJECT_LEAK",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightPublicPrecheckV6 {
    pub envelope: DaylightEnvelopeV6,
    pub policy: DaylightPolicyV6,
    pub keyset: DaylightKeySetPubV6,
    pub claims: Vec<DaylightClaimV6>,
    pub transcript: DaylightTranscriptV6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightPolicyV6 {
    pub policy_id: String,
    pub allowed_profiles: Vec<Profile>,
    pub allowed_aeads: Vec<AeadAlgorithm>,
    pub allowed_actions: Vec<Action>,
    pub min_mode_by_action: Vec<(Action, (u8, Mode))>,
    pub allowed_keyset_hashes: Vec<[u8; 64]>,
    pub require_exact_content_approval: bool,
    pub require_provenance: bool,
    pub require_witness: bool,
    pub log_required_actions: Vec<Action>,
    pub allowed_claim_classes: Vec<u8>,
    pub expiry_epoch: Option<u64>,
    pub policy_version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightClaimV6 {
    pub claim_class: u8,
    pub claim_name: String,
    pub claim_value: CborValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightQRosterEntryV6 {
    pub key_id: [u8; 64],
    pub pk_q: Vec<u8>,
    pub domain_id: CborValue,
    pub cert_ref: CborValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightThresholdsV6 {
    pub t_q: u64,
    pub u_q: u64,
    pub t_f: u64,
    pub u_f: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightKeySetPubV6 {
    pub ek_q: Vec<u8>,
    pub pk_c: [u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    pub q_roster: Vec<DaylightQRosterEntryV6>,
    pub pk_h: Option<Vec<u8>>,
    pub frost_pub: Option<CborValue>,
    pub certificates: CborValue,
    pub revocation_state: CborValue,
    pub policy_keys: CborValue,
    pub thresholds: DaylightThresholdsV6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightSealKemInputsV6 {
    pub mlkem_encaps_seed: [u8; 32],
    pub dhkem_ephemeral_ikm: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightKemKeyIdsV6 {
    pub q_kem_key_id: [u8; 64],
    pub c_kem_key_id: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightRecipientPublicKeysV6 {
    pub mlkem_encaps_key: Vec<u8>,
    pub dhkem_public_key: [u8; DHKEM_P384_PUBLIC_KEY_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightRecipientSecretKeysV6 {
    pub mlkem_decaps_key: Vec<u8>,
    pub dhkem_private_key: [u8; DHKEM_P384_PRIVATE_KEY_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightReferencePrecheckV6 {
    pub parse_ok: bool,
    pub schema_ok: bool,
    pub suite_ok: bool,
    pub aux_hash_ok: bool,
    pub policy_ok: bool,
    pub claims_ok: bool,
    pub kem_block_ok: bool,
    pub auth_block_ok: bool,
    pub auth_signature_ok: bool,
    pub review_ok: bool,
    pub downgrade_ok: bool,
    pub log_ok: bool,
    pub install_ok: bool,
    pub witness_ok: bool,
    pub external_authority_ok: bool,
    pub production_allowed: bool,
}

impl DaylightReferencePrecheckV6 {
    pub const fn nonproduction_all_passed() -> Self {
        Self {
            parse_ok: true,
            schema_ok: true,
            suite_ok: true,
            aux_hash_ok: true,
            policy_ok: true,
            claims_ok: true,
            kem_block_ok: true,
            auth_block_ok: true,
            auth_signature_ok: true,
            review_ok: true,
            downgrade_ok: true,
            log_ok: true,
            install_ok: true,
            witness_ok: true,
            external_authority_ok: true,
            production_allowed: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightOpenReportV6 {
    pub artifact: Vec<u8>,
    pub transcript: DaylightTranscriptV6,
    pub auth_msg: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightPrivatePayloadV6 {
    pub artifact: Vec<u8>,
    pub review_blind: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightV6SchemaVector {
    pub envelope: DaylightEnvelopeV6,
    pub omega: Vec<u8>,
    pub header_bytes: Vec<u8>,
    pub kem_block_bytes: Vec<u8>,
    pub auth_block_bytes: Vec<u8>,
    pub aux_block_bytes: Vec<u8>,
    pub transcript: DaylightTranscriptV6,
    pub expected_rejection_stage: DaylightRejectionStageV6,
    pub private_kem_allowed: bool,
    pub aead_dec_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightV6ProviderKemEvidence {
    pub schema_vector: DaylightV6SchemaVector,
    pub kem_context: Vec<u8>,
    pub kem_context_hash: [u8; 64],
    pub key_schedule: DaylightKeyScheduleV6,
    pub ss_q_hash: [u8; 64],
    pub ss_c_hash: [u8; 64],
    pub envelope_key_hash: [u8; 64],
    pub commitment_key_hash: [u8; 64],
    pub base_nonce_hash: [u8; 64],
    pub enc_q_hash: [u8; 64],
    pub enc_c_hash: [u8; 64],
    pub mlkem1024_decaps_matches: bool,
    pub dhkem_p384_decaps_matches: bool,
    pub provider_backed_kem: bool,
    pub provider_backed_reference_seal_open: bool,
    pub production_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightV6ProviderPrivateRoundtripEvidence {
    pub envelope: DaylightEnvelopeV6,
    pub omega: Vec<u8>,
    pub transcript: DaylightTranscriptV6,
    pub artifact_hash: [u8; 64],
    pub private_payload_hash: [u8; 64],
    pub ciphertext_hash: [u8; 64],
    pub nonce_hash: [u8; 64],
    pub com_a_hash: [u8; 64],
    pub opened_artifact_hash: [u8; 64],
    pub opened_artifact_matches: bool,
    pub commitment_matches: bool,
    pub aead_roundtrip_matches: bool,
    pub public_precheck_rejection_stage: DaylightRejectionStageV6,
    pub provider_backed_private_roundtrip: bool,
    pub provider_backed_reference_seal_open: bool,
    pub production_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightV6ReferenceSealOpenEvidence {
    pub envelope: DaylightEnvelopeV6,
    pub omega: Vec<u8>,
    pub opened: DaylightOpenReportV6,
    pub artifact_hash: [u8; 64],
    pub opened_artifact_hash: [u8; 64],
    pub ciphertext_hash: [u8; 64],
    pub com_a_hash: [u8; 64],
    pub auth_msg_hash: [u8; 64],
    pub public_precheck_rejection_stage: DaylightRejectionStageV6,
    pub opened_artifact_matches: bool,
    pub provider_backed_reference_seal_open: bool,
    pub public_authority_external: bool,
    pub production_allowed: bool,
}

struct EnvelopePartsV6 {
    header: CborValue,
    kem_block: CborValue,
    ciphertext: Vec<u8>,
    com_a: [u8; 32],
    auth_block: CborValue,
    aux_block: CborValue,
}

pub fn encode_cbor_value(value: &CborValue) -> Result<Vec<u8>, DaylightCryptoError> {
    let mut output = Vec::new();
    append_cbor_value(value, &mut output)?;
    Ok(output)
}

pub fn decode_cbor_value(input: &[u8]) -> Result<CborValue, DaylightCryptoError> {
    let mut cursor = CborCursor { input, offset: 0 };
    let value = cursor.decode_value()?;
    if cursor.offset != input.len() {
        return Err(DaylightCryptoError::DecodeRejected("trailing CBOR data"));
    }
    if encode_cbor_value(&value)? != input {
        return Err(DaylightCryptoError::DecodeRejected("non-canonical CBOR"));
    }
    Ok(value)
}

pub fn hb_v6(bytes: &[u8]) -> [u8; 64] {
    Sha3_512::digest(bytes).into()
}

pub fn hb32_v6(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    shake256_v6(bytes, &mut output);
    output
}

pub fn hc_v6(value: &CborValue) -> Result<[u8; 64], DaylightCryptoError> {
    Ok(hb_v6(&encode_cbor_value(value)?))
}

pub fn hc32_v6(value: &CborValue) -> Result<[u8; 32], DaylightCryptoError> {
    Ok(hb32_v6(&encode_cbor_value(value)?))
}

pub fn null_hash_v6() -> Result<[u8; 64], DaylightCryptoError> {
    hc_v6(&CborValue::Null)
}

pub fn artifact_hash_v6(artifact: &[u8]) -> [u8; 64] {
    hb_v6(artifact)
}

pub fn daylight_suite_id_v6() -> Result<[u8; 64], DaylightCryptoError> {
    hc_v6(&CborValue::Array(vec![
        CborValue::Text("Deterministic-CBOR-Daylight-v6".to_string()),
        CborValue::Text("SHA3-512".to_string()),
        CborValue::Text("SHAKE256".to_string()),
        CborValue::Text("HKDF-SHA512".to_string()),
        CborValue::Text("ML-KEM-1024".to_string()),
        CborValue::Text("DHKEM-P384-HKDF-SHA384".to_string()),
        CborValue::Text("AEAD-AES-256-GCM-or-ChaCha20-Poly1305".to_string()),
        CborValue::Text("ML-DSA-87".to_string()),
        CborValue::Text("SLH-DSA-SHAKE-256s".to_string()),
        CborValue::Text("optional-FROST-ciphersuite".to_string()),
    ]))
}

pub fn kdf2_v6(
    secret: &[u8],
    label: &str,
    input: &CborValue,
    out_len: usize,
) -> Result<Vec<u8>, DaylightCryptoError> {
    ensure_ascii_label(label)?;
    let salt = hc_v6(&CborValue::Array(vec![
        CborValue::Text("daylight-kdf2-salt.v6".to_string()),
        CborValue::Text(label.to_string()),
    ]))?;
    let info = encode_cbor_value(&CborValue::Array(vec![
        CborValue::Text("daylight-kdf2-info.v6".to_string()),
        CborValue::Text(label.to_string()),
        input.clone(),
    ]))?;
    let (_, hkdf) = Hkdf::<Sha512>::extract(Some(&salt), secret);
    let mut output = vec![0u8; out_len];
    hkdf.expand(&info, &mut output)
        .map_err(|_| DaylightCryptoError::KdfRejected)?;
    Ok(output)
}

pub fn daylight_header_bytes_v6(header: &DaylightHeaderV6) -> Result<Vec<u8>, DaylightCryptoError> {
    encode_cbor_value(&header.to_cbor())
}

pub fn daylight_decode_header_v6(input: &[u8]) -> Result<DaylightHeaderV6, DaylightCryptoError> {
    DaylightHeaderV6::from_cbor(&decode_cbor_value(input)?)
}

pub fn daylight_kem_block_bytes_v6(
    kem_block: &DaylightKemBlockV6,
) -> Result<Vec<u8>, DaylightCryptoError> {
    encode_cbor_value(&kem_block.to_cbor())
}

pub fn daylight_auth_block_bytes_v6(
    auth_block: &DaylightAuthBlockV6,
) -> Result<Vec<u8>, DaylightCryptoError> {
    encode_cbor_value(&auth_block.to_cbor())
}

pub fn daylight_aux_block_bytes_v6(
    aux_block: &DaylightAuxBlockV6,
) -> Result<Vec<u8>, DaylightCryptoError> {
    encode_cbor_value(&aux_block.to_cbor())
}

pub fn daylight_envelope_bytes_v6(
    envelope: &DaylightEnvelopeV6,
) -> Result<Vec<u8>, DaylightCryptoError> {
    encode_cbor_value(&envelope.to_cbor())
}

pub fn daylight_decode_envelope_v6(
    input: &[u8],
) -> Result<DaylightEnvelopeV6, DaylightCryptoError> {
    DaylightEnvelopeV6::from_cbor(&decode_cbor_value(input)?)
}

pub fn daylight_t0_v6(header: &DaylightHeaderV6) -> Result<Vec<u8>, DaylightCryptoError> {
    encode_cbor_value(&CborValue::Array(vec![
        CborValue::Text("daylight.pre.v6".to_string()),
        header.to_cbor(),
    ]))
}

pub fn daylight_t1_v6(
    h0: &[u8; 64],
    kem_hash: &[u8; 64],
    cipher_hash: &[u8; 64],
    com_a: &[u8; 32],
    review_receipt_hash: &[u8; 64],
) -> Result<Vec<u8>, DaylightCryptoError> {
    encode_cbor_value(&CborValue::Array(vec![
        CborValue::Text("daylight.auth.transcript.v6".to_string()),
        CborValue::Bytes(h0.to_vec()),
        CborValue::Bytes(kem_hash.to_vec()),
        CborValue::Bytes(cipher_hash.to_vec()),
        CborValue::Bytes(com_a.to_vec()),
        CborValue::Bytes(review_receipt_hash.to_vec()),
    ]))
}

pub fn daylight_auth_msg_v6(h1: &[u8; 64]) -> Result<Vec<u8>, DaylightCryptoError> {
    encode_cbor_value(&CborValue::Array(vec![
        CborValue::Text("daylight.authorization.message.v6".to_string()),
        CborValue::Bytes(DAYLIGHT_AUTH_CONTEXT_V6.to_vec()),
        CborValue::Bytes(h1.to_vec()),
    ]))
}

pub fn daylight_transcript_v6(
    header: &DaylightHeaderV6,
    kem_block: &DaylightKemBlockV6,
    ciphertext: &[u8],
    com_a: &[u8; 32],
    review_receipt_hash: &[u8; 64],
) -> Result<DaylightTranscriptV6, DaylightCryptoError> {
    let t0 = daylight_t0_v6(header)?;
    let h0 = hb_v6(&t0);
    let kem_hash = hc_v6(&kem_block.to_cbor())?;
    let cipher_hash = hb_v6(ciphertext);
    let t1 = daylight_t1_v6(&h0, &kem_hash, &cipher_hash, com_a, review_receipt_hash)?;
    let h1 = hb_v6(&t1);
    let auth_msg = daylight_auth_msg_v6(&h1)?;
    Ok(DaylightTranscriptV6 {
        t0,
        h0,
        kem_hash,
        cipher_hash,
        review_receipt_hash: *review_receipt_hash,
        t1,
        h1,
        auth_msg,
    })
}

pub fn daylight_kem_context_v6(
    header: &DaylightHeaderV6,
    h0: &[u8; 64],
    kem_block: &DaylightKemBlockV6,
) -> Result<Vec<u8>, DaylightCryptoError> {
    encode_cbor_value(&CborValue::Array(vec![
        CborValue::Text("daylight.kem.context.v6".to_string()),
        CborValue::Bytes(header.suite_id.to_vec()),
        CborValue::UInt(profile_code(header.profile)),
        CborValue::Bytes(h0.to_vec()),
        CborValue::Bytes(header.keyset_hash.to_vec()),
        CborValue::Bytes(kem_block.q_kem_key_id.to_vec()),
        CborValue::Bytes(kem_block.c_kem_key_id.to_vec()),
        CborValue::Bytes(kem_block.enc_q.clone()),
        CborValue::Bytes(kem_block.enc_c.to_vec()),
    ]))
}

pub fn daylight_key_schedule_v6(
    ss_q: &[u8; 32],
    ss_c: &[u8; DHKEM_P384_SHARED_SECRET_LEN],
    kem_context: &[u8],
    h0: &[u8; 64],
    kem_hash: &[u8; 64],
    header: &DaylightHeaderV6,
    kem_block: &DaylightKemBlockV6,
) -> Result<DaylightKeyScheduleV6, DaylightCryptoError> {
    let salt = hc32_v6(&CborValue::Array(vec![
        CborValue::Text("daylight.kem.salt.v6".to_string()),
        CborValue::Bytes(header.suite_id.to_vec()),
        CborValue::Bytes(h0.to_vec()),
        CborValue::Bytes(header.keyset_hash.to_vec()),
        CborValue::Bytes(kem_block.q_kem_key_id.to_vec()),
        CborValue::Bytes(kem_block.c_kem_key_id.to_vec()),
    ]))?;
    let ikm = encode_cbor_value(&CborValue::Array(vec![
        CborValue::Text("daylight.hybrid.ikm.v6".to_string()),
        CborValue::Bytes(ss_q.to_vec()),
        CborValue::Bytes(ss_c.to_vec()),
        CborValue::Bytes(kem_context.to_vec()),
    ]))?;
    let (_, hkdf) = Hkdf::<Sha512>::extract(Some(&salt), &ikm);
    let info = encode_cbor_value(&CborValue::Array(vec![
        CborValue::Text("daylight.key.schedule.v6".to_string()),
        CborValue::Bytes(h0.to_vec()),
        CborValue::Bytes(kem_hash.to_vec()),
        CborValue::Bytes(header.suite_id.to_vec()),
        CborValue::UInt(profile_code(header.profile)),
        CborValue::UInt(mode_code(header.mode)),
        CborValue::UInt(aead_code(header.aead)),
    ]))?;
    let mut okm = [0u8; 76];
    hkdf.expand(&info, &mut okm)
        .map_err(|_| DaylightCryptoError::KdfRejected)?;
    Ok(DaylightKeyScheduleV6 {
        envelope_key: fixed_decode(&okm[0..32])?,
        commitment_key: fixed_decode(&okm[32..64])?,
        base_nonce: fixed_decode(&okm[64..76])?,
    })
}

pub fn daylight_review_commit_v6(
    review_blind: &[u8; 32],
    artifact: &[u8],
    policy_hash: &[u8; 64],
    claims_hash: &[u8; 64],
) -> Result<[u8; 64], DaylightCryptoError> {
    let artifact_len =
        u64::try_from(artifact.len()).map_err(|_| DaylightCryptoError::EncodingTooLarge)?;
    let encoded = encode_cbor_value(&CborValue::Array(vec![
        CborValue::Text("daylight.review.hidden.v6".to_string()),
        CborValue::Bytes(review_blind.to_vec()),
        CborValue::UInt(artifact_len),
        CborValue::Bytes(artifact_hash_v6(artifact).to_vec()),
        CborValue::Bytes(policy_hash.to_vec()),
        CborValue::Bytes(claims_hash.to_vec()),
    ]))?;
    Ok(hb_v6(&encoded))
}

pub fn daylight_vector_public_precheck_v6(
    omega: &[u8],
    now_epoch: Option<u64>,
) -> Result<DaylightPublicPrecheckV6, DaylightRejectionStageV6> {
    let value = decode_cbor_value(omega).map_err(|_| DaylightRejectionStageV6::RejectParse)?;
    let parts =
        EnvelopePartsV6::from_cbor(&value).map_err(|_| DaylightRejectionStageV6::RejectSchema)?;
    let header = DaylightHeaderV6::from_cbor(&parts.header)
        .map_err(|_| DaylightRejectionStageV6::RejectSchema)?;
    check_suite_v6(&header)?;
    let aux_block = DaylightAuxBlockV6::from_cbor(&parts.aux_block)
        .map_err(|_| DaylightRejectionStageV6::RejectSchema)?;
    check_aux_hashes_v6(&header, &aux_block)?;
    let policy = DaylightPolicyV6::from_cbor(&aux_block.policy_obj)
        .map_err(|_| DaylightRejectionStageV6::RejectPolicy)?;
    let keyset = DaylightKeySetPubV6::from_cbor(&aux_block.keyset_obj)
        .map_err(|_| DaylightRejectionStageV6::RejectKemBlock)?;
    let claims = decode_claims_v6(&aux_block.claims_obj)
        .map_err(|_| DaylightRejectionStageV6::RejectClaims)?;
    check_static_policy_gate_v6(&header, &aux_block, &policy, &claims, now_epoch)?;
    let kem_block = DaylightKemBlockV6::from_cbor(&parts.kem_block)
        .map_err(|_| DaylightRejectionStageV6::RejectKemBlock)?;
    check_kem_block_public_shape_v6(&kem_block, &keyset)?;
    let review_receipt_hash = aux_block
        .review_receipt_hash()
        .map_err(|_| DaylightRejectionStageV6::RejectAuxHash)?;
    let transcript = daylight_transcript_v6(
        &header,
        &kem_block,
        &parts.ciphertext,
        &parts.com_a,
        &review_receipt_hash,
    )
    .map_err(|_| DaylightRejectionStageV6::RejectSchema)?;
    let auth_block = DaylightAuthBlockV6::from_cbor(&parts.auth_block)
        .map_err(|_| DaylightRejectionStageV6::RejectAuthBlock)?;
    check_auth_block_shape_v6(&auth_block, header.profile)
        .map_err(|_| DaylightRejectionStageV6::RejectAuthBlock)?;

    let envelope = DaylightEnvelopeV6 {
        header,
        kem_block,
        ciphertext: parts.ciphertext,
        com_a: parts.com_a,
        auth_block,
        aux_block,
    };

    // CertOK and Revoked are intentionally undefined in this M1 hardening
    // layer. Per v0.6, KeyLive then evaluates to 0, so authorization fails
    // before private KEM decapsulation or AEAD can run.
    let _ = (envelope, policy, keyset, claims, transcript);
    Err(DaylightRejectionStageV6::RejectAuthSignature)
}

pub fn daylight_v6_schema_vector() -> Result<DaylightV6SchemaVector, DaylightCryptoError> {
    let artifact = DAYLIGHT_V6_SCHEMA_ARTIFACT;
    let mlkem = mlkem1024_kat_fixture()?;
    let dhkem_recipient =
        dhkem_p384_hkdf_sha384_derive_keypair(DAYLIGHT_V6_SCHEMA_DHKEM_RECIPIENT_IKM)?;
    let dhkem_enc = dhkem_p384_hkdf_sha384_encaps_from_ikm(
        &dhkem_recipient.public_key,
        DAYLIGHT_V6_SCHEMA_DHKEM_EPHEMERAL_IKM,
    )?;
    let mldsa = mldsa87_kat_fixture()?;
    let domain_id = CborValue::Text("domain-a".to_string());
    let q_roster_key_id = daylight_roster_key_id_v6("ML-DSA-87", &mldsa.public_key, &domain_id)?;
    let q_kem_key_id = daylight_kem_key_id_v6("ML-KEM-1024", &mlkem.encaps_key)?;
    let c_kem_key_id =
        daylight_kem_key_id_v6("DHKEM-P384-HKDF-SHA384", &dhkem_recipient.public_key)?;

    let keyset = DaylightKeySetPubV6 {
        ek_q: mlkem.encaps_key.clone(),
        pk_c: dhkem_recipient.public_key,
        q_roster: vec![DaylightQRosterEntryV6 {
            key_id: q_roster_key_id,
            pk_q: mldsa.public_key.clone(),
            domain_id,
            cert_ref: CborValue::Text("cert-fixture-only".to_string()),
        }],
        pk_h: None,
        frost_pub: None,
        certificates: CborValue::Array(vec![]),
        revocation_state: CborValue::Array(vec![]),
        policy_keys: CborValue::Array(vec![]),
        thresholds: DaylightThresholdsV6 {
            t_q: 1,
            u_q: 1,
            t_f: 0,
            u_f: 0,
        },
    };
    let keyset_obj = keyset.to_cbor();
    let keyset_hash = hc_v6(&keyset_obj)?;
    let claims_obj = CborValue::Array(vec![
        claim_value_v6(
            0,
            "research-note",
            CborValue::Text("research_draft".to_string()),
        ),
        claim_value_v6(1, "schema-freeze", CborValue::Bool(false)),
    ]);
    let claims_hash = hc_v6(&claims_obj)?;
    let null_hash = null_hash_v6()?;
    let policy = DaylightPolicyV6 {
        policy_id: "daylight-v6-c1-policy".to_string(),
        allowed_profiles: vec![Profile::D2Hybrid],
        allowed_aeads: vec![AeadAlgorithm::Aes256Gcm, AeadAlgorithm::ChaCha20Poly1305],
        allowed_actions: vec![Action::Research, Action::Proof, Action::Open],
        min_mode_by_action: vec![(Action::Open, (1, Mode::Hybrid))],
        allowed_keyset_hashes: vec![keyset_hash],
        require_exact_content_approval: false,
        require_provenance: false,
        require_witness: false,
        log_required_actions: vec![],
        allowed_claim_classes: vec![0, 1, 2],
        expiry_epoch: None,
        policy_version: 6,
    };
    let policy_obj = policy.to_cbor();
    let policy_hash = hc_v6(&policy_obj)?;
    let header = DaylightHeaderV6 {
        version: 6,
        suite_id: daylight_suite_id_v6()?,
        profile: Profile::D2Hybrid,
        release_level: 1,
        mode: Mode::Hybrid,
        action: Action::Open,
        content_scope: DaylightContentScopeV6::MetadataOnly,
        leak_value: DaylightLeakValueV6::MetadataOnly {
            artifact_len: artifact.len() as u64,
        },
        aead: AeadAlgorithm::Aes256Gcm,
        policy_id: policy.policy_id.clone(),
        policy_hash,
        keyset_hash,
        prev_log_head: None,
        provenance_hash: null_hash,
        install_manifest_hash: null_hash,
        claims_hash,
        key_epoch: 1,
        conformance_min: DaylightConformanceLevelV6::C1Open,
    };
    let kem_block = DaylightKemBlockV6 {
        q_kem_key_id,
        c_kem_key_id,
        enc_q: mlkem.ciphertext,
        enc_c: dhkem_enc.encapped_key,
    };
    let auth_block = DaylightAuthBlockV6 {
        q_sigs: vec![DaylightQSigV6 {
            key_id: q_roster_key_id,
            sig: mldsa.signature,
        }],
        h_sig: None,
        frost_auth: None,
    };
    let aux_block = DaylightAuxBlockV6 {
        policy_obj,
        keyset_obj,
        claims_obj,
        provenance_obj: None,
        review_receipt: None,
        log_proof: None,
        install_manifest: None,
        witness_evidence: None,
    };
    let ciphertext = b"not-aead-opened-in-v6-schema-vector".to_vec();
    let com_a = [0x6au8; 32];
    let review_receipt_hash = aux_block.review_receipt_hash()?;
    let transcript = daylight_transcript_v6(
        &header,
        &kem_block,
        &ciphertext,
        &com_a,
        &review_receipt_hash,
    )?;
    let envelope = DaylightEnvelopeV6 {
        header,
        kem_block,
        ciphertext,
        com_a,
        auth_block,
        aux_block,
    };
    let omega = daylight_envelope_bytes_v6(&envelope)?;
    Ok(DaylightV6SchemaVector {
        header_bytes: daylight_header_bytes_v6(&envelope.header)?,
        kem_block_bytes: daylight_kem_block_bytes_v6(&envelope.kem_block)?,
        auth_block_bytes: daylight_auth_block_bytes_v6(&envelope.auth_block)?,
        aux_block_bytes: daylight_aux_block_bytes_v6(&envelope.aux_block)?,
        envelope,
        omega,
        transcript,
        expected_rejection_stage: DaylightRejectionStageV6::RejectAuthSignature,
        private_kem_allowed: false,
        aead_dec_allowed: false,
    })
}

pub fn daylight_v6_provider_kem_evidence(
) -> Result<DaylightV6ProviderKemEvidence, DaylightCryptoError> {
    let schema_vector = daylight_v6_schema_vector()?;
    let mlkem = mlkem1024_kat_fixture()?;
    let dhkem_recipient =
        dhkem_p384_hkdf_sha384_derive_keypair(DAYLIGHT_V6_SCHEMA_DHKEM_RECIPIENT_IKM)?;
    let dhkem_enc = dhkem_p384_hkdf_sha384_encaps_from_ikm(
        &dhkem_recipient.public_key,
        DAYLIGHT_V6_SCHEMA_DHKEM_EPHEMERAL_IKM,
    )?;

    if schema_vector.envelope.kem_block.enc_q != mlkem.ciphertext
        || schema_vector.envelope.kem_block.enc_c != dhkem_enc.encapped_key
    {
        return Err(DaylightCryptoError::DecodeRejected(
            "schema vector KEM material mismatch",
        ));
    }

    let ss_q = mlkem1024_decaps(&mlkem.decaps_key, &schema_vector.envelope.kem_block.enc_q)?;
    let ss_c = dhkem_p384_hkdf_sha384_decaps(
        &dhkem_recipient.private_key,
        &schema_vector.envelope.kem_block.enc_c,
    )?;
    let mlkem1024_decaps_matches = ss_q == mlkem.shared_secret;
    let dhkem_p384_decaps_matches = ss_c == dhkem_enc.shared_secret;
    if !mlkem1024_decaps_matches || !dhkem_p384_decaps_matches {
        return Err(DaylightCryptoError::DecapsulationFailed);
    }

    let kem_context = daylight_kem_context_v6(
        &schema_vector.envelope.header,
        &schema_vector.transcript.h0,
        &schema_vector.envelope.kem_block,
    )?;
    let key_schedule = daylight_key_schedule_v6(
        &ss_q,
        &ss_c,
        &kem_context,
        &schema_vector.transcript.h0,
        &schema_vector.transcript.kem_hash,
        &schema_vector.envelope.header,
        &schema_vector.envelope.kem_block,
    )?;

    Ok(DaylightV6ProviderKemEvidence {
        kem_context_hash: hb_v6(&kem_context),
        ss_q_hash: hb_v6(&ss_q),
        ss_c_hash: hb_v6(&ss_c),
        envelope_key_hash: hb_v6(&key_schedule.envelope_key),
        commitment_key_hash: hb_v6(&key_schedule.commitment_key),
        base_nonce_hash: hb_v6(&key_schedule.base_nonce),
        enc_q_hash: hb_v6(&schema_vector.envelope.kem_block.enc_q),
        enc_c_hash: hb_v6(&schema_vector.envelope.kem_block.enc_c),
        schema_vector,
        kem_context,
        key_schedule,
        mlkem1024_decaps_matches,
        dhkem_p384_decaps_matches,
        provider_backed_kem: true,
        provider_backed_reference_seal_open: false,
        production_allowed: false,
    })
}

pub fn daylight_seal_v6_with_kems_from_seed(
    header: DaylightHeaderV6,
    auth_block: DaylightAuthBlockV6,
    aux_block: DaylightAuxBlockV6,
    kem_key_ids: DaylightKemKeyIdsV6,
    recipient_keys: &DaylightRecipientPublicKeysV6,
    kem_inputs: &DaylightSealKemInputsV6,
    artifact: &[u8],
    review_blind: Option<&[u8; 32]>,
) -> Result<DaylightEnvelopeV6, DaylightCryptoError> {
    let (ss_q, enc_q) = mlkem1024_encaps_from_seed(
        &recipient_keys.mlkem_encaps_key,
        &kem_inputs.mlkem_encaps_seed,
    )?;
    let dhkem = dhkem_p384_hkdf_sha384_encaps_from_ikm(
        &recipient_keys.dhkem_public_key,
        &kem_inputs.dhkem_ephemeral_ikm,
    )?;
    let kem_block = DaylightKemBlockV6 {
        q_kem_key_id: kem_key_ids.q_kem_key_id,
        c_kem_key_id: kem_key_ids.c_kem_key_id,
        enc_q,
        enc_c: dhkem.encapped_key,
    };
    let t0 = daylight_t0_v6(&header)?;
    let h0 = hb_v6(&t0);
    let kem_hash = hc_v6(&kem_block.to_cbor())?;
    let kem_context = daylight_kem_context_v6(&header, &h0, &kem_block)?;
    let key_schedule = daylight_key_schedule_v6(
        &ss_q,
        &dhkem.shared_secret,
        &kem_context,
        &h0,
        &kem_hash,
        &header,
        &kem_block,
    )?;
    let private_payload = daylight_private_payload_bytes_v6(artifact, review_blind)?;
    let nonce = derive_nonce(&key_schedule.base_nonce, 0)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Nonce))?;
    let ciphertext = aead_seal(
        header.aead,
        &key_schedule.envelope_key,
        &nonce,
        &t0,
        &private_payload,
    )
    .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Aead))?;
    let com_a = daylight_artifact_commitment_v6(
        &key_schedule.commitment_key,
        &h0,
        &ciphertext,
        artifact,
        &header.leak_value,
    )?;
    Ok(DaylightEnvelopeV6 {
        header,
        kem_block,
        ciphertext,
        com_a,
        auth_block,
        aux_block,
    })
}

pub fn daylight_open_v6_with_kems(
    envelope: &DaylightEnvelopeV6,
    recipient_keys: &DaylightRecipientSecretKeysV6,
    precheck: &DaylightReferencePrecheckV6,
    now_epoch: Option<u64>,
) -> Result<DaylightOpenReportV6, DaylightCryptoError> {
    let transcript = daylight_reference_precheck_v6(envelope, precheck, now_epoch)?;
    let ss_q = mlkem1024_decaps(&recipient_keys.mlkem_decaps_key, &envelope.kem_block.enc_q)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Derive))?;
    let ss_c =
        dhkem_p384_hkdf_sha384_decaps(&recipient_keys.dhkem_private_key, &envelope.kem_block.enc_c)
            .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Derive))?;
    let kem_context =
        daylight_kem_context_v6(&envelope.header, &transcript.h0, &envelope.kem_block)
            .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Derive))?;
    let key_schedule = daylight_key_schedule_v6(
        &ss_q,
        &ss_c,
        &kem_context,
        &transcript.h0,
        &transcript.kem_hash,
        &envelope.header,
        &envelope.kem_block,
    )
    .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Derive))?;
    let nonce = derive_nonce(&key_schedule.base_nonce, 0)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Nonce))?;
    let opened_payload = aead_open(
        envelope.header.aead,
        &key_schedule.envelope_key,
        &nonce,
        &transcript.t0,
        &envelope.ciphertext,
    )
    .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Aead))?;
    let payload = daylight_private_payload_v6(&opened_payload)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Aead))?;
    let expected_com_a = daylight_artifact_commitment_v6(
        &key_schedule.commitment_key,
        &transcript.h0,
        &envelope.ciphertext,
        &payload.artifact,
        &envelope.header.leak_value,
    )?;
    if expected_com_a != envelope.com_a {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Commit,
        ));
    }
    if !daylight_private_leak_ok_v6(&envelope.header, &payload)? {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Leak));
    }
    Ok(DaylightOpenReportV6 {
        artifact: payload.artifact,
        auth_msg: transcript.auth_msg.clone(),
        transcript,
    })
}

fn daylight_reference_precheck_v6(
    envelope: &DaylightEnvelopeV6,
    precheck: &DaylightReferencePrecheckV6,
    now_epoch: Option<u64>,
) -> Result<DaylightTranscriptV6, DaylightCryptoError> {
    if precheck.production_allowed {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Gate));
    }
    if !precheck.parse_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Parse,
        ));
    }
    let envelope_bytes = daylight_envelope_bytes_v6(envelope)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env))?;
    let decoded = daylight_decode_envelope_v6(&envelope_bytes)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env))?;
    if decoded != *envelope || !precheck.schema_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env));
    }
    check_suite_v6(&envelope.header)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Suite))?;
    if !precheck.suite_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Suite,
        ));
    }
    check_aux_hashes_v6(&envelope.header, &envelope.aux_block)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env))?;
    if !precheck.aux_hash_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env));
    }
    let policy = DaylightPolicyV6::from_cbor(&envelope.aux_block.policy_obj)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Policy))?;
    let keyset = DaylightKeySetPubV6::from_cbor(&envelope.aux_block.keyset_obj)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env))?;
    let claims = decode_claims_v6(&envelope.aux_block.claims_obj)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Claim))?;
    if !precheck.policy_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Policy,
        ));
    }
    if !precheck.claims_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Claim,
        ));
    }
    check_static_policy_gate_v6(
        &envelope.header,
        &envelope.aux_block,
        &policy,
        &claims,
        now_epoch,
    )
    .map_err(daylight_open_error_from_rejection_v6)?;
    check_kem_block_public_shape_v6(&envelope.kem_block, &keyset)
        .map_err(daylight_open_error_from_rejection_v6)?;
    if !precheck.kem_block_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env));
    }
    let review_receipt_hash = envelope
        .aux_block
        .review_receipt_hash()
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env))?;
    let transcript = daylight_transcript_v6(
        &envelope.header,
        &envelope.kem_block,
        &envelope.ciphertext,
        &envelope.com_a,
        &review_receipt_hash,
    )
    .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env))?;
    check_auth_block_shape_v6(&envelope.auth_block, envelope.header.profile)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::AuthQ))?;
    if !precheck.auth_block_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::AuthQ,
        ));
    }
    if !precheck.auth_signature_ok || !precheck.external_authority_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::AuthQ,
        ));
    }
    if !precheck.review_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Gate));
    }
    if !precheck.downgrade_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::NoDowngrade,
        ));
    }
    if !precheck.log_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Log));
    }
    if !precheck.install_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Install,
        ));
    }
    if !precheck.witness_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Witness,
        ));
    }
    Ok(transcript)
}

fn daylight_open_error_from_rejection_v6(stage: DaylightRejectionStageV6) -> DaylightCryptoError {
    let failure = match stage {
        DaylightRejectionStageV6::RejectParse => DaylightOpenFailure::Parse,
        DaylightRejectionStageV6::RejectSuite => DaylightOpenFailure::Suite,
        DaylightRejectionStageV6::RejectPolicy => DaylightOpenFailure::Policy,
        DaylightRejectionStageV6::RejectClaims => DaylightOpenFailure::Claim,
        DaylightRejectionStageV6::RejectReview => DaylightOpenFailure::Gate,
        DaylightRejectionStageV6::RejectDowngrade => DaylightOpenFailure::NoDowngrade,
        DaylightRejectionStageV6::RejectLog => DaylightOpenFailure::Log,
        DaylightRejectionStageV6::RejectInstall => DaylightOpenFailure::Install,
        DaylightRejectionStageV6::RejectWitness => DaylightOpenFailure::Witness,
        DaylightRejectionStageV6::RejectAuthSignature
        | DaylightRejectionStageV6::RejectAuthBlock => DaylightOpenFailure::AuthQ,
        DaylightRejectionStageV6::RejectDecap => DaylightOpenFailure::Derive,
        DaylightRejectionStageV6::RejectAead => DaylightOpenFailure::Aead,
        DaylightRejectionStageV6::RejectPayload => DaylightOpenFailure::Aead,
        DaylightRejectionStageV6::RejectCommit => DaylightOpenFailure::Commit,
        DaylightRejectionStageV6::RejectLeak => DaylightOpenFailure::Leak,
        DaylightRejectionStageV6::RejectSchema
        | DaylightRejectionStageV6::RejectAuxHash
        | DaylightRejectionStageV6::RejectKemBlock => DaylightOpenFailure::Env,
    };
    DaylightCryptoError::OpenRejected(failure)
}

pub fn daylight_v6_provider_private_roundtrip_evidence(
) -> Result<DaylightV6ProviderPrivateRoundtripEvidence, DaylightCryptoError> {
    let kem_evidence = daylight_v6_provider_kem_evidence()?;
    let artifact = DAYLIGHT_V6_SCHEMA_ARTIFACT;
    let private_payload = daylight_private_payload_bytes_v6(artifact, None)?;
    let nonce = derive_nonce(&kem_evidence.key_schedule.base_nonce, 0)?;
    let ciphertext = aead_seal(
        kem_evidence.schema_vector.envelope.header.aead,
        &kem_evidence.key_schedule.envelope_key,
        &nonce,
        &kem_evidence.schema_vector.transcript.t0,
        &private_payload,
    )?;
    let com_a = daylight_artifact_commitment_v6(
        &kem_evidence.key_schedule.commitment_key,
        &kem_evidence.schema_vector.transcript.h0,
        &ciphertext,
        artifact,
        &kem_evidence.schema_vector.envelope.header.leak_value,
    )?;
    let mut envelope = kem_evidence.schema_vector.envelope.clone();
    envelope.ciphertext = ciphertext.clone();
    envelope.com_a = com_a;
    let review_receipt_hash = envelope.aux_block.review_receipt_hash()?;
    let transcript = daylight_transcript_v6(
        &envelope.header,
        &envelope.kem_block,
        &envelope.ciphertext,
        &envelope.com_a,
        &review_receipt_hash,
    )?;
    let omega = daylight_envelope_bytes_v6(&envelope)?;
    let public_precheck_rejection_stage = match daylight_vector_public_precheck_v6(&omega, Some(1))
    {
        Ok(_) => {
            return Err(DaylightCryptoError::DecodeRejected(
                "private roundtrip vector unexpectedly passed public precheck",
            ))
        }
        Err(stage) => stage,
    };
    let opened_payload = aead_open(
        envelope.header.aead,
        &kem_evidence.key_schedule.envelope_key,
        &nonce,
        &kem_evidence.schema_vector.transcript.t0,
        &ciphertext,
    )?;
    let opened_artifact = daylight_private_payload_artifact_v6(&opened_payload)?;
    let opened_artifact_matches = opened_artifact == artifact;
    let expected_com_a = daylight_artifact_commitment_v6(
        &kem_evidence.key_schedule.commitment_key,
        &kem_evidence.schema_vector.transcript.h0,
        &ciphertext,
        &opened_artifact,
        &envelope.header.leak_value,
    )?;
    let commitment_matches = expected_com_a == envelope.com_a;
    let aead_roundtrip_matches = opened_payload == private_payload;
    if !opened_artifact_matches || !commitment_matches || !aead_roundtrip_matches {
        return Err(DaylightCryptoError::VerificationRejected);
    }

    Ok(DaylightV6ProviderPrivateRoundtripEvidence {
        artifact_hash: hb_v6(artifact),
        private_payload_hash: hb_v6(&private_payload),
        ciphertext_hash: hb_v6(&ciphertext),
        nonce_hash: hb_v6(&nonce),
        com_a_hash: hb_v6(&com_a),
        opened_artifact_hash: hb_v6(&opened_artifact),
        envelope,
        omega,
        transcript,
        opened_artifact_matches,
        commitment_matches,
        aead_roundtrip_matches,
        public_precheck_rejection_stage,
        provider_backed_private_roundtrip: true,
        provider_backed_reference_seal_open: false,
        production_allowed: false,
    })
}

pub fn daylight_v6_reference_seal_open_evidence(
) -> Result<DaylightV6ReferenceSealOpenEvidence, DaylightCryptoError> {
    let schema_vector = daylight_v6_schema_vector()?;
    let mlkem = mlkem1024_kat_fixture()?;
    let dhkem_recipient =
        dhkem_p384_hkdf_sha384_derive_keypair(DAYLIGHT_V6_SCHEMA_DHKEM_RECIPIENT_IKM)?;
    let recipient_public = DaylightRecipientPublicKeysV6 {
        mlkem_encaps_key: mlkem.encaps_key,
        dhkem_public_key: dhkem_recipient.public_key,
    };
    let recipient_secret = DaylightRecipientSecretKeysV6 {
        mlkem_decaps_key: mlkem.decaps_key,
        dhkem_private_key: dhkem_recipient.private_key,
    };
    let kem_inputs = DaylightSealKemInputsV6 {
        mlkem_encaps_seed: [0x52; 32],
        dhkem_ephemeral_ikm: b"daylight v6 reference seal open ephemeral".to_vec(),
    };
    let kem_key_ids = DaylightKemKeyIdsV6 {
        q_kem_key_id: schema_vector.envelope.kem_block.q_kem_key_id,
        c_kem_key_id: schema_vector.envelope.kem_block.c_kem_key_id,
    };
    let envelope = daylight_seal_v6_with_kems_from_seed(
        schema_vector.envelope.header,
        schema_vector.envelope.auth_block,
        schema_vector.envelope.aux_block,
        kem_key_ids,
        &recipient_public,
        &kem_inputs,
        DAYLIGHT_V6_SCHEMA_ARTIFACT,
        None,
    )?;
    let omega = daylight_envelope_bytes_v6(&envelope)?;
    let public_precheck_rejection_stage = match daylight_vector_public_precheck_v6(&omega, Some(1))
    {
        Ok(_) => {
            return Err(DaylightCryptoError::DecodeRejected(
                "reference seal/open vector unexpectedly passed public precheck",
            ))
        }
        Err(stage) => stage,
    };
    let precheck = DaylightReferencePrecheckV6::nonproduction_all_passed();
    let opened = daylight_open_v6_with_kems(&envelope, &recipient_secret, &precheck, Some(1))?;
    let opened_artifact_matches = opened.artifact == DAYLIGHT_V6_SCHEMA_ARTIFACT;
    if !opened_artifact_matches {
        return Err(DaylightCryptoError::VerificationRejected);
    }

    Ok(DaylightV6ReferenceSealOpenEvidence {
        artifact_hash: hb_v6(DAYLIGHT_V6_SCHEMA_ARTIFACT),
        opened_artifact_hash: hb_v6(&opened.artifact),
        ciphertext_hash: hb_v6(&envelope.ciphertext),
        com_a_hash: hb_v6(&envelope.com_a),
        auth_msg_hash: hb_v6(&opened.auth_msg),
        envelope,
        omega,
        opened,
        public_precheck_rejection_stage,
        opened_artifact_matches,
        provider_backed_reference_seal_open: true,
        public_authority_external: true,
        production_allowed: false,
    })
}

pub fn daylight_artifact_commitment_v6(
    commitment_key: &[u8; 32],
    h0: &[u8; 64],
    ciphertext: &[u8],
    artifact: &[u8],
    leak_value: &DaylightLeakValueV6,
) -> Result<[u8; 32], DaylightCryptoError> {
    let artifact_len =
        u64::try_from(artifact.len()).map_err(|_| DaylightCryptoError::EncodingTooLarge)?;
    let input = CborValue::Array(vec![
        CborValue::Bytes(h0.to_vec()),
        CborValue::Bytes(hb_v6(ciphertext).to_vec()),
        CborValue::UInt(artifact_len),
        CborValue::Bytes(artifact_hash_v6(artifact).to_vec()),
        leak_value_cbor_v6(leak_value),
    ]);
    let output = kdf2_v6(commitment_key, "daylight.artifact.commit.v6", &input, 32)?;
    fixed_decode(&output)
}

pub fn daylight_private_payload_bytes_v6(
    artifact: &[u8],
    review_blind: Option<&[u8; 32]>,
) -> Result<Vec<u8>, DaylightCryptoError> {
    encode_cbor_value(&CborValue::Map(vec![
        (0, CborValue::Bytes(artifact.to_vec())),
        (
            1,
            review_blind
                .map(|blind| CborValue::Bytes(blind.to_vec()))
                .unwrap_or(CborValue::Null),
        ),
    ]))
}

pub fn daylight_private_payload_v6(
    payload: &[u8],
) -> Result<DaylightPrivatePayloadV6, DaylightCryptoError> {
    let value = decode_cbor_value(payload)?;
    let entries = expect_map_exact(&value, &[0, 1], "PrivatePayload_v6")?;
    let artifact = expect_bytes(map_get(entries, 0)?, "private_payload.artifact")?.to_vec();
    let review_blind = match map_get(entries, 1)? {
        CborValue::Null => None,
        CborValue::Bytes(bytes) if bytes.len() == 32 => Some(fixed_decode(bytes)?),
        _ => return Err(DaylightCryptoError::DecodeRejected("bad review_blind")),
    };
    Ok(DaylightPrivatePayloadV6 {
        artifact,
        review_blind,
    })
}

pub fn daylight_private_payload_artifact_v6(
    payload: &[u8],
) -> Result<Vec<u8>, DaylightCryptoError> {
    Ok(daylight_private_payload_v6(payload)?.artifact)
}

fn daylight_private_leak_ok_v6(
    header: &DaylightHeaderV6,
    payload: &DaylightPrivatePayloadV6,
) -> Result<bool, DaylightCryptoError> {
    let artifact_len =
        u64::try_from(payload.artifact.len()).map_err(|_| DaylightCryptoError::EncodingTooLarge)?;
    match (
        &header.content_scope,
        &header.leak_value,
        &payload.review_blind,
    ) {
        (
            DaylightContentScopeV6::MetadataOnly,
            DaylightLeakValueV6::MetadataOnly {
                artifact_len: expected,
            },
            None,
        ) => Ok(*expected == artifact_len),
        (
            DaylightContentScopeV6::PublicCommitment,
            DaylightLeakValueV6::PublicCommitment {
                artifact_len: expected_len,
                artifact_hash,
            },
            None,
        ) => {
            Ok(*expected_len == artifact_len
                && *artifact_hash == artifact_hash_v6(&payload.artifact))
        }
        (
            DaylightContentScopeV6::ReviewedContent,
            DaylightLeakValueV6::ReviewedContent {
                artifact_len: expected_len,
                review_commit,
            },
            Some(review_blind),
        ) => {
            let expected_commit = daylight_review_commit_v6(
                review_blind,
                &payload.artifact,
                &header.policy_hash,
                &header.claims_hash,
            )?;
            Ok(*expected_len == artifact_len && *review_commit == expected_commit)
        }
        _ => Ok(false),
    }
}

pub fn daylight_kem_key_id_v6(
    alg_id: &str,
    public_key_bytes: &[u8],
) -> Result<[u8; 64], DaylightCryptoError> {
    ensure_ascii_label(alg_id)?;
    hc_v6(&CborValue::Array(vec![
        CborValue::Text("daylight.key-id.v6".to_string()),
        CborValue::Text(alg_id.to_string()),
        CborValue::Bytes(public_key_bytes.to_vec()),
        CborValue::Text("kem".to_string()),
    ]))
}

pub fn daylight_roster_key_id_v6(
    alg_id: &str,
    public_key_bytes: &[u8],
    domain_id: &CborValue,
) -> Result<[u8; 64], DaylightCryptoError> {
    ensure_ascii_label(alg_id)?;
    hc_v6(&CborValue::Array(vec![
        CborValue::Text("daylight.key-id.v6".to_string()),
        CborValue::Text(alg_id.to_string()),
        CborValue::Bytes(public_key_bytes.to_vec()),
        domain_id.clone(),
    ]))
}

impl DaylightHeaderV6 {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (0, CborValue::UInt(u64::from(self.version))),
            (1, CborValue::Bytes(self.suite_id.to_vec())),
            (2, CborValue::UInt(profile_code(self.profile))),
            (3, CborValue::UInt(u64::from(self.release_level))),
            (4, CborValue::UInt(mode_code(self.mode))),
            (5, CborValue::UInt(action_code(self.action))),
            (6, CborValue::UInt(content_scope_code(self.content_scope))),
            (7, leak_value_cbor_v6(&self.leak_value)),
            (8, CborValue::UInt(aead_code(self.aead))),
            (9, CborValue::Text(self.policy_id.clone())),
            (10, CborValue::Bytes(self.policy_hash.to_vec())),
            (11, CborValue::Bytes(self.keyset_hash.to_vec())),
            (
                12,
                self.prev_log_head
                    .map(|hash| CborValue::Bytes(hash.to_vec()))
                    .unwrap_or(CborValue::Null),
            ),
            (13, CborValue::Bytes(self.provenance_hash.to_vec())),
            (14, CborValue::Bytes(self.install_manifest_hash.to_vec())),
            (15, CborValue::Bytes(self.claims_hash.to_vec())),
            (16, CborValue::UInt(self.key_epoch)),
            (17, CborValue::UInt(conformance_code(self.conformance_min))),
        ])
    }

    pub fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &(0..=17).collect::<Vec<_>>(), "Header_v6")?;
        let version = expect_u8(map_get(entries, 0)?, "header.version")?;
        if version != 6 {
            return Err(DaylightCryptoError::DecodeRejected(
                "unsupported Daylight header version",
            ));
        }
        let profile = decode_profile_code(expect_u64(map_get(entries, 2)?, "header.profile")?)?;
        let release_level = expect_u8(map_get(entries, 3)?, "header.r")?;
        if release_level > 3 {
            return Err(DaylightCryptoError::DecodeRejected(
                "release level out of range",
            ));
        }
        let mode = decode_mode_code(expect_u64(map_get(entries, 4)?, "header.mu")?)?;
        let action = decode_action_code(expect_u64(map_get(entries, 5)?, "header.action")?)?;
        let content_scope =
            decode_content_scope_code(expect_u64(map_get(entries, 6)?, "header.content_scope")?)?;
        let policy_id = expect_ascii_text(map_get(entries, 9)?, "header.policy_id", 1, 128)?;
        Ok(Self {
            version,
            suite_id: expect_hash64(map_get(entries, 1)?, "header.suite_id")?,
            profile,
            release_level,
            mode,
            action,
            content_scope,
            leak_value: decode_leak_value_v6(map_get(entries, 7)?, content_scope)?,
            aead: decode_aead_code(expect_u64(map_get(entries, 8)?, "header.aead_id")?)?,
            policy_id,
            policy_hash: expect_hash64(map_get(entries, 10)?, "header.policy_hash")?,
            keyset_hash: expect_hash64(map_get(entries, 11)?, "header.keyset_hash")?,
            prev_log_head: match map_get(entries, 12)? {
                CborValue::Null => None,
                other => Some(expect_hash64(other, "header.prev_log_head")?),
            },
            provenance_hash: expect_hash64(map_get(entries, 13)?, "header.provenance_hash")?,
            install_manifest_hash: expect_hash64(
                map_get(entries, 14)?,
                "header.install_manifest_hash",
            )?,
            claims_hash: expect_hash64(map_get(entries, 15)?, "header.claims_hash")?,
            key_epoch: expect_u64(map_get(entries, 16)?, "header.key_epoch")?,
            conformance_min: decode_conformance_code(expect_u64(
                map_get(entries, 17)?,
                "header.conformance_min",
            )?)?,
        })
    }
}

impl DaylightKemBlockV6 {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (0, CborValue::Bytes(self.q_kem_key_id.to_vec())),
            (1, CborValue::Bytes(self.c_kem_key_id.to_vec())),
            (2, CborValue::Bytes(self.enc_q.clone())),
            (3, CborValue::Bytes(self.enc_c.to_vec())),
        ])
    }

    pub fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &[0, 1, 2, 3], "KEMBlock_v6")?;
        let enc_q = expect_bytes(map_get(entries, 2)?, "kem_block.enc_Q")?.to_vec();
        if enc_q.len() != ml_kem_1024::CT_LEN {
            return Err(DaylightCryptoError::DecodeRejected(
                "unexpected ML-KEM ciphertext length",
            ));
        }
        Ok(Self {
            q_kem_key_id: expect_hash64(map_get(entries, 0)?, "kem_block.q_kem_key_id")?,
            c_kem_key_id: expect_hash64(map_get(entries, 1)?, "kem_block.c_kem_key_id")?,
            enc_q,
            enc_c: expect_fixed_bytes(map_get(entries, 3)?, "kem_block.enc_C")?,
        })
    }
}

impl DaylightAuthBlockV6 {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (
                0,
                CborValue::Array(self.q_sigs.iter().map(DaylightQSigV6::to_cbor).collect()),
            ),
            (
                1,
                self.h_sig
                    .as_ref()
                    .map(|sig| CborValue::Bytes(sig.clone()))
                    .unwrap_or(CborValue::Null),
            ),
            (
                2,
                self.frost_auth
                    .as_ref()
                    .map(DaylightFrostAuthV6::to_cbor)
                    .unwrap_or(CborValue::Null),
            ),
        ])
    }

    pub fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &[0, 1, 2], "AuthBlock_v6")?;
        let q_sig_values = expect_array(map_get(entries, 0)?, "auth_block.q_sigs")?;
        let mut q_sigs = Vec::with_capacity(q_sig_values.len());
        for item in q_sig_values {
            q_sigs.push(DaylightQSigV6::from_cbor(item)?);
        }
        ensure_sorted_unique_hashes(q_sigs.iter().map(|sig| sig.key_id))?;
        let h_sig = match map_get(entries, 1)? {
            CborValue::Null => None,
            other => {
                let bytes = expect_bytes(other, "auth_block.h_sig")?.to_vec();
                if bytes.len() != slh_dsa_shake_256s::SIG_LEN {
                    return Err(DaylightCryptoError::DecodeRejected(
                        "unexpected SLH-DSA signature length",
                    ));
                }
                Some(bytes)
            }
        };
        let frost_auth = match map_get(entries, 2)? {
            CborValue::Null => None,
            other => Some(DaylightFrostAuthV6::from_cbor(other)?),
        };
        Ok(Self {
            q_sigs,
            h_sig,
            frost_auth,
        })
    }
}

impl DaylightQSigV6 {
    fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (0, CborValue::Bytes(self.key_id.to_vec())),
            (1, CborValue::Bytes(self.sig.clone())),
        ])
    }

    fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &[0, 1], "QSig_v6")?;
        let sig = expect_bytes(map_get(entries, 1)?, "auth_block.q_sig.sig")?.to_vec();
        if sig.len() != ml_dsa_87::SIG_LEN {
            return Err(DaylightCryptoError::DecodeRejected(
                "unexpected ML-DSA signature length",
            ));
        }
        Ok(Self {
            key_id: expect_hash64(map_get(entries, 0)?, "auth_block.q_sig.key_id")?,
            sig,
        })
    }
}

impl DaylightFrostAuthV6 {
    fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (0, CborValue::Bytes(self.sig_f.clone())),
            (1, self.frost_transcript.clone()),
        ])
    }

    fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &[0, 1], "FrostAuth_v6")?;
        Ok(Self {
            sig_f: expect_bytes(map_get(entries, 0)?, "auth_block.frost.sig_F")?.to_vec(),
            frost_transcript: map_get(entries, 1)?.clone(),
        })
    }
}

impl DaylightAuxBlockV6 {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (0, self.policy_obj.clone()),
            (1, self.keyset_obj.clone()),
            (2, self.claims_obj.clone()),
            (3, option_obj_to_cbor(&self.provenance_obj)),
            (4, option_obj_to_cbor(&self.review_receipt)),
            (5, option_obj_to_cbor(&self.log_proof)),
            (6, option_obj_to_cbor(&self.install_manifest)),
            (7, option_obj_to_cbor(&self.witness_evidence)),
        ])
    }

    pub fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &[0, 1, 2, 3, 4, 5, 6, 7], "AuxBlock_v6")?;
        let policy_obj = map_get(entries, 0)?.clone();
        let keyset_obj = map_get(entries, 1)?.clone();
        let claims_obj = map_get(entries, 2)?.clone();
        if matches!(policy_obj, CborValue::Null)
            || matches!(keyset_obj, CborValue::Null)
            || matches!(claims_obj, CborValue::Null)
        {
            return Err(DaylightCryptoError::DecodeRejected(
                "mandatory aux object is null",
            ));
        }
        Ok(Self {
            policy_obj,
            keyset_obj,
            claims_obj,
            provenance_obj: option_obj_from_cbor(map_get(entries, 3)?),
            review_receipt: option_obj_from_cbor(map_get(entries, 4)?),
            log_proof: option_obj_from_cbor(map_get(entries, 5)?),
            install_manifest: option_obj_from_cbor(map_get(entries, 6)?),
            witness_evidence: option_obj_from_cbor(map_get(entries, 7)?),
        })
    }

    fn review_receipt_hash(&self) -> Result<[u8; 64], DaylightCryptoError> {
        match &self.review_receipt {
            Some(value) => hc_v6(value),
            None => null_hash_v6(),
        }
    }
}

impl DaylightEnvelopeV6 {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (0, CborValue::Text(DAYLIGHT_V6_MAGIC.to_string())),
            (1, self.header.to_cbor()),
            (2, self.kem_block.to_cbor()),
            (3, CborValue::Bytes(self.ciphertext.clone())),
            (4, CborValue::Bytes(self.com_a.to_vec())),
            (5, self.auth_block.to_cbor()),
            (6, self.aux_block.to_cbor()),
        ])
    }

    pub fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let parts = EnvelopePartsV6::from_cbor(value)?;
        Ok(Self {
            header: DaylightHeaderV6::from_cbor(&parts.header)?,
            kem_block: DaylightKemBlockV6::from_cbor(&parts.kem_block)?,
            ciphertext: parts.ciphertext,
            com_a: parts.com_a,
            auth_block: DaylightAuthBlockV6::from_cbor(&parts.auth_block)?,
            aux_block: DaylightAuxBlockV6::from_cbor(&parts.aux_block)?,
        })
    }
}

impl DaylightPolicyV6 {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (0, CborValue::Text(self.policy_id.clone())),
            (
                1,
                CborValue::Array(
                    self.allowed_profiles
                        .iter()
                        .map(|profile| CborValue::UInt(profile_code(*profile)))
                        .collect(),
                ),
            ),
            (
                2,
                CborValue::Array(
                    self.allowed_aeads
                        .iter()
                        .map(|aead| CborValue::UInt(aead_code(*aead)))
                        .collect(),
                ),
            ),
            (
                3,
                CborValue::Array(
                    self.allowed_actions
                        .iter()
                        .map(|action| CborValue::UInt(action_code(*action)))
                        .collect(),
                ),
            ),
            (
                4,
                CborValue::Map(
                    self.min_mode_by_action
                        .iter()
                        .map(|(action, (release_level, mode))| {
                            (
                                action_code(*action),
                                CborValue::Array(vec![
                                    CborValue::UInt(u64::from(*release_level)),
                                    CborValue::UInt(mode_code(*mode)),
                                ]),
                            )
                        })
                        .collect(),
                ),
            ),
            (
                5,
                CborValue::Array(
                    self.allowed_keyset_hashes
                        .iter()
                        .map(|hash| CborValue::Bytes(hash.to_vec()))
                        .collect(),
                ),
            ),
            (6, CborValue::Bool(self.require_exact_content_approval)),
            (7, CborValue::Bool(self.require_provenance)),
            (8, CborValue::Bool(self.require_witness)),
            (
                9,
                CborValue::Array(
                    self.log_required_actions
                        .iter()
                        .map(|action| CborValue::UInt(action_code(*action)))
                        .collect(),
                ),
            ),
            (
                10,
                CborValue::Array(
                    self.allowed_claim_classes
                        .iter()
                        .map(|class| CborValue::UInt(u64::from(*class)))
                        .collect(),
                ),
            ),
            (
                11,
                self.expiry_epoch
                    .map(CborValue::UInt)
                    .unwrap_or(CborValue::Null),
            ),
            (12, CborValue::UInt(self.policy_version)),
        ])
    }

    pub fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &(0..=12).collect::<Vec<_>>(), "Policy_v6")?;
        let allowed_profiles = decode_sorted_array(
            map_get(entries, 1)?,
            "policy.allowed_profiles",
            decode_profile_code,
        )?;
        let allowed_aeads = decode_sorted_array(
            map_get(entries, 2)?,
            "policy.allowed_aeads",
            decode_aead_code,
        )?;
        let allowed_actions = decode_sorted_array(
            map_get(entries, 3)?,
            "policy.allowed_actions",
            decode_action_code,
        )?;
        let min_mode_by_action = decode_min_mode_by_action(map_get(entries, 4)?)?;
        let allowed_keyset_hashes =
            decode_sorted_hash_array(map_get(entries, 5)?, "policy.allowed_keyset_hashes")?;
        let allowed_claim_classes =
            decode_sorted_claim_class_array(map_get(entries, 10)?, "policy.allowed_claim_classes")?;
        let policy_version = expect_u64(map_get(entries, 12)?, "policy.policy_version")?;
        if policy_version != 6 {
            return Err(DaylightCryptoError::DecodeRejected(
                "unsupported policy version",
            ));
        }
        Ok(Self {
            policy_id: expect_ascii_text(map_get(entries, 0)?, "policy.policy_id", 1, 128)?,
            allowed_profiles,
            allowed_aeads,
            allowed_actions,
            min_mode_by_action,
            allowed_keyset_hashes,
            require_exact_content_approval: expect_bool(
                map_get(entries, 6)?,
                "policy.require_exact_content_approval",
            )?,
            require_provenance: expect_bool(map_get(entries, 7)?, "policy.require_provenance")?,
            require_witness: expect_bool(map_get(entries, 8)?, "policy.require_witness")?,
            log_required_actions: decode_sorted_array(
                map_get(entries, 9)?,
                "policy.log_required_actions",
                decode_action_code,
            )?,
            allowed_claim_classes,
            expiry_epoch: match map_get(entries, 11)? {
                CborValue::Null => None,
                other => Some(expect_u64(other, "policy.expiry_epoch")?),
            },
            policy_version,
        })
    }
}

impl DaylightKeySetPubV6 {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (0, CborValue::Bytes(self.ek_q.clone())),
            (1, CborValue::Bytes(self.pk_c.to_vec())),
            (
                2,
                CborValue::Array(
                    self.q_roster
                        .iter()
                        .map(DaylightQRosterEntryV6::to_cbor)
                        .collect(),
                ),
            ),
            (
                3,
                self.pk_h
                    .as_ref()
                    .map(|pk| CborValue::Bytes(pk.clone()))
                    .unwrap_or(CborValue::Null),
            ),
            (4, option_obj_to_cbor(&self.frost_pub)),
            (5, self.certificates.clone()),
            (6, self.revocation_state.clone()),
            (7, self.policy_keys.clone()),
            (8, self.thresholds.to_cbor()),
        ])
    }

    pub fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &(0..=8).collect::<Vec<_>>(), "KeySetPub_v6")?;
        let ek_q = expect_bytes(map_get(entries, 0)?, "keyset.ek_Q")?.to_vec();
        if ek_q.len() != ml_kem_1024::EK_LEN {
            return Err(DaylightCryptoError::DecodeRejected(
                "unexpected ML-KEM public key length",
            ));
        }
        let roster_values = expect_array(map_get(entries, 2)?, "keyset.Q_roster")?;
        let mut q_roster = Vec::with_capacity(roster_values.len());
        for item in roster_values {
            q_roster.push(DaylightQRosterEntryV6::from_cbor(item)?);
        }
        ensure_sorted_unique_hashes(q_roster.iter().map(|entry| entry.key_id))?;
        Ok(Self {
            ek_q,
            pk_c: expect_fixed_bytes(map_get(entries, 1)?, "keyset.pk_C")?,
            q_roster,
            pk_h: match map_get(entries, 3)? {
                CborValue::Null => None,
                other => Some(expect_bytes(other, "keyset.pk_H")?.to_vec()),
            },
            frost_pub: option_obj_from_cbor(map_get(entries, 4)?),
            certificates: map_get(entries, 5)?.clone(),
            revocation_state: map_get(entries, 6)?.clone(),
            policy_keys: map_get(entries, 7)?.clone(),
            thresholds: DaylightThresholdsV6::from_cbor(map_get(entries, 8)?)?,
        })
    }
}

impl DaylightQRosterEntryV6 {
    fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (0, CborValue::Bytes(self.key_id.to_vec())),
            (1, CborValue::Bytes(self.pk_q.clone())),
            (2, self.domain_id.clone()),
            (3, self.cert_ref.clone()),
        ])
    }

    fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &[0, 1, 2, 3], "QRosterEntry_v6")?;
        Ok(Self {
            key_id: expect_hash64(map_get(entries, 0)?, "keyset.Q_roster.key_id")?,
            pk_q: expect_bytes(map_get(entries, 1)?, "keyset.Q_roster.pk_Q")?.to_vec(),
            domain_id: map_get(entries, 2)?.clone(),
            cert_ref: map_get(entries, 3)?.clone(),
        })
    }
}

impl DaylightThresholdsV6 {
    fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (0, CborValue::UInt(self.t_q)),
            (1, CborValue::UInt(self.u_q)),
            (2, CborValue::UInt(self.t_f)),
            (3, CborValue::UInt(self.u_f)),
        ])
    }

    fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &[0, 1, 2, 3], "Thresholds_v6")?;
        Ok(Self {
            t_q: expect_u64(map_get(entries, 0)?, "keyset.thresholds.t_Q")?,
            u_q: expect_u64(map_get(entries, 1)?, "keyset.thresholds.u_Q")?,
            t_f: expect_u64(map_get(entries, 2)?, "keyset.thresholds.t_F")?,
            u_f: expect_u64(map_get(entries, 3)?, "keyset.thresholds.u_F")?,
        })
    }
}

impl EnvelopePartsV6 {
    fn from_cbor(value: &CborValue) -> Result<Self, DaylightCryptoError> {
        let entries = expect_map_exact(value, &[0, 1, 2, 3, 4, 5, 6], "Envelope_v6")?;
        let magic = expect_text(map_get(entries, 0)?, "envelope.magic")?;
        if magic != DAYLIGHT_V6_MAGIC {
            return Err(DaylightCryptoError::DecodeRejected(
                "unknown DaylightEnvelopeV6 magic",
            ));
        }
        Ok(Self {
            header: map_get(entries, 1)?.clone(),
            kem_block: map_get(entries, 2)?.clone(),
            ciphertext: expect_bytes(map_get(entries, 3)?, "envelope.ciphertext")?.to_vec(),
            com_a: expect_fixed_bytes(map_get(entries, 4)?, "envelope.com_A")?,
            auth_block: map_get(entries, 5)?.clone(),
            aux_block: map_get(entries, 6)?.clone(),
        })
    }
}

fn append_cbor_value(value: &CborValue, output: &mut Vec<u8>) -> Result<(), DaylightCryptoError> {
    match value {
        CborValue::UInt(value) => append_cbor_type_len(0, *value, output),
        CborValue::Bytes(bytes) => {
            append_cbor_type_len(2, bytes.len() as u64, output);
            output.extend_from_slice(bytes);
        }
        CborValue::Text(text) => {
            append_cbor_type_len(3, text.len() as u64, output);
            output.extend_from_slice(text.as_bytes());
        }
        CborValue::Array(items) => {
            append_cbor_type_len(4, items.len() as u64, output);
            for item in items {
                append_cbor_value(item, output)?;
            }
        }
        CborValue::Map(entries) => {
            ensure_map_keys_strictly_increasing(entries)?;
            append_cbor_type_len(5, entries.len() as u64, output);
            for (key, item) in entries {
                append_cbor_type_len(0, *key, output);
                append_cbor_value(item, output)?;
            }
        }
        CborValue::Bool(false) => output.push(0xf4),
        CborValue::Bool(true) => output.push(0xf5),
        CborValue::Null => output.push(0xf6),
    }
    Ok(())
}

fn append_cbor_type_len(major: u8, value: u64, output: &mut Vec<u8>) {
    let head = major << 5;
    match value {
        0..=23 => output.push(head | value as u8),
        24..=0xff => {
            output.push(head | 24);
            output.push(value as u8);
        }
        0x100..=0xffff => {
            output.push(head | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(head | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(head | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct CborCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> CborCursor<'a> {
    fn decode_value(&mut self) -> Result<CborValue, DaylightCryptoError> {
        let head = self.read_u8()?;
        let major = head >> 5;
        let additional = head & 0x1f;
        match major {
            0 => Ok(CborValue::UInt(self.decode_argument(additional)?)),
            2 => {
                let len = usize::try_from(self.decode_argument(additional)?)
                    .map_err(|_| DaylightCryptoError::DecodeRejected("CBOR length too large"))?;
                Ok(CborValue::Bytes(self.read_bytes(len)?.to_vec()))
            }
            3 => {
                let len = usize::try_from(self.decode_argument(additional)?)
                    .map_err(|_| DaylightCryptoError::DecodeRejected("CBOR length too large"))?;
                let bytes = self.read_bytes(len)?;
                let text = core::str::from_utf8(bytes)
                    .map_err(|_| DaylightCryptoError::DecodeRejected("invalid UTF-8 text"))?;
                Ok(CborValue::Text(text.to_string()))
            }
            4 => {
                let len = usize::try_from(self.decode_argument(additional)?)
                    .map_err(|_| DaylightCryptoError::DecodeRejected("CBOR length too large"))?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.decode_value()?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                let len = usize::try_from(self.decode_argument(additional)?)
                    .map_err(|_| DaylightCryptoError::DecodeRejected("CBOR length too large"))?;
                let mut entries = Vec::with_capacity(len);
                let mut previous_key = None;
                for _ in 0..len {
                    let key = self.decode_map_key()?;
                    if previous_key
                        .map(|previous| key <= previous)
                        .unwrap_or(false)
                    {
                        return Err(DaylightCryptoError::DecodeRejected(
                            "duplicate or unsorted CBOR map key",
                        ));
                    }
                    previous_key = Some(key);
                    entries.push((key, self.decode_value()?));
                }
                Ok(CborValue::Map(entries))
            }
            7 => match additional {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                _ => Err(DaylightCryptoError::DecodeRejected(
                    "unsupported CBOR simple value",
                )),
            },
            _ => Err(DaylightCryptoError::DecodeRejected(
                "unsupported CBOR major type",
            )),
        }
    }

    fn decode_map_key(&mut self) -> Result<u64, DaylightCryptoError> {
        let head = self.read_u8()?;
        if head >> 5 != 0 {
            return Err(DaylightCryptoError::DecodeRejected(
                "expected unsigned integer CBOR map key",
            ));
        }
        self.decode_argument(head & 0x1f)
    }

    fn decode_argument(&mut self, additional: u8) -> Result<u64, DaylightCryptoError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.read_u8()?);
                if value <= 23 {
                    return Err(DaylightCryptoError::DecodeRejected(
                        "non-minimal CBOR integer or length",
                    ));
                }
                Ok(value)
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.read_array()?));
                if value <= 0xff {
                    return Err(DaylightCryptoError::DecodeRejected(
                        "non-minimal CBOR integer or length",
                    ));
                }
                Ok(value)
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.read_array()?));
                if value <= 0xffff {
                    return Err(DaylightCryptoError::DecodeRejected(
                        "non-minimal CBOR integer or length",
                    ));
                }
                Ok(value)
            }
            27 => {
                let value = u64::from_be_bytes(self.read_array()?);
                if value <= 0xffff_ffff {
                    return Err(DaylightCryptoError::DecodeRejected(
                        "non-minimal CBOR integer or length",
                    ));
                }
                Ok(value)
            }
            31 => Err(DaylightCryptoError::DecodeRejected(
                "indefinite-length CBOR is forbidden",
            )),
            _ => Err(DaylightCryptoError::DecodeRejected(
                "reserved CBOR additional information",
            )),
        }
    }

    fn read_u8(&mut self) -> Result<u8, DaylightCryptoError> {
        let value = self
            .input
            .get(self.offset)
            .copied()
            .ok_or(DaylightCryptoError::DecodeRejected("truncated CBOR input"))?;
        self.offset += 1;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DaylightCryptoError> {
        let bytes = self.read_bytes(N)?;
        fixed_decode(bytes).map_err(|_| DaylightCryptoError::DecodeRejected("truncated CBOR input"))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], DaylightCryptoError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DaylightCryptoError::DecodeRejected("CBOR length overflow"))?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(DaylightCryptoError::DecodeRejected("truncated CBOR input"))?;
        self.offset = end;
        Ok(bytes)
    }
}

fn check_suite_v6(header: &DaylightHeaderV6) -> Result<(), DaylightRejectionStageV6> {
    if header.suite_id
        != daylight_suite_id_v6().map_err(|_| DaylightRejectionStageV6::RejectSuite)?
    {
        return Err(DaylightRejectionStageV6::RejectSuite);
    }
    if !mode_ok(
        header.profile,
        header.release_level,
        header.mode,
        header.action,
    )
    .unwrap_or(false)
        || !action_allowed(header.release_level, header.action).unwrap_or(false)
    {
        return Err(DaylightRejectionStageV6::RejectSuite);
    }
    if !conformance_compatible(header.profile, header.conformance_min) {
        return Err(DaylightRejectionStageV6::RejectSuite);
    }
    Ok(())
}

fn check_aux_hashes_v6(
    header: &DaylightHeaderV6,
    aux: &DaylightAuxBlockV6,
) -> Result<(), DaylightRejectionStageV6> {
    if hc_v6(&aux.policy_obj).map_err(|_| DaylightRejectionStageV6::RejectAuxHash)?
        != header.policy_hash
        || hc_v6(&aux.keyset_obj).map_err(|_| DaylightRejectionStageV6::RejectAuxHash)?
            != header.keyset_hash
        || hc_v6(&aux.claims_obj).map_err(|_| DaylightRejectionStageV6::RejectAuxHash)?
            != header.claims_hash
        || !object_hash_ok_v6(&aux.provenance_obj, &header.provenance_hash)
            .map_err(|_| DaylightRejectionStageV6::RejectAuxHash)?
        || !object_hash_ok_v6(&aux.install_manifest, &header.install_manifest_hash)
            .map_err(|_| DaylightRejectionStageV6::RejectAuxHash)?
    {
        return Err(DaylightRejectionStageV6::RejectAuxHash);
    }
    Ok(())
}

fn check_static_policy_gate_v6(
    header: &DaylightHeaderV6,
    aux: &DaylightAuxBlockV6,
    policy: &DaylightPolicyV6,
    claims: &[DaylightClaimV6],
    now_epoch: Option<u64>,
) -> Result<(), DaylightRejectionStageV6> {
    if policy.policy_id != header.policy_id
        || !policy.allowed_profiles.contains(&header.profile)
        || !policy.allowed_aeads.contains(&header.aead)
        || !policy.allowed_actions.contains(&header.action)
        || !policy.allowed_keyset_hashes.contains(&header.keyset_hash)
    {
        return Err(DaylightRejectionStageV6::RejectPolicy);
    }
    if let Some(expiry) = policy.expiry_epoch {
        if now_epoch.map(|now| now > expiry).unwrap_or(true) {
            return Err(DaylightRejectionStageV6::RejectPolicy);
        }
    }
    let Some((release_min, mode_min)) = policy
        .min_mode_by_action
        .iter()
        .find_map(|(action, minimum)| (*action == header.action).then_some(*minimum))
    else {
        return Err(DaylightRejectionStageV6::RejectPolicy);
    };
    if header.release_level < release_min || mode_code(header.mode) < mode_code(mode_min) {
        return Err(DaylightRejectionStageV6::RejectDowngrade);
    }
    if policy.require_exact_content_approval
        && header.content_scope == DaylightContentScopeV6::MetadataOnly
    {
        return Err(DaylightRejectionStageV6::RejectReview);
    }
    if policy.require_provenance && aux.provenance_obj.is_none() {
        return Err(DaylightRejectionStageV6::RejectPolicy);
    }
    if policy.require_witness && aux.witness_evidence.is_none() {
        return Err(DaylightRejectionStageV6::RejectWitness);
    }
    if policy.log_required_actions.contains(&header.action) && aux.log_proof.is_none() {
        return Err(DaylightRejectionStageV6::RejectLog);
    }
    for claim in claims {
        if !claim_class_allowed_by_release(header.release_level, claim.claim_class)
            || !policy.allowed_claim_classes.contains(&claim.claim_class)
        {
            return Err(DaylightRejectionStageV6::RejectClaims);
        }
    }
    if header.content_scope != DaylightContentScopeV6::MetadataOnly && aux.review_receipt.is_none()
    {
        return Err(DaylightRejectionStageV6::RejectReview);
    }
    Ok(())
}

fn check_kem_block_public_shape_v6(
    kem_block: &DaylightKemBlockV6,
    keyset: &DaylightKeySetPubV6,
) -> Result<(), DaylightRejectionStageV6> {
    let q_kem_key_id = daylight_kem_key_id_v6("ML-KEM-1024", &keyset.ek_q)
        .map_err(|_| DaylightRejectionStageV6::RejectKemBlock)?;
    let c_kem_key_id = daylight_kem_key_id_v6("DHKEM-P384-HKDF-SHA384", &keyset.pk_c)
        .map_err(|_| DaylightRejectionStageV6::RejectKemBlock)?;
    if kem_block.q_kem_key_id != q_kem_key_id || kem_block.c_kem_key_id != c_kem_key_id {
        return Err(DaylightRejectionStageV6::RejectKemBlock);
    }
    Ok(())
}

fn check_auth_block_shape_v6(
    auth_block: &DaylightAuthBlockV6,
    profile: Profile,
) -> Result<(), DaylightCryptoError> {
    if profile != Profile::D2HybridFrost && auth_block.frost_auth.is_some() {
        return Err(DaylightCryptoError::DecodeRejected(
            "unexpected FROST auth for non-FROST profile",
        ));
    }
    ensure_sorted_unique_hashes(auth_block.q_sigs.iter().map(|sig| sig.key_id))?;
    Ok(())
}

fn object_hash_ok_v6(
    object: &Option<CborValue>,
    expected_hash: &[u8; 64],
) -> Result<bool, DaylightCryptoError> {
    let actual = match object {
        Some(value) => hc_v6(value)?,
        None => null_hash_v6()?,
    };
    Ok(&actual == expected_hash)
}

fn conformance_compatible(profile: Profile, conformance: DaylightConformanceLevelV6) -> bool {
    match profile {
        Profile::D2Hybrid => conformance != DaylightConformanceLevelV6::C5Frost,
        Profile::D3Root => conformance >= DaylightConformanceLevelV6::C2Root,
        Profile::D2HybridFrost => conformance == DaylightConformanceLevelV6::C5Frost,
    }
}

fn decode_claims_v6(value: &CborValue) -> Result<Vec<DaylightClaimV6>, DaylightCryptoError> {
    expect_array(value, "Claims_v6")?
        .iter()
        .map(decode_claim_v6)
        .collect()
}

fn decode_claim_v6(value: &CborValue) -> Result<DaylightClaimV6, DaylightCryptoError> {
    let entries = expect_map_exact(value, &[0, 1, 2], "Claim_v6")?;
    let claim_class = expect_u8(map_get(entries, 0)?, "claim.claim_class")?;
    if claim_class > 7 {
        return Err(DaylightCryptoError::DecodeRejected("unknown claim class"));
    }
    Ok(DaylightClaimV6 {
        claim_class,
        claim_name: expect_ascii_text(map_get(entries, 1)?, "claim.claim_name", 1, 128)?,
        claim_value: map_get(entries, 2)?.clone(),
    })
}

fn claim_value_v6(claim_class: u8, claim_name: &str, claim_value: CborValue) -> CborValue {
    CborValue::Map(vec![
        (0, CborValue::UInt(u64::from(claim_class))),
        (1, CborValue::Text(claim_name.to_string())),
        (2, claim_value),
    ])
}

fn claim_class_allowed_by_release(release_level: u8, claim_class: u8) -> bool {
    match release_level {
        0 => matches!(claim_class, 0 | 1),
        1 => matches!(claim_class, 0 | 1 | 2),
        2 => matches!(claim_class, 0 | 1 | 2 | 3 | 4 | 5),
        3 => claim_class <= 7,
        _ => false,
    }
}

fn decode_min_mode_by_action(
    value: &CborValue,
) -> Result<Vec<(Action, (u8, Mode))>, DaylightCryptoError> {
    let entries = expect_map(value, "policy.min_mode_by_action")?;
    let mut output = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let action = decode_action_code(*key)?;
        let tuple = expect_array_len(value, "policy.min_mode_by_action.value", 2)?;
        let release_level = expect_u8(&tuple[0], "policy.min_mode_by_action.r_min")?;
        if release_level > 3 {
            return Err(DaylightCryptoError::DecodeRejected(
                "policy minimum release level out of range",
            ));
        }
        let mode = decode_mode_code(expect_u64(&tuple[1], "policy.min_mode_by_action.mu_min")?)?;
        output.push((action, (release_level, mode)));
    }
    Ok(output)
}

fn decode_sorted_hash_array(
    value: &CborValue,
    name: &'static str,
) -> Result<Vec<[u8; 64]>, DaylightCryptoError> {
    let values = expect_array(value, name)?;
    let mut hashes = Vec::with_capacity(values.len());
    for value in values {
        hashes.push(expect_hash64(value, name)?);
    }
    ensure_sorted_unique_hashes(hashes.iter().copied())?;
    Ok(hashes)
}

fn decode_sorted_claim_class_array(
    value: &CborValue,
    name: &'static str,
) -> Result<Vec<u8>, DaylightCryptoError> {
    let values = expect_array(value, name)?;
    let mut output = Vec::with_capacity(values.len());
    let mut previous = None;
    for value in values {
        let class = expect_u8(value, name)?;
        if class > 7 {
            return Err(DaylightCryptoError::DecodeRejected("unknown claim class"));
        }
        if previous.map(|prev| class <= prev).unwrap_or(false) {
            return Err(DaylightCryptoError::DecodeRejected(
                "array is not strictly sorted",
            ));
        }
        previous = Some(class);
        output.push(class);
    }
    Ok(output)
}

fn decode_sorted_array<T, F>(
    value: &CborValue,
    name: &'static str,
    decode: F,
) -> Result<Vec<T>, DaylightCryptoError>
where
    F: Fn(u64) -> Result<T, DaylightCryptoError>,
{
    let values = expect_array(value, name)?;
    let mut output = Vec::with_capacity(values.len());
    let mut previous = None;
    for value in values {
        let code = expect_u64(value, name)?;
        if previous.map(|prev| code <= prev).unwrap_or(false) {
            return Err(DaylightCryptoError::DecodeRejected(
                "array is not strictly sorted",
            ));
        }
        previous = Some(code);
        output.push(decode(code)?);
    }
    Ok(output)
}

fn leak_value_cbor_v6(leak_value: &DaylightLeakValueV6) -> CborValue {
    match leak_value {
        DaylightLeakValueV6::MetadataOnly { artifact_len } => CborValue::UInt(*artifact_len),
        DaylightLeakValueV6::PublicCommitment {
            artifact_len,
            artifact_hash,
        } => CborValue::Array(vec![
            CborValue::UInt(*artifact_len),
            CborValue::Bytes(artifact_hash.to_vec()),
        ]),
        DaylightLeakValueV6::ReviewedContent {
            artifact_len,
            review_commit,
        } => CborValue::Array(vec![
            CborValue::UInt(*artifact_len),
            CborValue::Bytes(review_commit.to_vec()),
        ]),
    }
}

fn decode_leak_value_v6(
    value: &CborValue,
    content_scope: DaylightContentScopeV6,
) -> Result<DaylightLeakValueV6, DaylightCryptoError> {
    match content_scope {
        DaylightContentScopeV6::MetadataOnly => Ok(DaylightLeakValueV6::MetadataOnly {
            artifact_len: expect_u64(value, "header.leak_value")?,
        }),
        DaylightContentScopeV6::PublicCommitment => {
            let items = expect_array_len(value, "header.leak_value", 2)?;
            Ok(DaylightLeakValueV6::PublicCommitment {
                artifact_len: expect_u64(&items[0], "header.leak_value.artifact_len")?,
                artifact_hash: expect_hash64(&items[1], "header.leak_value.artifact_hash")?,
            })
        }
        DaylightContentScopeV6::ReviewedContent => {
            let items = expect_array_len(value, "header.leak_value", 2)?;
            Ok(DaylightLeakValueV6::ReviewedContent {
                artifact_len: expect_u64(&items[0], "header.leak_value.artifact_len")?,
                review_commit: expect_hash64(&items[1], "header.leak_value.review_commit")?,
            })
        }
    }
}

fn option_obj_to_cbor(value: &Option<CborValue>) -> CborValue {
    value.clone().unwrap_or(CborValue::Null)
}

fn option_obj_from_cbor(value: &CborValue) -> Option<CborValue> {
    if matches!(value, CborValue::Null) {
        None
    } else {
        Some(value.clone())
    }
}

fn profile_code(profile: Profile) -> u64 {
    match profile {
        Profile::D2Hybrid => 1,
        Profile::D3Root => 2,
        Profile::D2HybridFrost => 3,
    }
}

fn decode_profile_code(value: u64) -> Result<Profile, DaylightCryptoError> {
    match value {
        1 => Ok(Profile::D2Hybrid),
        2 => Ok(Profile::D3Root),
        3 => Ok(Profile::D2HybridFrost),
        _ => Err(DaylightCryptoError::DecodeRejected("unknown profile")),
    }
}

fn mode_code(mode: Mode) -> u64 {
    match mode {
        Mode::Hybrid => 1,
        Mode::PqStrict => 2,
        Mode::Compact => 0,
    }
}

fn decode_mode_code(value: u64) -> Result<Mode, DaylightCryptoError> {
    match value {
        1 => Ok(Mode::Hybrid),
        2 => Ok(Mode::PqStrict),
        _ => Err(DaylightCryptoError::DecodeRejected("unknown mode")),
    }
}

fn action_code(action: Action) -> u64 {
    match action {
        Action::Research => 0,
        Action::Proof => 1,
        Action::Open => 2,
        Action::Release => 3,
        Action::Install => 4,
        Action::RootRotate => 5,
        Action::AuditAccept => 6,
    }
}

fn decode_action_code(value: u64) -> Result<Action, DaylightCryptoError> {
    match value {
        0 => Ok(Action::Research),
        1 => Ok(Action::Proof),
        2 => Ok(Action::Open),
        3 => Ok(Action::Release),
        4 => Ok(Action::Install),
        5 => Ok(Action::RootRotate),
        6 => Ok(Action::AuditAccept),
        _ => Err(DaylightCryptoError::DecodeRejected("unknown action")),
    }
}

fn content_scope_code(content_scope: DaylightContentScopeV6) -> u64 {
    match content_scope {
        DaylightContentScopeV6::MetadataOnly => 0,
        DaylightContentScopeV6::PublicCommitment => 1,
        DaylightContentScopeV6::ReviewedContent => 2,
    }
}

fn decode_content_scope_code(value: u64) -> Result<DaylightContentScopeV6, DaylightCryptoError> {
    match value {
        0 => Ok(DaylightContentScopeV6::MetadataOnly),
        1 => Ok(DaylightContentScopeV6::PublicCommitment),
        2 => Ok(DaylightContentScopeV6::ReviewedContent),
        _ => Err(DaylightCryptoError::DecodeRejected("unknown content scope")),
    }
}

fn aead_code(aead: AeadAlgorithm) -> u64 {
    match aead {
        AeadAlgorithm::Aes256Gcm => 1,
        AeadAlgorithm::ChaCha20Poly1305 => 2,
    }
}

fn decode_aead_code(value: u64) -> Result<AeadAlgorithm, DaylightCryptoError> {
    match value {
        1 => Ok(AeadAlgorithm::Aes256Gcm),
        2 => Ok(AeadAlgorithm::ChaCha20Poly1305),
        _ => Err(DaylightCryptoError::DecodeRejected(
            "unknown AEAD algorithm",
        )),
    }
}

fn conformance_code(conformance: DaylightConformanceLevelV6) -> u64 {
    match conformance {
        DaylightConformanceLevelV6::C1Open => 1,
        DaylightConformanceLevelV6::C2Root => 2,
        DaylightConformanceLevelV6::C3Audit => 3,
        DaylightConformanceLevelV6::C4Install => 4,
        DaylightConformanceLevelV6::C5Frost => 5,
    }
}

fn decode_conformance_code(value: u64) -> Result<DaylightConformanceLevelV6, DaylightCryptoError> {
    match value {
        1 => Ok(DaylightConformanceLevelV6::C1Open),
        2 => Ok(DaylightConformanceLevelV6::C2Root),
        3 => Ok(DaylightConformanceLevelV6::C3Audit),
        4 => Ok(DaylightConformanceLevelV6::C4Install),
        5 => Ok(DaylightConformanceLevelV6::C5Frost),
        _ => Err(DaylightCryptoError::DecodeRejected(
            "unknown conformance level",
        )),
    }
}

fn expect_map<'a>(
    value: &'a CborValue,
    _name: &'static str,
) -> Result<&'a [(u64, CborValue)], DaylightCryptoError> {
    match value {
        CborValue::Map(entries) => Ok(entries),
        _ => Err(DaylightCryptoError::DecodeRejected("expected CBOR map")),
    }
}

fn expect_map_exact<'a>(
    value: &'a CborValue,
    expected_keys: &[u64],
    name: &'static str,
) -> Result<&'a [(u64, CborValue)], DaylightCryptoError> {
    let entries = expect_map(value, name)?;
    if entries.len() != expected_keys.len()
        || entries
            .iter()
            .map(|(key, _)| *key)
            .ne(expected_keys.iter().copied())
    {
        return Err(DaylightCryptoError::DecodeRejected(
            "unexpected CBOR map keys",
        ));
    }
    Ok(entries)
}

fn map_get(entries: &[(u64, CborValue)], key: u64) -> Result<&CborValue, DaylightCryptoError> {
    entries
        .iter()
        .find_map(|(candidate, value)| (*candidate == key).then_some(value))
        .ok_or(DaylightCryptoError::DecodeRejected(
            "missing required CBOR map key",
        ))
}

fn expect_array<'a>(
    value: &'a CborValue,
    _name: &'static str,
) -> Result<&'a [CborValue], DaylightCryptoError> {
    match value {
        CborValue::Array(items) => Ok(items),
        _ => Err(DaylightCryptoError::DecodeRejected("expected CBOR array")),
    }
}

fn expect_array_len<'a>(
    value: &'a CborValue,
    name: &'static str,
    expected: usize,
) -> Result<&'a [CborValue], DaylightCryptoError> {
    let items = expect_array(value, name)?;
    if items.len() != expected {
        return Err(DaylightCryptoError::DecodeRejected(
            "unexpected CBOR array length",
        ));
    }
    Ok(items)
}

fn expect_text<'a>(
    value: &'a CborValue,
    _name: &'static str,
) -> Result<&'a str, DaylightCryptoError> {
    match value {
        CborValue::Text(text) => Ok(text),
        _ => Err(DaylightCryptoError::DecodeRejected("expected CBOR text")),
    }
}

fn expect_ascii_text(
    value: &CborValue,
    name: &'static str,
    min_len: usize,
    max_len: usize,
) -> Result<String, DaylightCryptoError> {
    let text = expect_text(value, name)?;
    if !text.is_ascii() || text.len() < min_len || text.len() > max_len {
        return Err(DaylightCryptoError::DecodeRejected(
            "ASCII text length out of range",
        ));
    }
    Ok(text.to_string())
}

fn expect_bytes<'a>(
    value: &'a CborValue,
    _name: &'static str,
) -> Result<&'a [u8], DaylightCryptoError> {
    match value {
        CborValue::Bytes(bytes) => Ok(bytes),
        _ => Err(DaylightCryptoError::DecodeRejected("expected CBOR bytes")),
    }
}

fn expect_hash64(value: &CborValue, name: &'static str) -> Result<[u8; 64], DaylightCryptoError> {
    expect_fixed_bytes(value, name)
}

fn expect_fixed_bytes<const N: usize>(
    value: &CborValue,
    name: &'static str,
) -> Result<[u8; N], DaylightCryptoError> {
    fixed_decode(expect_bytes(value, name)?)
        .map_err(|_| DaylightCryptoError::DecodeRejected("unexpected byte-string length"))
}

fn expect_u64(value: &CborValue, _name: &'static str) -> Result<u64, DaylightCryptoError> {
    match value {
        CborValue::UInt(value) => Ok(*value),
        _ => Err(DaylightCryptoError::DecodeRejected("expected CBOR uint")),
    }
}

fn expect_u8(value: &CborValue, name: &'static str) -> Result<u8, DaylightCryptoError> {
    u8::try_from(expect_u64(value, name)?)
        .map_err(|_| DaylightCryptoError::DecodeRejected("uint out of range"))
}

fn expect_bool(value: &CborValue, _name: &'static str) -> Result<bool, DaylightCryptoError> {
    match value {
        CborValue::Bool(value) => Ok(*value),
        _ => Err(DaylightCryptoError::DecodeRejected("expected CBOR bool")),
    }
}

fn ensure_map_keys_strictly_increasing(
    entries: &[(u64, CborValue)],
) -> Result<(), DaylightCryptoError> {
    let mut previous = None;
    for (key, _) in entries {
        if previous.map(|prev| *key <= prev).unwrap_or(false) {
            return Err(DaylightCryptoError::DecodeRejected(
                "duplicate or unsorted CBOR map key",
            ));
        }
        previous = Some(*key);
    }
    Ok(())
}

fn ensure_sorted_unique_hashes(
    hashes: impl IntoIterator<Item = [u8; 64]>,
) -> Result<(), DaylightCryptoError> {
    let mut previous = None;
    for hash in hashes {
        if previous.map(|prev| hash <= prev).unwrap_or(false) {
            return Err(DaylightCryptoError::DecodeRejected(
                "hash array is not strictly sorted",
            ));
        }
        previous = Some(hash);
    }
    Ok(())
}

fn ensure_ascii_label(label: &str) -> Result<(), DaylightCryptoError> {
    if !label.is_ascii() {
        return Err(DaylightCryptoError::InvalidParameter(
            "Daylight v6 labels must be ASCII",
        ));
    }
    Ok(())
}

fn fixed_decode<const N: usize>(input: &[u8]) -> Result<[u8; N], DaylightCryptoError> {
    input
        .try_into()
        .map_err(|_| DaylightCryptoError::InvalidLength {
            name: "fixed byte string",
            expected: N,
            actual: input.len(),
        })
}

fn shake256_v6(input: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_vector_file(input: &str) -> std::collections::BTreeMap<String, String> {
        let mut fields = std::collections::BTreeMap::new();
        for (line_index, line) in input.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("malformed vector line {}", line_index + 1));
            assert!(
                fields.insert(key.to_string(), value.to_string()).is_none(),
                "duplicate vector key {key}"
            );
        }
        fields
    }

    fn vector_field<'a>(
        fields: &'a std::collections::BTreeMap<String, String>,
        key: &str,
    ) -> &'a str {
        fields
            .get(key)
            .unwrap_or_else(|| panic!("missing vector key {key}"))
    }

    #[test]
    fn deterministic_cbor_v6_supports_maps_null_and_bool() {
        let value = CborValue::Map(vec![
            (0, CborValue::Null),
            (1, CborValue::Bool(false)),
            (2, CborValue::Array(vec![CborValue::UInt(1)])),
        ]);
        let encoded = encode_cbor_value(&value).unwrap();
        assert_eq!(
            encoded,
            vec![0xa3, 0x00, 0xf6, 0x01, 0xf4, 0x02, 0x81, 0x01]
        );
        assert_eq!(decode_cbor_value(&encoded).unwrap(), value);
        assert_eq!(
            decode_cbor_value(&[0xa2, 0x00, 0x01, 0x00, 0x02]),
            Err(DaylightCryptoError::DecodeRejected(
                "duplicate or unsorted CBOR map key"
            ))
        );
        assert_eq!(
            decode_cbor_value(&[0xbf, 0xff]),
            Err(DaylightCryptoError::DecodeRejected(
                "indefinite-length CBOR is forbidden"
            ))
        );
    }

    #[test]
    fn v6_schema_vector_roundtrips_and_rejects_before_private_open() {
        let vector = daylight_v6_schema_vector().unwrap();
        let decoded = daylight_decode_envelope_v6(&vector.omega).unwrap();
        assert_eq!(decoded, vector.envelope);
        assert_eq!(daylight_envelope_bytes_v6(&decoded).unwrap(), vector.omega);
        assert_eq!(hb_v6(&vector.transcript.t0), vector.transcript.h0);
        assert_eq!(hb_v6(&vector.transcript.t1), vector.transcript.h1);
        assert_eq!(
            daylight_vector_public_precheck_v6(&vector.omega, Some(1)),
            Err(DaylightRejectionStageV6::RejectAuthSignature)
        );
        assert!(!vector.private_kem_allowed);
        assert!(!vector.aead_dec_allowed);
    }

    #[test]
    fn v6_aux_hash_policy_and_claim_failures_are_ordered() {
        let vector = daylight_v6_schema_vector().unwrap();
        let mut bad_aux_hash = vector.envelope.clone();
        bad_aux_hash.header.policy_hash[0] ^= 0x80;
        assert_eq!(
            daylight_vector_public_precheck_v6(
                &daylight_envelope_bytes_v6(&bad_aux_hash).unwrap(),
                Some(1)
            ),
            Err(DaylightRejectionStageV6::RejectAuxHash)
        );

        let mut bad_policy = vector.envelope.clone();
        let mut policy = DaylightPolicyV6::from_cbor(&bad_policy.aux_block.policy_obj).unwrap();
        policy.allowed_actions = vec![Action::Research, Action::Proof];
        bad_policy.aux_block.policy_obj = policy.to_cbor();
        bad_policy.header.policy_hash = hc_v6(&bad_policy.aux_block.policy_obj).unwrap();
        assert_eq!(
            daylight_vector_public_precheck_v6(
                &daylight_envelope_bytes_v6(&bad_policy).unwrap(),
                Some(1)
            ),
            Err(DaylightRejectionStageV6::RejectPolicy)
        );

        let mut bad_claim = vector.envelope.clone();
        bad_claim.aux_block.claims_obj = CborValue::Array(vec![claim_value_v6(
            7,
            "root-claim-too-early",
            CborValue::Bool(true),
        )]);
        bad_claim.header.claims_hash = hc_v6(&bad_claim.aux_block.claims_obj).unwrap();
        assert_eq!(
            daylight_vector_public_precheck_v6(
                &daylight_envelope_bytes_v6(&bad_claim).unwrap(),
                Some(1)
            ),
            Err(DaylightRejectionStageV6::RejectClaims)
        );
    }

    #[test]
    fn v6_digest_convention_distinguishes_raw_transcript_from_object_hash() {
        let vector = daylight_v6_schema_vector().unwrap();
        let h0 = hb_v6(&vector.transcript.t0);
        let object_hash_of_t0_bytes =
            hc_v6(&CborValue::Bytes(vector.transcript.t0.clone())).unwrap();
        assert_eq!(h0, vector.transcript.h0);
        assert_ne!(h0, object_hash_of_t0_bytes);
    }

    #[test]
    fn v6_kdf_and_schedule_labels_are_version_separated() {
        let vector = daylight_v6_schema_vector().unwrap();
        let kem_context = daylight_kem_context_v6(
            &vector.envelope.header,
            &vector.transcript.h0,
            &vector.envelope.kem_block,
        )
        .unwrap();
        let schedule = daylight_key_schedule_v6(
            &[0x22; 32],
            &[0x33; DHKEM_P384_SHARED_SECRET_LEN],
            &kem_context,
            &vector.transcript.h0,
            &vector.transcript.kem_hash,
            &vector.envelope.header,
            &vector.envelope.kem_block,
        )
        .unwrap();
        assert_ne!(schedule.envelope_key, schedule.commitment_key);
        assert_eq!(schedule.base_nonce.len(), 12);

        let left = kdf2_v6(
            &schedule.commitment_key,
            "daylight.artifact.commit.v6",
            &CborValue::Bytes(b"input".to_vec()),
            32,
        )
        .unwrap();
        let right = kdf2_v6(
            &schedule.commitment_key,
            "daylight.other.v6",
            &CborValue::Bytes(b"input".to_vec()),
            32,
        )
        .unwrap();
        assert_ne!(left, right);
    }

    #[test]
    fn v6_provider_kem_evidence_uses_real_kems_and_stays_non_open() {
        let evidence = daylight_v6_provider_kem_evidence().unwrap();
        assert!(evidence.provider_backed_kem);
        assert!(!evidence.provider_backed_reference_seal_open);
        assert!(!evidence.production_allowed);
        assert!(evidence.mlkem1024_decaps_matches);
        assert!(evidence.dhkem_p384_decaps_matches);
        assert_ne!(
            evidence.key_schedule.envelope_key,
            evidence.key_schedule.commitment_key
        );
        assert_eq!(evidence.key_schedule.base_nonce.len(), 12);
        assert_ne!(evidence.ss_q_hash, hb_v6(&[0u8; 32]));
        assert_ne!(
            evidence.ss_c_hash,
            hb_v6(&[0u8; DHKEM_P384_SHARED_SECRET_LEN])
        );
        assert_eq!(
            daylight_vector_public_precheck_v6(&evidence.schema_vector.omega, Some(1)),
            Err(DaylightRejectionStageV6::RejectAuthSignature)
        );
        assert!(!evidence.schema_vector.private_kem_allowed);
        assert!(!evidence.schema_vector.aead_dec_allowed);
    }

    #[test]
    fn v6_provider_private_roundtrip_opens_only_after_prechecked_private_path() {
        let evidence = daylight_v6_provider_private_roundtrip_evidence().unwrap();
        assert!(evidence.provider_backed_private_roundtrip);
        assert!(!evidence.provider_backed_reference_seal_open);
        assert!(!evidence.production_allowed);
        assert!(evidence.opened_artifact_matches);
        assert!(evidence.commitment_matches);
        assert!(evidence.aead_roundtrip_matches);
        assert_eq!(
            evidence.public_precheck_rejection_stage,
            DaylightRejectionStageV6::RejectAuthSignature
        );
        assert_eq!(
            daylight_vector_public_precheck_v6(&evidence.omega, Some(1)),
            Err(DaylightRejectionStageV6::RejectAuthSignature)
        );
        assert_ne!(evidence.ciphertext_hash, hb_v6(&[]));
        assert_ne!(evidence.envelope.com_a, [0u8; 32]);
    }

    #[test]
    fn v6_reference_seal_open_uses_external_nonproduction_precheck() {
        let evidence = daylight_v6_reference_seal_open_evidence().unwrap();
        assert!(evidence.provider_backed_reference_seal_open);
        assert!(evidence.public_authority_external);
        assert!(!evidence.production_allowed);
        assert!(evidence.opened_artifact_matches);
        assert_eq!(
            evidence.public_precheck_rejection_stage,
            DaylightRejectionStageV6::RejectAuthSignature
        );
        assert_eq!(
            daylight_vector_public_precheck_v6(&evidence.omega, Some(1)),
            Err(DaylightRejectionStageV6::RejectAuthSignature)
        );
    }

    #[test]
    fn v6_reference_open_fails_closed_on_precheck_and_private_mutations() {
        let schema_vector = daylight_v6_schema_vector().unwrap();
        let mlkem = mlkem1024_kat_fixture().unwrap();
        let dhkem_recipient =
            dhkem_p384_hkdf_sha384_derive_keypair(DAYLIGHT_V6_SCHEMA_DHKEM_RECIPIENT_IKM).unwrap();
        let recipient_public = DaylightRecipientPublicKeysV6 {
            mlkem_encaps_key: mlkem.encaps_key.clone(),
            dhkem_public_key: dhkem_recipient.public_key,
        };
        let recipient_secret = DaylightRecipientSecretKeysV6 {
            mlkem_decaps_key: mlkem.decaps_key,
            dhkem_private_key: dhkem_recipient.private_key,
        };
        let kem_inputs = DaylightSealKemInputsV6 {
            mlkem_encaps_seed: [0x52; 32],
            dhkem_ephemeral_ikm: b"daylight v6 reference seal open ephemeral".to_vec(),
        };
        let kem_key_ids = DaylightKemKeyIdsV6 {
            q_kem_key_id: schema_vector.envelope.kem_block.q_kem_key_id,
            c_kem_key_id: schema_vector.envelope.kem_block.c_kem_key_id,
        };
        let envelope = daylight_seal_v6_with_kems_from_seed(
            schema_vector.envelope.header.clone(),
            schema_vector.envelope.auth_block.clone(),
            schema_vector.envelope.aux_block.clone(),
            kem_key_ids,
            &recipient_public,
            &kem_inputs,
            DAYLIGHT_V6_SCHEMA_ARTIFACT,
            None,
        )
        .unwrap();
        let precheck = DaylightReferencePrecheckV6::nonproduction_all_passed();
        let opened =
            daylight_open_v6_with_kems(&envelope, &recipient_secret, &precheck, Some(1)).unwrap();
        assert_eq!(opened.artifact, DAYLIGHT_V6_SCHEMA_ARTIFACT);

        let mut bad_precheck = precheck.clone();
        bad_precheck.auth_signature_ok = false;
        assert_eq!(
            daylight_open_v6_with_kems(&envelope, &recipient_secret, &bad_precheck, Some(1)),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::AuthQ
            ))
        );

        let mut production_precheck = precheck.clone();
        production_precheck.production_allowed = true;
        assert_eq!(
            daylight_open_v6_with_kems(&envelope, &recipient_secret, &production_precheck, Some(1)),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Gate))
        );

        let mut bad_ciphertext = envelope.clone();
        bad_ciphertext.ciphertext[0] ^= 0x80;
        assert_eq!(
            daylight_open_v6_with_kems(&bad_ciphertext, &recipient_secret, &precheck, Some(1)),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Aead))
        );

        let mut bad_commitment = envelope;
        bad_commitment.com_a[0] ^= 0x80;
        assert_eq!(
            daylight_open_v6_with_kems(&bad_commitment, &recipient_secret, &precheck, Some(1)),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::Commit
            ))
        );
    }

    #[test]
    fn v6_schema_vector_file_matches_implementation() {
        let fields = parse_vector_file(include_str!("../vectors/daylight-v6-schema-vector-v1.txt"));
        let vector = daylight_v6_schema_vector().unwrap();
        assert_eq!(
            vector_field(&fields, "version"),
            "daylight-v6-schema-vector-v1"
        );
        assert_eq!(vector_field(&fields, "conformance_level"), "C1-OPEN");
        assert_eq!(vector_field(&fields, "expected_result"), "bottom");
        assert_eq!(
            vector_field(&fields, "expected_rejection_stage"),
            vector.expected_rejection_stage.as_str()
        );
        assert_eq!(
            vector_field(&fields, "private_kem_allowed"),
            vector.private_kem_allowed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "aead_dec_allowed"),
            vector.aead_dec_allowed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "omega_cbor_hex"),
            crate::hex_lower(&vector.omega)
        );
        assert_eq!(
            vector_field(&fields, "header_cbor_hex"),
            crate::hex_lower(&vector.header_bytes)
        );
        assert_eq!(
            vector_field(&fields, "kem_block_cbor_hex"),
            crate::hex_lower(&vector.kem_block_bytes)
        );
        assert_eq!(
            vector_field(&fields, "auth_block_cbor_hex"),
            crate::hex_lower(&vector.auth_block_bytes)
        );
        assert_eq!(
            vector_field(&fields, "aux_block_cbor_hex"),
            crate::hex_lower(&vector.aux_block_bytes)
        );
        assert_eq!(
            vector_field(&fields, "T0_hex"),
            crate::hex_lower(&vector.transcript.t0)
        );
        assert_eq!(
            vector_field(&fields, "h0_hex"),
            crate::hex_lower(&vector.transcript.h0)
        );
        assert_eq!(
            vector_field(&fields, "kem_hash_hex"),
            crate::hex_lower(&vector.transcript.kem_hash)
        );
        assert_eq!(
            vector_field(&fields, "cipher_hash_hex"),
            crate::hex_lower(&vector.transcript.cipher_hash)
        );
        assert_eq!(
            vector_field(&fields, "review_receipt_hash_hex"),
            crate::hex_lower(&vector.transcript.review_receipt_hash)
        );
        assert_eq!(
            vector_field(&fields, "T1_hex"),
            crate::hex_lower(&vector.transcript.t1)
        );
        assert_eq!(
            vector_field(&fields, "h1_hex"),
            crate::hex_lower(&vector.transcript.h1)
        );
        assert_eq!(
            vector_field(&fields, "AuthMsg_hex"),
            crate::hex_lower(&vector.transcript.auth_msg)
        );
    }

    #[test]
    fn v6_provider_kem_evidence_file_matches_implementation() {
        let fields = parse_vector_file(include_str!(
            "../vectors/daylight-v6-provider-kem-evidence-v1.txt"
        ));
        let evidence = daylight_v6_provider_kem_evidence().unwrap();
        assert_eq!(
            vector_field(&fields, "version"),
            "daylight-v6-provider-kem-evidence-v1"
        );
        assert_eq!(
            vector_field(&fields, "profile"),
            "fixture-only-provider-kem"
        );
        assert_eq!(vector_field(&fields, "expected_result"), "not_open");
        assert_eq!(
            vector_field(&fields, "provider_backed_kem"),
            evidence.provider_backed_kem.to_string()
        );
        assert_eq!(
            vector_field(&fields, "provider_backed_reference_seal_open"),
            evidence.provider_backed_reference_seal_open.to_string()
        );
        assert_eq!(
            vector_field(&fields, "production_allowed"),
            evidence.production_allowed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "schema_expected_rejection_stage"),
            evidence.schema_vector.expected_rejection_stage.as_str()
        );
        assert_eq!(
            vector_field(&fields, "schema_private_kem_allowed"),
            evidence.schema_vector.private_kem_allowed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "schema_aead_dec_allowed"),
            evidence.schema_vector.aead_dec_allowed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "mlkem1024_decaps_matches"),
            evidence.mlkem1024_decaps_matches.to_string()
        );
        assert_eq!(
            vector_field(&fields, "dhkem_p384_decaps_matches"),
            evidence.dhkem_p384_decaps_matches.to_string()
        );
        assert_eq!(
            vector_field(&fields, "h0_hex"),
            crate::hex_lower(&evidence.schema_vector.transcript.h0)
        );
        assert_eq!(
            vector_field(&fields, "kem_hash_hex"),
            crate::hex_lower(&evidence.schema_vector.transcript.kem_hash)
        );
        assert_eq!(
            vector_field(&fields, "kem_context_sha3_512_hex"),
            crate::hex_lower(&evidence.kem_context_hash)
        );
        assert_eq!(
            vector_field(&fields, "ss_q_sha3_512_hex"),
            crate::hex_lower(&evidence.ss_q_hash)
        );
        assert_eq!(
            vector_field(&fields, "ss_c_sha3_512_hex"),
            crate::hex_lower(&evidence.ss_c_hash)
        );
        assert_eq!(
            vector_field(&fields, "envelope_key_sha3_512_hex"),
            crate::hex_lower(&evidence.envelope_key_hash)
        );
        assert_eq!(
            vector_field(&fields, "commitment_key_sha3_512_hex"),
            crate::hex_lower(&evidence.commitment_key_hash)
        );
        assert_eq!(
            vector_field(&fields, "base_nonce_sha3_512_hex"),
            crate::hex_lower(&evidence.base_nonce_hash)
        );
        assert_eq!(
            vector_field(&fields, "enc_q_sha3_512_hex"),
            crate::hex_lower(&evidence.enc_q_hash)
        );
        assert_eq!(
            vector_field(&fields, "enc_c_sha3_512_hex"),
            crate::hex_lower(&evidence.enc_c_hash)
        );
    }

    #[test]
    fn v6_provider_private_roundtrip_evidence_file_matches_implementation() {
        let fields = parse_vector_file(include_str!(
            "../vectors/daylight-v6-provider-private-roundtrip-evidence-v1.txt"
        ));
        let evidence = daylight_v6_provider_private_roundtrip_evidence().unwrap();
        assert_eq!(
            vector_field(&fields, "version"),
            "daylight-v6-provider-private-roundtrip-evidence-v1"
        );
        assert_eq!(
            vector_field(&fields, "profile"),
            "fixture-only-provider-private-roundtrip"
        );
        assert_eq!(
            vector_field(&fields, "expected_result"),
            "private_roundtrip_only"
        );
        assert_eq!(
            vector_field(&fields, "provider_backed_private_roundtrip"),
            evidence.provider_backed_private_roundtrip.to_string()
        );
        assert_eq!(
            vector_field(&fields, "provider_backed_reference_seal_open"),
            evidence.provider_backed_reference_seal_open.to_string()
        );
        assert_eq!(
            vector_field(&fields, "production_allowed"),
            evidence.production_allowed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_precheck_rejection_stage"),
            evidence.public_precheck_rejection_stage.as_str()
        );
        assert_eq!(
            vector_field(&fields, "opened_artifact_matches"),
            evidence.opened_artifact_matches.to_string()
        );
        assert_eq!(
            vector_field(&fields, "commitment_matches"),
            evidence.commitment_matches.to_string()
        );
        assert_eq!(
            vector_field(&fields, "aead_roundtrip_matches"),
            evidence.aead_roundtrip_matches.to_string()
        );
        assert_eq!(
            vector_field(&fields, "artifact_sha3_512_hex"),
            crate::hex_lower(&evidence.artifact_hash)
        );
        assert_eq!(
            vector_field(&fields, "opened_artifact_sha3_512_hex"),
            crate::hex_lower(&evidence.opened_artifact_hash)
        );
        assert_eq!(
            vector_field(&fields, "private_payload_cbor_sha3_512_hex"),
            crate::hex_lower(&evidence.private_payload_hash)
        );
        assert_eq!(
            vector_field(&fields, "ciphertext_sha3_512_hex"),
            crate::hex_lower(&evidence.ciphertext_hash)
        );
        assert_eq!(
            vector_field(&fields, "nonce_sha3_512_hex"),
            crate::hex_lower(&evidence.nonce_hash)
        );
        assert_eq!(
            vector_field(&fields, "com_a_hex"),
            crate::hex_lower(&evidence.envelope.com_a)
        );
        assert_eq!(
            vector_field(&fields, "com_a_sha3_512_hex"),
            crate::hex_lower(&evidence.com_a_hash)
        );
        assert_eq!(
            vector_field(&fields, "h1_hex"),
            crate::hex_lower(&evidence.transcript.h1)
        );
        assert_eq!(
            vector_field(&fields, "AuthMsg_hex"),
            crate::hex_lower(&evidence.transcript.auth_msg)
        );
    }

    #[test]
    fn v6_reference_seal_open_evidence_file_matches_implementation() {
        let fields = parse_vector_file(include_str!(
            "../vectors/daylight-v6-reference-seal-open-evidence-v1.txt"
        ));
        let evidence = daylight_v6_reference_seal_open_evidence().unwrap();
        assert_eq!(
            vector_field(&fields, "version"),
            "daylight-v6-reference-seal-open-evidence-v1"
        );
        assert_eq!(
            vector_field(&fields, "profile"),
            "nonproduction-external-public-precheck"
        );
        assert_eq!(
            vector_field(&fields, "expected_result"),
            "reference_seal_open"
        );
        assert_eq!(
            vector_field(&fields, "provider_backed_reference_seal_open"),
            evidence.provider_backed_reference_seal_open.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_authority_external"),
            evidence.public_authority_external.to_string()
        );
        assert_eq!(
            vector_field(&fields, "production_allowed"),
            evidence.production_allowed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_precheck_rejection_stage"),
            evidence.public_precheck_rejection_stage.as_str()
        );
        assert_eq!(
            vector_field(&fields, "opened_artifact_matches"),
            evidence.opened_artifact_matches.to_string()
        );
        assert_eq!(
            vector_field(&fields, "artifact_sha3_512_hex"),
            crate::hex_lower(&evidence.artifact_hash)
        );
        assert_eq!(
            vector_field(&fields, "opened_artifact_sha3_512_hex"),
            crate::hex_lower(&evidence.opened_artifact_hash)
        );
        assert_eq!(
            vector_field(&fields, "ciphertext_sha3_512_hex"),
            crate::hex_lower(&evidence.ciphertext_hash)
        );
        assert_eq!(
            vector_field(&fields, "com_a_hex"),
            crate::hex_lower(&evidence.envelope.com_a)
        );
        assert_eq!(
            vector_field(&fields, "com_a_sha3_512_hex"),
            crate::hex_lower(&evidence.com_a_hash)
        );
        assert_eq!(
            vector_field(&fields, "auth_msg_sha3_512_hex"),
            crate::hex_lower(&evidence.auth_msg_hash)
        );
        assert_eq!(
            vector_field(&fields, "h1_hex"),
            crate::hex_lower(&evidence.opened.transcript.h1)
        );
        assert_eq!(
            vector_field(&fields, "AuthMsg_hex"),
            crate::hex_lower(&evidence.opened.auth_msg)
        );
    }
}
