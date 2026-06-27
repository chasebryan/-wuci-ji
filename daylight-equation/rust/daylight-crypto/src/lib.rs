//! Defensive Daylight Equation crypto helpers.
//!
//! This crate implements the hash, cSHAKE/KMAC derivation, and ML-DSA-87
//! verification pieces that can be pinned locally. Missing Daylight primitives
//! are explicit unsupported/fail-closed surfaces, not permissive stubs.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::ChaCha20Poly1305;
use daylight_model::{
    action_allowed, claim_allowed, mode_ok, Action, AuthPrimitive, Claim, Mode, Profile,
};
use fips203::ml_kem_1024;
use fips203::traits::{
    Decaps as KemDecaps, Encaps as KemEncaps, KeyGen as KemKeyGen, SerDes as KemSerDes,
};
use fips204::ml_dsa_87;
use fips204::traits::{
    KeyGen as MlDsaKeyGen, SerDes as MlDsaSerDes, Signer as MlDsaSigner, Verifier as MlDsaVerifier,
};
use fips205::slh_dsa_shake_256s;
use fips205::traits::{
    KeyGen as SlhDsaKeyGen, SerDes as SlhDsaSerDes, Signer as SlhDsaSigner,
    Verifier as SlhDsaVerifier,
};
use hkdf::Hkdf;
use p384::ecdh::diffie_hellman as p384_diffie_hellman;
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::{PublicKey as P384PublicKey, SecretKey as P384SecretKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as Sha2Digest, Sha384, Sha512};
use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256Core, Sha3_512, Shake256};

pub const DAYLIGHT_HASH_CUSTOMIZATION: &[u8] = b"wuci/daylight/hash/v1";
pub const DAYLIGHT_AUTH_FUNCTION: &[u8] = b"WUCI-DAYLIGHT";
pub const DAYLIGHT_PRE_ENVELOPE_CUSTOMIZATION: &[u8] = b"pre-envelope/v1";
pub const DAYLIGHT_AUTH_CUSTOMIZATION: &[u8] = b"authorization/v1";
pub const DAYLIGHT_KEM_COMBINE_CUSTOMIZATION: &[u8] = b"wuci/daylight/kem-combine/v1";
pub const DAYLIGHT_KEY_SCHEDULE_CUSTOMIZATION: &[u8] = b"wuci/daylight/key-schedule/v1";
pub const DAYLIGHT_ARTIFACT_COMMIT_CUSTOMIZATION: &[u8] = b"artifact-commit/v1";
pub const DAYLIGHT_AUTH_CONTEXT: &[u8] = b"WUCI-DAYLIGHT:authorization:v1";
pub const DAYLIGHT_AUTH_CONTEXT_V2: &[u8] = b"WUCI-DAYLIGHT:authorization:v2";
pub const DAYLIGHT_AUTH_CONTEXT_V4: &[u8] = b"WUCI-DAYLIGHT:AUTH:v4";
pub const DAYLIGHT_KDF_CUSTOMIZATION_V2: &[u8] = b"daylight-kdf-v2";
pub const DHKEM_P384_SHARED_SECRET_LEN: usize = 48;
pub const DHKEM_P384_ENCAPSULATED_KEY_LEN: usize = 97;
pub const DHKEM_P384_PRIVATE_KEY_LEN: usize = 48;
pub const DHKEM_P384_PUBLIC_KEY_LEN: usize = 97;
pub const DHKEM_P384_KEM_ID: u16 = 0x0011;
pub const DAYLIGHT_NONCE_LEN: usize = 12;

const CSHAKE256_RATE_BYTES: usize = 136;
const DAYLIGHT_HASH_LEN: usize = 64;
const DAYLIGHT_KEM_COMBINE_LEN: usize = 64;
const DAYLIGHT_KEY_COUNT: usize = 6;
const DAYLIGHT_KEY_LEN: usize = 32;
const DAYLIGHT_KEY_SCHEDULE_LEN: usize = DAYLIGHT_KEY_COUNT * DAYLIGHT_KEY_LEN + DAYLIGHT_NONCE_LEN;
const DAYLIGHT_V2_KEY_SCHEDULE_LEN: usize = 5 * DAYLIGHT_KEY_LEN + DAYLIGHT_NONCE_LEN;
const NONCE_SEQUENCE_LIMIT: u128 = 1u128 << 96;
const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";
const DHKEM_P384_SUITE_ID: [u8; 5] = [b'K', b'E', b'M', 0x00, 0x11];
const MLKEM1024_KAT_D_SEED: [u8; 32] = *b"WJ-DAYLIGHT-MLKEM1024-D-SEED!!!!";
const MLKEM1024_KAT_Z_SEED: [u8; 32] = *b"WJ-DAYLIGHT-MLKEM1024-Z-SEED!!!!";
const MLKEM1024_KAT_M_SEED: [u8; 32] = *b"WJ-DAYLIGHT-MLKEM1024-M-SEED!!!!";
const MLDSA87_KAT_KEY_SEED: [u8; 32] = *b"WUCI-DAYLIGHT-MLDSA87-KAT-KEY!!!";
const MLDSA87_KAT_SIGN_SEED: [u8; 32] = *b"WUCI-DAYLIGHT-MLDSA87-KAT-SIG!!!";
const MLDSA87_KAT_MESSAGE: &[u8] = b"wuci daylight ml-dsa-87 verifier kat v1\n";
const SLHDSA_SHAKE_256S_SK_SEED: [u8; 32] = *b"WJ-DAYLIGHT-SLH256-SK-SEED!!!!!!";
const SLHDSA_SHAKE_256S_SK_PRF: [u8; 32] = *b"WJ-DAYLIGHT-SLH256-SK-PRF!!!!!!!";
const SLHDSA_SHAKE_256S_PK_SEED: [u8; 32] = *b"WJ-DAYLIGHT-SLH256-PK-SEED!!!!!!";
const SLHDSA_SHAKE_256S_SIGN_SEED: [u8; 32] = *b"WJ-DAYLIGHT-SLH256-SIGN-SEED!!!!";
const SLHDSA_SHAKE_256S_KAT_MESSAGE: &[u8] = b"wuci daylight slh-dsa-shake-256s verifier kat v1\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedPrimitive {
    FrostCustomP384Sha384,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaylightCryptoError {
    EncodingTooLarge,
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidPublicKey,
    InvalidEncapsulationKey,
    InvalidDecapsulationKey,
    InvalidCiphertext,
    ContextTooLong {
        actual: usize,
    },
    EncapsulationFailed,
    DecapsulationFailed,
    SigningFailed,
    AeadRejected,
    KdfRejected,
    DecodeRejected(&'static str),
    InvalidParameter(&'static str),
    VerificationRejected,
    OpenRejected(DaylightOpenFailure),
    Unsupported(UnsupportedPrimitive),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestVector {
    pub sha2_512: [u8; 64],
    pub sha3_512: [u8; 64],
    pub shake256_512: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightKeySchedule {
    pub envelope_key: [u8; 32],
    pub artifact_commit_key: [u8; 32],
    pub ratchet_key: [u8; 32],
    pub witness_key: [u8; 32],
    pub ledger_key: [u8; 32],
    pub auxiliary_key: [u8; 32],
    pub base_nonce: [u8; 12],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightKeyScheduleV2 {
    pub envelope_key: [u8; 32],
    pub artifact_commit_key: [u8; 32],
    pub auth_key: [u8; 32],
    pub log_key: [u8; 32],
    pub export_key: [u8; 32],
    pub base_nonce: [u8; 12],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightKeyScheduleV4 {
    pub envelope_key: [u8; 32],
    pub commitment_key: [u8; 32],
    pub base_nonce: [u8; 12],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightSealKemInputsV4 {
    pub mlkem_encaps_seed: [u8; 32],
    pub dhkem_ephemeral_ikm: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightRecipientPublicKeysV4 {
    pub mlkem_encaps_key: Vec<u8>,
    pub dhkem_public_key: [u8; DHKEM_P384_PUBLIC_KEY_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightRecipientSecretKeysV4 {
    pub mlkem_decaps_key: Vec<u8>,
    pub dhkem_private_key: [u8; DHKEM_P384_PRIVATE_KEY_LEN],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaylightContentScopeV4 {
    MetadataOnly,
    PublicCommitment,
    ReviewedContent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaylightLeakValueV2 {
    LengthOnly(u64),
    PublicCommitment { len: u64, artifact_hash: [u8; 64] },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaylightLeakValueV4 {
    LengthOnly(u64),
    PublicCommitment { len: u64, artifact_hash: [u8; 64] },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightHeaderV2 {
    pub version: u16,
    pub suite_id: [u8; 64],
    pub profile: Profile,
    pub release_level: u8,
    pub mode: Mode,
    pub action: Action,
    pub leak_value: DaylightLeakValueV2,
    pub policy_id: Vec<u8>,
    pub policy_root: [u8; 64],
    pub keyset_hash: [u8; 64],
    pub prev_log_head: [u8; 64],
    pub provenance_hash: [u8; 64],
    pub install_manifest_hash: [u8; 64],
    pub claims_hash: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightEnvelopeV2 {
    pub header: DaylightHeaderV2,
    pub claims: Vec<Claim>,
    pub algorithm: AeadAlgorithm,
    pub enc_q: Vec<u8>,
    pub enc_c: [u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    pub ciphertext: Vec<u8>,
    pub commitment: [u8; 32],
    pub record_index: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightHeaderV4 {
    pub version: u16,
    pub suite_id: [u8; 64],
    pub profile: Profile,
    pub release_level: u8,
    pub mode: Mode,
    pub action: Action,
    pub content_scope: DaylightContentScopeV4,
    pub leak_value: DaylightLeakValueV4,
    pub policy_id: Vec<u8>,
    pub policy_hash: [u8; 64],
    pub keyset_hash: [u8; 64],
    pub prev_log_head: [u8; 64],
    pub provenance_hash: [u8; 64],
    pub install_manifest_hash: [u8; 64],
    pub claims_hash: [u8; 64],
    pub review_receipt_hash: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightEnvelopeV4 {
    pub header: DaylightHeaderV4,
    pub claims: Vec<Claim>,
    pub algorithm: AeadAlgorithm,
    pub enc_q: Vec<u8>,
    pub enc_c: [u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    pub ciphertext: Vec<u8>,
    pub commitment: [u8; 32],
    pub record_index: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightPrecheckEvidenceV2 {
    pub parse_ok: bool,
    pub env_ok: bool,
    pub policy_ok: bool,
    pub gate_ok: bool,
    pub provenance_ok: bool,
    pub install_ok: bool,
    pub witness_ok: bool,
    pub log_ok: bool,
    pub log_monotone_ok: bool,
    pub no_downgrade_ok: bool,
    pub auth_q_ok: bool,
    pub auth_h_ok: bool,
    pub auth_f_ok: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightOpenReportV2 {
    pub artifact: Vec<u8>,
    pub t0: Vec<u8>,
    pub t1: Vec<u8>,
    pub auth_msg: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaylightV4ReferenceVector {
    pub artifact: Vec<u8>,
    pub envelope: DaylightEnvelopeV4,
    pub recipient_secret_keys: DaylightRecipientSecretKeysV4,
    pub prechecks: DaylightPrecheckEvidenceV2,
    pub envelope_bytes: Vec<u8>,
    pub header_bytes: Vec<u8>,
    pub t0: Vec<u8>,
    pub t1: Vec<u8>,
    pub auth_msg: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaylightOpenFailure {
    Parse,
    Suite,
    Env,
    Mode,
    Policy,
    Gate,
    Provenance,
    Install,
    Witness,
    Log,
    LogMonotone,
    Claim,
    NoDowngrade,
    AuthQ,
    AuthH,
    AuthFUnsupported,
    Nonce,
    Derive,
    Aead,
    Commit,
    Leak,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhkemP384HkdfSha384Keypair {
    pub private_key: [u8; DHKEM_P384_PRIVATE_KEY_LEN],
    pub public_key: [u8; DHKEM_P384_PUBLIC_KEY_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhkemP384HkdfSha384Encapsulation {
    pub shared_secret: [u8; DHKEM_P384_SHARED_SECRET_LEN],
    pub encapped_key: [u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlKem1024Kat {
    pub encaps_key: Vec<u8>,
    pub decaps_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub shared_secret: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlDsa87Kat {
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlhDsaShake256sKat {
    pub public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimitiveStatus {
    pub name: &'static str,
    pub implemented: bool,
    pub note: &'static str,
}

pub fn primitive_statuses() -> &'static [PrimitiveStatus] {
    &[
        PrimitiveStatus {
            name: "SHA2-512/SHA3-512/SHAKE256-512 digest vector",
            implemented: true,
            note: "implemented through pinned sha2/sha3 crates",
        },
        PrimitiveStatus {
            name: "SP800-185 cSHAKE256/TupleHash256/KMAC256 derivation",
            implemented: true,
            note: "implemented over sha3 cSHAKE256 with local encoding tests",
        },
        PrimitiveStatus {
            name: "AES-256-GCM",
            implemented: true,
            note: "implemented through pinned aes-gcm 0.10.3; caller supplies nonce",
        },
        PrimitiveStatus {
            name: "ChaCha20-Poly1305",
            implemented: true,
            note: "implemented through pinned chacha20poly1305 0.10.1; caller supplies nonce",
        },
        PrimitiveStatus {
            name: "ML-KEM-1024 encaps/decaps",
            implemented: true,
            note: "implemented through pinned fips203 0.4.3 with deterministic KAT",
        },
        PrimitiveStatus {
            name: "ML-DSA-87 verify",
            implemented: true,
            note: "implemented through pinned fips204 0.4.6 verifier",
        },
        PrimitiveStatus {
            name: "SLH-DSA-SHAKE-256s verify",
            implemented: true,
            note: "implemented through pinned fips205 0.4.1 verifier",
        },
        PrimitiveStatus {
            name: "DHKEM(P-384,HKDF-SHA384)",
            implemented: true,
            note: "KEM-only RFC 9180 lane over pinned p384 0.13.1 and hkdf 0.12.4",
        },
        PrimitiveStatus {
            name: "Argon2id",
            implemented: true,
            note: "implemented through pinned argon2 0.5.3 with caller-supplied parameters",
        },
        PrimitiveStatus {
            name: "Daylight Minimal Core v4 seal/open",
            implemented: true,
            note: "fail-closed v0.4 surface with deterministic-CBOR header/envelope decoding, HKDF-SHA512, ML-KEM+DHKEM-derived key schedules, caller-supplied RNG seal API, and persisted positive/negative seed vectors; real auth/log/witness integration remains external precheck evidence",
        },
        PrimitiveStatus {
            name: "FROST_custom(P-384,SHA-384)",
            implemented: false,
            note: "unsupported; RFC 9591 does not define this ciphersuite",
        },
    ]
}

pub fn unsupported(primitive: UnsupportedPrimitive) -> Result<(), DaylightCryptoError> {
    Err(DaylightCryptoError::Unsupported(primitive))
}

pub fn digest_vector(input: &[u8]) -> DigestVector {
    let sha2_512 = Sha512::digest(input).into();
    let sha3_512 = Sha3_512::digest(input).into();
    let mut shake256_512 = [0u8; 64];
    shake256(input, &mut shake256_512);
    DigestVector {
        sha2_512,
        sha3_512,
        shake256_512,
    }
}

pub fn daylight_hash(input: &[u8]) -> Result<[u8; DAYLIGHT_HASH_LEN], DaylightCryptoError> {
    let vector = digest_vector(input);
    let digest = tuple_hash256(
        DAYLIGHT_HASH_CUSTOMIZATION,
        &[&vector.sha2_512, &vector.sha3_512, &vector.shake256_512],
        DAYLIGHT_HASH_LEN,
    )?;
    fixed_array("daylight hash", &digest)
}

pub fn daylight_pre_envelope_message(
    transcript_t0: &[u8],
) -> Result<[u8; 64], DaylightCryptoError> {
    let message = cshake256(
        DAYLIGHT_AUTH_FUNCTION,
        DAYLIGHT_PRE_ENVELOPE_CUSTOMIZATION,
        transcript_t0,
        64,
    )?;
    fixed_array("daylight pre-envelope message", &message)
}

pub fn daylight_authorization_message(transcript: &[u8]) -> Result<[u8; 64], DaylightCryptoError> {
    let message = cshake256(
        DAYLIGHT_AUTH_FUNCTION,
        DAYLIGHT_AUTH_CUSTOMIZATION,
        transcript,
        64,
    )?;
    fixed_array("daylight authorization message", &message)
}

pub fn daylight_kem_combine(
    salt_d: &[u8; 32],
    ss_q: &[u8; 32],
    ss_c: &[u8; DHKEM_P384_SHARED_SECRET_LEN],
    ct_q: &[u8],
    enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    m0: &[u8; 64],
    k_d: &[u8; 64],
) -> Result<[u8; DAYLIGHT_KEM_COMBINE_LEN], DaylightCryptoError> {
    let input = enc_tuple(&[&ss_q[..], &ss_c[..], ct_q, &enc_c[..], &m0[..], &k_d[..]])?;
    let output = kmac256(
        salt_d,
        &input,
        DAYLIGHT_KEM_COMBINE_LEN,
        DAYLIGHT_KEM_COMBINE_CUSTOMIZATION,
    )?;
    fixed_array("daylight KEM combiner", &output)
}

pub fn daylight_key_schedule(
    z_d: &[u8; 64],
    t0: &[u8],
    ct_q: &[u8],
    enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    eta: &[u8],
) -> Result<DaylightKeySchedule, DaylightCryptoError> {
    let input = enc_tuple(&[t0, ct_q, &enc_c[..], eta])?;
    let output = kmac256(
        z_d,
        &input,
        DAYLIGHT_KEY_SCHEDULE_LEN,
        DAYLIGHT_KEY_SCHEDULE_CUSTOMIZATION,
    )?;
    Ok(DaylightKeySchedule {
        envelope_key: fixed_array("envelope key", &output[0..32])?,
        artifact_commit_key: fixed_array("artifact commit key", &output[32..64])?,
        ratchet_key: fixed_array("ratchet key", &output[64..96])?,
        witness_key: fixed_array("witness key", &output[96..128])?,
        ledger_key: fixed_array("ledger key", &output[128..160])?,
        auxiliary_key: fixed_array("auxiliary key", &output[160..192])?,
        base_nonce: fixed_array("base nonce", &output[192..204])?,
    })
}

pub fn daylight_suite_id_v2() -> Result<[u8; 64], DaylightCryptoError> {
    let suite_core = EncValue::List(vec![
        EncValue::Text("ML-KEM-1024"),
        EncValue::Text("DHKEM-P384-HKDF-SHA384"),
        EncValue::Text("SHA3-512"),
        EncValue::Text("SHAKE256"),
        EncValue::Text("KMAC256"),
        EncValue::Text("AEAD-AES-256-GCM-or-ChaCha20-Poly1305"),
        EncValue::Text("ML-DSA-87"),
        EncValue::Text("SLH-DSA-SHAKE-256s"),
    ]);
    daylight_h_v2(&suite_core)
}

pub fn daylight_claims_hash_v2(claims: &[Claim]) -> Result<[u8; 64], DaylightCryptoError> {
    let encoded_claims = EncValue::List(
        claims
            .iter()
            .map(|claim| EncValue::Text(claim_label(*claim)))
            .collect(),
    );
    daylight_h_v2(&encoded_claims)
}

pub fn daylight_leak_value_v2(
    artifact: &[u8],
    public_commitment: bool,
) -> Result<DaylightLeakValueV2, DaylightCryptoError> {
    let len = artifact_len(artifact)?;
    if public_commitment {
        Ok(DaylightLeakValueV2::PublicCommitment {
            len,
            artifact_hash: daylight_h_v2(&EncValue::Bytes(artifact))?,
        })
    } else {
        Ok(DaylightLeakValueV2::LengthOnly(len))
    }
}

pub fn daylight_t0_v2(header: &DaylightHeaderV2) -> Result<Vec<u8>, DaylightCryptoError> {
    daylight_e_v2("daylight/pre/v2", vec![header_value_v2(header)])
}

pub fn daylight_pre_message_v2(t0: &[u8]) -> Result<[u8; 64], DaylightCryptoError> {
    let input = enc_value(&EncValue::List(vec![
        EncValue::Text("daylight/pre-message/v2"),
        EncValue::Bytes(t0),
    ]))?;
    let mut output = [0u8; 64];
    shake256(&input, &mut output);
    Ok(output)
}

pub fn daylight_t1_v2(
    t0: &[u8],
    ciphertext: &[u8],
    enc_q: &[u8],
    enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    algorithm: AeadAlgorithm,
    commitment: &[u8; 32],
) -> Result<Vec<u8>, DaylightCryptoError> {
    let t0_hash = daylight_h_v2(&EncValue::Bytes(t0))?;
    let ciphertext_hash = daylight_h_bytes_v2(ciphertext);
    daylight_e_v2(
        "daylight/auth/v2",
        vec![
            EncValue::Bytes(&t0_hash),
            EncValue::Bytes(&ciphertext_hash),
            EncValue::Bytes(enc_q),
            EncValue::Bytes(enc_c),
            EncValue::Text(aead_label(algorithm)),
            EncValue::Bytes(commitment),
        ],
    )
}

pub fn daylight_auth_message_v2(t1: &[u8]) -> Result<Vec<u8>, DaylightCryptoError> {
    let t1_hash = daylight_h_v2(&EncValue::Bytes(t1))?;
    daylight_e_v2(
        "daylight/auth-message/v2",
        vec![
            EncValue::Bytes(DAYLIGHT_AUTH_CONTEXT_V2),
            EncValue::Bytes(&t1_hash),
        ],
    )
}

pub fn daylight_salt_v2(suite_id: &[u8; 64], t0: &[u8]) -> Result<[u8; 32], DaylightCryptoError> {
    let t0_hash = daylight_h_v2(&EncValue::Bytes(t0))?;
    let value = EncValue::List(vec![
        EncValue::Text("daylight/salt/v2"),
        EncValue::Bytes(suite_id),
        EncValue::Bytes(&t0_hash),
    ]);
    daylight_h256_v2(&value)
}

pub fn daylight_kem_context_v2(
    suite_id: &[u8; 64],
    profile: Profile,
    t0: &[u8],
    enc_q: &[u8],
    enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    keyset_hash: &[u8; 64],
) -> Result<Vec<u8>, DaylightCryptoError> {
    let t0_hash = daylight_h_v2(&EncValue::Bytes(t0))?;
    enc_value(&EncValue::List(vec![
        EncValue::Bytes(suite_id),
        EncValue::Text(profile_label(profile)),
        EncValue::Bytes(&t0_hash),
        EncValue::Bytes(enc_q),
        EncValue::Bytes(enc_c),
        EncValue::Bytes(keyset_hash),
    ]))
}

pub fn daylight_hybrid_combine_v2(
    salt_d: &[u8; 32],
    ss_q: &[u8; 32],
    ss_c: &[u8; DHKEM_P384_SHARED_SECRET_LEN],
    kem_context: &[u8],
) -> Result<[u8; 64], DaylightCryptoError> {
    let value = EncValue::List(vec![
        EncValue::Bytes(ss_q),
        EncValue::Bytes(ss_c),
        EncValue::Bytes(kem_context),
    ]);
    let output = daylight_kdf_v2(salt_d, "daylight/hybrid-combine/v2", &value, 64)?;
    fixed_array("daylight v2 hybrid combiner", &output)
}

pub fn daylight_key_schedule_v2(
    z_d: &[u8; 64],
    t0: &[u8],
    enc_q: &[u8],
    enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    suite_id: &[u8; 64],
    profile: Profile,
) -> Result<DaylightKeyScheduleV2, DaylightCryptoError> {
    let t0_hash = daylight_h_v2(&EncValue::Bytes(t0))?;
    let value = EncValue::List(vec![
        EncValue::Bytes(&t0_hash),
        EncValue::Bytes(enc_q),
        EncValue::Bytes(enc_c),
        EncValue::Bytes(suite_id),
        EncValue::Text(profile_label(profile)),
    ]);
    let output = daylight_kdf_v2(
        z_d,
        "daylight/key-schedule/v2",
        &value,
        DAYLIGHT_V2_KEY_SCHEDULE_LEN,
    )?;
    Ok(DaylightKeyScheduleV2 {
        envelope_key: fixed_array("daylight v2 envelope key", &output[0..32])?,
        artifact_commit_key: fixed_array("daylight v2 artifact commit key", &output[32..64])?,
        auth_key: fixed_array("daylight v2 auth key", &output[64..96])?,
        log_key: fixed_array("daylight v2 log key", &output[96..128])?,
        export_key: fixed_array("daylight v2 export key", &output[128..160])?,
        base_nonce: fixed_array("daylight v2 base nonce", &output[160..172])?,
    })
}

pub fn daylight_artifact_commitment_v2(
    artifact_commit_key: &[u8; 32],
    t0: &[u8],
    ciphertext: &[u8],
    artifact: &[u8],
) -> Result<[u8; 32], DaylightCryptoError> {
    let t0_hash = daylight_h_v2(&EncValue::Bytes(t0))?;
    let ciphertext_hash = daylight_h_bytes_v2(ciphertext);
    let value = EncValue::List(vec![
        EncValue::Bytes(&t0_hash),
        EncValue::Bytes(&ciphertext_hash),
        EncValue::Bytes(artifact),
    ]);
    let output = daylight_kdf_v2(
        artifact_commit_key,
        "daylight/artifact-commit/v2",
        &value,
        32,
    )?;
    fixed_array("daylight v2 artifact commitment", &output)
}

pub fn daylight_seal_v2_with_schedule(
    mut header: DaylightHeaderV2,
    claims: Vec<Claim>,
    algorithm: AeadAlgorithm,
    key_schedule: &DaylightKeyScheduleV2,
    enc_q: Vec<u8>,
    enc_c: [u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    artifact: &[u8],
) -> Result<DaylightEnvelopeV2, DaylightCryptoError> {
    if !leak_ok_v2(artifact, &header.leak_value)? {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Leak));
    }
    header.claims_hash = daylight_claims_hash_v2(&claims)?;
    let t0 = daylight_t0_v2(&header)?;
    let nonce = derive_nonce(&key_schedule.base_nonce, 0)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Nonce))?;
    let ciphertext = aead_seal(algorithm, &key_schedule.envelope_key, &nonce, &t0, artifact)?;
    let commitment = daylight_artifact_commitment_v2(
        &key_schedule.artifact_commit_key,
        &t0,
        &ciphertext,
        artifact,
    )?;
    Ok(DaylightEnvelopeV2 {
        header,
        claims,
        algorithm,
        enc_q,
        enc_c,
        ciphertext,
        commitment,
        record_index: 0,
    })
}

pub fn daylight_open_v2_with_schedule(
    envelope: &DaylightEnvelopeV2,
    key_schedule: &DaylightKeyScheduleV2,
    prechecks: &DaylightPrecheckEvidenceV2,
) -> Result<DaylightOpenReportV2, DaylightCryptoError> {
    let t0 = daylight_t0_v2(&envelope.header)?;
    pre_ok_v2(envelope, prechecks)?;
    let nonce = derive_nonce(&key_schedule.base_nonce, envelope.record_index)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Nonce))?;
    let artifact = aead_open(
        envelope.algorithm,
        &key_schedule.envelope_key,
        &nonce,
        &t0,
        &envelope.ciphertext,
    )
    .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Aead))?;
    let expected_commitment = daylight_artifact_commitment_v2(
        &key_schedule.artifact_commit_key,
        &t0,
        &envelope.ciphertext,
        &artifact,
    )?;
    if expected_commitment != envelope.commitment {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Commit,
        ));
    }
    if !leak_ok_v2(&artifact, &envelope.header.leak_value)? {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Leak));
    }
    let t1 = daylight_t1_v2(
        &t0,
        &envelope.ciphertext,
        &envelope.enc_q,
        &envelope.enc_c,
        envelope.algorithm,
        &envelope.commitment,
    )?;
    let auth_msg = daylight_auth_message_v2(&t1)?;
    Ok(DaylightOpenReportV2 {
        artifact,
        t0,
        t1,
        auth_msg,
    })
}

pub fn daylight_suite_id_v4() -> Result<[u8; 64], DaylightCryptoError> {
    let suite = EncValue::List(vec![
        EncValue::Text("Deterministic-CBOR-Daylight-v1"),
        EncValue::Text("SHA3-512"),
        EncValue::Text("SHAKE256"),
        EncValue::Text("HKDF-SHA512"),
        EncValue::Text("ML-KEM-1024"),
        EncValue::Text("DHKEM-P384-HKDF-SHA384"),
        EncValue::Text("AEAD-AES-256-GCM-or-ChaCha20-Poly1305"),
        EncValue::Text("ML-DSA-87"),
        EncValue::Text("SLH-DSA-SHAKE-256s"),
        EncValue::Text("optional-FROST-ciphersuite"),
    ]);
    daylight_h_v2(&suite)
}

pub fn daylight_leak_value_v4(
    artifact: &[u8],
    content_scope: DaylightContentScopeV4,
) -> Result<DaylightLeakValueV4, DaylightCryptoError> {
    let len = artifact_len(artifact)?;
    match content_scope {
        DaylightContentScopeV4::MetadataOnly | DaylightContentScopeV4::ReviewedContent => {
            Ok(DaylightLeakValueV4::LengthOnly(len))
        }
        DaylightContentScopeV4::PublicCommitment => Ok(DaylightLeakValueV4::PublicCommitment {
            len,
            artifact_hash: daylight_h_v2(&EncValue::Bytes(artifact))?,
        }),
    }
}

pub fn daylight_t0_v4(header: &DaylightHeaderV4) -> Result<Vec<u8>, DaylightCryptoError> {
    daylight_e_v2("daylight.pre.v4", vec![header_value_v4(header)])
}

pub fn daylight_header_bytes_v4(header: &DaylightHeaderV4) -> Result<Vec<u8>, DaylightCryptoError> {
    enc_value(&header_value_v4(header))
}

pub fn daylight_decode_header_v4(input: &[u8]) -> Result<DaylightHeaderV4, DaylightCryptoError> {
    decode_header_v4_value(&decode_enc_value(input)?)
}

pub fn daylight_t0_v4_from_header_bytes(input: &[u8]) -> Result<Vec<u8>, DaylightCryptoError> {
    let header = daylight_decode_header_v4(input)?;
    daylight_t0_v4(&header)
}

pub fn daylight_envelope_bytes_v4(
    envelope: &DaylightEnvelopeV4,
) -> Result<Vec<u8>, DaylightCryptoError> {
    let record_index = record_index_bytes_v4(envelope.record_index)?;
    enc_value(&envelope_value_v4(envelope, &record_index))
}

pub fn daylight_decode_envelope_v4(
    input: &[u8],
) -> Result<DaylightEnvelopeV4, DaylightCryptoError> {
    let envelope = decode_envelope_v4_value(&decode_enc_value(input)?)?;
    if daylight_envelope_bytes_v4(&envelope)? != input {
        return Err(DaylightCryptoError::DecodeRejected(
            "non-canonical DaylightEnvelopeV4",
        ));
    }
    Ok(envelope)
}

pub fn daylight_v4_reference_vector() -> Result<DaylightV4ReferenceVector, DaylightCryptoError> {
    let artifact = b"daylight v4 KEM-derived artifact".to_vec();
    let claims = vec![
        Claim::Research,
        Claim::Proof,
        Claim::ReleaseCandidate,
        Claim::HybridEvidence,
    ];
    let header = DaylightHeaderV4 {
        version: 4,
        suite_id: daylight_suite_id_v4()?,
        profile: Profile::D2Hybrid,
        release_level: 2,
        mode: Mode::Hybrid,
        action: Action::Release,
        content_scope: DaylightContentScopeV4::MetadataOnly,
        leak_value: daylight_leak_value_v4(&artifact, DaylightContentScopeV4::MetadataOnly)?,
        policy_id: b"policy-v4".to_vec(),
        policy_hash: daylight_reference_hash_v4(b"policy-hash-v4")?,
        keyset_hash: daylight_reference_hash_v4(b"keyset-v4")?,
        prev_log_head: daylight_reference_hash_v4(b"prev-log-head-v4")?,
        provenance_hash: daylight_reference_hash_v4(b"provenance-v4")?,
        install_manifest_hash: daylight_reference_hash_v4(b"install-manifest-v4")?,
        claims_hash: daylight_claims_hash_v2(&claims)?,
        review_receipt_hash: daylight_reference_hash_v4(b"review-receipt-v4")?,
    };
    let mlkem = mlkem1024_kat_fixture()?;
    let dhkem = dhkem_p384_hkdf_sha384_derive_keypair(b"daylight v4 recipient key")?;
    let public_keys = DaylightRecipientPublicKeysV4 {
        mlkem_encaps_key: mlkem.encaps_key,
        dhkem_public_key: dhkem.public_key,
    };
    let recipient_secret_keys = DaylightRecipientSecretKeysV4 {
        mlkem_decaps_key: mlkem.decaps_key,
        dhkem_private_key: dhkem.private_key,
    };
    let kem_inputs = DaylightSealKemInputsV4 {
        mlkem_encaps_seed: [0x54u8; 32],
        dhkem_ephemeral_ikm: b"daylight v4 deterministic ephemeral ikm".to_vec(),
    };
    let envelope = daylight_seal_v4_with_kems_from_seed(
        header,
        claims,
        AeadAlgorithm::Aes256Gcm,
        &public_keys,
        &kem_inputs,
        &artifact,
    )?;
    let prechecks = DaylightPrecheckEvidenceV2 {
        parse_ok: true,
        env_ok: true,
        policy_ok: true,
        gate_ok: true,
        provenance_ok: true,
        install_ok: true,
        witness_ok: true,
        log_ok: true,
        log_monotone_ok: true,
        no_downgrade_ok: true,
        auth_q_ok: true,
        auth_h_ok: false,
        auth_f_ok: false,
    };
    let opened = daylight_open_v4_with_kems(&envelope, &recipient_secret_keys, &prechecks)?;
    let envelope_bytes = daylight_envelope_bytes_v4(&envelope)?;
    let header_bytes = daylight_header_bytes_v4(&envelope.header)?;
    Ok(DaylightV4ReferenceVector {
        artifact,
        envelope,
        recipient_secret_keys,
        prechecks,
        envelope_bytes,
        header_bytes,
        t0: opened.t0,
        t1: opened.t1,
        auth_msg: opened.auth_msg,
    })
}

pub fn daylight_t1_v4(
    t0: &[u8],
    ciphertext: &[u8],
    enc_q: &[u8],
    enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    algorithm: AeadAlgorithm,
    commitment: &[u8; 32],
) -> Result<Vec<u8>, DaylightCryptoError> {
    let t0_hash = daylight_h_v2(&EncValue::Bytes(t0))?;
    let ciphertext_hash = daylight_h_bytes_v2(ciphertext);
    daylight_e_v2(
        "daylight.auth.transcript.v4",
        vec![
            EncValue::Bytes(&t0_hash),
            EncValue::Bytes(&ciphertext_hash),
            EncValue::Bytes(enc_q),
            EncValue::Bytes(enc_c),
            EncValue::Text(aead_label(algorithm)),
            EncValue::Bytes(commitment),
        ],
    )
}

pub fn daylight_auth_message_v4(t1: &[u8]) -> Result<Vec<u8>, DaylightCryptoError> {
    let t1_hash = daylight_h_v2(&EncValue::Bytes(t1))?;
    daylight_e_v2(
        "daylight.authorization.message.v4",
        vec![
            EncValue::Bytes(DAYLIGHT_AUTH_CONTEXT_V4),
            EncValue::Bytes(&t1_hash),
        ],
    )
}

pub fn daylight_salt_v4(
    suite_id: &[u8; 64],
    t0: &[u8],
    keyset_hash: &[u8; 64],
) -> Result<[u8; 32], DaylightCryptoError> {
    let t0_hash = daylight_h_v2(&EncValue::Bytes(t0))?;
    let value = EncValue::List(vec![
        EncValue::Text("daylight.kem.salt.v4"),
        EncValue::Bytes(suite_id),
        EncValue::Bytes(&t0_hash),
        EncValue::Bytes(keyset_hash),
    ]);
    daylight_h256_v2(&value)
}

pub fn daylight_kem_context_v4(
    suite_id: &[u8; 64],
    profile: Profile,
    t0: &[u8],
    keyset_hash: &[u8; 64],
    enc_q: &[u8],
    enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
) -> Result<Vec<u8>, DaylightCryptoError> {
    let t0_hash = daylight_h_v2(&EncValue::Bytes(t0))?;
    enc_value(&EncValue::List(vec![
        EncValue::Bytes(suite_id),
        EncValue::Text(profile_label(profile)),
        EncValue::Bytes(&t0_hash),
        EncValue::Bytes(keyset_hash),
        EncValue::Bytes(enc_q),
        EncValue::Bytes(enc_c),
    ]))
}

pub fn daylight_key_schedule_v4(
    salt_kem: &[u8; 32],
    ss_q: &[u8; 32],
    ss_c: &[u8; DHKEM_P384_SHARED_SECRET_LEN],
    kem_context: &[u8],
    t0: &[u8],
    enc_q: &[u8],
    enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    suite_id: &[u8; 64],
    profile: Profile,
) -> Result<DaylightKeyScheduleV4, DaylightCryptoError> {
    let hybrid_ikm = EncValue::List(vec![
        EncValue::Text("daylight.hybrid.ikm.v4"),
        EncValue::Bytes(ss_q),
        EncValue::Bytes(ss_c),
        EncValue::Bytes(kem_context),
    ]);
    let prk = hkdf_sha512_extract(salt_kem, &enc_value(&hybrid_ikm)?);
    let t0_hash = daylight_h_v2(&EncValue::Bytes(t0))?;
    let info = enc_value(&EncValue::List(vec![
        EncValue::Text("daylight.key.schedule.v4"),
        EncValue::Bytes(&t0_hash),
        EncValue::Bytes(enc_q),
        EncValue::Bytes(enc_c),
        EncValue::Bytes(suite_id),
        EncValue::Text(profile_label(profile)),
    ]))?;
    let mut output = [0u8; 76];
    hkdf_sha512_expand(&prk, &info, &mut output)?;
    Ok(DaylightKeyScheduleV4 {
        envelope_key: fixed_array("daylight v4 envelope key", &output[0..32])?,
        commitment_key: fixed_array("daylight v4 commitment key", &output[32..64])?,
        base_nonce: fixed_array("daylight v4 base nonce", &output[64..76])?,
    })
}

pub fn daylight_key_schedule_v4_from_kems(
    header: &DaylightHeaderV4,
    t0: &[u8],
    enc_q: &[u8],
    enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    ss_q: &[u8; 32],
    ss_c: &[u8; DHKEM_P384_SHARED_SECRET_LEN],
) -> Result<DaylightKeyScheduleV4, DaylightCryptoError> {
    let kem_context = daylight_kem_context_v4(
        &header.suite_id,
        header.profile,
        t0,
        &header.keyset_hash,
        enc_q,
        enc_c,
    )?;
    let salt = daylight_salt_v4(&header.suite_id, t0, &header.keyset_hash)?;
    daylight_key_schedule_v4(
        &salt,
        ss_q,
        ss_c,
        &kem_context,
        t0,
        enc_q,
        enc_c,
        &header.suite_id,
        header.profile,
    )
}

pub fn daylight_artifact_commitment_v4(
    commitment_key: &[u8; 32],
    t0: &[u8],
    ciphertext: &[u8],
    artifact: &[u8],
) -> Result<[u8; 32], DaylightCryptoError> {
    let t0_hash = daylight_h_v2(&EncValue::Bytes(t0))?;
    let ciphertext_hash = daylight_h_bytes_v2(ciphertext);
    let value = EncValue::List(vec![
        EncValue::Bytes(&t0_hash),
        EncValue::Bytes(&ciphertext_hash),
        EncValue::Bytes(artifact),
    ]);
    let output = daylight_kdf2_v4(commitment_key, "daylight.artifact.commit.v4", &value, 32)?;
    fixed_array("daylight v4 artifact commitment", &output)
}

pub fn daylight_seal_v4_with_schedule(
    mut header: DaylightHeaderV4,
    claims: Vec<Claim>,
    algorithm: AeadAlgorithm,
    key_schedule: &DaylightKeyScheduleV4,
    enc_q: Vec<u8>,
    enc_c: [u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    artifact: &[u8],
) -> Result<DaylightEnvelopeV4, DaylightCryptoError> {
    if !leak_ok_v4(artifact, header.content_scope, &header.leak_value)? {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Leak));
    }
    header.claims_hash = daylight_claims_hash_v2(&claims)?;
    let t0 = daylight_t0_v4(&header)?;
    let nonce = derive_nonce(&key_schedule.base_nonce, 0)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Nonce))?;
    let ciphertext = aead_seal(algorithm, &key_schedule.envelope_key, &nonce, &t0, artifact)?;
    let commitment =
        daylight_artifact_commitment_v4(&key_schedule.commitment_key, &t0, &ciphertext, artifact)?;
    Ok(DaylightEnvelopeV4 {
        header,
        claims,
        algorithm,
        enc_q,
        enc_c,
        ciphertext,
        commitment,
        record_index: 0,
    })
}

pub fn daylight_seal_v4_with_kems_from_seed(
    mut header: DaylightHeaderV4,
    claims: Vec<Claim>,
    algorithm: AeadAlgorithm,
    recipient_keys: &DaylightRecipientPublicKeysV4,
    kem_inputs: &DaylightSealKemInputsV4,
    artifact: &[u8],
) -> Result<DaylightEnvelopeV4, DaylightCryptoError> {
    if !leak_ok_v4(artifact, header.content_scope, &header.leak_value)? {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Leak));
    }
    header.claims_hash = daylight_claims_hash_v2(&claims)?;
    let t0 = daylight_t0_v4(&header)?;
    let (ss_q, enc_q) = mlkem1024_encaps_from_seed(
        &recipient_keys.mlkem_encaps_key,
        &kem_inputs.mlkem_encaps_seed,
    )?;
    let dhkem = dhkem_p384_hkdf_sha384_encaps_from_ikm(
        &recipient_keys.dhkem_public_key,
        &kem_inputs.dhkem_ephemeral_ikm,
    )?;
    let key_schedule = daylight_key_schedule_v4_from_kems(
        &header,
        &t0,
        &enc_q,
        &dhkem.encapped_key,
        &ss_q,
        &dhkem.shared_secret,
    )?;
    daylight_seal_v4_with_schedule(
        header,
        claims,
        algorithm,
        &key_schedule,
        enc_q,
        dhkem.encapped_key,
        artifact,
    )
}

pub fn daylight_seal_v4_with_kems_rng(
    mut header: DaylightHeaderV4,
    claims: Vec<Claim>,
    algorithm: AeadAlgorithm,
    recipient_keys: &DaylightRecipientPublicKeysV4,
    rng: &mut (impl RngCore + CryptoRng),
    artifact: &[u8],
) -> Result<DaylightEnvelopeV4, DaylightCryptoError> {
    let mut mlkem_encaps_seed = [0u8; 32];
    let mut dhkem_ephemeral_ikm = [0u8; DHKEM_P384_PRIVATE_KEY_LEN];
    rng.fill_bytes(&mut mlkem_encaps_seed);
    rng.fill_bytes(&mut dhkem_ephemeral_ikm);
    let result = (|| {
        if !leak_ok_v4(artifact, header.content_scope, &header.leak_value)? {
            return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Leak));
        }
        header.claims_hash = daylight_claims_hash_v2(&claims)?;
        let t0 = daylight_t0_v4(&header)?;
        let (ss_q, enc_q) =
            mlkem1024_encaps_from_seed(&recipient_keys.mlkem_encaps_key, &mlkem_encaps_seed)?;
        let dhkem = dhkem_p384_hkdf_sha384_encaps_from_ikm(
            &recipient_keys.dhkem_public_key,
            &dhkem_ephemeral_ikm,
        )?;
        let key_schedule = daylight_key_schedule_v4_from_kems(
            &header,
            &t0,
            &enc_q,
            &dhkem.encapped_key,
            &ss_q,
            &dhkem.shared_secret,
        )?;
        daylight_seal_v4_with_schedule(
            header,
            claims,
            algorithm,
            &key_schedule,
            enc_q,
            dhkem.encapped_key,
            artifact,
        )
    })();
    mlkem_encaps_seed.fill(0);
    dhkem_ephemeral_ikm.fill(0);
    result
}

pub fn daylight_open_v4_with_schedule(
    envelope: &DaylightEnvelopeV4,
    key_schedule: &DaylightKeyScheduleV4,
    prechecks: &DaylightPrecheckEvidenceV2,
) -> Result<DaylightOpenReportV2, DaylightCryptoError> {
    let t0 = daylight_t0_v4(&envelope.header)?;
    pre_ok_v4(envelope, prechecks)?;
    daylight_open_v4_private_with_schedule(envelope, key_schedule, t0)
}

pub fn daylight_open_v4_with_kems(
    envelope: &DaylightEnvelopeV4,
    recipient_keys: &DaylightRecipientSecretKeysV4,
    prechecks: &DaylightPrecheckEvidenceV2,
) -> Result<DaylightOpenReportV2, DaylightCryptoError> {
    let t0 = daylight_t0_v4(&envelope.header)?;
    pre_ok_v4(envelope, prechecks)?;
    let ss_q = mlkem1024_decaps(&recipient_keys.mlkem_decaps_key, &envelope.enc_q)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Derive))?;
    let ss_c = dhkem_p384_hkdf_sha384_decaps(&recipient_keys.dhkem_private_key, &envelope.enc_c)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Derive))?;
    let key_schedule = daylight_key_schedule_v4_from_kems(
        &envelope.header,
        &t0,
        &envelope.enc_q,
        &envelope.enc_c,
        &ss_q,
        &ss_c,
    )
    .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Derive))?;
    daylight_open_v4_private_with_schedule(envelope, &key_schedule, t0)
}

fn daylight_open_v4_private_with_schedule(
    envelope: &DaylightEnvelopeV4,
    key_schedule: &DaylightKeyScheduleV4,
    t0: Vec<u8>,
) -> Result<DaylightOpenReportV2, DaylightCryptoError> {
    let nonce = derive_nonce(&key_schedule.base_nonce, envelope.record_index)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Nonce))?;
    let artifact = aead_open(
        envelope.algorithm,
        &key_schedule.envelope_key,
        &nonce,
        &t0,
        &envelope.ciphertext,
    )
    .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Aead))?;
    let expected_commitment = daylight_artifact_commitment_v4(
        &key_schedule.commitment_key,
        &t0,
        &envelope.ciphertext,
        &artifact,
    )?;
    if expected_commitment != envelope.commitment {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Commit,
        ));
    }
    if !leak_ok_v4(
        &artifact,
        envelope.header.content_scope,
        &envelope.header.leak_value,
    )? {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Leak));
    }
    let t1 = daylight_t1_v4(
        &t0,
        &envelope.ciphertext,
        &envelope.enc_q,
        &envelope.enc_c,
        envelope.algorithm,
        &envelope.commitment,
    )?;
    let auth_msg = daylight_auth_message_v4(&t1)?;
    Ok(DaylightOpenReportV2 {
        artifact,
        t0,
        t1,
        auth_msg,
    })
}

pub fn artifact_commitment(
    artifact_commit_key: &[u8; 32],
    artifact: &[u8],
) -> Result<[u8; 32], DaylightCryptoError> {
    let output = kmac256(
        artifact_commit_key,
        artifact,
        32,
        DAYLIGHT_ARTIFACT_COMMIT_CUSTOMIZATION,
    )?;
    fixed_array("artifact commitment", &output)
}

pub fn derive_nonce(
    base_nonce: &[u8; DAYLIGHT_NONCE_LEN],
    sequence: u128,
) -> Result<[u8; DAYLIGHT_NONCE_LEN], DaylightCryptoError> {
    if sequence >= NONCE_SEQUENCE_LIMIT {
        return Err(DaylightCryptoError::InvalidParameter(
            "nonce sequence must be less than 2^96",
        ));
    }
    let sequence_bytes = sequence.to_be_bytes();
    let sequence_96 = &sequence_bytes[4..16];
    let mut nonce = *base_nonce;
    for (left, right) in nonce.iter_mut().zip(sequence_96.iter()) {
        *left ^= *right;
    }
    Ok(nonce)
}

pub fn aead_seal(
    algorithm: AeadAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, DaylightCryptoError> {
    match algorithm {
        AeadAlgorithm::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| DaylightCryptoError::InvalidLength {
                    name: "AES-256-GCM key",
                    expected: 32,
                    actual: key.len(),
                })?;
            cipher
                .encrypt(
                    aes_gcm::Nonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad: associated_data,
                    },
                )
                .map_err(|_| DaylightCryptoError::AeadRejected)
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
                DaylightCryptoError::InvalidLength {
                    name: "ChaCha20-Poly1305 key",
                    expected: 32,
                    actual: key.len(),
                }
            })?;
            cipher
                .encrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad: associated_data,
                    },
                )
                .map_err(|_| DaylightCryptoError::AeadRejected)
        }
    }
}

pub fn aead_open(
    algorithm: AeadAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, DaylightCryptoError> {
    match algorithm {
        AeadAlgorithm::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| DaylightCryptoError::InvalidLength {
                    name: "AES-256-GCM key",
                    expected: 32,
                    actual: key.len(),
                })?;
            cipher
                .decrypt(
                    aes_gcm::Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext_and_tag,
                        aad: associated_data,
                    },
                )
                .map_err(|_| DaylightCryptoError::AeadRejected)
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
                DaylightCryptoError::InvalidLength {
                    name: "ChaCha20-Poly1305 key",
                    expected: 32,
                    actual: key.len(),
                }
            })?;
            cipher
                .decrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext_and_tag,
                        aad: associated_data,
                    },
                )
                .map_err(|_| DaylightCryptoError::AeadRejected)
        }
    }
}

pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
    output_len: usize,
) -> Result<Vec<u8>, DaylightCryptoError> {
    if password.is_empty() {
        return Err(DaylightCryptoError::InvalidParameter(
            "Argon2id password must not be empty",
        ));
    }
    if salt.len() < 16 {
        return Err(DaylightCryptoError::InvalidParameter(
            "Argon2id salt must be at least 16 bytes",
        ));
    }
    let params = Params::new(memory_cost_kib, time_cost, parallelism, Some(output_len))
        .map_err(|_| DaylightCryptoError::KdfRejected)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| DaylightCryptoError::KdfRejected)?;
    Ok(output)
}

pub fn dhkem_p384_hkdf_sha384_derive_keypair(
    ikm: &[u8],
) -> Result<DhkemP384HkdfSha384Keypair, DaylightCryptoError> {
    let private_key = dhkem_p384_secret_from_ikm(ikm)?;
    let public_key = private_key.public_key();
    Ok(DhkemP384HkdfSha384Keypair {
        private_key: dhkem_p384_serialize_private_key(&private_key)?,
        public_key: dhkem_p384_serialize_public_key(&public_key)?,
    })
}

pub fn dhkem_p384_hkdf_sha384_public_key_from_private(
    private_key: &[u8; DHKEM_P384_PRIVATE_KEY_LEN],
) -> Result<[u8; DHKEM_P384_PUBLIC_KEY_LEN], DaylightCryptoError> {
    let private_key = dhkem_p384_parse_private_key(private_key)?;
    dhkem_p384_serialize_public_key(&private_key.public_key())
}

pub fn dhkem_p384_hkdf_sha384_encaps_from_ikm(
    public_key: &[u8; DHKEM_P384_PUBLIC_KEY_LEN],
    ephemeral_ikm: &[u8],
) -> Result<DhkemP384HkdfSha384Encapsulation, DaylightCryptoError> {
    let recipient_public_key = dhkem_p384_parse_public_key(public_key)?;
    let ephemeral_private_key = dhkem_p384_secret_from_ikm(ephemeral_ikm)?;
    dhkem_p384_hkdf_sha384_encaps_with_private(&recipient_public_key, &ephemeral_private_key)
}

pub fn dhkem_p384_hkdf_sha384_encaps_with_rng(
    public_key: &[u8; DHKEM_P384_PUBLIC_KEY_LEN],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<DhkemP384HkdfSha384Encapsulation, DaylightCryptoError> {
    let mut ephemeral_ikm = [0u8; DHKEM_P384_PRIVATE_KEY_LEN];
    rng.fill_bytes(&mut ephemeral_ikm);
    dhkem_p384_hkdf_sha384_encaps_from_ikm(public_key, &ephemeral_ikm)
}

pub fn dhkem_p384_hkdf_sha384_decaps(
    private_key: &[u8; DHKEM_P384_PRIVATE_KEY_LEN],
    encapped_key: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
) -> Result<[u8; DHKEM_P384_SHARED_SECRET_LEN], DaylightCryptoError> {
    let recipient_private_key = dhkem_p384_parse_private_key(private_key)?;
    let ephemeral_public_key = dhkem_p384_parse_public_key(encapped_key)?;
    let recipient_public_key = recipient_private_key.public_key();
    let raw_dh = dhkem_p384_raw_dh(&recipient_private_key, &ephemeral_public_key)?;
    let mut kem_context = Vec::with_capacity(DHKEM_P384_ENCAPSULATED_KEY_LEN * 2);
    kem_context.extend_from_slice(encapped_key);
    kem_context.extend_from_slice(&dhkem_p384_serialize_public_key(&recipient_public_key)?);
    dhkem_p384_extract_and_expand(&raw_dh, &kem_context)
}

fn dhkem_p384_hkdf_sha384_encaps_with_private(
    recipient_public_key: &P384PublicKey,
    ephemeral_private_key: &P384SecretKey,
) -> Result<DhkemP384HkdfSha384Encapsulation, DaylightCryptoError> {
    let ephemeral_public_key = ephemeral_private_key.public_key();
    let encapped_key = dhkem_p384_serialize_public_key(&ephemeral_public_key)?;
    let recipient_public_key_bytes = dhkem_p384_serialize_public_key(recipient_public_key)?;
    let raw_dh = dhkem_p384_raw_dh(ephemeral_private_key, recipient_public_key)?;
    let mut kem_context = Vec::with_capacity(DHKEM_P384_ENCAPSULATED_KEY_LEN * 2);
    kem_context.extend_from_slice(&encapped_key);
    kem_context.extend_from_slice(&recipient_public_key_bytes);
    let shared_secret = dhkem_p384_extract_and_expand(&raw_dh, &kem_context)?;
    Ok(DhkemP384HkdfSha384Encapsulation {
        shared_secret,
        encapped_key,
    })
}

pub fn mlkem1024_encaps_from_seed(
    encaps_key: &[u8],
    seed: &[u8; 32],
) -> Result<([u8; 32], Vec<u8>), DaylightCryptoError> {
    let encaps_key_array: [u8; ml_kem_1024::EK_LEN] =
        encaps_key
            .try_into()
            .map_err(|_| DaylightCryptoError::InvalidLength {
                name: "ML-KEM-1024 encapsulation key",
                expected: ml_kem_1024::EK_LEN,
                actual: encaps_key.len(),
            })?;
    let encaps_key = ml_kem_1024::EncapsKey::try_from_bytes(encaps_key_array)
        .map_err(|_| DaylightCryptoError::InvalidEncapsulationKey)?;
    let (shared_secret, ciphertext) = encaps_key.encaps_from_seed(seed);
    Ok((shared_secret.into_bytes(), ciphertext.into_bytes().to_vec()))
}

pub fn mlkem1024_decaps(
    decaps_key: &[u8],
    ciphertext: &[u8],
) -> Result<[u8; 32], DaylightCryptoError> {
    let decaps_key_array: [u8; ml_kem_1024::DK_LEN] =
        decaps_key
            .try_into()
            .map_err(|_| DaylightCryptoError::InvalidLength {
                name: "ML-KEM-1024 decapsulation key",
                expected: ml_kem_1024::DK_LEN,
                actual: decaps_key.len(),
            })?;
    let ciphertext_array: [u8; ml_kem_1024::CT_LEN] =
        ciphertext
            .try_into()
            .map_err(|_| DaylightCryptoError::InvalidLength {
                name: "ML-KEM-1024 ciphertext",
                expected: ml_kem_1024::CT_LEN,
                actual: ciphertext.len(),
            })?;
    let decaps_key = ml_kem_1024::DecapsKey::try_from_bytes(decaps_key_array)
        .map_err(|_| DaylightCryptoError::InvalidDecapsulationKey)?;
    let ciphertext = ml_kem_1024::CipherText::try_from_bytes(ciphertext_array)
        .map_err(|_| DaylightCryptoError::InvalidCiphertext)?;
    let shared_secret = decaps_key
        .try_decaps(&ciphertext)
        .map_err(|_| DaylightCryptoError::DecapsulationFailed)?;
    Ok(shared_secret.into_bytes())
}

pub fn mlkem1024_kat_fixture() -> Result<MlKem1024Kat, DaylightCryptoError> {
    let (encaps_key, decaps_key) =
        ml_kem_1024::KG::keygen_from_seed(MLKEM1024_KAT_D_SEED, MLKEM1024_KAT_Z_SEED);
    let encaps_key = encaps_key.into_bytes().to_vec();
    let decaps_key = decaps_key.into_bytes().to_vec();
    let (shared_secret, ciphertext) =
        mlkem1024_encaps_from_seed(&encaps_key, &MLKEM1024_KAT_M_SEED)?;
    let decaps_shared_secret = mlkem1024_decaps(&decaps_key, &ciphertext)?;
    if shared_secret != decaps_shared_secret {
        return Err(DaylightCryptoError::DecapsulationFailed);
    }
    Ok(MlKem1024Kat {
        encaps_key,
        decaps_key,
        ciphertext,
        shared_secret,
    })
}

pub fn verify_mldsa87(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<(), DaylightCryptoError> {
    if context.len() > 255 {
        return Err(DaylightCryptoError::ContextTooLong {
            actual: context.len(),
        });
    }
    let public_key_array: [u8; ml_dsa_87::PK_LEN] =
        public_key
            .try_into()
            .map_err(|_| DaylightCryptoError::InvalidLength {
                name: "ML-DSA-87 public key",
                expected: ml_dsa_87::PK_LEN,
                actual: public_key.len(),
            })?;
    let signature_array: [u8; ml_dsa_87::SIG_LEN] =
        signature
            .try_into()
            .map_err(|_| DaylightCryptoError::InvalidLength {
                name: "ML-DSA-87 signature",
                expected: ml_dsa_87::SIG_LEN,
                actual: signature.len(),
            })?;
    let public_key = ml_dsa_87::PublicKey::try_from_bytes(public_key_array)
        .map_err(|_| DaylightCryptoError::InvalidPublicKey)?;
    if public_key.verify(message, &signature_array, context) {
        Ok(())
    } else {
        Err(DaylightCryptoError::VerificationRejected)
    }
}

pub fn verify_slhdsa_shake_256s(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<(), DaylightCryptoError> {
    if context.len() > 255 {
        return Err(DaylightCryptoError::ContextTooLong {
            actual: context.len(),
        });
    }
    let public_key_array: [u8; slh_dsa_shake_256s::PK_LEN] =
        public_key
            .try_into()
            .map_err(|_| DaylightCryptoError::InvalidLength {
                name: "SLH-DSA-SHAKE-256s public key",
                expected: slh_dsa_shake_256s::PK_LEN,
                actual: public_key.len(),
            })?;
    let signature_array: [u8; slh_dsa_shake_256s::SIG_LEN] =
        signature
            .try_into()
            .map_err(|_| DaylightCryptoError::InvalidLength {
                name: "SLH-DSA-SHAKE-256s signature",
                expected: slh_dsa_shake_256s::SIG_LEN,
                actual: signature.len(),
            })?;
    let public_key = slh_dsa_shake_256s::PublicKey::try_from_bytes(&public_key_array)
        .map_err(|_| DaylightCryptoError::InvalidPublicKey)?;
    if public_key.verify(message, &signature_array, context) {
        Ok(())
    } else {
        Err(DaylightCryptoError::VerificationRejected)
    }
}

pub fn mldsa87_kat_fixture() -> Result<MlDsa87Kat, DaylightCryptoError> {
    let (public_key, private_key) = ml_dsa_87::KG::keygen_from_seed(&MLDSA87_KAT_KEY_SEED);
    let signature = private_key
        .try_sign_with_seed(
            &MLDSA87_KAT_SIGN_SEED,
            MLDSA87_KAT_MESSAGE,
            DAYLIGHT_AUTH_CONTEXT,
        )
        .map_err(|_| DaylightCryptoError::VerificationRejected)?;
    let public_key = public_key.into_bytes().to_vec();
    verify_mldsa87(
        &public_key,
        MLDSA87_KAT_MESSAGE,
        &signature,
        DAYLIGHT_AUTH_CONTEXT,
    )?;
    Ok(MlDsa87Kat {
        public_key,
        message: MLDSA87_KAT_MESSAGE.to_vec(),
        signature: signature.to_vec(),
    })
}

pub fn slhdsa_shake_256s_kat_fixture() -> Result<SlhDsaShake256sKat, DaylightCryptoError> {
    let (public_key, private_key) = slh_dsa_shake_256s::KG::keygen_with_seeds(
        &SLHDSA_SHAKE_256S_SK_SEED,
        &SLHDSA_SHAKE_256S_SK_PRF,
        &SLHDSA_SHAKE_256S_PK_SEED,
    );
    let mut rng = KatRng::new(SLHDSA_SHAKE_256S_SIGN_SEED);
    let signature = private_key
        .try_sign_with_rng(
            &mut rng,
            SLHDSA_SHAKE_256S_KAT_MESSAGE,
            DAYLIGHT_AUTH_CONTEXT,
            true,
        )
        .map_err(|_| DaylightCryptoError::SigningFailed)?;
    let public_key = public_key.into_bytes().to_vec();
    verify_slhdsa_shake_256s(
        &public_key,
        SLHDSA_SHAKE_256S_KAT_MESSAGE,
        &signature,
        DAYLIGHT_AUTH_CONTEXT,
    )?;
    Ok(SlhDsaShake256sKat {
        public_key,
        message: SLHDSA_SHAKE_256S_KAT_MESSAGE.to_vec(),
        signature: signature.to_vec(),
    })
}

pub fn cshake256(
    function_name: &[u8],
    customization: &[u8],
    input: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, DaylightCryptoError> {
    ensure_bit_len(function_name)?;
    ensure_bit_len(customization)?;
    ensure_bit_len(input)?;
    ensure_bit_len_by_len(out_len)?;
    let core = CShake256Core::new_with_function_name(function_name, customization);
    let mut hasher = CoreWrapper::from_core(core);
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; out_len];
    reader.read(&mut output);
    Ok(output)
}

pub fn tuple_hash256(
    customization: &[u8],
    tuple: &[&[u8]],
    out_len: usize,
) -> Result<Vec<u8>, DaylightCryptoError> {
    let mut input = tuple_hash_input(tuple)?;
    input.extend(right_encode(
        (out_len as u64)
            .checked_mul(8)
            .ok_or(DaylightCryptoError::EncodingTooLarge)?,
    ));
    cshake256(b"TupleHash", customization, &input, out_len)
}

pub fn kmac256(
    key: &[u8],
    input: &[u8],
    out_len: usize,
    customization: &[u8],
) -> Result<Vec<u8>, DaylightCryptoError> {
    ensure_bit_len(input)?;
    let mut encoded = bytepad(&encode_string(key)?, CSHAKE256_RATE_BYTES)?;
    encoded.extend_from_slice(input);
    encoded.extend(right_encode(
        (out_len as u64)
            .checked_mul(8)
            .ok_or(DaylightCryptoError::EncodingTooLarge)?,
    ));
    cshake256(b"KMAC", customization, &encoded, out_len)
}

pub fn tuple_hash_input(tuple: &[&[u8]]) -> Result<Vec<u8>, DaylightCryptoError> {
    let mut output = Vec::new();
    for item in tuple {
        output.extend(encode_string(item)?);
    }
    Ok(output)
}

pub fn enc_tuple(tuple: &[&[u8]]) -> Result<Vec<u8>, DaylightCryptoError> {
    let mut output = left_encode(tuple.len() as u64);
    for item in tuple {
        output.extend(encode_string(item)?);
    }
    Ok(output)
}

fn pre_ok_v2(
    envelope: &DaylightEnvelopeV2,
    prechecks: &DaylightPrecheckEvidenceV2,
) -> Result<(), DaylightCryptoError> {
    if !prechecks.parse_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Parse,
        ));
    }
    if envelope.header.version != 2 || envelope.header.suite_id != daylight_suite_id_v2()? {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Suite,
        ));
    }
    if envelope.enc_q.len() != ml_kem_1024::CT_LEN
        || dhkem_p384_parse_public_key(&envelope.enc_c).is_err()
    {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env));
    }
    if envelope.record_index >= NONCE_SEQUENCE_LIMIT {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Nonce,
        ));
    }
    if !prechecks.env_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env));
    }
    if !action_allowed(envelope.header.release_level, envelope.header.action)
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Mode))?
        || !mode_ok(
            envelope.header.profile,
            envelope.header.release_level,
            envelope.header.mode,
            envelope.header.action,
        )
        .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Mode))?
    {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Mode));
    }
    if !prechecks.policy_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Policy,
        ));
    }
    if !prechecks.gate_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Gate));
    }
    if !prechecks.provenance_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Provenance,
        ));
    }
    if !prechecks.install_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Install,
        ));
    }
    if !prechecks.witness_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Witness,
        ));
    }
    if !prechecks.log_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Log));
    }
    if !prechecks.log_monotone_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::LogMonotone,
        ));
    }
    if envelope.header.claims_hash != daylight_claims_hash_v2(&envelope.claims)?
        || envelope
            .claims
            .iter()
            .any(|claim| !claim_allowed(envelope.header.release_level, *claim).unwrap_or(false))
    {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Claim,
        ));
    }
    if !prechecks.no_downgrade_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::NoDowngrade,
        ));
    }
    let required = daylight_model::required_auth_primitives(
        envelope.header.profile,
        envelope.header.release_level,
        envelope.header.mode,
        envelope.header.action,
    )
    .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Mode))?;
    for primitive in required {
        match primitive {
            AuthPrimitive::Q if !prechecks.auth_q_ok => {
                return Err(DaylightCryptoError::OpenRejected(
                    DaylightOpenFailure::AuthQ,
                ));
            }
            AuthPrimitive::H if !prechecks.auth_h_ok => {
                return Err(DaylightCryptoError::OpenRejected(
                    DaylightOpenFailure::AuthH,
                ));
            }
            AuthPrimitive::F => {
                return Err(DaylightCryptoError::OpenRejected(
                    DaylightOpenFailure::AuthFUnsupported,
                ));
            }
            AuthPrimitive::Q | AuthPrimitive::H => {}
        }
    }
    Ok(())
}

fn pre_ok_v4(
    envelope: &DaylightEnvelopeV4,
    prechecks: &DaylightPrecheckEvidenceV2,
) -> Result<(), DaylightCryptoError> {
    if !prechecks.parse_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Parse,
        ));
    }
    if envelope.header.version != 4 || envelope.header.suite_id != daylight_suite_id_v4()? {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Suite,
        ));
    }
    if envelope.enc_q.len() != ml_kem_1024::CT_LEN
        || dhkem_p384_parse_public_key(&envelope.enc_c).is_err()
    {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env));
    }
    if envelope.record_index >= NONCE_SEQUENCE_LIMIT {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Nonce,
        ));
    }
    if !prechecks.env_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env));
    }
    if !mode_ok(
        envelope.header.profile,
        envelope.header.release_level,
        envelope.header.mode,
        envelope.header.action,
    )
    .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Mode))?
    {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Mode));
    }
    if !prechecks.policy_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Policy,
        ));
    }
    if !prechecks.gate_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Gate));
    }
    if !prechecks.provenance_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Provenance,
        ));
    }
    if !prechecks.install_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Install,
        ));
    }
    if !prechecks.witness_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Witness,
        ));
    }
    if !prechecks.log_ok {
        return Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Log));
    }
    if !prechecks.log_monotone_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::LogMonotone,
        ));
    }
    if envelope.header.claims_hash != daylight_claims_hash_v2(&envelope.claims)?
        || envelope
            .claims
            .iter()
            .any(|claim| !claim_allowed(envelope.header.release_level, *claim).unwrap_or(false))
    {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::Claim,
        ));
    }
    if !prechecks.no_downgrade_ok {
        return Err(DaylightCryptoError::OpenRejected(
            DaylightOpenFailure::NoDowngrade,
        ));
    }
    let required = daylight_model::required_auth_primitives(
        envelope.header.profile,
        envelope.header.release_level,
        envelope.header.mode,
        envelope.header.action,
    )
    .map_err(|_| DaylightCryptoError::OpenRejected(DaylightOpenFailure::Mode))?;
    for primitive in required {
        match primitive {
            AuthPrimitive::Q if !prechecks.auth_q_ok => {
                return Err(DaylightCryptoError::OpenRejected(
                    DaylightOpenFailure::AuthQ,
                ));
            }
            AuthPrimitive::H if !prechecks.auth_h_ok => {
                return Err(DaylightCryptoError::OpenRejected(
                    DaylightOpenFailure::AuthH,
                ));
            }
            AuthPrimitive::F => {
                return Err(DaylightCryptoError::OpenRejected(
                    DaylightOpenFailure::AuthFUnsupported,
                ));
            }
            AuthPrimitive::Q | AuthPrimitive::H => {}
        }
    }
    Ok(())
}

fn leak_ok_v2(
    artifact: &[u8],
    leak_value: &DaylightLeakValueV2,
) -> Result<bool, DaylightCryptoError> {
    let len = artifact_len(artifact)?;
    match leak_value {
        DaylightLeakValueV2::LengthOnly(expected_len) => Ok(*expected_len == len),
        DaylightLeakValueV2::PublicCommitment {
            len: expected_len,
            artifact_hash,
        } => Ok(
            *expected_len == len && *artifact_hash == daylight_h_v2(&EncValue::Bytes(artifact))?
        ),
    }
}

fn leak_ok_v4(
    artifact: &[u8],
    content_scope: DaylightContentScopeV4,
    leak_value: &DaylightLeakValueV4,
) -> Result<bool, DaylightCryptoError> {
    let len = artifact_len(artifact)?;
    match (content_scope, leak_value) {
        (
            DaylightContentScopeV4::MetadataOnly | DaylightContentScopeV4::ReviewedContent,
            DaylightLeakValueV4::LengthOnly(expected_len),
        ) => Ok(*expected_len == len),
        (
            DaylightContentScopeV4::PublicCommitment,
            DaylightLeakValueV4::PublicCommitment {
                len: expected_len,
                artifact_hash,
            },
        ) => Ok(
            *expected_len == len && *artifact_hash == daylight_h_v2(&EncValue::Bytes(artifact))?
        ),
        _ => Ok(false),
    }
}

fn artifact_len(artifact: &[u8]) -> Result<u64, DaylightCryptoError> {
    u64::try_from(artifact.len()).map_err(|_| DaylightCryptoError::EncodingTooLarge)
}

fn daylight_e_v2(
    label: &'static str,
    values: Vec<EncValue<'_>>,
) -> Result<Vec<u8>, DaylightCryptoError> {
    let mut tuple = Vec::with_capacity(values.len() + 1);
    tuple.push(EncValue::Text(label));
    tuple.extend(values);
    enc_value(&EncValue::List(tuple))
}

fn daylight_h_v2(value: &EncValue<'_>) -> Result<[u8; 64], DaylightCryptoError> {
    let encoded = enc_value(value)?;
    Ok(Sha3_512::digest(&encoded).into())
}

fn daylight_h256_v2(value: &EncValue<'_>) -> Result<[u8; 32], DaylightCryptoError> {
    let encoded = enc_value(value)?;
    let mut output = [0u8; 32];
    shake256(&encoded, &mut output);
    Ok(output)
}

fn daylight_h_bytes_v2(input: &[u8]) -> [u8; 64] {
    Sha3_512::digest(input).into()
}

fn daylight_kdf_v2(
    key: &[u8],
    label: &'static str,
    value: &EncValue<'_>,
    out_len: usize,
) -> Result<Vec<u8>, DaylightCryptoError> {
    let input = enc_value(&EncValue::List(vec![
        EncValue::Text(label),
        value.clone_for_encode(),
    ]))?;
    kmac256(key, &input, out_len, DAYLIGHT_KDF_CUSTOMIZATION_V2)
}

fn daylight_kdf2_v4(
    salt: &[u8],
    label: &'static str,
    input: &EncValue<'_>,
    out_len: usize,
) -> Result<Vec<u8>, DaylightCryptoError> {
    let extract_ikm = enc_value(&EncValue::List(vec![
        EncValue::Text(label),
        input.clone_for_encode(),
    ]))?;
    let info = enc_value(&EncValue::List(vec![
        EncValue::Text("daylight-kdf-info-v1"),
        EncValue::Text(label),
        input.clone_for_encode(),
    ]))?;
    let prk = hkdf_sha512_extract(salt, &extract_ikm);
    let mut output = vec![0u8; out_len];
    hkdf_sha512_expand(&prk, &info, &mut output)?;
    Ok(output)
}

fn hkdf_sha512_extract(salt: &[u8], ikm: &[u8]) -> Hkdf<Sha512> {
    let (_, hkdf) = Hkdf::<Sha512>::extract(Some(salt), ikm);
    hkdf
}

fn hkdf_sha512_expand(
    prk: &Hkdf<Sha512>,
    info: &[u8],
    output: &mut [u8],
) -> Result<(), DaylightCryptoError> {
    prk.expand(info, output)
        .map_err(|_| DaylightCryptoError::KdfRejected)
}

fn daylight_reference_hash_v4(label: &[u8]) -> Result<[u8; 64], DaylightCryptoError> {
    daylight_h_v2(&EncValue::Bytes(label))
}

#[derive(Clone)]
enum EncValue<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
    UInt(u128),
    List(Vec<EncValue<'a>>),
}

impl<'a> EncValue<'a> {
    fn clone_for_encode(&self) -> EncValue<'a> {
        self.clone()
    }
}

fn enc_value(value: &EncValue<'_>) -> Result<Vec<u8>, DaylightCryptoError> {
    let mut output = Vec::new();
    append_enc_value(value, &mut output)?;
    Ok(output)
}

fn append_enc_value(value: &EncValue<'_>, output: &mut Vec<u8>) -> Result<(), DaylightCryptoError> {
    match value {
        EncValue::Text(text) => {
            append_cbor_type_len(3, text.len() as u64, output);
            output.extend_from_slice(text.as_bytes());
        }
        EncValue::Bytes(bytes) => {
            append_cbor_type_len(2, bytes.len() as u64, output);
            output.extend_from_slice(bytes);
        }
        EncValue::UInt(value) => {
            let value = u64::try_from(*value).map_err(|_| DaylightCryptoError::EncodingTooLarge)?;
            append_cbor_type_len(0, value, output);
        }
        EncValue::List(items) => {
            append_cbor_type_len(4, items.len() as u64, output);
            for item in items {
                append_enc_value(item, output)?;
            }
        }
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum EncOwned {
    Text(String),
    Bytes(Vec<u8>),
    UInt(u64),
    List(Vec<EncOwned>),
}

fn decode_enc_value(input: &[u8]) -> Result<EncOwned, DaylightCryptoError> {
    let mut cursor = CborCursor { input, offset: 0 };
    let value = cursor.decode_value()?;
    if cursor.offset != input.len() {
        return Err(DaylightCryptoError::DecodeRejected("trailing CBOR data"));
    }
    Ok(value)
}

struct CborCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> CborCursor<'a> {
    fn decode_value(&mut self) -> Result<EncOwned, DaylightCryptoError> {
        let head = self.read_u8()?;
        let major = head >> 5;
        let additional = head & 0x1f;
        match major {
            0 => Ok(EncOwned::UInt(self.decode_argument(additional)?)),
            2 => {
                let len = usize::try_from(self.decode_argument(additional)?)
                    .map_err(|_| DaylightCryptoError::DecodeRejected("CBOR length too large"))?;
                let bytes = self.read_bytes(len)?;
                Ok(EncOwned::Bytes(bytes.to_vec()))
            }
            3 => {
                let len = usize::try_from(self.decode_argument(additional)?)
                    .map_err(|_| DaylightCryptoError::DecodeRejected("CBOR length too large"))?;
                let bytes = self.read_bytes(len)?;
                let text = core::str::from_utf8(bytes)
                    .map_err(|_| DaylightCryptoError::DecodeRejected("invalid UTF-8 text"))?;
                Ok(EncOwned::Text(text.to_string()))
            }
            4 => {
                let len = usize::try_from(self.decode_argument(additional)?)
                    .map_err(|_| DaylightCryptoError::DecodeRejected("CBOR length too large"))?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.decode_value()?);
                }
                Ok(EncOwned::List(items))
            }
            _ => Err(DaylightCryptoError::DecodeRejected(
                "unsupported CBOR major type",
            )),
        }
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
        fixed_array("CBOR fixed argument", bytes)
            .map_err(|_| DaylightCryptoError::DecodeRejected("truncated CBOR input"))
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

fn decode_header_v4_value(value: &EncOwned) -> Result<DaylightHeaderV4, DaylightCryptoError> {
    let items = expect_list_len(value, 16, "DaylightHeaderV4")?;
    let version = expect_u16(&items[0], "header.version")?;
    if version != 4 {
        return Err(DaylightCryptoError::DecodeRejected(
            "unsupported Daylight header version",
        ));
    }
    let release_level = expect_u8(&items[3], "header.r")?;
    if release_level > 3 {
        return Err(DaylightCryptoError::DecodeRejected(
            "release level out of range",
        ));
    }
    Ok(DaylightHeaderV4 {
        version,
        suite_id: expect_bytes_array(&items[1], "header.suite_id")?,
        profile: decode_profile(expect_text(&items[2], "header.profile")?)?,
        release_level,
        mode: decode_mode(expect_text(&items[4], "header.mu")?)?,
        action: decode_action(expect_text(&items[5], "header.action")?)?,
        content_scope: decode_content_scope(expect_text(&items[6], "header.content_scope")?)?,
        leak_value: decode_leak_value_v4(&items[7])?,
        policy_id: expect_bytes(&items[8], "header.policy_id")?.to_vec(),
        policy_hash: expect_bytes_array(&items[9], "header.policy_hash")?,
        keyset_hash: expect_bytes_array(&items[10], "header.keyset_hash")?,
        prev_log_head: expect_bytes_array(&items[11], "header.prev_log_head")?,
        provenance_hash: expect_bytes_array(&items[12], "header.provenance_hash")?,
        install_manifest_hash: expect_bytes_array(&items[13], "header.install_manifest_hash")?,
        claims_hash: expect_bytes_array(&items[14], "header.claims_hash")?,
        review_receipt_hash: expect_bytes_array(&items[15], "header.review_receipt_hash")?,
    })
}

fn decode_leak_value_v4(value: &EncOwned) -> Result<DaylightLeakValueV4, DaylightCryptoError> {
    let items = expect_list(value, "header.leak_value")?;
    let tag = expect_text(
        items.first().ok_or(DaylightCryptoError::DecodeRejected(
            "empty leak_value tuple",
        ))?,
        "header.leak_value.tag",
    )?;
    match tag {
        "length-only" if items.len() == 2 => Ok(DaylightLeakValueV4::LengthOnly(expect_u64(
            &items[1],
            "header.leak_value.len",
        )?)),
        "public-commitment" if items.len() == 3 => Ok(DaylightLeakValueV4::PublicCommitment {
            len: expect_u64(&items[1], "header.leak_value.len")?,
            artifact_hash: expect_bytes_array(&items[2], "header.leak_value.artifact_hash")?,
        }),
        _ => Err(DaylightCryptoError::DecodeRejected(
            "unknown or malformed leak_value tuple",
        )),
    }
}

fn decode_envelope_v4_value(value: &EncOwned) -> Result<DaylightEnvelopeV4, DaylightCryptoError> {
    let items = expect_list_len(value, 9, "DaylightEnvelopeV4")?;
    let tag = expect_text(&items[0], "envelope.tag")?;
    if tag != "daylight.envelope.v4" {
        return Err(DaylightCryptoError::DecodeRejected(
            "unknown DaylightEnvelopeV4 label",
        ));
    }
    let enc_q = expect_bytes(&items[4], "envelope.enc_q")?.to_vec();
    if enc_q.len() != ml_kem_1024::CT_LEN {
        return Err(DaylightCryptoError::DecodeRejected(
            "unexpected ML-KEM ciphertext length",
        ));
    }
    Ok(DaylightEnvelopeV4 {
        header: decode_header_v4_value(&items[1])?,
        claims: decode_claims_v4(&items[2])?,
        algorithm: decode_aead(expect_text(&items[3], "envelope.aead")?)?,
        enc_q,
        enc_c: expect_bytes_array(&items[5], "envelope.enc_c")?,
        ciphertext: expect_bytes(&items[6], "envelope.ciphertext")?.to_vec(),
        commitment: expect_bytes_array(&items[7], "envelope.commitment")?,
        record_index: record_index_from_bytes_v4(expect_bytes(
            &items[8],
            "envelope.record_index",
        )?)?,
    })
}

fn decode_claims_v4(value: &EncOwned) -> Result<Vec<Claim>, DaylightCryptoError> {
    expect_list(value, "envelope.claims")?
        .iter()
        .map(|item| decode_claim(expect_text(item, "envelope.claim")?))
        .collect()
}

fn expect_list<'a>(
    value: &'a EncOwned,
    _name: &'static str,
) -> Result<&'a [EncOwned], DaylightCryptoError> {
    match value {
        EncOwned::List(items) => Ok(items),
        _ => Err(DaylightCryptoError::DecodeRejected("expected CBOR array")),
    }
}

fn expect_list_len<'a>(
    value: &'a EncOwned,
    expected: usize,
    name: &'static str,
) -> Result<&'a [EncOwned], DaylightCryptoError> {
    let items = expect_list(value, name)?;
    if items.len() != expected {
        return Err(DaylightCryptoError::DecodeRejected(
            "unexpected CBOR array length",
        ));
    }
    Ok(items)
}

fn expect_text<'a>(
    value: &'a EncOwned,
    _name: &'static str,
) -> Result<&'a str, DaylightCryptoError> {
    match value {
        EncOwned::Text(text) => Ok(text),
        _ => Err(DaylightCryptoError::DecodeRejected("expected CBOR text")),
    }
}

fn expect_bytes<'a>(
    value: &'a EncOwned,
    _name: &'static str,
) -> Result<&'a [u8], DaylightCryptoError> {
    match value {
        EncOwned::Bytes(bytes) => Ok(bytes),
        _ => Err(DaylightCryptoError::DecodeRejected("expected CBOR bytes")),
    }
}

fn expect_bytes_array<const N: usize>(
    value: &EncOwned,
    name: &'static str,
) -> Result<[u8; N], DaylightCryptoError> {
    fixed_array(name, expect_bytes(value, name)?)
        .map_err(|_| DaylightCryptoError::DecodeRejected("unexpected byte-string length"))
}

fn expect_u64(value: &EncOwned, _name: &'static str) -> Result<u64, DaylightCryptoError> {
    match value {
        EncOwned::UInt(value) => Ok(*value),
        _ => Err(DaylightCryptoError::DecodeRejected("expected CBOR uint")),
    }
}

fn expect_u16(value: &EncOwned, name: &'static str) -> Result<u16, DaylightCryptoError> {
    u16::try_from(expect_u64(value, name)?)
        .map_err(|_| DaylightCryptoError::DecodeRejected("uint out of range"))
}

fn expect_u8(value: &EncOwned, name: &'static str) -> Result<u8, DaylightCryptoError> {
    u8::try_from(expect_u64(value, name)?)
        .map_err(|_| DaylightCryptoError::DecodeRejected("uint out of range"))
}

fn header_value_v2(header: &DaylightHeaderV2) -> EncValue<'_> {
    EncValue::List(vec![
        EncValue::UInt(u128::from(header.version)),
        EncValue::Bytes(&header.suite_id),
        EncValue::Text(profile_label(header.profile)),
        EncValue::UInt(u128::from(header.release_level)),
        EncValue::Text(mode_label(header.mode)),
        EncValue::Text(action_label(header.action)),
        leak_value_v2_value(&header.leak_value),
        EncValue::Bytes(&header.policy_id),
        EncValue::Bytes(&header.policy_root),
        EncValue::Bytes(&header.keyset_hash),
        EncValue::Bytes(&header.prev_log_head),
        EncValue::Bytes(&header.provenance_hash),
        EncValue::Bytes(&header.install_manifest_hash),
        EncValue::Bytes(&header.claims_hash),
    ])
}

fn header_value_v4(header: &DaylightHeaderV4) -> EncValue<'_> {
    EncValue::List(vec![
        EncValue::UInt(u128::from(header.version)),
        EncValue::Bytes(&header.suite_id),
        EncValue::Text(profile_label(header.profile)),
        EncValue::UInt(u128::from(header.release_level)),
        EncValue::Text(mode_label(header.mode)),
        EncValue::Text(action_label(header.action)),
        EncValue::Text(content_scope_label(header.content_scope)),
        leak_value_v4_value(&header.leak_value),
        EncValue::Bytes(&header.policy_id),
        EncValue::Bytes(&header.policy_hash),
        EncValue::Bytes(&header.keyset_hash),
        EncValue::Bytes(&header.prev_log_head),
        EncValue::Bytes(&header.provenance_hash),
        EncValue::Bytes(&header.install_manifest_hash),
        EncValue::Bytes(&header.claims_hash),
        EncValue::Bytes(&header.review_receipt_hash),
    ])
}

fn envelope_value_v4<'a>(
    envelope: &'a DaylightEnvelopeV4,
    record_index: &'a [u8; 12],
) -> EncValue<'a> {
    EncValue::List(vec![
        EncValue::Text("daylight.envelope.v4"),
        header_value_v4(&envelope.header),
        claims_value(&envelope.claims),
        EncValue::Text(aead_label(envelope.algorithm)),
        EncValue::Bytes(&envelope.enc_q),
        EncValue::Bytes(&envelope.enc_c),
        EncValue::Bytes(&envelope.ciphertext),
        EncValue::Bytes(&envelope.commitment),
        EncValue::Bytes(record_index),
    ])
}

fn claims_value(claims: &[Claim]) -> EncValue<'_> {
    EncValue::List(
        claims
            .iter()
            .map(|claim| EncValue::Text(claim_label(*claim)))
            .collect(),
    )
}

fn leak_value_v2_value(leak_value: &DaylightLeakValueV2) -> EncValue<'_> {
    match leak_value {
        DaylightLeakValueV2::LengthOnly(len) => EncValue::List(vec![
            EncValue::Text("length-only"),
            EncValue::UInt(u128::from(*len)),
        ]),
        DaylightLeakValueV2::PublicCommitment { len, artifact_hash } => EncValue::List(vec![
            EncValue::Text("public-commitment"),
            EncValue::UInt(u128::from(*len)),
            EncValue::Bytes(artifact_hash),
        ]),
    }
}

fn leak_value_v4_value(leak_value: &DaylightLeakValueV4) -> EncValue<'_> {
    match leak_value {
        DaylightLeakValueV4::LengthOnly(len) => EncValue::List(vec![
            EncValue::Text("length-only"),
            EncValue::UInt(u128::from(*len)),
        ]),
        DaylightLeakValueV4::PublicCommitment { len, artifact_hash } => EncValue::List(vec![
            EncValue::Text("public-commitment"),
            EncValue::UInt(u128::from(*len)),
            EncValue::Bytes(artifact_hash),
        ]),
    }
}

fn profile_label(profile: Profile) -> &'static str {
    match profile {
        Profile::D2Hybrid => "D2-HYBRID",
        Profile::D3Root => "D3-ROOT",
        Profile::D2HybridFrost => "D2-HYBRID-FROST",
    }
}

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Compact => "compact",
        Mode::Hybrid => "hybrid",
        Mode::PqStrict => "pq-strict",
    }
}

fn action_label(action: Action) -> &'static str {
    match action {
        Action::Research => "research",
        Action::Proof => "proof",
        Action::Open => "open",
        Action::Release => "release",
        Action::Install => "install",
        Action::RootRotate => "root_rotate",
        Action::AuditAccept => "audit_accept",
    }
}

fn content_scope_label(content_scope: DaylightContentScopeV4) -> &'static str {
    match content_scope {
        DaylightContentScopeV4::MetadataOnly => "metadata_only",
        DaylightContentScopeV4::PublicCommitment => "public_commitment",
        DaylightContentScopeV4::ReviewedContent => "reviewed_content",
    }
}

fn decode_profile(value: &str) -> Result<Profile, DaylightCryptoError> {
    match value {
        "D2-HYBRID" => Ok(Profile::D2Hybrid),
        "D3-ROOT" => Ok(Profile::D3Root),
        "D2-HYBRID-FROST" => Ok(Profile::D2HybridFrost),
        _ => Err(DaylightCryptoError::DecodeRejected("unknown profile")),
    }
}

fn decode_mode(value: &str) -> Result<Mode, DaylightCryptoError> {
    match value {
        "hybrid" => Ok(Mode::Hybrid),
        "pq-strict" => Ok(Mode::PqStrict),
        "compact" => Err(DaylightCryptoError::DecodeRejected(
            "compact is not openable in v4",
        )),
        _ => Err(DaylightCryptoError::DecodeRejected("unknown mode")),
    }
}

fn decode_action(value: &str) -> Result<Action, DaylightCryptoError> {
    match value {
        "research" => Ok(Action::Research),
        "proof" => Ok(Action::Proof),
        "open" => Ok(Action::Open),
        "release" => Ok(Action::Release),
        "install" => Ok(Action::Install),
        "root_rotate" => Ok(Action::RootRotate),
        "audit_accept" => Ok(Action::AuditAccept),
        _ => Err(DaylightCryptoError::DecodeRejected("unknown action")),
    }
}

fn decode_content_scope(value: &str) -> Result<DaylightContentScopeV4, DaylightCryptoError> {
    match value {
        "metadata_only" => Ok(DaylightContentScopeV4::MetadataOnly),
        "public_commitment" => Ok(DaylightContentScopeV4::PublicCommitment),
        "reviewed_content" => Ok(DaylightContentScopeV4::ReviewedContent),
        _ => Err(DaylightCryptoError::DecodeRejected("unknown content scope")),
    }
}

fn decode_claim(value: &str) -> Result<Claim, DaylightCryptoError> {
    match value {
        "research" => Ok(Claim::Research),
        "proof" => Ok(Claim::Proof),
        "open-evidence" => Ok(Claim::OpenEvidence),
        "release-candidate" => Ok(Claim::ReleaseCandidate),
        "install-evidence" => Ok(Claim::InstallEvidence),
        "hybrid-evidence" => Ok(Claim::HybridEvidence),
        "root-ceremony" => Ok(Claim::RootCeremony),
        "audit-evidence" => Ok(Claim::AuditEvidence),
        _ => Err(DaylightCryptoError::DecodeRejected("unknown claim")),
    }
}

fn claim_label(claim: Claim) -> &'static str {
    match claim {
        Claim::Research => "research",
        Claim::Proof => "proof",
        Claim::OpenEvidence => "open-evidence",
        Claim::ReleaseCandidate => "release-candidate",
        Claim::InstallEvidence => "install-evidence",
        Claim::HybridEvidence => "hybrid-evidence",
        Claim::RootCeremony => "root-ceremony",
        Claim::AuditEvidence => "audit-evidence",
    }
}

fn aead_label(algorithm: AeadAlgorithm) -> &'static str {
    match algorithm {
        AeadAlgorithm::Aes256Gcm => "AES-256-GCM",
        AeadAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
    }
}

fn decode_aead(value: &str) -> Result<AeadAlgorithm, DaylightCryptoError> {
    match value {
        "AES-256-GCM" => Ok(AeadAlgorithm::Aes256Gcm),
        "ChaCha20-Poly1305" => Ok(AeadAlgorithm::ChaCha20Poly1305),
        _ => Err(DaylightCryptoError::DecodeRejected(
            "unknown AEAD algorithm",
        )),
    }
}

fn record_index_bytes_v4(sequence: u128) -> Result<[u8; 12], DaylightCryptoError> {
    if sequence >= NONCE_SEQUENCE_LIMIT {
        return Err(DaylightCryptoError::InvalidParameter(
            "record index out of range",
        ));
    }
    let mut output = [0u8; 12];
    output.copy_from_slice(&sequence.to_be_bytes()[4..16]);
    Ok(output)
}

fn record_index_from_bytes_v4(input: &[u8]) -> Result<u128, DaylightCryptoError> {
    let bytes: [u8; 12] = fixed_array("envelope.record_index", input)
        .map_err(|_| DaylightCryptoError::DecodeRejected("unexpected byte-string length"))?;
    let mut wide = [0u8; 16];
    wide[4..16].copy_from_slice(&bytes);
    Ok(u128::from_be_bytes(wide))
}

fn dhkem_p384_secret_from_ikm(ikm: &[u8]) -> Result<P384SecretKey, DaylightCryptoError> {
    let dkp_prk = hpke_labeled_extract_sha384(&[], b"dkp_prk", ikm);
    for counter in 0u8..=255 {
        let mut candidate = [0u8; DHKEM_P384_PRIVATE_KEY_LEN];
        hpke_labeled_expand_sha384(&dkp_prk, b"candidate", &[counter], &mut candidate)?;
        if let Ok(secret_key) = P384SecretKey::from_slice(&candidate) {
            return Ok(secret_key);
        }
    }
    Err(DaylightCryptoError::KdfRejected)
}

fn dhkem_p384_parse_private_key(
    private_key: &[u8; DHKEM_P384_PRIVATE_KEY_LEN],
) -> Result<P384SecretKey, DaylightCryptoError> {
    P384SecretKey::from_slice(private_key).map_err(|_| DaylightCryptoError::InvalidDecapsulationKey)
}

fn dhkem_p384_parse_public_key(
    public_key: &[u8; DHKEM_P384_PUBLIC_KEY_LEN],
) -> Result<P384PublicKey, DaylightCryptoError> {
    P384PublicKey::from_sec1_bytes(public_key).map_err(|_| DaylightCryptoError::InvalidPublicKey)
}

fn dhkem_p384_serialize_private_key(
    private_key: &P384SecretKey,
) -> Result<[u8; DHKEM_P384_PRIVATE_KEY_LEN], DaylightCryptoError> {
    fixed_array(
        "DHKEM(P-384,HKDF-SHA384) private key",
        private_key.to_bytes().as_slice(),
    )
}

fn dhkem_p384_serialize_public_key(
    public_key: &P384PublicKey,
) -> Result<[u8; DHKEM_P384_PUBLIC_KEY_LEN], DaylightCryptoError> {
    let encoded = public_key.to_encoded_point(false);
    fixed_array("DHKEM(P-384,HKDF-SHA384) public key", encoded.as_bytes())
}

fn dhkem_p384_raw_dh(
    private_key: &P384SecretKey,
    public_key: &P384PublicKey,
) -> Result<[u8; DHKEM_P384_SHARED_SECRET_LEN], DaylightCryptoError> {
    let shared_secret =
        p384_diffie_hellman(private_key.to_nonzero_scalar(), public_key.as_affine());
    fixed_array(
        "DHKEM(P-384,HKDF-SHA384) raw DH",
        shared_secret.raw_secret_bytes().as_slice(),
    )
}

fn dhkem_p384_extract_and_expand(
    dh: &[u8; DHKEM_P384_SHARED_SECRET_LEN],
    kem_context: &[u8],
) -> Result<[u8; DHKEM_P384_SHARED_SECRET_LEN], DaylightCryptoError> {
    let eae_prk = hpke_labeled_extract_sha384(&[], b"eae_prk", dh);
    let mut shared_secret = [0u8; DHKEM_P384_SHARED_SECRET_LEN];
    hpke_labeled_expand_sha384(&eae_prk, b"shared_secret", kem_context, &mut shared_secret)?;
    Ok(shared_secret)
}

fn hpke_labeled_extract_sha384(salt: &[u8], label: &[u8], ikm: &[u8]) -> Hkdf<Sha384> {
    let mut labeled_ikm = Vec::with_capacity(
        HPKE_VERSION_LABEL.len() + DHKEM_P384_SUITE_ID.len() + label.len() + ikm.len(),
    );
    labeled_ikm.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_ikm.extend_from_slice(&DHKEM_P384_SUITE_ID);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    Hkdf::<Sha384>::new(Some(salt), &labeled_ikm)
}

fn hpke_labeled_expand_sha384(
    prk: &Hkdf<Sha384>,
    label: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), DaylightCryptoError> {
    if output.len() > u16::MAX as usize {
        return Err(DaylightCryptoError::KdfRejected);
    }
    let length = (output.len() as u16).to_be_bytes();
    let mut labeled_info = Vec::with_capacity(
        length.len()
            + HPKE_VERSION_LABEL.len()
            + DHKEM_P384_SUITE_ID.len()
            + label.len()
            + info.len(),
    );
    labeled_info.extend_from_slice(&length);
    labeled_info.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_info.extend_from_slice(&DHKEM_P384_SUITE_ID);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    prk.expand(&labeled_info, output)
        .map_err(|_| DaylightCryptoError::KdfRejected)
}

pub fn left_encode(value: u64) -> Vec<u8> {
    let minimal = minimal_be_bytes(value);
    let mut output = Vec::with_capacity(minimal.len() + 1);
    output.push(minimal.len() as u8);
    output.extend_from_slice(&minimal);
    output
}

pub fn right_encode(value: u64) -> Vec<u8> {
    let minimal = minimal_be_bytes(value);
    let mut output = Vec::with_capacity(minimal.len() + 1);
    output.extend_from_slice(&minimal);
    output.push(minimal.len() as u8);
    output
}

pub fn encode_string(input: &[u8]) -> Result<Vec<u8>, DaylightCryptoError> {
    let bit_len = ensure_bit_len(input)?;
    let mut output = left_encode(bit_len);
    output.extend_from_slice(input);
    Ok(output)
}

pub fn bytepad(input: &[u8], width: usize) -> Result<Vec<u8>, DaylightCryptoError> {
    if width == 0 || width > u8::MAX as usize {
        return Err(DaylightCryptoError::EncodingTooLarge);
    }
    let mut output = left_encode(width as u64);
    output.extend_from_slice(input);
    while output.len() % width != 0 {
        output.push(0);
    }
    Ok(output)
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn shake256(input: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

fn ensure_bit_len(input: &[u8]) -> Result<u64, DaylightCryptoError> {
    (input.len() as u64)
        .checked_mul(8)
        .ok_or(DaylightCryptoError::EncodingTooLarge)
}

fn ensure_bit_len_by_len(len: usize) -> Result<u64, DaylightCryptoError> {
    (len as u64)
        .checked_mul(8)
        .ok_or(DaylightCryptoError::EncodingTooLarge)
}

fn minimal_be_bytes(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[first..].to_vec()
}

fn fixed_array<const N: usize>(
    name: &'static str,
    input: &[u8],
) -> Result<[u8; N], DaylightCryptoError> {
    input
        .try_into()
        .map_err(|_| DaylightCryptoError::InvalidLength {
            name,
            expected: N,
            actual: input.len(),
        })
}

struct KatRng {
    seed: [u8; 32],
    counter: u64,
}

impl KatRng {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }
}

impl RngCore for KatRng {
    fn next_u32(&mut self) -> u32 {
        let mut output = [0u8; 4];
        self.fill_bytes(&mut output);
        u32::from_le_bytes(output)
    }

    fn next_u64(&mut self) -> u64 {
        let mut output = [0u8; 8];
        self.fill_bytes(&mut output);
        u64::from_le_bytes(output)
    }

    fn fill_bytes(&mut self, output: &mut [u8]) {
        let mut offset = 0;
        while offset < output.len() {
            let mut hasher = Shake256::default();
            Update::update(&mut hasher, &self.seed);
            Update::update(&mut hasher, &self.counter.to_be_bytes());
            self.counter += 1;
            let mut reader = hasher.finalize_xof();
            let mut block = [0u8; 64];
            reader.read(&mut block);
            let take = (output.len() - offset).min(block.len());
            output[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
        }
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(output);
        Ok(())
    }
}

impl CryptoRng for KatRng {}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_vec(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        (0..input.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&input[index..index + 2], 16).unwrap())
            .collect()
    }

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

    fn assert_decode_rejected<T: std::fmt::Debug>(
        result: Result<T, DaylightCryptoError>,
        expected: &str,
    ) {
        match result {
            Err(DaylightCryptoError::DecodeRejected(actual)) => assert_eq!(actual, expected),
            other => panic!("expected DecodeRejected({expected:?}), got {other:?}"),
        }
    }

    #[test]
    fn digest_vector_matches_known_hash_vectors() {
        let vector = digest_vector(b"abc");
        assert_eq!(
            hex_lower(&vector.sha2_512),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                .replace(' ', "")
        );
        assert_eq!(
            hex_lower(&vector.sha3_512),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
                .replace(' ', "")
        );
        assert_eq!(
            hex_lower(&vector.shake256_512),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
             d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
                .replace(' ', "")
        );
    }

    #[test]
    fn sp800_185_encodings_match_basic_shapes() {
        assert_eq!(left_encode(0), vec![1, 0]);
        assert_eq!(left_encode(136), vec![1, 136]);
        assert_eq!(left_encode(512), vec![2, 2, 0]);
        assert_eq!(right_encode(512), vec![2, 0, 2]);
        assert_eq!(encode_string(b"abc").unwrap(), b"\x01\x18abc".to_vec());
        assert_eq!(bytepad(b"abc", 8).unwrap(), b"\x01\x08abc\0\0\0".to_vec());
        assert_eq!(
            enc_tuple(&[b"a", b"bc"]).unwrap(),
            b"\x01\x02\x01\x08a\x01\x10bc".to_vec()
        );
    }

    #[test]
    fn cshake_tuplehash_and_kmac_are_domain_separated() {
        let a = cshake256(b"WUCI-DAYLIGHT", b"authorization/v1", b"abc", 64).unwrap();
        let b = cshake256(b"WUCI-DAYLIGHT", b"authorization/v2", b"abc", 64).unwrap();
        let c = cshake256(b"WUCI-DAYLIGHT", b"authorization/v1", b"abd", 64).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);

        let tuple_ab = tuple_hash256(b"domain", &[b"a", b"bc"], 64).unwrap();
        let tuple_ba = tuple_hash256(b"domain", &[b"ab", b"c"], 64).unwrap();
        assert_ne!(tuple_ab, tuple_ba);

        let mac_a = kmac256(b"key-a", b"message", 64, b"domain").unwrap();
        let mac_b = kmac256(b"key-b", b"message", 64, b"domain").unwrap();
        assert_ne!(mac_a, mac_b);
    }

    #[test]
    fn daylight_derivations_are_stable_and_separated() {
        let h_a = daylight_hash(b"artifact").unwrap();
        let h_b = daylight_hash(b"artifact!").unwrap();
        assert_ne!(h_a, h_b);

        let m0 = daylight_pre_envelope_message(b"T0").unwrap();
        let m_d = daylight_authorization_message(b"T1").unwrap();
        assert_ne!(m0, m_d);

        let salt_d = [0x11u8; 32];
        let ss_q = [0x22u8; 32];
        let ss_c = [0x33u8; DHKEM_P384_SHARED_SECRET_LEN];
        let ct_q = vec![0x44u8; ml_kem_1024::CT_LEN];
        let enc_c = [0x55u8; DHKEM_P384_ENCAPSULATED_KEY_LEN];
        let k_d = daylight_hash(b"keyset").unwrap();
        let z_d = daylight_kem_combine(&salt_d, &ss_q, &ss_c, &ct_q, &enc_c, &m0, &k_d).unwrap();
        let schedule = daylight_key_schedule(&z_d, b"T0", &ct_q, &enc_c, b"AES-256-GCM").unwrap();
        assert_ne!(schedule.envelope_key, schedule.artifact_commit_key);
        assert_ne!(schedule.ratchet_key, schedule.witness_key);
        assert_ne!(schedule.witness_key, schedule.ledger_key);

        let commitment = artifact_commitment(&schedule.artifact_commit_key, b"artifact").unwrap();
        let other_commitment =
            artifact_commitment(&schedule.artifact_commit_key, b"artifact!").unwrap();
        assert_ne!(commitment, other_commitment);

        let nonce_0 = derive_nonce(&schedule.base_nonce, 0).unwrap();
        let nonce_1 = derive_nonce(&schedule.base_nonce, 1).unwrap();
        assert_eq!(nonce_0, schedule.base_nonce);
        assert_ne!(nonce_0, nonce_1);
        assert_eq!(
            derive_nonce(&schedule.base_nonce, 1u128 << 96),
            Err(DaylightCryptoError::InvalidParameter(
                "nonce sequence must be less than 2^96"
            ))
        );
    }

    fn v2_hash(label: &[u8]) -> [u8; 64] {
        daylight_h_v2(&EncValue::Bytes(label)).unwrap()
    }

    fn v2_header(
        artifact: &[u8],
        claims: &[Claim],
        profile: Profile,
        release_level: u8,
        mode: Mode,
        action: Action,
    ) -> DaylightHeaderV2 {
        DaylightHeaderV2 {
            version: 2,
            suite_id: daylight_suite_id_v2().unwrap(),
            profile,
            release_level,
            mode,
            action,
            leak_value: daylight_leak_value_v2(artifact, false).unwrap(),
            policy_id: b"policy-v2".to_vec(),
            policy_root: v2_hash(b"policy-root"),
            keyset_hash: v2_hash(b"keyset"),
            prev_log_head: v2_hash(b"prev-log-head"),
            provenance_hash: v2_hash(b"provenance"),
            install_manifest_hash: v2_hash(b"install-manifest"),
            claims_hash: daylight_claims_hash_v2(claims).unwrap(),
        }
    }

    fn v2_enc_c() -> [u8; DHKEM_P384_ENCAPSULATED_KEY_LEN] {
        let recipient =
            dhkem_p384_hkdf_sha384_derive_keypair(b"wuci daylight v2 recipient").unwrap();
        dhkem_p384_hkdf_sha384_encaps_from_ikm(&recipient.public_key, b"wuci daylight v2 ephemeral")
            .unwrap()
            .encapped_key
    }

    fn v2_schedule(
        header: &DaylightHeaderV2,
        enc_q: &[u8],
        enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    ) -> DaylightKeyScheduleV2 {
        let t0 = daylight_t0_v2(header).unwrap();
        daylight_key_schedule_v2(
            &[0x7au8; 64],
            &t0,
            enc_q,
            enc_c,
            &header.suite_id,
            header.profile,
        )
        .unwrap()
    }

    fn v2_prechecks_all_passed() -> DaylightPrecheckEvidenceV2 {
        DaylightPrecheckEvidenceV2 {
            parse_ok: true,
            env_ok: true,
            policy_ok: true,
            gate_ok: true,
            provenance_ok: true,
            install_ok: true,
            witness_ok: true,
            log_ok: true,
            log_monotone_ok: true,
            no_downgrade_ok: true,
            auth_q_ok: true,
            auth_h_ok: false,
            auth_f_ok: false,
        }
    }

    fn v2_fixture() -> (
        Vec<u8>,
        DaylightEnvelopeV2,
        DaylightKeyScheduleV2,
        DaylightPrecheckEvidenceV2,
    ) {
        let artifact = b"daylight v2 artifact".to_vec();
        let claims = vec![
            Claim::Research,
            Claim::Proof,
            Claim::ReleaseCandidate,
            Claim::HybridEvidence,
        ];
        let header = v2_header(
            &artifact,
            &claims,
            Profile::D2Hybrid,
            2,
            Mode::Hybrid,
            Action::Release,
        );
        let enc_q = vec![0x44u8; ml_kem_1024::CT_LEN];
        let enc_c = v2_enc_c();
        let schedule = v2_schedule(&header, &enc_q, &enc_c);
        let envelope = daylight_seal_v2_with_schedule(
            header,
            claims,
            AeadAlgorithm::Aes256Gcm,
            &schedule,
            enc_q,
            enc_c,
            &artifact,
        )
        .unwrap();
        (artifact, envelope, schedule, v2_prechecks_all_passed())
    }

    #[test]
    fn daylight_v2_seal_open_accepts_valid_p2_hybrid_release() {
        let (artifact, envelope, schedule, prechecks) = v2_fixture();
        let opened = daylight_open_v2_with_schedule(&envelope, &schedule, &prechecks).unwrap();
        assert_eq!(opened.artifact, artifact);
        assert!(!opened.t0.is_empty());
        assert!(!opened.t1.is_empty());
        assert!(!opened.auth_msg.is_empty());
    }

    #[test]
    fn daylight_v2_open_fails_closed_on_precheck_gates() {
        let (_, envelope, schedule, mut prechecks) = v2_fixture();
        prechecks.gate_ok = false;
        assert_eq!(
            daylight_open_v2_with_schedule(&envelope, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Gate))
        );

        let mut prechecks = v2_prechecks_all_passed();
        prechecks.no_downgrade_ok = false;
        assert_eq!(
            daylight_open_v2_with_schedule(&envelope, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::NoDowngrade
            ))
        );
    }

    #[test]
    fn daylight_v2_open_fails_closed_on_mode_claim_and_auth_rules() {
        let (artifact, envelope, schedule, prechecks) = v2_fixture();

        let mut compact = envelope.clone();
        compact.header.mode = Mode::Compact;
        assert_eq!(
            daylight_open_v2_with_schedule(&compact, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Mode))
        );

        let mut bad_claim = envelope.clone();
        bad_claim.claims.push(Claim::RootCeremony);
        bad_claim.header.claims_hash = daylight_claims_hash_v2(&bad_claim.claims).unwrap();
        assert_eq!(
            daylight_open_v2_with_schedule(&bad_claim, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::Claim
            ))
        );

        let claims = vec![
            Claim::Research,
            Claim::Proof,
            Claim::ReleaseCandidate,
            Claim::HybridEvidence,
        ];
        let root_header = v2_header(
            &artifact,
            &claims,
            Profile::D3Root,
            3,
            Mode::Hybrid,
            Action::RootRotate,
        );
        let enc_q = vec![0x44u8; ml_kem_1024::CT_LEN];
        let enc_c = v2_enc_c();
        let root_schedule = v2_schedule(&root_header, &enc_q, &enc_c);
        let root_envelope = daylight_seal_v2_with_schedule(
            root_header,
            claims,
            AeadAlgorithm::Aes256Gcm,
            &root_schedule,
            enc_q,
            enc_c,
            &artifact,
        )
        .unwrap();
        assert_eq!(
            daylight_open_v2_with_schedule(&root_envelope, &root_schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::AuthH
            ))
        );

        let frost_header = v2_header(
            &artifact,
            &[Claim::Research, Claim::Proof],
            Profile::D2HybridFrost,
            2,
            Mode::Hybrid,
            Action::Release,
        );
        let enc_q = vec![0x44u8; ml_kem_1024::CT_LEN];
        let enc_c = v2_enc_c();
        let frost_schedule = v2_schedule(&frost_header, &enc_q, &enc_c);
        let frost_envelope = daylight_seal_v2_with_schedule(
            frost_header,
            vec![Claim::Research, Claim::Proof],
            AeadAlgorithm::Aes256Gcm,
            &frost_schedule,
            enc_q,
            enc_c,
            &artifact,
        )
        .unwrap();
        let mut frost_prechecks = prechecks;
        frost_prechecks.auth_f_ok = true;
        assert_eq!(
            daylight_open_v2_with_schedule(&frost_envelope, &frost_schedule, &frost_prechecks),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::AuthFUnsupported
            ))
        );
    }

    #[test]
    fn daylight_v2_open_fails_closed_on_postchecks() {
        let (_, envelope, schedule, prechecks) = v2_fixture();

        let mut bad_ciphertext = envelope.clone();
        bad_ciphertext.ciphertext[0] ^= 0x80;
        assert_eq!(
            daylight_open_v2_with_schedule(&bad_ciphertext, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Aead))
        );

        let mut bad_commitment = envelope.clone();
        bad_commitment.commitment[0] ^= 0x80;
        assert_eq!(
            daylight_open_v2_with_schedule(&bad_commitment, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::Commit
            ))
        );
    }

    #[test]
    fn daylight_v2_open_fails_closed_on_nonce_and_leakage() {
        let (artifact, envelope, schedule, prechecks) = v2_fixture();

        let mut bad_nonce = envelope.clone();
        bad_nonce.record_index = 1u128 << 96;
        assert_eq!(
            daylight_open_v2_with_schedule(&bad_nonce, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::Nonce
            ))
        );

        let claims = envelope.claims.clone();
        let mut leak_header = v2_header(
            &artifact,
            &claims,
            Profile::D2Hybrid,
            2,
            Mode::Hybrid,
            Action::Release,
        );
        leak_header.leak_value = DaylightLeakValueV2::LengthOnly(artifact.len() as u64 + 1);
        let enc_q = vec![0x44u8; ml_kem_1024::CT_LEN];
        let enc_c = v2_enc_c();
        let leak_schedule = v2_schedule(&leak_header, &enc_q, &enc_c);
        let t0 = daylight_t0_v2(&leak_header).unwrap();
        let ciphertext = aead_seal(
            AeadAlgorithm::Aes256Gcm,
            &leak_schedule.envelope_key,
            &leak_schedule.base_nonce,
            &t0,
            &artifact,
        )
        .unwrap();
        let commitment = daylight_artifact_commitment_v2(
            &leak_schedule.artifact_commit_key,
            &t0,
            &ciphertext,
            &artifact,
        )
        .unwrap();
        let leak_envelope = DaylightEnvelopeV2 {
            header: leak_header,
            claims,
            algorithm: AeadAlgorithm::Aes256Gcm,
            enc_q,
            enc_c,
            ciphertext,
            commitment,
            record_index: 0,
        };
        assert_eq!(
            daylight_open_v2_with_schedule(&leak_envelope, &leak_schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Leak))
        );
    }

    fn v4_header(
        artifact: &[u8],
        claims: &[Claim],
        profile: Profile,
        release_level: u8,
        mode: Mode,
        action: Action,
        content_scope: DaylightContentScopeV4,
    ) -> DaylightHeaderV4 {
        DaylightHeaderV4 {
            version: 4,
            suite_id: daylight_suite_id_v4().unwrap(),
            profile,
            release_level,
            mode,
            action,
            content_scope,
            leak_value: daylight_leak_value_v4(artifact, content_scope).unwrap(),
            policy_id: b"policy-v4".to_vec(),
            policy_hash: v2_hash(b"policy-hash-v4"),
            keyset_hash: v2_hash(b"keyset-v4"),
            prev_log_head: v2_hash(b"prev-log-head-v4"),
            provenance_hash: v2_hash(b"provenance-v4"),
            install_manifest_hash: v2_hash(b"install-manifest-v4"),
            claims_hash: daylight_claims_hash_v2(claims).unwrap(),
            review_receipt_hash: v2_hash(b"review-receipt-v4"),
        }
    }

    fn v4_schedule(
        header: &DaylightHeaderV4,
        enc_q: &[u8],
        enc_c: &[u8; DHKEM_P384_ENCAPSULATED_KEY_LEN],
    ) -> DaylightKeyScheduleV4 {
        let t0 = daylight_t0_v4(header).unwrap();
        let kem_context = daylight_kem_context_v4(
            &header.suite_id,
            header.profile,
            &t0,
            &header.keyset_hash,
            enc_q,
            enc_c,
        )
        .unwrap();
        let salt = daylight_salt_v4(&header.suite_id, &t0, &header.keyset_hash).unwrap();
        daylight_key_schedule_v4(
            &salt,
            &[0x22u8; 32],
            &[0x33u8; DHKEM_P384_SHARED_SECRET_LEN],
            &kem_context,
            &t0,
            enc_q,
            enc_c,
            &header.suite_id,
            header.profile,
        )
        .unwrap()
    }

    fn v4_fixture() -> (
        Vec<u8>,
        DaylightEnvelopeV4,
        DaylightKeyScheduleV4,
        DaylightPrecheckEvidenceV2,
    ) {
        let artifact = b"daylight v4 artifact".to_vec();
        let claims = vec![
            Claim::Research,
            Claim::Proof,
            Claim::ReleaseCandidate,
            Claim::HybridEvidence,
        ];
        let header = v4_header(
            &artifact,
            &claims,
            Profile::D2Hybrid,
            2,
            Mode::Hybrid,
            Action::Release,
            DaylightContentScopeV4::MetadataOnly,
        );
        let enc_q = vec![0x44u8; ml_kem_1024::CT_LEN];
        let enc_c = v2_enc_c();
        let schedule = v4_schedule(&header, &enc_q, &enc_c);
        let envelope = daylight_seal_v4_with_schedule(
            header,
            claims,
            AeadAlgorithm::Aes256Gcm,
            &schedule,
            enc_q,
            enc_c,
            &artifact,
        )
        .unwrap();
        (artifact, envelope, schedule, v2_prechecks_all_passed())
    }

    fn v4_kem_fixture() -> (
        Vec<u8>,
        DaylightEnvelopeV4,
        DaylightRecipientSecretKeysV4,
        DaylightPrecheckEvidenceV2,
    ) {
        let vector = daylight_v4_reference_vector().unwrap();
        (
            vector.artifact,
            vector.envelope,
            vector.recipient_secret_keys,
            vector.prechecks,
        )
    }

    #[test]
    fn daylight_v4_encoding_uses_canonical_cbor_subset() {
        assert_eq!(enc_value(&EncValue::UInt(23)).unwrap(), vec![0x17]);
        assert_eq!(enc_value(&EncValue::UInt(24)).unwrap(), vec![0x18, 0x18]);
        assert_eq!(
            enc_value(&EncValue::Bytes(b"abc")).unwrap(),
            b"\x43abc".to_vec()
        );
        assert_eq!(
            enc_value(&EncValue::Text("abc")).unwrap(),
            b"\x63abc".to_vec()
        );
        assert_eq!(
            enc_value(&EncValue::List(vec![
                EncValue::Text("a"),
                EncValue::UInt(1)
            ]))
            .unwrap(),
            b"\x82\x61a\x01".to_vec()
        );
    }

    #[test]
    fn daylight_v4_decoder_rejects_noncanonical_cbor_subset() {
        assert_eq!(
            decode_enc_value(&[0x18, 0x17]),
            Err(DaylightCryptoError::DecodeRejected(
                "non-minimal CBOR integer or length"
            ))
        );
        assert_eq!(
            decode_enc_value(b"\x78\x03abc"),
            Err(DaylightCryptoError::DecodeRejected(
                "non-minimal CBOR integer or length"
            ))
        );
        assert_eq!(
            decode_enc_value(&[0x9f, 0xff]),
            Err(DaylightCryptoError::DecodeRejected(
                "indefinite-length CBOR is forbidden"
            ))
        );
        assert_eq!(
            decode_enc_value(&[0xa0]),
            Err(DaylightCryptoError::DecodeRejected(
                "unsupported CBOR major type"
            ))
        );
        assert_eq!(
            decode_enc_value(&[0x01, 0x02]),
            Err(DaylightCryptoError::DecodeRejected("trailing CBOR data"))
        );
        assert_eq!(
            decode_enc_value(&[0x43, 0x61]),
            Err(DaylightCryptoError::DecodeRejected("truncated CBOR input"))
        );
    }

    #[test]
    fn daylight_v4_header_decode_roundtrips_and_rebuilds_t0() {
        let artifact = b"daylight v4 public commitment artifact";
        let claims = vec![
            Claim::Research,
            Claim::Proof,
            Claim::OpenEvidence,
            Claim::ReleaseCandidate,
        ];
        let header = v4_header(
            artifact,
            &claims,
            Profile::D2Hybrid,
            2,
            Mode::Hybrid,
            Action::Release,
            DaylightContentScopeV4::PublicCommitment,
        );
        let encoded = daylight_header_bytes_v4(&header).unwrap();
        assert_eq!(daylight_decode_header_v4(&encoded).unwrap(), header);
        assert_eq!(
            daylight_t0_v4_from_header_bytes(&encoded).unwrap(),
            daylight_t0_v4(&header).unwrap()
        );
    }

    #[test]
    fn daylight_v4_header_decode_rejects_wrong_types_and_modes() {
        let artifact = b"daylight v4 malformed header";
        let claims = vec![Claim::Research, Claim::Proof];
        let mut header = v4_header(
            artifact,
            &claims,
            Profile::D2Hybrid,
            1,
            Mode::Hybrid,
            Action::Open,
            DaylightContentScopeV4::MetadataOnly,
        );

        header.mode = Mode::Compact;
        let compact = daylight_header_bytes_v4(&header).unwrap();
        assert_eq!(
            daylight_decode_header_v4(&compact),
            Err(DaylightCryptoError::DecodeRejected(
                "compact is not openable in v4"
            ))
        );

        header.mode = Mode::Hybrid;
        header.version = 3;
        let wrong_version = daylight_header_bytes_v4(&header).unwrap();
        assert_eq!(
            daylight_decode_header_v4(&wrong_version),
            Err(DaylightCryptoError::DecodeRejected(
                "unsupported Daylight header version"
            ))
        );

        header.version = 4;
        header.release_level = 4;
        let bad_release = daylight_header_bytes_v4(&header).unwrap();
        assert_eq!(
            daylight_decode_header_v4(&bad_release),
            Err(DaylightCryptoError::DecodeRejected(
                "release level out of range"
            ))
        );

        let zero64 = [0u8; 64];
        let malformed = EncValue::List(vec![
            EncValue::UInt(4),
            EncValue::Text("not-bytes"),
            EncValue::Text("D2-HYBRID"),
            EncValue::UInt(1),
            EncValue::Text("hybrid"),
            EncValue::Text("open"),
            EncValue::Text("metadata_only"),
            leak_value_v4_value(&DaylightLeakValueV4::LengthOnly(0)),
            EncValue::Bytes(b"policy"),
            EncValue::Bytes(&zero64),
            EncValue::Bytes(&zero64),
            EncValue::Bytes(&zero64),
            EncValue::Bytes(&zero64),
            EncValue::Bytes(&zero64),
            EncValue::Bytes(&zero64),
            EncValue::Bytes(&zero64),
        ]);
        assert_eq!(
            daylight_decode_header_v4(&enc_value(&malformed).unwrap()),
            Err(DaylightCryptoError::DecodeRejected("expected CBOR bytes"))
        );
    }

    #[test]
    fn daylight_v4_envelope_decode_roundtrips_and_rebuilds_open() {
        let (artifact, envelope, secret_keys, prechecks) = v4_kem_fixture();
        let encoded = daylight_envelope_bytes_v4(&envelope).unwrap();
        let decoded = daylight_decode_envelope_v4(&encoded).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(daylight_envelope_bytes_v4(&decoded).unwrap(), encoded);

        let opened = daylight_open_v4_with_kems(&decoded, &secret_keys, &prechecks).unwrap();
        assert_eq!(opened.artifact, artifact);

        let mut wide_record = envelope.clone();
        wide_record.record_index = (1u128 << 80) + 7;
        let wide_encoded = daylight_envelope_bytes_v4(&wide_record).unwrap();
        assert_eq!(
            daylight_decode_envelope_v4(&wide_encoded)
                .unwrap()
                .record_index,
            (1u128 << 80) + 7
        );

        let mut out_of_range = envelope;
        out_of_range.record_index = NONCE_SEQUENCE_LIMIT;
        assert_eq!(
            daylight_envelope_bytes_v4(&out_of_range),
            Err(DaylightCryptoError::InvalidParameter(
                "record index out of range"
            ))
        );
    }

    #[test]
    fn daylight_v4_envelope_decode_rejects_wrong_types_lengths_and_labels() {
        let (_, envelope, _, _) = v4_kem_fixture();
        let record_index = record_index_bytes_v4(envelope.record_index).unwrap();
        let bad_label = enc_value(&EncValue::List(vec![
            EncValue::Text("daylight.envelope.v3"),
            header_value_v4(&envelope.header),
            claims_value(&envelope.claims),
            EncValue::Text(aead_label(envelope.algorithm)),
            EncValue::Bytes(&envelope.enc_q),
            EncValue::Bytes(&envelope.enc_c),
            EncValue::Bytes(&envelope.ciphertext),
            EncValue::Bytes(&envelope.commitment),
            EncValue::Bytes(&record_index),
        ]))
        .unwrap();
        assert_eq!(
            daylight_decode_envelope_v4(&bad_label),
            Err(DaylightCryptoError::DecodeRejected(
                "unknown DaylightEnvelopeV4 label"
            ))
        );

        let bad_algorithm = enc_value(&EncValue::List(vec![
            EncValue::Text("daylight.envelope.v4"),
            header_value_v4(&envelope.header),
            claims_value(&envelope.claims),
            EncValue::Text("AES-128-GCM"),
            EncValue::Bytes(&envelope.enc_q),
            EncValue::Bytes(&envelope.enc_c),
            EncValue::Bytes(&envelope.ciphertext),
            EncValue::Bytes(&envelope.commitment),
            EncValue::Bytes(&record_index),
        ]))
        .unwrap();
        assert_eq!(
            daylight_decode_envelope_v4(&bad_algorithm),
            Err(DaylightCryptoError::DecodeRejected(
                "unknown AEAD algorithm"
            ))
        );

        let bad_enc_q = enc_value(&EncValue::List(vec![
            EncValue::Text("daylight.envelope.v4"),
            header_value_v4(&envelope.header),
            claims_value(&envelope.claims),
            EncValue::Text(aead_label(envelope.algorithm)),
            EncValue::Bytes(&envelope.enc_q[..10]),
            EncValue::Bytes(&envelope.enc_c),
            EncValue::Bytes(&envelope.ciphertext),
            EncValue::Bytes(&envelope.commitment),
            EncValue::Bytes(&record_index),
        ]))
        .unwrap();
        assert_eq!(
            daylight_decode_envelope_v4(&bad_enc_q),
            Err(DaylightCryptoError::DecodeRejected(
                "unexpected ML-KEM ciphertext length"
            ))
        );

        let bad_record_type = enc_value(&EncValue::List(vec![
            EncValue::Text("daylight.envelope.v4"),
            header_value_v4(&envelope.header),
            claims_value(&envelope.claims),
            EncValue::Text(aead_label(envelope.algorithm)),
            EncValue::Bytes(&envelope.enc_q),
            EncValue::Bytes(&envelope.enc_c),
            EncValue::Bytes(&envelope.ciphertext),
            EncValue::Bytes(&envelope.commitment),
            EncValue::UInt(0),
        ]))
        .unwrap();
        assert_eq!(
            daylight_decode_envelope_v4(&bad_record_type),
            Err(DaylightCryptoError::DecodeRejected("expected CBOR bytes"))
        );
    }

    #[test]
    fn daylight_v4_reference_vector_file_matches_implementation() {
        let persisted = parse_vector_file(include_str!(
            "../vectors/daylight-v4-reference-vector-v1.txt"
        ));
        let vector = daylight_v4_reference_vector().unwrap();
        let opened = daylight_open_v4_with_kems(
            &vector.envelope,
            &vector.recipient_secret_keys,
            &vector.prechecks,
        )
        .unwrap();
        let envelope_digest = digest_vector(&vector.envelope_bytes);
        let header_digest = digest_vector(&vector.header_bytes);
        let t0_digest = digest_vector(&vector.t0);
        let t1_digest = digest_vector(&vector.t1);
        let enc_q_digest = digest_vector(&vector.envelope.enc_q);

        assert_eq!(
            vector_field(&persisted, "version"),
            "daylight-v4-reference-vector-v1"
        );
        assert_eq!(
            vector_field(&persisted, "artifact_hex"),
            hex_lower(&vector.artifact)
        );
        assert_eq!(
            vector_field(&persisted, "envelope_sha3_512_hex"),
            hex_lower(&envelope_digest.sha3_512)
        );
        assert_eq!(
            vector_field(&persisted, "header_sha3_512_hex"),
            hex_lower(&header_digest.sha3_512)
        );
        assert_eq!(
            vector_field(&persisted, "header_hex"),
            hex_lower(&vector.header_bytes)
        );
        assert_eq!(
            daylight_decode_header_v4(&hex_to_vec(vector_field(&persisted, "header_hex"))).unwrap(),
            vector.envelope.header
        );
        assert_eq!(
            vector_field(&persisted, "t0_sha3_512_hex"),
            hex_lower(&t0_digest.sha3_512)
        );
        assert_eq!(
            vector_field(&persisted, "t1_sha3_512_hex"),
            hex_lower(&t1_digest.sha3_512)
        );
        assert_eq!(
            vector_field(&persisted, "auth_msg_hex"),
            hex_lower(&vector.auth_msg)
        );
        assert_eq!(
            vector_field(&persisted, "suite_id_hex"),
            hex_lower(&vector.envelope.header.suite_id)
        );
        assert_eq!(
            vector_field(&persisted, "enc_q_sha3_512_hex"),
            hex_lower(&enc_q_digest.sha3_512)
        );
        assert_eq!(
            vector_field(&persisted, "enc_c_hex"),
            hex_lower(&vector.envelope.enc_c)
        );
        assert_eq!(
            vector_field(&persisted, "ciphertext_hex"),
            hex_lower(&vector.envelope.ciphertext)
        );
        assert_eq!(
            vector_field(&persisted, "commitment_hex"),
            hex_lower(&vector.envelope.commitment)
        );
        assert_eq!(
            vector_field(&persisted, "record_index"),
            vector.envelope.record_index.to_string()
        );
        assert_eq!(opened.artifact, vector.artifact);
    }

    #[test]
    fn daylight_v4_negative_parser_vectors_reject() {
        let persisted = parse_vector_file(include_str!(
            "../vectors/daylight-v4-negative-parser-vectors-v1.txt"
        ));
        assert_eq!(
            vector_field(&persisted, "version"),
            "daylight-v4-negative-parser-vectors-v1"
        );
        for case in vector_field(&persisted, "cases").split(',') {
            let target_key = format!("case.{case}.target");
            let input_key = format!("case.{case}.input_hex");
            let expected_key = format!("case.{case}.expected");
            let target = vector_field(&persisted, &target_key);
            let input = hex_to_vec(vector_field(&persisted, &input_key));
            let expected = vector_field(&persisted, &expected_key);
            match target {
                "enc" => assert_decode_rejected(decode_enc_value(&input), expected),
                "header" => assert_decode_rejected(daylight_decode_header_v4(&input), expected),
                "envelope" => assert_decode_rejected(daylight_decode_envelope_v4(&input), expected),
                other => panic!("unknown negative vector target {other}"),
            }
        }
    }

    #[test]
    fn daylight_v4_seal_open_accepts_valid_d2_hybrid_release() {
        let (artifact, envelope, schedule, prechecks) = v4_fixture();
        let opened = daylight_open_v4_with_schedule(&envelope, &schedule, &prechecks).unwrap();
        assert_eq!(opened.artifact, artifact);
        assert!(opened.t0.starts_with(&[0x82]));
        assert!(!opened.t1.is_empty());
        assert!(!opened.auth_msg.is_empty());
    }

    #[test]
    fn daylight_v4_seal_open_with_kems_accepts_valid_d2_hybrid_release() {
        let (artifact, envelope, secret_keys, prechecks) = v4_kem_fixture();
        let opened = daylight_open_v4_with_kems(&envelope, &secret_keys, &prechecks).unwrap();
        assert_eq!(opened.artifact, artifact);
        assert_eq!(envelope.enc_q.len(), ml_kem_1024::CT_LEN);
        assert!(dhkem_p384_parse_public_key(&envelope.enc_c).is_ok());
        assert!(!opened.auth_msg.is_empty());
    }

    #[test]
    fn daylight_v4_seal_with_rng_roundtrips_and_changes_encapsulations() {
        let artifact = b"daylight v4 rng seal artifact".to_vec();
        let claims = vec![
            Claim::Research,
            Claim::Proof,
            Claim::ReleaseCandidate,
            Claim::HybridEvidence,
        ];
        let mlkem = mlkem1024_kat_fixture().unwrap();
        let dhkem =
            dhkem_p384_hkdf_sha384_derive_keypair(b"daylight v4 rng recipient key").unwrap();
        let public_keys = DaylightRecipientPublicKeysV4 {
            mlkem_encaps_key: mlkem.encaps_key,
            dhkem_public_key: dhkem.public_key,
        };
        let secret_keys = DaylightRecipientSecretKeysV4 {
            mlkem_decaps_key: mlkem.decaps_key,
            dhkem_private_key: dhkem.private_key,
        };
        let header = v4_header(
            &artifact,
            &claims,
            Profile::D2Hybrid,
            2,
            Mode::Hybrid,
            Action::Release,
            DaylightContentScopeV4::MetadataOnly,
        );
        let mut first_rng = KatRng::new([0x51u8; 32]);
        let first = daylight_seal_v4_with_kems_rng(
            header.clone(),
            claims.clone(),
            AeadAlgorithm::Aes256Gcm,
            &public_keys,
            &mut first_rng,
            &artifact,
        )
        .unwrap();
        let opened =
            daylight_open_v4_with_kems(&first, &secret_keys, &v2_prechecks_all_passed()).unwrap();
        assert_eq!(opened.artifact, artifact);

        let mut second_rng = KatRng::new([0x52u8; 32]);
        let second = daylight_seal_v4_with_kems_rng(
            header,
            claims,
            AeadAlgorithm::Aes256Gcm,
            &public_keys,
            &mut second_rng,
            &artifact,
        )
        .unwrap();
        assert_ne!(first.enc_q, second.enc_q);
        assert_ne!(first.enc_c, second.enc_c);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn daylight_v4_public_precheck_failure_happens_before_aead() {
        let (_, envelope, mut schedule, mut prechecks) = v4_fixture();
        schedule.envelope_key[0] ^= 0x80;
        prechecks.gate_ok = false;
        assert_eq!(
            daylight_open_v4_with_schedule(&envelope, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Gate))
        );
    }

    #[test]
    fn daylight_v4_kem_open_fails_closed_on_derivation_failure() {
        let (_, envelope, mut secret_keys, prechecks) = v4_kem_fixture();
        secret_keys.mlkem_decaps_key.pop();
        assert_eq!(
            daylight_open_v4_with_kems(&envelope, &secret_keys, &prechecks),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::Derive
            ))
        );
    }

    #[test]
    fn daylight_v4_kem_open_public_precheck_failure_happens_before_derivation() {
        let (_, envelope, mut secret_keys, mut prechecks) = v4_kem_fixture();
        secret_keys.mlkem_decaps_key.clear();
        secret_keys.dhkem_private_key = [0u8; DHKEM_P384_PRIVATE_KEY_LEN];
        prechecks.gate_ok = false;
        assert_eq!(
            daylight_open_v4_with_kems(&envelope, &secret_keys, &prechecks),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Gate))
        );
    }

    #[test]
    fn daylight_v4_open_fails_closed_on_core_negative_cases() {
        let (artifact, envelope, schedule, prechecks) = v4_fixture();

        let mut compact = envelope.clone();
        compact.header.mode = Mode::Compact;
        assert_eq!(
            daylight_open_v4_with_schedule(&compact, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Mode))
        );

        let mut bad_enc_c = envelope.clone();
        bad_enc_c.enc_c[0] = 0x00;
        assert_eq!(
            daylight_open_v4_with_schedule(&bad_enc_c, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Env))
        );

        let mut bad_ciphertext = envelope.clone();
        bad_ciphertext.ciphertext[0] ^= 0x80;
        assert_eq!(
            daylight_open_v4_with_schedule(&bad_ciphertext, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Aead))
        );

        let mut bad_commitment = envelope.clone();
        bad_commitment.commitment[0] ^= 0x80;
        assert_eq!(
            daylight_open_v4_with_schedule(&bad_commitment, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::Commit
            ))
        );

        let claims = envelope.claims.clone();
        let mut leak_header = v4_header(
            &artifact,
            &claims,
            Profile::D2Hybrid,
            2,
            Mode::Hybrid,
            Action::Release,
            DaylightContentScopeV4::PublicCommitment,
        );
        leak_header.leak_value = DaylightLeakValueV4::PublicCommitment {
            len: artifact.len() as u64,
            artifact_hash: v2_hash(b"wrong artifact hash"),
        };
        let enc_q = vec![0x44u8; ml_kem_1024::CT_LEN];
        let enc_c = v2_enc_c();
        let leak_schedule = v4_schedule(&leak_header, &enc_q, &enc_c);
        let t0 = daylight_t0_v4(&leak_header).unwrap();
        let ciphertext = aead_seal(
            AeadAlgorithm::Aes256Gcm,
            &leak_schedule.envelope_key,
            &leak_schedule.base_nonce,
            &t0,
            &artifact,
        )
        .unwrap();
        let commitment = daylight_artifact_commitment_v4(
            &leak_schedule.commitment_key,
            &t0,
            &ciphertext,
            &artifact,
        )
        .unwrap();
        let leak_envelope = DaylightEnvelopeV4 {
            header: leak_header,
            claims,
            algorithm: AeadAlgorithm::Aes256Gcm,
            enc_q,
            enc_c,
            ciphertext,
            commitment,
            record_index: 0,
        };
        assert_eq!(
            daylight_open_v4_with_schedule(&leak_envelope, &leak_schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(DaylightOpenFailure::Leak))
        );
    }

    #[test]
    fn daylight_v4_frost_extension_remains_fail_closed() {
        let artifact = b"daylight v4 frost artifact".to_vec();
        let claims = vec![Claim::Research, Claim::Proof, Claim::ReleaseCandidate];
        let header = v4_header(
            &artifact,
            &claims,
            Profile::D2HybridFrost,
            2,
            Mode::Hybrid,
            Action::Release,
            DaylightContentScopeV4::MetadataOnly,
        );
        let enc_q = vec![0x44u8; ml_kem_1024::CT_LEN];
        let enc_c = v2_enc_c();
        let schedule = v4_schedule(&header, &enc_q, &enc_c);
        let envelope = daylight_seal_v4_with_schedule(
            header,
            claims,
            AeadAlgorithm::Aes256Gcm,
            &schedule,
            enc_q,
            enc_c,
            &artifact,
        )
        .unwrap();
        let mut prechecks = v2_prechecks_all_passed();
        prechecks.auth_f_ok = true;
        assert_eq!(
            daylight_open_v4_with_schedule(&envelope, &schedule, &prechecks),
            Err(DaylightCryptoError::OpenRejected(
                DaylightOpenFailure::AuthFUnsupported
            ))
        );
    }

    #[test]
    fn aes256_gcm_matches_empty_known_answer_vector() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let sealed = aead_seal(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"", b"").unwrap();
        assert_eq!(hex_lower(&sealed), "530f8afbc74536b9a963b4f1c4cb738b");
        assert_eq!(
            aead_open(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"", &sealed).unwrap(),
            b""
        );
    }

    #[test]
    fn aead_roundtrips_and_rejects_tampering() {
        for algorithm in [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::ChaCha20Poly1305] {
            let key = [0x42u8; 32];
            let nonce = [0x24u8; 12];
            let aad = b"daylight aad";
            let plaintext = b"daylight plaintext";
            let sealed = aead_seal(algorithm, &key, &nonce, aad, plaintext).unwrap();
            assert_eq!(
                aead_open(algorithm, &key, &nonce, aad, &sealed).unwrap(),
                plaintext
            );

            let mut bad_sealed = sealed.clone();
            bad_sealed[0] ^= 0x80;
            assert_eq!(
                aead_open(algorithm, &key, &nonce, aad, &bad_sealed),
                Err(DaylightCryptoError::AeadRejected)
            );
            assert_eq!(
                aead_open(algorithm, &key, &nonce, b"wrong aad", &sealed),
                Err(DaylightCryptoError::AeadRejected)
            );
        }
    }

    #[test]
    fn argon2id_derives_stable_password_keys() {
        let first =
            argon2id_derive(b"daylight password", b"daylight salt 0001", 19, 2, 1, 32).unwrap();
        let second =
            argon2id_derive(b"daylight password", b"daylight salt 0001", 19, 2, 1, 32).unwrap();
        let other_salt =
            argon2id_derive(b"daylight password", b"daylight salt 0002", 19, 2, 1, 32).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, other_salt);
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn argon2id_rejects_weak_inputs() {
        assert_eq!(
            argon2id_derive(b"", b"daylight salt 0001", 19, 2, 1, 32),
            Err(DaylightCryptoError::InvalidParameter(
                "Argon2id password must not be empty"
            ))
        );
        assert_eq!(
            argon2id_derive(b"password", b"short", 19, 2, 1, 32),
            Err(DaylightCryptoError::InvalidParameter(
                "Argon2id salt must be at least 16 bytes"
            ))
        );
        assert_eq!(
            argon2id_derive(b"password", b"daylight salt 0001", 1, 0, 1, 32),
            Err(DaylightCryptoError::KdfRejected)
        );
    }

    #[test]
    fn dhkem_p384_raw_ecdh_matches_curve_vector() {
        let private_key: [u8; DHKEM_P384_PRIVATE_KEY_LEN] = hex_to_vec(
            "099f3c7034d4a2c699884d73a375a67f7624ef7c6b3c0f160647b67414dce655\
             e35b538041e649ee3faef896783ab194",
        )
        .try_into()
        .unwrap();
        let public_key: [u8; DHKEM_P384_PUBLIC_KEY_LEN] = hex_to_vec(
            "04e558dbef53eecde3d3fccfc1aea08a89a987475d12fd950d83cfa41732bc\
             509d0d1ac43a0336def96fda41d0774a3571dcfbec7aacf3196472169e8384\
             30367f66eebe3c6e70c416dd5f0c68759dd1fff83fa40142209dff5eaad96d\
             b9e6386c",
        )
        .try_into()
        .unwrap();
        let expected = hex_to_vec(
            "11187331c279962d93d604243fd592cb9d0a926f422e47187521287e7156c5c4\
             d603135569b9e9d09cf5d4a270f59746",
        );
        let private_key = dhkem_p384_parse_private_key(&private_key).unwrap();
        let public_key = dhkem_p384_parse_public_key(&public_key).unwrap();
        assert_eq!(
            dhkem_p384_raw_dh(&private_key, &public_key)
                .unwrap()
                .to_vec(),
            expected
        );
    }

    #[test]
    fn dhkem_p384_hkdf_sha384_encapsulates_and_decapsulates() {
        let recipient =
            dhkem_p384_hkdf_sha384_derive_keypair(b"wuci daylight dhkem p384 recipient ikm v1")
                .unwrap();
        assert_eq!(recipient.private_key.len(), DHKEM_P384_PRIVATE_KEY_LEN);
        assert_eq!(recipient.public_key.len(), DHKEM_P384_PUBLIC_KEY_LEN);
        assert_eq!(recipient.public_key[0], 0x04);
        assert_eq!(
            dhkem_p384_hkdf_sha384_public_key_from_private(&recipient.private_key).unwrap(),
            recipient.public_key
        );

        let encapsulation = dhkem_p384_hkdf_sha384_encaps_from_ikm(
            &recipient.public_key,
            b"wuci daylight dhkem p384 ephemeral ikm v1",
        )
        .unwrap();
        let repeated = dhkem_p384_hkdf_sha384_encaps_from_ikm(
            &recipient.public_key,
            b"wuci daylight dhkem p384 ephemeral ikm v1",
        )
        .unwrap();
        assert_eq!(encapsulation, repeated);
        assert_eq!(encapsulation.encapped_key[0], 0x04);
        assert_eq!(
            dhkem_p384_hkdf_sha384_decaps(&recipient.private_key, &encapsulation.encapped_key)
                .unwrap(),
            encapsulation.shared_secret
        );

        let other = dhkem_p384_hkdf_sha384_encaps_from_ikm(
            &recipient.public_key,
            b"wuci daylight dhkem p384 other ephemeral ikm v1",
        )
        .unwrap();
        assert_ne!(other.encapped_key, encapsulation.encapped_key);
        assert_ne!(other.shared_secret, encapsulation.shared_secret);
    }

    #[test]
    fn dhkem_p384_hkdf_sha384_rejects_invalid_keys() {
        let recipient =
            dhkem_p384_hkdf_sha384_derive_keypair(b"wuci daylight dhkem p384 recipient ikm v1")
                .unwrap();
        let mut bad_public_key = recipient.public_key;
        bad_public_key[0] = 0x05;
        assert_eq!(
            dhkem_p384_hkdf_sha384_encaps_from_ikm(
                &bad_public_key,
                b"wuci daylight dhkem p384 ephemeral ikm v1"
            ),
            Err(DaylightCryptoError::InvalidPublicKey)
        );

        let zero_private_key = [0u8; DHKEM_P384_PRIVATE_KEY_LEN];
        let encapsulation = dhkem_p384_hkdf_sha384_encaps_from_ikm(
            &recipient.public_key,
            b"wuci daylight dhkem p384 ephemeral ikm v1",
        )
        .unwrap();
        assert_eq!(
            dhkem_p384_hkdf_sha384_decaps(&zero_private_key, &encapsulation.encapped_key),
            Err(DaylightCryptoError::InvalidDecapsulationKey)
        );

        let mut bad_encapped_key = encapsulation.encapped_key;
        bad_encapped_key[0] = 0x00;
        assert_eq!(
            dhkem_p384_hkdf_sha384_decaps(&recipient.private_key, &bad_encapped_key),
            Err(DaylightCryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn mlkem1024_kat_encapsulates_and_decapsulates() {
        let kat = mlkem1024_kat_fixture().unwrap();
        assert_eq!(kat.encaps_key.len(), ml_kem_1024::EK_LEN);
        assert_eq!(kat.decaps_key.len(), ml_kem_1024::DK_LEN);
        assert_eq!(kat.ciphertext.len(), ml_kem_1024::CT_LEN);
        assert_eq!(
            mlkem1024_decaps(&kat.decaps_key, &kat.ciphertext).unwrap(),
            kat.shared_secret
        );

        let mut bad_ciphertext = kat.ciphertext.clone();
        bad_ciphertext[0] ^= 0x80;
        assert_ne!(
            mlkem1024_decaps(&kat.decaps_key, &bad_ciphertext).unwrap(),
            kat.shared_secret
        );
    }

    #[test]
    fn mlkem1024_rejects_bad_lengths() {
        let kat = mlkem1024_kat_fixture().unwrap();
        assert_eq!(
            mlkem1024_encaps_from_seed(
                &kat.encaps_key[..kat.encaps_key.len() - 1],
                &MLKEM1024_KAT_M_SEED,
            ),
            Err(DaylightCryptoError::InvalidLength {
                name: "ML-KEM-1024 encapsulation key",
                expected: ml_kem_1024::EK_LEN,
                actual: ml_kem_1024::EK_LEN - 1,
            })
        );
        assert_eq!(
            mlkem1024_decaps(&kat.decaps_key, &kat.ciphertext[..kat.ciphertext.len() - 1]),
            Err(DaylightCryptoError::InvalidLength {
                name: "ML-KEM-1024 ciphertext",
                expected: ml_kem_1024::CT_LEN,
                actual: ml_kem_1024::CT_LEN - 1,
            })
        );
    }

    #[test]
    fn mldsa87_kat_accepts_and_rejects_mutations() {
        let kat = mldsa87_kat_fixture().unwrap();
        verify_mldsa87(
            &kat.public_key,
            &kat.message,
            &kat.signature,
            DAYLIGHT_AUTH_CONTEXT,
        )
        .unwrap();

        let mut bad_signature = kat.signature.clone();
        bad_signature[0] ^= 0x80;
        assert_eq!(
            verify_mldsa87(
                &kat.public_key,
                &kat.message,
                &bad_signature,
                DAYLIGHT_AUTH_CONTEXT,
            ),
            Err(DaylightCryptoError::VerificationRejected)
        );

        let mut bad_message = kat.message.clone();
        bad_message.push(b'!');
        assert_eq!(
            verify_mldsa87(
                &kat.public_key,
                &bad_message,
                &kat.signature,
                DAYLIGHT_AUTH_CONTEXT,
            ),
            Err(DaylightCryptoError::VerificationRejected)
        );
    }

    #[test]
    #[ignore = "SLH-DSA-SHAKE-256s KAT is intentionally slow in debug builds"]
    fn slhdsa_shake_256s_kat_accepts_and_rejects_mutations() {
        let kat = slhdsa_shake_256s_kat_fixture().unwrap();
        verify_slhdsa_shake_256s(
            &kat.public_key,
            &kat.message,
            &kat.signature,
            DAYLIGHT_AUTH_CONTEXT,
        )
        .unwrap();

        let mut bad_signature = kat.signature.clone();
        bad_signature[0] ^= 0x80;
        assert_eq!(
            verify_slhdsa_shake_256s(
                &kat.public_key,
                &kat.message,
                &bad_signature,
                DAYLIGHT_AUTH_CONTEXT,
            ),
            Err(DaylightCryptoError::VerificationRejected)
        );

        let mut bad_message = kat.message.clone();
        bad_message.push(b'!');
        assert_eq!(
            verify_slhdsa_shake_256s(
                &kat.public_key,
                &bad_message,
                &kat.signature,
                DAYLIGHT_AUTH_CONTEXT,
            ),
            Err(DaylightCryptoError::VerificationRejected)
        );
    }

    #[test]
    fn mldsa87_rejects_bad_lengths_and_contexts() {
        let kat = mldsa87_kat_fixture().unwrap();
        assert_eq!(
            verify_mldsa87(
                &kat.public_key[..kat.public_key.len() - 1],
                &kat.message,
                &kat.signature,
                DAYLIGHT_AUTH_CONTEXT,
            ),
            Err(DaylightCryptoError::InvalidLength {
                name: "ML-DSA-87 public key",
                expected: ml_dsa_87::PK_LEN,
                actual: ml_dsa_87::PK_LEN - 1,
            })
        );
        assert_eq!(
            verify_mldsa87(&kat.public_key, &kat.message, &kat.signature, &[0u8; 256]),
            Err(DaylightCryptoError::ContextTooLong { actual: 256 })
        );
    }

    #[test]
    fn unsupported_primitives_fail_closed() {
        assert_eq!(
            unsupported(UnsupportedPrimitive::FrostCustomP384Sha384),
            Err(DaylightCryptoError::Unsupported(
                UnsupportedPrimitive::FrostCustomP384Sha384
            ))
        );
    }

    #[test]
    fn hex_helper_is_lowercase() {
        assert_eq!(hex_lower(&hex_to_vec("00abcdef")), "00abcdef");
    }
}
