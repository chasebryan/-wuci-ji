//! Penumbra v1 evidence-derived envelope.
//!
//! This crate implements the byte-exact `WJSEAL` wire format, HKDF-SHA-256 key
//! derivation, ChaCha20-Poly1305 sealing/opening, and keyless inspection. Policy
//! and witness verification are supplied through [`TranscriptVerifier`] so the
//! crypto envelope cannot accidentally consume asserted scorecard bytes as proof.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: [u8; 16] = *b"WJSEAL\0PENUMBRA\0";
pub const VERSION: u16 = 1;
pub const KDF_ID_HKDF_SHA256: u8 = 1;
pub const AEAD_ID_CHACHA20_POLY1305: u8 = 1;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const TAU_TAG: &[u8] = b"wuci-daylight/penumbra/tau/v1";
pub const SECRET_TAG: &[u8] = b"wuci-daylight/penumbra/secret/v1";
pub const KDF_LABEL: &[u8] = b"wuci-daylight/penumbra/v1";
pub const DEFAULT_CANON_DESCRIPTOR: &[u8] =
    b"daylight-v15-meridian/canonical-transcript/file-verifier-v1";

const MAX_FIELD_LEN: usize = 16 * 1024 * 1024;
const MAX_CIPHERTEXT_LEN: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    SealedSecret,
    SealedPublic,
}

impl Mode {
    pub fn from_wire(value: u8) -> Result<Self, PenumbraError> {
        match value {
            1 => Ok(Self::SealedSecret),
            2 => Ok(Self::SealedPublic),
            _ => Err(PenumbraError::ParseRejected("unknown mode")),
        }
    }

    pub fn to_wire(self) -> u8 {
        match self {
            Self::SealedSecret => 1,
            Self::SealedPublic => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SealedSecret => "SEALED_SECRET",
            Self::SealedPublic => "SEALED_PUBLIC",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PenumbraError {
    InvalidInput(&'static str),
    LengthOverflow(&'static str),
    ParseRejected(&'static str),
    PolicyRefused,
    CryptoRejected,
    OpenRefused,
    RandomRejected,
}

impl fmt::Display for PenumbraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::LengthOverflow(msg) => write!(f, "length overflow: {msg}"),
            Self::ParseRejected(msg) => write!(f, "parse rejected: {msg}"),
            Self::PolicyRefused => write!(f, "policy refused"),
            Self::CryptoRejected => write!(f, "cryptographic operation rejected"),
            Self::OpenRefused => write!(f, "open refused"),
            Self::RandomRejected => write!(f, "OS random source rejected"),
        }
    }
}

impl std::error::Error for PenumbraError {}

pub trait TranscriptVerifier {
    fn verify_and_transcript(
        &self,
        policy: &[u8],
        witness: &[u8],
        canon_descriptor: &[u8],
    ) -> Result<Vec<u8>, PenumbraError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FileTranscriptVerifier;

impl TranscriptVerifier for FileTranscriptVerifier {
    fn verify_and_transcript(
        &self,
        policy: &[u8],
        witness: &[u8],
        canon_descriptor: &[u8],
    ) -> Result<Vec<u8>, PenumbraError> {
        let parsed = FileWitness::parse(witness)?;
        if parsed.policy_sha256 != sha256_hex(policy) {
            return Err(PenumbraError::PolicyRefused);
        }
        if parsed.canon_descriptor_sha256 != sha256_hex(canon_descriptor) {
            return Err(PenumbraError::PolicyRefused);
        }
        Ok(parsed.base_transcript)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HeaderCore {
    pub mode: Mode,
    pub policy: Vec<u8>,
    pub canon_descriptor: Vec<u8>,
    pub seal_salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub asserted_entropy_bits: Option<u16>,
}

impl HeaderCore {
    pub fn encode(&self) -> Result<Vec<u8>, PenumbraError> {
        let mut out =
            Vec::with_capacity(16 + 2 + 1 + self.policy.len() + self.canon_descriptor.len() + 64);
        out.extend_from_slice(&MAGIC);
        put_u16(&mut out, VERSION);
        out.push(self.mode.to_wire());
        put_bytes(&mut out, &self.policy, "policy")?;
        put_bytes(&mut out, &self.canon_descriptor, "canon_descriptor")?;
        out.push(KDF_ID_HKDF_SHA256);
        put_bytes(&mut out, KDF_LABEL, "kdf_label")?;
        out.extend_from_slice(&self.seal_salt);
        out.push(AEAD_ID_CHACHA20_POLY1305);
        out.extend_from_slice(&self.nonce);
        match self.asserted_entropy_bits {
            Some(bits) => {
                out.push(1);
                put_u16(&mut out, bits);
            }
            None => {
                out.push(0);
            }
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EnvelopeParts {
    pub header: HeaderCore,
    pub header_core: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

#[derive(Clone, Copy)]
pub struct SealRequest<'a> {
    pub policy: &'a [u8],
    pub canon_descriptor: &'a [u8],
    pub mode: Mode,
    pub public_witness: &'a [u8],
    pub secret_component: Option<&'a [u8]>,
    pub asserted_entropy_bits: Option<u16>,
    pub seal_salt: Option<[u8; SALT_LEN]>,
    pub nonce: Option<[u8; NONCE_LEN]>,
}

#[derive(Clone, Copy)]
pub struct OpenRequest<'a> {
    pub envelope: &'a [u8],
    pub public_witness: &'a [u8],
    pub secret_component: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InspectReport {
    pub version: u16,
    pub mode: Mode,
    pub policy_len: usize,
    pub policy_sha256: String,
    pub policy_descriptor: String,
    pub canon_descriptor: String,
    pub kdf_id: u8,
    pub aead_id: u8,
    pub ciphertext_len: usize,
    pub asserted_entropy_bits: Option<u16>,
    pub header_sha256: String,
}

impl InspectReport {
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("Penumbra WJSEAL inspect\n");
        out.push_str(&format!("version: {}\n", self.version));
        out.push_str(&format!("mode: {}\n", self.mode.as_str()));
        out.push_str(&format!("policy_len: {}\n", self.policy_len));
        out.push_str(&format!("policy_sha256: {}\n", self.policy_sha256));
        out.push_str(&format!("policy_descriptor: {}\n", self.policy_descriptor));
        out.push_str(&format!("canon_descriptor: {}\n", self.canon_descriptor));
        out.push_str(&format!("kdf_id: {}\n", self.kdf_id));
        out.push_str(&format!("aead_id: {}\n", self.aead_id));
        out.push_str(&format!("ciphertext_len: {}\n", self.ciphertext_len));
        out.push_str(&format!("header_sha256: {}\n", self.header_sha256));
        out.push_str("AEAD: ChaCha20-Poly1305 - key recovery ~2^256 classical / ~2^128 Grover\n");
        match self.mode {
            Mode::SealedPublic => {
                out.push_str(
                    "CONFIDENTIALITY: NONE (public witness). Integrity / policy-binding only.\n",
                );
            }
            Mode::SealedSecret => {
                let asserted = self
                    .asserted_entropy_bits
                    .map(|bits| bits.to_string())
                    .unwrap_or_else(|| "UNSPECIFIED".to_string());
                out.push_str(&format!(
                    "CONFIDENTIALITY (ASSERTED, NOT PROVEN): min(AEAD, Hinf(tau)) = min(256/128, {asserted})\n"
                ));
                out.push_str(
                    "This tool cannot verify witness entropy. Any strength claim requires external attestation.\n",
                );
            }
        }
        out
    }
}

pub fn seal(
    plaintext: &[u8],
    request: SealRequest<'_>,
    verifier: &impl TranscriptVerifier,
) -> Result<Vec<u8>, PenumbraError> {
    validate_mode_secret(request.mode, request.secret_component)?;
    let mut base = verifier.verify_and_transcript(
        request.policy,
        request.public_witness,
        request.canon_descriptor,
    )?;
    let mut tau = derive_tau(request.mode, &base, request.secret_component)?;
    base.zeroize();

    let seal_salt = match request.seal_salt {
        Some(salt) => salt,
        None => random_array::<SALT_LEN>()?,
    };
    let nonce = match request.nonce {
        Some(nonce) => nonce,
        None => random_array::<NONCE_LEN>()?,
    };

    let header = HeaderCore {
        mode: request.mode,
        policy: request.policy.to_vec(),
        canon_descriptor: request.canon_descriptor.to_vec(),
        seal_salt,
        nonce,
        asserted_entropy_bits: request.asserted_entropy_bits,
    };
    let header_core = header.encode()?;
    let mut key = derive_key(&seal_salt, &tau, &header_core)?;
    tau.zeroize();

    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| PenumbraError::CryptoRejected)?;
    let payload = Payload {
        msg: plaintext,
        aad: &header_core,
    };
    let mut sealed = cipher
        .encrypt((&nonce).into(), payload)
        .map_err(|_| PenumbraError::CryptoRejected)?;
    key.zeroize();
    if sealed.len() < TAG_LEN {
        sealed.zeroize();
        return Err(PenumbraError::CryptoRejected);
    }
    let tag_offset = sealed.len() - TAG_LEN;
    let tag_vec = sealed.split_off(tag_offset);
    let mut envelope = Vec::with_capacity(header_core.len() + 4 + sealed.len() + TAG_LEN);
    envelope.extend_from_slice(&header_core);
    put_u32(&mut envelope, sealed.len() as u32);
    envelope.extend_from_slice(&sealed);
    envelope.extend_from_slice(&tag_vec);
    sealed.zeroize();
    Ok(envelope)
}

pub fn open(
    request: OpenRequest<'_>,
    verifier: &impl TranscriptVerifier,
) -> Result<Vec<u8>, PenumbraError> {
    let parts = parse_envelope(request.envelope).map_err(|_| PenumbraError::OpenRefused)?;
    validate_mode_secret(parts.header.mode, request.secret_component)
        .map_err(|_| PenumbraError::OpenRefused)?;
    let mut base = verifier
        .verify_and_transcript(
            &parts.header.policy,
            request.public_witness,
            &parts.header.canon_descriptor,
        )
        .map_err(|_| PenumbraError::OpenRefused)?;
    let mut tau = derive_tau(parts.header.mode, &base, request.secret_component)
        .map_err(|_| PenumbraError::OpenRefused)?;
    base.zeroize();
    let mut key = derive_key(&parts.header.seal_salt, &tau, &parts.header_core)
        .map_err(|_| PenumbraError::OpenRefused)?;
    tau.zeroize();

    let cipher =
        ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| PenumbraError::OpenRefused)?;
    let mut body = Vec::with_capacity(parts.ciphertext.len() + TAG_LEN);
    body.extend_from_slice(&parts.ciphertext);
    body.extend_from_slice(&parts.tag);
    let payload = Payload {
        msg: &body,
        aad: &parts.header_core,
    };
    let plaintext = cipher
        .decrypt((&parts.header.nonce).into(), payload)
        .map_err(|_| PenumbraError::OpenRefused);
    key.zeroize();
    body.zeroize();
    plaintext
}

pub fn inspect(envelope: &[u8]) -> Result<InspectReport, PenumbraError> {
    let parts = parse_envelope(envelope)?;
    Ok(InspectReport {
        version: VERSION,
        mode: parts.header.mode,
        policy_len: parts.header.policy.len(),
        policy_sha256: sha256_hex(&parts.header.policy),
        policy_descriptor: display_bytes(&parts.header.policy),
        canon_descriptor: display_bytes(&parts.header.canon_descriptor),
        kdf_id: KDF_ID_HKDF_SHA256,
        aead_id: AEAD_ID_CHACHA20_POLY1305,
        ciphertext_len: parts.ciphertext.len(),
        asserted_entropy_bits: parts.header.asserted_entropy_bits,
        header_sha256: sha256_hex(&parts.header_core),
    })
}

pub fn parse_envelope(envelope: &[u8]) -> Result<EnvelopeParts, PenumbraError> {
    if envelope.len() > MAX_CIPHERTEXT_LEN + MAX_FIELD_LEN {
        return Err(PenumbraError::ParseRejected("envelope too large"));
    }
    let mut cursor = Cursor::new(envelope);
    let magic = cursor.take(MAGIC.len(), "magic")?;
    if magic.ct_eq(&MAGIC).unwrap_u8() != 1 {
        return Err(PenumbraError::ParseRejected("bad magic"));
    }
    let version = cursor.u16("version")?;
    if version != VERSION {
        return Err(PenumbraError::ParseRejected("unsupported version"));
    }
    let mode = Mode::from_wire(cursor.u8("mode")?)?;
    let policy = cursor.var_bytes("policy")?.to_vec();
    let canon_descriptor = cursor.var_bytes("canon_descriptor")?.to_vec();
    let kdf_id = cursor.u8("kdf_id")?;
    if kdf_id != KDF_ID_HKDF_SHA256 {
        return Err(PenumbraError::ParseRejected("unknown kdf id"));
    }
    let kdf_label = cursor.var_bytes("kdf_label")?;
    if kdf_label != KDF_LABEL {
        return Err(PenumbraError::ParseRejected("bad kdf label"));
    }
    let seal_salt: [u8; SALT_LEN] = cursor
        .take(SALT_LEN, "seal_salt")?
        .try_into()
        .map_err(|_| PenumbraError::ParseRejected("bad salt"))?;
    let aead_id = cursor.u8("aead_id")?;
    if aead_id != AEAD_ID_CHACHA20_POLY1305 {
        return Err(PenumbraError::ParseRejected("unknown aead id"));
    }
    let nonce: [u8; NONCE_LEN] = cursor
        .take(NONCE_LEN, "nonce")?
        .try_into()
        .map_err(|_| PenumbraError::ParseRejected("bad nonce"))?;
    let asserted_present = cursor.u8("asserted_entropy_present")?;
    let asserted_entropy_bits = match asserted_present {
        0 => None,
        1 => Some(cursor.u16("asserted_entropy_bits")?),
        _ => return Err(PenumbraError::ParseRejected("bad asserted entropy flag")),
    };
    let header_len = cursor.position();
    let header_core = envelope[..header_len].to_vec();
    let ct_len = cursor.u32("ct_len")? as usize;
    if ct_len > MAX_CIPHERTEXT_LEN {
        return Err(PenumbraError::ParseRejected("ciphertext too large"));
    }
    let ciphertext = cursor.take(ct_len, "ciphertext")?.to_vec();
    let tag: [u8; TAG_LEN] = cursor
        .take(TAG_LEN, "tag")?
        .try_into()
        .map_err(|_| PenumbraError::ParseRejected("bad tag"))?;
    if !cursor.is_done() {
        return Err(PenumbraError::ParseRejected("trailing bytes"));
    }
    Ok(EnvelopeParts {
        header: HeaderCore {
            mode,
            policy,
            canon_descriptor,
            seal_salt,
            nonce,
            asserted_entropy_bits,
        },
        header_core,
        ciphertext,
        tag,
    })
}

pub fn build_file_witness(
    policy: &[u8],
    canon_descriptor: &[u8],
    base_transcript: &[u8],
) -> Vec<u8> {
    format!(
        "WJ-PENUMBRA-WITNESS-v1\npolicy_sha256:{}\ncanon_descriptor_sha256:{}\nbase_transcript_hex:{}\n",
        sha256_hex(policy),
        sha256_hex(canon_descriptor),
        hex_encode(base_transcript)
    )
    .into_bytes()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode(input: &str) -> Result<Vec<u8>, PenumbraError> {
    let bytes = input.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(PenumbraError::ParseRejected("hex length must be even"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_value(bytes[index])?;
        let lo = hex_value(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn validate_mode_secret(mode: Mode, secret_component: Option<&[u8]>) -> Result<(), PenumbraError> {
    match (mode, secret_component) {
        (Mode::SealedSecret, Some(secret)) if !secret.is_empty() => Ok(()),
        (Mode::SealedSecret, _) => Err(PenumbraError::InvalidInput(
            "SEALED_SECRET requires a non-empty secret component",
        )),
        (Mode::SealedPublic, None) => Ok(()),
        (Mode::SealedPublic, Some(_)) => Err(PenumbraError::InvalidInput(
            "SEALED_PUBLIC must not receive a secret component",
        )),
    }
}

fn derive_tau(
    mode: Mode,
    base: &[u8],
    secret_component: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, PenumbraError> {
    let mut tau = Zeroizing::new(Vec::with_capacity(TAU_TAG.len() + base.len() + 32));
    tau.extend_from_slice(TAU_TAG);
    tau.extend_from_slice(base);
    if mode == Mode::SealedSecret {
        let secret = secret_component.ok_or(PenumbraError::InvalidInput("missing secret"))?;
        let mut hasher = Sha256::new();
        hasher.update(SECRET_TAG);
        hasher.update(secret);
        let digest = hasher.finalize();
        tau.extend_from_slice(&digest);
    }
    Ok(tau)
}

fn derive_key(
    salt: &[u8; SALT_LEN],
    tau: &[u8],
    header_core: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, PenumbraError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), tau);
    let mut info = Zeroizing::new(Vec::with_capacity(KDF_LABEL.len() + 32));
    info.extend_from_slice(KDF_LABEL);
    info.extend_from_slice(&Sha256::digest(header_core));
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(&info, key.as_mut())
        .map_err(|_| PenumbraError::CryptoRejected)?;
    Ok(key)
}

fn random_array<const N: usize>() -> Result<[u8; N], PenumbraError> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|_| PenumbraError::RandomRejected)?;
    Ok(out)
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8], name: &'static str) -> Result<(), PenumbraError> {
    if bytes.len() > u32::MAX as usize {
        return Err(PenumbraError::LengthOverflow(name));
    }
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
    Ok(())
}

fn display_bytes(bytes: &[u8]) -> String {
    if bytes
        .iter()
        .all(|byte| matches!(*byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
    {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        format!("hex:{}", hex_encode(bytes))
    }
}

fn hex_value(byte: u8) -> Result<u8, PenumbraError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PenumbraError::ParseRejected("invalid hex")),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, len: usize, name: &'static str) -> Result<&'a [u8], PenumbraError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PenumbraError::ParseRejected(name))?;
        if end > self.bytes.len() {
            return Err(PenumbraError::ParseRejected(name));
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self, name: &'static str) -> Result<u8, PenumbraError> {
        Ok(self.take(1, name)?[0])
    }

    fn u16(&mut self, name: &'static str) -> Result<u16, PenumbraError> {
        let bytes = self.take(2, name)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self, name: &'static str) -> Result<u32, PenumbraError> {
        let bytes = self.take(4, name)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn var_bytes(&mut self, name: &'static str) -> Result<&'a [u8], PenumbraError> {
        let len = self.u32(name)? as usize;
        if len > MAX_FIELD_LEN {
            return Err(PenumbraError::ParseRejected(name));
        }
        self.take(len, name)
    }
}

struct FileWitness {
    policy_sha256: String,
    canon_descriptor_sha256: String,
    base_transcript: Vec<u8>,
}

impl FileWitness {
    fn parse(witness: &[u8]) -> Result<Self, PenumbraError> {
        let text = std::str::from_utf8(witness)
            .map_err(|_| PenumbraError::ParseRejected("witness is not utf-8"))?;
        let mut lines = text.lines();
        if lines.next() != Some("WJ-PENUMBRA-WITNESS-v1") {
            return Err(PenumbraError::ParseRejected("bad witness magic"));
        }
        let mut policy_sha256 = None;
        let mut canon_descriptor_sha256 = None;
        let mut base_transcript_hex = None;
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once(':')
                .ok_or(PenumbraError::ParseRejected("bad witness line"))?;
            match key {
                "policy_sha256" => policy_sha256 = Some(value.trim().to_string()),
                "canon_descriptor_sha256" => {
                    canon_descriptor_sha256 = Some(value.trim().to_string())
                }
                "base_transcript_hex" => base_transcript_hex = Some(value.trim().to_string()),
                _ => return Err(PenumbraError::ParseRejected("unknown witness key")),
            }
        }
        let policy_sha256 = validate_hex_digest(
            policy_sha256.ok_or(PenumbraError::ParseRejected("missing policy digest"))?,
        )?;
        let canon_descriptor_sha256 = validate_hex_digest(canon_descriptor_sha256.ok_or(
            PenumbraError::ParseRejected("missing canon descriptor digest"),
        )?)?;
        let base_transcript = hex_decode(
            &base_transcript_hex.ok_or(PenumbraError::ParseRejected("missing transcript"))?,
        )?;
        if base_transcript.is_empty() {
            return Err(PenumbraError::ParseRejected("empty transcript"));
        }
        Ok(Self {
            policy_sha256,
            canon_descriptor_sha256,
            base_transcript,
        })
    }
}

fn validate_hex_digest(value: String) -> Result<String, PenumbraError> {
    if value.len() != 64 || !value.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(PenumbraError::ParseRejected("bad sha256 digest"));
    }
    Ok(value.to_ascii_lowercase())
}
