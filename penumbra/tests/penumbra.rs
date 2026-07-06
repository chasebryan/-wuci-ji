use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use wuci_penumbra::{
    build_file_witness, hex_decode, inspect, open, parse_envelope, seal, FileTranscriptVerifier,
    Mode, OpenRequest, SealRequest, DEFAULT_CANON_DESCRIPTOR,
};

const FORBIDDEN_OUTPUT: &[&str] = &[
    "unbreakable",
    "uncrackable",
    "perfect secrecy",
    "impossible to break",
    "guaranteed secure",
    "quantum-proof",
    "100% secure",
];

fn policy() -> Vec<u8> {
    br#"{"obligations_digest":"fixture","min_score":998900,"predicate":"penumbra-test"}"#.to_vec()
}

fn base_transcript() -> Vec<u8> {
    b"fixture meridian canonical transcript v1".to_vec()
}

fn witness_for(policy: &[u8], base: &[u8]) -> Vec<u8> {
    build_file_witness(policy, DEFAULT_CANON_DESCRIPTOR, base)
}

fn secret() -> Vec<u8> {
    b"fixture high entropy secret component for penumbra tests".to_vec()
}

fn deterministic_secret_envelope() -> Vec<u8> {
    let policy = policy();
    let witness = witness_for(&policy, &base_transcript());
    seal(
        b"sealed message",
        SealRequest {
            policy: &policy,
            canon_descriptor: DEFAULT_CANON_DESCRIPTOR,
            mode: Mode::SealedSecret,
            public_witness: &witness,
            secret_component: Some(&secret()),
            asserted_entropy_bits: Some(192),
            seal_salt: Some([0x11; 32]),
            nonce: Some([0x22; 12]),
        },
        &FileTranscriptVerifier,
    )
    .unwrap()
}

#[test]
fn rfc8439_chacha20_poly1305_vector_passes() {
    let key =
        hex_decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce = hex_decode("070000004041424344454647").unwrap();
    let aad = hex_decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = hex_decode(concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2",
        "a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b",
        "1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58",
        "fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b6116",
        "1ae10b594f09e26a7e902ecbd0600691"
    ))
    .unwrap();
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let actual = cipher
        .encrypt(
            (&nonce[..]).into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn rfc5869_hkdf_sha256_vector_passes() {
    let ikm = vec![0x0b; 22];
    let salt = hex_decode("000102030405060708090a0b0c").unwrap();
    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let expected_okm = hex_decode(concat!(
        "3cb25f25faacd57a90434f64d0362f2a",
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
        "34007208d5b887185865"
    ))
    .unwrap();
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(okm.as_slice(), expected_okm.as_slice());
}

#[test]
fn sealed_secret_round_trip_succeeds() {
    let policy = policy();
    let witness = witness_for(&policy, &base_transcript());
    let envelope = deterministic_secret_envelope();
    let plaintext = open(
        OpenRequest {
            envelope: &envelope,
            public_witness: &witness,
            secret_component: Some(&secret()),
        },
        &FileTranscriptVerifier,
    )
    .unwrap();
    assert_eq!(plaintext, b"sealed message");
}

#[test]
fn sealed_secret_is_deterministic_when_test_material_is_injected() {
    let first = deterministic_secret_envelope();
    let second = deterministic_secret_envelope();
    assert_eq!(first, second);
}

#[test]
fn wrong_secret_refuses_to_open() {
    let policy = policy();
    let witness = witness_for(&policy, &base_transcript());
    let envelope = deterministic_secret_envelope();
    let err = open(
        OpenRequest {
            envelope: &envelope,
            public_witness: &witness,
            secret_component: Some(b"wrong secret"),
        },
        &FileTranscriptVerifier,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "open refused");
}

#[test]
fn header_byte_tamper_refuses_to_open() {
    let policy = policy();
    let witness = witness_for(&policy, &base_transcript());
    let mut envelope = deterministic_secret_envelope();
    envelope[19] ^= 0x01;
    assert!(open(
        OpenRequest {
            envelope: &envelope,
            public_witness: &witness,
            secret_component: Some(&secret()),
        },
        &FileTranscriptVerifier,
    )
    .is_err());
}

#[test]
fn ciphertext_or_tag_tamper_refuses_to_open() {
    let policy = policy();
    let witness = witness_for(&policy, &base_transcript());
    let mut envelope = deterministic_secret_envelope();
    let last = envelope.len() - 1;
    envelope[last] ^= 0x01;
    assert!(open(
        OpenRequest {
            envelope: &envelope,
            public_witness: &witness,
            secret_component: Some(&secret()),
        },
        &FileTranscriptVerifier,
    )
    .is_err());
}

#[test]
fn forged_transcript_witness_refuses_to_open() {
    let policy = policy();
    let forged_witness = witness_for(&policy, b"forged transcript");
    let envelope = deterministic_secret_envelope();
    assert!(open(
        OpenRequest {
            envelope: &envelope,
            public_witness: &forged_witness,
            secret_component: Some(&secret()),
        },
        &FileTranscriptVerifier,
    )
    .is_err());
}

#[test]
fn malformed_and_truncated_envelopes_do_not_panic() {
    let envelope = deterministic_secret_envelope();
    for len in 0..envelope.len() {
        let _ = parse_envelope(&envelope[..len]);
    }
    let malformed = vec![0xff; 128];
    assert!(parse_envelope(&malformed).is_err());
}

#[test]
fn sealed_public_round_trip_and_inspect_reports_no_confidentiality() {
    let policy = policy();
    let witness = witness_for(&policy, &base_transcript());
    let envelope = seal(
        b"publicly openable",
        SealRequest {
            policy: &policy,
            canon_descriptor: DEFAULT_CANON_DESCRIPTOR,
            mode: Mode::SealedPublic,
            public_witness: &witness,
            secret_component: None,
            asserted_entropy_bits: None,
            seal_salt: Some([0x33; 32]),
            nonce: Some([0x44; 12]),
        },
        &FileTranscriptVerifier,
    )
    .unwrap();
    let plaintext = open(
        OpenRequest {
            envelope: &envelope,
            public_witness: &witness,
            secret_component: None,
        },
        &FileTranscriptVerifier,
    )
    .unwrap();
    assert_eq!(plaintext, b"publicly openable");
    let report = inspect(&envelope).unwrap().to_text();
    assert!(report.contains("CONFIDENTIALITY: NONE"));
}

#[test]
fn inspect_output_has_no_forbidden_overclaims() {
    let report = inspect(&deterministic_secret_envelope()).unwrap().to_text();
    let lowered = report.to_ascii_lowercase();
    for needle in FORBIDDEN_OUTPUT {
        assert!(
            !lowered.contains(needle),
            "inspect output contained forbidden string {needle:?}: {report}"
        );
    }
}

#[test]
#[cfg(unix)]
fn cli_refuses_symlink_output() {
    let root = std::env::temp_dir().join(format!(
        "penumbra-cli-symlink-output-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let policy_path = root.join("policy.json");
    let witness_path = root.join("witness.bin");
    let plaintext_path = root.join("plain.txt");
    let target_path = root.join("target.wjseal");
    let link_path = root.join("link.wjseal");
    std::fs::write(&policy_path, policy()).unwrap();
    std::fs::write(&witness_path, witness_for(&policy(), &base_transcript())).unwrap();
    std::fs::write(&plaintext_path, b"no link writes").unwrap();
    std::fs::write(&target_path, b"existing").unwrap();
    std::os::unix::fs::symlink(&target_path, &link_path).unwrap();

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_penumbra"))
        .arg("seal")
        .arg("--policy")
        .arg(&policy_path)
        .arg("--mode")
        .arg("public")
        .arg("--witness")
        .arg(&witness_path)
        .arg("--in")
        .arg(&plaintext_path)
        .arg("--out")
        .arg(&link_path)
        .status()
        .unwrap();

    assert!(!status.success());
    assert_eq!(std::fs::read(&target_path).unwrap(), b"existing");
    let _ = std::fs::remove_dir_all(&root);
}
