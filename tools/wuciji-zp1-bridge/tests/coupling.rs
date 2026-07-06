use wuciji_zp1_bridge::coupling_aad;
use zp1::open::{open, OpenOptions};
use zp1::provider::test_utils::InsecureTestProvider;
use zp1::seal::{seal, SealOptions};
use zp1::Zp1Error;

const ARTIFACT_SHA256: &str = "95f3cb750357eeb2cd840ddfc7b62c6addf08b2d66079871a4d8e8efdd9ae45f";
const RECEIPT_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const GATE_POLICY_SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn zp1_binds_wuciji_metadata_as_aad() -> Result<(), Zp1Error> {
    let aad = coupling_aad(ARTIFACT_SHA256, RECEIPT_SHA256, GATE_POLICY_SHA256)
        .expect("valid deterministic Wuci-Ji/ZP-1 AAD");

    let plaintext = b"Wuci-Ji/ZP-1 coupling probe; public test plaintext only";

    let mut provider = InsecureTestProvider::new(b"wuciji-zp1-coupling-proof-lane");
    let (recipient_pk, recipient_sk) = provider.generate_kem_keypair(b"recipient-0");
    let (signer_pk, signer_sk) = provider.generate_signature_keypair(b"signer-0");

    let object = seal(
        &mut provider,
        &[recipient_pk],
        &signer_sk,
        &signer_pk,
        &aad,
        plaintext,
        SealOptions::default(),
    )?;

    let opened = open(
        &mut provider,
        &recipient_sk,
        &signer_pk,
        &aad,
        &object,
        OpenOptions::default(),
    )?;

    assert_eq!(opened, plaintext);

    let wrong_aad = coupling_aad(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        RECEIPT_SHA256,
        GATE_POLICY_SHA256,
    )
    .expect("valid but different AAD");

    let denied = open(
        &mut provider,
        &recipient_sk,
        &signer_pk,
        &wrong_aad,
        &object,
        OpenOptions::default(),
    );

    assert!(matches!(denied, Err(Zp1Error::Auth)));

    Ok(())
}

#[test]
fn aad_rejects_non_canonical_digest_text() {
    assert!(coupling_aad("A", RECEIPT_SHA256, GATE_POLICY_SHA256).is_err());
    assert!(coupling_aad(ARTIFACT_SHA256, "bad", GATE_POLICY_SHA256).is_err());
    assert!(coupling_aad(ARTIFACT_SHA256, RECEIPT_SHA256, "ABCDEF").is_err());
}
