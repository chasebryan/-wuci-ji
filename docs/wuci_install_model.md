# WUCI-INSTALL / No Such Install

WUCI-INSTALL v1 is a zero-prompt signed install lane for Wuci-ji.

It is not `curl | sh`. It does not prompt. It does not use shell evaluation.
It refuses to install unless the user first copies the repository install root
public key into a local trust path.

Let:

```text
A     = candidate binary bytes
K     = user-copied install public key
M     = canonical install manifest bytes
sigma = detached OpenSSH signature over M
P     = install prefix
R     = live proof evidence bundle
```

The v1 acceptance predicate is:

```text
Accept_install(A, K, M, sigma, P, R) =
  KeyCopied(K)
  AND KeyFingerprintOK(K)
  AND SignatureOK(K, M, sigma)
  AND ManifestCanonical(M)
  AND DigestVectorOK(A, M)
  AND VerifierIdentityOK(A)
  AND SelftestOK(A)
  AND HardenOK(R)
  AND CageOK(R)
  AND QcageCompatOK(R)
  AND PrefixSafe(P)
  AND AtomicInstall(P, A)
  AND AuditReceiptOK(P, A, M, sigma, R)
```

The digest-vector check is:

```text
DigestVectorOK(A, M) =
  SHA256(A) = M.binary_sha256
  AND SHA384(A) = M.binary_sha384
  AND SHA512(A) = M.binary_sha512
```

The install transcript is the canonical ASCII manifest:

```text
schema: wuci-install-manifest-v1
product-unicode-name-utf8-sha256: sha256("无此机")
product-english-name: Wuci-ji
version: 0.1
platform: linux-x86_64
binary-path: build/wuci-ji
binary-sha256: ...
binary-sha384: ...
binary-sha512: ...
install-policy-sha512: ...
witness-bundle-sha512: ...
cage-attestation-sha512: ...
qcage-attestation-sha512: ...
runtime-sandbox-claimed: false
quantum-safe-claimed: false
```

`witness-bundle-sha512`, `cage-attestation-sha512`, and
`qcage-attestation-sha512` may be all-zero placeholders in the signed manifest
when the installer is expected to regenerate live proof evidence. The install
receipt records the live hashes observed after the proof gates pass.

Signature verification is:

```text
SignatureOK(K, M, sigma) =
  OpenSSH_Verify(
    K,
    namespace = "wuci-install-v1",
    identity = "wuci-install",
    message = M,
    signature = sigma
  )
```

The local key-copy rule is:

```text
KeyCopied(K) =
  local_trust_key_path exists
  AND local_trust_key_path is regular
  AND local_trust_key_path is not a symlink
  AND SHA256(local_trust_key_path) = SHA256(repo_install_root_key)
```

Copying the key from the same checkout creates an explicit local trust pin and
prevents blind remote execution, but it does not protect an already-compromised
first checkout. The install root key fingerprint should be published
out-of-band before production use.
