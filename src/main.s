.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global _start
.global usage_exit
.global help_exit
.extern write_all
.extern streq
.extern exit_process
.extern run_sha256
.extern run_frost_p256_h4
.extern run_frost_p256_h1
.extern run_frost_p256_h2
.extern run_frost_p256_h3
.extern run_frost_p256_h5
.extern run_frost_secp256k1_h1
.extern run_frost_secp256k1_h2
.extern run_frost_secp256k1_h3
.extern run_frost_secp256k1_h4
.extern run_frost_secp256k1_h5
.extern run_frost_secp256k1_nonce_generate
.extern run_frost_secp256k1_commit
.extern run_frost_secp256k1_commitment_hash
.extern run_frost_secp256k1_binding_factor
.extern run_frost_secp256k1_group_commitment
.extern run_frost_secp256k1_challenge
.extern run_frost_secp256k1_signing_share
.extern run_frost_secp256k1_aggregate
.extern run_frost_secp256k1_verify
.extern run_secp256k1_scalar_add
.extern run_secp256k1_scalar_sub
.extern run_secp256k1_scalar_mul
.extern run_secp256k1_scalar_inv
.extern run_frost_secp256k1_lagrange
.extern run_secp256k1_field_add
.extern run_secp256k1_field_sub
.extern run_secp256k1_field_mul
.extern run_secp256k1_field_square
.extern run_secp256k1_field_inv
.extern run_secp256k1_point_validate
.extern run_secp256k1_point_double
.extern run_secp256k1_point_add
.extern run_secp256k1_basepoint_mul
.extern run_secp256k1_jacobian_double
.extern run_secp256k1_jacobian_mixed_add
.extern run_secp256k1_projective_basepoint_mul
.extern run_secp256k1_point_encode_compressed
.extern run_secp256k1_point_encode_uncompressed
.extern run_secp256k1_point_decode
.extern run_keygen
.extern run_keypair
.extern run_hmac_sha256
.extern run_hkdf_sha256
.extern run_poly1305
.extern run_chacha20
.extern run_seal
.extern run_seal_v2
.extern run_seal_file
.extern run_seal_file_v2
.extern run_seal_file_keyfile
.extern run_seal_file_keyfile_v2
.extern run_seal_to
.extern run_seal_keyfile
.extern run_seal_keyfile_v2
.extern run_open
.extern run_open_file
.extern run_open_file_keyfile
.extern run_authority_root_verify
.extern run_gate_contract_verify
.extern run_gate_contract_verify_rooted
.extern run_open_authorized_contract
.extern run_open_authorized_rooted
.extern run_release_authorized_contract
.extern run_release_authorized_rooted
.extern run_ledger_empty_root
.extern run_ledger_leaf_file
.extern run_ledger_node
.extern run_open_to
.extern run_open_keyfile
.extern run_inspect
.extern run_inspect_file
.extern run_manifest
.extern run_manifest_file
.extern run_warrant_message_file
.extern run_armor_file
.extern run_dearmor_file
.extern run_aead_seal
.extern run_aead_open
.extern run_selftest
.extern run_asm_regression
.extern run_sandbox_net_deny_probe
.extern run_sandbox_seccomp_net_deny_selftest

_start:
    mov rax, qword ptr [rsp]
    cmp rax, 2
    jb usage_exit

    mov rbx, qword ptr [rsp + 16]
    lea r12, [rip + command_table]

.Ldispatch_loop:
    mov rsi, qword ptr [r12]
    test rsi, rsi
    jz usage_exit
    mov rdi, rbx
    call streq
    cmp eax, 1
    je .Ldispatch_found
    add r12, 16
    jmp .Ldispatch_loop

.Ldispatch_found:
    jmp qword ptr [r12 + 8]

usage_exit:
    mov rdi, STDERR
    lea rsi, [rip + usage_msg]
    mov edx, OFFSET FLAT:usage_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

help_exit:
    cmp qword ptr [rsp], 2
    jne usage_exit

    mov rdi, STDOUT
    lea rsi, [rip + usage_msg]
    mov edx, OFFSET FLAT:usage_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

.section .rodata
.align 8
command_table:
    .quad cmd_sha256, run_sha256
    .quad cmd_frost_p256_h1, run_frost_p256_h1
    .quad cmd_frost_p256_h2, run_frost_p256_h2
    .quad cmd_frost_p256_h3, run_frost_p256_h3
    .quad cmd_frost_p256_h4, run_frost_p256_h4
    .quad cmd_frost_p256_h5, run_frost_p256_h5
    .quad cmd_frost_secp256k1_h1, run_frost_secp256k1_h1
    .quad cmd_frost_secp256k1_h2, run_frost_secp256k1_h2
    .quad cmd_frost_secp256k1_h3, run_frost_secp256k1_h3
    .quad cmd_frost_secp256k1_h4, run_frost_secp256k1_h4
    .quad cmd_frost_secp256k1_h5, run_frost_secp256k1_h5
    .quad cmd_secp256k1_scalar_add, run_secp256k1_scalar_add
    .quad cmd_secp256k1_scalar_sub, run_secp256k1_scalar_sub
    .quad cmd_secp256k1_scalar_mul, run_secp256k1_scalar_mul
    .quad cmd_secp256k1_scalar_inv, run_secp256k1_scalar_inv
    .quad cmd_frost_secp256k1_lagrange, run_frost_secp256k1_lagrange
    .quad cmd_frost_secp256k1_nonce_generate, run_frost_secp256k1_nonce_generate
    .quad cmd_frost_secp256k1_commit, run_frost_secp256k1_commit
    .quad cmd_frost_secp256k1_commitment_hash, run_frost_secp256k1_commitment_hash
    .quad cmd_frost_secp256k1_binding_factor, run_frost_secp256k1_binding_factor
    .quad cmd_frost_secp256k1_group_commitment, run_frost_secp256k1_group_commitment
    .quad cmd_frost_secp256k1_challenge, run_frost_secp256k1_challenge
    .quad cmd_frost_secp256k1_signing_share, run_frost_secp256k1_signing_share
    .quad cmd_frost_secp256k1_aggregate, run_frost_secp256k1_aggregate
    .quad cmd_frost_secp256k1_verify, run_frost_secp256k1_verify
    .quad cmd_secp256k1_field_add, run_secp256k1_field_add
    .quad cmd_secp256k1_field_sub, run_secp256k1_field_sub
    .quad cmd_secp256k1_field_mul, run_secp256k1_field_mul
    .quad cmd_secp256k1_field_square, run_secp256k1_field_square
    .quad cmd_secp256k1_field_inv, run_secp256k1_field_inv
    .quad cmd_secp256k1_point_validate, run_secp256k1_point_validate
    .quad cmd_secp256k1_point_double, run_secp256k1_point_double
    .quad cmd_secp256k1_point_add, run_secp256k1_point_add
    .quad cmd_secp256k1_basepoint_mul_variable_time_public_only, run_secp256k1_basepoint_mul
    .quad cmd_secp256k1_jacobian_double, run_secp256k1_jacobian_double
    .quad cmd_secp256k1_jacobian_mixed_add, run_secp256k1_jacobian_mixed_add
    .quad cmd_secp256k1_projective_basepoint_mul, run_secp256k1_projective_basepoint_mul
    .quad cmd_secp256k1_point_encode_compressed, run_secp256k1_point_encode_compressed
    .quad cmd_secp256k1_point_encode_uncompressed, run_secp256k1_point_encode_uncompressed
    .quad cmd_secp256k1_point_decode, run_secp256k1_point_decode
    .quad cmd_selftest, run_selftest
    .quad cmd_keygen, run_keygen
    .quad cmd_keypair, run_keypair
    .quad cmd_hmac_sha256, run_hmac_sha256
    .quad cmd_hkdf_sha256, run_hkdf_sha256
    .quad cmd_poly1305, run_poly1305
    .quad cmd_chacha20, run_chacha20
    .quad cmd_seal, run_seal
    .quad cmd_seal_v2, run_seal_v2
    .quad cmd_seal_file, run_seal_file
    .quad cmd_seal_file_v2, run_seal_file_v2
    .quad cmd_seal_file_keyfile, run_seal_file_keyfile
    .quad cmd_seal_file_keyfile_v2, run_seal_file_keyfile_v2
    .quad cmd_seal_to, run_seal_to
    .quad cmd_seal_keyfile, run_seal_keyfile
    .quad cmd_seal_keyfile_v2, run_seal_keyfile_v2
    .quad cmd_open, run_open
    .quad cmd_open_file, run_open_file
    .quad cmd_open_file_keyfile, run_open_file_keyfile
    .quad cmd_authority_root_verify, run_authority_root_verify
    .quad cmd_gate_contract_verify, run_gate_contract_verify
    .quad cmd_gate_contract_verify_rooted, run_gate_contract_verify_rooted
    .quad cmd_open_authorized_contract, run_open_authorized_contract
    .quad cmd_open_authorized_rooted, run_open_authorized_rooted
    .quad cmd_release_authorized_contract, run_release_authorized_contract
    .quad cmd_release_authorized_rooted, run_release_authorized_rooted
    .quad cmd_ledger_empty_root, run_ledger_empty_root
    .quad cmd_ledger_leaf_file, run_ledger_leaf_file
    .quad cmd_ledger_node, run_ledger_node
    .quad cmd_open_to, run_open_to
    .quad cmd_open_keyfile, run_open_keyfile
    .quad cmd_inspect, run_inspect
    .quad cmd_inspect_file, run_inspect_file
    .quad cmd_manifest, run_manifest
    .quad cmd_manifest_file, run_manifest_file
    .quad cmd_warrant_message_file, run_warrant_message_file
    .quad cmd_armor_file, run_armor_file
    .quad cmd_dearmor_file, run_dearmor_file
    .quad cmd_aead_seal, run_aead_seal
    .quad cmd_aead_open, run_aead_open
    .quad cmd_asm_regression, run_asm_regression
    .quad cmd_sandbox_net_deny_probe, run_sandbox_net_deny_probe
    .quad cmd_sandbox_seccomp_net_deny_selftest, run_sandbox_seccomp_net_deny_selftest
    .quad cmd_help, help_exit
    .quad cmd_help_long, help_exit
    .quad 0, 0

cmd_sha256:
    .asciz "sha256"
cmd_frost_p256_h1:
    .asciz "frost-p256-h1"
cmd_frost_p256_h2:
    .asciz "frost-p256-h2"
cmd_frost_p256_h3:
    .asciz "frost-p256-h3"
cmd_frost_p256_h4:
    .asciz "frost-p256-h4"
cmd_frost_p256_h5:
    .asciz "frost-p256-h5"
cmd_frost_secp256k1_h1:
    .asciz "frost-secp256k1-h1"
cmd_frost_secp256k1_h2:
    .asciz "frost-secp256k1-h2"
cmd_frost_secp256k1_h3:
    .asciz "frost-secp256k1-h3"
cmd_frost_secp256k1_h4:
    .asciz "frost-secp256k1-h4"
cmd_frost_secp256k1_h5:
    .asciz "frost-secp256k1-h5"
cmd_secp256k1_scalar_add:
    .asciz "secp256k1-scalar-add"
cmd_secp256k1_scalar_sub:
    .asciz "secp256k1-scalar-sub"
cmd_secp256k1_scalar_mul:
    .asciz "secp256k1-scalar-mul"
cmd_secp256k1_scalar_inv:
    .asciz "secp256k1-scalar-inv"
cmd_frost_secp256k1_lagrange:
    .asciz "frost-secp256k1-lagrange"
cmd_frost_secp256k1_nonce_generate:
    .asciz "frost-secp256k1-nonce-generate"
cmd_frost_secp256k1_commit:
    .asciz "frost-secp256k1-commit"
cmd_frost_secp256k1_commitment_hash:
    .asciz "frost-secp256k1-commitment-hash"
cmd_frost_secp256k1_binding_factor:
    .asciz "frost-secp256k1-binding-factor"
cmd_frost_secp256k1_group_commitment:
    .asciz "frost-secp256k1-group-commitment"
cmd_frost_secp256k1_challenge:
    .asciz "frost-secp256k1-challenge"
cmd_frost_secp256k1_signing_share:
    .asciz "frost-secp256k1-signing-share"
cmd_frost_secp256k1_aggregate:
    .asciz "frost-secp256k1-aggregate"
cmd_frost_secp256k1_verify:
    .asciz "frost-secp256k1-verify"
cmd_secp256k1_field_add:
    .asciz "secp256k1-field-add"
cmd_secp256k1_field_sub:
    .asciz "secp256k1-field-sub"
cmd_secp256k1_field_mul:
    .asciz "secp256k1-field-mul"
cmd_secp256k1_field_square:
    .asciz "secp256k1-field-square"
cmd_secp256k1_field_inv:
    .asciz "secp256k1-field-inv"
cmd_secp256k1_point_validate:
    .asciz "secp256k1-point-validate"
cmd_secp256k1_point_double:
    .asciz "secp256k1-point-double"
cmd_secp256k1_point_add:
    .asciz "secp256k1-point-add"
cmd_secp256k1_basepoint_mul_variable_time_public_only:
    .asciz "secp256k1-basepoint-mul-variable-time-public-only"
cmd_secp256k1_jacobian_double:
    .asciz "secp256k1-jacobian-double"
cmd_secp256k1_jacobian_mixed_add:
    .asciz "secp256k1-jacobian-mixed-add"
cmd_secp256k1_projective_basepoint_mul:
    .asciz "secp256k1-projective-basepoint-mul"
cmd_secp256k1_point_encode_compressed:
    .asciz "secp256k1-point-encode-compressed"
cmd_secp256k1_point_encode_uncompressed:
    .asciz "secp256k1-point-encode-uncompressed"
cmd_secp256k1_point_decode:
    .asciz "secp256k1-point-decode"
cmd_selftest:
    .asciz "selftest"
cmd_asm_regression:
    .asciz "asm-regression"
cmd_sandbox_net_deny_probe:
    .asciz "sandbox-net-deny-probe"
cmd_sandbox_seccomp_net_deny_selftest:
    .asciz "sandbox-seccomp-net-deny-selftest"
cmd_keygen:
    .asciz "keygen"
cmd_keypair:
    .asciz "keypair"
cmd_hmac_sha256:
    .asciz "hmac-sha256"
cmd_hkdf_sha256:
    .asciz "hkdf-sha256"
cmd_poly1305:
    .asciz "poly1305"
cmd_chacha20:
    .asciz "chacha20"
cmd_seal:
    .asciz "seal"
cmd_seal_v2:
    .asciz "seal-v2"
cmd_seal_file:
    .asciz "seal-file"
cmd_seal_file_v2:
    .asciz "seal-file-v2"
cmd_seal_file_keyfile:
    .asciz "seal-file-keyfile"
cmd_seal_file_keyfile_v2:
    .asciz "seal-file-keyfile-v2"
cmd_seal_to:
    .asciz "seal-to"
cmd_seal_keyfile:
    .asciz "seal-keyfile"
cmd_seal_keyfile_v2:
    .asciz "seal-keyfile-v2"
cmd_open:
    .asciz "open"
cmd_open_file:
    .asciz "open-file"
cmd_open_file_keyfile:
    .asciz "open-file-keyfile"
cmd_authority_root_verify:
    .asciz "authority-root-verify"
cmd_gate_contract_verify:
    .asciz "gate-contract-verify"
cmd_gate_contract_verify_rooted:
    .asciz "gate-contract-verify-rooted"
cmd_open_authorized_contract:
    .asciz "open-authorized-contract"
cmd_open_authorized_rooted:
    .asciz "open-authorized-rooted"
cmd_release_authorized_contract:
    .asciz "release-authorized-contract"
cmd_release_authorized_rooted:
    .asciz "release-authorized-rooted"
cmd_ledger_empty_root:
    .asciz "ledger-empty-root"
cmd_ledger_leaf_file:
    .asciz "ledger-leaf-file"
cmd_ledger_node:
    .asciz "ledger-node"
cmd_open_to:
    .asciz "open-to"
cmd_open_keyfile:
    .asciz "open-keyfile"
cmd_inspect:
    .asciz "inspect"
cmd_inspect_file:
    .asciz "inspect-file"
cmd_manifest:
    .asciz "manifest"
cmd_manifest_file:
    .asciz "manifest-file"
cmd_warrant_message_file:
    .asciz "warrant-message-file"
cmd_armor_file:
    .asciz "armor-file"
cmd_dearmor_file:
    .asciz "dearmor-file"
cmd_aead_seal:
    .asciz "aead-seal"
cmd_aead_open:
    .asciz "aead-open"
cmd_help:
    .asciz "-h"
cmd_help_long:
    .asciz "--help"

usage_msg:
    .ascii "usage: wuci-ji <sha256|frost-p256-h1|frost-p256-h2|frost-p256-h3|frost-p256-h4|frost-p256-h5|frost-secp256k1-h1|frost-secp256k1-h2|frost-secp256k1-h3|frost-secp256k1-h4|frost-secp256k1-h5|secp256k1-scalar-add|secp256k1-scalar-sub|secp256k1-scalar-mul|secp256k1-scalar-inv|frost-secp256k1-lagrange|frost-secp256k1-nonce-generate|frost-secp256k1-commit|frost-secp256k1-commitment-hash|frost-secp256k1-binding-factor|frost-secp256k1-group-commitment|frost-secp256k1-challenge|frost-secp256k1-signing-share|frost-secp256k1-aggregate|frost-secp256k1-verify|secp256k1-field-add|secp256k1-field-sub|secp256k1-field-mul|secp256k1-field-square|secp256k1-field-inv|secp256k1-point-validate|secp256k1-point-double|secp256k1-point-add|secp256k1-basepoint-mul-variable-time-public-only|secp256k1-jacobian-double|secp256k1-jacobian-mixed-add|secp256k1-projective-basepoint-mul|secp256k1-point-encode-compressed|secp256k1-point-encode-uncompressed|secp256k1-point-decode|hmac-sha256|hkdf-sha256|poly1305|chacha20|keygen|keypair|seal|seal-v2|seal-to|seal-file|seal-file-v2|seal-file-keyfile|seal-file-keyfile-v2|open|open-to|open-file|open-file-keyfile|authority-root-verify|gate-contract-verify|gate-contract-verify-rooted|open-authorized-contract|open-authorized-rooted|release-authorized-contract|release-authorized-rooted|ledger-empty-root|ledger-leaf-file|ledger-node|inspect|inspect-file|manifest|manifest-file|warrant-message-file|armor-file|dearmor-file|seal-keyfile|seal-keyfile-v2|open-keyfile|aead-seal|aead-open|selftest|asm-regression|sandbox-net-deny-probe|sandbox-seccomp-net-deny-selftest> [args]\n"
    .ascii "  sha256                         hash stdin with the assembly SHA-256 core\n"
    .ascii "  frost-p256-h1                  RFC9591 FROST(P-256,SHA-256) H1(rho) scalar over stdin\n"
    .ascii "  frost-p256-h2                  RFC9591 FROST(P-256,SHA-256) H2(chal) scalar over stdin\n"
    .ascii "  frost-p256-h3                  RFC9591 FROST(P-256,SHA-256) H3(nonce) scalar over stdin\n"
    .ascii "  frost-p256-h4                  RFC9591 FROST(P-256,SHA-256) H4(msg) over stdin\n"
    .ascii "  frost-p256-h5                  RFC9591 FROST(P-256,SHA-256) H5(com) over stdin\n"
    .ascii "  frost-secp256k1-h1             RFC9591 FROST(secp256k1,SHA-256) H1(rho) scalar over stdin\n"
    .ascii "  frost-secp256k1-h2             RFC9591 FROST(secp256k1,SHA-256) H2(chal) scalar over stdin\n"
    .ascii "  frost-secp256k1-h3             RFC9591 FROST(secp256k1,SHA-256) H3(nonce) scalar over stdin\n"
    .ascii "  frost-secp256k1-h4             RFC9591 FROST(secp256k1,SHA-256) H4(msg) over stdin\n"
    .ascii "  frost-secp256k1-h5             RFC9591 FROST(secp256k1,SHA-256) H5(com) over stdin\n"
    .ascii "  secp256k1-scalar-add <a> <b>   add 32-byte hex scalars modulo group order\n"
    .ascii "  secp256k1-scalar-sub <a> <b>   subtract 32-byte hex scalars modulo group order\n"
    .ascii "  secp256k1-scalar-mul <a> <b>   multiply 32-byte hex scalars modulo group order\n"
    .ascii "  secp256k1-scalar-inv <a>       invert a nonzero scalar modulo group order\n"
    .ascii "  frost-secp256k1-lagrange <i> <id...> derive RFC9591 interpolation scalar\n"
    .ascii "  frost-secp256k1-nonce-generate <secret> derive one RFC9591 nonce with fresh randomness\n"
    .ascii "  frost-secp256k1-commit <hiding> <binding> derive compressed round-one commitments\n"
    .ascii "  frost-secp256k1-commitment-hash <id D E>... hash sorted commitment triples\n"
    .ascii "  frost-secp256k1-binding-factor <PK> <H4> <H5> <id> derive one binding factor\n"
    .ascii "  frost-secp256k1-group-commitment <id D E rho>... aggregate group commitment\n"
    .ascii "  frost-secp256k1-challenge <R> <PK> derive H2 challenge over R, PK, and stdin\n"
    .ascii "  frost-secp256k1-signing-share <d> <e> <rho> <lambda> <share> <c> derive z_i\n"
    .ascii "  frost-secp256k1-aggregate <R> <z...> aggregate signature shares\n"
    .ascii "  frost-secp256k1-verify <R> <PK> <z> <c> verify z*G = R + c*PK\n"
    .ascii "  secp256k1-field-add <a> <b>    add 32-byte hex field elements modulo p\n"
    .ascii "  secp256k1-field-sub <a> <b>    subtract 32-byte hex field elements modulo p\n"
    .ascii "  secp256k1-field-mul <a> <b>    multiply 32-byte hex field elements modulo p\n"
    .ascii "  secp256k1-field-square <a>     square a 32-byte hex field element modulo p\n"
    .ascii "  secp256k1-field-inv <a>        invert a 32-byte hex field element modulo p\n"
    .ascii "  secp256k1-point-validate <x> <y> validate affine point coordinates\n"
    .ascii "  secp256k1-point-double <x> <y> double an affine point; prints x/y or infinity\n"
    .ascii "  secp256k1-point-add <x1> <y1> <x2> <y2> add affine points; prints x/y or infinity\n"
    .ascii "  secp256k1-basepoint-mul-variable-time-public-only <k> multiply basepoint by public scalar only\n"
    .ascii "  secp256k1-jacobian-double <x> <y> <z> double a Jacobian point; prints x/y/z or infinity\n"
    .ascii "  secp256k1-jacobian-mixed-add <jx> <jy> <jz> <ax> <ay> add Jacobian and affine points\n"
    .ascii "  secp256k1-projective-basepoint-mul <k> multiply the basepoint with Jacobian intermediates\n"
    .ascii "  secp256k1-point-encode-compressed <x> <y> encode affine point as SEC1 compressed hex\n"
    .ascii "  secp256k1-point-encode-uncompressed <x> <y> encode affine point as SEC1 uncompressed hex\n"
    .ascii "  secp256k1-point-decode <point> decode SEC1 compressed or uncompressed hex point\n"
    .ascii "  hmac-sha256 <key>              authenticate stdin with a 32-byte hex key\n"
    .ascii "  hkdf-sha256 <salt> <info>      derive 32 bytes from stdin; salt/info are 64 hex each\n"
    .ascii "  poly1305 <key>                 authenticate stdin with a 32-byte one-time hex key\n"
    .ascii "  chacha20 <key> <nonce> <ctr>   xor stdin with ChaCha20; key=64 hex, nonce=24 hex, ctr=8 hex\n"
    .ascii "  keygen                         write a random 32-byte key as 64 hex plus newline\n"
    .ascii "  keypair                        write random X25519 private/public keys as hex\n"
    .ascii "  seal <key>                     write framed ChaCha20-Poly1305 envelope with random nonce\n"
    .ascii "  seal-v2 <key> <key-id>         write v2 envelope; key-id is 16 bytes / 32 hex\n"
    .ascii "  seal-to <public> <in> <out>    seal v3 file to X25519 public key; no overwrite\n"
    .ascii "  seal-file <key> <in> <out>     seal file to a new path; no overwrite\n"
    .ascii "  seal-file-v2 <key> <key-id> <in> <out> seal v2 file; no overwrite\n"
    .ascii "  seal-file-keyfile <path> <in> <out> seal file with key file; no overwrite\n"
    .ascii "  seal-file-keyfile-v2 <path> <key-id> <in> <out> seal v2 with key file; no overwrite\n"
    .ascii "  open <key>                     verify framed envelope from stdin, then write plaintext\n"
    .ascii "  open-to <private> <in> <out>   open v3 file with X25519 private key; no overwrite\n"
    .ascii "  open-file <key> <in> <out>     open file to a new path; no overwrite\n"
    .ascii "  open-file-keyfile <path> <in> <out> open file with key file; no overwrite\n"
    .ascii "  authority-root-verify <authority> verify flat WUCI-ROOT authority file\n"
    .ascii "  gate-contract-verify <artifact> <contract> verify flat WUCI-GATE receipt contract\n"
    .ascii "  gate-contract-verify-rooted <authority> <artifact> <contract> verify contract against trusted authority root\n"
    .ascii "  open-authorized-contract <keyfile> <artifact> <contract> <out> verify contract, then open; no overwrite\n"
    .ascii "  open-authorized-rooted <authority> <keyfile> <artifact> <contract> <out> verify rooted contract, then open; no overwrite\n"
    .ascii "  release-authorized-contract <artifact> <contract> verify release contract and print decision\n"
    .ascii "  release-authorized-rooted <authority> <artifact> <contract> verify rooted release contract and print decision\n"
    .ascii "  ledger-empty-root              print SHA-256 Merkle root for an empty WUCI-LEDGER\n"
    .ascii "  ledger-leaf-file <entry>       print SHA-256(00 || entry bytes) for a ledger entry\n"
    .ascii "  ledger-node <left> <right>     print SHA-256(01 || left || right); inputs are 64 hex\n"
    .ascii "  inspect                        print envelope metadata from stdin without a key\n"
    .ascii "  inspect-file <path>            print envelope metadata from a file without a key\n"
    .ascii "  manifest                       print metadata, SHA-256 fingerprints, and tag\n"
    .ascii "  manifest-file <path>           print file metadata, SHA-256 fingerprints, and tag\n"
    .ascii "  warrant-message-file <action> <path> print FROST warrant message bytes; action=open/release/trust/publish\n"
    .ascii "  armor-file <in> <out>          wrap an artifact in copy/paste ASCII armor; no overwrite\n"
    .ascii "  dearmor-file <in> <out>        decode copy/paste ASCII armor; no overwrite\n"
    .ascii "  seal-keyfile <path>            seal with a key file containing 64 hex plus optional newline\n"
    .ascii "  seal-keyfile-v2 <path> <key-id> seal v2 with a key file; key-id is 32 hex\n"
    .ascii "  open-keyfile <path>            open with a key file containing 64 hex plus optional newline\n"
    .ascii "  aead-seal <key> <nonce>        write ChaCha20-Poly1305 ciphertext || raw tag\n"
    .ascii "  aead-open <key> <nonce> <tag>  verify raw ciphertext, then write plaintext; tag=32 hex\n"
    .ascii "  selftest                       run built-in known-answer tests\n"
    .ascii "  asm-regression                 run assembly-owned regression vectors\n"
    .ascii "  sandbox-net-deny-probe         pass only when AF_INET socket creation is denied\n"
    .ascii "  sandbox-seccomp-net-deny-selftest install seccomp network syscall deny filter and verify socket EPERM\n"
.set usage_msg_len, . - usage_msg

.section .note.GNU-stack,"",@progbits
