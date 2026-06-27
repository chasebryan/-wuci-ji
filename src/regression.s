.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global run_asm_regression
.extern usage_exit
.extern write_all
.extern exit_process
.extern sha256_init
.extern sha256_update
.extern sha256_final
.extern memeq
.extern sha_ctx
.extern digest_buf
.extern aead_open_buf
.extern aead_text_len
.extern gate_use_streamed
.extern gate_artifact_sha256
.extern gate_authorization_message_sha256
.extern gate_manifest_buf
.extern gate_manifest_len
.extern gate_warrant_buf
.extern gate_warrant_len
.extern gate_contract_buf
.extern gate_contract_len
.extern gate_setup_open_action
.extern gate_parse_contract
.extern gate_build_manifest
.extern gate_build_warrant
.extern secp256k1_scalar_add_limbs
.extern secp256k1_scalar_sub_limbs
.extern secp256k1_scalar_mul_limbs

run_asm_regression:
    cmp qword ptr [rsp], 2
    jne usage_exit

    call regression_ledger_empty_root
    cmp eax, 1
    jne asm_regression_fail

    call regression_ledger_leaf
    cmp eax, 1
    jne asm_regression_fail

    call regression_ledger_node
    cmp eax, 1
    jne asm_regression_fail

    call regression_crypto_kats
    cmp eax, 1
    jne asm_regression_fail

    call regression_manifest_warrant
    cmp eax, 1
    jne asm_regression_fail

    call regression_gate_parser
    cmp eax, 1
    jne asm_regression_fail

    mov rdi, STDOUT
    lea rsi, [rip + asm_regression_pass_msg]
    mov edx, OFFSET FLAT:asm_regression_pass_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

asm_regression_fail:
    mov rdi, STDERR
    lea rsi, [rip + asm_regression_fail_msg]
    mov edx, OFFSET FLAT:asm_regression_fail_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

regression_ledger_empty_root:
    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + regression_empty_root]
    mov edx, 32
    call memeq
    ret

regression_ledger_leaf:
    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + regression_leaf_prefix]
    mov edx, 1
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + regression_leaf_payload]
    mov edx, OFFSET FLAT:regression_leaf_payload_len
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + regression_leaf_hash]
    mov edx, 32
    call memeq
    ret

regression_ledger_node:
    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + regression_node_prefix]
    mov edx, 1
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + regression_empty_root]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + regression_leaf_hash]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + regression_node_hash]
    mov edx, 32
    call memeq
    ret

regression_crypto_kats:
    lea rdi, [rip + regression_scalar_two]
    lea rsi, [rip + regression_scalar_three]
    lea rdx, [rip + regression_scalar_out]
    call secp256k1_scalar_add_limbs
    lea rdi, [rip + regression_scalar_out]
    lea rsi, [rip + regression_scalar_five]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne .Lregression_crypto_fail

    lea rdi, [rip + regression_scalar_three]
    lea rsi, [rip + regression_scalar_two]
    lea rdx, [rip + regression_scalar_out]
    call secp256k1_scalar_sub_limbs
    lea rdi, [rip + regression_scalar_out]
    lea rsi, [rip + regression_scalar_one]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne .Lregression_crypto_fail

    lea rdi, [rip + regression_scalar_two]
    lea rsi, [rip + regression_scalar_three]
    lea rdx, [rip + regression_scalar_out]
    call secp256k1_scalar_mul_limbs
    lea rdi, [rip + regression_scalar_out]
    lea rsi, [rip + regression_scalar_six]
    mov edx, 32
    call memeq
    ret

.Lregression_crypto_fail:
    xor eax, eax
    ret

regression_manifest_warrant:
    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + regression_v1_envelope]
    mov edx, OFFSET FLAT:regression_v1_envelope_len
    call regression_copy
    mov qword ptr [rip + aead_text_len], OFFSET FLAT:regression_v1_envelope_len
    mov byte ptr [rip + gate_use_streamed], 0

    lea rdi, [rip + gate_artifact_sha256]
    lea rsi, [rip + regression_v1_artifact_sha256]
    mov edx, 32
    call regression_copy
    call gate_build_manifest
    cmp eax, 1
    jne .Lregression_manifest_fail

    lea rdi, [rip + gate_manifest_buf]
    mov rsi, qword ptr [rip + gate_manifest_len]
    lea rdx, [rip + regression_v1_manifest]
    mov ecx, OFFSET FLAT:regression_v1_manifest_len
    call regression_expect_buf
    cmp eax, 1
    jne .Lregression_manifest_fail

    call gate_setup_open_action
    lea rdi, [rip + gate_authorization_message_sha256]
    lea rsi, [rip + regression_v1_warrant_sha256]
    mov edx, 32
    call regression_copy
    call gate_build_warrant
    cmp eax, 1
    jne .Lregression_manifest_fail

    lea rdi, [rip + gate_warrant_buf]
    mov rsi, qword ptr [rip + gate_warrant_len]
    lea rdx, [rip + regression_v1_warrant]
    mov ecx, OFFSET FLAT:regression_v1_warrant_len
    call regression_expect_buf
    ret

.Lregression_manifest_fail:
    xor eax, eax
    ret

regression_gate_parser:
    call gate_setup_open_action
    lea rdi, [rip + regression_gate_contract_valid]
    mov esi, OFFSET FLAT:regression_gate_contract_valid_len
    call regression_load_contract
    call gate_parse_contract
    cmp eax, 1
    jne .Lregression_gate_fail

    call gate_setup_open_action
    lea rdi, [rip + regression_gate_contract_release_action]
    mov esi, OFFSET FLAT:regression_gate_contract_release_action_len
    call regression_load_contract
    call gate_parse_contract
    cmp eax, 1
    je .Lregression_gate_fail

    call gate_setup_open_action
    lea rdi, [rip + regression_gate_contract_upper_hex]
    mov esi, OFFSET FLAT:regression_gate_contract_upper_hex_len
    call regression_load_contract
    call gate_parse_contract
    cmp eax, 1
    je .Lregression_gate_fail

    call gate_setup_open_action
    lea rdi, [rip + regression_gate_contract_reordered]
    mov esi, OFFSET FLAT:regression_gate_contract_reordered_len
    call regression_load_contract
    call gate_parse_contract
    cmp eax, 1
    je .Lregression_gate_fail

    call gate_setup_open_action
    lea rdi, [rip + regression_gate_contract_duplicate]
    mov esi, OFFSET FLAT:regression_gate_contract_duplicate_len
    call regression_load_contract
    call gate_parse_contract
    cmp eax, 1
    je .Lregression_gate_fail

    mov eax, 1
    ret

.Lregression_gate_fail:
    xor eax, eax
    ret

regression_load_contract:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    lea rdi, [rip + gate_contract_buf]
    mov rsi, rbx
    mov rdx, r12
    call regression_copy
    mov qword ptr [rip + gate_contract_len], r12
    pop r12
    pop rbx
    ret

regression_expect_buf:
    cmp rsi, rcx
    jne .Lregression_expect_fail
    mov rsi, rdx
    mov edx, ecx
    call memeq
    ret
.Lregression_expect_fail:
    xor eax, eax
    ret

regression_copy:
    mov rcx, rdx
    rep movsb
    ret

.section .rodata
asm_regression_pass_msg:
    .ascii "wuci-ji asm-regression: PASS\n"
.set asm_regression_pass_msg_len, . - asm_regression_pass_msg

asm_regression_fail_msg:
    .ascii "wuci-ji asm-regression: FAIL\n"
.set asm_regression_fail_msg_len, . - asm_regression_fail_msg

regression_leaf_payload:
    .ascii "wuci-ledger-regression\n"
.set regression_leaf_payload_len, . - regression_leaf_payload

regression_leaf_prefix:
    .byte 0
regression_node_prefix:
    .byte 1

regression_empty_root:
    .byte 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14
    .byte 0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24
    .byte 0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c
    .byte 0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55

regression_leaf_hash:
    .byte 0xd3,0x5b,0x1b,0x0f,0x10,0x17,0xfc,0x41
    .byte 0x15,0x5d,0xcb,0x93,0x1f,0x9c,0xd4,0x1c
    .byte 0x04,0xb9,0xfe,0xee,0x43,0x26,0xf6,0x66
    .byte 0x3b,0xfe,0xbb,0x73,0xdf,0x3e,0x4b,0x51

regression_node_hash:
    .byte 0x6d,0x9d,0xfb,0x2f,0x6c,0x02,0xa9,0xe3
    .byte 0x47,0x1e,0x93,0x54,0x24,0x64,0x1e,0x46
    .byte 0xd7,0x25,0xb7,0x82,0x9e,0x52,0x94,0x5a
    .byte 0x24,0x1e,0x16,0xf3,0xbe,0xfb,0xe9,0xb5

regression_scalar_one:
    .quad 1,0,0,0
regression_scalar_two:
    .quad 2,0,0,0
regression_scalar_three:
    .quad 3,0,0,0
regression_scalar_five:
    .quad 5,0,0,0
regression_scalar_six:
    .quad 6,0,0,0

regression_v1_envelope:
    .ascii "WJSEAL"
    .byte 0x01,0x01
    .byte 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
    .byte 0x08,0x09,0x0a,0x0b
    .byte 0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7
    .byte 0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
.set regression_v1_envelope_len, . - regression_v1_envelope

regression_v1_artifact_sha256:
    .byte 0xbb,0x13,0x14,0xd9,0xd0,0xa3,0x79,0x8c
    .byte 0x68,0xbe,0x12,0x41,0x41,0xaa,0x86,0xf6
    .byte 0xf5,0x73,0xc7,0x13,0xc4,0x33,0x7d,0x97
    .byte 0xf6,0x86,0x42,0x8e,0x25,0x23,0x11,0x25

regression_v1_warrant_sha256:
    .byte 0x1a,0x9f,0x8a,0xa1,0xf5,0xb9,0x55,0x1e
    .byte 0xdc,0xfa,0xd8,0x6f,0xae,0x38,0xe3,0x0c
    .byte 0x0f,0x24,0xe0,0x5d,0xaf,0x5a,0x88,0x6b
    .byte 0x7a,0x04,0x81,0x05,0xee,0xad,0xa9,0xe5

regression_v1_manifest:
    .ascii "version: 1\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 20\n"
    .ascii "artifact-sha256: bb1314d9d0a3798c68be124141aa86f6f573c713c4337d97f686428e25231125\n"
    .ascii "ciphertext-length: 0\n"
    .ascii "ciphertext-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    .ascii "nonce: 000102030405060708090a0b\n"
    .ascii "tag: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\n"
.set regression_v1_manifest_len, . - regression_v1_manifest

regression_v1_warrant:
    .ascii "schema: wuci-frost-authorization-message-v1\n"
    .ascii "suite: FROST-secp256k1-SHA256-v1\n"
    .ascii "production: false\n"
    .ascii "action: open\n"
    .ascii "artifact-manifest:\n"
    .ascii "version: 1\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 20\n"
    .ascii "artifact-sha256: bb1314d9d0a3798c68be124141aa86f6f573c713c4337d97f686428e25231125\n"
    .ascii "ciphertext-length: 0\n"
    .ascii "ciphertext-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    .ascii "nonce: 000102030405060708090a0b\n"
    .ascii "tag: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\n"
.set regression_v1_warrant_len, . - regression_v1_warrant

regression_gate_contract_valid:
    .ascii "schema: wuci-gate-receipt-contract-v1\n"
    .ascii "action: open\n"
    .ascii "artifact-sha256: bb1314d9d0a3798c68be124141aa86f6f573c713c4337d97f686428e25231125\n"
    .ascii "authorization-message-sha256: 1a9f8aa1f5b9551edcfad86fae38e30c0f24e05daf5a886b7a048105eeada9e5\n"
    .ascii "receipt-sha256: 2222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "artifact-manifest-sha256: 53779a7e6779d6202ac5171f96c6846ffcd8f4a535cce67d08f0faa09261b0fa\n"
    .ascii "group-public-key: 021111111111111111111111111111111111111111111111111111111111111111\n"
    .ascii "group-commitment: 022222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "challenge: 3333333333333333333333333333333333333333333333333333333333333333\n"
    .ascii "signature-commitment: 022222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "signature-scalar: 4444444444444444444444444444444444444444444444444444444444444444\n"
.set regression_gate_contract_valid_len, . - regression_gate_contract_valid

regression_gate_contract_release_action:
    .ascii "schema: wuci-gate-receipt-contract-v1\n"
    .ascii "action: release\n"
    .ascii "artifact-sha256: bb1314d9d0a3798c68be124141aa86f6f573c713c4337d97f686428e25231125\n"
    .ascii "authorization-message-sha256: 1a9f8aa1f5b9551edcfad86fae38e30c0f24e05daf5a886b7a048105eeada9e5\n"
    .ascii "receipt-sha256: 2222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "artifact-manifest-sha256: 53779a7e6779d6202ac5171f96c6846ffcd8f4a535cce67d08f0faa09261b0fa\n"
    .ascii "group-public-key: 021111111111111111111111111111111111111111111111111111111111111111\n"
    .ascii "group-commitment: 022222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "challenge: 3333333333333333333333333333333333333333333333333333333333333333\n"
    .ascii "signature-commitment: 022222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "signature-scalar: 4444444444444444444444444444444444444444444444444444444444444444\n"
.set regression_gate_contract_release_action_len, . - regression_gate_contract_release_action

regression_gate_contract_upper_hex:
    .ascii "schema: wuci-gate-receipt-contract-v1\n"
    .ascii "action: open\n"
    .ascii "artifact-sha256: Bb1314d9d0a3798c68be124141aa86f6f573c713c4337d97f686428e25231125\n"
    .ascii "authorization-message-sha256: 1a9f8aa1f5b9551edcfad86fae38e30c0f24e05daf5a886b7a048105eeada9e5\n"
    .ascii "receipt-sha256: 2222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "artifact-manifest-sha256: 53779a7e6779d6202ac5171f96c6846ffcd8f4a535cce67d08f0faa09261b0fa\n"
    .ascii "group-public-key: 021111111111111111111111111111111111111111111111111111111111111111\n"
    .ascii "group-commitment: 022222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "challenge: 3333333333333333333333333333333333333333333333333333333333333333\n"
    .ascii "signature-commitment: 022222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "signature-scalar: 4444444444444444444444444444444444444444444444444444444444444444\n"
.set regression_gate_contract_upper_hex_len, . - regression_gate_contract_upper_hex

regression_gate_contract_reordered:
    .ascii "action: open\n"
    .ascii "schema: wuci-gate-receipt-contract-v1\n"
    .ascii "artifact-sha256: bb1314d9d0a3798c68be124141aa86f6f573c713c4337d97f686428e25231125\n"
    .ascii "authorization-message-sha256: 1a9f8aa1f5b9551edcfad86fae38e30c0f24e05daf5a886b7a048105eeada9e5\n"
    .ascii "receipt-sha256: 2222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "artifact-manifest-sha256: 53779a7e6779d6202ac5171f96c6846ffcd8f4a535cce67d08f0faa09261b0fa\n"
    .ascii "group-public-key: 021111111111111111111111111111111111111111111111111111111111111111\n"
    .ascii "group-commitment: 022222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "challenge: 3333333333333333333333333333333333333333333333333333333333333333\n"
    .ascii "signature-commitment: 022222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "signature-scalar: 4444444444444444444444444444444444444444444444444444444444444444\n"
.set regression_gate_contract_reordered_len, . - regression_gate_contract_reordered

regression_gate_contract_duplicate:
    .ascii "schema: wuci-gate-receipt-contract-v1\n"
    .ascii "action: open\n"
    .ascii "artifact-sha256: bb1314d9d0a3798c68be124141aa86f6f573c713c4337d97f686428e25231125\n"
    .ascii "authorization-message-sha256: 1a9f8aa1f5b9551edcfad86fae38e30c0f24e05daf5a886b7a048105eeada9e5\n"
    .ascii "receipt-sha256: 2222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "artifact-manifest-sha256: 53779a7e6779d6202ac5171f96c6846ffcd8f4a535cce67d08f0faa09261b0fa\n"
    .ascii "group-public-key: 021111111111111111111111111111111111111111111111111111111111111111\n"
    .ascii "group-commitment: 022222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "challenge: 3333333333333333333333333333333333333333333333333333333333333333\n"
    .ascii "signature-commitment: 022222222222222222222222222222222222222222222222222222222222222222\n"
    .ascii "signature-scalar: 4444444444444444444444444444444444444444444444444444444444444444\n"
    .ascii "schema: wuci-gate-receipt-contract-v1\n"
.set regression_gate_contract_duplicate_len, . - regression_gate_contract_duplicate

.section .bss
.align 32
regression_scalar_out:
    .skip 32

.section .note.GNU-stack,"",@progbits
