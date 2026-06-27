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

.section .note.GNU-stack,"",@progbits
