.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global run_ledger_empty_root
.global run_ledger_leaf_file
.global run_ledger_node
.extern usage_exit
.extern read_error
.extern write_all
.extern exit_process
.extern sha256_init
.extern sha256_update
.extern sha256_final
.extern hex_encode
.extern hex32_decode
.extern sha_ctx
.extern digest_buf
.extern io_buf
.extern hex_buf

run_ledger_empty_root:
    cmp qword ptr [rsp], 2
    jne usage_exit

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final
    jmp ledger_write_digest

run_ledger_leaf_file:
    cmp qword ptr [rsp], 3
    jne usage_exit

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + ledger_leaf_prefix]
    mov edx, 1
    call sha256_update

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, qword ptr [rsp + 24]
    mov edx, O_RDONLY
    xor r10d, r10d
    syscall
    test rax, rax
    js read_error
    mov r12, rax

.Lledger_leaf_read_loop:
    mov eax, SYS_READ
    mov rdi, r12
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js .Lledger_leaf_read_fail_close
    jz .Lledger_leaf_read_done

    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + io_buf]
    mov rdx, rax
    call sha256_update
    jmp .Lledger_leaf_read_loop

.Lledger_leaf_read_fail_close:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall
    jmp read_error

.Lledger_leaf_read_done:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final
    jmp ledger_write_digest

run_ledger_node:
    cmp qword ptr [rsp], 4
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + ledger_left_hash]
    call hex32_decode
    cmp eax, 1
    jne ledger_arg_error

    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + ledger_right_hash]
    call hex32_decode
    cmp eax, 1
    jne ledger_arg_error

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + ledger_node_prefix]
    mov edx, 1
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + ledger_left_hash]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + ledger_right_hash]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final
    jmp ledger_write_digest

ledger_write_digest:
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + hex_buf]
    mov edx, 32
    call hex_encode
    mov byte ptr [rip + hex_buf + 64], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 65
    call write_all
    xor edi, edi
    jmp exit_process

ledger_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + ledger_arg_error_msg]
    mov edx, OFFSET FLAT:ledger_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

.section .rodata
ledger_leaf_prefix:
    .byte 0
ledger_node_prefix:
    .byte 1
ledger_arg_error_msg:
    .ascii "invalid ledger hash argument\n"
.set ledger_arg_error_msg_len, . - ledger_arg_error_msg

.section .bss
.align 32
ledger_left_hash:
    .skip 32
ledger_right_hash:
    .skip 32

.section .note.GNU-stack,"",@progbits
