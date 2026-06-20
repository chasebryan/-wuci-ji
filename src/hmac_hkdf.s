.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global run_hmac_sha256
.global run_hkdf_sha256
.global hmac_prepare_sha256_key32
.extern usage_exit
.extern read_error
.extern key_error
.extern hkdf_arg_error
.extern exit_process
.extern write_all
.extern hex_encode
.extern hex32_decode
.extern sha256_init
.extern sha256_update
.extern sha256_final
.extern sha_ctx
.extern io_buf
.extern digest_buf
.extern hex_buf
.extern hmac_key
.extern hmac_ipad
.extern hmac_opad
.extern hmac_inner
.extern hkdf_salt
.extern hkdf_info
.extern hkdf_prk
.extern hkdf_counter_one

run_hmac_sha256:
    cmp qword ptr [rsp], 3
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + hmac_key]
    call hex32_decode
    cmp eax, 1
    jne key_error

    lea rdi, [rip + hmac_key]
    lea rsi, [rip + hmac_ipad]
    lea rdx, [rip + hmac_opad]
    call hmac_prepare_sha256_key32

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_ipad]
    mov edx, 64
    call sha256_update

.Lhmac_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Lhmac_eof

    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + io_buf]
    mov rdx, rax
    call sha256_update
    jmp .Lhmac_read_loop

.Lhmac_eof:
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_inner]
    call sha256_final

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_opad]
    mov edx, 64
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_inner]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final

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

run_hkdf_sha256:
    cmp qword ptr [rsp], 4
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + hkdf_salt]
    call hex32_decode
    cmp eax, 1
    jne hkdf_arg_error

    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + hkdf_info]
    call hex32_decode
    cmp eax, 1
    jne hkdf_arg_error

    lea rdi, [rip + hkdf_salt]
    lea rsi, [rip + hmac_ipad]
    lea rdx, [rip + hmac_opad]
    call hmac_prepare_sha256_key32

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_ipad]
    mov edx, 64
    call sha256_update

.Lhkdf_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Lhkdf_eof

    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + io_buf]
    mov rdx, rax
    call sha256_update
    jmp .Lhkdf_read_loop

.Lhkdf_eof:
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_inner]
    call sha256_final

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_opad]
    mov edx, 64
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_inner]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hkdf_prk]
    call sha256_final

    lea rdi, [rip + hkdf_prk]
    lea rsi, [rip + hmac_ipad]
    lea rdx, [rip + hmac_opad]
    call hmac_prepare_sha256_key32

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_ipad]
    mov edx, 64
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hkdf_info]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hkdf_counter_one]
    mov edx, 1
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_inner]
    call sha256_final

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_opad]
    mov edx, 64
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hmac_inner]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final

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

hmac_prepare_sha256_key32:
    xor rcx, rcx
.Lhmac_key_loop:
    cmp rcx, 32
    je .Lhmac_pad_loop
    mov al, byte ptr [rdi + rcx]
    mov r8b, al
    xor al, 0x36
    mov byte ptr [rsi + rcx], al
    mov al, r8b
    xor al, 0x5c
    mov byte ptr [rdx + rcx], al
    inc rcx
    jmp .Lhmac_key_loop
.Lhmac_pad_loop:
    cmp rcx, 64
    je .Lhmac_prepare_done
    mov byte ptr [rsi + rcx], 0x36
    mov byte ptr [rdx + rcx], 0x5c
    inc rcx
    jmp .Lhmac_pad_loop
.Lhmac_prepare_done:
    ret

.section .note.GNU-stack,"",@progbits
