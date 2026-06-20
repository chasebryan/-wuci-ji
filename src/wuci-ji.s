.intel_syntax noprefix

.equ SYS_READ, 0
.equ SYS_WRITE, 1
.equ SYS_CLOSE, 3
.equ SYS_EXIT, 60
.equ SYS_OPENAT, 257
.equ SYS_GETRANDOM, 318

.equ STDIN, 0
.equ STDOUT, 1
.equ STDERR, 2
.equ AT_FDCWD, -100
.equ O_RDONLY, 0

.equ SHA256_STATE, 0
.equ SHA256_BYTES, 32
.equ SHA256_BUFLEN, 40
.equ SHA256_BUFFER, 48
.equ SHA256_CTX_SIZE, 112
.equ AEAD_OPEN_MAX, 1048576
.equ ENVELOPE_PREFIX_LEN, 8
.equ ENVELOPE_NONCE_LEN, 12
.equ ENVELOPE_TAG_LEN, 16
.equ ENVELOPE_HEADER_LEN, ENVELOPE_PREFIX_LEN + ENVELOPE_NONCE_LEN
.equ ENVELOPE_MIN_LEN, ENVELOPE_HEADER_LEN + ENVELOPE_TAG_LEN
.equ ENVELOPE_KEY_ID_LEN, 16
.equ ENVELOPE_V2_HEADER_LEN, ENVELOPE_PREFIX_LEN + ENVELOPE_KEY_ID_LEN + ENVELOPE_NONCE_LEN
.equ ENVELOPE_V2_MIN_LEN, ENVELOPE_V2_HEADER_LEN + ENVELOPE_TAG_LEN
.equ KEYFILE_READ_MAX, 66

.section .text
.global _start

_start:
    mov rax, qword ptr [rsp]
    cmp rax, 2
    jb usage_exit

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_sha256]
    call streq
    cmp eax, 1
    je run_sha256

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_selftest]
    call streq
    cmp eax, 1
    je run_selftest

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_keygen]
    call streq
    cmp eax, 1
    je run_keygen

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_hmac_sha256]
    call streq
    cmp eax, 1
    je run_hmac_sha256

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_hkdf_sha256]
    call streq
    cmp eax, 1
    je run_hkdf_sha256

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_poly1305]
    call streq
    cmp eax, 1
    je run_poly1305

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_chacha20]
    call streq
    cmp eax, 1
    je run_chacha20

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_seal]
    call streq
    cmp eax, 1
    je run_seal

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_seal_v2]
    call streq
    cmp eax, 1
    je run_seal_v2

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_seal_keyfile]
    call streq
    cmp eax, 1
    je run_seal_keyfile

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_seal_keyfile_v2]
    call streq
    cmp eax, 1
    je run_seal_keyfile_v2

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_open]
    call streq
    cmp eax, 1
    je run_open

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_open_keyfile]
    call streq
    cmp eax, 1
    je run_open_keyfile

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_aead_seal]
    call streq
    cmp eax, 1
    je run_aead_seal

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_aead_open]
    call streq
    cmp eax, 1
    je run_aead_open

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_help]
    call streq
    cmp eax, 1
    je help_exit

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_help_long]
    call streq
    cmp eax, 1
    je help_exit

usage_exit:
    mov rdi, STDERR
    lea rsi, [rip + usage_msg]
    mov edx, OFFSET FLAT:usage_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

help_exit:
    mov rdi, STDOUT
    lea rsi, [rip + usage_msg]
    mov edx, OFFSET FLAT:usage_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

run_sha256:
    lea rdi, [rip + sha_ctx]
    call sha256_init

.Lread_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Lsha_eof

    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + io_buf]
    mov rdx, rax
    call sha256_update
    jmp .Lread_loop

.Lsha_eof:
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

read_error:
    mov rdi, STDERR
    lea rsi, [rip + read_error_msg]
    mov edx, OFFSET FLAT:read_error_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

key_error:
    mov rdi, STDERR
    lea rsi, [rip + key_error_msg]
    mov edx, OFFSET FLAT:key_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

keyfile_error:
    mov rdi, STDERR
    lea rsi, [rip + keyfile_error_msg]
    mov edx, OFFSET FLAT:keyfile_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

keyid_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + keyid_arg_error_msg]
    mov edx, OFFSET FLAT:keyid_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

chacha_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + chacha_arg_error_msg]
    mov edx, OFFSET FLAT:chacha_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

hkdf_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + hkdf_arg_error_msg]
    mov edx, OFFSET FLAT:hkdf_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

poly_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + poly_arg_error_msg]
    mov edx, OFFSET FLAT:poly_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

aead_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + aead_arg_error_msg]
    mov edx, OFFSET FLAT:aead_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

aead_auth_error:
    mov rdi, STDERR
    lea rsi, [rip + aead_auth_error_msg]
    mov edx, OFFSET FLAT:aead_auth_error_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

aead_size_error:
    mov rdi, STDERR
    lea rsi, [rip + aead_size_error_msg]
    mov edx, OFFSET FLAT:aead_size_error_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

random_error:
    mov rdi, STDERR
    lea rsi, [rip + random_error_msg]
    mov edx, OFFSET FLAT:random_error_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

envelope_error:
    mov rdi, STDERR
    lea rsi, [rip + envelope_error_msg]
    mov edx, OFFSET FLAT:envelope_error_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

run_keygen:
    lea rdi, [rip + chacha_key]
    mov esi, 32
    call fill_random
    cmp eax, 1
    jne random_error

    lea rdi, [rip + chacha_key]
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

run_hmac_sha256:
    cmp qword ptr [rsp], 3
    jb usage_exit

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
    jb usage_exit

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

run_poly1305:
    cmp qword ptr [rsp], 3
    jb usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + poly_key]
    call hex32_decode
    cmp eax, 1
    jne poly_arg_error

    lea rdi, [rip + poly_key]
    call poly1305_init

.Lpoly_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Lpoly_eof

    lea rdi, [rip + io_buf]
    mov rsi, rax
    call poly1305_update
    jmp .Lpoly_read_loop

.Lpoly_eof:
    lea rdi, [rip + poly_tag]
    call poly1305_final

    lea rdi, [rip + poly_tag]
    lea rsi, [rip + hex_buf]
    mov edx, 16
    call hex_encode

    mov byte ptr [rip + hex_buf + 32], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call write_all

    xor edi, edi
    jmp exit_process

run_chacha20:
    cmp qword ptr [rsp], 5
    jb usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call hex32_decode
    cmp eax, 1
    jne chacha_arg_error

    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + chacha_nonce]
    call hex12_decode
    cmp eax, 1
    jne chacha_arg_error

    mov rdi, qword ptr [rsp + 40]
    lea rsi, [rip + chacha_counter]
    call hex_u32_decode
    cmp eax, 1
    jne chacha_arg_error

.Lchacha_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Lchacha_eof

    lea rdi, [rip + io_buf]
    mov rsi, rax
    call chacha20_xor

    mov rdi, STDOUT
    lea rsi, [rip + io_buf]
    mov rdx, rax
    call write_all
    jmp .Lchacha_read_loop

.Lchacha_eof:
    xor edi, edi
    jmp exit_process

run_seal:
    cmp qword ptr [rsp], 3
    jb usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call hex32_decode
    cmp eax, 1
    jne aead_arg_error

    jmp seal_with_loaded_key

run_seal_v2:
    cmp qword ptr [rsp], 4
    jb usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call hex32_decode
    cmp eax, 1
    jne aead_arg_error

    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + envelope_key_id]
    call hex16_decode
    cmp eax, 1
    jne keyid_arg_error

    jmp seal_v2_with_loaded_key

run_seal_keyfile:
    cmp qword ptr [rsp], 3
    jb usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call read_key_file
    cmp eax, 1
    jne keyfile_error

    jmp seal_with_loaded_key

run_seal_keyfile_v2:
    cmp qword ptr [rsp], 4
    jb usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call read_key_file
    cmp eax, 1
    jne keyfile_error

    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + envelope_key_id]
    call hex16_decode
    cmp eax, 1
    jne keyid_arg_error

    jmp seal_v2_with_loaded_key

seal_with_loaded_key:
    lea rdi, [rip + chacha_nonce]
    mov esi, ENVELOPE_NONCE_LEN
    call fill_random
    cmp eax, 1
    jne random_error

    mov rdi, STDOUT
    lea rsi, [rip + envelope_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + chacha_nonce]
    mov edx, ENVELOPE_NONCE_LEN
    call write_all

    call aead_poly1305_init
    jmp seal_stream_with_current_aad

seal_v2_with_loaded_key:
    lea rdi, [rip + chacha_nonce]
    mov esi, ENVELOPE_NONCE_LEN
    call fill_random
    cmp eax, 1
    jne random_error

    call build_envelope_v2_header

    mov rdi, STDOUT
    lea rsi, [rip + envelope_header_buf]
    mov edx, ENVELOPE_V2_HEADER_LEN
    call write_all

    call aead_poly1305_init
    lea rdi, [rip + envelope_header_buf]
    mov esi, ENVELOPE_V2_HEADER_LEN
    call aead_poly1305_update_aad

seal_stream_with_current_aad:
    mov qword ptr [rip + aead_text_len], 0
    mov dword ptr [rip + chacha_counter], 1

.Lseal_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Lseal_eof

    lea rdi, [rip + io_buf]
    mov rsi, rax
    call chacha20_xor
    mov r14, rax
    add qword ptr [rip + aead_text_len], r14

    lea rdi, [rip + io_buf]
    mov rsi, r14
    call poly1305_update

    mov rdi, STDOUT
    lea rsi, [rip + io_buf]
    mov rdx, r14
    call write_all
    jmp .Lseal_read_loop

.Lseal_eof:
    mov rdi, qword ptr [rip + aead_text_len]
    lea rsi, [rip + poly_tag]
    call aead_poly1305_finish

    mov rdi, STDOUT
    lea rsi, [rip + poly_tag]
    mov edx, ENVELOPE_TAG_LEN
    call write_all

    xor edi, edi
    jmp exit_process

run_open:
    cmp qword ptr [rsp], 3
    jb usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call hex32_decode
    cmp eax, 1
    jne aead_arg_error

    jmp open_with_loaded_key

run_open_keyfile:
    cmp qword ptr [rsp], 3
    jb usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call read_key_file
    cmp eax, 1
    jne keyfile_error

open_with_loaded_key:
    mov qword ptr [rip + aead_text_len], 0

.Lopen_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Lopen_eof

    mov rbx, qword ptr [rip + aead_text_len]
    mov rcx, AEAD_OPEN_MAX
    sub rcx, rbx
    cmp rax, rcx
    ja aead_size_error

    lea rdi, [rip + aead_open_buf]
    add rdi, rbx
    lea rsi, [rip + io_buf]
    mov rcx, rax
    rep movsb
    add qword ptr [rip + aead_text_len], rax
    jmp .Lopen_read_loop

.Lopen_eof:
    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_MIN_LEN
    jb envelope_error

    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + envelope_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    je .Lopen_v1

    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_V2_MIN_LEN
    jb envelope_error
    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + envelope_v2_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    jne envelope_error
    jmp .Lopen_v2

.Lopen_v1:
    lea rdi, [rip + chacha_nonce]
    lea rsi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    mov ecx, ENVELOPE_NONCE_LEN
    rep movsb

    mov rax, qword ptr [rip + aead_text_len]
    sub rax, ENVELOPE_MIN_LEN
    mov qword ptr [rip + aead_text_len], rax

    lea rsi, [rip + aead_open_buf + ENVELOPE_HEADER_LEN]
    add rsi, rax
    lea rdi, [rip + aead_expected_tag]
    mov ecx, ENVELOPE_TAG_LEN
    rep movsb

    call aead_poly1305_init
    lea rdi, [rip + aead_open_buf + ENVELOPE_HEADER_LEN]
    mov rsi, qword ptr [rip + aead_text_len]
    call poly1305_update
    mov rdi, qword ptr [rip + aead_text_len]
    lea rsi, [rip + poly_tag]
    call aead_poly1305_finish

    lea rdi, [rip + poly_tag]
    lea rsi, [rip + aead_expected_tag]
    mov edx, ENVELOPE_TAG_LEN
    call memeq
    cmp eax, 1
    jne envelope_error

    mov dword ptr [rip + chacha_counter], 1
    lea rdi, [rip + aead_open_buf + ENVELOPE_HEADER_LEN]
    mov rsi, qword ptr [rip + aead_text_len]
    call chacha20_xor

    mov rdi, STDOUT
    lea rsi, [rip + aead_open_buf + ENVELOPE_HEADER_LEN]
    mov rdx, qword ptr [rip + aead_text_len]
    call write_all

    xor edi, edi
    jmp exit_process

.Lopen_v2:
    lea rdi, [rip + chacha_nonce]
    lea rsi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_KEY_ID_LEN]
    mov ecx, ENVELOPE_NONCE_LEN
    rep movsb

    mov rax, qword ptr [rip + aead_text_len]
    sub rax, ENVELOPE_V2_MIN_LEN
    mov qword ptr [rip + aead_text_len], rax

    lea rsi, [rip + aead_open_buf + ENVELOPE_V2_HEADER_LEN]
    add rsi, rax
    lea rdi, [rip + aead_expected_tag]
    mov ecx, ENVELOPE_TAG_LEN
    rep movsb

    call aead_poly1305_init
    lea rdi, [rip + aead_open_buf]
    mov esi, ENVELOPE_V2_HEADER_LEN
    call aead_poly1305_update_aad
    lea rdi, [rip + aead_open_buf + ENVELOPE_V2_HEADER_LEN]
    mov rsi, qword ptr [rip + aead_text_len]
    call poly1305_update
    mov rdi, qword ptr [rip + aead_text_len]
    lea rsi, [rip + poly_tag]
    call aead_poly1305_finish

    lea rdi, [rip + poly_tag]
    lea rsi, [rip + aead_expected_tag]
    mov edx, ENVELOPE_TAG_LEN
    call memeq
    cmp eax, 1
    jne envelope_error

    mov dword ptr [rip + chacha_counter], 1
    lea rdi, [rip + aead_open_buf + ENVELOPE_V2_HEADER_LEN]
    mov rsi, qword ptr [rip + aead_text_len]
    call chacha20_xor

    mov rdi, STDOUT
    lea rsi, [rip + aead_open_buf + ENVELOPE_V2_HEADER_LEN]
    mov rdx, qword ptr [rip + aead_text_len]
    call write_all

    xor edi, edi
    jmp exit_process

run_aead_seal:
    cmp qword ptr [rsp], 4
    jb usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call hex32_decode
    cmp eax, 1
    jne aead_arg_error

    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + chacha_nonce]
    call hex12_decode
    cmp eax, 1
    jne aead_arg_error

    call aead_poly1305_init
    mov qword ptr [rip + aead_text_len], 0
    mov dword ptr [rip + chacha_counter], 1

.Laead_seal_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Laead_seal_eof

    lea rdi, [rip + io_buf]
    mov rsi, rax
    call chacha20_xor
    mov r14, rax
    add qword ptr [rip + aead_text_len], r14

    lea rdi, [rip + io_buf]
    mov rsi, r14
    call poly1305_update

    mov rdi, STDOUT
    lea rsi, [rip + io_buf]
    mov rdx, r14
    call write_all
    jmp .Laead_seal_read_loop

.Laead_seal_eof:
    mov rdi, qword ptr [rip + aead_text_len]
    lea rsi, [rip + poly_tag]
    call aead_poly1305_finish

    mov rdi, STDOUT
    lea rsi, [rip + poly_tag]
    mov edx, 16
    call write_all

    xor edi, edi
    jmp exit_process

run_aead_open:
    cmp qword ptr [rsp], 5
    jb usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call hex32_decode
    cmp eax, 1
    jne aead_arg_error

    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + chacha_nonce]
    call hex12_decode
    cmp eax, 1
    jne aead_arg_error

    mov rdi, qword ptr [rsp + 40]
    lea rsi, [rip + aead_expected_tag]
    call hex16_decode
    cmp eax, 1
    jne aead_arg_error

    mov qword ptr [rip + aead_text_len], 0

.Laead_open_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Laead_open_eof

    mov rbx, qword ptr [rip + aead_text_len]
    mov rcx, AEAD_OPEN_MAX
    sub rcx, rbx
    cmp rax, rcx
    ja aead_size_error

    lea rdi, [rip + aead_open_buf]
    add rdi, rbx
    lea rsi, [rip + io_buf]
    mov rcx, rax
    rep movsb
    add qword ptr [rip + aead_text_len], rax
    jmp .Laead_open_read_loop

.Laead_open_eof:
    call aead_poly1305_init
    lea rdi, [rip + aead_open_buf]
    mov rsi, qword ptr [rip + aead_text_len]
    call poly1305_update
    mov rdi, qword ptr [rip + aead_text_len]
    lea rsi, [rip + poly_tag]
    call aead_poly1305_finish

    lea rdi, [rip + poly_tag]
    lea rsi, [rip + aead_expected_tag]
    mov edx, 16
    call memeq
    cmp eax, 1
    jne aead_auth_error

    mov dword ptr [rip + chacha_counter], 1
    lea rdi, [rip + aead_open_buf]
    mov rsi, qword ptr [rip + aead_text_len]
    call chacha20_xor

    mov rdi, STDOUT
    lea rsi, [rip + aead_open_buf]
    mov rdx, qword ptr [rip + aead_text_len]
    call write_all

    xor edi, edi
    jmp exit_process

run_selftest:
    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + sha256_empty]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne selftest_fail

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + msg_abc]
    mov edx, 3
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + sha256_abc]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne selftest_fail

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + msg_abc]
    mov edx, 1
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + msg_abc + 1]
    mov edx, 2
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final
    lea rdi, [rip + digest_buf]
    lea rsi, [rip + sha256_abc]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne selftest_fail

    lea rdi, [rip + hmac_selftest_key]
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
    lea rsi, [rip + msg_hi_there]
    mov edx, 8
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
    lea rsi, [rip + hmac_sha256_hi_there]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne selftest_fail

    lea rdi, [rip + hkdf_selftest_salt]
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
    lea rsi, [rip + msg_abc]
    mov edx, 3
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
    lea rsi, [rip + hkdf_selftest_info]
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
    lea rsi, [rip + hkdf_sha256_abc]
    mov edx, 32
    call memeq
    cmp eax, 1
    jne selftest_fail

    lea rdi, [rip + poly1305_selftest_key]
    call poly1305_init
    lea rdi, [rip + msg_poly1305]
    mov esi, 34
    call poly1305_update
    lea rdi, [rip + poly_tag]
    call poly1305_final
    lea rdi, [rip + poly_tag]
    lea rsi, [rip + poly1305_expected]
    mov edx, 16
    call memeq
    cmp eax, 1
    jne selftest_fail

    lea rdi, [rip + hmac_selftest_key]
    lea rsi, [rip + chacha_selftest_nonce]
    mov edx, 1
    lea rcx, [rip + chacha_block]
    call chacha20_block
    lea rdi, [rip + chacha_block]
    lea rsi, [rip + chacha20_block_expected]
    mov edx, 64
    call memeq
    cmp eax, 1
    jne selftest_fail

    lea rdi, [rip + chacha_key]
    lea rsi, [rip + hmac_selftest_key]
    mov ecx, 32
    rep movsb
    lea rdi, [rip + chacha_nonce]
    lea rsi, [rip + chacha_selftest_nonce]
    mov ecx, 12
    rep movsb
    lea rdi, [rip + io_buf]
    lea rsi, [rip + msg_abc]
    mov ecx, 3
    rep movsb
    mov dword ptr [rip + chacha_counter], 1
    lea rdi, [rip + io_buf]
    mov esi, 3
    call chacha20_xor
    lea rdi, [rip + io_buf]
    lea rsi, [rip + aead_abc_ciphertext]
    mov edx, 3
    call memeq
    cmp eax, 1
    jne selftest_fail

    call aead_poly1305_init
    lea rdi, [rip + io_buf]
    mov esi, 3
    call poly1305_update
    mov edi, 3
    lea rsi, [rip + poly_tag]
    call aead_poly1305_finish
    lea rdi, [rip + poly_tag]
    lea rsi, [rip + aead_abc_tag]
    mov edx, 16
    call memeq
    cmp eax, 1
    jne selftest_fail

    mov dword ptr [rip + chacha_counter], 1
    lea rdi, [rip + io_buf]
    mov esi, 3
    call chacha20_xor
    lea rdi, [rip + io_buf]
    lea rsi, [rip + msg_abc]
    mov edx, 3
    call memeq
    cmp eax, 1
    jne selftest_fail

    mov rdi, STDOUT
    lea rsi, [rip + selftest_pass_msg]
    mov edx, OFFSET FLAT:selftest_pass_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

selftest_fail:
    mov rdi, STDERR
    lea rsi, [rip + selftest_fail_msg]
    mov edx, OFFSET FLAT:selftest_fail_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

exit_process:
    push rdi
    call zero_sensitive_state
    pop rdi
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    mov eax, SYS_EXIT
    syscall

streq:
    xor eax, eax
.Lstreq_loop:
    mov dl, byte ptr [rdi]
    mov cl, byte ptr [rsi]
    cmp dl, cl
    jne .Lstreq_done
    test dl, dl
    je .Lstreq_equal
    inc rdi
    inc rsi
    jmp .Lstreq_loop
.Lstreq_equal:
    mov eax, 1
.Lstreq_done:
    ret

memeq:
    xor eax, eax
    test rdx, rdx
    jz .Lmemeq_equal
.Lmemeq_loop:
    mov cl, byte ptr [rdi]
    xor cl, byte ptr [rsi]
    or al, cl
    inc rdi
    inc rsi
    dec rdx
    jne .Lmemeq_loop
    test al, al
    sete al
    movzx eax, al
    ret
.Lmemeq_equal:
    mov eax, 1
    ret

write_all:
    push rbx
    push r12
    push r13
    mov r13, rdi
    mov rbx, rsi
    mov r12, rdx
.Lwrite_all_loop:
    test r12, r12
    jz .Lwrite_all_ok
    mov eax, SYS_WRITE
    mov rdi, r13
    mov rsi, rbx
    mov rdx, r12
    syscall
    cmp rax, 0
    jle .Lwrite_all_err
    add rbx, rax
    sub r12, rax
    jmp .Lwrite_all_loop
.Lwrite_all_ok:
    xor eax, eax
    jmp .Lwrite_all_done
.Lwrite_all_err:
    mov eax, 1
.Lwrite_all_done:
    pop r13
    pop r12
    pop rbx
    ret

fill_random:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
.Lfill_random_loop:
    test r12, r12
    jz .Lfill_random_ok
    mov eax, SYS_GETRANDOM
    mov rdi, rbx
    mov rsi, r12
    xor edx, edx
    syscall
    cmp rax, 0
    jle .Lfill_random_fail
    add rbx, rax
    sub r12, rax
    jmp .Lfill_random_loop
.Lfill_random_ok:
    mov eax, 1
    jmp .Lfill_random_done
.Lfill_random_fail:
    xor eax, eax
.Lfill_random_done:
    pop r12
    pop rbx
    ret

read_key_file:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, rbx
    mov edx, O_RDONLY
    xor r10d, r10d
    syscall
    test rax, rax
    js .Lread_key_file_fail

    mov r13, rax
    mov eax, SYS_READ
    mov rdi, r13
    lea rsi, [rip + hex_buf]
    mov edx, KEYFILE_READ_MAX
    syscall
    mov rbx, rax

    mov eax, SYS_CLOSE
    mov rdi, r13
    syscall

    test rbx, rbx
    js .Lread_key_file_fail
    cmp rbx, 64
    jb .Lread_key_file_fail
    cmp rbx, 64
    je .Lread_key_file_decode
    cmp rbx, 65
    jne .Lread_key_file_fail
    cmp byte ptr [rip + hex_buf + 64], 10
    jne .Lread_key_file_fail

.Lread_key_file_decode:
    mov byte ptr [rip + hex_buf + 64], 0
    lea rdi, [rip + hex_buf]
    mov rsi, r12
    call hex32_decode
    cmp eax, 1
    jne .Lread_key_file_fail
    mov eax, 1
    jmp .Lread_key_file_done

.Lread_key_file_fail:
    xor eax, eax
.Lread_key_file_done:
    pop r13
    pop r12
    pop rbx
    ret

build_envelope_v2_header:
    lea rdi, [rip + envelope_header_buf]
    lea rsi, [rip + envelope_v2_prefix]
    mov ecx, ENVELOPE_PREFIX_LEN
    rep movsb
    lea rsi, [rip + envelope_key_id]
    mov ecx, ENVELOPE_KEY_ID_LEN
    rep movsb
    lea rsi, [rip + chacha_nonce]
    mov ecx, ENVELOPE_NONCE_LEN
    rep movsb
    ret

zero_sensitive_state:
    lea rdi, [rip + bss_sensitive_start]
    mov esi, OFFSET FLAT:bss_sensitive_len
    jmp zero_memory

zero_memory:
    xor eax, eax
    mov rcx, rsi
    rep stosb
    ret

hex_encode:
    push rbx
    mov r8, rdi
    mov r9, rsi
    mov rcx, rdx
    lea r10, [rip + hex_chars]
    test rcx, rcx
    jz .Lhex_done
.Lhex_loop:
    movzx eax, byte ptr [r8]
    mov ebx, eax
    shr eax, 4
    mov al, byte ptr [r10 + rax]
    mov byte ptr [r9], al
    mov eax, ebx
    and eax, 15
    mov al, byte ptr [r10 + rax]
    mov byte ptr [r9 + 1], al
    inc r8
    add r9, 2
    dec rcx
    jne .Lhex_loop
.Lhex_done:
    pop rbx
    ret

hex32_decode:
    mov edx, 32
    jmp hex_decode_fixed

hex16_decode:
    mov edx, 16
    jmp hex_decode_fixed

hex12_decode:
    mov edx, 12
    jmp hex_decode_fixed

hex_decode_fixed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r15, rdx
    xor r13, r13
.Lhex_decode_loop:
    cmp r13, r15
    je .Lhex_decode_check_end
    mov al, byte ptr [rbx + r13 * 2]
    call hex_value
    cmp eax, 0
    jl .Lhex_decode_fail
    shl eax, 4
    mov r14d, eax
    mov al, byte ptr [rbx + r13 * 2 + 1]
    call hex_value
    cmp eax, 0
    jl .Lhex_decode_fail
    or eax, r14d
    mov byte ptr [r12 + r13], al
    inc r13
    jmp .Lhex_decode_loop
.Lhex_decode_check_end:
    cmp byte ptr [rbx + r15 * 2], 0
    jne .Lhex_decode_fail
    mov eax, 1
    jmp .Lhex_decode_done
.Lhex_decode_fail:
    xor eax, eax
.Lhex_decode_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

hex_u32_decode:
    push rbx
    push r12
    mov rbx, rdi
    xor r12d, r12d
    xor ecx, ecx
.Lhex_u32_loop:
    cmp ecx, 8
    je .Lhex_u32_check_end
    mov al, byte ptr [rbx + rcx]
    call hex_value
    cmp eax, 0
    jl .Lhex_u32_fail
    shl r12d, 4
    or r12d, eax
    inc ecx
    jmp .Lhex_u32_loop
.Lhex_u32_check_end:
    cmp byte ptr [rbx + 8], 0
    jne .Lhex_u32_fail
    mov dword ptr [rsi], r12d
    mov eax, 1
    jmp .Lhex_u32_done
.Lhex_u32_fail:
    xor eax, eax
.Lhex_u32_done:
    pop r12
    pop rbx
    ret

hex_value:
    cmp al, '0'
    jb .Lhex_value_fail
    cmp al, '9'
    jbe .Lhex_value_digit
    cmp al, 'a'
    jb .Lhex_value_upper
    cmp al, 'f'
    jbe .Lhex_value_lower
    jmp .Lhex_value_fail
.Lhex_value_upper:
    cmp al, 'A'
    jb .Lhex_value_fail
    cmp al, 'F'
    ja .Lhex_value_fail
    sub al, 'A' - 10
    movzx eax, al
    ret
.Lhex_value_lower:
    sub al, 'a' - 10
    movzx eax, al
    ret
.Lhex_value_digit:
    sub al, '0'
    movzx eax, al
    ret
.Lhex_value_fail:
    mov eax, -1
    ret

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

aead_poly1305_init:
    lea rdi, [rip + chacha_key]
    lea rsi, [rip + chacha_nonce]
    xor edx, edx
    lea rcx, [rip + chacha_block]
    call chacha20_block
    lea rdi, [rip + chacha_block]
    call poly1305_init
    lea rdi, [rip + chacha_block]
    mov esi, 64
    call zero_memory
    mov qword ptr [rip + aead_aad_len], 0
    ret

aead_poly1305_update_aad:
    push rbx
    mov rbx, rsi
    mov qword ptr [rip + aead_aad_len], rsi
    call poly1305_update

    mov rax, rbx
    and eax, 15
    jz .Laead_aad_done
    mov ecx, 16
    sub rcx, rax
    lea rdi, [rip + aead_zero_pad]
    mov rsi, rcx
    call poly1305_update

.Laead_aad_done:
    pop rbx
    ret

aead_poly1305_finish:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi

    mov rax, rbx
    and eax, 15
    jz .Laead_finish_lengths
    mov ecx, 16
    sub rcx, rax
    lea rdi, [rip + aead_zero_pad]
    mov rsi, rcx
    call poly1305_update

.Laead_finish_lengths:
    mov rax, qword ptr [rip + aead_aad_len]
    mov qword ptr [rip + aead_len_block], rax
    mov qword ptr [rip + aead_len_block + 8], rbx
    lea rdi, [rip + aead_len_block]
    mov esi, 16
    call poly1305_update
    mov rdi, r12
    call poly1305_final

    pop r12
    pop rbx
    ret

.macro SCRUB_STACK bytes
    lea rdi, [rsp]
    mov ecx, \bytes
    xor eax, eax
    rep stosb
.endm

.macro SCRUB_VOLATILE
    xor eax, eax
    xor ecx, ecx
    xor edx, edx
    xor edi, edi
    xor esi, esi
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
.endm

.macro POLY_MULADD acc, h, f
    mov rax, qword ptr [rip + \h]
    imul rax, qword ptr [rip + \f]
    add qword ptr [rsp + \acc], rax
.endm

poly1305_init:
    mov r8d, dword ptr [rdi + 0]
    mov r9d, dword ptr [rdi + 4]
    mov r10d, dword ptr [rdi + 8]
    mov r11d, dword ptr [rdi + 12]

    mov eax, r8d
    and eax, 0x03ffffff
    mov qword ptr [rip + poly_r0], rax

    mov eax, r8d
    shr eax, 26
    mov ecx, r9d
    shl ecx, 6
    or eax, ecx
    and eax, 0x03ffff03
    mov qword ptr [rip + poly_r1], rax
    lea rcx, [rax + rax * 4]
    mov qword ptr [rip + poly_s1], rcx

    mov eax, r9d
    shr eax, 20
    mov ecx, r10d
    shl ecx, 12
    or eax, ecx
    and eax, 0x03ffc0ff
    mov qword ptr [rip + poly_r2], rax
    lea rcx, [rax + rax * 4]
    mov qword ptr [rip + poly_s2], rcx

    mov eax, r10d
    shr eax, 14
    mov ecx, r11d
    shl ecx, 18
    or eax, ecx
    and eax, 0x03f03fff
    mov qword ptr [rip + poly_r3], rax
    lea rcx, [rax + rax * 4]
    mov qword ptr [rip + poly_s3], rcx

    mov eax, r11d
    shr eax, 8
    and eax, 0x000fffff
    mov qword ptr [rip + poly_r4], rax
    lea rcx, [rax + rax * 4]
    mov qword ptr [rip + poly_s4], rcx

    mov eax, dword ptr [rdi + 16]
    mov dword ptr [rip + poly_pad0], eax
    mov eax, dword ptr [rdi + 20]
    mov dword ptr [rip + poly_pad1], eax
    mov eax, dword ptr [rdi + 24]
    mov dword ptr [rip + poly_pad2], eax
    mov eax, dword ptr [rdi + 28]
    mov dword ptr [rip + poly_pad3], eax

    mov qword ptr [rip + poly_h0], 0
    mov qword ptr [rip + poly_h1], 0
    mov qword ptr [rip + poly_h2], 0
    mov qword ptr [rip + poly_h3], 0
    mov qword ptr [rip + poly_h4], 0
    mov qword ptr [rip + poly_leftover], 0
    ret

poly1305_update:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    test r12, r12
    jz .Lpoly_update_done

    mov r13, qword ptr [rip + poly_leftover]
    test r13, r13
    jz .Lpoly_update_full_blocks

    mov r14, 16
    sub r14, r13
    cmp r12, r14
    jb .Lpoly_update_buffer_only

    lea rdi, [rip + poly_buffer]
    add rdi, r13
    mov rsi, rbx
    mov rcx, r14
    rep movsb
    add rbx, r14
    sub r12, r14
    mov qword ptr [rip + poly_leftover], 0
    lea rdi, [rip + poly_buffer]
    mov esi, 16
    mov edx, 0x01000000
    call poly1305_blocks
    jmp .Lpoly_update_full_blocks

.Lpoly_update_buffer_only:
    lea rdi, [rip + poly_buffer]
    add rdi, r13
    mov rsi, rbx
    mov rcx, r12
    rep movsb
    add r13, r12
    mov qword ptr [rip + poly_leftover], r13
    jmp .Lpoly_update_done

.Lpoly_update_full_blocks:
    mov r13, r12
    and r13, -16
    test r13, r13
    jz .Lpoly_update_tail
    mov rdi, rbx
    mov rsi, r13
    mov edx, 0x01000000
    call poly1305_blocks
    add rbx, r13
    sub r12, r13

.Lpoly_update_tail:
    test r12, r12
    jz .Lpoly_update_done
    lea rdi, [rip + poly_buffer]
    mov rsi, rbx
    mov rcx, r12
    rep movsb
    mov qword ptr [rip + poly_leftover], r12

.Lpoly_update_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

poly1305_final:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov r12, rdi

    mov rbx, qword ptr [rip + poly_leftover]
    test rbx, rbx
    jz .Lpoly_final_reduce
    lea rdi, [rip + poly_buffer]
    add rdi, rbx
    mov byte ptr [rdi], 1
    inc rbx
    mov rcx, 16
    sub rcx, rbx
    lea rdi, [rip + poly_buffer]
    add rdi, rbx
    xor eax, eax
    rep stosb
    lea rdi, [rip + poly_buffer]
    mov esi, 16
    xor edx, edx
    call poly1305_blocks

.Lpoly_final_reduce:
    mov rax, qword ptr [rip + poly_h1]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h1], rax
    add qword ptr [rip + poly_h2], rcx

    mov rax, qword ptr [rip + poly_h2]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h2], rax
    add qword ptr [rip + poly_h3], rcx

    mov rax, qword ptr [rip + poly_h3]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h3], rax
    add qword ptr [rip + poly_h4], rcx

    mov rax, qword ptr [rip + poly_h4]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h4], rax
    lea rcx, [rcx + rcx * 4]
    add qword ptr [rip + poly_h0], rcx

    mov rax, qword ptr [rip + poly_h0]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h0], rax
    add qword ptr [rip + poly_h1], rcx

    mov rax, qword ptr [rip + poly_h0]
    add rax, 5
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rsp + 0], rax

    mov rax, qword ptr [rip + poly_h1]
    add rax, rcx
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rsp + 8], rax

    mov rax, qword ptr [rip + poly_h2]
    add rax, rcx
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rsp + 16], rax

    mov rax, qword ptr [rip + poly_h3]
    add rax, rcx
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rsp + 24], rax

    mov rax, qword ptr [rip + poly_h4]
    add rax, rcx
    sub rax, 0x04000000
    mov qword ptr [rsp + 32], rax

    mov r15, rax
    shr r15, 63
    sub r15, 1
    mov r14, r15
    not r14

    mov rax, qword ptr [rip + poly_h0]
    and rax, r14
    mov rcx, qword ptr [rsp + 0]
    and rcx, r15
    or rax, rcx
    mov qword ptr [rip + poly_h0], rax

    mov rax, qword ptr [rip + poly_h1]
    and rax, r14
    mov rcx, qword ptr [rsp + 8]
    and rcx, r15
    or rax, rcx
    mov qword ptr [rip + poly_h1], rax

    mov rax, qword ptr [rip + poly_h2]
    and rax, r14
    mov rcx, qword ptr [rsp + 16]
    and rcx, r15
    or rax, rcx
    mov qword ptr [rip + poly_h2], rax

    mov rax, qword ptr [rip + poly_h3]
    and rax, r14
    mov rcx, qword ptr [rsp + 24]
    and rcx, r15
    or rax, rcx
    mov qword ptr [rip + poly_h3], rax

    mov rax, qword ptr [rip + poly_h4]
    and rax, r14
    mov rcx, qword ptr [rsp + 32]
    and rcx, r15
    or rax, rcx
    mov qword ptr [rip + poly_h4], rax

    mov rax, qword ptr [rip + poly_h0]
    mov rcx, qword ptr [rip + poly_h1]
    mov rdx, rcx
    shl rdx, 26
    or rax, rdx
    mov r8d, eax

    mov rax, rcx
    shr rax, 6
    mov rcx, qword ptr [rip + poly_h2]
    mov rdx, rcx
    shl rdx, 20
    or rax, rdx
    mov r9d, eax

    mov rax, rcx
    shr rax, 12
    mov rcx, qword ptr [rip + poly_h3]
    mov rdx, rcx
    shl rdx, 14
    or rax, rdx
    mov r10d, eax

    mov rax, rcx
    shr rax, 18
    mov rcx, qword ptr [rip + poly_h4]
    mov rdx, rcx
    shl rdx, 8
    or rax, rdx
    mov r11d, eax

    mov eax, r8d
    mov ecx, dword ptr [rip + poly_pad0]
    add rax, rcx
    mov dword ptr [r12 + 0], eax
    shr rax, 32
    mov r13, rax

    mov eax, r9d
    mov ecx, dword ptr [rip + poly_pad1]
    add rax, rcx
    add rax, r13
    mov dword ptr [r12 + 4], eax
    shr rax, 32
    mov r13, rax

    mov eax, r10d
    mov ecx, dword ptr [rip + poly_pad2]
    add rax, rcx
    add rax, r13
    mov dword ptr [r12 + 8], eax
    shr rax, 32
    mov r13, rax

    mov eax, r11d
    mov ecx, dword ptr [rip + poly_pad3]
    add rax, rcx
    add rax, r13
    mov dword ptr [r12 + 12], eax

    SCRUB_STACK 40
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    SCRUB_VOLATILE
    ret

poly1305_blocks:
    push rbx
    push r12
    push r13
    sub rsp, 40
    mov rbx, rdi
    mov r12, rsi
    mov r13d, edx
    test r12, r12
    jz .Lpoly_blocks_done

.Lpoly_blocks_loop:
    mov r8d, dword ptr [rbx + 0]
    mov r9d, dword ptr [rbx + 4]
    mov r10d, dword ptr [rbx + 8]
    mov r11d, dword ptr [rbx + 12]

    mov eax, r8d
    and eax, 0x03ffffff
    add qword ptr [rip + poly_h0], rax

    mov eax, r8d
    shr eax, 26
    mov ecx, r9d
    shl ecx, 6
    or eax, ecx
    and eax, 0x03ffffff
    add qword ptr [rip + poly_h1], rax

    mov eax, r9d
    shr eax, 20
    mov ecx, r10d
    shl ecx, 12
    or eax, ecx
    and eax, 0x03ffffff
    add qword ptr [rip + poly_h2], rax

    mov eax, r10d
    shr eax, 14
    mov ecx, r11d
    shl ecx, 18
    or eax, ecx
    and eax, 0x03ffffff
    add qword ptr [rip + poly_h3], rax

    mov eax, r11d
    shr eax, 8
    or eax, r13d
    add qword ptr [rip + poly_h4], rax

    mov qword ptr [rsp + 0], 0
    mov qword ptr [rsp + 8], 0
    mov qword ptr [rsp + 16], 0
    mov qword ptr [rsp + 24], 0
    mov qword ptr [rsp + 32], 0

    POLY_MULADD 0, poly_h0, poly_r0
    POLY_MULADD 0, poly_h1, poly_s4
    POLY_MULADD 0, poly_h2, poly_s3
    POLY_MULADD 0, poly_h3, poly_s2
    POLY_MULADD 0, poly_h4, poly_s1

    POLY_MULADD 8, poly_h0, poly_r1
    POLY_MULADD 8, poly_h1, poly_r0
    POLY_MULADD 8, poly_h2, poly_s4
    POLY_MULADD 8, poly_h3, poly_s3
    POLY_MULADD 8, poly_h4, poly_s2

    POLY_MULADD 16, poly_h0, poly_r2
    POLY_MULADD 16, poly_h1, poly_r1
    POLY_MULADD 16, poly_h2, poly_r0
    POLY_MULADD 16, poly_h3, poly_s4
    POLY_MULADD 16, poly_h4, poly_s3

    POLY_MULADD 24, poly_h0, poly_r3
    POLY_MULADD 24, poly_h1, poly_r2
    POLY_MULADD 24, poly_h2, poly_r1
    POLY_MULADD 24, poly_h3, poly_r0
    POLY_MULADD 24, poly_h4, poly_s4

    POLY_MULADD 32, poly_h0, poly_r4
    POLY_MULADD 32, poly_h1, poly_r3
    POLY_MULADD 32, poly_h2, poly_r2
    POLY_MULADD 32, poly_h3, poly_r1
    POLY_MULADD 32, poly_h4, poly_r0

    mov rax, qword ptr [rsp + 0]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h0], rax
    add qword ptr [rsp + 8], rcx

    mov rax, qword ptr [rsp + 8]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h1], rax
    add qword ptr [rsp + 16], rcx

    mov rax, qword ptr [rsp + 16]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h2], rax
    add qword ptr [rsp + 24], rcx

    mov rax, qword ptr [rsp + 24]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h3], rax
    add qword ptr [rsp + 32], rcx

    mov rax, qword ptr [rsp + 32]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h4], rax
    lea rcx, [rcx + rcx * 4]
    add qword ptr [rip + poly_h0], rcx

    mov rax, qword ptr [rip + poly_h0]
    mov rcx, rax
    shr rcx, 26
    and rax, 0x03ffffff
    mov qword ptr [rip + poly_h0], rax
    add qword ptr [rip + poly_h1], rcx

    add rbx, 16
    sub r12, 16
    jne .Lpoly_blocks_loop

.Lpoly_blocks_done:
    SCRUB_STACK 40
    add rsp, 40
    pop r13
    pop r12
    pop rbx
    SCRUB_VOLATILE
    ret

.macro CHACHA_QR a, b, c, d
    mov eax, dword ptr [rsp + \a * 4]
    add eax, dword ptr [rsp + \b * 4]
    mov dword ptr [rsp + \a * 4], eax
    mov r8d, dword ptr [rsp + \d * 4]
    xor r8d, eax
    rol r8d, 16
    mov dword ptr [rsp + \d * 4], r8d

    mov ecx, dword ptr [rsp + \c * 4]
    add ecx, r8d
    mov dword ptr [rsp + \c * 4], ecx
    mov ebx, dword ptr [rsp + \b * 4]
    xor ebx, ecx
    rol ebx, 12
    mov dword ptr [rsp + \b * 4], ebx

    mov eax, dword ptr [rsp + \a * 4]
    add eax, ebx
    mov dword ptr [rsp + \a * 4], eax
    mov r8d, dword ptr [rsp + \d * 4]
    xor r8d, eax
    rol r8d, 8
    mov dword ptr [rsp + \d * 4], r8d

    mov ecx, dword ptr [rsp + \c * 4]
    add ecx, r8d
    mov dword ptr [rsp + \c * 4], ecx
    mov ebx, dword ptr [rsp + \b * 4]
    xor ebx, ecx
    rol ebx, 7
    mov dword ptr [rsp + \b * 4], ebx
.endm

chacha20_xor:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r15, rsi
.Lchacha_xor_blocks:
    test r12, r12
    jz .Lchacha_xor_done

    lea rdi, [rip + chacha_key]
    lea rsi, [rip + chacha_nonce]
    mov edx, dword ptr [rip + chacha_counter]
    lea rcx, [rip + chacha_block]
    call chacha20_block
    inc dword ptr [rip + chacha_counter]

    mov r13, 64
    cmp r12, 64
    jae .Lchacha_xor_chunk_ready
    mov r13, r12
.Lchacha_xor_chunk_ready:
    xor r14, r14
    lea r8, [rip + chacha_block]
.Lchacha_xor_loop:
    cmp r14, r13
    je .Lchacha_xor_next
    mov al, byte ptr [r8 + r14]
    xor byte ptr [rbx + r14], al
    inc r14
    jmp .Lchacha_xor_loop
.Lchacha_xor_next:
    add rbx, r13
    sub r12, r13
    jmp .Lchacha_xor_blocks
.Lchacha_xor_done:
    lea rdi, [rip + chacha_block]
    mov esi, 64
    call zero_memory
    mov rax, r15
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

chacha20_block:
    push rbx
    sub rsp, 128
    mov r10, rcx

    mov dword ptr [rsp + 0], 0x61707865
    mov dword ptr [rsp + 4], 0x3320646e
    mov dword ptr [rsp + 8], 0x79622d32
    mov dword ptr [rsp + 12], 0x6b206574

    mov eax, dword ptr [rdi + 0]
    mov dword ptr [rsp + 16], eax
    mov eax, dword ptr [rdi + 4]
    mov dword ptr [rsp + 20], eax
    mov eax, dword ptr [rdi + 8]
    mov dword ptr [rsp + 24], eax
    mov eax, dword ptr [rdi + 12]
    mov dword ptr [rsp + 28], eax
    mov eax, dword ptr [rdi + 16]
    mov dword ptr [rsp + 32], eax
    mov eax, dword ptr [rdi + 20]
    mov dword ptr [rsp + 36], eax
    mov eax, dword ptr [rdi + 24]
    mov dword ptr [rsp + 40], eax
    mov eax, dword ptr [rdi + 28]
    mov dword ptr [rsp + 44], eax

    mov dword ptr [rsp + 48], edx
    mov eax, dword ptr [rsi + 0]
    mov dword ptr [rsp + 52], eax
    mov eax, dword ptr [rsi + 4]
    mov dword ptr [rsp + 56], eax
    mov eax, dword ptr [rsi + 8]
    mov dword ptr [rsp + 60], eax

    xor r9, r9
.Lchacha_copy_state:
    mov eax, dword ptr [rsp + r9 * 4]
    mov dword ptr [rsp + 64 + r9 * 4], eax
    inc r9
    cmp r9, 16
    jne .Lchacha_copy_state

    mov r9d, 10
.Lchacha_rounds:
    CHACHA_QR 0, 4, 8, 12
    CHACHA_QR 1, 5, 9, 13
    CHACHA_QR 2, 6, 10, 14
    CHACHA_QR 3, 7, 11, 15
    CHACHA_QR 0, 5, 10, 15
    CHACHA_QR 1, 6, 11, 12
    CHACHA_QR 2, 7, 8, 13
    CHACHA_QR 3, 4, 9, 14
    dec r9d
    jne .Lchacha_rounds

    xor r9, r9
.Lchacha_emit:
    mov eax, dword ptr [rsp + r9 * 4]
    add eax, dword ptr [rsp + 64 + r9 * 4]
    mov dword ptr [r10 + r9 * 4], eax
    inc r9
    cmp r9, 16
    jne .Lchacha_emit

    SCRUB_STACK 128
    add rsp, 128
    pop rbx
    SCRUB_VOLATILE
    ret

sha256_init:
    mov dword ptr [rdi + SHA256_STATE + 0], 0x6a09e667
    mov dword ptr [rdi + SHA256_STATE + 4], 0xbb67ae85
    mov dword ptr [rdi + SHA256_STATE + 8], 0x3c6ef372
    mov dword ptr [rdi + SHA256_STATE + 12], 0xa54ff53a
    mov dword ptr [rdi + SHA256_STATE + 16], 0x510e527f
    mov dword ptr [rdi + SHA256_STATE + 20], 0x9b05688c
    mov dword ptr [rdi + SHA256_STATE + 24], 0x1f83d9ab
    mov dword ptr [rdi + SHA256_STATE + 28], 0x5be0cd19
    mov qword ptr [rdi + SHA256_BYTES], 0
    mov qword ptr [rdi + SHA256_BUFLEN], 0
    ret

sha256_update:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    test r13, r13
    jz .Lupdate_done

    add qword ptr [rbx + SHA256_BYTES], r13
    mov r14, qword ptr [rbx + SHA256_BUFLEN]
    test r14, r14
    jz .Lupdate_full_blocks

    mov eax, 64
    sub rax, r14
    cmp r13, rax
    jb .Lupdate_buffer_only

    lea rdi, [rbx + r14 + SHA256_BUFFER]
    mov rsi, r12
    mov rcx, rax
    rep movsb
    add r12, rax
    sub r13, rax
    mov qword ptr [rbx + SHA256_BUFLEN], 0
    mov rdi, rbx
    lea rsi, [rbx + SHA256_BUFFER]
    call sha256_transform
    jmp .Lupdate_full_blocks

.Lupdate_buffer_only:
    lea rdi, [rbx + r14 + SHA256_BUFFER]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    add r14, r13
    mov qword ptr [rbx + SHA256_BUFLEN], r14
    jmp .Lupdate_done

.Lupdate_full_blocks:
    cmp r13, 64
    jb .Lupdate_tail
.Lupdate_block_loop:
    mov rdi, rbx
    mov rsi, r12
    call sha256_transform
    add r12, 64
    sub r13, 64
    cmp r13, 64
    jae .Lupdate_block_loop

.Lupdate_tail:
    test r13, r13
    jz .Lupdate_done
    lea rdi, [rbx + SHA256_BUFFER]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov qword ptr [rbx + SHA256_BUFLEN], r13

.Lupdate_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

sha256_final:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, qword ptr [rbx + SHA256_BYTES]
    shl r13, 3

    mov rax, qword ptr [rbx + SHA256_BUFLEN]
    lea rdi, [rbx + SHA256_BUFFER]
    mov byte ptr [rdi + rax], 0x80
    inc rax

    cmp rax, 56
    jbe .Lfinal_zero_to_56

    mov rcx, 64
    sub rcx, rax
    lea rdi, [rbx + rax + SHA256_BUFFER]
    xor eax, eax
    rep stosb
    mov rdi, rbx
    lea rsi, [rbx + SHA256_BUFFER]
    call sha256_transform
    xor rax, rax

.Lfinal_zero_to_56:
    mov rcx, 56
    sub rcx, rax
    lea rdi, [rbx + rax + SHA256_BUFFER]
    xor eax, eax
    rep stosb
    mov rax, r13
    bswap rax
    mov qword ptr [rbx + SHA256_BUFFER + 56], rax
    mov rdi, rbx
    lea rsi, [rbx + SHA256_BUFFER]
    call sha256_transform

    xor rcx, rcx
.Lfinal_digest_loop:
    mov eax, dword ptr [rbx + rcx * 4 + SHA256_STATE]
    bswap eax
    mov dword ptr [r12 + rcx * 4], eax
    inc rcx
    cmp rcx, 8
    jne .Lfinal_digest_loop

    pop r13
    pop r12
    pop rbx
    ret

sha256_transform:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 272
    mov qword ptr [rsp + 256], rdi

    xor r14d, r14d
.Lw_load_loop:
    mov r15d, dword ptr [rsi + r14 * 4]
    bswap r15d
    mov dword ptr [rsp + r14 * 4], r15d
    inc r14
    cmp r14, 16
    jne .Lw_load_loop

.Lw_expand_loop:
    mov r15d, dword ptr [rsp + r14 * 4 - 60]
    mov r12d, r15d
    ror r12d, 7
    mov r13d, r15d
    ror r13d, 18
    xor r12d, r13d
    mov r13d, r15d
    shr r13d, 3
    xor r12d, r13d

    mov r15d, dword ptr [rsp + r14 * 4 - 8]
    mov r13d, r15d
    ror r13d, 17
    mov edi, r15d
    ror edi, 19
    xor r13d, edi
    mov edi, r15d
    shr edi, 10
    xor r13d, edi

    add r12d, r13d
    add r12d, dword ptr [rsp + r14 * 4 - 64]
    add r12d, dword ptr [rsp + r14 * 4 - 28]
    mov dword ptr [rsp + r14 * 4], r12d

    inc r14
    cmp r14, 64
    jne .Lw_expand_loop

    mov rdi, qword ptr [rsp + 256]
    mov eax, dword ptr [rdi + SHA256_STATE + 0]
    mov ebx, dword ptr [rdi + SHA256_STATE + 4]
    mov ecx, dword ptr [rdi + SHA256_STATE + 8]
    mov edx, dword ptr [rdi + SHA256_STATE + 12]
    mov r8d, dword ptr [rdi + SHA256_STATE + 16]
    mov r9d, dword ptr [rdi + SHA256_STATE + 20]
    mov r10d, dword ptr [rdi + SHA256_STATE + 24]
    mov r11d, dword ptr [rdi + SHA256_STATE + 28]

    xor r14d, r14d
    lea r15, [rip + sha256_k]
.Lround_loop:
    mov r12d, r8d
    ror r12d, 6
    mov edi, r8d
    ror edi, 11
    xor r12d, edi
    mov edi, r8d
    ror edi, 25
    xor r12d, edi

    mov edi, r9d
    xor edi, r10d
    and edi, r8d
    xor edi, r10d
    add r12d, edi
    add r12d, r11d
    add r12d, dword ptr [r15 + r14 * 4]
    add r12d, dword ptr [rsp + r14 * 4]

    mov r13d, eax
    ror r13d, 2
    mov edi, eax
    ror edi, 13
    xor r13d, edi
    mov edi, eax
    ror edi, 22
    xor r13d, edi

    mov edi, eax
    and edi, ebx
    mov esi, eax
    xor esi, ebx
    and esi, ecx
    xor edi, esi
    add r13d, edi

    mov r11d, r10d
    mov r10d, r9d
    mov r9d, r8d
    mov r8d, edx
    add r8d, r12d
    mov edx, ecx
    mov ecx, ebx
    mov ebx, eax
    mov eax, r12d
    add eax, r13d

    inc r14
    cmp r14, 64
    jne .Lround_loop

    mov rdi, qword ptr [rsp + 256]
    add dword ptr [rdi + SHA256_STATE + 0], eax
    add dword ptr [rdi + SHA256_STATE + 4], ebx
    add dword ptr [rdi + SHA256_STATE + 8], ecx
    add dword ptr [rdi + SHA256_STATE + 12], edx
    add dword ptr [rdi + SHA256_STATE + 16], r8d
    add dword ptr [rdi + SHA256_STATE + 20], r9d
    add dword ptr [rdi + SHA256_STATE + 24], r10d
    add dword ptr [rdi + SHA256_STATE + 28], r11d

    SCRUB_STACK 272
    add rsp, 272
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    SCRUB_VOLATILE
    ret

.section .rodata
cmd_sha256:
    .asciz "sha256"
cmd_selftest:
    .asciz "selftest"
cmd_keygen:
    .asciz "keygen"
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
cmd_seal_keyfile:
    .asciz "seal-keyfile"
cmd_seal_keyfile_v2:
    .asciz "seal-keyfile-v2"
cmd_open:
    .asciz "open"
cmd_open_keyfile:
    .asciz "open-keyfile"
cmd_aead_seal:
    .asciz "aead-seal"
cmd_aead_open:
    .asciz "aead-open"
cmd_help:
    .asciz "-h"
cmd_help_long:
    .asciz "--help"

usage_msg:
    .ascii "usage: wuci-ji <sha256|hmac-sha256|hkdf-sha256|poly1305|chacha20|keygen|seal|seal-v2|open|seal-keyfile|seal-keyfile-v2|open-keyfile|aead-seal|aead-open|selftest> [args]\n"
    .ascii "  sha256                         hash stdin with the assembly SHA-256 core\n"
    .ascii "  hmac-sha256 <key>              authenticate stdin with a 32-byte hex key\n"
    .ascii "  hkdf-sha256 <salt> <info>      derive 32 bytes from stdin; salt/info are 64 hex each\n"
    .ascii "  poly1305 <key>                 authenticate stdin with a 32-byte one-time hex key\n"
    .ascii "  chacha20 <key> <nonce> <ctr>   xor stdin with ChaCha20; key=64 hex, nonce=24 hex, ctr=8 hex\n"
    .ascii "  keygen                         write a random 32-byte key as 64 hex plus newline\n"
    .ascii "  seal <key>                     write framed ChaCha20-Poly1305 envelope with random nonce\n"
    .ascii "  seal-v2 <key> <key-id>         write v2 envelope; key-id is 16 bytes / 32 hex\n"
    .ascii "  open <key>                     verify framed envelope from stdin, then write plaintext\n"
    .ascii "  seal-keyfile <path>            seal with a key file containing 64 hex plus optional newline\n"
    .ascii "  seal-keyfile-v2 <path> <key-id> seal v2 with a key file; key-id is 32 hex\n"
    .ascii "  open-keyfile <path>            open with a key file containing 64 hex plus optional newline\n"
    .ascii "  aead-seal <key> <nonce>        write ChaCha20-Poly1305 ciphertext || raw tag\n"
    .ascii "  aead-open <key> <nonce> <tag>  verify raw ciphertext, then write plaintext; tag=32 hex\n"
    .ascii "  selftest                       run built-in known-answer tests\n"
.set usage_msg_len, . - usage_msg

read_error_msg:
    .ascii "wuci-ji: read failed\n"
.set read_error_msg_len, . - read_error_msg

key_error_msg:
    .ascii "wuci-ji: hmac-sha256 requires exactly 64 hex key characters\n"
.set key_error_msg_len, . - key_error_msg

keyfile_error_msg:
    .ascii "wuci-ji: key file must contain 64 hex characters plus optional newline\n"
.set keyfile_error_msg_len, . - keyfile_error_msg

keyid_arg_error_msg:
    .ascii "wuci-ji: key id must contain exactly 32 hex characters\n"
.set keyid_arg_error_msg_len, . - keyid_arg_error_msg

chacha_arg_error_msg:
    .ascii "wuci-ji: chacha20 requires key=64 hex, nonce=24 hex, counter=8 hex\n"
.set chacha_arg_error_msg_len, . - chacha_arg_error_msg

hkdf_arg_error_msg:
    .ascii "wuci-ji: hkdf-sha256 requires salt=64 hex and info=64 hex\n"
.set hkdf_arg_error_msg_len, . - hkdf_arg_error_msg

poly_arg_error_msg:
    .ascii "wuci-ji: poly1305 requires exactly 64 hex key characters\n"
.set poly_arg_error_msg_len, . - poly_arg_error_msg

aead_arg_error_msg:
    .ascii "wuci-ji: aead requires key=64 hex, nonce=24 hex, and open tag=32 hex\n"
.set aead_arg_error_msg_len, . - aead_arg_error_msg

aead_auth_error_msg:
    .ascii "wuci-ji: aead authentication failed\n"
.set aead_auth_error_msg_len, . - aead_auth_error_msg

aead_size_error_msg:
    .ascii "wuci-ji: aead-open ciphertext exceeds internal verification buffer\n"
.set aead_size_error_msg_len, . - aead_size_error_msg

random_error_msg:
    .ascii "wuci-ji: random nonce generation failed\n"
.set random_error_msg_len, . - random_error_msg

envelope_error_msg:
    .ascii "wuci-ji: envelope authentication failed\n"
.set envelope_error_msg_len, . - envelope_error_msg

selftest_pass_msg:
    .ascii "wuci-ji selftest: PASS\n"
.set selftest_pass_msg_len, . - selftest_pass_msg

selftest_fail_msg:
    .ascii "wuci-ji selftest: FAIL\n"
.set selftest_fail_msg_len, . - selftest_fail_msg

hex_chars:
    .ascii "0123456789abcdef"

envelope_prefix:
    .ascii "WJSEAL"
    .byte 0x01, 0x01

envelope_v2_prefix:
    .ascii "WJSEAL"
    .byte 0x02, 0x01

hkdf_counter_one:
    .byte 0x01

msg_abc:
    .ascii "abc"

msg_hi_there:
    .ascii "Hi There"

msg_poly1305:
    .ascii "Cryptographic Forum Research Group"

hmac_selftest_key:
    .byte 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    .byte 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    .byte 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    .byte 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f

chacha_selftest_nonce:
    .byte 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a
    .byte 0x00, 0x00, 0x00, 0x00

hkdf_selftest_salt:
    .byte 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    .byte 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    .byte 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    .byte 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f

hkdf_selftest_info:
    .byte 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    .byte 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    .byte 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57
    .byte 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f

sha256_empty:
    .byte 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
    .byte 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24
    .byte 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c
    .byte 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55

sha256_abc:
    .byte 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea
    .byte 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23
    .byte 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c
    .byte 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad

hmac_sha256_hi_there:
    .byte 0x27, 0x86, 0x39, 0xec, 0x02, 0x30, 0x9d, 0x3a
    .byte 0xfd, 0xed, 0x1b, 0x27, 0x3f, 0x13, 0x49, 0xba
    .byte 0x63, 0xb9, 0x08, 0x9c, 0x12, 0x47, 0x6d, 0x71
    .byte 0x6b, 0xee, 0x3e, 0xcc, 0x94, 0x67, 0x3e, 0x9e

hkdf_sha256_abc:
    .byte 0x06, 0xf7, 0xe8, 0xc5, 0x5e, 0x1e, 0x8f, 0x5b
    .byte 0xbb, 0x2c, 0x41, 0x48, 0x16, 0xfb, 0x3e, 0xac
    .byte 0x09, 0xc1, 0xf9, 0x6f, 0xa3, 0xe7, 0x29, 0xa4
    .byte 0xe3, 0x02, 0x67, 0x3a, 0xe2, 0x46, 0x49, 0x3b

poly1305_selftest_key:
    .byte 0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33
    .byte 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8
    .byte 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd
    .byte 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b

poly1305_expected:
    .byte 0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6
    .byte 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9

chacha20_block_expected:
    .byte 0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15
    .byte 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4
    .byte 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03
    .byte 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e
    .byte 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09
    .byte 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2
    .byte 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9
    .byte 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e

aead_abc_ciphertext:
    .byte 0x71, 0x93, 0x84

aead_abc_tag:
    .byte 0x03, 0xae, 0x1f, 0xc6, 0x9e, 0x28, 0x60, 0x11
    .byte 0x55, 0x11, 0xc1, 0x99, 0x31, 0x9b, 0x26, 0x38

.align 4
sha256_k:
    .long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

.section .bss
.align 16
bss_sensitive_start:
sha_ctx:
    .skip SHA256_CTX_SIZE
.align 16
io_buf:
    .skip 4096
.align 16
digest_buf:
    .skip 32
.align 16
hmac_key:
    .skip 32
.align 16
hmac_ipad:
    .skip 64
.align 16
hmac_opad:
    .skip 64
.align 16
hmac_inner:
    .skip 32
.align 16
hkdf_salt:
    .skip 32
.align 16
hkdf_info:
    .skip 32
.align 16
hkdf_prk:
    .skip 32
.align 16
poly_key:
    .skip 32
.align 16
poly_tag:
    .skip 16
.align 16
poly_buffer:
    .skip 16
.align 8
poly_leftover:
    .skip 8
.align 8
poly_r0:
    .skip 8
poly_r1:
    .skip 8
poly_r2:
    .skip 8
poly_r3:
    .skip 8
poly_r4:
    .skip 8
poly_s1:
    .skip 8
poly_s2:
    .skip 8
poly_s3:
    .skip 8
poly_s4:
    .skip 8
poly_h0:
    .skip 8
poly_h1:
    .skip 8
poly_h2:
    .skip 8
poly_h3:
    .skip 8
poly_h4:
    .skip 8
poly_pad0:
    .skip 4
poly_pad1:
    .skip 4
poly_pad2:
    .skip 4
poly_pad3:
    .skip 4
.align 16
aead_expected_tag:
    .skip 16
.align 16
aead_zero_pad:
    .skip 16
.align 16
aead_len_block:
    .skip 16
.align 8
aead_text_len:
    .skip 8
.align 8
aead_aad_len:
    .skip 8
.align 16
chacha_key:
    .skip 32
.align 16
chacha_nonce:
    .skip 12
.align 4
chacha_counter:
    .skip 4
.align 16
chacha_block:
    .skip 64
.align 16
envelope_key_id:
    .skip ENVELOPE_KEY_ID_LEN
.align 16
envelope_header_buf:
    .skip ENVELOPE_V2_HEADER_LEN
.align 16
aead_open_buf:
    .skip AEAD_OPEN_MAX
.align 16
hex_buf:
    .skip 128
.align 16
bss_sensitive_end:
.set bss_sensitive_len, bss_sensitive_end - bss_sensitive_start

.section .note.GNU-stack,"",@progbits
