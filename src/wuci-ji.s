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
.equ O_WRONLY, 1
.equ O_CREAT, 64
.equ O_EXCL, 128
.equ FILE_CREATE_FLAGS, O_WRONLY + O_CREAT + O_EXCL
.equ FILE_CREATE_MODE, 384

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
.equ ENVELOPE_X25519_PUBLIC_LEN, 32
.equ ENVELOPE_V3_HEADER_LEN, ENVELOPE_PREFIX_LEN + ENVELOPE_X25519_PUBLIC_LEN + ENVELOPE_KEY_ID_LEN + ENVELOPE_NONCE_LEN
.equ ENVELOPE_V3_MIN_LEN, ENVELOPE_V3_HEADER_LEN + ENVELOPE_TAG_LEN
.equ KEYFILE_READ_MAX, 66

.section .text
.global _start
.extern x25519_basepoint
.extern x25519_scalar_mult

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
    lea rsi, [rip + cmd_frost_p256_h1]
    call streq
    cmp eax, 1
    je run_frost_p256_h1

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_p256_h2]
    call streq
    cmp eax, 1
    je run_frost_p256_h2

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_p256_h3]
    call streq
    cmp eax, 1
    je run_frost_p256_h3

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_p256_h4]
    call streq
    cmp eax, 1
    je run_frost_p256_h4

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_p256_h5]
    call streq
    cmp eax, 1
    je run_frost_p256_h5

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_h1]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_h1

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_h2]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_h2

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_h3]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_h3

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_h4]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_h4

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_h5]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_h5

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_scalar_add]
    call streq
    cmp eax, 1
    je run_secp256k1_scalar_add

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_scalar_sub]
    call streq
    cmp eax, 1
    je run_secp256k1_scalar_sub

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_scalar_mul]
    call streq
    cmp eax, 1
    je run_secp256k1_scalar_mul

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_scalar_inv]
    call streq
    cmp eax, 1
    je run_secp256k1_scalar_inv

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_lagrange]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_lagrange

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_nonce_generate]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_nonce_generate

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_commit]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_commit

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_commitment_hash]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_commitment_hash

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_binding_factor]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_binding_factor

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_frost_secp256k1_group_commitment]
    call streq
    cmp eax, 1
    je run_frost_secp256k1_group_commitment

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_field_add]
    call streq
    cmp eax, 1
    je run_secp256k1_field_add

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_field_sub]
    call streq
    cmp eax, 1
    je run_secp256k1_field_sub

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_field_mul]
    call streq
    cmp eax, 1
    je run_secp256k1_field_mul

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_field_square]
    call streq
    cmp eax, 1
    je run_secp256k1_field_square

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_field_inv]
    call streq
    cmp eax, 1
    je run_secp256k1_field_inv

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_point_validate]
    call streq
    cmp eax, 1
    je run_secp256k1_point_validate

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_point_double]
    call streq
    cmp eax, 1
    je run_secp256k1_point_double

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_point_add]
    call streq
    cmp eax, 1
    je run_secp256k1_point_add

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_basepoint_mul]
    call streq
    cmp eax, 1
    je run_secp256k1_basepoint_mul

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_jacobian_double]
    call streq
    cmp eax, 1
    je run_secp256k1_jacobian_double

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_jacobian_mixed_add]
    call streq
    cmp eax, 1
    je run_secp256k1_jacobian_mixed_add

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_projective_basepoint_mul]
    call streq
    cmp eax, 1
    je run_secp256k1_projective_basepoint_mul

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_point_encode_compressed]
    call streq
    cmp eax, 1
    je run_secp256k1_point_encode_compressed

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_point_encode_uncompressed]
    call streq
    cmp eax, 1
    je run_secp256k1_point_encode_uncompressed

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_secp256k1_point_decode]
    call streq
    cmp eax, 1
    je run_secp256k1_point_decode

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
    lea rsi, [rip + cmd_keypair]
    call streq
    cmp eax, 1
    je run_keypair

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
    lea rsi, [rip + cmd_seal_file]
    call streq
    cmp eax, 1
    je run_seal_file

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_seal_file_v2]
    call streq
    cmp eax, 1
    je run_seal_file_v2

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_seal_file_keyfile]
    call streq
    cmp eax, 1
    je run_seal_file_keyfile

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_seal_file_keyfile_v2]
    call streq
    cmp eax, 1
    je run_seal_file_keyfile_v2

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_seal_to]
    call streq
    cmp eax, 1
    je run_seal_to

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
    lea rsi, [rip + cmd_open_file]
    call streq
    cmp eax, 1
    je run_open_file

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_open_file_keyfile]
    call streq
    cmp eax, 1
    je run_open_file_keyfile

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_open_to]
    call streq
    cmp eax, 1
    je run_open_to

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_open_keyfile]
    call streq
    cmp eax, 1
    je run_open_keyfile

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_inspect]
    call streq
    cmp eax, 1
    je run_inspect

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_inspect_file]
    call streq
    cmp eax, 1
    je run_inspect_file

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_manifest]
    call streq
    cmp eax, 1
    je run_manifest

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_manifest_file]
    call streq
    cmp eax, 1
    je run_manifest_file

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_armor_file]
    call streq
    cmp eax, 1
    je run_armor_file

    mov rdi, qword ptr [rsp + 16]
    lea rsi, [rip + cmd_dearmor_file]
    call streq
    cmp eax, 1
    je run_dearmor_file

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
    cmp qword ptr [rsp], 2
    jne usage_exit

    mov rdi, STDOUT
    lea rsi, [rip + usage_msg]
    mov edx, OFFSET FLAT:usage_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

run_sha256:
    cmp qword ptr [rsp], 2
    jne usage_exit

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

run_frost_p256_h4:
    cmp qword ptr [rsp], 2
    jne usage_exit
    lea rdi, [rip + frost_p256_h4_prefix]
    mov esi, OFFSET FLAT:frost_p256_h4_prefix_len
    jmp frost_hash_stdin

run_frost_p256_h1:
    cmp qword ptr [rsp], 2
    jne usage_exit
    lea rdi, [rip + frost_p256_h1_dst_prime]
    mov esi, OFFSET FLAT:frost_p256_h1_dst_prime_len
    lea rdx, [rip + frost_p256_order_le]
    jmp frost_hash_to_scalar_stdin

run_frost_p256_h2:
    cmp qword ptr [rsp], 2
    jne usage_exit
    lea rdi, [rip + frost_p256_h2_dst_prime]
    mov esi, OFFSET FLAT:frost_p256_h2_dst_prime_len
    lea rdx, [rip + frost_p256_order_le]
    jmp frost_hash_to_scalar_stdin

run_frost_p256_h3:
    cmp qword ptr [rsp], 2
    jne usage_exit
    lea rdi, [rip + frost_p256_h3_dst_prime]
    mov esi, OFFSET FLAT:frost_p256_h3_dst_prime_len
    lea rdx, [rip + frost_p256_order_le]
    jmp frost_hash_to_scalar_stdin

run_frost_p256_h5:
    cmp qword ptr [rsp], 2
    jne usage_exit
    lea rdi, [rip + frost_p256_h5_prefix]
    mov esi, OFFSET FLAT:frost_p256_h5_prefix_len
    jmp frost_hash_stdin

run_frost_secp256k1_h1:
    cmp qword ptr [rsp], 2
    jne usage_exit
    lea rdi, [rip + frost_secp256k1_h1_dst_prime]
    mov esi, OFFSET FLAT:frost_secp256k1_h1_dst_prime_len
    lea rdx, [rip + frost_secp256k1_order_le]
    jmp frost_hash_to_scalar_stdin

run_frost_secp256k1_h2:
    cmp qword ptr [rsp], 2
    jne usage_exit
    lea rdi, [rip + frost_secp256k1_h2_dst_prime]
    mov esi, OFFSET FLAT:frost_secp256k1_h2_dst_prime_len
    lea rdx, [rip + frost_secp256k1_order_le]
    jmp frost_hash_to_scalar_stdin

run_frost_secp256k1_h3:
    cmp qword ptr [rsp], 2
    jne usage_exit
    lea rdi, [rip + frost_secp256k1_h3_dst_prime]
    mov esi, OFFSET FLAT:frost_secp256k1_h3_dst_prime_len
    lea rdx, [rip + frost_secp256k1_order_le]
    jmp frost_hash_to_scalar_stdin

run_frost_secp256k1_h4:
    cmp qword ptr [rsp], 2
    jne usage_exit
    lea rdi, [rip + frost_secp256k1_h4_prefix]
    mov esi, OFFSET FLAT:frost_secp256k1_h4_prefix_len
    jmp frost_hash_stdin

run_frost_secp256k1_h5:
    cmp qword ptr [rsp], 2
    jne usage_exit
    lea rdi, [rip + frost_secp256k1_h5_prefix]
    mov esi, OFFSET FLAT:frost_secp256k1_h5_prefix_len
    jmp frost_hash_stdin

run_frost_secp256k1_nonce_generate:
    cmp qword ptr [rsp], 3
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error

    lea rdi, [rip + frost_nonce_input]
    mov esi, 32
    call fill_random
    cmp eax, 1
    jne random_error

    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + frost_nonce_input + 32]
    call store_le4_to_be32

    lea rdi, [rip + frost_secp256k1_h3_dst_prime]
    mov esi, OFFSET FLAT:frost_secp256k1_h3_dst_prime_len
    lea rdx, [rip + frost_secp256k1_order_le]
    lea rcx, [rip + frost_nonce_input]
    mov r8d, 64
    lea r9, [rip + frost_nonce_scalar_be]
    call frost_hash_to_scalar_mem

    lea rdi, [rip + frost_nonce_scalar_be]
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

run_frost_secp256k1_commit:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je scalar_arg_error

    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + secp256k1_scalar_b]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_b]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je scalar_arg_error

    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + frost_hiding_commitment]
    call frost_secp256k1_commit_scalar
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_scalar_b]
    lea rsi, [rip + frost_binding_commitment]
    call frost_secp256k1_commit_scalar
    cmp eax, 1
    jne point_arg_error

    mov rdi, STDOUT
    lea rsi, [rip + frost_hiding_commitment_label]
    mov edx, OFFSET FLAT:frost_hiding_commitment_label_len
    call write_all
    lea rdi, [rip + frost_hiding_commitment]
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call hex_encode
    mov byte ptr [rip + hex_buf + 66], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 67
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + frost_binding_commitment_label]
    mov edx, OFFSET FLAT:frost_binding_commitment_label_len
    call write_all
    lea rdi, [rip + frost_binding_commitment]
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call hex_encode
    mov byte ptr [rip + hex_buf + 66], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 67
    call write_all

    xor edi, edi
    jmp exit_process

run_frost_secp256k1_commitment_hash:
    cmp qword ptr [rsp], 5
    jb usage_exit
    mov rax, qword ptr [rsp]
    sub rax, 2
    xor edx, edx
    mov ecx, 3
    div rcx
    test rdx, rdx
    jne usage_exit
    cmp rax, 40
    ja usage_exit

    mov r10, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r15, r10
    mov r14, qword ptr [r15]
    mov r12, 2
    xor ebx, ebx
    xor r13d, r13d

.Lrun_frost_commitment_hash_loop:
    cmp r12, r14
    jae .Lrun_frost_commitment_hash_done
    mov rdi, qword ptr [r15 + r12 * 8 + 8]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne frost_commitment_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je frost_commitment_arg_error
    test r13d, r13d
    jz .Lrun_frost_commitment_hash_store_id
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + secp256k1_scalar_lagrange_id]
    call secp256k1_scalar_gt_limbs
    cmp eax, 1
    jne frost_commitment_arg_error

.Lrun_frost_commitment_hash_store_id:
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + secp256k1_scalar_lagrange_id]
    call copy_field4
    mov r13d, 1

    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + frost_commitment_list_buf]
    add rsi, rbx
    call store_le4_to_be32

    mov rax, r12
    inc rax
    mov rdi, qword ptr [r15 + rax * 8 + 8]
    lea rsi, [rip + frost_commitment_list_buf]
    add rsi, rbx
    add rsi, 32
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne frost_commitment_arg_error

    mov rax, r12
    add rax, 2
    mov rdi, qword ptr [r15 + rax * 8 + 8]
    lea rsi, [rip + frost_commitment_list_buf]
    add rsi, rbx
    add rsi, 65
    lea rdx, [rip + secp256k1_point_x2]
    lea rcx, [rip + secp256k1_point_y2]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne frost_commitment_arg_error

    add rbx, 98
    add r12, 3
    jmp .Lrun_frost_commitment_hash_loop

.Lrun_frost_commitment_hash_done:
    lea rdi, [rip + frost_secp256k1_h5_prefix]
    mov esi, OFFSET FLAT:frost_secp256k1_h5_prefix_len
    lea rdx, [rip + frost_commitment_list_buf]
    mov rcx, rbx
    lea r8, [rip + digest_buf]
    call frost_hash_mem
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

run_frost_secp256k1_binding_factor:
    cmp qword ptr [rsp], 6
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + frost_group_public_key]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne frost_commitment_arg_error

    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + frost_msg_hash]
    call hex32_decode
    cmp eax, 1
    jne frost_commitment_arg_error

    mov rdi, qword ptr [rsp + 40]
    lea rsi, [rip + frost_commitment_hash]
    call hex32_decode
    cmp eax, 1
    jne frost_commitment_arg_error

    mov rdi, qword ptr [rsp + 48]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne frost_commitment_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je frost_commitment_arg_error

    lea rdi, [rip + frost_binding_input]
    lea rsi, [rip + frost_group_public_key]
    mov ecx, 33
    rep movsb
    lea rdi, [rip + frost_binding_input + 33]
    lea rsi, [rip + frost_msg_hash]
    mov ecx, 32
    rep movsb
    lea rdi, [rip + frost_binding_input + 65]
    lea rsi, [rip + frost_commitment_hash]
    mov ecx, 32
    rep movsb
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + frost_binding_input + 97]
    call store_le4_to_be32

    lea rdi, [rip + frost_secp256k1_h1_dst_prime]
    mov esi, OFFSET FLAT:frost_secp256k1_h1_dst_prime_len
    lea rdx, [rip + frost_secp256k1_order_le]
    lea rcx, [rip + frost_binding_input]
    mov r8d, 129
    lea r9, [rip + frost_nonce_scalar_be]
    call frost_hash_to_scalar_mem
    lea rdi, [rip + frost_nonce_scalar_be]
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

run_frost_secp256k1_group_commitment:
    cmp qword ptr [rsp], 6
    jb usage_exit
    mov rax, qword ptr [rsp]
    sub rax, 2
    xor edx, edx
    mov ecx, 4
    div rcx
    test rdx, rdx
    jne usage_exit
    cmp rax, 40
    ja usage_exit

    mov r10, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r15, r10
    mov r14, qword ptr [r15]
    mov r12, 2
    xor r13d, r13d
    mov qword ptr [rip + frost_group_acc_infinity], 1

.Lrun_frost_group_commitment_loop:
    cmp r12, r14
    jae .Lrun_frost_group_commitment_done
    mov rdi, qword ptr [r15 + r12 * 8 + 8]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne frost_commitment_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je frost_commitment_arg_error
    test r13d, r13d
    jz .Lrun_frost_group_commitment_store_id
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + secp256k1_scalar_lagrange_id]
    call secp256k1_scalar_gt_limbs
    cmp eax, 1
    jne frost_commitment_arg_error

.Lrun_frost_group_commitment_store_id:
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + secp256k1_scalar_lagrange_id]
    call copy_field4
    mov r13d, 1

    mov rax, r12
    inc rax
    mov rdi, qword ptr [r15 + rax * 8 + 8]
    lea rsi, [rip + frost_hiding_commitment]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne frost_commitment_arg_error

    mov rax, r12
    add rax, 2
    mov rdi, qword ptr [r15 + rax * 8 + 8]
    lea rsi, [rip + frost_binding_commitment]
    lea rdx, [rip + secp256k1_point_x2]
    lea rcx, [rip + secp256k1_point_y2]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne frost_commitment_arg_error

    mov rax, r12
    add rax, 3
    mov rdi, qword ptr [r15 + rax * 8 + 8]
    lea rsi, [rip + secp256k1_scalar_b]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne frost_commitment_arg_error
    lea rdi, [rip + secp256k1_scalar_b]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je .Lrun_frost_group_commitment_hiding_only

    lea rdi, [rip + secp256k1_scalar_b]
    lea rsi, [rip + secp256k1_point_x2]
    lea rdx, [rip + secp256k1_point_y2]
    lea rcx, [rip + frost_group_binding_x]
    lea r8, [rip + frost_group_binding_y]
    call secp256k1_point_mul_limbs
    cmp eax, 1
    jne frost_commitment_arg_error
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    lea rdx, [rip + frost_group_binding_x]
    lea rcx, [rip + frost_group_binding_y]
    lea r8, [rip + secp256k1_point_rx]
    lea r9, [rip + secp256k1_point_ry]
    call secp256k1_point_add_limbs
    cmp eax, 1
    jne .Lrun_frost_group_commitment_contribution_infinity
    lea rdi, [rip + secp256k1_point_rx]
    lea rsi, [rip + frost_group_contrib_x]
    call copy_field4
    lea rdi, [rip + secp256k1_point_ry]
    lea rsi, [rip + frost_group_contrib_y]
    call copy_field4
    jmp .Lrun_frost_group_commitment_add_contribution

.Lrun_frost_group_commitment_hiding_only:
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + frost_group_contrib_x]
    call copy_field4
    lea rdi, [rip + secp256k1_point_y1]
    lea rsi, [rip + frost_group_contrib_y]
    call copy_field4

.Lrun_frost_group_commitment_add_contribution:
    cmp qword ptr [rip + frost_group_acc_infinity], 1
    jne .Lrun_frost_group_commitment_add_to_acc
    lea rdi, [rip + frost_group_contrib_x]
    lea rsi, [rip + frost_group_acc_x]
    call copy_field4
    lea rdi, [rip + frost_group_contrib_y]
    lea rsi, [rip + frost_group_acc_y]
    call copy_field4
    mov qword ptr [rip + frost_group_acc_infinity], 0
    jmp .Lrun_frost_group_commitment_next

.Lrun_frost_group_commitment_add_to_acc:
    lea rdi, [rip + frost_group_acc_x]
    lea rsi, [rip + frost_group_acc_y]
    lea rdx, [rip + frost_group_contrib_x]
    lea rcx, [rip + frost_group_contrib_y]
    lea r8, [rip + secp256k1_point_rx]
    lea r9, [rip + secp256k1_point_ry]
    call secp256k1_point_add_limbs
    cmp eax, 1
    jne .Lrun_frost_group_commitment_acc_infinity
    lea rdi, [rip + secp256k1_point_rx]
    lea rsi, [rip + frost_group_acc_x]
    call copy_field4
    lea rdi, [rip + secp256k1_point_ry]
    lea rsi, [rip + frost_group_acc_y]
    call copy_field4
    mov qword ptr [rip + frost_group_acc_infinity], 0
    jmp .Lrun_frost_group_commitment_next

.Lrun_frost_group_commitment_acc_infinity:
    mov qword ptr [rip + frost_group_acc_infinity], 1
    jmp .Lrun_frost_group_commitment_next

.Lrun_frost_group_commitment_contribution_infinity:
    jmp .Lrun_frost_group_commitment_next

.Lrun_frost_group_commitment_next:
    add r12, 4
    jmp .Lrun_frost_group_commitment_loop

.Lrun_frost_group_commitment_done:
    cmp qword ptr [rip + frost_group_acc_infinity], 1
    je frost_commitment_arg_error
    lea rdi, [rip + frost_group_acc_x]
    lea rsi, [rip + frost_group_acc_y]
    lea rdx, [rip + frost_group_commitment]
    call encode_secp256k1_compressed_point
    mov rdi, STDOUT
    lea rsi, [rip + frost_group_commitment_label]
    mov edx, OFFSET FLAT:frost_group_commitment_label_len
    call write_all
    lea rdi, [rip + frost_group_commitment]
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call hex_encode
    mov byte ptr [rip + hex_buf + 66], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 67
    call write_all
    xor edi, edi
    jmp exit_process

run_secp256k1_scalar_add:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + secp256k1_scalar_b]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + secp256k1_scalar_b]
    lea rdx, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_add_limbs
    jmp write_secp256k1_scalar_out

run_secp256k1_scalar_sub:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + secp256k1_scalar_b]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + secp256k1_scalar_b]
    lea rdx, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_sub_limbs
    jmp write_secp256k1_scalar_out

run_secp256k1_scalar_mul:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + secp256k1_scalar_b]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + secp256k1_scalar_b]
    lea rdx, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_mul_limbs
    jmp write_secp256k1_scalar_out

run_secp256k1_scalar_inv:
    cmp qword ptr [rsp], 3
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_inverse_limbs
    jmp write_secp256k1_scalar_out

run_frost_secp256k1_lagrange:
    cmp qword ptr [rsp], 4
    jb usage_exit
    mov r10, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r15, r10
    mov r14, qword ptr [r15]

    mov rdi, qword ptr [r15 + 24]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je frost_lagrange_arg_error
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + secp256k1_scalar_lagrange_id]
    call copy_field4

    mov qword ptr [rip + secp256k1_scalar_lagrange_num], 1
    mov qword ptr [rip + secp256k1_scalar_lagrange_num + 8], 0
    mov qword ptr [rip + secp256k1_scalar_lagrange_num + 16], 0
    mov qword ptr [rip + secp256k1_scalar_lagrange_num + 24], 0
    mov qword ptr [rip + secp256k1_scalar_lagrange_den], 1
    mov qword ptr [rip + secp256k1_scalar_lagrange_den + 8], 0
    mov qword ptr [rip + secp256k1_scalar_lagrange_den + 16], 0
    mov qword ptr [rip + secp256k1_scalar_lagrange_den + 24], 0

    xor ebx, ebx
    mov r12, 3
.Lrun_frost_lagrange_outer:
    cmp r12, r14
    jae .Lrun_frost_lagrange_after_loop
    mov rdi, qword ptr [r15 + r12 * 8 + 8]
    lea rsi, [rip + secp256k1_scalar_b]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_b]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je frost_lagrange_arg_error

    mov r13, 3
.Lrun_frost_lagrange_duplicate_loop:
    cmp r13, r12
    jae .Lrun_frost_lagrange_duplicate_done
    mov rdi, qword ptr [r15 + r13 * 8 + 8]
    lea rsi, [rip + secp256k1_scalar_tmp]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_tmp]
    lea rsi, [rip + secp256k1_scalar_b]
    call secp256k1_scalar_equal_limbs
    cmp eax, 1
    je frost_lagrange_arg_error
    inc r13
    jmp .Lrun_frost_lagrange_duplicate_loop

.Lrun_frost_lagrange_duplicate_done:
    lea rdi, [rip + secp256k1_scalar_b]
    lea rsi, [rip + secp256k1_scalar_lagrange_id]
    call secp256k1_scalar_equal_limbs
    cmp eax, 1
    jne .Lrun_frost_lagrange_accumulate
    mov ebx, 1
    jmp .Lrun_frost_lagrange_next

.Lrun_frost_lagrange_accumulate:
    lea rdi, [rip + secp256k1_scalar_lagrange_num]
    lea rsi, [rip + secp256k1_scalar_b]
    lea rdx, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_mul_limbs
    lea rdi, [rip + secp256k1_scalar_out]
    lea rsi, [rip + secp256k1_scalar_lagrange_num]
    call copy_field4

    lea rdi, [rip + secp256k1_scalar_b]
    lea rsi, [rip + secp256k1_scalar_lagrange_id]
    lea rdx, [rip + secp256k1_scalar_inv_tmp]
    call secp256k1_scalar_sub_limbs
    lea rdi, [rip + secp256k1_scalar_lagrange_den]
    lea rsi, [rip + secp256k1_scalar_inv_tmp]
    lea rdx, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_mul_limbs
    lea rdi, [rip + secp256k1_scalar_out]
    lea rsi, [rip + secp256k1_scalar_lagrange_den]
    call copy_field4

.Lrun_frost_lagrange_next:
    inc r12
    jmp .Lrun_frost_lagrange_outer

.Lrun_frost_lagrange_after_loop:
    cmp ebx, 1
    jne frost_lagrange_arg_error
    lea rdi, [rip + secp256k1_scalar_lagrange_den]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je frost_lagrange_arg_error
    lea rdi, [rip + secp256k1_scalar_lagrange_den]
    lea rsi, [rip + secp256k1_scalar_inv_tmp]
    call secp256k1_scalar_inverse_limbs
    lea rdi, [rip + secp256k1_scalar_lagrange_num]
    lea rsi, [rip + secp256k1_scalar_inv_tmp]
    lea rdx, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_mul_limbs
    jmp write_secp256k1_scalar_out

run_secp256k1_field_add:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_field_a_bytes]
    call hex32_decode
    cmp eax, 1
    jne field_arg_error
    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + secp256k1_field_b_bytes]
    call hex32_decode
    cmp eax, 1
    jne field_arg_error
    lea rdi, [rip + secp256k1_field_a_bytes]
    lea rsi, [rip + secp256k1_field_a]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_field_b_bytes]
    lea rsi, [rip + secp256k1_field_b]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_field_a]
    call secp256k1_field_normalize_limbs
    lea rdi, [rip + secp256k1_field_b]
    call secp256k1_field_normalize_limbs
    lea rdi, [rip + secp256k1_field_a]
    lea rsi, [rip + secp256k1_field_b]
    lea rdx, [rip + secp256k1_field_out]
    call secp256k1_field_add_limbs
    jmp write_secp256k1_field_out

run_secp256k1_field_sub:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_field_a_bytes]
    call hex32_decode
    cmp eax, 1
    jne field_arg_error
    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + secp256k1_field_b_bytes]
    call hex32_decode
    cmp eax, 1
    jne field_arg_error
    lea rdi, [rip + secp256k1_field_a_bytes]
    lea rsi, [rip + secp256k1_field_a]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_field_b_bytes]
    lea rsi, [rip + secp256k1_field_b]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_field_a]
    call secp256k1_field_normalize_limbs
    lea rdi, [rip + secp256k1_field_b]
    call secp256k1_field_normalize_limbs
    lea rdi, [rip + secp256k1_field_a]
    lea rsi, [rip + secp256k1_field_b]
    lea rdx, [rip + secp256k1_field_out]
    call secp256k1_field_sub_limbs
    jmp write_secp256k1_field_out

run_secp256k1_field_mul:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_field_a_bytes]
    call hex32_decode
    cmp eax, 1
    jne field_arg_error
    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + secp256k1_field_b_bytes]
    call hex32_decode
    cmp eax, 1
    jne field_arg_error
    lea rdi, [rip + secp256k1_field_a_bytes]
    lea rsi, [rip + secp256k1_field_a]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_field_b_bytes]
    lea rsi, [rip + secp256k1_field_b]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_field_a]
    call secp256k1_field_normalize_limbs
    lea rdi, [rip + secp256k1_field_b]
    call secp256k1_field_normalize_limbs
    lea rdi, [rip + secp256k1_field_a]
    lea rsi, [rip + secp256k1_field_b]
    lea rdx, [rip + secp256k1_field_out]
    call secp256k1_field_mul_limbs
    jmp write_secp256k1_field_out

run_secp256k1_field_square:
    cmp qword ptr [rsp], 3
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_field_a_bytes]
    call hex32_decode
    cmp eax, 1
    jne field_arg_error
    lea rdi, [rip + secp256k1_field_a_bytes]
    lea rsi, [rip + secp256k1_field_a]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_field_a]
    call secp256k1_field_normalize_limbs
    lea rdi, [rip + secp256k1_field_a]
    lea rsi, [rip + secp256k1_field_a]
    lea rdx, [rip + secp256k1_field_out]
    call secp256k1_field_mul_limbs
    jmp write_secp256k1_field_out

run_secp256k1_field_inv:
    cmp qword ptr [rsp], 3
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_field_a_bytes]
    call hex32_decode
    cmp eax, 1
    jne field_arg_error
    lea rdi, [rip + secp256k1_field_a_bytes]
    lea rsi, [rip + secp256k1_field_a]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_field_a]
    call secp256k1_field_normalize_limbs
    lea rdi, [rip + secp256k1_field_a]
    lea rsi, [rip + secp256k1_field_out]
    call secp256k1_field_inverse_limbs
    jmp write_secp256k1_field_out

run_secp256k1_point_validate:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    mov rsi, qword ptr [rsp + 32]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_point_xy
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne write_secp256k1_point_invalid
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    call secp256k1_point_validate_limbs
    cmp eax, 1
    jne write_secp256k1_point_invalid
    jmp write_secp256k1_point_valid

run_secp256k1_point_double:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    mov rsi, qword ptr [rsp + 32]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_point_xy
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    call secp256k1_point_validate_limbs
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    lea rdx, [rip + secp256k1_point_rx]
    lea rcx, [rip + secp256k1_point_ry]
    call secp256k1_point_double_limbs
    cmp eax, 1
    jne write_secp256k1_point_infinity
    jmp write_secp256k1_point_out

run_secp256k1_point_add:
    cmp qword ptr [rsp], 6
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    mov rsi, qword ptr [rsp + 32]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_point_xy
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error
    mov rdi, qword ptr [rsp + 40]
    mov rsi, qword ptr [rsp + 48]
    lea rdx, [rip + secp256k1_point_x2]
    lea rcx, [rip + secp256k1_point_y2]
    call load_secp256k1_point_xy
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    call secp256k1_point_validate_limbs
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_point_x2]
    lea rsi, [rip + secp256k1_point_y2]
    call secp256k1_point_validate_limbs
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    lea rdx, [rip + secp256k1_point_x2]
    lea rcx, [rip + secp256k1_point_y2]
    lea r8, [rip + secp256k1_point_rx]
    lea r9, [rip + secp256k1_point_ry]
    call secp256k1_point_add_limbs
    cmp eax, 1
    jne write_secp256k1_point_infinity
    jmp write_secp256k1_point_out

run_secp256k1_basepoint_mul:
    cmp qword ptr [rsp], 3
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_scalar_bytes]
    call hex32_decode
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_bytes]
    lea rsi, [rip + secp256k1_scalar]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_scalar]
    lea rsi, [rip + secp256k1_basepoint_x]
    lea rdx, [rip + secp256k1_basepoint_y]
    lea rcx, [rip + secp256k1_point_rx]
    lea r8, [rip + secp256k1_point_ry]
    call secp256k1_point_mul_limbs
    cmp eax, 1
    jne write_secp256k1_point_infinity
    jmp write_secp256k1_point_out

run_secp256k1_jacobian_double:
    cmp qword ptr [rsp], 5
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_jacobian_x]
    call load_secp256k1_field_arg
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error
    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + secp256k1_jacobian_y]
    call load_secp256k1_field_arg
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error
    mov rdi, qword ptr [rsp + 40]
    lea rsi, [rip + secp256k1_jacobian_z]
    call load_secp256k1_field_arg
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error

    lea rdi, [rip + secp256k1_jacobian_z]
    call secp256k1_field_is_zero_limbs
    cmp eax, 1
    je write_secp256k1_jacobian_infinity
    lea rdi, [rip + secp256k1_jacobian_x]
    lea rsi, [rip + secp256k1_jacobian_y]
    lea rdx, [rip + secp256k1_jacobian_z]
    lea rcx, [rip + secp256k1_point_x1]
    lea r8, [rip + secp256k1_point_y1]
    call secp256k1_jacobian_to_affine_limbs
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    call secp256k1_point_validate_limbs
    cmp eax, 1
    jne point_arg_error

    lea rdi, [rip + secp256k1_jacobian_x]
    lea rsi, [rip + secp256k1_jacobian_y]
    lea rdx, [rip + secp256k1_jacobian_z]
    call secp256k1_jacobian_double_limbs
    cmp eax, 1
    jne write_secp256k1_jacobian_infinity
    jmp write_secp256k1_jacobian_out

run_secp256k1_jacobian_mixed_add:
    cmp qword ptr [rsp], 7
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_jacobian_x]
    call load_secp256k1_field_arg
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error
    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + secp256k1_jacobian_y]
    call load_secp256k1_field_arg
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error
    mov rdi, qword ptr [rsp + 40]
    lea rsi, [rip + secp256k1_jacobian_z]
    call load_secp256k1_field_arg
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error

    mov rdi, qword ptr [rsp + 48]
    mov rsi, qword ptr [rsp + 56]
    lea rdx, [rip + secp256k1_point_x2]
    lea rcx, [rip + secp256k1_point_y2]
    call load_secp256k1_point_xy
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_point_x2]
    lea rsi, [rip + secp256k1_point_y2]
    call secp256k1_point_validate_limbs
    cmp eax, 1
    jne point_arg_error

    lea rdi, [rip + secp256k1_jacobian_z]
    call secp256k1_field_is_zero_limbs
    cmp eax, 1
    je .Lrun_jacobian_mixed_add_input_infinity
    lea rdi, [rip + secp256k1_jacobian_x]
    lea rsi, [rip + secp256k1_jacobian_y]
    lea rdx, [rip + secp256k1_jacobian_z]
    lea rcx, [rip + secp256k1_point_x1]
    lea r8, [rip + secp256k1_point_y1]
    call secp256k1_jacobian_to_affine_limbs
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    call secp256k1_point_validate_limbs
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_jacobian_x]
    lea rsi, [rip + secp256k1_jacobian_y]
    lea rdx, [rip + secp256k1_jacobian_z]
    lea rcx, [rip + secp256k1_point_x2]
    lea r8, [rip + secp256k1_point_y2]
    call secp256k1_jacobian_mixed_add_limbs
    cmp eax, 1
    jne write_secp256k1_jacobian_infinity
    jmp write_secp256k1_jacobian_out

.Lrun_jacobian_mixed_add_input_infinity:
    lea rdi, [rip + secp256k1_point_x2]
    lea rsi, [rip + secp256k1_jacobian_rx]
    call copy_field4
    lea rdi, [rip + secp256k1_point_y2]
    lea rsi, [rip + secp256k1_jacobian_ry]
    call copy_field4
    mov qword ptr [rip + secp256k1_jacobian_rz], 1
    mov qword ptr [rip + secp256k1_jacobian_rz + 8], 0
    mov qword ptr [rip + secp256k1_jacobian_rz + 16], 0
    mov qword ptr [rip + secp256k1_jacobian_rz + 24], 0
    jmp write_secp256k1_jacobian_out

run_secp256k1_projective_basepoint_mul:
    cmp qword ptr [rsp], 3
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + secp256k1_scalar_bytes]
    call hex32_decode
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_bytes]
    lea rsi, [rip + secp256k1_scalar]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_scalar]
    call secp256k1_projective_basepoint_mul_limbs
    cmp eax, 1
    jne write_secp256k1_point_infinity
    lea rdi, [rip + secp256k1_jacobian_rx]
    lea rsi, [rip + secp256k1_jacobian_ry]
    lea rdx, [rip + secp256k1_jacobian_rz]
    lea rcx, [rip + secp256k1_point_rx]
    lea r8, [rip + secp256k1_point_ry]
    call secp256k1_jacobian_to_affine_limbs
    cmp eax, 1
    jne write_secp256k1_point_infinity
    jmp write_secp256k1_point_out

run_secp256k1_point_encode_compressed:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    mov rsi, qword ptr [rsp + 32]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_point_xy
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    call secp256k1_point_validate_limbs
    cmp eax, 1
    jne point_arg_error
    mov al, byte ptr [rip + secp256k1_point_y1]
    and al, 1
    add al, 2
    mov byte ptr [rip + secp256k1_encoded_point], al
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_encoded_point + 1]
    call store_le4_to_be32
    lea rdi, [rip + secp256k1_encoded_point]
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call hex_encode
    mov byte ptr [rip + hex_buf + 66], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 67
    call write_all
    xor edi, edi
    jmp exit_process

run_secp256k1_point_encode_uncompressed:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    mov rsi, qword ptr [rsp + 32]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_point_xy
    cmp eax, 0
    je field_arg_error
    cmp eax, 1
    jne point_arg_error
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    call secp256k1_point_validate_limbs
    cmp eax, 1
    jne point_arg_error
    mov byte ptr [rip + secp256k1_encoded_point], 4
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_encoded_point + 1]
    call store_le4_to_be32
    lea rdi, [rip + secp256k1_point_y1]
    lea rsi, [rip + secp256k1_encoded_point + 33]
    call store_le4_to_be32
    lea rdi, [rip + secp256k1_encoded_point]
    lea rsi, [rip + hex_buf]
    mov edx, 65
    call hex_encode
    mov byte ptr [rip + hex_buf + 130], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 131
    call write_all
    xor edi, edi
    jmp exit_process

run_secp256k1_point_decode:
    cmp qword ptr [rsp], 3
    jne usage_exit
    mov rbx, qword ptr [rsp + 24]
    cmp byte ptr [rbx], '0'
    jne point_encoding_arg_error
    mov al, byte ptr [rbx + 1]
    cmp al, '2'
    je .Lrun_point_decode_compressed
    cmp al, '3'
    je .Lrun_point_decode_compressed
    cmp al, '4'
    je .Lrun_point_decode_uncompressed
    jmp point_encoding_arg_error

.Lrun_point_decode_compressed:
    mov rdi, rbx
    lea rsi, [rip + secp256k1_encoded_point]
    mov edx, 33
    call hex_decode_fixed
    cmp eax, 1
    jne point_encoding_arg_error
    lea rsi, [rip + secp256k1_encoded_point + 1]
    lea rdi, [rip + secp256k1_field_a_bytes]
    mov ecx, 32
    rep movsb
    lea rdi, [rip + secp256k1_field_a_bytes]
    lea rsi, [rip + secp256k1_point_rx]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_point_rx]
    call secp256k1_field_is_canonical_limbs
    cmp eax, 1
    jne point_encoding_arg_error
    lea rdi, [rip + secp256k1_point_rx]
    lea rsi, [rip + secp256k1_point_rx]
    lea rdx, [rip + secp256k1_point_t0]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_point_t0]
    lea rsi, [rip + secp256k1_point_rx]
    lea rdx, [rip + secp256k1_point_t0]
    call secp256k1_field_mul_limbs
    mov qword ptr [rip + secp256k1_point_t1], 7
    mov qword ptr [rip + secp256k1_point_t1 + 8], 0
    mov qword ptr [rip + secp256k1_point_t1 + 16], 0
    mov qword ptr [rip + secp256k1_point_t1 + 24], 0
    lea rdi, [rip + secp256k1_point_t0]
    lea rsi, [rip + secp256k1_point_t1]
    lea rdx, [rip + secp256k1_point_t0]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_point_t0]
    lea rsi, [rip + secp256k1_point_ry]
    call secp256k1_field_sqrt_limbs
    lea rdi, [rip + secp256k1_point_ry]
    lea rsi, [rip + secp256k1_point_ry]
    lea rdx, [rip + secp256k1_point_t1]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_point_t1]
    lea rsi, [rip + secp256k1_point_t0]
    call secp256k1_field_equal_limbs
    cmp eax, 1
    jne point_encoding_arg_error
    mov al, byte ptr [rip + secp256k1_encoded_point]
    and al, 1
    mov dl, byte ptr [rip + secp256k1_point_ry]
    and dl, 1
    cmp al, dl
    je .Lrun_point_decode_compressed_write
    mov qword ptr [rip + secp256k1_point_t2], 0
    mov qword ptr [rip + secp256k1_point_t2 + 8], 0
    mov qword ptr [rip + secp256k1_point_t2 + 16], 0
    mov qword ptr [rip + secp256k1_point_t2 + 24], 0
    lea rdi, [rip + secp256k1_point_t2]
    lea rsi, [rip + secp256k1_point_ry]
    lea rdx, [rip + secp256k1_point_ry]
    call secp256k1_field_sub_limbs
.Lrun_point_decode_compressed_write:
    jmp write_secp256k1_point_out

.Lrun_point_decode_uncompressed:
    mov rdi, rbx
    lea rsi, [rip + secp256k1_encoded_point]
    mov edx, 65
    call hex_decode_fixed
    cmp eax, 1
    jne point_encoding_arg_error
    cmp byte ptr [rip + secp256k1_encoded_point], 4
    jne point_encoding_arg_error
    lea rsi, [rip + secp256k1_encoded_point + 1]
    lea rdi, [rip + secp256k1_field_a_bytes]
    mov ecx, 32
    rep movsb
    lea rdi, [rip + secp256k1_field_a_bytes]
    lea rsi, [rip + secp256k1_point_rx]
    call load_be32_to_le4
    lea rsi, [rip + secp256k1_encoded_point + 33]
    lea rdi, [rip + secp256k1_field_b_bytes]
    mov ecx, 32
    rep movsb
    lea rdi, [rip + secp256k1_field_b_bytes]
    lea rsi, [rip + secp256k1_point_ry]
    call load_be32_to_le4
    lea rdi, [rip + secp256k1_point_rx]
    call secp256k1_field_is_canonical_limbs
    cmp eax, 1
    jne point_encoding_arg_error
    lea rdi, [rip + secp256k1_point_ry]
    call secp256k1_field_is_canonical_limbs
    cmp eax, 1
    jne point_encoding_arg_error
    lea rdi, [rip + secp256k1_point_rx]
    lea rsi, [rip + secp256k1_point_ry]
    call secp256k1_point_validate_limbs
    cmp eax, 1
    jne point_encoding_arg_error
    jmp write_secp256k1_point_out

write_secp256k1_field_out:
    lea rdi, [rip + secp256k1_field_out]
    lea rsi, [rip + secp256k1_field_out_bytes]
    call store_le4_to_be32
    lea rdi, [rip + secp256k1_field_out_bytes]
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

write_secp256k1_scalar_out:
    lea rdi, [rip + secp256k1_scalar_out]
    lea rsi, [rip + secp256k1_field_out_bytes]
    call store_le4_to_be32
    lea rdi, [rip + secp256k1_field_out_bytes]
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

write_secp256k1_point_out:
    mov rdi, STDOUT
    lea rsi, [rip + point_x_label]
    mov edx, OFFSET FLAT:point_x_label_len
    call write_all
    lea rdi, [rip + secp256k1_point_rx]
    lea rsi, [rip + secp256k1_point_bytes]
    call store_le4_to_be32
    lea rdi, [rip + secp256k1_point_bytes]
    lea rsi, [rip + hex_buf]
    mov edx, 32
    call hex_encode
    mov byte ptr [rip + hex_buf + 64], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 65
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + point_y_label]
    mov edx, OFFSET FLAT:point_y_label_len
    call write_all
    lea rdi, [rip + secp256k1_point_ry]
    lea rsi, [rip + secp256k1_point_bytes]
    call store_le4_to_be32
    lea rdi, [rip + secp256k1_point_bytes]
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

write_secp256k1_point_valid:
    mov rdi, STDOUT
    lea rsi, [rip + point_valid_msg]
    mov edx, OFFSET FLAT:point_valid_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

write_secp256k1_point_invalid:
    mov rdi, STDOUT
    lea rsi, [rip + point_invalid_msg]
    mov edx, OFFSET FLAT:point_invalid_msg_len
    call write_all
    mov edi, 1
    jmp exit_process

write_secp256k1_point_infinity:
    mov rdi, STDOUT
    lea rsi, [rip + point_infinity_msg]
    mov edx, OFFSET FLAT:point_infinity_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

write_secp256k1_jacobian_out:
    mov rdi, STDOUT
    lea rsi, [rip + point_x_label]
    mov edx, OFFSET FLAT:point_x_label_len
    call write_all
    lea rdi, [rip + secp256k1_jacobian_rx]
    lea rsi, [rip + secp256k1_point_bytes]
    call store_le4_to_be32
    lea rdi, [rip + secp256k1_point_bytes]
    lea rsi, [rip + hex_buf]
    mov edx, 32
    call hex_encode
    mov byte ptr [rip + hex_buf + 64], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 65
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + point_y_label]
    mov edx, OFFSET FLAT:point_y_label_len
    call write_all
    lea rdi, [rip + secp256k1_jacobian_ry]
    lea rsi, [rip + secp256k1_point_bytes]
    call store_le4_to_be32
    lea rdi, [rip + secp256k1_point_bytes]
    lea rsi, [rip + hex_buf]
    mov edx, 32
    call hex_encode
    mov byte ptr [rip + hex_buf + 64], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 65
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + point_z_label]
    mov edx, OFFSET FLAT:point_z_label_len
    call write_all
    lea rdi, [rip + secp256k1_jacobian_rz]
    lea rsi, [rip + secp256k1_point_bytes]
    call store_le4_to_be32
    lea rdi, [rip + secp256k1_point_bytes]
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

write_secp256k1_jacobian_infinity:
    mov rdi, STDOUT
    lea rsi, [rip + point_infinity_msg]
    mov edx, OFFSET FLAT:point_infinity_msg_len
    call write_all
    xor edi, edi
    jmp exit_process

frost_hash_stdin:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    mov rsi, rbx
    mov rdx, r12
    call sha256_update

.Lfrost_hash_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Lfrost_hash_eof

    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + io_buf]
    mov rdx, rax
    call sha256_update
    jmp .Lfrost_hash_read_loop

.Lfrost_hash_eof:
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

    pop r12
    pop rbx
    xor edi, edi
    jmp exit_process

frost_hash_to_scalar_stdin:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_zpad64]
    mov edx, 64
    call sha256_update

.Lfrost_xmd_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Lfrost_xmd_read_eof

    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + io_buf]
    mov rdx, rax
    call sha256_update
    jmp .Lfrost_xmd_read_loop

.Lfrost_xmd_read_eof:
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_len48_zero]
    mov edx, 3
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, rbx
    mov rdx, r12
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_b0]
    call sha256_final

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_b0]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_counter_one]
    mov edx, 1
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, rbx
    mov rdx, r12
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_b1]
    call sha256_final

    lea rdi, [rip + frost_uniform_buf]
    lea rsi, [rip + frost_b1]
    mov ecx, 32
    rep movsb

    lea rdi, [rip + frost_xor_buf]
    lea rsi, [rip + frost_b0]
    lea rdx, [rip + frost_b1]
    mov ecx, 32
.Lfrost_xor_loop:
    mov al, byte ptr [rsi]
    xor al, byte ptr [rdx]
    mov byte ptr [rdi], al
    inc rdi
    inc rsi
    inc rdx
    dec ecx
    jne .Lfrost_xor_loop

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_xor_buf]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_counter_two]
    mov edx, 1
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, rbx
    mov rdx, r12
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_b2]
    call sha256_final

    lea rdi, [rip + frost_uniform_buf + 32]
    lea rsi, [rip + frost_b2]
    mov ecx, 16
    rep movsb

    lea rdi, [rip + frost_uniform_buf]
    mov rsi, r13
    lea rdx, [rip + frost_scalar_buf]
    call frost_reduce_48_mod_order

    lea rdi, [rip + frost_scalar_buf]
    lea rsi, [rip + hex_buf]
    mov edx, 32
    call hex_encode
    mov byte ptr [rip + hex_buf + 64], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 65
    call write_all

    pop r13
    pop r12
    pop rbx
    xor edi, edi
    jmp exit_process

frost_hash_to_scalar_mem:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    mov rbp, r9

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_zpad64]
    mov edx, 64
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, r14
    mov rdx, r15
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_len48_zero]
    mov edx, 3
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, rbx
    mov rdx, r12
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_b0]
    call sha256_final

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_b0]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_counter_one]
    mov edx, 1
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, rbx
    mov rdx, r12
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_b1]
    call sha256_final

    lea rdi, [rip + frost_uniform_buf]
    lea rsi, [rip + frost_b1]
    mov ecx, 32
    rep movsb

    lea rdi, [rip + frost_xor_buf]
    lea rsi, [rip + frost_b0]
    lea rdx, [rip + frost_b1]
    mov ecx, 32
.Lfrost_mem_xor_loop:
    mov al, byte ptr [rsi]
    xor al, byte ptr [rdx]
    mov byte ptr [rdi], al
    inc rdi
    inc rsi
    inc rdx
    dec ecx
    jne .Lfrost_mem_xor_loop

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_xor_buf]
    mov edx, 32
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_counter_two]
    mov edx, 1
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, rbx
    mov rdx, r12
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + frost_b2]
    call sha256_final

    lea rdi, [rip + frost_uniform_buf + 32]
    lea rsi, [rip + frost_b2]
    mov ecx, 16
    rep movsb

    lea rdi, [rip + frost_uniform_buf]
    mov rsi, r13
    mov rdx, rbp
    call frost_reduce_48_mod_order

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

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

field_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + field_arg_error_msg]
    mov edx, OFFSET FLAT:field_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

scalar_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + scalar_arg_error_msg]
    mov edx, OFFSET FLAT:scalar_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

frost_lagrange_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + frost_lagrange_arg_error_msg]
    mov edx, OFFSET FLAT:frost_lagrange_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

frost_commitment_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + frost_commitment_arg_error_msg]
    mov edx, OFFSET FLAT:frost_commitment_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

point_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + point_arg_error_msg]
    mov edx, OFFSET FLAT:point_arg_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

point_encoding_arg_error:
    mov rdi, STDERR
    lea rsi, [rip + point_encoding_arg_error_msg]
    mov edx, OFFSET FLAT:point_encoding_arg_error_msg_len
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

artifact_file_error:
    mov rdi, STDERR
    lea rsi, [rip + artifact_file_error_msg]
    mov edx, OFFSET FLAT:artifact_file_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

input_file_error:
    mov rdi, STDERR
    lea rsi, [rip + input_file_error_msg]
    mov edx, OFFSET FLAT:input_file_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

output_file_error:
    mov rdi, STDERR
    lea rsi, [rip + output_file_error_msg]
    mov edx, OFFSET FLAT:output_file_error_msg_len
    call write_all
    mov edi, 2
    jmp exit_process

armor_error:
    mov rdi, STDERR
    lea rsi, [rip + armor_error_msg]
    mov edx, OFFSET FLAT:armor_error_msg_len
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
    cmp qword ptr [rsp], 2
    jne usage_exit

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

run_keypair:
    cmp qword ptr [rsp], 2
    jne usage_exit

    lea rdi, [rip + x25519_private_key]
    mov esi, 32
    call fill_random
    cmp eax, 1
    jne random_error

    lea rdi, [rip + x25519_public_key]
    lea rsi, [rip + x25519_private_key]
    call x25519_basepoint
    cmp eax, 1
    jne random_error

    mov rdi, STDOUT
    lea rsi, [rip + keypair_private_label]
    mov edx, OFFSET FLAT:keypair_private_label_len
    call write_all
    lea rdi, [rip + x25519_private_key]
    lea rsi, [rip + hex_buf]
    mov edx, 32
    call hex_encode
    mov byte ptr [rip + hex_buf + 64], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 65
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + keypair_public_label]
    mov edx, OFFSET FLAT:keypair_public_label_len
    call write_all
    lea rdi, [rip + x25519_public_key]
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

run_poly1305:
    cmp qword ptr [rsp], 3
    jne usage_exit

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
    jne usage_exit

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
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call hex32_decode
    cmp eax, 1
    jne aead_arg_error

    jmp seal_stdio_with_loaded_key

run_seal_v2:
    cmp qword ptr [rsp], 4
    jne usage_exit

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

    jmp seal_v2_stdio_with_loaded_key

run_seal_file:
    cmp qword ptr [rsp], 5
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call hex32_decode
    cmp eax, 1
    jne aead_arg_error

    mov rdi, qword ptr [rsp + 32]
    mov rsi, qword ptr [rsp + 40]
    call open_seal_file_paths
    cmp eax, 1
    je .Lseal_file_paths_open
    cmp eax, 2
    je output_file_error
    jmp input_file_error

.Lseal_file_paths_open:
    jmp seal_with_loaded_key

run_seal_file_v2:
    cmp qword ptr [rsp], 6
    jne usage_exit

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

    mov rdi, qword ptr [rsp + 40]
    mov rsi, qword ptr [rsp + 48]
    call open_seal_file_paths
    cmp eax, 1
    je .Lseal_file_v2_paths_open
    cmp eax, 2
    je output_file_error
    jmp input_file_error

.Lseal_file_v2_paths_open:
    jmp seal_v2_with_loaded_key

run_seal_file_keyfile:
    cmp qword ptr [rsp], 5
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call read_key_file
    cmp eax, 1
    jne keyfile_error

    mov rdi, qword ptr [rsp + 32]
    mov rsi, qword ptr [rsp + 40]
    call open_seal_file_paths
    cmp eax, 1
    je .Lseal_file_keyfile_paths_open
    cmp eax, 2
    je output_file_error
    jmp input_file_error

.Lseal_file_keyfile_paths_open:
    jmp seal_with_loaded_key

run_seal_file_keyfile_v2:
    cmp qword ptr [rsp], 6
    jne usage_exit

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

    mov rdi, qword ptr [rsp + 40]
    mov rsi, qword ptr [rsp + 48]
    call open_seal_file_paths
    cmp eax, 1
    je .Lseal_file_keyfile_v2_paths_open
    cmp eax, 2
    je output_file_error
    jmp input_file_error

.Lseal_file_keyfile_v2_paths_open:
    jmp seal_v2_with_loaded_key

run_seal_to:
    cmp qword ptr [rsp], 5
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + x25519_recipient_public]
    call hex32_decode
    cmp eax, 1
    jne key_error

    lea rdi, [rip + x25519_private_key]
    mov esi, 32
    call fill_random
    cmp eax, 1
    jne random_error

    lea rdi, [rip + x25519_ephemeral_public]
    lea rsi, [rip + x25519_private_key]
    call x25519_basepoint
    cmp eax, 1
    jne envelope_error

    lea rdi, [rip + x25519_shared_secret]
    lea rsi, [rip + x25519_private_key]
    lea rdx, [rip + x25519_recipient_public]
    call x25519_scalar_mult
    cmp eax, 1
    jne envelope_error

    lea rdi, [rip + chacha_nonce]
    mov esi, ENVELOPE_NONCE_LEN
    call fill_random
    cmp eax, 1
    jne random_error

    call build_envelope_v3_header
    call derive_v3_aead_key

    mov rdi, qword ptr [rsp + 32]
    mov rsi, qword ptr [rsp + 40]
    call open_seal_file_paths
    cmp eax, 1
    je .Lseal_to_paths_open
    cmp eax, 2
    je output_file_error
    jmp input_file_error

.Lseal_to_paths_open:
    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + envelope_v3_header_buf]
    mov edx, ENVELOPE_V3_HEADER_LEN
    call write_all
    test eax, eax
    jne seal_output_write_error

    call aead_poly1305_init
    lea rdi, [rip + envelope_v3_header_buf]
    mov esi, ENVELOPE_V3_HEADER_LEN
    call aead_poly1305_update_aad
    jmp seal_stream_with_current_aad

run_seal_keyfile:
    cmp qword ptr [rsp], 3
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call read_key_file
    cmp eax, 1
    jne keyfile_error

    jmp seal_stdio_with_loaded_key

run_seal_keyfile_v2:
    cmp qword ptr [rsp], 4
    jne usage_exit

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

    jmp seal_v2_stdio_with_loaded_key

seal_stdio_with_loaded_key:
    mov qword ptr [rip + seal_input_fd], STDIN
    mov qword ptr [rip + seal_output_fd], STDOUT
    mov qword ptr [rip + seal_file_mode], 0
    jmp seal_with_loaded_key

seal_v2_stdio_with_loaded_key:
    mov qword ptr [rip + seal_input_fd], STDIN
    mov qword ptr [rip + seal_output_fd], STDOUT
    mov qword ptr [rip + seal_file_mode], 0
    jmp seal_v2_with_loaded_key

seal_with_loaded_key:
    lea rdi, [rip + chacha_nonce]
    mov esi, ENVELOPE_NONCE_LEN
    call fill_random
    cmp eax, 1
    jne random_error

    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + envelope_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call write_all
    test eax, eax
    jne seal_output_write_error

    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + chacha_nonce]
    mov edx, ENVELOPE_NONCE_LEN
    call write_all
    test eax, eax
    jne seal_output_write_error

    call aead_poly1305_init
    jmp seal_stream_with_current_aad

seal_v2_with_loaded_key:
    lea rdi, [rip + chacha_nonce]
    mov esi, ENVELOPE_NONCE_LEN
    call fill_random
    cmp eax, 1
    jne random_error

    call build_envelope_v2_header

    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + envelope_header_buf]
    mov edx, ENVELOPE_V2_HEADER_LEN
    call write_all
    test eax, eax
    jne seal_output_write_error

    call aead_poly1305_init
    lea rdi, [rip + envelope_header_buf]
    mov esi, ENVELOPE_V2_HEADER_LEN
    call aead_poly1305_update_aad

seal_stream_with_current_aad:
    mov qword ptr [rip + aead_text_len], 0
    mov dword ptr [rip + chacha_counter], 1

.Lseal_read_loop:
    mov eax, SYS_READ
    mov rdi, qword ptr [rip + seal_input_fd]
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js seal_input_read_error
    jz .Lseal_eof

    lea rdi, [rip + io_buf]
    mov rsi, rax
    call chacha20_xor
    mov r14, rax
    add qword ptr [rip + aead_text_len], r14

    lea rdi, [rip + io_buf]
    mov rsi, r14
    call poly1305_update

    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + io_buf]
    mov rdx, r14
    call write_all
    test eax, eax
    jne seal_output_write_error
    jmp .Lseal_read_loop

.Lseal_eof:
    mov rdi, qword ptr [rip + aead_text_len]
    lea rsi, [rip + poly_tag]
    call aead_poly1305_finish

    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + poly_tag]
    mov edx, ENVELOPE_TAG_LEN
    call write_all
    test eax, eax
    jne seal_output_write_error

    call close_seal_files

    xor edi, edi
    jmp exit_process

seal_input_read_error:
    call close_seal_files
    jmp read_error

seal_output_write_error:
    call close_seal_files
    jmp output_file_error

run_open:
    cmp qword ptr [rsp], 3
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call hex32_decode
    cmp eax, 1
    jne aead_arg_error

    jmp open_with_loaded_key

run_open_file:
    cmp qword ptr [rsp], 5
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call hex32_decode
    cmp eax, 1
    jne aead_arg_error

    mov rax, qword ptr [rsp + 40]
    mov qword ptr [rip + aead_output_path], rax

    mov rdi, qword ptr [rsp + 32]
    call read_artifact_file
    cmp eax, 1
    je open_parse_loaded_envelope
    cmp eax, 2
    je aead_size_error
    jmp artifact_file_error

run_open_file_keyfile:
    cmp qword ptr [rsp], 5
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call read_key_file
    cmp eax, 1
    jne keyfile_error

    mov rax, qword ptr [rsp + 40]
    mov qword ptr [rip + aead_output_path], rax

    mov rdi, qword ptr [rsp + 32]
    call read_artifact_file
    cmp eax, 1
    je open_parse_loaded_envelope
    cmp eax, 2
    je aead_size_error
    jmp artifact_file_error

run_open_to:
    cmp qword ptr [rsp], 5
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + x25519_private_key]
    call hex32_decode
    cmp eax, 1
    jne key_error

    mov rax, qword ptr [rsp + 40]
    mov qword ptr [rip + aead_output_path], rax

    mov rdi, qword ptr [rsp + 32]
    call read_artifact_file
    cmp eax, 1
    je open_to_parse_loaded_envelope
    cmp eax, 2
    je aead_size_error
    jmp artifact_file_error

run_open_keyfile:
    cmp qword ptr [rsp], 3
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + chacha_key]
    call read_key_file
    cmp eax, 1
    jne keyfile_error

open_with_loaded_key:
    mov qword ptr [rip + aead_output_path], 0
    mov qword ptr [rip + aead_text_len], 0

.Lopen_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz open_parse_loaded_envelope

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

open_parse_loaded_envelope:
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

    lea rsi, [rip + aead_open_buf + ENVELOPE_HEADER_LEN]
    mov rdi, rsi
    mov rsi, qword ptr [rip + aead_text_len]
    call write_open_plaintext
    cmp eax, 1
    jne output_file_error

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

    lea rsi, [rip + aead_open_buf + ENVELOPE_V2_HEADER_LEN]
    mov rdi, rsi
    mov rsi, qword ptr [rip + aead_text_len]
    call write_open_plaintext
    cmp eax, 1
    jne output_file_error

    xor edi, edi
    jmp exit_process

open_to_parse_loaded_envelope:
    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_V3_MIN_LEN
    jb envelope_error

    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + envelope_v3_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    jne envelope_error

    lea rdi, [rip + x25519_ephemeral_public]
    lea rsi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    mov ecx, ENVELOPE_X25519_PUBLIC_LEN
    rep movsb

    lea rdi, [rip + chacha_nonce]
    lea rsi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_X25519_PUBLIC_LEN + ENVELOPE_KEY_ID_LEN]
    mov ecx, ENVELOPE_NONCE_LEN
    rep movsb

    lea rdi, [rip + x25519_recipient_public]
    lea rsi, [rip + x25519_private_key]
    call x25519_basepoint
    cmp eax, 1
    jne envelope_error

    call compute_recipient_key_id
    lea rdi, [rip + envelope_key_id]
    lea rsi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_X25519_PUBLIC_LEN]
    mov edx, ENVELOPE_KEY_ID_LEN
    call memeq
    cmp eax, 1
    jne envelope_error

    lea rdi, [rip + x25519_shared_secret]
    lea rsi, [rip + x25519_private_key]
    lea rdx, [rip + x25519_ephemeral_public]
    call x25519_scalar_mult
    cmp eax, 1
    jne envelope_error

    lea rdi, [rip + envelope_v3_header_buf]
    lea rsi, [rip + aead_open_buf]
    mov ecx, ENVELOPE_V3_HEADER_LEN
    rep movsb
    call derive_v3_aead_key

    mov rax, qword ptr [rip + aead_text_len]
    sub rax, ENVELOPE_V3_MIN_LEN
    mov qword ptr [rip + aead_text_len], rax

    lea rsi, [rip + aead_open_buf + ENVELOPE_V3_HEADER_LEN]
    add rsi, rax
    lea rdi, [rip + aead_expected_tag]
    mov ecx, ENVELOPE_TAG_LEN
    rep movsb

    call aead_poly1305_init
    lea rdi, [rip + aead_open_buf]
    mov esi, ENVELOPE_V3_HEADER_LEN
    call aead_poly1305_update_aad
    lea rdi, [rip + aead_open_buf + ENVELOPE_V3_HEADER_LEN]
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
    lea rdi, [rip + aead_open_buf + ENVELOPE_V3_HEADER_LEN]
    mov rsi, qword ptr [rip + aead_text_len]
    call chacha20_xor

    lea rsi, [rip + aead_open_buf + ENVELOPE_V3_HEADER_LEN]
    mov rdi, rsi
    mov rsi, qword ptr [rip + aead_text_len]
    call write_open_plaintext
    cmp eax, 1
    jne output_file_error

    xor edi, edi
    jmp exit_process

run_inspect:
    cmp qword ptr [rsp], 2
    jne usage_exit

    mov qword ptr [rip + aead_text_len], 0

.Linspect_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz inspect_parse_loaded_envelope

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
    jmp .Linspect_read_loop

run_inspect_file:
    cmp qword ptr [rsp], 3
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    call read_artifact_file
    cmp eax, 1
    je inspect_parse_loaded_envelope
    cmp eax, 2
    je aead_size_error
    jmp artifact_file_error

inspect_parse_loaded_envelope:
    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_MIN_LEN
    jb envelope_error

    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + envelope_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    je .Linspect_v1

    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_V2_MIN_LEN
    jb envelope_error
    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + envelope_v2_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    je .Linspect_v2

    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + envelope_v3_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    jne envelope_error
    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_V3_MIN_LEN
    jb envelope_error
    jmp .Linspect_v3

.Linspect_v1:
    mov rdi, STDOUT
    lea rsi, [rip + inspect_v1_msg]
    mov edx, OFFSET FLAT:inspect_v1_msg_len
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + inspect_nonce_label]
    mov edx, OFFSET FLAT:inspect_nonce_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_NONCE_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 24], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 25
    call write_all

    xor edi, edi
    jmp exit_process

.Linspect_v2:
    mov rdi, STDOUT
    lea rsi, [rip + inspect_v2_msg]
    mov edx, OFFSET FLAT:inspect_v2_msg_len
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + inspect_key_id_label]
    mov edx, OFFSET FLAT:inspect_key_id_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_KEY_ID_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 32], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + inspect_nonce_label]
    mov edx, OFFSET FLAT:inspect_nonce_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_KEY_ID_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_NONCE_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 24], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 25
    call write_all

    xor edi, edi
    jmp exit_process

.Linspect_v3:
    mov rdi, STDOUT
    lea rsi, [rip + inspect_v3_msg]
    mov edx, OFFSET FLAT:inspect_v3_msg_len
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + inspect_ephemeral_public_label]
    mov edx, OFFSET FLAT:inspect_ephemeral_public_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_X25519_PUBLIC_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 64], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 65
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + inspect_key_id_label]
    mov edx, OFFSET FLAT:inspect_key_id_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_X25519_PUBLIC_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_KEY_ID_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 32], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + inspect_nonce_label]
    mov edx, OFFSET FLAT:inspect_nonce_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_X25519_PUBLIC_LEN + ENVELOPE_KEY_ID_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_NONCE_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 24], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 25
    call write_all

    xor edi, edi
    jmp exit_process

run_manifest:
    cmp qword ptr [rsp], 2
    jne usage_exit

    mov qword ptr [rip + aead_text_len], 0

.Lmanifest_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz manifest_parse_loaded_envelope

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
    jmp .Lmanifest_read_loop

run_manifest_file:
    cmp qword ptr [rsp], 3
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    call read_artifact_file
    cmp eax, 1
    je manifest_parse_loaded_envelope
    cmp eax, 2
    je aead_size_error
    jmp artifact_file_error

manifest_parse_loaded_envelope:
    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_MIN_LEN
    jb envelope_error

    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + envelope_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    je .Lmanifest_v1

    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_V2_MIN_LEN
    jb envelope_error
    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + envelope_v2_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    je .Lmanifest_v2

    lea rdi, [rip + aead_open_buf]
    lea rsi, [rip + envelope_v3_prefix]
    mov edx, ENVELOPE_PREFIX_LEN
    call memeq
    cmp eax, 1
    jne envelope_error
    mov rbx, qword ptr [rip + aead_text_len]
    cmp rbx, ENVELOPE_V3_MIN_LEN
    jb envelope_error
    jmp .Lmanifest_v3

.Lmanifest_v1:
    mov rdi, STDOUT
    lea rsi, [rip + manifest_v1_msg]
    mov edx, OFFSET FLAT:manifest_v1_msg_len
    call write_all

    lea rdi, [rip + manifest_artifact_sha256_label]
    mov esi, OFFSET FLAT:manifest_artifact_sha256_label_len
    lea rdx, [rip + aead_open_buf]
    mov rcx, qword ptr [rip + aead_text_len]
    call write_manifest_labeled_sha256

    mov rdi, STDOUT
    lea rsi, [rip + manifest_ciphertext_length_label]
    mov edx, OFFSET FLAT:manifest_ciphertext_length_label_len
    call write_all
    mov rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_MIN_LEN
    call write_u64_decimal_stdout
    mov rdi, STDOUT
    lea rsi, [rip + newline_msg]
    mov edx, OFFSET FLAT:newline_msg_len
    call write_all

    lea rdi, [rip + manifest_ciphertext_sha256_label]
    mov esi, OFFSET FLAT:manifest_ciphertext_sha256_label_len
    lea rdx, [rip + aead_open_buf + ENVELOPE_HEADER_LEN]
    mov rcx, qword ptr [rip + aead_text_len]
    sub rcx, ENVELOPE_MIN_LEN
    call write_manifest_labeled_sha256

    mov rdi, STDOUT
    lea rsi, [rip + inspect_nonce_label]
    mov edx, OFFSET FLAT:inspect_nonce_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_NONCE_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 24], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 25
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + manifest_tag_label]
    mov edx, OFFSET FLAT:manifest_tag_label_len
    call write_all
    lea rdi, [rip + aead_open_buf]
    add rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_TAG_LEN
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_TAG_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 32], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call write_all

    xor edi, edi
    jmp exit_process

.Lmanifest_v2:
    mov rdi, STDOUT
    lea rsi, [rip + manifest_v2_msg]
    mov edx, OFFSET FLAT:manifest_v2_msg_len
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + inspect_key_id_label]
    mov edx, OFFSET FLAT:inspect_key_id_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_KEY_ID_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 32], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call write_all

    lea rdi, [rip + manifest_artifact_sha256_label]
    mov esi, OFFSET FLAT:manifest_artifact_sha256_label_len
    lea rdx, [rip + aead_open_buf]
    mov rcx, qword ptr [rip + aead_text_len]
    call write_manifest_labeled_sha256

    mov rdi, STDOUT
    lea rsi, [rip + manifest_ciphertext_length_label]
    mov edx, OFFSET FLAT:manifest_ciphertext_length_label_len
    call write_all
    mov rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_V2_MIN_LEN
    call write_u64_decimal_stdout
    mov rdi, STDOUT
    lea rsi, [rip + newline_msg]
    mov edx, OFFSET FLAT:newline_msg_len
    call write_all

    lea rdi, [rip + manifest_ciphertext_sha256_label]
    mov esi, OFFSET FLAT:manifest_ciphertext_sha256_label_len
    lea rdx, [rip + aead_open_buf + ENVELOPE_V2_HEADER_LEN]
    mov rcx, qword ptr [rip + aead_text_len]
    sub rcx, ENVELOPE_V2_MIN_LEN
    call write_manifest_labeled_sha256

    mov rdi, STDOUT
    lea rsi, [rip + inspect_nonce_label]
    mov edx, OFFSET FLAT:inspect_nonce_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_KEY_ID_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_NONCE_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 24], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 25
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + manifest_tag_label]
    mov edx, OFFSET FLAT:manifest_tag_label_len
    call write_all
    lea rdi, [rip + aead_open_buf]
    add rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_TAG_LEN
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_TAG_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 32], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call write_all

    xor edi, edi
    jmp exit_process

.Lmanifest_v3:
    mov rdi, STDOUT
    lea rsi, [rip + manifest_v3_msg]
    mov edx, OFFSET FLAT:manifest_v3_msg_len
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + inspect_ephemeral_public_label]
    mov edx, OFFSET FLAT:inspect_ephemeral_public_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_X25519_PUBLIC_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 64], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 65
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + inspect_key_id_label]
    mov edx, OFFSET FLAT:inspect_key_id_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_X25519_PUBLIC_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_KEY_ID_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 32], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call write_all

    lea rdi, [rip + manifest_artifact_sha256_label]
    mov esi, OFFSET FLAT:manifest_artifact_sha256_label_len
    lea rdx, [rip + aead_open_buf]
    mov rcx, qword ptr [rip + aead_text_len]
    call write_manifest_labeled_sha256

    mov rdi, STDOUT
    lea rsi, [rip + manifest_ciphertext_length_label]
    mov edx, OFFSET FLAT:manifest_ciphertext_length_label_len
    call write_all
    mov rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_V3_MIN_LEN
    call write_u64_decimal_stdout
    mov rdi, STDOUT
    lea rsi, [rip + newline_msg]
    mov edx, OFFSET FLAT:newline_msg_len
    call write_all

    lea rdi, [rip + manifest_ciphertext_sha256_label]
    mov esi, OFFSET FLAT:manifest_ciphertext_sha256_label_len
    lea rdx, [rip + aead_open_buf + ENVELOPE_V3_HEADER_LEN]
    mov rcx, qword ptr [rip + aead_text_len]
    sub rcx, ENVELOPE_V3_MIN_LEN
    call write_manifest_labeled_sha256

    mov rdi, STDOUT
    lea rsi, [rip + inspect_nonce_label]
    mov edx, OFFSET FLAT:inspect_nonce_label_len
    call write_all
    lea rdi, [rip + aead_open_buf + ENVELOPE_PREFIX_LEN + ENVELOPE_X25519_PUBLIC_LEN + ENVELOPE_KEY_ID_LEN]
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_NONCE_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 24], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 25
    call write_all

    mov rdi, STDOUT
    lea rsi, [rip + manifest_tag_label]
    mov edx, OFFSET FLAT:manifest_tag_label_len
    call write_all
    lea rdi, [rip + aead_open_buf]
    add rdi, qword ptr [rip + aead_text_len]
    sub rdi, ENVELOPE_TAG_LEN
    lea rsi, [rip + hex_buf]
    mov edx, ENVELOPE_TAG_LEN
    call hex_encode
    mov byte ptr [rip + hex_buf + 32], 10
    mov rdi, STDOUT
    lea rsi, [rip + hex_buf]
    mov edx, 33
    call write_all

    xor edi, edi
    jmp exit_process

run_armor_file:
    cmp qword ptr [rsp], 4
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    call read_artifact_file
    cmp eax, 1
    je .Larmor_file_loaded
    cmp eax, 2
    je aead_size_error
    jmp artifact_file_error

.Larmor_file_loaded:
    mov rdi, qword ptr [rsp + 32]
    call open_output_file
    cmp eax, 1
    jne output_file_error

    call write_armor_loaded_file
    cmp eax, 1
    jne output_file_error

    xor edi, edi
    jmp exit_process

run_dearmor_file:
    cmp qword ptr [rsp], 4
    jne usage_exit

    mov rdi, qword ptr [rsp + 24]
    call read_artifact_file
    cmp eax, 1
    je .Ldearmor_file_loaded
    cmp eax, 2
    je aead_size_error
    jmp artifact_file_error

.Ldearmor_file_loaded:
    call decode_armor_loaded_file
    cmp eax, 1
    jne armor_error

    mov rax, qword ptr [rsp + 32]
    mov qword ptr [rip + aead_output_path], rax
    lea rdi, [rip + aead_open_buf]
    mov rsi, qword ptr [rip + aead_text_len]
    call write_open_plaintext
    cmp eax, 1
    jne output_file_error

    xor edi, edi
    jmp exit_process

run_aead_seal:
    cmp qword ptr [rsp], 4
    jne usage_exit

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
    jne usage_exit

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
    cmp qword ptr [rsp], 2
    jne usage_exit

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

read_artifact_file:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov qword ptr [rip + aead_text_len], 0

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, rbx
    mov edx, O_RDONLY
    xor r10d, r10d
    syscall
    test rax, rax
    js .Lread_artifact_file_fail

    mov r12, rax

.Lread_artifact_file_loop:
    mov eax, SYS_READ
    mov rdi, r12
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js .Lread_artifact_file_fail_close
    jz .Lread_artifact_file_ok_close

    mov r13, qword ptr [rip + aead_text_len]
    mov rdx, AEAD_OPEN_MAX
    sub rdx, r13
    cmp rax, rdx
    ja .Lread_artifact_file_size_close

    lea rdi, [rip + aead_open_buf]
    add rdi, r13
    lea rsi, [rip + io_buf]
    mov rcx, rax
    rep movsb
    add qword ptr [rip + aead_text_len], rax
    jmp .Lread_artifact_file_loop

.Lread_artifact_file_ok_close:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall
    mov eax, 1
    jmp .Lread_artifact_file_done

.Lread_artifact_file_size_close:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall
    mov eax, 2
    jmp .Lread_artifact_file_done

.Lread_artifact_file_fail_close:
    mov eax, SYS_CLOSE
    mov rdi, r12
    syscall

.Lread_artifact_file_fail:
    xor eax, eax
.Lread_artifact_file_done:
    pop r13
    pop r12
    pop rbx
    ret

open_seal_file_paths:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    mov qword ptr [rip + seal_file_mode], 0

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, rbx
    mov edx, O_RDONLY
    xor r10d, r10d
    syscall
    test rax, rax
    js .Lopen_seal_file_input_fail
    mov qword ptr [rip + seal_input_fd], rax

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, r12
    mov edx, FILE_CREATE_FLAGS
    mov r10d, FILE_CREATE_MODE
    syscall
    test rax, rax
    js .Lopen_seal_file_output_fail
    mov qword ptr [rip + seal_output_fd], rax
    mov qword ptr [rip + seal_file_mode], 1
    mov eax, 1
    jmp .Lopen_seal_file_done

.Lopen_seal_file_output_fail:
    mov eax, SYS_CLOSE
    mov rdi, qword ptr [rip + seal_input_fd]
    syscall
    mov eax, 2
    jmp .Lopen_seal_file_done

.Lopen_seal_file_input_fail:
    xor eax, eax
.Lopen_seal_file_done:
    pop r12
    pop rbx
    ret

close_seal_files:
    cmp qword ptr [rip + seal_file_mode], 1
    jne .Lclose_seal_files_done

    mov eax, SYS_CLOSE
    mov rdi, qword ptr [rip + seal_input_fd]
    syscall
    mov eax, SYS_CLOSE
    mov rdi, qword ptr [rip + seal_output_fd]
    syscall
    mov qword ptr [rip + seal_file_mode], 0

.Lclose_seal_files_done:
    ret

open_output_file:
    mov eax, SYS_OPENAT
    mov rsi, rdi
    mov rdi, AT_FDCWD
    mov edx, FILE_CREATE_FLAGS
    mov r10d, FILE_CREATE_MODE
    syscall
    test rax, rax
    js .Lopen_output_file_fail
    mov qword ptr [rip + seal_output_fd], rax
    mov eax, 1
    ret
.Lopen_output_file_fail:
    xor eax, eax
    ret

write_open_plaintext:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, STDOUT
    xor r14d, r14d

    mov rax, qword ptr [rip + aead_output_path]
    test rax, rax
    jz .Lwrite_open_plaintext_write

    mov eax, SYS_OPENAT
    mov rdi, AT_FDCWD
    mov rsi, qword ptr [rip + aead_output_path]
    mov edx, FILE_CREATE_FLAGS
    mov r10d, FILE_CREATE_MODE
    syscall
    test rax, rax
    js .Lwrite_open_plaintext_fail
    mov r13, rax
    mov r14d, 1

.Lwrite_open_plaintext_write:
    mov rdi, r13
    mov rsi, rbx
    mov rdx, r12
    call write_all
    test eax, eax
    jne .Lwrite_open_plaintext_fail_close

    test r14, r14
    jz .Lwrite_open_plaintext_ok
    mov eax, SYS_CLOSE
    mov rdi, r13
    syscall
    test rax, rax
    js .Lwrite_open_plaintext_fail

.Lwrite_open_plaintext_ok:
    mov eax, 1
    jmp .Lwrite_open_plaintext_done

.Lwrite_open_plaintext_fail_close:
    test r14, r14
    jz .Lwrite_open_plaintext_fail
    mov eax, SYS_CLOSE
    mov rdi, r13
    syscall

.Lwrite_open_plaintext_fail:
    xor eax, eax
.Lwrite_open_plaintext_done:
    pop r14
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

compute_recipient_key_id:
    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + x25519_recipient_public]
    mov edx, ENVELOPE_X25519_PUBLIC_LEN
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + digest_buf]
    call sha256_final
    lea rdi, [rip + envelope_key_id]
    lea rsi, [rip + digest_buf]
    mov ecx, ENVELOPE_KEY_ID_LEN
    rep movsb
    ret

build_envelope_v3_header:
    call compute_recipient_key_id

    lea rdi, [rip + envelope_v3_header_buf]
    lea rsi, [rip + envelope_v3_prefix]
    mov ecx, ENVELOPE_PREFIX_LEN
    rep movsb
    lea rsi, [rip + x25519_ephemeral_public]
    mov ecx, ENVELOPE_X25519_PUBLIC_LEN
    rep movsb
    lea rsi, [rip + envelope_key_id]
    mov ecx, ENVELOPE_KEY_ID_LEN
    rep movsb
    lea rsi, [rip + chacha_nonce]
    mov ecx, ENVELOPE_NONCE_LEN
    rep movsb
    ret

derive_v3_aead_key:
    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + envelope_v3_header_buf]
    mov edx, ENVELOPE_V3_HEADER_LEN
    call sha256_update
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + hkdf_salt]
    call sha256_final

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
    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + x25519_shared_secret]
    mov edx, 32
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
    lea rsi, [rip + v3_hkdf_info]
    mov edx, OFFSET FLAT:v3_hkdf_info_len
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
    lea rsi, [rip + chacha_key]
    call sha256_final
    ret

write_armor_loaded_file:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + armor_header]
    mov edx, OFFSET FLAT:armor_header_len
    call write_all
    test eax, eax
    jne .Lwrite_armor_fail_close
    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + newline_msg]
    mov edx, OFFSET FLAT:newline_msg_len
    call write_all
    test eax, eax
    jne .Lwrite_armor_fail_close

    lea rbx, [rip + aead_open_buf]
    mov r12, qword ptr [rip + aead_text_len]
    lea r13, [rip + io_buf]
    xor r14d, r14d
    lea r15, [rip + base64_alphabet]

.Lwrite_armor_loop:
    test r12, r12
    jz .Lwrite_armor_flush_tail

    mov r8d, 1
    movzx r11d, byte ptr [rbx]
    xor r9d, r9d
    xor r10d, r10d
    cmp r12, 2
    jb .Lwrite_armor_have_group
    movzx r9d, byte ptr [rbx + 1]
    mov r8d, 2
    cmp r12, 3
    jb .Lwrite_armor_have_group
    movzx r10d, byte ptr [rbx + 2]
    mov r8d, 3

.Lwrite_armor_have_group:
    mov edx, r11d
    shr edx, 2
    mov dl, byte ptr [r15 + rdx]
    mov byte ptr [r13], dl
    inc r13
    inc r14

    mov edx, r11d
    and edx, 3
    shl edx, 4
    mov ecx, r9d
    shr ecx, 4
    or edx, ecx
    mov dl, byte ptr [r15 + rdx]
    mov byte ptr [r13], dl
    inc r13
    inc r14

    cmp r8d, 2
    jb .Lwrite_armor_pad_two
    mov edx, r9d
    and edx, 15
    shl edx, 2
    mov ecx, r10d
    shr ecx, 6
    or edx, ecx
    mov dl, byte ptr [r15 + rdx]
    mov byte ptr [r13], dl
    inc r13
    inc r14
    jmp .Lwrite_armor_fourth

.Lwrite_armor_pad_two:
    mov byte ptr [r13], '='
    inc r13
    inc r14
    mov byte ptr [r13], '='
    inc r13
    inc r14
    jmp .Lwrite_armor_advance

.Lwrite_armor_fourth:
    cmp r8d, 3
    jb .Lwrite_armor_pad_one
    mov edx, r10d
    and edx, 63
    mov dl, byte ptr [r15 + rdx]
    mov byte ptr [r13], dl
    inc r13
    inc r14
    jmp .Lwrite_armor_advance

.Lwrite_armor_pad_one:
    mov byte ptr [r13], '='
    inc r13
    inc r14

.Lwrite_armor_advance:
    add rbx, r8
    sub r12, r8
    cmp r14, 64
    jne .Lwrite_armor_loop

    mov byte ptr [r13], 10
    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + io_buf]
    mov edx, 65
    call write_all
    test eax, eax
    jne .Lwrite_armor_fail_close
    lea r13, [rip + io_buf]
    xor r14d, r14d
    jmp .Lwrite_armor_loop

.Lwrite_armor_flush_tail:
    test r14, r14
    jz .Lwrite_armor_footer
    mov byte ptr [r13], 10
    mov rdx, r14
    inc rdx
    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + io_buf]
    call write_all
    test eax, eax
    jne .Lwrite_armor_fail_close

.Lwrite_armor_footer:
    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + armor_footer]
    mov edx, OFFSET FLAT:armor_footer_len
    call write_all
    test eax, eax
    jne .Lwrite_armor_fail_close
    mov rdi, qword ptr [rip + seal_output_fd]
    lea rsi, [rip + newline_msg]
    mov edx, OFFSET FLAT:newline_msg_len
    call write_all
    test eax, eax
    jne .Lwrite_armor_fail_close

    mov eax, SYS_CLOSE
    mov rdi, qword ptr [rip + seal_output_fd]
    syscall
    test rax, rax
    js .Lwrite_armor_fail
    mov eax, 1
    jmp .Lwrite_armor_done

.Lwrite_armor_fail_close:
    mov eax, SYS_CLOSE
    mov rdi, qword ptr [rip + seal_output_fd]
    syscall
.Lwrite_armor_fail:
    xor eax, eax
.Lwrite_armor_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

decode_armor_loaded_file:
    push rbx
    push r12
    push r13
    push r14
    push r15

    lea rbx, [rip + aead_open_buf]
    mov r12, rbx
    add r12, qword ptr [rip + aead_text_len]
    mov rax, r12
    sub rax, rbx
    cmp rax, OFFSET FLAT:armor_header_len
    jb .Ldecode_armor_fail

    mov rdi, rbx
    lea rsi, [rip + armor_header]
    mov edx, OFFSET FLAT:armor_header_len
    call memeq
    cmp eax, 1
    jne .Ldecode_armor_fail
    add rbx, OFFSET FLAT:armor_header_len

    lea r13, [rip + aead_open_buf]
    mov qword ptr [rip + base64_quad_len], 0
    mov qword ptr [rip + base64_quad_pad], 0
    mov qword ptr [rip + base64_seen_padding], 0

.Ldecode_armor_loop:
    cmp rbx, r12
    jae .Ldecode_armor_fail

.Ldecode_armor_skip_ws:
    cmp rbx, r12
    jae .Ldecode_armor_fail
    mov al, byte ptr [rbx]
    cmp al, 10
    je .Ldecode_armor_skip_one
    cmp al, 13
    je .Ldecode_armor_skip_one
    cmp al, 32
    je .Ldecode_armor_skip_one
    cmp al, 9
    jne .Ldecode_armor_check_footer
.Ldecode_armor_skip_one:
    inc rbx
    jmp .Ldecode_armor_skip_ws

.Ldecode_armor_check_footer:
    mov rax, r12
    sub rax, rbx
    cmp rax, OFFSET FLAT:armor_footer_len
    jb .Ldecode_armor_read_char
    mov rdi, rbx
    lea rsi, [rip + armor_footer]
    mov edx, OFFSET FLAT:armor_footer_len
    call memeq
    cmp eax, 1
    je .Ldecode_armor_footer

.Ldecode_armor_read_char:
    mov al, byte ptr [rbx]
    inc rbx
    cmp al, '='
    je .Ldecode_armor_padding
    cmp qword ptr [rip + base64_seen_padding], 0
    jne .Ldecode_armor_fail
    cmp qword ptr [rip + base64_quad_pad], 0
    jne .Ldecode_armor_fail
    movzx edi, al
    call base64_decode_char
    cmp eax, -1
    je .Ldecode_armor_fail
    jmp .Ldecode_armor_store_value

.Ldecode_armor_padding:
    cmp qword ptr [rip + base64_seen_padding], 0
    jne .Ldecode_armor_fail
    mov rcx, qword ptr [rip + base64_quad_len]
    cmp rcx, 2
    jb .Ldecode_armor_fail
    inc qword ptr [rip + base64_quad_pad]
    xor eax, eax

.Ldecode_armor_store_value:
    mov rcx, qword ptr [rip + base64_quad_len]
    cmp rcx, 4
    jae .Ldecode_armor_fail
    lea rdx, [rip + base64_quad]
    mov byte ptr [rdx + rcx], al
    inc rcx
    mov qword ptr [rip + base64_quad_len], rcx
    cmp rcx, 4
    jne .Ldecode_armor_loop

    call base64_emit_quad
    cmp eax, 1
    jne .Ldecode_armor_fail
    jmp .Ldecode_armor_loop

.Ldecode_armor_footer:
    cmp qword ptr [rip + base64_quad_len], 0
    jne .Ldecode_armor_fail
    add rbx, OFFSET FLAT:armor_footer_len

.Ldecode_armor_trailing_ws:
    cmp rbx, r12
    je .Ldecode_armor_ok
    mov al, byte ptr [rbx]
    cmp al, 10
    je .Ldecode_armor_trailing_skip
    cmp al, 13
    je .Ldecode_armor_trailing_skip
    cmp al, 32
    je .Ldecode_armor_trailing_skip
    cmp al, 9
    jne .Ldecode_armor_fail
.Ldecode_armor_trailing_skip:
    inc rbx
    jmp .Ldecode_armor_trailing_ws

.Ldecode_armor_ok:
    mov rax, r13
    lea rdx, [rip + aead_open_buf]
    sub rax, rdx
    mov qword ptr [rip + aead_text_len], rax
    mov eax, 1
    jmp .Ldecode_armor_done

.Ldecode_armor_fail:
    xor eax, eax
.Ldecode_armor_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

base64_emit_quad:
    mov rax, qword ptr [rip + base64_quad_pad]
    cmp rax, 2
    ja .Lbase64_emit_fail
    test rax, rax
    jz .Lbase64_emit_values
    mov qword ptr [rip + base64_seen_padding], 1

.Lbase64_emit_values:
    lea r15, [rip + base64_quad]
    movzx eax, byte ptr [r15]
    movzx edx, byte ptr [r15 + 1]
    mov ecx, eax
    shl ecx, 2
    mov r8d, edx
    shr r8d, 4
    or ecx, r8d
    mov byte ptr [r13], cl
    inc r13

    cmp qword ptr [rip + base64_quad_pad], 2
    je .Lbase64_emit_reset
    mov ecx, edx
    and ecx, 15
    shl ecx, 4
    movzx r8d, byte ptr [r15 + 2]
    mov r9d, r8d
    shr r9d, 2
    or ecx, r9d
    mov byte ptr [r13], cl
    inc r13

    cmp qword ptr [rip + base64_quad_pad], 1
    je .Lbase64_emit_reset
    mov ecx, r8d
    and ecx, 3
    shl ecx, 6
    movzx r9d, byte ptr [r15 + 3]
    or ecx, r9d
    mov byte ptr [r13], cl
    inc r13

.Lbase64_emit_reset:
    mov qword ptr [rip + base64_quad_len], 0
    mov qword ptr [rip + base64_quad_pad], 0
    mov eax, 1
    ret

.Lbase64_emit_fail:
    xor eax, eax
    ret

base64_decode_char:
    cmp dil, 'A'
    jb .Lbase64_decode_lower
    cmp dil, 'Z'
    ja .Lbase64_decode_lower
    movzx eax, dil
    sub eax, 'A'
    ret

.Lbase64_decode_lower:
    cmp dil, 'a'
    jb .Lbase64_decode_digit
    cmp dil, 'z'
    ja .Lbase64_decode_digit
    movzx eax, dil
    sub eax, 'a'
    add eax, 26
    ret

.Lbase64_decode_digit:
    cmp dil, '0'
    jb .Lbase64_decode_plus
    cmp dil, '9'
    ja .Lbase64_decode_plus
    movzx eax, dil
    sub eax, '0'
    add eax, 52
    ret

.Lbase64_decode_plus:
    cmp dil, '+'
    jne .Lbase64_decode_slash
    mov eax, 62
    ret

.Lbase64_decode_slash:
    cmp dil, '/'
    jne .Lbase64_decode_fail
    mov eax, 63
    ret

.Lbase64_decode_fail:
    mov eax, -1
    ret

frost_reduce_48_mod_order:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx

    mov qword ptr [rip + frost_rem0], 0
    mov qword ptr [rip + frost_rem1], 0
    mov qword ptr [rip + frost_rem2], 0
    mov qword ptr [rip + frost_rem3], 0

    xor r14d, r14d
.Lfrost_reduce_bit_loop:
    mov rax, qword ptr [rip + frost_rem0]
    add rax, rax
    mov qword ptr [rip + frost_rem0], rax
    mov rax, qword ptr [rip + frost_rem1]
    adc rax, rax
    mov qword ptr [rip + frost_rem1], rax
    mov rax, qword ptr [rip + frost_rem2]
    adc rax, rax
    mov qword ptr [rip + frost_rem2], rax
    mov rax, qword ptr [rip + frost_rem3]
    adc rax, rax
    mov qword ptr [rip + frost_rem3], rax
    setc r15b

    mov eax, r14d
    shr eax, 3
    movzx ecx, byte ptr [rbx + rax]
    mov eax, r14d
    and eax, 7
    mov edx, 7
    sub edx, eax
    mov eax, ecx
    mov ecx, edx
    shr eax, cl
    and eax, 1
    add qword ptr [rip + frost_rem0], rax
    adc qword ptr [rip + frost_rem1], 0
    adc qword ptr [rip + frost_rem2], 0
    adc qword ptr [rip + frost_rem3], 0
    setc al
    or r15b, al

    call frost_conditional_sub_order

    inc r14d
    cmp r14d, 384
    jne .Lfrost_reduce_bit_loop

    lea r15, [rip + frost_rem0]
    mov rax, qword ptr [r15 + 24]
    call store64_be_at_r13
    mov rax, qword ptr [r15 + 16]
    call store64_be_at_r13
    mov rax, qword ptr [r15 + 8]
    call store64_be_at_r13
    mov rax, qword ptr [r15]
    call store64_be_at_r13

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

frost_conditional_sub_order:
    mov r8, qword ptr [rip + frost_rem0]
    mov r9, qword ptr [rip + frost_rem1]
    mov r10, qword ptr [rip + frost_rem2]
    mov r11, qword ptr [rip + frost_rem3]

    mov rax, r8
    sub rax, qword ptr [r12]
    mov qword ptr [rip + frost_tmp0], rax
    mov rax, r9
    sbb rax, qword ptr [r12 + 8]
    mov qword ptr [rip + frost_tmp1], rax
    mov rax, r10
    sbb rax, qword ptr [r12 + 16]
    mov qword ptr [rip + frost_tmp2], rax
    mov rax, r11
    sbb rax, qword ptr [r12 + 24]
    mov qword ptr [rip + frost_tmp3], rax

    sbb rax, rax
    not rax
    movzx rcx, r15b
    neg rcx
    or rax, rcx
    mov rdx, rax
    not rdx

    mov rcx, qword ptr [rip + frost_tmp0]
    and rcx, rax
    and r8, rdx
    or rcx, r8
    mov qword ptr [rip + frost_rem0], rcx

    mov rcx, qword ptr [rip + frost_tmp1]
    and rcx, rax
    and r9, rdx
    or rcx, r9
    mov qword ptr [rip + frost_rem1], rcx

    mov rcx, qword ptr [rip + frost_tmp2]
    and rcx, rax
    and r10, rdx
    or rcx, r10
    mov qword ptr [rip + frost_rem2], rcx

    mov rcx, qword ptr [rip + frost_tmp3]
    and rcx, rax
    and r11, rdx
    or rcx, r11
    mov qword ptr [rip + frost_rem3], rcx
    ret

store64_be_at_r13:
    mov rdx, rax
    mov rcx, rdx
    shr rcx, 56
    mov byte ptr [r13], cl
    mov rcx, rdx
    shr rcx, 48
    mov byte ptr [r13 + 1], cl
    mov rcx, rdx
    shr rcx, 40
    mov byte ptr [r13 + 2], cl
    mov rcx, rdx
    shr rcx, 32
    mov byte ptr [r13 + 3], cl
    mov rcx, rdx
    shr rcx, 24
    mov byte ptr [r13 + 4], cl
    mov rcx, rdx
    shr rcx, 16
    mov byte ptr [r13 + 5], cl
    mov rcx, rdx
    shr rcx, 8
    mov byte ptr [r13 + 6], cl
    mov byte ptr [r13 + 7], dl
    add r13, 8
    ret

load_be32_to_le4:
    mov rax, qword ptr [rdi + 24]
    bswap rax
    mov qword ptr [rsi], rax
    mov rax, qword ptr [rdi + 16]
    bswap rax
    mov qword ptr [rsi + 8], rax
    mov rax, qword ptr [rdi + 8]
    bswap rax
    mov qword ptr [rsi + 16], rax
    mov rax, qword ptr [rdi]
    bswap rax
    mov qword ptr [rsi + 24], rax
    ret

store_le4_to_be32:
    push r13
    mov r13, rsi
    mov rax, qword ptr [rdi + 24]
    call store64_be_at_r13
    mov rax, qword ptr [rdi + 16]
    call store64_be_at_r13
    mov rax, qword ptr [rdi + 8]
    call store64_be_at_r13
    mov rax, qword ptr [rdi]
    call store64_be_at_r13
    pop r13
    ret

secp256k1_field_normalize_limbs:
    push r15
    xor r15d, r15d
    call secp256k1_field_conditional_sub_p
    pop r15
    ret

secp256k1_field_add_limbs:
    push r15
    mov r8, qword ptr [rdi]
    add r8, qword ptr [rsi]
    mov r9, qword ptr [rdi + 8]
    adc r9, qword ptr [rsi + 8]
    mov r10, qword ptr [rdi + 16]
    adc r10, qword ptr [rsi + 16]
    mov r11, qword ptr [rdi + 24]
    adc r11, qword ptr [rsi + 24]
    setc r15b

    mov qword ptr [rdx], r8
    mov qword ptr [rdx + 8], r9
    mov qword ptr [rdx + 16], r10
    mov qword ptr [rdx + 24], r11
    mov rdi, rdx
    call secp256k1_field_conditional_sub_p
    pop r15
    ret

secp256k1_field_sub_limbs:
    push rbx
    mov rbx, rdx
    mov r8, qword ptr [rdi]
    sub r8, qword ptr [rsi]
    mov r9, qword ptr [rdi + 8]
    sbb r9, qword ptr [rsi + 8]
    mov r10, qword ptr [rdi + 16]
    sbb r10, qword ptr [rsi + 16]
    mov r11, qword ptr [rdi + 24]
    sbb r11, qword ptr [rsi + 24]
    sbb rax, rax

    mov rcx, qword ptr [rip + secp256k1_field_p_le]
    and rcx, rax
    mov qword ptr [rip + secp256k1_field_tmp], rcx
    mov rcx, qword ptr [rip + secp256k1_field_p_le + 8]
    and rcx, rax
    mov qword ptr [rip + secp256k1_field_tmp + 8], rcx
    mov rcx, qword ptr [rip + secp256k1_field_p_le + 16]
    and rcx, rax
    mov qword ptr [rip + secp256k1_field_tmp + 16], rcx
    mov rcx, qword ptr [rip + secp256k1_field_p_le + 24]
    and rcx, rax
    mov qword ptr [rip + secp256k1_field_tmp + 24], rcx

    add r8, qword ptr [rip + secp256k1_field_tmp]
    adc r9, qword ptr [rip + secp256k1_field_tmp + 8]
    adc r10, qword ptr [rip + secp256k1_field_tmp + 16]
    adc r11, qword ptr [rip + secp256k1_field_tmp + 24]

    mov qword ptr [rbx], r8
    mov qword ptr [rbx + 8], r9
    mov qword ptr [rbx + 16], r10
    mov qword ptr [rbx + 24], r11
    pop rbx
    ret

secp256k1_field_mul_limbs:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rsi
    mov r13, rdx

    mov qword ptr [rip + secp256k1_field_acc], 0
    mov qword ptr [rip + secp256k1_field_acc + 8], 0
    mov qword ptr [rip + secp256k1_field_acc + 16], 0
    mov qword ptr [rip + secp256k1_field_acc + 24], 0

    mov rax, qword ptr [rdi]
    mov qword ptr [rip + secp256k1_field_mul_base], rax
    mov rax, qword ptr [rdi + 8]
    mov qword ptr [rip + secp256k1_field_mul_base + 8], rax
    mov rax, qword ptr [rdi + 16]
    mov qword ptr [rip + secp256k1_field_mul_base + 16], rax
    mov rax, qword ptr [rdi + 24]
    mov qword ptr [rip + secp256k1_field_mul_base + 24], rax

    xor r12d, r12d
.Lsecp256k1_field_mul_loop:
    mov eax, r12d
    shr eax, 6
    mov rdx, qword ptr [rbx + rax * 8]
    mov ecx, r12d
    and ecx, 63
    shr rdx, cl
    and edx, 1
    mov r14, rdx
    neg r14

    lea rdi, [rip + secp256k1_field_acc]
    lea rsi, [rip + secp256k1_field_mul_base]
    lea rdx, [rip + secp256k1_field_tmp]
    call secp256k1_field_add_limbs

    mov rdx, r14
    not rdx
    mov rax, qword ptr [rip + secp256k1_field_tmp]
    and rax, r14
    mov rcx, qword ptr [rip + secp256k1_field_acc]
    and rcx, rdx
    or rax, rcx
    mov qword ptr [rip + secp256k1_field_acc], rax

    mov rax, qword ptr [rip + secp256k1_field_tmp + 8]
    and rax, r14
    mov rcx, qword ptr [rip + secp256k1_field_acc + 8]
    and rcx, rdx
    or rax, rcx
    mov qword ptr [rip + secp256k1_field_acc + 8], rax

    mov rax, qword ptr [rip + secp256k1_field_tmp + 16]
    and rax, r14
    mov rcx, qword ptr [rip + secp256k1_field_acc + 16]
    and rcx, rdx
    or rax, rcx
    mov qword ptr [rip + secp256k1_field_acc + 16], rax

    mov rax, qword ptr [rip + secp256k1_field_tmp + 24]
    and rax, r14
    mov rcx, qword ptr [rip + secp256k1_field_acc + 24]
    and rcx, rdx
    or rax, rcx
    mov qword ptr [rip + secp256k1_field_acc + 24], rax

    lea rdi, [rip + secp256k1_field_mul_base]
    lea rsi, [rip + secp256k1_field_mul_base]
    lea rdx, [rip + secp256k1_field_mul_base]
    call secp256k1_field_add_limbs

    inc r12d
    cmp r12d, 256
    jne .Lsecp256k1_field_mul_loop

    mov rax, qword ptr [rip + secp256k1_field_acc]
    mov qword ptr [r13], rax
    mov rax, qword ptr [rip + secp256k1_field_acc + 8]
    mov qword ptr [r13 + 8], rax
    mov rax, qword ptr [rip + secp256k1_field_acc + 16]
    mov qword ptr [r13 + 16], rax
    mov rax, qword ptr [rip + secp256k1_field_acc + 24]
    mov qword ptr [r13 + 24], rax

    pop r14
    pop r13
    pop r12
    pop rbx
    ret

secp256k1_field_conditional_sub_p:
    mov r8, qword ptr [rdi]
    mov r9, qword ptr [rdi + 8]
    mov r10, qword ptr [rdi + 16]
    mov r11, qword ptr [rdi + 24]

    mov rax, r8
    sub rax, qword ptr [rip + secp256k1_field_p_le]
    mov qword ptr [rip + secp256k1_field_tmp], rax
    mov rax, r9
    sbb rax, qword ptr [rip + secp256k1_field_p_le + 8]
    mov qword ptr [rip + secp256k1_field_tmp + 8], rax
    mov rax, r10
    sbb rax, qword ptr [rip + secp256k1_field_p_le + 16]
    mov qword ptr [rip + secp256k1_field_tmp + 16], rax
    mov rax, r11
    sbb rax, qword ptr [rip + secp256k1_field_p_le + 24]
    mov qword ptr [rip + secp256k1_field_tmp + 24], rax

    sbb rax, rax
    not rax
    movzx rcx, r15b
    neg rcx
    or rax, rcx
    mov rdx, rax
    not rdx

    mov rcx, qword ptr [rip + secp256k1_field_tmp]
    and rcx, rax
    and r8, rdx
    or rcx, r8
    mov qword ptr [rdi], rcx

    mov rcx, qword ptr [rip + secp256k1_field_tmp + 8]
    and rcx, rax
    and r9, rdx
    or rcx, r9
    mov qword ptr [rdi + 8], rcx

    mov rcx, qword ptr [rip + secp256k1_field_tmp + 16]
    and rcx, rax
    and r10, rdx
    or rcx, r10
    mov qword ptr [rdi + 16], rcx

    mov rcx, qword ptr [rip + secp256k1_field_tmp + 24]
    and rcx, rax
    and r11, rdx
    or rcx, r11
    mov qword ptr [rdi + 24], rcx
    ret

copy_field4:
    mov rax, qword ptr [rdi]
    mov qword ptr [rsi], rax
    mov rax, qword ptr [rdi + 8]
    mov qword ptr [rsi + 8], rax
    mov rax, qword ptr [rdi + 16]
    mov qword ptr [rsi + 16], rax
    mov rax, qword ptr [rdi + 24]
    mov qword ptr [rsi + 24], rax
    ret

load_secp256k1_compressed_point_arg:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rsi
    mov r12, rdx
    mov r13, rcx
    mov rsi, rbx
    mov edx, 33
    call hex_decode_fixed
    cmp eax, 1
    jne .Lload_compressed_point_fail
    mov al, byte ptr [rbx]
    cmp al, 2
    je .Lload_compressed_point_prefix_ok
    cmp al, 3
    jne .Lload_compressed_point_fail

.Lload_compressed_point_prefix_ok:
    lea rdi, [rbx + 1]
    mov rsi, r12
    call load_be32_to_le4
    mov rdi, r12
    call secp256k1_field_is_canonical_limbs
    cmp eax, 1
    jne .Lload_compressed_point_fail
    mov rdi, r12
    mov rsi, r12
    lea rdx, [rip + secp256k1_point_t0]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_point_t0]
    mov rsi, r12
    lea rdx, [rip + secp256k1_point_t0]
    call secp256k1_field_mul_limbs
    mov qword ptr [rip + secp256k1_point_t1], 7
    mov qword ptr [rip + secp256k1_point_t1 + 8], 0
    mov qword ptr [rip + secp256k1_point_t1 + 16], 0
    mov qword ptr [rip + secp256k1_point_t1 + 24], 0
    lea rdi, [rip + secp256k1_point_t0]
    lea rsi, [rip + secp256k1_point_t1]
    lea rdx, [rip + secp256k1_point_t0]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_point_t0]
    mov rsi, r13
    call secp256k1_field_sqrt_limbs
    mov rdi, r13
    mov rsi, r13
    lea rdx, [rip + secp256k1_point_t1]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_point_t1]
    lea rsi, [rip + secp256k1_point_t0]
    call secp256k1_field_equal_limbs
    cmp eax, 1
    jne .Lload_compressed_point_fail
    mov al, byte ptr [rbx]
    and al, 1
    mov dl, byte ptr [r13]
    and dl, 1
    cmp al, dl
    je .Lload_compressed_point_success
    mov qword ptr [rip + secp256k1_point_t2], 0
    mov qword ptr [rip + secp256k1_point_t2 + 8], 0
    mov qword ptr [rip + secp256k1_point_t2 + 16], 0
    mov qword ptr [rip + secp256k1_point_t2 + 24], 0
    lea rdi, [rip + secp256k1_point_t2]
    mov rsi, r13
    mov rdx, r13
    call secp256k1_field_sub_limbs

.Lload_compressed_point_success:
    mov eax, 1
    jmp .Lload_compressed_point_done

.Lload_compressed_point_fail:
    xor eax, eax

.Lload_compressed_point_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

encode_secp256k1_compressed_point:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rdx
    mov al, byte ptr [rsi]
    and al, 1
    add al, 2
    mov byte ptr [r12], al
    mov rdi, rbx
    lea rsi, [r12 + 1]
    call store_le4_to_be32
    pop r12
    pop rbx
    ret

frost_secp256k1_commit_scalar:
    push rbx
    mov rbx, rsi
    call secp256k1_projective_basepoint_mul_limbs
    cmp eax, 1
    jne .Lfrost_commit_scalar_fail
    lea rdi, [rip + secp256k1_jacobian_rx]
    lea rsi, [rip + secp256k1_jacobian_ry]
    lea rdx, [rip + secp256k1_jacobian_rz]
    lea rcx, [rip + secp256k1_point_rx]
    lea r8, [rip + secp256k1_point_ry]
    call secp256k1_jacobian_to_affine_limbs
    cmp eax, 1
    jne .Lfrost_commit_scalar_fail
    mov al, byte ptr [rip + secp256k1_point_ry]
    and al, 1
    add al, 2
    mov byte ptr [rbx], al
    lea rdi, [rip + secp256k1_point_rx]
    lea rsi, [rbx + 1]
    call store_le4_to_be32
    mov eax, 1
    jmp .Lfrost_commit_scalar_done

.Lfrost_commit_scalar_fail:
    xor eax, eax

.Lfrost_commit_scalar_done:
    pop rbx
    ret

secp256k1_scalar_gt_limbs:
    mov rax, qword ptr [rdi + 24]
    cmp rax, qword ptr [rsi + 24]
    ja .Lsecp256k1_scalar_gt_yes
    jb .Lsecp256k1_scalar_gt_no
    mov rax, qword ptr [rdi + 16]
    cmp rax, qword ptr [rsi + 16]
    ja .Lsecp256k1_scalar_gt_yes
    jb .Lsecp256k1_scalar_gt_no
    mov rax, qword ptr [rdi + 8]
    cmp rax, qword ptr [rsi + 8]
    ja .Lsecp256k1_scalar_gt_yes
    jb .Lsecp256k1_scalar_gt_no
    mov rax, qword ptr [rdi]
    cmp rax, qword ptr [rsi]
    ja .Lsecp256k1_scalar_gt_yes
.Lsecp256k1_scalar_gt_no:
    xor eax, eax
    ret
.Lsecp256k1_scalar_gt_yes:
    mov eax, 1
    ret

secp256k1_field_select_mask:
    mov r10, rcx
    not r10

    mov r8, qword ptr [rsi]
    and r8, rcx
    mov r9, qword ptr [rdi]
    and r9, r10
    or r8, r9
    mov qword ptr [rdx], r8

    mov r8, qword ptr [rsi + 8]
    and r8, rcx
    mov r9, qword ptr [rdi + 8]
    and r9, r10
    or r8, r9
    mov qword ptr [rdx + 8], r8

    mov r8, qword ptr [rsi + 16]
    and r8, rcx
    mov r9, qword ptr [rdi + 16]
    and r9, r10
    or r8, r9
    mov qword ptr [rdx + 16], r8

    mov r8, qword ptr [rsi + 24]
    and r8, rcx
    mov r9, qword ptr [rdi + 24]
    and r9, r10
    or r8, r9
    mov qword ptr [rdx + 24], r8
    ret

secp256k1_field_is_zero_limbs:
    mov rax, qword ptr [rdi]
    or rax, qword ptr [rdi + 8]
    or rax, qword ptr [rdi + 16]
    or rax, qword ptr [rdi + 24]
    sete al
    movzx eax, al
    ret

secp256k1_field_equal_limbs:
    mov rax, qword ptr [rdi]
    xor rax, qword ptr [rsi]
    mov rdx, qword ptr [rdi + 8]
    xor rdx, qword ptr [rsi + 8]
    or rax, rdx
    mov rdx, qword ptr [rdi + 16]
    xor rdx, qword ptr [rsi + 16]
    or rax, rdx
    mov rdx, qword ptr [rdi + 24]
    xor rdx, qword ptr [rsi + 24]
    or rax, rdx
    sete al
    movzx eax, al
    ret

secp256k1_field_is_canonical_limbs:
    mov rax, qword ptr [rdi + 24]
    cmp rax, qword ptr [rip + secp256k1_field_p_le + 24]
    jb .Lsecp256k1_canonical_yes
    ja .Lsecp256k1_canonical_no
    mov rax, qword ptr [rdi + 16]
    cmp rax, qword ptr [rip + secp256k1_field_p_le + 16]
    jb .Lsecp256k1_canonical_yes
    ja .Lsecp256k1_canonical_no
    mov rax, qword ptr [rdi + 8]
    cmp rax, qword ptr [rip + secp256k1_field_p_le + 8]
    jb .Lsecp256k1_canonical_yes
    ja .Lsecp256k1_canonical_no
    mov rax, qword ptr [rdi]
    cmp rax, qword ptr [rip + secp256k1_field_p_le]
    jb .Lsecp256k1_canonical_yes
.Lsecp256k1_canonical_no:
    xor eax, eax
    ret
.Lsecp256k1_canonical_yes:
    mov eax, 1
    ret

load_secp256k1_scalar_arg:
    push rbx
    mov rbx, rsi
    lea rsi, [rip + secp256k1_scalar_bytes]
    call hex32_decode
    cmp eax, 1
    jne .Lload_secp256k1_scalar_arg_hex_fail
    lea rdi, [rip + secp256k1_scalar_bytes]
    mov rsi, rbx
    call load_be32_to_le4
    mov rdi, rbx
    call secp256k1_scalar_is_canonical_limbs
    cmp eax, 1
    jne .Lload_secp256k1_scalar_arg_noncanonical
    mov eax, 1
    jmp .Lload_secp256k1_scalar_arg_done

.Lload_secp256k1_scalar_arg_noncanonical:
    mov eax, 2
    jmp .Lload_secp256k1_scalar_arg_done

.Lload_secp256k1_scalar_arg_hex_fail:
    xor eax, eax

.Lload_secp256k1_scalar_arg_done:
    pop rbx
    ret

secp256k1_scalar_add_limbs:
    push r15
    mov r8, qword ptr [rdi]
    add r8, qword ptr [rsi]
    mov r9, qword ptr [rdi + 8]
    adc r9, qword ptr [rsi + 8]
    mov r10, qword ptr [rdi + 16]
    adc r10, qword ptr [rsi + 16]
    mov r11, qword ptr [rdi + 24]
    adc r11, qword ptr [rsi + 24]
    setc r15b

    mov qword ptr [rdx], r8
    mov qword ptr [rdx + 8], r9
    mov qword ptr [rdx + 16], r10
    mov qword ptr [rdx + 24], r11
    mov rdi, rdx
    call secp256k1_scalar_conditional_sub_n
    pop r15
    ret

secp256k1_scalar_sub_limbs:
    push rbx
    mov rbx, rdx
    mov r8, qword ptr [rdi]
    sub r8, qword ptr [rsi]
    mov r9, qword ptr [rdi + 8]
    sbb r9, qword ptr [rsi + 8]
    mov r10, qword ptr [rdi + 16]
    sbb r10, qword ptr [rsi + 16]
    mov r11, qword ptr [rdi + 24]
    sbb r11, qword ptr [rsi + 24]
    sbb rax, rax

    mov rcx, qword ptr [rip + frost_secp256k1_order_le]
    and rcx, rax
    mov qword ptr [rip + secp256k1_scalar_tmp], rcx
    mov rcx, qword ptr [rip + frost_secp256k1_order_le + 8]
    and rcx, rax
    mov qword ptr [rip + secp256k1_scalar_tmp + 8], rcx
    mov rcx, qword ptr [rip + frost_secp256k1_order_le + 16]
    and rcx, rax
    mov qword ptr [rip + secp256k1_scalar_tmp + 16], rcx
    mov rcx, qword ptr [rip + frost_secp256k1_order_le + 24]
    and rcx, rax
    mov qword ptr [rip + secp256k1_scalar_tmp + 24], rcx

    add r8, qword ptr [rip + secp256k1_scalar_tmp]
    adc r9, qword ptr [rip + secp256k1_scalar_tmp + 8]
    adc r10, qword ptr [rip + secp256k1_scalar_tmp + 16]
    adc r11, qword ptr [rip + secp256k1_scalar_tmp + 24]

    mov qword ptr [rbx], r8
    mov qword ptr [rbx + 8], r9
    mov qword ptr [rbx + 16], r10
    mov qword ptr [rbx + 24], r11
    pop rbx
    ret

secp256k1_scalar_mul_limbs:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rsi
    mov r13, rdx

    mov qword ptr [rip + secp256k1_scalar_acc], 0
    mov qword ptr [rip + secp256k1_scalar_acc + 8], 0
    mov qword ptr [rip + secp256k1_scalar_acc + 16], 0
    mov qword ptr [rip + secp256k1_scalar_acc + 24], 0

    mov rax, qword ptr [rdi]
    mov qword ptr [rip + secp256k1_scalar_mul_base], rax
    mov rax, qword ptr [rdi + 8]
    mov qword ptr [rip + secp256k1_scalar_mul_base + 8], rax
    mov rax, qword ptr [rdi + 16]
    mov qword ptr [rip + secp256k1_scalar_mul_base + 16], rax
    mov rax, qword ptr [rdi + 24]
    mov qword ptr [rip + secp256k1_scalar_mul_base + 24], rax

    xor r12d, r12d
.Lsecp256k1_scalar_mul_loop:
    mov eax, r12d
    shr eax, 6
    mov rdx, qword ptr [rbx + rax * 8]
    mov ecx, r12d
    and ecx, 63
    shr rdx, cl
    and edx, 1
    mov r14, rdx
    neg r14

    lea rdi, [rip + secp256k1_scalar_acc]
    lea rsi, [rip + secp256k1_scalar_mul_base]
    lea rdx, [rip + secp256k1_scalar_tmp]
    call secp256k1_scalar_add_limbs

    mov rdx, r14
    not rdx
    mov rax, qword ptr [rip + secp256k1_scalar_tmp]
    and rax, r14
    mov rcx, qword ptr [rip + secp256k1_scalar_acc]
    and rcx, rdx
    or rax, rcx
    mov qword ptr [rip + secp256k1_scalar_acc], rax

    mov rax, qword ptr [rip + secp256k1_scalar_tmp + 8]
    and rax, r14
    mov rcx, qword ptr [rip + secp256k1_scalar_acc + 8]
    and rcx, rdx
    or rax, rcx
    mov qword ptr [rip + secp256k1_scalar_acc + 8], rax

    mov rax, qword ptr [rip + secp256k1_scalar_tmp + 16]
    and rax, r14
    mov rcx, qword ptr [rip + secp256k1_scalar_acc + 16]
    and rcx, rdx
    or rax, rcx
    mov qword ptr [rip + secp256k1_scalar_acc + 16], rax

    mov rax, qword ptr [rip + secp256k1_scalar_tmp + 24]
    and rax, r14
    mov rcx, qword ptr [rip + secp256k1_scalar_acc + 24]
    and rcx, rdx
    or rax, rcx
    mov qword ptr [rip + secp256k1_scalar_acc + 24], rax

    lea rdi, [rip + secp256k1_scalar_mul_base]
    lea rsi, [rip + secp256k1_scalar_mul_base]
    lea rdx, [rip + secp256k1_scalar_mul_base]
    call secp256k1_scalar_add_limbs

    inc r12d
    cmp r12d, 256
    jne .Lsecp256k1_scalar_mul_loop

    lea rdi, [rip + secp256k1_scalar_acc]
    mov rsi, r13
    call copy_field4

    pop r14
    pop r13
    pop r12
    pop rbx
    ret

secp256k1_scalar_inverse_limbs:
    push rbx
    push r12
    push r13
    mov rbx, rsi
    lea rsi, [rip + secp256k1_scalar_inv_base]
    call copy_field4

    mov qword ptr [rip + secp256k1_scalar_inv_result], 1
    mov qword ptr [rip + secp256k1_scalar_inv_result + 8], 0
    mov qword ptr [rip + secp256k1_scalar_inv_result + 16], 0
    mov qword ptr [rip + secp256k1_scalar_inv_result + 24], 0

    lea r13, [rip + frost_secp256k1_order_minus_2_le]
    xor r12d, r12d
.Lsecp256k1_scalar_inverse_loop:
    mov eax, r12d
    shr eax, 6
    mov rdx, qword ptr [r13 + rax * 8]
    mov ecx, r12d
    and ecx, 63
    shr rdx, cl
    test dl, 1
    jz .Lsecp256k1_scalar_inverse_skip_mul
    lea rdi, [rip + secp256k1_scalar_inv_result]
    lea rsi, [rip + secp256k1_scalar_inv_base]
    lea rdx, [rip + secp256k1_scalar_inv_tmp]
    call secp256k1_scalar_mul_limbs
    lea rdi, [rip + secp256k1_scalar_inv_tmp]
    lea rsi, [rip + secp256k1_scalar_inv_result]
    call copy_field4

.Lsecp256k1_scalar_inverse_skip_mul:
    lea rdi, [rip + secp256k1_scalar_inv_base]
    lea rsi, [rip + secp256k1_scalar_inv_base]
    lea rdx, [rip + secp256k1_scalar_inv_base]
    call secp256k1_scalar_mul_limbs
    inc r12d
    cmp r12d, 256
    jne .Lsecp256k1_scalar_inverse_loop

    lea rdi, [rip + secp256k1_scalar_inv_result]
    mov rsi, rbx
    call copy_field4

    pop r13
    pop r12
    pop rbx
    ret

secp256k1_scalar_conditional_sub_n:
    mov r8, qword ptr [rdi]
    mov r9, qword ptr [rdi + 8]
    mov r10, qword ptr [rdi + 16]
    mov r11, qword ptr [rdi + 24]

    mov rax, r8
    sub rax, qword ptr [rip + frost_secp256k1_order_le]
    mov qword ptr [rip + secp256k1_scalar_tmp], rax
    mov rax, r9
    sbb rax, qword ptr [rip + frost_secp256k1_order_le + 8]
    mov qword ptr [rip + secp256k1_scalar_tmp + 8], rax
    mov rax, r10
    sbb rax, qword ptr [rip + frost_secp256k1_order_le + 16]
    mov qword ptr [rip + secp256k1_scalar_tmp + 16], rax
    mov rax, r11
    sbb rax, qword ptr [rip + frost_secp256k1_order_le + 24]
    mov qword ptr [rip + secp256k1_scalar_tmp + 24], rax

    sbb rax, rax
    not rax
    movzx rcx, r15b
    neg rcx
    or rax, rcx
    mov rdx, rax
    not rdx

    mov rcx, qword ptr [rip + secp256k1_scalar_tmp]
    and rcx, rax
    and r8, rdx
    or rcx, r8
    mov qword ptr [rdi], rcx

    mov rcx, qword ptr [rip + secp256k1_scalar_tmp + 8]
    and rcx, rax
    and r9, rdx
    or rcx, r9
    mov qword ptr [rdi + 8], rcx

    mov rcx, qword ptr [rip + secp256k1_scalar_tmp + 16]
    and rcx, rax
    and r10, rdx
    or rcx, r10
    mov qword ptr [rdi + 16], rcx

    mov rcx, qword ptr [rip + secp256k1_scalar_tmp + 24]
    and rcx, rax
    and r11, rdx
    or rcx, r11
    mov qword ptr [rdi + 24], rcx
    ret

secp256k1_scalar_is_zero_limbs:
    jmp secp256k1_field_is_zero_limbs

secp256k1_scalar_equal_limbs:
    jmp secp256k1_field_equal_limbs

secp256k1_scalar_is_canonical_limbs:
    mov rax, qword ptr [rdi + 24]
    cmp rax, qword ptr [rip + frost_secp256k1_order_le + 24]
    jb .Lsecp256k1_scalar_canonical_yes
    ja .Lsecp256k1_scalar_canonical_no
    mov rax, qword ptr [rdi + 16]
    cmp rax, qword ptr [rip + frost_secp256k1_order_le + 16]
    jb .Lsecp256k1_scalar_canonical_yes
    ja .Lsecp256k1_scalar_canonical_no
    mov rax, qword ptr [rdi + 8]
    cmp rax, qword ptr [rip + frost_secp256k1_order_le + 8]
    jb .Lsecp256k1_scalar_canonical_yes
    ja .Lsecp256k1_scalar_canonical_no
    mov rax, qword ptr [rdi]
    cmp rax, qword ptr [rip + frost_secp256k1_order_le]
    jb .Lsecp256k1_scalar_canonical_yes
.Lsecp256k1_scalar_canonical_no:
    xor eax, eax
    ret
.Lsecp256k1_scalar_canonical_yes:
    mov eax, 1
    ret

load_secp256k1_point_xy:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx

    mov rdi, rbx
    lea rsi, [rip + secp256k1_field_a_bytes]
    call hex32_decode
    cmp eax, 1
    jne .Lload_secp256k1_point_hex_fail
    lea rdi, [rip + secp256k1_field_a_bytes]
    mov rsi, r13
    call load_be32_to_le4
    mov rdi, r13
    call secp256k1_field_is_canonical_limbs
    cmp eax, 1
    jne .Lload_secp256k1_point_noncanonical

    mov rdi, r12
    lea rsi, [rip + secp256k1_field_b_bytes]
    call hex32_decode
    cmp eax, 1
    jne .Lload_secp256k1_point_hex_fail
    lea rdi, [rip + secp256k1_field_b_bytes]
    mov rsi, r14
    call load_be32_to_le4
    mov rdi, r14
    call secp256k1_field_is_canonical_limbs
    cmp eax, 1
    jne .Lload_secp256k1_point_noncanonical

    mov eax, 1
    jmp .Lload_secp256k1_point_done

.Lload_secp256k1_point_noncanonical:
    mov eax, 2
    jmp .Lload_secp256k1_point_done

.Lload_secp256k1_point_hex_fail:
    xor eax, eax

.Lload_secp256k1_point_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

load_secp256k1_field_arg:
    push rbx
    mov rbx, rsi
    lea rsi, [rip + secp256k1_field_a_bytes]
    call hex32_decode
    cmp eax, 1
    jne .Lload_secp256k1_field_arg_hex_fail
    lea rdi, [rip + secp256k1_field_a_bytes]
    mov rsi, rbx
    call load_be32_to_le4
    mov rdi, rbx
    call secp256k1_field_is_canonical_limbs
    cmp eax, 1
    jne .Lload_secp256k1_field_arg_noncanonical
    mov eax, 1
    jmp .Lload_secp256k1_field_arg_done

.Lload_secp256k1_field_arg_noncanonical:
    mov eax, 2
    jmp .Lload_secp256k1_field_arg_done

.Lload_secp256k1_field_arg_hex_fail:
    xor eax, eax

.Lload_secp256k1_field_arg_done:
    pop rbx
    ret

secp256k1_field_inverse_limbs:
    push rbx
    push r12
    push r13
    mov rbx, rsi

    mov rsi, rdi
    lea rdi, [rip + secp256k1_inv_base]
    xchg rdi, rsi
    call copy_field4

    mov qword ptr [rip + secp256k1_inv_result], 1
    mov qword ptr [rip + secp256k1_inv_result + 8], 0
    mov qword ptr [rip + secp256k1_inv_result + 16], 0
    mov qword ptr [rip + secp256k1_inv_result + 24], 0

    lea r13, [rip + secp256k1_field_p_minus_2_le]
    xor r12d, r12d
.Lsecp256k1_inverse_loop:
    mov eax, r12d
    shr eax, 6
    mov rdx, qword ptr [r13 + rax * 8]
    mov ecx, r12d
    and ecx, 63
    shr rdx, cl
    test dl, 1
    jz .Lsecp256k1_inverse_skip_mul
    lea rdi, [rip + secp256k1_inv_result]
    lea rsi, [rip + secp256k1_inv_base]
    lea rdx, [rip + secp256k1_inv_tmp]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_inv_tmp]
    lea rsi, [rip + secp256k1_inv_result]
    call copy_field4

.Lsecp256k1_inverse_skip_mul:
    lea rdi, [rip + secp256k1_inv_base]
    lea rsi, [rip + secp256k1_inv_base]
    lea rdx, [rip + secp256k1_inv_base]
    call secp256k1_field_mul_limbs
    inc r12d
    cmp r12d, 256
    jne .Lsecp256k1_inverse_loop

    lea rdi, [rip + secp256k1_inv_result]
    mov rsi, rbx
    call copy_field4

    pop r13
    pop r12
    pop rbx
    ret

secp256k1_field_sqrt_limbs:
    push rbx
    push r12
    push r13
    mov rbx, rsi

    mov rsi, rdi
    lea rdi, [rip + secp256k1_inv_base]
    xchg rdi, rsi
    call copy_field4

    mov qword ptr [rip + secp256k1_inv_result], 1
    mov qword ptr [rip + secp256k1_inv_result + 8], 0
    mov qword ptr [rip + secp256k1_inv_result + 16], 0
    mov qword ptr [rip + secp256k1_inv_result + 24], 0

    lea r13, [rip + secp256k1_field_sqrt_exp_le]
    xor r12d, r12d
.Lsecp256k1_sqrt_loop:
    mov eax, r12d
    shr eax, 6
    mov rdx, qword ptr [r13 + rax * 8]
    mov ecx, r12d
    and ecx, 63
    shr rdx, cl
    test dl, 1
    jz .Lsecp256k1_sqrt_skip_mul
    lea rdi, [rip + secp256k1_inv_result]
    lea rsi, [rip + secp256k1_inv_base]
    lea rdx, [rip + secp256k1_inv_tmp]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_inv_tmp]
    lea rsi, [rip + secp256k1_inv_result]
    call copy_field4

.Lsecp256k1_sqrt_skip_mul:
    lea rdi, [rip + secp256k1_inv_base]
    lea rsi, [rip + secp256k1_inv_base]
    lea rdx, [rip + secp256k1_inv_base]
    call secp256k1_field_mul_limbs
    inc r12d
    cmp r12d, 256
    jne .Lsecp256k1_sqrt_loop

    lea rdi, [rip + secp256k1_inv_result]
    mov rsi, rbx
    call copy_field4

    pop r13
    pop r12
    pop rbx
    ret

secp256k1_point_validate_limbs:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi

    mov rdi, r12
    mov rsi, r12
    lea rdx, [rip + secp256k1_point_t0]
    call secp256k1_field_mul_limbs

    mov rdi, rbx
    mov rsi, rbx
    lea rdx, [rip + secp256k1_point_t1]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_point_t1]
    mov rsi, rbx
    lea rdx, [rip + secp256k1_point_t1]
    call secp256k1_field_mul_limbs

    mov qword ptr [rip + secp256k1_point_t2], 7
    mov qword ptr [rip + secp256k1_point_t2 + 8], 0
    mov qword ptr [rip + secp256k1_point_t2 + 16], 0
    mov qword ptr [rip + secp256k1_point_t2 + 24], 0
    lea rdi, [rip + secp256k1_point_t1]
    lea rsi, [rip + secp256k1_point_t2]
    lea rdx, [rip + secp256k1_point_t1]
    call secp256k1_field_add_limbs

    lea rdi, [rip + secp256k1_point_t0]
    lea rsi, [rip + secp256k1_point_t1]
    call secp256k1_field_equal_limbs

    pop r12
    pop rbx
    ret

secp256k1_point_double_limbs:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx

    mov rdi, r12
    call secp256k1_field_is_zero_limbs
    cmp eax, 1
    je .Lsecp256k1_point_double_infinity

    mov rdi, rbx
    mov rsi, rbx
    lea rdx, [rip + secp256k1_point_t0]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_point_t0]
    lea rsi, [rip + secp256k1_point_t0]
    lea rdx, [rip + secp256k1_point_t1]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_point_t1]
    lea rsi, [rip + secp256k1_point_t0]
    lea rdx, [rip + secp256k1_point_t0]
    call secp256k1_field_add_limbs

    mov rdi, r12
    mov rsi, r12
    lea rdx, [rip + secp256k1_point_t1]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_point_t1]
    lea rsi, [rip + secp256k1_point_t2]
    call secp256k1_field_inverse_limbs
    lea rdi, [rip + secp256k1_point_t0]
    lea rsi, [rip + secp256k1_point_t2]
    lea rdx, [rip + secp256k1_point_t3]
    call secp256k1_field_mul_limbs

    lea rdi, [rip + secp256k1_point_t3]
    lea rsi, [rip + secp256k1_point_t3]
    lea rdx, [rip + secp256k1_point_t4]
    call secp256k1_field_mul_limbs
    mov rdi, rbx
    mov rsi, rbx
    lea rdx, [rip + secp256k1_point_t1]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_point_t4]
    lea rsi, [rip + secp256k1_point_t1]
    mov rdx, r13
    call secp256k1_field_sub_limbs

    mov rdi, rbx
    mov rsi, r13
    lea rdx, [rip + secp256k1_point_t4]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_point_t3]
    lea rsi, [rip + secp256k1_point_t4]
    lea rdx, [rip + secp256k1_point_t5]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_point_t5]
    mov rsi, r12
    mov rdx, r14
    call secp256k1_field_sub_limbs

    mov eax, 1
    jmp .Lsecp256k1_point_double_done

.Lsecp256k1_point_double_infinity:
    xor eax, eax

.Lsecp256k1_point_double_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

secp256k1_point_add_limbs:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push r9
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8

    mov rdi, rbx
    mov rsi, r13
    call secp256k1_field_equal_limbs
    cmp eax, 1
    jne .Lsecp256k1_point_add_distinct_x
    mov rdi, r12
    mov rsi, r14
    call secp256k1_field_equal_limbs
    cmp eax, 1
    jne .Lsecp256k1_point_add_infinity
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r15
    mov rcx, qword ptr [rsp]
    call secp256k1_point_double_limbs
    jmp .Lsecp256k1_point_add_done

.Lsecp256k1_point_add_distinct_x:
    mov rdi, r14
    mov rsi, r12
    lea rdx, [rip + secp256k1_point_t0]
    call secp256k1_field_sub_limbs
    mov rdi, r13
    mov rsi, rbx
    lea rdx, [rip + secp256k1_point_t1]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_point_t1]
    lea rsi, [rip + secp256k1_point_t2]
    call secp256k1_field_inverse_limbs
    lea rdi, [rip + secp256k1_point_t0]
    lea rsi, [rip + secp256k1_point_t2]
    lea rdx, [rip + secp256k1_point_t3]
    call secp256k1_field_mul_limbs

    lea rdi, [rip + secp256k1_point_t3]
    lea rsi, [rip + secp256k1_point_t3]
    lea rdx, [rip + secp256k1_point_t4]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_point_t4]
    mov rsi, rbx
    lea rdx, [rip + secp256k1_point_t4]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_point_t4]
    mov rsi, r13
    mov rdx, r15
    call secp256k1_field_sub_limbs

    mov rdi, rbx
    mov rsi, r15
    lea rdx, [rip + secp256k1_point_t4]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_point_t3]
    lea rsi, [rip + secp256k1_point_t4]
    lea rdx, [rip + secp256k1_point_t5]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_point_t5]
    mov rsi, r12
    mov rdx, qword ptr [rsp]
    call secp256k1_field_sub_limbs

    mov eax, 1
    jmp .Lsecp256k1_point_add_done

.Lsecp256k1_point_add_infinity:
    xor eax, eax

.Lsecp256k1_point_add_done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

secp256k1_point_mul_limbs:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push r8
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx

    mov rdi, rbx
    call secp256k1_field_is_zero_limbs
    cmp eax, 1
    je .Lsecp256k1_point_mul_infinity

    mov rdi, r12
    lea rsi, [rip + secp256k1_point_base_x]
    call copy_field4
    mov rdi, r13
    lea rsi, [rip + secp256k1_point_base_y]
    call copy_field4
    mov qword ptr [rip + secp256k1_point_acc_infinity], 1

    xor r15d, r15d
.Lsecp256k1_point_mul_loop:
    mov eax, r15d
    shr eax, 6
    mov rdx, qword ptr [rbx + rax * 8]
    mov ecx, r15d
    and ecx, 63
    shr rdx, cl
    test dl, 1
    jz .Lsecp256k1_point_mul_skip_add

    cmp qword ptr [rip + secp256k1_point_acc_infinity], 1
    jne .Lsecp256k1_point_mul_add_acc
    lea rdi, [rip + secp256k1_point_base_x]
    lea rsi, [rip + secp256k1_point_acc_x]
    call copy_field4
    lea rdi, [rip + secp256k1_point_base_y]
    lea rsi, [rip + secp256k1_point_acc_y]
    call copy_field4
    mov qword ptr [rip + secp256k1_point_acc_infinity], 0
    jmp .Lsecp256k1_point_mul_skip_add

.Lsecp256k1_point_mul_add_acc:
    lea rdi, [rip + secp256k1_point_acc_x]
    lea rsi, [rip + secp256k1_point_acc_y]
    lea rdx, [rip + secp256k1_point_base_x]
    lea rcx, [rip + secp256k1_point_base_y]
    lea r8, [rip + secp256k1_point_rx]
    lea r9, [rip + secp256k1_point_ry]
    call secp256k1_point_add_limbs
    cmp eax, 1
    jne .Lsecp256k1_point_mul_add_infinity
    lea rdi, [rip + secp256k1_point_rx]
    lea rsi, [rip + secp256k1_point_acc_x]
    call copy_field4
    lea rdi, [rip + secp256k1_point_ry]
    lea rsi, [rip + secp256k1_point_acc_y]
    call copy_field4
    mov qword ptr [rip + secp256k1_point_acc_infinity], 0
    jmp .Lsecp256k1_point_mul_skip_add

.Lsecp256k1_point_mul_add_infinity:
    mov qword ptr [rip + secp256k1_point_acc_infinity], 1

.Lsecp256k1_point_mul_skip_add:
    lea rdi, [rip + secp256k1_point_base_x]
    lea rsi, [rip + secp256k1_point_base_y]
    lea rdx, [rip + secp256k1_point_rx]
    lea rcx, [rip + secp256k1_point_ry]
    call secp256k1_point_double_limbs
    cmp eax, 1
    jne .Lsecp256k1_point_mul_base_infinity
    lea rdi, [rip + secp256k1_point_rx]
    lea rsi, [rip + secp256k1_point_base_x]
    call copy_field4
    lea rdi, [rip + secp256k1_point_ry]
    lea rsi, [rip + secp256k1_point_base_y]
    call copy_field4

.Lsecp256k1_point_mul_base_infinity:
    inc r15d
    cmp r15d, 256
    jne .Lsecp256k1_point_mul_loop

    cmp qword ptr [rip + secp256k1_point_acc_infinity], 1
    je .Lsecp256k1_point_mul_infinity
    lea rdi, [rip + secp256k1_point_acc_x]
    mov rsi, r14
    call copy_field4
    lea rdi, [rip + secp256k1_point_acc_y]
    mov rsi, qword ptr [rsp]
    call copy_field4
    mov eax, 1
    jmp .Lsecp256k1_point_mul_done

.Lsecp256k1_point_mul_infinity:
    xor eax, eax

.Lsecp256k1_point_mul_done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

secp256k1_jacobian_to_affine_limbs:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8

    mov rdi, r13
    call secp256k1_field_is_zero_limbs
    cmp eax, 1
    je .Lsecp256k1_jacobian_to_affine_infinity

    mov rdi, r13
    lea rsi, [rip + secp256k1_jacobian_t0]
    call secp256k1_field_inverse_limbs
    lea rdi, [rip + secp256k1_jacobian_t0]
    lea rsi, [rip + secp256k1_jacobian_t0]
    lea rdx, [rip + secp256k1_jacobian_t1]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_t1]
    lea rsi, [rip + secp256k1_jacobian_t0]
    lea rdx, [rip + secp256k1_jacobian_t2]
    call secp256k1_field_mul_limbs
    mov rdi, rbx
    lea rsi, [rip + secp256k1_jacobian_t1]
    mov rdx, r14
    call secp256k1_field_mul_limbs
    mov rdi, r12
    lea rsi, [rip + secp256k1_jacobian_t2]
    mov rdx, r15
    call secp256k1_field_mul_limbs
    mov eax, 1
    jmp .Lsecp256k1_jacobian_to_affine_done

.Lsecp256k1_jacobian_to_affine_infinity:
    xor eax, eax

.Lsecp256k1_jacobian_to_affine_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

secp256k1_jacobian_double_limbs:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx

    mov rdi, r13
    call secp256k1_field_is_zero_limbs
    cmp eax, 1
    je .Lsecp256k1_jacobian_double_infinity
    mov rdi, r12
    call secp256k1_field_is_zero_limbs
    cmp eax, 1
    je .Lsecp256k1_jacobian_double_infinity

    mov rdi, rbx
    mov rsi, rbx
    lea rdx, [rip + secp256k1_jacobian_t0]
    call secp256k1_field_mul_limbs
    mov rdi, r12
    mov rsi, r12
    lea rdx, [rip + secp256k1_jacobian_t1]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_t1]
    lea rsi, [rip + secp256k1_jacobian_t1]
    lea rdx, [rip + secp256k1_jacobian_t2]
    call secp256k1_field_mul_limbs

    mov rdi, rbx
    lea rsi, [rip + secp256k1_jacobian_t1]
    lea rdx, [rip + secp256k1_jacobian_t3]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_jacobian_t3]
    lea rsi, [rip + secp256k1_jacobian_t3]
    lea rdx, [rip + secp256k1_jacobian_t3]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_t3]
    lea rsi, [rip + secp256k1_jacobian_t0]
    lea rdx, [rip + secp256k1_jacobian_t3]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_jacobian_t3]
    lea rsi, [rip + secp256k1_jacobian_t2]
    lea rdx, [rip + secp256k1_jacobian_t3]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_jacobian_t3]
    lea rsi, [rip + secp256k1_jacobian_t3]
    lea rdx, [rip + secp256k1_jacobian_t3]
    call secp256k1_field_add_limbs

    lea rdi, [rip + secp256k1_jacobian_t0]
    lea rsi, [rip + secp256k1_jacobian_t0]
    lea rdx, [rip + secp256k1_jacobian_t4]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_jacobian_t4]
    lea rsi, [rip + secp256k1_jacobian_t0]
    lea rdx, [rip + secp256k1_jacobian_t4]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_jacobian_t4]
    lea rsi, [rip + secp256k1_jacobian_t4]
    lea rdx, [rip + secp256k1_jacobian_t5]
    call secp256k1_field_mul_limbs

    lea rdi, [rip + secp256k1_jacobian_t3]
    lea rsi, [rip + secp256k1_jacobian_t3]
    lea rdx, [rip + secp256k1_jacobian_t6]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_jacobian_t5]
    lea rsi, [rip + secp256k1_jacobian_t6]
    lea rdx, [rip + secp256k1_jacobian_rx]
    call secp256k1_field_sub_limbs

    lea rdi, [rip + secp256k1_jacobian_t3]
    lea rsi, [rip + secp256k1_jacobian_rx]
    lea rdx, [rip + secp256k1_jacobian_t6]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_jacobian_t4]
    lea rsi, [rip + secp256k1_jacobian_t6]
    lea rdx, [rip + secp256k1_jacobian_t7]
    call secp256k1_field_mul_limbs

    lea rdi, [rip + secp256k1_jacobian_t2]
    lea rsi, [rip + secp256k1_jacobian_t2]
    lea rdx, [rip + secp256k1_jacobian_t8]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_jacobian_t8]
    lea rsi, [rip + secp256k1_jacobian_t8]
    lea rdx, [rip + secp256k1_jacobian_t8]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_jacobian_t8]
    lea rsi, [rip + secp256k1_jacobian_t8]
    lea rdx, [rip + secp256k1_jacobian_t8]
    call secp256k1_field_add_limbs
    lea rdi, [rip + secp256k1_jacobian_t7]
    lea rsi, [rip + secp256k1_jacobian_t8]
    lea rdx, [rip + secp256k1_jacobian_ry]
    call secp256k1_field_sub_limbs

    mov rdi, r12
    mov rsi, r13
    lea rdx, [rip + secp256k1_jacobian_rz]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_rz]
    lea rsi, [rip + secp256k1_jacobian_rz]
    lea rdx, [rip + secp256k1_jacobian_rz]
    call secp256k1_field_add_limbs

    mov eax, 1
    jmp .Lsecp256k1_jacobian_double_done

.Lsecp256k1_jacobian_double_infinity:
    xor eax, eax

.Lsecp256k1_jacobian_double_done:
    pop r13
    pop r12
    pop rbx
    ret

secp256k1_jacobian_mixed_add_limbs:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8

    mov rdi, r13
    call secp256k1_field_is_zero_limbs
    cmp eax, 1
    jne .Lsecp256k1_jacobian_mixed_add_not_infinity
    mov rdi, r14
    lea rsi, [rip + secp256k1_jacobian_rx]
    call copy_field4
    mov rdi, r15
    lea rsi, [rip + secp256k1_jacobian_ry]
    call copy_field4
    mov qword ptr [rip + secp256k1_jacobian_rz], 1
    mov qword ptr [rip + secp256k1_jacobian_rz + 8], 0
    mov qword ptr [rip + secp256k1_jacobian_rz + 16], 0
    mov qword ptr [rip + secp256k1_jacobian_rz + 24], 0
    mov eax, 1
    jmp .Lsecp256k1_jacobian_mixed_add_done

.Lsecp256k1_jacobian_mixed_add_not_infinity:
    mov rdi, r13
    mov rsi, r13
    lea rdx, [rip + secp256k1_jacobian_t0]
    call secp256k1_field_mul_limbs
    mov rdi, r14
    lea rsi, [rip + secp256k1_jacobian_t0]
    lea rdx, [rip + secp256k1_jacobian_t1]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_t0]
    mov rsi, r13
    lea rdx, [rip + secp256k1_jacobian_t2]
    call secp256k1_field_mul_limbs
    mov rdi, r15
    lea rsi, [rip + secp256k1_jacobian_t2]
    lea rdx, [rip + secp256k1_jacobian_t2]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_t1]
    mov rsi, rbx
    lea rdx, [rip + secp256k1_jacobian_t3]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_jacobian_t2]
    mov rsi, r12
    lea rdx, [rip + secp256k1_jacobian_t4]
    call secp256k1_field_sub_limbs

    lea rdi, [rip + secp256k1_jacobian_t3]
    call secp256k1_field_is_zero_limbs
    cmp eax, 1
    jne .Lsecp256k1_jacobian_mixed_add_distinct
    lea rdi, [rip + secp256k1_jacobian_t4]
    call secp256k1_field_is_zero_limbs
    cmp eax, 1
    jne .Lsecp256k1_jacobian_mixed_add_infinity
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    call secp256k1_jacobian_double_limbs
    jmp .Lsecp256k1_jacobian_mixed_add_done

.Lsecp256k1_jacobian_mixed_add_distinct:
    lea rdi, [rip + secp256k1_jacobian_t3]
    lea rsi, [rip + secp256k1_jacobian_t3]
    lea rdx, [rip + secp256k1_jacobian_t5]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_t5]
    lea rsi, [rip + secp256k1_jacobian_t3]
    lea rdx, [rip + secp256k1_jacobian_t6]
    call secp256k1_field_mul_limbs
    mov rdi, rbx
    lea rsi, [rip + secp256k1_jacobian_t5]
    lea rdx, [rip + secp256k1_jacobian_t7]
    call secp256k1_field_mul_limbs

    lea rdi, [rip + secp256k1_jacobian_t4]
    lea rsi, [rip + secp256k1_jacobian_t4]
    lea rdx, [rip + secp256k1_jacobian_rx]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_rx]
    lea rsi, [rip + secp256k1_jacobian_t6]
    lea rdx, [rip + secp256k1_jacobian_rx]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_jacobian_rx]
    lea rsi, [rip + secp256k1_jacobian_t7]
    lea rdx, [rip + secp256k1_jacobian_rx]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_jacobian_rx]
    lea rsi, [rip + secp256k1_jacobian_t7]
    lea rdx, [rip + secp256k1_jacobian_rx]
    call secp256k1_field_sub_limbs

    lea rdi, [rip + secp256k1_jacobian_t7]
    lea rsi, [rip + secp256k1_jacobian_rx]
    lea rdx, [rip + secp256k1_jacobian_t8]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_jacobian_t4]
    lea rsi, [rip + secp256k1_jacobian_t8]
    lea rdx, [rip + secp256k1_jacobian_ry]
    call secp256k1_field_mul_limbs
    mov rdi, r12
    lea rsi, [rip + secp256k1_jacobian_t6]
    lea rdx, [rip + secp256k1_jacobian_t9]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_ry]
    lea rsi, [rip + secp256k1_jacobian_t9]
    lea rdx, [rip + secp256k1_jacobian_ry]
    call secp256k1_field_sub_limbs

    mov rdi, r13
    lea rsi, [rip + secp256k1_jacobian_t3]
    lea rdx, [rip + secp256k1_jacobian_rz]
    call secp256k1_field_mul_limbs
    mov eax, 1
    jmp .Lsecp256k1_jacobian_mixed_add_done

.Lsecp256k1_jacobian_mixed_add_infinity:
    xor eax, eax

.Lsecp256k1_jacobian_mixed_add_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

secp256k1_projective_basepoint_mul_limbs:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi

    mov qword ptr [rip + secp256k1_jacobian_acc_infinity], 1
    mov qword ptr [rip + secp256k1_jacobian_acc_x], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_x + 8], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_x + 16], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_x + 24], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_y], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_y + 8], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_y + 16], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_y + 24], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_z], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_z + 8], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_z + 16], 0
    mov qword ptr [rip + secp256k1_jacobian_acc_z + 24], 0

    mov r12d, 255
.Lsecp256k1_projective_mul_loop:
    lea rdi, [rip + secp256k1_jacobian_acc_x]
    lea rsi, [rip + secp256k1_jacobian_acc_y]
    lea rdx, [rip + secp256k1_jacobian_acc_z]
    call secp256k1_jacobian_double_limbs
    mov r13d, eax
    mov ecx, eax
    neg rcx
    lea rdi, [rip + secp256k1_field_zero]
    lea rsi, [rip + secp256k1_jacobian_rx]
    lea rdx, [rip + secp256k1_jacobian_dbl_x]
    call secp256k1_field_select_mask
    mov ecx, r13d
    neg rcx
    lea rdi, [rip + secp256k1_field_zero]
    lea rsi, [rip + secp256k1_jacobian_ry]
    lea rdx, [rip + secp256k1_jacobian_dbl_y]
    call secp256k1_field_select_mask
    mov ecx, r13d
    neg rcx
    lea rdi, [rip + secp256k1_field_zero]
    lea rsi, [rip + secp256k1_jacobian_rz]
    lea rdx, [rip + secp256k1_jacobian_dbl_z]
    call secp256k1_field_select_mask

    lea rdi, [rip + secp256k1_jacobian_dbl_x]
    lea rsi, [rip + secp256k1_jacobian_dbl_y]
    lea rdx, [rip + secp256k1_jacobian_dbl_z]
    lea rcx, [rip + secp256k1_basepoint_x]
    lea r8, [rip + secp256k1_basepoint_y]
    call secp256k1_jacobian_mixed_add_limbs
    mov r14d, eax
    mov ecx, eax
    neg rcx
    lea rdi, [rip + secp256k1_field_zero]
    lea rsi, [rip + secp256k1_jacobian_rx]
    lea rdx, [rip + secp256k1_jacobian_add_x]
    call secp256k1_field_select_mask
    mov ecx, r14d
    neg rcx
    lea rdi, [rip + secp256k1_field_zero]
    lea rsi, [rip + secp256k1_jacobian_ry]
    lea rdx, [rip + secp256k1_jacobian_add_y]
    call secp256k1_field_select_mask
    mov ecx, r14d
    neg rcx
    lea rdi, [rip + secp256k1_field_zero]
    lea rsi, [rip + secp256k1_jacobian_rz]
    lea rdx, [rip + secp256k1_jacobian_add_z]
    call secp256k1_field_select_mask

    mov eax, r12d
    shr eax, 6
    mov rdx, qword ptr [rbx + rax * 8]
    mov ecx, r12d
    and ecx, 63
    shr rdx, cl
    and edx, 1
    mov r15, rdx
    neg r15

    mov rcx, r15
    lea rdi, [rip + secp256k1_jacobian_dbl_x]
    lea rsi, [rip + secp256k1_jacobian_add_x]
    lea rdx, [rip + secp256k1_jacobian_acc_x]
    call secp256k1_field_select_mask
    mov rcx, r15
    lea rdi, [rip + secp256k1_jacobian_dbl_y]
    lea rsi, [rip + secp256k1_jacobian_add_y]
    lea rdx, [rip + secp256k1_jacobian_acc_y]
    call secp256k1_field_select_mask
    mov rcx, r15
    lea rdi, [rip + secp256k1_jacobian_dbl_z]
    lea rsi, [rip + secp256k1_jacobian_add_z]
    lea rdx, [rip + secp256k1_jacobian_acc_z]
    call secp256k1_field_select_mask

    mov rax, r14
    xor rax, 1
    and rax, r15
    mov rdx, r13
    xor rdx, 1
    mov rcx, r15
    not rcx
    and rdx, rcx
    or rax, rdx
    mov qword ptr [rip + secp256k1_jacobian_acc_infinity], rax

.Lsecp256k1_projective_mul_next:
    dec r12d
    cmp r12d, -1
    jne .Lsecp256k1_projective_mul_loop

    cmp qword ptr [rip + secp256k1_jacobian_acc_infinity], 1
    je .Lsecp256k1_projective_mul_infinity
    lea rdi, [rip + secp256k1_jacobian_acc_x]
    lea rsi, [rip + secp256k1_jacobian_rx]
    call copy_field4
    lea rdi, [rip + secp256k1_jacobian_acc_y]
    lea rsi, [rip + secp256k1_jacobian_ry]
    call copy_field4
    lea rdi, [rip + secp256k1_jacobian_acc_z]
    lea rsi, [rip + secp256k1_jacobian_rz]
    call copy_field4
    mov eax, 1
    jmp .Lsecp256k1_projective_mul_done

.Lsecp256k1_projective_mul_infinity:
    xor eax, eax

.Lsecp256k1_projective_mul_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
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

write_u64_decimal_stdout:
    push rbx
    push r12
    push r13
    mov rax, rdi
    lea rbx, [rip + hex_buf + 32]
    xor r12d, r12d
    test rax, rax
    jne .Ldecimal_loop
    dec rbx
    mov byte ptr [rbx], '0'
    mov r12d, 1
    jmp .Ldecimal_write

.Ldecimal_loop:
    xor edx, edx
    mov r13, 10
    div r13
    add dl, '0'
    dec rbx
    mov byte ptr [rbx], dl
    inc r12
    test rax, rax
    jne .Ldecimal_loop

.Ldecimal_write:
    mov rdi, STDOUT
    mov rsi, rbx
    mov rdx, r12
    call write_all
    pop r13
    pop r12
    pop rbx
    ret

write_manifest_labeled_sha256:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx

    mov rdi, STDOUT
    mov rsi, rbx
    mov rdx, r12
    call write_all

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    mov rsi, r13
    mov rdx, r14
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

    pop r14
    pop r13
    pop r12
    pop rbx
    ret

frost_hash_mem:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8

    lea rdi, [rip + sha_ctx]
    call sha256_init
    lea rdi, [rip + sha_ctx]
    mov rsi, rbx
    mov rdx, r12
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, r13
    mov rdx, r14
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, r15
    call sha256_final

    pop r15
    pop r14
    pop r13
    pop r12
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


.section .rodata
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
cmd_secp256k1_basepoint_mul:
    .asciz "secp256k1-basepoint-mul"
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
    .ascii "usage: wuci-ji <sha256|frost-p256-h1|frost-p256-h2|frost-p256-h3|frost-p256-h4|frost-p256-h5|frost-secp256k1-h1|frost-secp256k1-h2|frost-secp256k1-h3|frost-secp256k1-h4|frost-secp256k1-h5|secp256k1-scalar-add|secp256k1-scalar-sub|secp256k1-scalar-mul|secp256k1-scalar-inv|frost-secp256k1-lagrange|frost-secp256k1-nonce-generate|frost-secp256k1-commit|frost-secp256k1-commitment-hash|frost-secp256k1-binding-factor|frost-secp256k1-group-commitment|secp256k1-field-add|secp256k1-field-sub|secp256k1-field-mul|secp256k1-field-square|secp256k1-field-inv|secp256k1-point-validate|secp256k1-point-double|secp256k1-point-add|secp256k1-basepoint-mul|secp256k1-jacobian-double|secp256k1-jacobian-mixed-add|secp256k1-projective-basepoint-mul|secp256k1-point-encode-compressed|secp256k1-point-encode-uncompressed|secp256k1-point-decode|hmac-sha256|hkdf-sha256|poly1305|chacha20|keygen|keypair|seal|seal-v2|seal-to|seal-file|seal-file-v2|seal-file-keyfile|seal-file-keyfile-v2|open|open-to|open-file|open-file-keyfile|inspect|inspect-file|manifest|manifest-file|armor-file|dearmor-file|seal-keyfile|seal-keyfile-v2|open-keyfile|aead-seal|aead-open|selftest> [args]\n"
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
    .ascii "  secp256k1-field-add <a> <b>    add 32-byte hex field elements modulo p\n"
    .ascii "  secp256k1-field-sub <a> <b>    subtract 32-byte hex field elements modulo p\n"
    .ascii "  secp256k1-field-mul <a> <b>    multiply 32-byte hex field elements modulo p\n"
    .ascii "  secp256k1-field-square <a>     square a 32-byte hex field element modulo p\n"
    .ascii "  secp256k1-field-inv <a>        invert a 32-byte hex field element modulo p\n"
    .ascii "  secp256k1-point-validate <x> <y> validate affine point coordinates\n"
    .ascii "  secp256k1-point-double <x> <y> double an affine point; prints x/y or infinity\n"
    .ascii "  secp256k1-point-add <x1> <y1> <x2> <y2> add affine points; prints x/y or infinity\n"
    .ascii "  secp256k1-basepoint-mul <k>    multiply the secp256k1 basepoint by a 32-byte hex scalar\n"
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
    .ascii "  inspect                        print envelope metadata from stdin without a key\n"
    .ascii "  inspect-file <path>            print envelope metadata from a file without a key\n"
    .ascii "  manifest                       print metadata, SHA-256 fingerprints, and tag\n"
    .ascii "  manifest-file <path>           print file metadata, SHA-256 fingerprints, and tag\n"
    .ascii "  armor-file <in> <out>          wrap an artifact in copy/paste ASCII armor; no overwrite\n"
    .ascii "  dearmor-file <in> <out>        decode copy/paste ASCII armor; no overwrite\n"
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

field_arg_error_msg:
    .ascii "wuci-ji: secp256k1 field elements require exactly 64 hex characters\n"
.set field_arg_error_msg_len, . - field_arg_error_msg

scalar_arg_error_msg:
    .ascii "wuci-ji: secp256k1 scalar requires exactly 64 hex characters\n"
.set scalar_arg_error_msg_len, . - scalar_arg_error_msg

frost_lagrange_arg_error_msg:
    .ascii "wuci-ji: frost lagrange identifiers must be unique, nonzero, and include i\n"
.set frost_lagrange_arg_error_msg_len, . - frost_lagrange_arg_error_msg

frost_commitment_arg_error_msg:
    .ascii "wuci-ji: frost commitments require sorted unique nonzero ids and valid compressed points\n"
.set frost_commitment_arg_error_msg_len, . - frost_commitment_arg_error_msg

frost_hiding_commitment_label:
    .ascii "hiding_nonce_commitment: "
.set frost_hiding_commitment_label_len, . - frost_hiding_commitment_label

frost_binding_commitment_label:
    .ascii "binding_nonce_commitment: "
.set frost_binding_commitment_label_len, . - frost_binding_commitment_label

frost_group_commitment_label:
    .ascii "group_commitment: "
.set frost_group_commitment_label_len, . - frost_group_commitment_label

point_arg_error_msg:
    .ascii "wuci-ji: secp256k1 point is not a valid affine curve point\n"
.set point_arg_error_msg_len, . - point_arg_error_msg

point_encoding_arg_error_msg:
    .ascii "wuci-ji: secp256k1 point encoding is malformed or not on curve\n"
.set point_encoding_arg_error_msg_len, . - point_encoding_arg_error_msg

point_x_label:
    .ascii "x: "
.set point_x_label_len, . - point_x_label

point_y_label:
    .ascii "y: "
.set point_y_label_len, . - point_y_label

point_z_label:
    .ascii "z: "
.set point_z_label_len, . - point_z_label

point_valid_msg:
    .ascii "valid\n"
.set point_valid_msg_len, . - point_valid_msg

point_invalid_msg:
    .ascii "invalid\n"
.set point_invalid_msg_len, . - point_invalid_msg

point_infinity_msg:
    .ascii "infinity\n"
.set point_infinity_msg_len, . - point_infinity_msg

keypair_private_label:
    .ascii "private: "
.set keypair_private_label_len, . - keypair_private_label

keypair_public_label:
    .ascii "public: "
.set keypair_public_label_len, . - keypair_public_label

keyfile_error_msg:
    .ascii "wuci-ji: key file must contain 64 hex characters plus optional newline\n"
.set keyfile_error_msg_len, . - keyfile_error_msg

artifact_file_error_msg:
    .ascii "wuci-ji: artifact file could not be read\n"
.set artifact_file_error_msg_len, . - artifact_file_error_msg

input_file_error_msg:
    .ascii "wuci-ji: input file could not be read\n"
.set input_file_error_msg_len, . - input_file_error_msg

output_file_error_msg:
    .ascii "wuci-ji: output file could not be created or written\n"
.set output_file_error_msg_len, . - output_file_error_msg

armor_error_msg:
    .ascii "wuci-ji: ASCII armor is malformed\n"
.set armor_error_msg_len, . - armor_error_msg

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

inspect_v1_msg:
    .ascii "version: 1\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 20\n"
.set inspect_v1_msg_len, . - inspect_v1_msg

inspect_v2_msg:
    .ascii "version: 2\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 36\n"
.set inspect_v2_msg_len, . - inspect_v2_msg

inspect_v3_msg:
    .ascii "version: 3\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 68\n"
.set inspect_v3_msg_len, . - inspect_v3_msg

inspect_ephemeral_public_label:
    .ascii "ephemeral-public: "
.set inspect_ephemeral_public_label_len, . - inspect_ephemeral_public_label

inspect_key_id_label:
    .ascii "key-id: "
.set inspect_key_id_label_len, . - inspect_key_id_label

inspect_nonce_label:
    .ascii "nonce: "
.set inspect_nonce_label_len, . - inspect_nonce_label

manifest_v1_msg:
    .ascii "version: 1\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 20\n"
.set manifest_v1_msg_len, . - manifest_v1_msg

manifest_v2_msg:
    .ascii "version: 2\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 36\n"
.set manifest_v2_msg_len, . - manifest_v2_msg

manifest_v3_msg:
    .ascii "version: 3\n"
    .ascii "algorithm: 1\n"
    .ascii "header-length: 68\n"
.set manifest_v3_msg_len, . - manifest_v3_msg

manifest_ciphertext_length_label:
    .ascii "ciphertext-length: "
.set manifest_ciphertext_length_label_len, . - manifest_ciphertext_length_label

manifest_artifact_sha256_label:
    .ascii "artifact-sha256: "
.set manifest_artifact_sha256_label_len, . - manifest_artifact_sha256_label

manifest_ciphertext_sha256_label:
    .ascii "ciphertext-sha256: "
.set manifest_ciphertext_sha256_label_len, . - manifest_ciphertext_sha256_label

manifest_tag_label:
    .ascii "tag: "
.set manifest_tag_label_len, . - manifest_tag_label

newline_msg:
    .ascii "\n"
.set newline_msg_len, . - newline_msg

selftest_pass_msg:
    .ascii "wuci-ji selftest: PASS\n"
.set selftest_pass_msg_len, . - selftest_pass_msg

selftest_fail_msg:
    .ascii "wuci-ji selftest: FAIL\n"
.set selftest_fail_msg_len, . - selftest_fail_msg

hex_chars:
    .ascii "0123456789abcdef"

base64_alphabet:
    .ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

armor_header:
    .ascii "-----BEGIN WUCI-JI ARTIFACT-----"
.set armor_header_len, . - armor_header

armor_footer:
    .ascii "-----END WUCI-JI ARTIFACT-----"
.set armor_footer_len, . - armor_footer

frost_zpad64:
    .zero 64

frost_len48_zero:
    .byte 0x00, 0x30, 0x00

frost_counter_one:
    .byte 0x01

frost_counter_two:
    .byte 0x02

frost_p256_h1_dst_prime:
    .ascii "FROST-P256-SHA256-v1rho"
    .byte 0x17
.set frost_p256_h1_dst_prime_len, . - frost_p256_h1_dst_prime

frost_p256_h2_dst_prime:
    .ascii "FROST-P256-SHA256-v1chal"
    .byte 0x18
.set frost_p256_h2_dst_prime_len, . - frost_p256_h2_dst_prime

frost_p256_h3_dst_prime:
    .ascii "FROST-P256-SHA256-v1nonce"
    .byte 0x19
.set frost_p256_h3_dst_prime_len, . - frost_p256_h3_dst_prime

frost_p256_h4_prefix:
    .ascii "FROST-P256-SHA256-v1msg"
.set frost_p256_h4_prefix_len, . - frost_p256_h4_prefix

frost_p256_h5_prefix:
    .ascii "FROST-P256-SHA256-v1com"
.set frost_p256_h5_prefix_len, . - frost_p256_h5_prefix

frost_secp256k1_h1_dst_prime:
    .ascii "FROST-secp256k1-SHA256-v1rho"
    .byte 0x1c
.set frost_secp256k1_h1_dst_prime_len, . - frost_secp256k1_h1_dst_prime

frost_secp256k1_h2_dst_prime:
    .ascii "FROST-secp256k1-SHA256-v1chal"
    .byte 0x1d
.set frost_secp256k1_h2_dst_prime_len, . - frost_secp256k1_h2_dst_prime

frost_secp256k1_h3_dst_prime:
    .ascii "FROST-secp256k1-SHA256-v1nonce"
    .byte 0x1e
.set frost_secp256k1_h3_dst_prime_len, . - frost_secp256k1_h3_dst_prime

frost_secp256k1_h4_prefix:
    .ascii "FROST-secp256k1-SHA256-v1msg"
.set frost_secp256k1_h4_prefix_len, . - frost_secp256k1_h4_prefix

frost_secp256k1_h5_prefix:
    .ascii "FROST-secp256k1-SHA256-v1com"
.set frost_secp256k1_h5_prefix_len, . - frost_secp256k1_h5_prefix

.align 8
frost_p256_order_le:
    .quad 0xf3b9cac2fc632551
    .quad 0xbce6faada7179e84
    .quad 0xffffffffffffffff
    .quad 0xffffffff00000000

.align 8
frost_secp256k1_order_le:
    .quad 0xbfd25e8cd0364141
    .quad 0xbaaedce6af48a03b
    .quad 0xfffffffffffffffe
    .quad 0xffffffffffffffff

.align 8
frost_secp256k1_order_minus_2_le:
    .quad 0xbfd25e8cd036413f
    .quad 0xbaaedce6af48a03b
    .quad 0xfffffffffffffffe
    .quad 0xffffffffffffffff

.align 8
secp256k1_field_p_le:
    .quad 0xfffffffefffffc2f
    .quad 0xffffffffffffffff
    .quad 0xffffffffffffffff
    .quad 0xffffffffffffffff

.align 8
secp256k1_field_p_minus_2_le:
    .quad 0xfffffffefffffc2d
    .quad 0xffffffffffffffff
    .quad 0xffffffffffffffff
    .quad 0xffffffffffffffff

.align 8
secp256k1_field_sqrt_exp_le:
    .quad 0xffffffffbfffff0c
    .quad 0xffffffffffffffff
    .quad 0xffffffffffffffff
    .quad 0x3fffffffffffffff

.align 8
secp256k1_field_zero:
    .quad 0
    .quad 0
    .quad 0
    .quad 0

.align 8
secp256k1_basepoint_x:
    .quad 0x59f2815b16f81798
    .quad 0x029bfcdb2dce28d9
    .quad 0x55a06295ce870b07
    .quad 0x79be667ef9dcbbac

.align 8
secp256k1_basepoint_y:
    .quad 0x9c47d08ffb10d4b8
    .quad 0xfd17b448a6855419
    .quad 0x5da4fbfc0e1108a8
    .quad 0x483ada7726a3c465

envelope_prefix:
    .ascii "WJSEAL"
    .byte 0x01, 0x01

envelope_v2_prefix:
    .ascii "WJSEAL"
    .byte 0x02, 0x01

envelope_v3_prefix:
    .ascii "WJSEAL"
    .byte 0x03, 0x01

v3_hkdf_info:
    .ascii "wuci-ji v3 X25519 recipient AEAD key"
.set v3_hkdf_info_len, . - v3_hkdf_info

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
frost_b0:
    .skip 32
.align 16
frost_b1:
    .skip 32
.align 16
frost_b2:
    .skip 32
.align 16
frost_xor_buf:
    .skip 32
.align 16
frost_uniform_buf:
    .skip 48
.align 16
frost_scalar_buf:
    .skip 32
.align 8
frost_nonce_input:
    .skip 64
.align 16
frost_nonce_scalar_be:
    .skip 32
.align 16
frost_hiding_commitment:
    .skip 33
.align 16
frost_binding_commitment:
    .skip 33
.align 8
frost_commitment_list_buf:
    .skip 3920
.align 16
frost_group_public_key:
    .skip 33
.align 16
frost_msg_hash:
    .skip 32
.align 16
frost_commitment_hash:
    .skip 32
.align 16
frost_binding_input:
    .skip 129
.align 16
frost_group_acc_x:
    .skip 32
.align 16
frost_group_acc_y:
    .skip 32
.align 16
frost_group_contrib_x:
    .skip 32
.align 16
frost_group_contrib_y:
    .skip 32
.align 16
frost_group_binding_x:
    .skip 32
.align 16
frost_group_binding_y:
    .skip 32
.align 16
frost_group_commitment:
    .skip 33
.align 8
frost_group_acc_infinity:
    .skip 8
.align 8
frost_rem0:
    .skip 8
frost_rem1:
    .skip 8
frost_rem2:
    .skip 8
frost_rem3:
    .skip 8
frost_tmp0:
    .skip 8
frost_tmp1:
    .skip 8
frost_tmp2:
    .skip 8
frost_tmp3:
    .skip 8
.align 16
secp256k1_field_a_bytes:
    .skip 32
.align 16
secp256k1_field_b_bytes:
    .skip 32
.align 16
secp256k1_field_out_bytes:
    .skip 32
.align 16
secp256k1_field_a:
    .skip 32
.align 16
secp256k1_field_b:
    .skip 32
.align 16
secp256k1_field_out:
    .skip 32
.align 16
secp256k1_field_tmp:
    .skip 32
.align 16
secp256k1_field_acc:
    .skip 32
.align 16
secp256k1_field_mul_base:
    .skip 32
.align 16
secp256k1_inv_base:
    .skip 32
.align 16
secp256k1_inv_result:
    .skip 32
.align 16
secp256k1_inv_tmp:
    .skip 32
.align 16
secp256k1_point_bytes:
    .skip 32
.align 16
secp256k1_scalar_bytes:
    .skip 32
.align 16
secp256k1_scalar:
    .skip 32
.align 16
secp256k1_scalar_a:
    .skip 32
.align 16
secp256k1_scalar_b:
    .skip 32
.align 16
secp256k1_scalar_out:
    .skip 32
.align 16
secp256k1_scalar_tmp:
    .skip 32
.align 16
secp256k1_scalar_acc:
    .skip 32
.align 16
secp256k1_scalar_mul_base:
    .skip 32
.align 16
secp256k1_scalar_inv_base:
    .skip 32
.align 16
secp256k1_scalar_inv_result:
    .skip 32
.align 16
secp256k1_scalar_inv_tmp:
    .skip 32
.align 16
secp256k1_scalar_lagrange_id:
    .skip 32
.align 16
secp256k1_scalar_lagrange_num:
    .skip 32
.align 16
secp256k1_scalar_lagrange_den:
    .skip 32
.align 16
secp256k1_point_x1:
    .skip 32
.align 16
secp256k1_point_y1:
    .skip 32
.align 16
secp256k1_point_x2:
    .skip 32
.align 16
secp256k1_point_y2:
    .skip 32
.align 16
secp256k1_point_rx:
    .skip 32
.align 16
secp256k1_point_ry:
    .skip 32
.align 16
secp256k1_point_t0:
    .skip 32
.align 16
secp256k1_point_t1:
    .skip 32
.align 16
secp256k1_point_t2:
    .skip 32
.align 16
secp256k1_point_t3:
    .skip 32
.align 16
secp256k1_point_t4:
    .skip 32
.align 16
secp256k1_point_t5:
    .skip 32
.align 16
secp256k1_point_acc_x:
    .skip 32
.align 16
secp256k1_point_acc_y:
    .skip 32
.align 16
secp256k1_point_base_x:
    .skip 32
.align 16
secp256k1_point_base_y:
    .skip 32
.align 8
secp256k1_point_acc_infinity:
    .skip 8
.align 16
secp256k1_encoded_point:
    .skip 65
.align 16
secp256k1_jacobian_x:
    .skip 32
.align 16
secp256k1_jacobian_y:
    .skip 32
.align 16
secp256k1_jacobian_z:
    .skip 32
.align 16
secp256k1_jacobian_rx:
    .skip 32
.align 16
secp256k1_jacobian_ry:
    .skip 32
.align 16
secp256k1_jacobian_rz:
    .skip 32
.align 16
secp256k1_jacobian_acc_x:
    .skip 32
.align 16
secp256k1_jacobian_acc_y:
    .skip 32
.align 16
secp256k1_jacobian_acc_z:
    .skip 32
.align 8
secp256k1_jacobian_acc_infinity:
    .skip 8
.align 16
secp256k1_jacobian_dbl_x:
    .skip 32
.align 16
secp256k1_jacobian_dbl_y:
    .skip 32
.align 16
secp256k1_jacobian_dbl_z:
    .skip 32
.align 16
secp256k1_jacobian_add_x:
    .skip 32
.align 16
secp256k1_jacobian_add_y:
    .skip 32
.align 16
secp256k1_jacobian_add_z:
    .skip 32
.align 16
secp256k1_jacobian_t0:
    .skip 32
.align 16
secp256k1_jacobian_t1:
    .skip 32
.align 16
secp256k1_jacobian_t2:
    .skip 32
.align 16
secp256k1_jacobian_t3:
    .skip 32
.align 16
secp256k1_jacobian_t4:
    .skip 32
.align 16
secp256k1_jacobian_t5:
    .skip 32
.align 16
secp256k1_jacobian_t6:
    .skip 32
.align 16
secp256k1_jacobian_t7:
    .skip 32
.align 16
secp256k1_jacobian_t8:
    .skip 32
.align 16
secp256k1_jacobian_t9:
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
.align 8
aead_output_path:
    .skip 8
.align 8
seal_input_fd:
    .skip 8
.align 8
seal_output_fd:
    .skip 8
.align 8
seal_file_mode:
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
envelope_v3_header_buf:
    .skip ENVELOPE_V3_HEADER_LEN
.align 16
x25519_private_key:
    .skip 32
.align 16
x25519_public_key:
    .skip 32
.align 16
x25519_recipient_public:
    .skip 32
.align 16
x25519_ephemeral_public:
    .skip 32
.align 16
x25519_shared_secret:
    .skip 32
.align 16
aead_open_buf:
    .skip AEAD_OPEN_MAX
.align 16
hex_buf:
    .skip 160
.align 8
base64_quad_len:
    .skip 8
.align 8
base64_quad_pad:
    .skip 8
.align 8
base64_seen_padding:
    .skip 8
.align 4
base64_quad:
    .skip 4
.align 16
bss_sensitive_end:
.set bss_sensitive_len, bss_sensitive_end - bss_sensitive_start

.section .note.GNU-stack,"",@progbits
