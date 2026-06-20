.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global run_sha256
.global run_frost_p256_h4
.global run_frost_p256_h1
.global run_frost_p256_h2
.global run_frost_p256_h3
.global run_frost_p256_h5
.global run_frost_secp256k1_h1
.global run_frost_secp256k1_h2
.global run_frost_secp256k1_h3
.global run_frost_secp256k1_h4
.global run_frost_secp256k1_h5
.global run_frost_secp256k1_nonce_generate
.global run_frost_secp256k1_commit
.global run_frost_secp256k1_commitment_hash
.global run_frost_secp256k1_binding_factor
.global run_frost_secp256k1_group_commitment
.global run_frost_secp256k1_challenge
.global run_frost_secp256k1_signing_share
.global run_frost_secp256k1_aggregate
.global run_frost_secp256k1_verify
.global run_keygen
.global run_keypair
.global run_poly1305
.global run_chacha20
.global run_seal
.global run_seal_v2
.global run_seal_file
.global run_seal_file_v2
.global run_seal_file_keyfile
.global run_seal_file_keyfile_v2
.global run_seal_to
.global run_seal_keyfile
.global run_seal_keyfile_v2
.global run_open
.global run_open_file
.global run_open_file_keyfile
.global run_open_to
.global run_open_keyfile
.global run_inspect
.global run_inspect_file
.global run_manifest
.global run_manifest_file
.global run_armor_file
.global run_dearmor_file
.global run_aead_seal
.global run_aead_open
.global run_selftest
.global read_error
.global key_error
.global hkdf_arg_error
.global field_arg_error
.global scalar_arg_error
.global point_arg_error
.global point_encoding_arg_error
.global frost_lagrange_arg_error
.global streq
.global exit_process
.global sha_ctx
.global digest_buf
.global io_buf
.global aead_text_len
.global aead_output_path
.global seal_input_fd
.global seal_output_fd
.global seal_file_mode
.global aead_open_buf
.global hex_buf
.global hmac_key
.global hmac_ipad
.global hmac_opad
.global hmac_inner
.global hkdf_salt
.global hkdf_info
.global hkdf_prk
.global base64_quad_len
.global base64_quad_pad
.global base64_seen_padding
.global base64_quad
.global hkdf_counter_one
.global secp256k1_field_p_le
.global secp256k1_field_p_minus_2_le
.global secp256k1_field_sqrt_exp_le
.global frost_secp256k1_order_le
.global frost_secp256k1_order_minus_2_le
.global secp256k1_field_a_bytes
.global secp256k1_field_b_bytes
.global secp256k1_field_out_bytes
.global secp256k1_field_a
.global secp256k1_field_b
.global secp256k1_field_out
.global secp256k1_field_tmp
.global secp256k1_field_acc
.global secp256k1_field_mul_base
.global secp256k1_inv_base
.global secp256k1_inv_result
.global secp256k1_inv_tmp
.global secp256k1_scalar_bytes
.global secp256k1_scalar
.global secp256k1_scalar_a
.global secp256k1_scalar_b
.global secp256k1_scalar_out
.global secp256k1_scalar_tmp
.global secp256k1_scalar_acc
.global secp256k1_scalar_mul_base
.global secp256k1_scalar_inv_base
.global secp256k1_scalar_inv_result
.global secp256k1_scalar_inv_tmp
.global secp256k1_scalar_lagrange_id
.global secp256k1_scalar_lagrange_num
.global secp256k1_scalar_lagrange_den
.global secp256k1_point_bytes
.global secp256k1_encoded_point
.global secp256k1_point_x1
.global secp256k1_point_y1
.global secp256k1_point_x2
.global secp256k1_point_y2
.global secp256k1_point_rx
.global secp256k1_point_ry
.global secp256k1_point_t0
.global secp256k1_point_t1
.global secp256k1_point_t2
.global secp256k1_point_t3
.global secp256k1_point_t4
.global secp256k1_point_t5
.global secp256k1_point_acc_x
.global secp256k1_point_acc_y
.global secp256k1_point_base_x
.global secp256k1_point_base_y
.global secp256k1_point_acc_infinity
.global secp256k1_jacobian_x
.global secp256k1_jacobian_y
.global secp256k1_jacobian_z
.global secp256k1_jacobian_rx
.global secp256k1_jacobian_ry
.global secp256k1_jacobian_rz
.global secp256k1_jacobian_acc_x
.global secp256k1_jacobian_acc_y
.global secp256k1_jacobian_acc_z
.global secp256k1_jacobian_acc_infinity
.global secp256k1_jacobian_dbl_x
.global secp256k1_jacobian_dbl_y
.global secp256k1_jacobian_dbl_z
.global secp256k1_jacobian_add_x
.global secp256k1_jacobian_add_y
.global secp256k1_jacobian_add_z
.global secp256k1_jacobian_t0
.global secp256k1_jacobian_t1
.global secp256k1_jacobian_t2
.global secp256k1_jacobian_t3
.global secp256k1_jacobian_t4
.global secp256k1_jacobian_t5
.global secp256k1_jacobian_t6
.global secp256k1_jacobian_t7
.global secp256k1_jacobian_t8
.global secp256k1_jacobian_t9
.extern write_all
.extern fill_random
.extern read_key_file
.extern read_artifact_file
.extern open_seal_file_paths
.extern close_seal_files
.extern open_output_file
.extern write_open_plaintext
.extern x25519_basepoint
.extern x25519_scalar_mult
.extern usage_exit
.extern hex_encode
.extern hex32_decode
.extern hex16_decode
.extern hex12_decode
.extern hex_decode_fixed
.extern hex_u32_decode
.extern write_u64_decimal_stdout
.extern write_manifest_labeled_sha256
.extern hmac_prepare_sha256_key32
.extern base64_emit_quad
.extern base64_decode_char
.extern base64_alphabet
.extern store64_be_at_r13
.extern load_be32_to_le4
.extern store_le4_to_be32
.extern copy_field4
.extern load_secp256k1_field_arg
.extern secp256k1_field_add_limbs
.extern secp256k1_field_sub_limbs
.extern secp256k1_field_mul_limbs
.extern secp256k1_field_inverse_limbs
.extern secp256k1_field_sqrt_limbs
.extern secp256k1_field_select_mask
.extern secp256k1_field_is_zero_limbs
.extern secp256k1_field_equal_limbs
.extern secp256k1_field_is_canonical_limbs
.extern write_secp256k1_scalar_out
.extern secp256k1_scalar_gt_limbs
.extern load_secp256k1_scalar_arg
.extern secp256k1_scalar_add_limbs
.extern secp256k1_scalar_sub_limbs
.extern secp256k1_scalar_mul_limbs
.extern secp256k1_scalar_inverse_limbs
.extern secp256k1_scalar_is_zero_limbs
.extern secp256k1_scalar_equal_limbs
.extern secp256k1_scalar_is_canonical_limbs
.extern load_secp256k1_compressed_point_arg
.extern encode_secp256k1_compressed_point
.extern frost_secp256k1_commit_scalar
.extern secp256k1_point_add_limbs
.extern secp256k1_point_mul_limbs
.extern secp256k1_projective_basepoint_mul_limbs
.extern secp256k1_jacobian_to_affine_limbs
.extern write_secp256k1_point_valid
.extern write_secp256k1_point_invalid

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

run_frost_secp256k1_challenge:
    cmp qword ptr [rsp], 4
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + frost_challenge_prefix]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne frost_commitment_arg_error
    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + frost_challenge_prefix + 33]
    lea rdx, [rip + secp256k1_point_x2]
    lea rcx, [rip + secp256k1_point_y2]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne frost_commitment_arg_error

    lea rdi, [rip + frost_secp256k1_h2_dst_prime]
    mov esi, OFFSET FLAT:frost_secp256k1_h2_dst_prime_len
    lea rdx, [rip + frost_secp256k1_order_le]
    lea rcx, [rip + frost_challenge_prefix]
    mov r8d, 66
    jmp frost_hash_to_scalar_prefixed_stdin

run_frost_secp256k1_signing_share:
    cmp qword ptr [rsp], 8
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

    mov rdi, qword ptr [rsp + 40]
    lea rsi, [rip + secp256k1_scalar_inv_tmp]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error

    mov rdi, qword ptr [rsp + 48]
    lea rsi, [rip + secp256k1_scalar_lagrange_num]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_lagrange_num]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je scalar_arg_error

    mov rdi, qword ptr [rsp + 56]
    lea rsi, [rip + secp256k1_scalar_lagrange_den]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_lagrange_den]
    call secp256k1_scalar_is_zero_limbs
    cmp eax, 1
    je scalar_arg_error

    mov rdi, qword ptr [rsp + 64]
    lea rsi, [rip + secp256k1_scalar_lagrange_id]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error

    lea rdi, [rip + secp256k1_scalar_b]
    lea rsi, [rip + secp256k1_scalar_inv_tmp]
    lea rdx, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_mul_limbs
    lea rdi, [rip + secp256k1_scalar_a]
    lea rsi, [rip + secp256k1_scalar_out]
    lea rdx, [rip + secp256k1_scalar_inv_result]
    call secp256k1_scalar_add_limbs

    lea rdi, [rip + secp256k1_scalar_lagrange_num]
    lea rsi, [rip + secp256k1_scalar_lagrange_den]
    lea rdx, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_mul_limbs
    lea rdi, [rip + secp256k1_scalar_out]
    lea rsi, [rip + secp256k1_scalar_lagrange_id]
    lea rdx, [rip + secp256k1_scalar_inv_tmp]
    call secp256k1_scalar_mul_limbs
    lea rdi, [rip + secp256k1_scalar_inv_result]
    lea rsi, [rip + secp256k1_scalar_inv_tmp]
    lea rdx, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_add_limbs
    jmp write_secp256k1_scalar_out

run_frost_secp256k1_aggregate:
    cmp qword ptr [rsp], 4
    jb usage_exit
    mov r10, rsp
    push rbx
    push r12
    push r13
    push r15
    mov r15, r10
    mov r13, qword ptr [r15]

    mov rdi, qword ptr [r15 + 24]
    lea rsi, [rip + frost_group_commitment]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne frost_commitment_arg_error

    mov qword ptr [rip + secp256k1_scalar_inv_result], 0
    mov qword ptr [rip + secp256k1_scalar_inv_result + 8], 0
    mov qword ptr [rip + secp256k1_scalar_inv_result + 16], 0
    mov qword ptr [rip + secp256k1_scalar_inv_result + 24], 0

    mov r12, 3
.Lrun_frost_aggregate_loop:
    cmp r12, r13
    jae .Lrun_frost_aggregate_done
    mov rdi, qword ptr [r15 + r12 * 8 + 8]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error
    lea rdi, [rip + secp256k1_scalar_inv_result]
    lea rsi, [rip + secp256k1_scalar_a]
    lea rdx, [rip + secp256k1_scalar_out]
    call secp256k1_scalar_add_limbs
    lea rdi, [rip + secp256k1_scalar_out]
    lea rsi, [rip + secp256k1_scalar_inv_result]
    call copy_field4
    inc r12
    jmp .Lrun_frost_aggregate_loop

.Lrun_frost_aggregate_done:
    mov rdi, STDOUT
    lea rsi, [rip + frost_signature_commitment_label]
    mov edx, OFFSET FLAT:frost_signature_commitment_label_len
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

    mov rdi, STDOUT
    lea rsi, [rip + frost_signature_scalar_label]
    mov edx, OFFSET FLAT:frost_signature_scalar_label_len
    call write_all
    lea rdi, [rip + secp256k1_scalar_inv_result]
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

run_frost_secp256k1_verify:
    cmp qword ptr [rsp], 6
    jne usage_exit
    mov rdi, qword ptr [rsp + 24]
    lea rsi, [rip + frost_group_commitment]
    lea rdx, [rip + secp256k1_point_x1]
    lea rcx, [rip + secp256k1_point_y1]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne frost_commitment_arg_error

    mov rdi, qword ptr [rsp + 32]
    lea rsi, [rip + frost_group_public_key]
    lea rdx, [rip + secp256k1_point_x2]
    lea rcx, [rip + secp256k1_point_y2]
    call load_secp256k1_compressed_point_arg
    cmp eax, 1
    jne frost_commitment_arg_error

    mov rdi, qword ptr [rsp + 40]
    lea rsi, [rip + secp256k1_scalar_a]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error

    mov rdi, qword ptr [rsp + 48]
    lea rsi, [rip + secp256k1_scalar_b]
    call load_secp256k1_scalar_arg
    cmp eax, 1
    jne scalar_arg_error

    lea rdi, [rip + secp256k1_scalar_a]
    call secp256k1_projective_basepoint_mul_limbs
    cmp eax, 1
    jne write_secp256k1_point_invalid
    lea rdi, [rip + secp256k1_jacobian_rx]
    lea rsi, [rip + secp256k1_jacobian_ry]
    lea rdx, [rip + secp256k1_jacobian_rz]
    lea rcx, [rip + frost_verify_left_x]
    lea r8, [rip + frost_verify_left_y]
    call secp256k1_jacobian_to_affine_limbs
    cmp eax, 1
    jne write_secp256k1_point_invalid

    lea rdi, [rip + secp256k1_scalar_b]
    lea rsi, [rip + secp256k1_point_x2]
    lea rdx, [rip + secp256k1_point_y2]
    lea rcx, [rip + frost_verify_scaled_x]
    lea r8, [rip + frost_verify_scaled_y]
    call secp256k1_point_mul_limbs
    cmp eax, 1
    jne .Lrun_frost_verify_right_is_r

    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + secp256k1_point_y1]
    lea rdx, [rip + frost_verify_scaled_x]
    lea rcx, [rip + frost_verify_scaled_y]
    lea r8, [rip + secp256k1_point_rx]
    lea r9, [rip + secp256k1_point_ry]
    call secp256k1_point_add_limbs
    cmp eax, 1
    jne write_secp256k1_point_invalid
    lea rdi, [rip + secp256k1_point_rx]
    lea rsi, [rip + frost_verify_right_x]
    call copy_field4
    lea rdi, [rip + secp256k1_point_ry]
    lea rsi, [rip + frost_verify_right_y]
    call copy_field4
    jmp .Lrun_frost_verify_compare

.Lrun_frost_verify_right_is_r:
    lea rdi, [rip + secp256k1_point_x1]
    lea rsi, [rip + frost_verify_right_x]
    call copy_field4
    lea rdi, [rip + secp256k1_point_y1]
    lea rsi, [rip + frost_verify_right_y]
    call copy_field4

.Lrun_frost_verify_compare:
    lea rdi, [rip + frost_verify_left_x]
    lea rsi, [rip + frost_verify_right_x]
    call secp256k1_field_equal_limbs
    cmp eax, 1
    jne write_secp256k1_point_invalid
    lea rdi, [rip + frost_verify_left_y]
    lea rsi, [rip + frost_verify_right_y]
    call secp256k1_field_equal_limbs
    cmp eax, 1
    jne write_secp256k1_point_invalid
    jmp write_secp256k1_point_valid

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

frost_hash_to_scalar_prefixed_stdin:
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
    lea rsi, [rip + frost_zpad64]
    mov edx, 64
    call sha256_update
    lea rdi, [rip + sha_ctx]
    mov rsi, r14
    mov rdx, r15
    call sha256_update

.Lfrost_prefixed_xmd_read_loop:
    mov eax, SYS_READ
    mov edi, STDIN
    lea rsi, [rip + io_buf]
    mov edx, 4096
    syscall
    test rax, rax
    js read_error
    jz .Lfrost_prefixed_xmd_read_eof

    lea rdi, [rip + sha_ctx]
    lea rsi, [rip + io_buf]
    mov rdx, rax
    call sha256_update
    jmp .Lfrost_prefixed_xmd_read_loop

.Lfrost_prefixed_xmd_read_eof:
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
.Lfrost_prefixed_xor_loop:
    mov al, byte ptr [rsi]
    xor al, byte ptr [rdx]
    mov byte ptr [rdi], al
    inc rdi
    inc rsi
    inc rdx
    dec ecx
    jne .Lfrost_prefixed_xor_loop

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

    pop r15
    pop r14
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

zero_sensitive_state:
    lea rdi, [rip + bss_sensitive_start]
    mov esi, OFFSET FLAT:bss_sensitive_len
    jmp zero_memory

zero_memory:
    xor eax, eax
    mov rcx, rsi
    rep stosb
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

frost_signature_commitment_label:
    .ascii "signature_commitment: "
.set frost_signature_commitment_label_len, . - frost_signature_commitment_label

frost_signature_scalar_label:
    .ascii "signature_scalar: "
.set frost_signature_scalar_label_len, . - frost_signature_scalar_label

point_arg_error_msg:
    .ascii "wuci-ji: secp256k1 point is not a valid affine curve point\n"
.set point_arg_error_msg_len, . - point_arg_error_msg

point_encoding_arg_error_msg:
    .ascii "wuci-ji: secp256k1 point encoding is malformed or not on curve\n"
.set point_encoding_arg_error_msg_len, . - point_encoding_arg_error_msg

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
.align 16
frost_challenge_prefix:
    .skip 66
.align 16
frost_verify_left_x:
    .skip 32
.align 16
frost_verify_left_y:
    .skip 32
.align 16
frost_verify_right_x:
    .skip 32
.align 16
frost_verify_right_y:
    .skip 32
.align 16
frost_verify_scaled_x:
    .skip 32
.align 16
frost_verify_scaled_y:
    .skip 32
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
