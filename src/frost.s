.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
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
.global frost_lagrange_arg_error
.global frost_secp256k1_order_le
.global frost_secp256k1_order_minus_2_le
.extern usage_exit
.extern read_error
.extern scalar_arg_error
.extern point_arg_error
.extern random_error
.extern exit_process
.extern write_all
.extern hex_encode
.extern hex32_decode
.extern sha256_init
.extern sha256_update
.extern sha256_final
.extern store64_be_at_r13
.extern store_le4_to_be32
.extern copy_field4
.extern load_secp256k1_scalar_arg
.extern write_secp256k1_scalar_out
.extern secp256k1_scalar_gt_limbs
.extern secp256k1_scalar_add_limbs
.extern secp256k1_scalar_mul_limbs
.extern secp256k1_scalar_is_zero_limbs
.extern load_secp256k1_compressed_point_arg
.extern encode_secp256k1_compressed_point
.extern frost_secp256k1_commit_scalar
.extern secp256k1_point_add_limbs
.extern secp256k1_point_mul_limbs
.extern secp256k1_projective_basepoint_mul_limbs
.extern secp256k1_jacobian_to_affine_limbs
.extern secp256k1_field_equal_limbs
.extern write_secp256k1_point_valid
.extern write_secp256k1_point_invalid
.extern sha_ctx
.extern io_buf
.extern digest_buf
.extern hex_buf
.extern secp256k1_field_out_bytes
.extern secp256k1_scalar_a
.extern secp256k1_scalar_b
.extern secp256k1_scalar_out
.extern secp256k1_scalar_inv_result
.extern secp256k1_scalar_inv_tmp
.extern secp256k1_scalar_lagrange_id
.extern secp256k1_scalar_lagrange_num
.extern secp256k1_scalar_lagrange_den
.extern secp256k1_point_x1
.extern secp256k1_point_y1
.extern secp256k1_point_x2
.extern secp256k1_point_y2
.extern secp256k1_point_rx
.extern secp256k1_point_ry
.extern secp256k1_jacobian_rx
.extern secp256k1_jacobian_ry
.extern secp256k1_jacobian_rz
.extern frost_b0
.extern frost_b1
.extern frost_b2
.extern frost_xor_buf
.extern frost_uniform_buf
.extern frost_scalar_buf
.extern frost_nonce_input
.extern frost_nonce_scalar_be
.extern frost_hiding_commitment
.extern frost_binding_commitment
.extern frost_commitment_list_buf
.extern frost_group_public_key
.extern frost_msg_hash
.extern frost_commitment_hash
.extern frost_binding_input
.extern frost_group_acc_x
.extern frost_group_acc_y
.extern frost_group_contrib_x
.extern frost_group_contrib_y
.extern frost_group_binding_x
.extern frost_group_binding_y
.extern frost_group_commitment
.extern frost_group_acc_infinity
.extern frost_challenge_prefix
.extern frost_verify_left_x
.extern frost_verify_left_y
.extern frost_verify_right_x
.extern frost_verify_right_y
.extern frost_verify_scaled_x
.extern frost_verify_scaled_y
.extern frost_rem0
.extern frost_rem1
.extern frost_rem2
.extern frost_rem3
.extern frost_tmp0
.extern frost_tmp1
.extern frost_tmp2
.extern frost_tmp3

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



.section .rodata
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



.section .note.GNU-stack,"",@progbits
