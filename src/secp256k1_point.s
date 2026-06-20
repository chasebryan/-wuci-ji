.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global run_secp256k1_point_validate
.global run_secp256k1_point_double
.global run_secp256k1_point_add
.global run_secp256k1_basepoint_mul
.global run_secp256k1_jacobian_double
.global run_secp256k1_jacobian_mixed_add
.global run_secp256k1_projective_basepoint_mul
.global run_secp256k1_point_encode_compressed
.global run_secp256k1_point_encode_uncompressed
.global run_secp256k1_point_decode
.global write_secp256k1_point_out
.global write_secp256k1_point_valid
.global write_secp256k1_point_invalid
.global write_secp256k1_point_infinity
.global write_secp256k1_jacobian_out
.global write_secp256k1_jacobian_infinity
.global load_secp256k1_compressed_point_arg
.global encode_secp256k1_compressed_point
.global frost_secp256k1_commit_scalar
.global load_secp256k1_point_xy
.global secp256k1_point_validate_limbs
.global secp256k1_point_double_limbs
.global secp256k1_point_add_limbs
.global secp256k1_public_point_mul_limbs
.global secp256k1_point_mul_limbs
.global secp256k1_jacobian_to_affine_limbs
.global secp256k1_jacobian_to_affine_finite_limbs
.global secp256k1_jacobian_double_finite_limbs
.global secp256k1_jacobian_double_limbs
.global secp256k1_jacobian_mixed_add_masked_limbs
.global secp256k1_jacobian_mixed_add_limbs
.global secp256k1_projective_basepoint_mul_limbs
.extern usage_exit
.extern field_arg_error
.extern scalar_arg_error
.extern point_arg_error
.extern point_encoding_arg_error
.extern exit_process
.extern write_all
.extern hex_encode
.extern hex32_decode
.extern hex_decode_fixed
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
.extern hex_buf
.extern secp256k1_field_a_bytes
.extern secp256k1_field_b_bytes
.extern secp256k1_scalar_bytes
.extern secp256k1_scalar
.extern secp256k1_point_bytes
.extern secp256k1_encoded_point
.extern secp256k1_point_x1
.extern secp256k1_point_y1
.extern secp256k1_point_x2
.extern secp256k1_point_y2
.extern secp256k1_point_rx
.extern secp256k1_point_ry
.extern secp256k1_point_t0
.extern secp256k1_point_t1
.extern secp256k1_point_t2
.extern secp256k1_point_t3
.extern secp256k1_point_t4
.extern secp256k1_point_t5
.extern secp256k1_point_acc_x
.extern secp256k1_point_acc_y
.extern secp256k1_point_base_x
.extern secp256k1_point_base_y
.extern secp256k1_point_acc_infinity
.extern secp256k1_jacobian_x
.extern secp256k1_jacobian_y
.extern secp256k1_jacobian_z
.extern secp256k1_jacobian_rx
.extern secp256k1_jacobian_ry
.extern secp256k1_jacobian_rz
.extern secp256k1_jacobian_acc_x
.extern secp256k1_jacobian_acc_y
.extern secp256k1_jacobian_acc_z
.extern secp256k1_jacobian_acc_infinity
.extern secp256k1_jacobian_dbl_x
.extern secp256k1_jacobian_dbl_y
.extern secp256k1_jacobian_dbl_z
.extern secp256k1_jacobian_add_x
.extern secp256k1_jacobian_add_y
.extern secp256k1_jacobian_add_z
.extern secp256k1_jacobian_t0
.extern secp256k1_jacobian_t1
.extern secp256k1_jacobian_t2
.extern secp256k1_jacobian_t3
.extern secp256k1_jacobian_t4
.extern secp256k1_jacobian_t5
.extern secp256k1_jacobian_t6
.extern secp256k1_jacobian_t7
.extern secp256k1_jacobian_t8
.extern secp256k1_jacobian_t9

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
    call secp256k1_public_point_mul_limbs
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
    call secp256k1_jacobian_to_affine_finite_limbs
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
    call secp256k1_jacobian_to_affine_finite_limbs
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

secp256k1_public_point_mul_limbs:
    jmp secp256k1_point_mul_limbs

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
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    mov rcx, r14
    mov r8, r15
    call secp256k1_jacobian_to_affine_finite_limbs
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

secp256k1_jacobian_to_affine_finite_limbs:
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
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

secp256k1_jacobian_double_finite_limbs:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    jmp .Lsecp256k1_jacobian_double_compute

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

.Lsecp256k1_jacobian_double_compute:
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

secp256k1_jacobian_mixed_add_masked_limbs:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8

    mov rdi, r13
    call secp256k1_field_is_zero_limbs
    mov qword ptr [rsp], rax

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
    mov qword ptr [rsp + 8], rax
    lea rdi, [rip + secp256k1_jacobian_t4]
    call secp256k1_field_is_zero_limbs
    mov qword ptr [rsp + 16], rax

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
    lea rdx, [rip + secp256k1_jacobian_add_x]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_add_x]
    lea rsi, [rip + secp256k1_jacobian_t6]
    lea rdx, [rip + secp256k1_jacobian_add_x]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_jacobian_add_x]
    lea rsi, [rip + secp256k1_jacobian_t7]
    lea rdx, [rip + secp256k1_jacobian_add_x]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_jacobian_add_x]
    lea rsi, [rip + secp256k1_jacobian_t7]
    lea rdx, [rip + secp256k1_jacobian_add_x]
    call secp256k1_field_sub_limbs

    lea rdi, [rip + secp256k1_jacobian_t7]
    lea rsi, [rip + secp256k1_jacobian_add_x]
    lea rdx, [rip + secp256k1_jacobian_t8]
    call secp256k1_field_sub_limbs
    lea rdi, [rip + secp256k1_jacobian_t4]
    lea rsi, [rip + secp256k1_jacobian_t8]
    lea rdx, [rip + secp256k1_jacobian_add_y]
    call secp256k1_field_mul_limbs
    mov rdi, r12
    lea rsi, [rip + secp256k1_jacobian_t6]
    lea rdx, [rip + secp256k1_jacobian_t9]
    call secp256k1_field_mul_limbs
    lea rdi, [rip + secp256k1_jacobian_add_y]
    lea rsi, [rip + secp256k1_jacobian_t9]
    lea rdx, [rip + secp256k1_jacobian_add_y]
    call secp256k1_field_sub_limbs

    mov rdi, r13
    lea rsi, [rip + secp256k1_jacobian_t3]
    lea rdx, [rip + secp256k1_jacobian_add_z]
    call secp256k1_field_mul_limbs

    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    call secp256k1_jacobian_double_finite_limbs

    mov rax, qword ptr [rsp]
    mov r8, rax
    xor r8, 1
    mov r9, qword ptr [rsp + 8]
    mov r10, r9
    xor r10, 1
    mov r11, qword ptr [rsp + 16]
    mov rax, r8
    and rax, r9
    and rax, r11
    mov qword ptr [rsp + 24], rax
    mov rdx, r8
    and rdx, r10
    or rdx, rax
    or rdx, qword ptr [rsp]
    mov qword ptr [rsp + 16], rdx

    mov rcx, qword ptr [rsp + 24]
    neg rcx
    lea rdi, [rip + secp256k1_jacobian_add_x]
    lea rsi, [rip + secp256k1_jacobian_rx]
    lea rdx, [rip + secp256k1_jacobian_rx]
    call secp256k1_field_select_mask
    mov rcx, qword ptr [rsp + 24]
    neg rcx
    lea rdi, [rip + secp256k1_jacobian_add_y]
    lea rsi, [rip + secp256k1_jacobian_ry]
    lea rdx, [rip + secp256k1_jacobian_ry]
    call secp256k1_field_select_mask
    mov rcx, qword ptr [rsp + 24]
    neg rcx
    lea rdi, [rip + secp256k1_jacobian_add_z]
    lea rsi, [rip + secp256k1_jacobian_rz]
    lea rdx, [rip + secp256k1_jacobian_rz]
    call secp256k1_field_select_mask

    mov qword ptr [rip + secp256k1_jacobian_t0], 1
    mov qword ptr [rip + secp256k1_jacobian_t0 + 8], 0
    mov qword ptr [rip + secp256k1_jacobian_t0 + 16], 0
    mov qword ptr [rip + secp256k1_jacobian_t0 + 24], 0
    mov rcx, qword ptr [rsp]
    neg rcx
    lea rdi, [rip + secp256k1_jacobian_rx]
    lea rsi, [rip + secp256k1_basepoint_x]
    lea rdx, [rip + secp256k1_jacobian_rx]
    call secp256k1_field_select_mask
    mov rcx, qword ptr [rsp]
    neg rcx
    lea rdi, [rip + secp256k1_jacobian_ry]
    lea rsi, [rip + secp256k1_basepoint_y]
    lea rdx, [rip + secp256k1_jacobian_ry]
    call secp256k1_field_select_mask
    mov rcx, qword ptr [rsp]
    neg rcx
    lea rdi, [rip + secp256k1_jacobian_rz]
    lea rsi, [rip + secp256k1_jacobian_t0]
    lea rdx, [rip + secp256k1_jacobian_rz]
    call secp256k1_field_select_mask

    mov rcx, qword ptr [rsp + 16]
    neg rcx
    lea rdi, [rip + secp256k1_field_zero]
    lea rsi, [rip + secp256k1_jacobian_rx]
    lea rdx, [rip + secp256k1_jacobian_rx]
    call secp256k1_field_select_mask
    mov rcx, qword ptr [rsp + 16]
    neg rcx
    lea rdi, [rip + secp256k1_field_zero]
    lea rsi, [rip + secp256k1_jacobian_ry]
    lea rdx, [rip + secp256k1_jacobian_ry]
    call secp256k1_field_select_mask
    mov rcx, qword ptr [rsp + 16]
    neg rcx
    lea rdi, [rip + secp256k1_field_zero]
    lea rsi, [rip + secp256k1_jacobian_rz]
    lea rdx, [rip + secp256k1_jacobian_rz]
    call secp256k1_field_select_mask

    mov rax, qword ptr [rsp + 16]
    add rsp, 32
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
    call secp256k1_jacobian_double_finite_limbs
    mov r13, qword ptr [rip + secp256k1_jacobian_acc_infinity]
    xor r13, 1
    mov ecx, r13d
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
    call secp256k1_jacobian_mixed_add_masked_limbs
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


.section .rodata
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


.section .note.GNU-stack,"",@progbits
