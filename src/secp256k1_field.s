.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global run_secp256k1_field_add
.global run_secp256k1_field_sub
.global run_secp256k1_field_mul
.global run_secp256k1_field_square
.global run_secp256k1_field_inv
.global store64_be_at_r13
.global load_be32_to_le4
.global store_le4_to_be32
.global secp256k1_field_add_limbs
.global secp256k1_field_sub_limbs
.global secp256k1_field_mul_limbs
.global copy_field4
.global secp256k1_field_select_mask
.global secp256k1_field_is_zero_limbs
.global secp256k1_field_equal_limbs
.global secp256k1_field_is_canonical_limbs
.global load_secp256k1_field_arg
.global secp256k1_field_inverse_limbs
.global secp256k1_field_sqrt_limbs
.extern usage_exit
.extern field_arg_error
.extern exit_process
.extern write_all
.extern hex_encode
.extern hex32_decode
.extern hex_buf
.extern secp256k1_field_p_le
.extern secp256k1_field_p_minus_2_le
.extern secp256k1_field_sqrt_exp_le
.extern secp256k1_field_a_bytes
.extern secp256k1_field_b_bytes
.extern secp256k1_field_out_bytes
.extern secp256k1_field_a
.extern secp256k1_field_b
.extern secp256k1_field_out
.extern secp256k1_field_tmp
.extern secp256k1_field_acc
.extern secp256k1_field_mul_base
.extern secp256k1_inv_base
.extern secp256k1_inv_result
.extern secp256k1_inv_tmp

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

.section .note.GNU-stack,"",@progbits
