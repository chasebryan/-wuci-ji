.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global run_secp256k1_scalar_add
.global run_secp256k1_scalar_sub
.global run_secp256k1_scalar_mul
.global run_secp256k1_scalar_inv
.global run_frost_secp256k1_lagrange
.global write_secp256k1_scalar_out
.global secp256k1_scalar_gt_limbs
.global load_secp256k1_scalar_arg
.global secp256k1_scalar_add_limbs
.global secp256k1_scalar_sub_limbs
.global secp256k1_scalar_mul_limbs
.global secp256k1_scalar_inverse_limbs
.global secp256k1_scalar_conditional_sub_n
.global secp256k1_scalar_is_zero_limbs
.global secp256k1_scalar_equal_limbs
.global secp256k1_scalar_is_canonical_limbs
.extern usage_exit
.extern scalar_arg_error
.extern frost_lagrange_arg_error
.extern exit_process
.extern write_all
.extern hex_encode
.extern hex32_decode
.extern load_be32_to_le4
.extern store_le4_to_be32
.extern copy_field4
.extern secp256k1_field_select_mask
.extern secp256k1_field_is_zero_limbs
.extern secp256k1_field_equal_limbs
.extern hex_buf
.extern secp256k1_field_out_bytes
.extern secp256k1_scalar_bytes
.extern secp256k1_scalar_a
.extern secp256k1_scalar_b
.extern secp256k1_scalar_out
.extern secp256k1_scalar_tmp
.extern secp256k1_scalar_acc
.extern secp256k1_scalar_mul_base
.extern secp256k1_scalar_inv_base
.extern secp256k1_scalar_inv_result
.extern secp256k1_scalar_inv_tmp
.extern secp256k1_scalar_lagrange_id
.extern secp256k1_scalar_lagrange_num
.extern secp256k1_scalar_lagrange_den
.extern frost_secp256k1_order_le
.extern frost_secp256k1_order_minus_2_le

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
    push r14
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
    and edx, 1
    mov r14, rdx
    neg r14
    lea rdi, [rip + secp256k1_scalar_inv_result]
    lea rsi, [rip + secp256k1_scalar_inv_base]
    lea rdx, [rip + secp256k1_scalar_inv_tmp]
    call secp256k1_scalar_mul_limbs
    mov rcx, r14
    lea rdi, [rip + secp256k1_scalar_inv_result]
    lea rsi, [rip + secp256k1_scalar_inv_tmp]
    lea rdx, [rip + secp256k1_scalar_inv_result]
    call secp256k1_field_select_mask

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

    pop r14
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

.section .note.GNU-stack,"",@progbits
