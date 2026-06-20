.intel_syntax noprefix

.include "include/wuci.inc"

.section .text
.global hex_encode
.global write_u64_decimal_stdout
.global write_manifest_labeled_sha256
.global hex32_decode
.global hex16_decode
.global hex12_decode
.global hex_decode_fixed
.global hex_u32_decode
.global hex_value
.global base64_emit_quad
.global base64_decode_char
.extern write_all
.extern sha256_init
.extern sha256_update
.extern sha256_final
.extern sha_ctx
.extern digest_buf
.extern hex_buf
.extern base64_quad_len
.extern base64_quad_pad
.extern base64_seen_padding
.extern base64_quad

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

.section .rodata
hex_chars:
    .ascii "0123456789abcdef"

.global base64_alphabet
base64_alphabet:
    .ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

.section .note.GNU-stack,"",@progbits
