.intel_syntax noprefix

.equ SHA256_STATE, 0
.equ SHA256_BYTES, 32
.equ SHA256_BUFLEN, 40
.equ SHA256_BUFFER, 48

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

.section .text
.global sha256_init
.global sha256_update
.global sha256_final

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
