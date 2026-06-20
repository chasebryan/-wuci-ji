	.file	"x25519.s"
	.intel_syntax noprefix
	.text
	.p2align 4
	.type	load64_le, @function
load64_le:
	mov	rax, QWORD PTR [rdi]
	ret
	.size	load64_le, .-load64_le
	.p2align 4
	.type	fe_carry, @function
fe_carry:
	mov	rsi, rdi
	push	rbx
	mov	rdx, QWORD PTR [rdi]
	mov	r11d, 2
	mov	rdi, QWORD PTR [rdi+8]
	mov	r10, QWORD PTR [rsi+16]
	movabs	rcx, 2251799813685247
	mov	r9, QWORD PTR [rsi+24]
	mov	r8, QWORD PTR [rsi+32]
.L4:
	mov	rax, rdx
	and	rdx, rcx
	shr	rax, 51
	add	rax, rdi
	mov	rdi, rax
	shr	rax, 51
	add	rax, r10
	and	rdi, rcx
	mov	r10, rax
	shr	rax, 51
	add	rax, r9
	and	r10, rcx
	mov	r9, rax
	shr	rax, 51
	add	rax, r8
	and	r9, rcx
	mov	r8, rax
	shr	rax, 51
	lea	rbx, [rax+rax*8]
	and	r8, rcx
	lea	rax, [rax+rbx*2]
	add	rdx, rax
	cmp	r11d, 1
	jne	.L5
	and	rcx, rdx
	shr	rdx, 51
	mov	QWORD PTR [rsi+16], r10
	pop	rbx
	add	rdx, rdi
	mov	QWORD PTR [rsi+24], r9
	mov	QWORD PTR [rsi+32], r8
	mov	QWORD PTR [rsi], rcx
	mov	QWORD PTR [rsi+8], rdx
	ret
	.p2align 4,,10
	.p2align 3
.L5:
	mov	r11d, 1
	jmp	.L4
	.size	fe_carry, .-fe_carry
	.p2align 4
	.type	fe_mul, @function
fe_mul:
	push	r15
	mov	rcx, rdi
	mov	rdi, rsi
	xor	r10d, r10d
	push	r14
	mov	rax, rdx
	xor	r15d, r15d
	push	r13
	push	r12
	xor	r12d, r12d
	push	rbx
	sub	rsp, 160
	mov	rbx, QWORD PTR [rsi]
	mov	r9, QWORD PTR [rdx+32]
	xor	esi, esi
	mov	r14, QWORD PTR [rdi+8]
	mov	r11, QWORD PTR [rdi+16]
	mov	QWORD PTR [rsp+56], rsi
	xor	esi, esi
	mov	QWORD PTR [rsp], rbx
	mov	rbx, QWORD PTR [rdx]
	mov	QWORD PTR [rsp+80], r9
	xor	r9d, r9d
	mov	r8, QWORD PTR [rdx+24]
	mov	QWORD PTR [rsp+48], rbx
	mov	rbx, QWORD PTR [rdi+32]
	mov	QWORD PTR [rsp+120], r9
	mov	r9, QWORD PTR [rdx+8]
	mov	rdx, r14
	mov	QWORD PTR [rsp+16], rbx
	mov	rbx, QWORD PTR [rdi+24]
	mov	QWORD PTR [rsp+88], r10
	xor	r10d, r10d
	mov	QWORD PTR [rsp+112], r8
	mov	QWORD PTR [rsp+24], rsi
	xor	esi, esi
	mov	QWORD PTR [rsp+144], r9
	mov	QWORD PTR [rsp+152], r10
	mov	QWORD PTR [rsp+32], rbx
	mulx	r9, r8, QWORD PTR [rax+32]
	mov	rdx, r11
	movabs	rbx, 2251799813685247
	mov	QWORD PTR [rsp+40], rsi
	mulx	rdi, rsi, QWORD PTR [rax+24]
	mov	rdx, QWORD PTR [rsp+16]
	mov	QWORD PTR [rsp+96], r11
	mov	QWORD PTR [rsp+64], r14
	mov	QWORD PTR [rsp+72], r15
	add	rsi, r8
	mov	QWORD PTR [rsp+104], r12
	adc	rdi, r9
	mulx	r9, r8, QWORD PTR [rax+8]
	mov	rdx, QWORD PTR [rsp+32]
	add	r8, rsi
	adc	r9, rdi
	mulx	rdi, rsi, QWORD PTR [rax+16]
	mov	rdx, QWORD PTR [rsp]
	add	r8, rsi
	adc	r9, rdi
	mov	rsi, r8
	mov	rdi, r9
	sal	rsi, 2
	shld	rdi, r8, 2
	add	rsi, r8
	adc	rdi, r9
	shld	rdi, rsi, 2
	sal	rsi, 2
	sub	rsi, r8
	sbb	rdi, r9
	mulx	r9, r8, QWORD PTR [rax]
	mov	rdx, QWORD PTR [rsp+96]
	add	rsi, r8
	adc	rdi, r9
	mulx	r9, r8, QWORD PTR [rsp+80]
	mov	rdx, QWORD PTR [rsp+112]
	mov	r15, rsi
	mulx	r11, r10, QWORD PTR [rsp+32]
	mov	rdx, QWORD PTR [rsp+16]
	add	r10, r8
	adc	r11, r9
	mulx	r9, r8, QWORD PTR [rax+16]
	mov	rdx, QWORD PTR [rsp]
	add	r10, r8
	adc	r11, r9
	mov	r8, r10
	mov	r9, r11
	sal	r8, 2
	shld	r9, r10, 2
	add	r8, r10
	adc	r9, r11
	shld	r9, r8, 2
	sal	r8, 2
	sub	r8, r10
	sbb	r9, r11
	mulx	r11, r10, QWORD PTR [rax+8]
	mov	rdx, QWORD PTR [rsp+64]
	mulx	r13, r12, QWORD PTR [rsp+48]
	mov	rdx, QWORD PTR [rsp]
	add	r10, r12
	adc	r11, r13
	add	r10, r8
	mov	r8, rsi
	adc	r11, r9
	shrd	r8, rdi, 51
	mov	r9, rdi
	shr	r9, 51
	add	r10, r8
	adc	r11, r9
	mulx	r9, r8, QWORD PTR [rax+16]
	and	r15, rbx
	mov	r13, r10
	mov	rdx, QWORD PTR [rsp+64]
	mov	r14, r11
	mov	r12, r13
	mov	QWORD PTR [rsp+128], r13
	mov	r13, r14
	mov	QWORD PTR [rsp+136], r14
	mulx	rdi, rsi, QWORD PTR [rax+8]
	mov	rdx, QWORD PTR [rsp+96]
	add	rsi, r8
	adc	rdi, r9
	mulx	r9, r8, QWORD PTR [rsp+48]
	mov	rdx, QWORD PTR [rsp+80]
	mulx	r11, r10, QWORD PTR [rsp+32]
	mov	rdx, QWORD PTR [rsp+16]
	add	rsi, r8
	adc	rdi, r9
	mulx	r9, r8, QWORD PTR [rsp+112]
	mov	rdx, QWORD PTR [rsp+112]
	add	r10, r8
	adc	r11, r9
	mov	r8, r10
	mov	r9, r11
	sal	r8, 2
	shld	r9, r10, 2
	add	r8, r10
	adc	r9, r11
	shld	r9, r8, 2
	sal	r8, 2
	sub	r8, r10
	sbb	r9, r11
	add	rsi, r8
	adc	rdi, r9
	mulx	r9, r8, QWORD PTR [rsp]
	mov	rdx, QWORD PTR [rsp+64]
	shr	r13, 51
	shrd	r12, r14, 51
	add	r12, rsi
	adc	r13, rdi
	mulx	rdi, rsi, QWORD PTR [rax+16]
	mov	rdx, QWORD PTR [rsp+48]
	add	rsi, r8
	adc	rdi, r9
	mulx	r9, r8, QWORD PTR [rsp+32]
	mov	rdx, QWORD PTR [rsp+96]
	add	r8, rsi
	adc	r9, rdi
	mulx	rdi, rsi, QWORD PTR [rax+8]
	mov	rdx, QWORD PTR [rsp+16]
	mulx	r11, r10, QWORD PTR [rsp+80]
	mov	rdx, QWORD PTR [rsp+80]
	add	r8, rsi
	adc	r9, rdi
	mov	rsi, r10
	mov	rdi, r11
	sal	rsi, 2
	shld	rdi, r10, 2
	add	rsi, r10
	adc	rdi, r11
	shld	rdi, rsi, 2
	sal	rsi, 2
	sub	rsi, r10
	sbb	rdi, r11
	add	rsi, r8
	mov	r8, r12
	mulx	r11, r10, QWORD PTR [rsp]
	adc	rdi, r9
	mov	rdx, QWORD PTR [rsp+112]
	shrd	r8, r13, 51
	mov	r9, r13
	shr	r9, 51
	add	rsi, r8
	adc	rdi, r9
	mulx	r9, r8, QWORD PTR [rsp+64]
	mov	QWORD PTR [rsp], rsi
	mov	rdx, QWORD PTR [rsp+144]
	mov	QWORD PTR [rsp+8], rdi
	add	r8, r10
	adc	r9, r11
	mulx	r11, r10, QWORD PTR [rsp+32]
	mov	rdx, QWORD PTR [rsp+96]
	add	r10, r8
	adc	r11, r9
	mulx	r9, r8, QWORD PTR [rax+16]
	mov	rdx, QWORD PTR [rsp+16]
	add	r8, r10
	adc	r9, r11
	mulx	r11, r10, QWORD PTR [rsp+48]
	add	r10, r8
	adc	r11, r9
	shrd	rsi, rdi, 51
	mov	r8, rsi
	shr	rdi, 51
	mov	rsi, QWORD PTR [rsp]
	add	r8, r10
	mov	r9, rdi
	adc	r9, r11
	mov	rax, r8
	and	r12, rbx
	and	rsi, rbx
	shrd	rax, r9, 51
	and	r8, rbx
	mov	QWORD PTR [rcx+16], r12
	lea	rdi, [rax+rax*8]
	mov	QWORD PTR [rcx+24], rsi
	lea	rax, [rax+rdi*2]
	mov	QWORD PTR [rcx+32], r8
	mov	rdi, rcx
	add	rax, r15
	mov	QWORD PTR [rcx], rax
	mov	rax, QWORD PTR [rsp+128]
	and	rax, rbx
	mov	QWORD PTR [rcx+8], rax
	add	rsp, 160
	pop	rbx
	pop	r12
	pop	r13
	pop	r14
	pop	r15
	jmp	fe_carry
	.size	fe_mul, .-fe_mul
	.p2align 4
	.type	x25519_scalar_mult.part.0, @function
x25519_scalar_mult.part.0:
	push	rbp
	mov	rcx, rdx
	mov	r8, rdi
	vpxor	xmm1, xmm1, xmm1
	mov	rdi, rcx
	mov	rbp, rsp
	push	r15
	push	r14
	push	r13
	push	r12
	push	rbx
	and	rsp, -32
	sub	rsp, 1344
	vmovdqu	ymm0, YMMWORD PTR [rsi]
	movabs	rsi, 2251799813685247
	vmovdqa	YMMWORD PTR [rsp+96], ymm0
	vpextrb	eax, xmm0, 0
	vextracti128	xmm0, ymm0, 0x1
	vpextrb	edx, xmm0, 15
	and	eax, -8
	and	edx, 127
	mov	BYTE PTR [rsp+96], al
	or	edx, 64
	mov	BYTE PTR [rsp+127], dl
	call	load64_le
	lea	rdi, [rcx+6]
	and	rax, rsi
	mov	QWORD PTR [rsp+128], rax
	call	load64_le
	lea	rdi, [rcx+12]
	shr	rax, 3
	and	rax, rsi
	mov	QWORD PTR [rsp+136], rax
	call	load64_le
	lea	rdi, [rcx+19]
	shr	rax, 6
	and	rax, rsi
	mov	QWORD PTR [rsp+144], rax
	call	load64_le
	lea	rdi, [rcx+24]
	shr	rax
	and	rax, rsi
	mov	QWORD PTR [rsp+152], rax
	call	load64_le
	vmovdqa	ymm0, YMMWORD PTR .LC0[rip]
	mov	QWORD PTR [rsp+224], 0
	mov	QWORD PTR [rsp+288], 0
	shr	rax, 12
	vmovdqa	YMMWORD PTR [rsp+192], ymm0
	and	rax, rsi
	mov	QWORD PTR [rsp+160], rax
	xor	eax, eax
	vmovdqa	YMMWORD PTR [rsp+256], ymm1
.L10:
	mov	rcx, QWORD PTR [rsp+128+rax]
	mov	QWORD PTR [rsp+320+rax], rcx
	add	rax, 8
	cmp	rax, 40
	jne	.L10
	mov	DWORD PTR [rsp+88], 254
	xor	edi, edi
	lea	rbx, [rsp+192]
	movzx	eax, dl
	mov	QWORD PTR [rsp+8], r8
	lea	r12, [rsp+256]
	lea	r13, [rsp+384]
	mov	rsi, rdi
	lea	r14, [rsp+960]
	lea	r15, [rsp+1024]
	mov	QWORD PTR [rsp+416], 0
	vmovdqa	YMMWORD PTR [rsp+384], ymm0
	.p2align 4
	.p2align 3
.L22:
	mov	edx, DWORD PTR [rsp+88]
	mov	QWORD PTR [rsp+16], rbx
	and	edx, 7
	sarx	ecx, eax, edx
	mov	eax, ecx
	mov	DWORD PTR [rsp+52], ecx
	and	eax, 1
	mov	QWORD PTR [rsp+56], rax
	xor	esi, eax
	lea	rax, [rsp+320]
	mov	QWORD PTR [rsp+32], rax
	mov	rcx, rax
	mov	rax, rbx
.L11:
	mov	rdx, QWORD PTR [rax]
	mov	rdi, QWORD PTR [rcx]
	test	sil, sil
	mov	r8, rdx
	cmove	rdx, rdi
	cmovne	r8, rdi
	add	rax, 8
	add	rcx, 8
	lea	rdi, [rsp+232]
	mov	QWORD PTR [rcx-8], rdx
	mov	QWORD PTR [rax-8], r8
	cmp	rax, rdi
	jne	.L11
	mov	QWORD PTR [rsp+40], r12
	mov	rcx, r13
	mov	rax, r12
	mov	QWORD PTR [rsp+24], r13
.L12:
	mov	rdx, QWORD PTR [rax]
	mov	rdi, QWORD PTR [rcx]
	test	sil, sil
	mov	r8, rdx
	cmove	rdx, rdi
	cmovne	r8, rdi
	add	rax, 8
	add	rcx, 8
	lea	rdi, [rsp+296]
	mov	QWORD PTR [rcx-8], rdx
	mov	QWORD PTR [rax-8], r8
	cmp	rax, rdi
	jne	.L12
	xor	eax, eax
.L13:
	mov	rdx, QWORD PTR [r12+rax]
	add	rdx, QWORD PTR [rbx+rax]
	mov	QWORD PTR [rsp+448+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L13
	lea	rdi, [rsp+448]
	call	fe_carry
	lea	rdx, [rsp+448]
	lea	rdi, [rsp+576]
	mov	rsi, rdx
	call	fe_mul
	xor	eax, eax
.L14:
	mov	rdx, QWORD PTR four_p.2[rax]
	add	rdx, QWORD PTR [rbx+rax]
	sub	rdx, QWORD PTR [r12+rax]
	mov	QWORD PTR [rsp+512+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L14
	lea	rdi, [rsp+512]
	call	fe_carry
	lea	rdx, [rsp+512]
	lea	rdi, [rsp+640]
	mov	rsi, rdx
	call	fe_mul
	xor	eax, eax
.L15:
	mov	rdx, QWORD PTR four_p.2[rax]
	add	rdx, QWORD PTR [rsp+576+rax]
	sub	rdx, QWORD PTR [rsp+640+rax]
	mov	QWORD PTR [rsp+704+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L15
	lea	rdi, [rsp+704]
	call	fe_carry
	xor	eax, eax
.L16:
	mov	rdx, QWORD PTR [r13+0+rax]
	add	rdx, QWORD PTR [rsp+320+rax]
	mov	QWORD PTR [rsp+768+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L16
	lea	rdi, [rsp+768]
	call	fe_carry
	xor	eax, eax
.L17:
	mov	rdx, QWORD PTR four_p.2[rax]
	add	rdx, QWORD PTR [rsp+320+rax]
	sub	rdx, QWORD PTR [r13+0+rax]
	mov	QWORD PTR [rsp+832+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L17
	lea	rdi, [rsp+832]
	call	fe_carry
	lea	rdx, [rsp+448]
	lea	rsi, [rsp+832]
	lea	rdi, [rsp+896]
	call	fe_mul
	lea	rdx, [rsp+512]
	lea	rsi, [rsp+768]
	mov	rdi, r14
	call	fe_mul
	xor	eax, eax
.L18:
	mov	rdx, QWORD PTR [r14+rax]
	add	rdx, QWORD PTR [rsp+896+rax]
	mov	QWORD PTR [r15+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L18
	mov	rdi, r15
	call	fe_carry
	mov	rdx, r15
	mov	rsi, r15
	lea	rdi, [rsp+320]
	call	fe_mul
	xor	eax, eax
.L19:
	mov	rdx, QWORD PTR four_p.2[rax]
	add	rdx, QWORD PTR [rsp+896+rax]
	sub	rdx, QWORD PTR [r14+rax]
	mov	QWORD PTR [r15+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L19
	mov	rdi, r15
	call	fe_carry
	mov	rdx, r15
	mov	rsi, r15
	lea	rdi, [rsp+1088]
	call	fe_mul
	lea	rdx, [rsp+128]
	lea	rsi, [rsp+1088]
	mov	rdi, r13
	call	fe_mul
	lea	rdx, [rsp+640]
	lea	rsi, [rsp+576]
	mov	rdi, rbx
	call	fe_mul
	mov	rax, QWORD PTR [rsp+704]
	mov	ecx, 121666
	mov	rdx, rax
	mulx	r9, r8, rcx
	mov	rdx, QWORD PTR [rsp+712]
	mulx	rdi, rsi, rcx
	mov	rax, r8
	mov	rdx, r9
	shrd	rax, r9, 51
	shr	rdx, 51
	mov	r10, rax
	mov	r11, rdx
	mov	rdx, QWORD PTR [rsp+720]
	movabs	rax, 2251799813685247
	add	r10, rsi
	adc	r11, rdi
	mulx	rdi, rsi, rcx
	and	rax, r8
	mov	QWORD PTR [rsp+80], rax
	mov	rax, r10
	mov	rdx, r11
	shrd	rax, r11, 51
	shr	rdx, 51
	add	rsi, rax
	mov	rax, QWORD PTR [rsp+728]
	adc	rdi, rdx
	mov	r8, rsi
	mul	rcx
	shrd	r8, rdi, 51
	mov	r9, rdi
	mov	rdi, r15
	shr	r9, 51
	add	rax, r8
	adc	rdx, r9
	mov	QWORD PTR [rsp+64], rax
	mov	rax, QWORD PTR [rsp+64]
	mov	QWORD PTR [rsp+72], rdx
	mov	rdx, QWORD PTR [rsp+736]
	mulx	r9, r8, rcx
	mov	rdx, QWORD PTR [rsp+72]
	shrd	rax, rdx, 51
	shr	rdx, 51
	add	r8, rax
	mov	rax, QWORD PTR [rsp+80]
	adc	r9, rdx
	mov	rdx, r8
	shrd	rdx, r9, 51
	lea	rcx, [rdx+rdx*8]
	lea	rdx, [rdx+rcx*2]
	add	rdx, rax
	movabs	rax, 2251799813685247
	and	rsi, rax
	mov	QWORD PTR [rsp+1024], rdx
	movabs	rdx, 2251799813685247
	mov	QWORD PTR [rsp+1040], rsi
	mov	rsi, rax
	and	rdx, r10
	and	rax, QWORD PTR [rsp+64]
	and	r8, rsi
	mov	QWORD PTR [rsp+1048], rax
	mov	QWORD PTR [rsp+1032], rdx
	mov	QWORD PTR [rsp+1056], r8
	call	fe_carry
	xor	eax, eax
.L20:
	mov	rdx, QWORD PTR [r15+rax]
	add	rdx, QWORD PTR [rsp+576+rax]
	mov	QWORD PTR [rsp+1088+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L20
	lea	rdi, [rsp+1088]
	call	fe_carry
	lea	rdx, [rsp+1088]
	lea	rsi, [rsp+704]
	mov	rdi, r12
	call	fe_mul
	sub	DWORD PTR [rsp+88], 1
	mov	eax, DWORD PTR [rsp+88]
	cmp	eax, -1
	je	.L21
	sar	eax, 3
	mov	rsi, QWORD PTR [rsp+56]
	cdqe
	movzx	eax, BYTE PTR [rsp+96+rax]
	jmp	.L22
.L21:
	movzx	edx, BYTE PTR [rsp+52]
	mov	r8, QWORD PTR [rsp+8]
	mov	rsi, QWORD PTR [rsp+32]
	mov	rax, QWORD PTR [rsp+16]
	and	edx, 1
.L23:
	mov	rcx, QWORD PTR [rax]
	mov	rdi, QWORD PTR [rsi]
	test	dl, dl
	mov	r9, rcx
	cmove	rcx, rdi
	cmovne	r9, rdi
	add	rax, 8
	add	rsi, 8
	mov	QWORD PTR [rsi-8], rcx
	lea	rcx, [rsp+232]
	mov	QWORD PTR [rax-8], r9
	cmp	rcx, rax
	jne	.L23
	mov	rax, QWORD PTR [rsp+40]
	mov	rsi, QWORD PTR [rsp+24]
.L24:
	mov	rcx, QWORD PTR [rax]
	mov	rdi, QWORD PTR [rsi]
	test	dl, dl
	mov	r9, rcx
	cmove	rcx, rdi
	cmovne	r9, rdi
	add	rax, 8
	add	rsi, 8
	mov	QWORD PTR [rsi-8], rcx
	lea	rcx, [rsp+296]
	mov	QWORD PTR [rax-8], r9
	cmp	rax, rcx
	jne	.L24
	mov	QWORD PTR [rsp+1184], 0
	xor	eax, eax
	vmovdqa	YMMWORD PTR [rsp+1152], ymm0
.L25:
	mov	rdx, QWORD PTR [r12+rax]
	mov	QWORD PTR [rsp+1216+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L25
	mov	QWORD PTR [rsp+88], r8
	mov	r15d, 254
	lea	r13, [rsp+1152]
	lea	r14, [rsp+1280]
	.p2align 4
	.p2align 3
.L28:
	mov	rdx, r13
	mov	rsi, r13
	mov	rdi, r14
	call	fe_mul
	xor	eax, eax
.L26:
	mov	rdx, QWORD PTR [r14+rax]
	mov	QWORD PTR [r13+0+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L26
	mov	eax, r15d
	shr	eax, 3
	movzx	edx, BYTE PTR exp.1[rax]
	mov	eax, r15d
	and	eax, 7
	bt	edx, eax
	jc	.L27
.L31:
	sub	r15d, 1
	jnb	.L28
	mov	r8, QWORD PTR [rsp+88]
	xor	eax, eax
.L29:
	mov	rdx, QWORD PTR [r13+0+rax]
	mov	QWORD PTR [r12+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L29
	mov	rdx, r12
	mov	rsi, rbx
	mov	rdi, rbx
	mov	QWORD PTR [rsp+88], r8
	call	fe_mul
	mov	r8, QWORD PTR [rsp+88]
	xor	eax, eax
.L32:
	mov	rdx, QWORD PTR [rbx+rax]
	mov	QWORD PTR [r14+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L32
	mov	rdi, r14
	mov	QWORD PTR [rsp+88], r8
	call	fe_carry
	mov	rdx, QWORD PTR [rsp+1280]
	mov	rdi, r14
	lea	rax, [rdx+19]
	shr	rax, 51
	add	rax, QWORD PTR [rsp+1288]
	shr	rax, 51
	add	rax, QWORD PTR [rsp+1296]
	shr	rax, 51
	add	rax, QWORD PTR [rsp+1304]
	shr	rax, 51
	add	rax, QWORD PTR [rsp+1312]
	shr	rax, 51
	lea	rcx, [rax+rax*8]
	lea	rax, [rax+rcx*2]
	add	rax, rdx
	mov	QWORD PTR [rsp+1280], rax
	call	fe_carry
	mov	rsi, QWORD PTR [rsp+1288]
	mov	r8, QWORD PTR [rsp+88]
	xor	eax, eax
	mov	rcx, rsi
	sal	rcx, 51
	or	rcx, QWORD PTR [rsp+1280]
	.p2align 5
	.p2align 4
	.p2align 3
.L33:
	lea	edx, [0+rax*8]
	shrx	rdx, rcx, rdx
	mov	BYTE PTR [r8+rax], dl
	add	rax, 1
	cmp	rax, 8
	jne	.L33
	mov	rcx, QWORD PTR [rsp+1296]
	shr	rsi, 13
	mov	rax, rcx
	sal	rax, 38
	or	rsi, rax
	xor	eax, eax
	.p2align 5
	.p2align 4
	.p2align 3
.L34:
	lea	edx, [0+rax*8]
	shrx	rdx, rsi, rdx
	mov	BYTE PTR [r8+8+rax], dl
	add	rax, 1
	cmp	rax, 8
	jne	.L34
	mov	rsi, QWORD PTR [rsp+1304]
	shr	rcx, 26
	mov	rax, rsi
	sal	rax, 25
	or	rcx, rax
	xor	eax, eax
	.p2align 5
	.p2align 4
	.p2align 3
.L35:
	lea	edx, [0+rax*8]
	shrx	rdx, rcx, rdx
	mov	BYTE PTR [r8+16+rax], dl
	add	rax, 1
	cmp	rax, 8
	jne	.L35
	shr	rsi, 39
	mov	eax, 12
	shlx	rcx, QWORD PTR [rsp+1312], rax
	xor	eax, eax
	or	rcx, rsi
	.p2align 5
	.p2align 4
	.p2align 3
.L36:
	lea	edx, [0+rax*8]
	shrx	rdx, rcx, rdx
	mov	BYTE PTR [r8+24+rax], dl
	add	rax, 1
	cmp	rax, 8
	jne	.L36
	vmovdqu	ymm1, YMMWORD PTR [r8]
	vextracti128	xmm0, ymm1, 0x1
	vpor	xmm0, xmm0, xmm1
	vpsrldq	xmm1, xmm0, 8
	vpor	xmm0, xmm0, xmm1
	vpsrldq	xmm1, xmm0, 4
	vpor	xmm0, xmm0, xmm1
	vpsrldq	xmm1, xmm0, 2
	vpor	xmm0, xmm0, xmm1
	vpsrldq	xmm1, xmm0, 1
	vpor	xmm0, xmm0, xmm1
	vpextrb	eax, xmm0, 0
	test	al, al
	vzeroupper
	setne	al
	lea	rsp, [rbp-40]
	pop	rbx
	movzx	eax, al
	pop	r12
	pop	r13
	pop	r14
	pop	r15
	pop	rbp
	ret
	.p2align 4,,10
	.p2align 3
.L27:
	lea	rdx, [rsp+1216]
	mov	rsi, r13
	mov	rdi, r14
	call	fe_mul
	xor	eax, eax
.L30:
	mov	rdx, QWORD PTR [r14+rax]
	mov	QWORD PTR [r13+0+rax], rdx
	add	rax, 8
	cmp	rax, 40
	jne	.L30
	jmp	.L31
	.size	x25519_scalar_mult.part.0, .-x25519_scalar_mult.part.0
	.p2align 4
	.globl	x25519_scalar_mult
	.type	x25519_scalar_mult, @function
x25519_scalar_mult:
	push	rbp
	mov	r10, rdx
	mov	r8d, OFFSET FLAT:blocklist.3
	mov	rbp, rsp
	push	r13
	mov	r13, rdx
	push	r12
	mov	r12, rsi
	push	rbx
	mov	rbx, rdi
	and	rsp, -32
	sub	rsp, 32
	mov	DWORD PTR [rsp], 0
	mov	r9, rsp
	lea	rdi, [rsp+7]
	mov	DWORD PTR [rsp+3], 0
	.p2align 4
	.p2align 3
.L62:
	movzx	esi, BYTE PTR [r10]
	mov	r11, r9
	mov	rdx, r8
	mov	rax, r9
	.p2align 5
	.p2align 4
	.p2align 3
.L63:
	movzx	ecx, BYTE PTR [rdx]
	add	rdx, 32
	xor	ecx, esi
	or	BYTE PTR [rax], cl
	add	rax, 1
	cmp	rax, rdi
	jne	.L63
	add	r8, 1
	add	r10, 1
	cmp	r8, OFFSET FLAT:blocklist.3+31
	jne	.L62
	movzx	ecx, BYTE PTR [r13+31]
	mov	eax, OFFSET FLAT:blocklist.3+31
	and	ecx, 127
	.p2align 5
	.p2align 4
	.p2align 3
.L65:
	movzx	edx, BYTE PTR [rax]
	add	rax, 32
	xor	edx, ecx
	or	BYTE PTR [r9], dl
	add	r9, 1
	cmp	r9, rdi
	jne	.L65
	xor	edx, edx
	.p2align 5
	.p2align 4
	.p2align 3
.L66:
	movzx	eax, BYTE PTR [r11]
	add	r11, 1
	sub	eax, 1
	or	edx, eax
	cmp	r11, rdi
	jne	.L66
	and	dh, 1
	jne	.L67
	lea	rsp, [rbp-24]
	mov	rdx, r13
	mov	rsi, r12
	mov	rdi, rbx
	pop	rbx
	pop	r12
	pop	r13
	pop	rbp
	jmp	x25519_scalar_mult.part.0
.L67:
	lea	rsp, [rbp-24]
	xor	eax, eax
	pop	rbx
	pop	r12
	pop	r13
	pop	rbp
	ret
	.size	x25519_scalar_mult, .-x25519_scalar_mult
	.p2align 4
	.globl	x25519_basepoint
	.type	x25519_basepoint, @function
x25519_basepoint:
	mov	edx, OFFSET FLAT:basepoint.0
	jmp	x25519_scalar_mult
	.size	x25519_basepoint, .-x25519_basepoint
	.section	.rodata
	.align 32
	.type	basepoint.0, @object
	.size	basepoint.0, 32
basepoint.0:
	.string	"\t"
	.zero	30
	.align 32
	.type	exp.1, @object
	.size	exp.1, 32
exp.1:
	.ascii	"\353\377\377\377\377\377\377\377\377\377\377\377\377\377\377"
	.ascii	"\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377"
	.ascii	"\377\177"
	.align 32
	.type	four_p.2, @object
	.size	four_p.2, 40
four_p.2:
	.quad	9007199254740916
	.quad	9007199254740988
	.quad	9007199254740988
	.quad	9007199254740988
	.quad	9007199254740988
	.align 32
	.type	blocklist.3, @object
	.size	blocklist.3, 224
blocklist.3:
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\001"
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	"\340\353z|;A\270\256\026V\343\372\361\237\304j\332\t\215\353\2342\261\375\206b\005\026_I\270"
	.ascii	"_\234\225\274\243P\214$\261\320\261U\234\203\357[\004D\\\304"
	.ascii	"X\034\216\206\330\"N\335\320\237\021W"
	.ascii	"\354\377\377\377\377\377\377\377\377\377\377\377\377\377\377"
	.ascii	"\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377"
	.ascii	"\377\177"
	.ascii	"\355\377\377\377\377\377\377\377\377\377\377\377\377\377\377"
	.ascii	"\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377"
	.ascii	"\377\177"
	.ascii	"\356\377\377\377\377\377\377\377\377\377\377\377\377\377\377"
	.ascii	"\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377"
	.ascii	"\377\177"
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.LC0:
	.quad	1
	.quad	0
	.quad	0
	.quad	0
	.section	.note.GNU-stack,"",@progbits
