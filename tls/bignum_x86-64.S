/**
 *		Tempesta FW
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/linkage.h>
#include <asm/alternative-asm.h>
#include <asm/export.h>
#include <asm/nospec-branch.h>

// TODO
//#if !defined(BMI2) || !defined(ADX)
//#error "BMI2 and ADX CPU extensions are required"
//#endif

/**
 * Add X = A + B, where A->used >= B->used.
 *
 * %RDI and %RSI - pointer to X and X->limbs correspondingly;
 * %RDX and %RCX - pointer to B and B->used correspondingly;
 * %R8 and %R9 - pointer to A and A->used correspondingly.
 */
ENTRY(mpi_add_x86_64)
	subq	%rcx, %r9
	addq	$1, %r9

	/*
	 * Initialize return value for X->used (RAX).
	 * Also clear (initialize) CF from.
	 */
	xorq	%rax, %rax

	/* Add loop over the smaller MPI. */
.add_smaller:
	movq	(%r8, %rax, 8), %r10
	adcq	(%rdx, %rax, 8), %r10
	movq	%r10, (%rdi, %rax, 8)
	incq	%rax
	loop	.add_smaller

	/* Add loop over the bigger MPI. */
	movq	%r9, %rcx
	jmp	.add_bigger
.add_bigger_loop:
	movq	$0, %r10
	adcq	(%r8, %rax, 8), %r10
	movq	%r10, (%rdi, %rax, 8)
	incq	%rax
.add_bigger:
	loop	.add_bigger_loop

	/* Propagate carry to a new X limb if necessary. */
	jnc	.done
	cmpq	%rax, %rsi
	jl	.enospc
	movq	$1, (%rdi, %rax, 8)
	incq	%rax

.done:
	ret
.enospc:
	movq	$-1, %rax
	ret
ENDPROC(mpi_add_x86_64)


/**
 * Subtract X = A - B, where A->used >= B->used.
 *
 * %RDI	- pointer to X;
 * %RSI	- pointer to B;
 * %RDX	- pointer to A;
 * %RCX	- B->used (used directly for looping);
 * %R8	- A->used.
 */
ENTRY(mpi_sub_x86_64)
	subq	%rcx, %r8
	addq	$1, %r8

	/* Get code address by size of tail. */
.section .rodata
.align 8
.sub_tail_jmp_tbl:
	.quad	.sub_tail0
	.quad	.sub_tail1
	.quad	.sub_tail2
	.quad	.sub_tail3
.text
	pushq	%rbx
	movq	%rcx, %rbx
	andq	$3, %rbx
	movq	.sub_tail_jmp_tbl(, %rbx, 8), %rbx

	xorq	%rax, %rax
	shrq	$2, %rcx
	jz	.small_b
	pushq	%r12
	clc
.sub_by_4:
	movq	(%rdx, %rax, 8), %r9
	movq	8(%rdx, %rax, 8), %r10
	movq	16(%rdx, %rax, 8), %r11
	movq	24(%rdx, %rax, 8), %r12
	sbbq	(%rsi, %rax, 8), %r9
	sbbq	8(%rsi, %rax, 8), %r10
	sbbq	16(%rsi, %rax, 8), %r11
	sbbq	24(%rsi, %rax, 8), %r12
	movq	%r9, (%rdi, %rax, 8)
	incq	%rax
	movq	%r10, (%rdi, %rax, 8)
	incq	%rax
	movq	%r11, (%rdi, %rax, 8)
	incq	%rax
	movq	%r12, (%rdi, %rax, 8)
	incq	%rax
	loop	.sub_by_4
	popq	%r12
	ANNOTATE_RETPOLINE_SAFE
	jmpq	*%rbx
.small_b:
	clc
	ANNOTATE_RETPOLINE_SAFE
	jmpq	*%rbx

.sub_tail3:
	movq	(%rdx, %rax, 8), %r9
	sbbq	(%rsi, %rax, 8), %r9
	movq	%r9, (%rdi, %rax, 8)
	incq	%rax
.sub_tail2:
	movq	(%rdx, %rax, 8), %r10
	sbbq	(%rsi, %rax, 8), %r10
	movq	%r10, (%rdi, %rax, 8)
	incq	%rax
.sub_tail1:
	movq	(%rdx, %rax, 8), %r11
	sbbq	(%rsi, %rax, 8), %r11
	movq	%r11, (%rdi, %rax, 8)
	incq	%rax
.sub_tail0:
	popq	%rbx

	/*
	 * Borrow required digets from the more significant limbs in @A.
	 * There is either CF = 0 or we have more limbs in @A.
	 */
	movq	%r8, %rcx
	jnc	.copy_msb
	jmp	.propagate_borrow
.propagate_borrow_loop:
	movq	(%rdx, %rax, 8), %r10
	sbbq	$0, %r10
	movq	%r10, (%rdi, %rax, 8)
	incq	%rax
	jnc	.need_copy
.propagate_borrow:
	loop	.propagate_borrow_loop
	ud2

	/* Copy the rest of A to X if no need to borrow. */
.copy_msb_loop:
	movq	(%rdx, %rax, 8), %r10
	movq	%r10, (%rdi, %rax, 8)
	incq	%rax
.copy_msb:
	loop	.copy_msb_loop
	ret

.need_copy:
	cmpq	%rdx, %rdi
	jne	.copy_msb
	ret
ENDPROC(mpi_sub_x86_64)

/*
 * Operands size specialized implementations of the function above.
 */
ENTRY(mpi_sub_x86_64_5_4)
	movq	(%rdx), %r8
	movq	8(%rdx), %r9
	movq	16(%rdx), %r10
	movq	24(%rdx), %r11
	subq	(%rsi), %r8
	sbbq	8(%rsi), %r9
	sbbq	16(%rsi), %r10
	sbbq	24(%rsi), %r11
	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	32(%rdx), %r8
	sbbq	$0, %r8
	movq	%r8, 32(%rdi)
	ret
ENDPROC(mpi_sub_x86_64_5_4)

ENTRY(mpi_sub_x86_64_4_4)
	movq	(%rdx), %r8
	movq	8(%rdx), %r9
	movq	16(%rdx), %r10
	movq	24(%rdx), %r11
	subq	(%rsi), %r8
	sbbq	8(%rsi), %r9
	sbbq	16(%rsi), %r10
	sbbq	24(%rsi), %r11
	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	ret
ENDPROC(mpi_sub_x86_64_4_4)

ENTRY(mpi_sub_x86_64_3_3)
	movq	(%rdx), %r8
	movq	8(%rdx), %r9
	movq	16(%rdx), %r10
	subq	(%rsi), %r8
	sbbq	8(%rsi), %r9
	sbbq	16(%rsi), %r10
	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	ret
ENDPROC(mpi_sub_x86_64_3_3)

ENTRY(mpi_sub_x86_64_2_2)
	movq	(%rdx), %r8
	movq	8(%rdx), %r9
	subq	(%rsi), %r8
	sbbq	8(%rsi), %r9
	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	ret
ENDPROC(mpi_sub_x86_64_2_2)


/**
 * Shift X left for N < 64 bits.
 *
 * %RDI	- pointer to X;
 * %RSI	- size of X (value of X->used for after the shift);
 * %RDX	- N.
 */
ENTRY(mpi_shift_l_x86_64)
	movq	%rdx, %rcx

	/*
	 * Frst iteration with zeroed most significant limb propagating its
	 * bits to the extra limb.
	 */
	xorq	%r11, %r11
	movq	-8(%rdi, %rsi, 8), %r8
	shldq	%cl, %r8, %r11
	movq	%r11, (%rdi, %rsi, 8)
	decq	%rsi
	jz	.shl_last

	/* The main loop with carying bits from less significant limbs. */
.shl_loop:
	movq	-8(%rdi, %rsi, 8), %r11
	shldq	%cl, %r11, (%rdi, %rsi, 8)
	decq	%rsi
	jnz	.shl_loop

	/* Shift the less significant limb right in-place. */
.shl_last:
	shlq	%cl, (%rdi)
	ret
ENDPROC(mpi_shift_l_x86_64)

/**
 * A specialization of the above for 4 limbs MPI with and extra 5th limb.
 *
 * %RDI	- pointer to X;
 * %RSI	- N bits to shift.
 */
ENTRY(mpi_shift_l_x86_64_4)
	movq	%rsi, %rcx
	movq	(%rdi), %r8
	movq	8(%rdi), %r9
	movq	16(%rdi), %r10
	xorq	%rdx, %rdx
	movq	24(%rdi), %r11
	shldq	%cl, %r11, %rdx
	shldq	%cl, %r10, 24(%rdi)
	shldq	%cl, %r9, 16(%rdi)
	shldq	%cl, %r8, 8(%rdi)
	movq	%rdx, 32(%rdi)
	shlq	%cl, (%rdi)
	ret
ENDPROC(mpi_shift_l_x86_64_4)


/**
 * Shift X right for N < 64 bits.
 *
 * %RDI	- pointer to X;
 * %RSI	- size of X (current X->used);
 * %RDX	- N.
 */
ENTRY(mpi_shift_r_x86_64)
	movq	%rdx, %rcx
	xorq	%rax, %rax

	decq	%rsi
	jz	.shr_last

.shr_loop:
	movq	8(%rdi, %rax, 8), %r8
	shrdq	%cl, %r8, (%rdi, %rax, 8)
	incq	%rax
	cmpq	%rax, %rsi
	jg	.shr_loop

.shr_last:
	shrq	%cl, (%rdi, %rax, 8)
	ret
ENDPROC(mpi_shift_r_x86_64)

/**
 * A specialization of the above for 4 limbs MPI.
 *
 * %RDI	- pointer to X;
 * %RSI	- N bits to shift.
 */
ENTRY(mpi_shift_r_x86_64_4)
	movq	%rsi, %rcx
	movq	8(%rdi), %r8
	movq	16(%rdi), %r9
	movq	24(%rdi), %r10
	shrdq	%cl, %r8, (%rdi)
	shrdq	%cl, %r9, 8(%rdi)
	shrdq	%cl, %r10, 16(%rdi)
	shrq	%cl, 24(%rdi)
	ret
ENDPROC(mpi_shift_r_x86_64_4)


/**
 * Multiply two 4-limbs MPIs (pointed by %RSI and %RDX correspondingly) and
 * store up to 8 limbs by pointer to result %RDI.
 *
 * The function code is borrowed from WolfSSL library
 * (https://github.com/wolfSSL/wolfssl/), sp_256_mul_avx2_4(),
 * wolfssl/wolfcrypt/src/sp_x86_64_asm.S .
 */
ENTRY(mpi_mul_x86_64_4)
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	movq	%rdx, %rax /* we need RDX as implicit argument for MULX */

	/* A[0] * B[0] */
	movq	(%rax), %rdx
	mulxq	(%rsi), %r9, %r10
	/* A[2] * B[0] */
	mulxq	16(%rsi), %r11, %r12
	/* A[1] * B[0] */
	mulxq	8(%rsi), %rcx, %r8
	xorq	%rbx, %rbx
	adcxq	%rcx, %r10
	/* A[1] * B[3] */
	movq	24(%rax), %rdx
	mulxq	8(%rsi), %r13, %r14
	adcxq	%r8, %r11
	/* A[0] * B[1] */
	movq	8(%rax), %rdx
	mulxq	(%rsi), %rcx, %r8
	adoxq	%rcx, %r10
	/* A[2] * B[1] */
	mulxq	16(%rsi), %rcx, %r15
	adoxq	%r8, %r11
	adcxq	%rcx, %r12
	/* A[1] * B[2] */
	movq	16(%rax), %rdx
	mulxq	8(%rsi), %rcx, %r8
	adcxq	%r15, %r13
	adoxq	%rcx, %r12
	adcxq	%rbx, %r14
	adoxq	%r8, %r13
	/* A[0] * B[2] */
	mulxq	(%rsi), %rcx, %r8
	adoxq	%rbx, %r14
	xorq	%r15, %r15
	adcxq	%rcx, %r11
	/* A[1] * B[1] */
	movq	8(%rax), %rdx
	mulxq	8(%rsi), %rdx, %rcx
	adcxq	%r8, %r12
	adoxq	%rdx, %r11
	/* A[3] * B[1] */
	movq	8(%rax), %rdx
	adoxq	%rcx, %r12
	mulxq	24(%rsi), %rcx, %r8
	adcxq	%rcx, %r13
	/* A[2] * B[2] */
	movq	16(%rax), %rdx
	mulxq	16(%rsi), %rdx, %rcx
	adcxq	%r8, %r14
	adoxq	%rdx, %r13
	/* A[3] * B[3] */
	movq	24(%rax), %rdx
	adoxq	%rcx, %r14
	mulxq	24(%rsi), %rcx, %r8
	adoxq	%rbx, %r15
	adcxq	%rcx, %r15
	/* A[0] * B[3] */
	mulxq	(%rsi), %rdx, %rcx
	adcxq	%r8, %rbx
	xorq	%r8, %r8
	adcxq	%rdx, %r12
	/* A[3] * B[0] */
	movq	(%rax), %rdx
	adcxq	%rcx, %r13
	mulxq	24(%rsi), %rdx, %rcx
	adoxq	%rdx, %r12
	adoxq	%rcx, %r13
	/* A[2] * B[3] */
	movq	24(%rax), %rdx
	mulxq	16(%rsi), %rdx, %rcx
	adcxq	%rdx, %r14
	/* A[3] * B[2] */
	movq	16(%rax), %rdx
	adcxq	%rcx, %r15
	mulxq	24(%rsi), %rcx, %rdx
	adcxq	%r8, %rbx
	adoxq	%rcx, %r14
	adoxq	%rdx, %r15
	adoxq	%r8, %rbx
	movq	%r9, (%rdi)
	movq	%r10, 8(%rdi)
	movq	%r11, 16(%rdi)
	movq	%r12, 24(%rdi)
	movq	%r13, 32(%rdi)
	movq	%r14, 40(%rdi)
	movq	%r15, 48(%rdi)
	movq	%rbx, 56(%rdi)

	pop	%rbx
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	ret
ENDPROC(mpi_mul_x86_64_4)


/**
 * Square a 4-limbs MPIs pointed by %RSI and store up to 8 limbs by pointer
 * to result %RDI.
 *
 * The function code is borrowed from WolfSSL library
 * (https://github.com/wolfSSL/wolfssl/), sp_256_sqr_avx2_4(),
 * wolfssl/wolfcrypt/src/sp_x86_64_asm.S .
 */
ENTRY(mpi_sqr_x86_64_4)
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	/* A[0] * A[1] */
	movq	(%rsi), %rdx
	mulxq	8(%rsi), %r9, %r10
	/* A[0] * A[3] */
	mulxq	24(%rsi), %r11, %r12
	/* A[2] * A[1] */
	movq	16(%rsi), %rdx
	mulxq	8(%rsi), %rcx, %rbx
	xorq	%r15, %r15
	adoxq	%rcx, %r11
	/* A[2] * A[3] */
	mulxq	24(%rsi), %r13, %r14
	adoxq	%rbx, %r12
	/* A[2] * A[0] */
	mulxq	(%rsi), %rcx, %rbx
	adoxq	%r15, %r13
	adcxq	%rcx, %r10
	adoxq	%r15, %r14
	/* A[1] * A[3] */
	movq	8(%rsi), %rdx
	mulxq	24(%rsi), %rax, %r8
	adcxq	%rbx, %r11
	adcxq	%rax, %r12
	adcxq	%r8, %r13
	adcxq	%r15, %r14

	/* Double with Carry Flag. */
	xorq	%r15, %r15
	/* A[0] * A[0] */
	movq	(%rsi), %rdx
	mulxq	%rdx, %r8, %rax
	adcxq	%r9, %r9
	/* A[1] * A[1] */
	movq	8(%rsi), %rdx
	mulxq	%rdx, %rcx, %rbx
	adcxq	%r10, %r10
	adoxq	%rax, %r9
	adcxq	%r11, %r11
	adoxq	%rcx, %r10
	/* A[2] * A[2] */
	movq	16(%rsi), %rdx
	mulxq	%rdx, %rax, %rcx
	adcxq	%r12, %r12
	adoxq	%rbx, %r11
	adcxq	%r13, %r13
	adoxq	%rax, %r12
	/* A[3] * A[3] */
	movq	24(%rsi), %rdx
	mulxq	%rdx, %rax, %rbx
	adcxq	%r14, %r14
	adoxq	%rcx, %r13
	adcxq	%r15, %r15
	adoxq	%rax, %r14
	adoxq	%rbx, %r15
	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx
	ret
ENDPROC(mpi_sqr_x86_64_4)


/**
 * Fast reduction modulo 256 by FIPS 186-3 D.2:
 *
 *	s1 = (c7,  c6,  c5,  c4,  c3,  c2,  c1,  c0 )
 *	s2 = (c15, c14, c13, c12, c11, 0,   0,   0  )
 *	s3 = (0,   c15, c14, c13, c12, 0,   0,   0  )
 *	s4 = (c15, c14, 0,   0,   0,   c10, c9,  c8 )
 *	s5 = (c8,  c13, c15, c14, c13, c11, c10, c9 )
 *	s6 = (c10, c8,  0,   0,   0,   c13, c12, c11)
 *	s7 = (c11, c9,  0,   0,   c15, c14, c13, c12)
 *	s8 = (c12, 0,   c10, c9,  c8,  c15, c14, c13)
 *	s9 = (c13, 0,   c11, c10, c9,  0,   c15, c14)
 *
 *	x = s1 + 2*s2 + 2*s3 + s4 + s5 − s6 − s7 − s8 − s9
 *
 * , where c i'th is a 32-bit word.
 *
 * As the original mbed TLS implementation we process the formula by columns
 * for 4 bytes at a time. However, we use 64-bit arithmetics to automatically
 * process the carry. The explicit formula coding allows us to not to add or
 * subtract zeroes, avoid conditions, simplify loading and storing, and read
 * the more significant half of the big integer int registers win less
 * steps.
 *
 * %RDI	- pointer to 8 limbs big integer to be reduced.
 *
 * TODO 46 add/sub vs WolfSSL 33 add/sub including zeroes
 * ..... or 27 add/sub if do this by rows of 64 bit ops
 */
ENTRY(ecp_mod_p256_x86_64)
ENDPROC(ecp_mod_p256_x86_64)
