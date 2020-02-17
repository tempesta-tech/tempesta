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


/*
 * Use CF to carry multiplication overflow to higher digit and OF to carry
 * addition of results of current and previous multiplications.
 * TODO write data to the registers and then write back them to memory.
 *      Or, like it is in wolfssl, make special versions for paricular sizes
 *	(e.g. sp_256_mul_avx2_4) and call them instead of __mpi_mul()?
 *	See wolfcrypt/src/sp_x86_64_asm.S _sp_256_mul_avx2_4
 */
.macro MULX_ROUND4
	mulxq	(%rsi), %r9, %r10
	mulxq	8(%rsi), %r11, %r12
	mulxq	16(%rsi), %r13, %r14
	adcxq	%r10, %r11
	adcxq	%r12, %r13
	mulxq	24(%rsi), %r15, %rbx
	#adoxq	%r9, (%r10)  /* FIXME */
	#adoxq	%r11, 8(%r10)
	#adoxq	%r13, 16(%r10)
	adcxq	%r14, %r15
	addq	$32, %r10
.endm

/**
 * Multiply vector pointed by %RDX of size %RDI by vector pointed by %RCX of
 * size %RSI and stores the result by address %R8.
 * Row-wise school book method: the outer loop iterates the first %RDX (MULX
 * implicit argument) vector and the inner loop multiplies each limb of the
 * %RCX vector with %RDX.
 *
 * This is a generic multiplication, which allows different sizes for both the
 * operands. A better operations ordering and registers loading are possible
 * for predefined operand sizes, e.g. 256 bit for Secp256.
 *
 * Vector multiplication shuld be used for large vectors multiplication
 * (e.g. RSA 1204 or 2048), see "Fast multiplication of binary polynomials with
 * theforthcoming vectorized VPCLMULQDQ instruction" by N.Drucker et al.
 *
 * The implementation uses BMI2 and ADX extensions.
 */
ENTRY(mpi_mul_x86_64)
	testq	%rsi, %rsi
	js	.empty_vec2
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbp
	movq	%rcx, %rbp
	leaq	0(,%rsi,8), %rcx
	pushq	%rbx
	movq	%rdx, %rbx
.vec1_16unrolling_prolog:
	movq	0(%rbp,%rcx), %r11
	leaq	(%r8,%rcx), %r10
	movq	%rbx, %rsi
	cmpq	$15, %rdi
	jbe	.end_16unrolling
	movq	%rdi, %r13
	xorl	%eax, %eax
.vec1_16unrolling:
	subq	$16, %r13
	movq	%rax, %r12

	xorq	%r9, %r9
	MULX_ROUND4
	MULX_ROUND4
	MULX_ROUND4
	MULX_ROUND4

	movq	%r12, %rax
	cmpq	$15, %r13
	ja	.vec1_16unrolling
	movq	%rdi, %r12
	andl	$15, %r12d
.vec1_8unrolling:
	cmpq	$7, %r12
	jbe	.end_8unrolling
	movq	%rax, %r13
	subq	$8, %r12

	xorq	%r9, %r9
	MULX_ROUND4
	MULX_ROUND4

	movq	%r13, %rax
.end_8unrolling:
	testq	%r12, %r12
	je	.finish
.vec1_single_step:
	movq	%rax, %r13

	xorq	%r9, %r9
	MULX_ROUND4

	movq	%r13, %rax
	subq	$1, %r12
	jne	.vec1_single_step
.finish:
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	ret
.end_16unrolling:
	movq	%rdi, %r12
	xorl	%eax, %eax
	jmp	.vec1_8unrolling
.empty_vec2:
	ret
ENDPROC(mpi_mul_x86_64)
