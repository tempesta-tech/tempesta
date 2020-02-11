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

/**
 * Multiply X = A * B, where A->used >= B->used.
 *
 * %RDI and %RSI - pointer to X and X->limbs correspondingly;
 * %RDX and %RCX - pointer to B and B->used correspondingly;
 * %RDI and %RSI - pointer to A and A->used correspondingly.
 */
ENTRY(mpi_add_x86_64)
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
	movq	$0, %r10
	jnc	.no_carry
	movq	$1, %r10
.no_carry:
	subq	%rax, %r9
	movq	%r9, %rcx
	addq	$1, %rcx
	jmp	.add_bigger
.add_bigger_loop:
	adcq	(%r8, %rax, 8), %r10
	movq	%r10, (%rdi, %rax, 8)
	movq	$0, %r10
	incq	%rax
.add_bigger:
	loop	.add_bigger_loop

	/* Propagate carry to the next X limb if necessary. */
	adc	$-1, %r10
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

#if defined(BMI2) && defined(ADX)
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

#else
.macro MULADDC_ROUND CNT_R:req
	movq	(%rsi), %rax
	mulq	%r11
	addq	$8, %rsi
	addq	\CNT_R, %rax
	movq	%r9, \CNT_R
	adcq	$0, %rdx
	nop
	addq	%rax, (%r10)
	adcq	%rdx, \CNT_R
	addq	$8, %r10
.endm

/**
 * Multiply vector pointed by %RDX of size %RDI by vector pointed by %RCX of
 * size %RSI and stores the result by address %R8.
 * The outer loop iterates the second vector and the inner loop iterates the
 * first vector with unrolling for 16, 8, and 1 8-byte operations.
 *
 * Legacy implementation.
 */
ENTRY(mpi_mul_x86_64)
	testq	%rsi, %rsi
	js	.empty_vec2
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
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12
	MULADDC_ROUND %r12

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
	MULADDC_ROUND %r13
	MULADDC_ROUND %r13
	MULADDC_ROUND %r13
	MULADDC_ROUND %r13
	MULADDC_ROUND %r13
	MULADDC_ROUND %r13
	MULADDC_ROUND %r13
	MULADDC_ROUND %r13

	movq	%r13, %rax
.end_8unrolling:
	testq	%r12, %r12
	je	.propagate_carry
.vec1_single_step:
	movq	%rax, %r13

	xorq	%r9, %r9
	MULADDC_ROUND %r13

	movq	%r13, %rax
	subq	$1, %r12
	jne	.vec1_single_step
.propagate_carry:
	xorl	%edx, %edx
	addq	(%r10), %rax
	setc	%dl
	movq	%rax, (%r10)
	addq	$8, %r10
	movl	$1, %eax
	testq	%rdx, %rdx
	jne	.propagate_carry
	subq	$8, %rcx
	cmpq	$-8, %rcx
	jne	.vec1_16unrolling_prolog
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	ret
.end_16unrolling:
	movq	%rdi, %r12
	xorl	%eax, %eax
	jmp	.vec1_8unrolling
.empty_vec2:
	ret
ENDPROC(mpi_mul_x86_64)
#endif
