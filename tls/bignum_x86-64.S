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
	jz	.sub_small_b
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
.sub_small_b:
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
 * TODO Probably there is no case for the function with the new modp.
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
 * Square a 4-limbs MPI pointed by %RSI and store up to 8 limbs by pointer
 * to result %RDI.
 *
 * The function code is borrowed from WolfSSL library
 * (https://github.com/wolfSSL/wolfssl/), sp_256_sqr_avx2_4(),
 * wolfssl/wolfcrypt/src/sp_x86_64_asm.S .
 *
 * This is the classic HAC 14.2.4 squaring algorithm with (i,j) doubling by
 * double addition and this can be improved with left shift (Algorithm 2) as
 * described in "Speeding up Big-Numbers Squaring" by S.Gueron and V.Krasnov,
 * 2012.
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
 *	s1 = (c7,  C6,    c5,  C4,    c3,  C2,    c1,  C0 )
 *	s2 = (c15, c14,   c13, c12,   c11, 0,     0,   0  )
 *	s3 = (0,   c15,   c14, c13,   c12, 0,     0,   0  )
 *	s4 = (c15, c14,   0,   0,     0,   c10,   c9,  c8 )
 *	s5 = (c8,  c13,   c15, c14,   c13, c11,   c10, c9 )
 *	s6 = (c10, c8,    0,   0,     0,   c13,   c12, c11)
 *	s7 = (c11, c9,    0,   0,     c15, c14,   c13, c12)
 *	s8 = (c12, 0,     c10, c9,    c8,  c15,   c14, c13)
 *	s9 = (c13, 0,     c11, c10,   c9,  0,     c15, c14)
 *
 *	x = s1 + 2*s2 + 2*s3 + s4 + s5 − s6 − s7 − s8 − s9
 *
 * , where c i'th is a 32-bit word.
 *
 * In opposite to mbed TLS we process the formula by rows, fully exploiting
 * 64-bit arithmetics and avoid manual carry manipulations. We can not use
 * SIMD as the rows use non-trivial permutations, so SIMD becomes too
 * expensive. The explicit formula coding allows us to not to add or
 * subtract zeroes, avoid conditions, simplify loading and storing, and read
 * the more significant half of the big integer int registers win less
 * steps.
 *
 * The FIPS is an alternative to Montgomery multiplication with reduction.
 * Camparing this funcion with the reduction step of WolfSSL's
 * sp_256_mont_mul_avx2_4() we do about 12 more ADC/SBB instructions plus
 * the the tail additions/subtractions with the conditional jumps.
 *
 * The esitmation for tail processing:
 * 1. no need to add/sub - 2 not taken branches (~1/2 of taken branch cost)
 *			   + 1 jmp + 8 adc/sbb + 2 add/sub;
 * 2. N additions	 - (N + 1) taken branches + 1 add + 4 adc;
 * 3. N subtractions	 - 2 not taken branchs + (N + 1) taken branch
 *			   + (N + 1) sub + (N * 1) * 4 sbb + 1 add + 3 abc
 *			   + 1 jmp
 *
 * In average we need only one addition or subtraction, i.e. N = 1, so a typical
 * subtraction (the most expensive path) costs about 3 jumps and 11 ADC/SBB.
 *
 * TBD: in total, this is about 65% slower than the Montgomery P-reduction after
 * multiplication, but we don't pay for Montgomery transformations.
 *
 * TODO align the MPI on a cache line.
 *
 * %RDI	- pointer to 8 limbs big integer to be reduced.
 * %RSI	- size if the MPI.
 */
ENTRY(ecp_mod_p256_x86_64)
	pushq	%rbx
	pushq	%r10
	pushq	%r11
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	xorq	%rcx, %rcx /* carry register for 5th limb */

	/* Load the base line. */
	movq	(%rdi), %rbx
	movq	2*4(%rdi), %rdx
	movq	4*4(%rdi), %r8
	movq	6*4(%rdi), %r9

	/* It's faster for small MPIs just to subtract P. */
	cmpq	$4, %rsi
	jle	.mod256_fast_sub

	/*
	 * Load and add the s2 line.
	 * SH{L,R}D have latency ~3 and throughtput 2, whcih is much worse
	 * than ADC (1 and 1 correspondingly), so use double ADD instead of
	 * shifting s2 and s3.
	 * There is also data dependency on first addition with CF and OF,
	 * so we can't use ADCX and ADOX.
	 */
	movq	11*4(%rdi), %r11
	movq	12*4(%rdi), %r12 /* used in s7 */
	movq	14*4(%rdi), %r10 /* used in s4, s5, s7, s9 */
	shlq	$32, %r11	/* c11, 0 - half used in s5*/
	addq	%r11, %rdx
	adcq	%r12, %r8
	adcq	%r10, %r9
	adcq	$0, %rcx
	addq	%r11, %rdx
	adcq	%r12, %r8
	adcq	%r10, %r9
	adcq	$0, %rcx

	/* The s3 line, no need to carry on shift. */
	movl	15*4(%rdi), %eax
	movq	12*4(%rdi), %r13
	movq	13*4(%rdi), %rsi
	shlq	$32, %r13
	addq	%r13, %rdx
	adcq	%rsi, %r8
	adcq	%rax, %r9
	adcq	$0, %rcx
	addq	%r13, %rdx
	adcq	%rsi, %r8
	adcq	%rax, %r9
	adcq	$0, %rcx

	/* Load and add s4. */
	movq	8*4(%rdi), %r14 /* half used in s7 */
	movl	10*4(%rdi), %eax /* 0,c10 */
	addq	%r14, %rbx
	adcq	%rax, %rdx
	adcq	$0, %r8
	adcq	%r10, %r9
	adcq	$0, %rcx

	/* Load and add s5. */
	shrq	$32, %r11
	shlq	$32, %rsi	/* c13,0 */
	movq	9*4(%rdi), %r15	/* used in s8 */
	orq	%rsi, %r11	/* c13,c11 in R11 */
	movl	8*4(%rdi), %eax
	shrq	$32, %rsi	/* 0,c13 - used in s6 */
	shlq	$32, %rax
	orq	%rsi, %rax	/* c8,c13 in RAX */
	addq	%r15, %rbx
	adcq	%r11, %rdx
	adcq	%r10, %r8
	adcq	%rax, %r9
	adcq	$0, %rcx

	/* Load and subtract s6. */
	movq	10*4(%rdi), %r13
	shrq	$32, %rax
	shlq	$32, %r13
	movq	11*4(%rdi), %r11 /* half used in s7 */
	orq	%rax, %r13	/* c10,c8 - half used in s8 */
	subq	%r11, %rbx
	sbbq	%rsi, %rdx
	sbbq	$0, %r8
	sbbq	%r13, %r9
	sbbq	$0, %rcx

	/* Load and subtract s7. */
	movl	9*4(%rdi), %eax	/* 0,c9 in RAX */
	shlq	$32, %r11
	orq	%rax, %r11
	subq	%r12, %rbx
	sbbq	%r10, %rdx
	sbbq	$0, %r8
	sbbq	%r11, %r9
	sbbq	$0, %rcx

	/*
	 * Load and subtract s8.
	 * It's also the time to start to load P256.
	 */
	movq	13*4(%rdi), %r11
	shldq	$32, %r10, %r13	/* c8,c15 */
	shlq	$32, %r12	/* c12,0 */
	xorq	%rsi, %rsi	/* P256[1] */
	subq	%r11, %rbx
	movq	$0xffffffff00000001, %rax /* P256[0] */
	sbbq	%r13, %rdx
	sbbq	%r15, %r8
	sbbq	%r12, %r9
	sbbq	$0, %rcx

	/* Load and subtract s9. */
	movq	10*4(%rdi), %r14
	shlq	$32, %r11
	shlq	$32, %r15
	subq	%r10, %rbx
	movq	$-1, %r13	/* P256[3] */
	sbbq	%r15, %rdx
	sbbq	%r14, %r8
	movq	$0x00000000ffffffff, %r12 /* P256[2] */
	sbbq	%r11, %r9
	sbbq	$0, %rcx

	/*
	 * Quasi-reduction is done, add/subtract to get final modulo.
	 * In average only one addition or subtraction is required, but it's
	 * required to compare the whole MPI (4 limbs and for each of them we
	 * can jump on less or greater values) against P to know which operation
	 * we need to do. It's cheaper to subtract P unconditionally on positive
	 * value and add it back if we get SF in RCX.
	 */
	js	.mod256_add_loop
.mod256_sub_loop:
	subq	%r13, %rbx
	sbbq	%r12, %rdx
	sbbq	%rsi, %r8
	sbbq	%rax, %r9
	sbbq	$0, %rcx
	jns	.mod256_sub_loop
	/* We had RCX >= 0, and now we're under 0: add back and return. */
	addq	%r13, %rbx
	adcq	%r12, %rdx
	adcq	%rsi, %r8
	adcq	%rax, %r9
	jmp	.mod256_done

.mod256_add_loop:
	/* Negative RCX value w/ overflow, need at least one addition. */
	addq	%r13, %rbx
	adcq	%r12, %rdx
	adcq	%rsi, %r8
	adcq	%rax, %r9
	adcq	$0, %rcx
	jnz	.mod256_add_loop

.mod256_done:
	movq	%rbx, (%rdi)
	movq	%rdx, 2*4(%rdi)
	movq	%r8, 4*4(%rdi)
	movq	%r9, 6*4(%rdi)
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%r11
	popq	%r10
	popq	%rbx
	ret

.mod256_fast_sub:
	movq	$0xffffffff00000001, %rax /* P256[0] */
	xorq	%rsi, %rsi	/* P256[1] */
	movq	$0x00000000ffffffff, %r12 /* P256[2] */
	movq	$-1, %r13	/* P256[3] */
	jmp .mod256_sub_loop
ENDPROC(ecp_mod_p256_x86_64)
