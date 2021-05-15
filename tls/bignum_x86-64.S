/**
 *		Tempesta FW
 *
 * Copyright (C) 2020-2021 Tempesta Technologies, Inc.
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
#include <asm/export.h>
#include <asm/nospec-branch.h>

/*
 * Use 32-byte alignment instead of common 4-byte to improve micro-op caching
 * for the functions with many LCPs and/or branches.
 */
#define SYM_FUNC_START_32(name)	SYM_START(name, SYM_L_GLOBAL, .align 32)

/**
 * Compare 4-limbs MPI %RDI with MPI %RSI.
 */
SYM_FUNC_START(mpi_cmp_x86_64_4)
	movq	$-1, %rdx
	movq	24(%rdi), %rax
	subq	24(%rsi), %rax
	jnz	.cmp_4_done
	movq	16(%rdi), %rax
	subq	16(%rsi), %rax
	jnz	.cmp_4_done
	movq	8(%rdi), %rax
	subq	8(%rsi), %rax
	jnz	.cmp_4_done
	movq	(%rdi), %rax
	subq	(%rsi), %rax
	jnz	.cmp_4_done
.cmp_4_done:
	cmovbq	%rdx, %rax
	retq
SYM_FUNC_END(mpi_cmp_x86_64_4)


/**
 * Add X = A + B, where A->used >= B->used.
 *
 * %RDI and %RSI - pointer to X and X->limbs correspondingly;
 * %RDX and %RCX - pointer to B and B->used correspondingly;
 * %R8 and %R9 - pointer to A and A->used correspondingly.
 *
 * TODO #1335 it seems we can throw out the generic-length functions.
 */
SYM_FUNC_START(mpi_add_x86_64)
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
	jnc	.add_done
	cmpq	%rax, %rsi	/* macro-op fused with jl */
	jl	.enospc
	movq	$1, (%rdi, %rax, 8)
	incq	%rax

.add_done:
	ret
.enospc:
	movq	$-1, %rax
	ret
SYM_FUNC_END(mpi_add_x86_64)


/**
 * Modular addition X = A + B mod P256. All the operands are 4 limbs in size.
 *
 * %RDI	- pointer to X;
 * %RSI	- pointer to A (can be the same as X);
 * %RDX	- pointer to B;
 *
 * Borrowed from WolfSSL sp_256_mont_add_4().
 */
SYM_FUNC_START(mpi_add_mod_p256_x86_64)
	movq	(%rsi), %rax
	movq	8(%rsi), %rcx
	movq	16(%rsi), %r8
	movq	24(%rsi), %r9
	movq	$0xffffffff, %r10
	movq	$0xffffffff00000001, %r11
	addq	(%rdx), %rax
	adcq	8(%rdx), %rcx
	adcq	16(%rdx), %r8
	movq	$0x00, %rsi
	adcq	24(%rdx), %r9
	sbbq	$0x00, %rsi
	andq	%rsi, %r10
	andq	%rsi, %r11
	subq	%rsi, %rax
	sbbq	%r10, %rcx
	movq	%rax, (%rdi)
	sbbq	$0x00, %r8
	movq	%rcx, 8(%rdi)
	sbbq	%r11, %r9
	movq	%r8, 16(%rdi)
	movq	%r9, 24(%rdi)
	retq
SYM_FUNC_END(mpi_add_mod_p256_x86_64)


/**
 * Subtract X = A - B, where A->used >= B->used.
 *
 * %RDI	- pointer to X;
 * %RSI	- pointer to B;
 * %RDX	- pointer to A;
 * %RCX	- B->used (used directly for looping);
 * %R8	- A->used.
 *
 * TODO #1335 it seems we can throw out the generic-length functions.
 */
SYM_FUNC_START(mpi_sub_x86_64)
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
SYM_FUNC_END(mpi_sub_x86_64)

/*
 * Operands size specialized implementations of the function above.
 *
 * TODO #1064 This function, mpi_sub_x86_64_4_4, mpi_sub_x86_64_3_3, and
 * mpi_sub_x86_64_2_2 are still can be used from NIST 256 modular inversion.
 * It seems they can be removed after the inversion optimization or just
 * called directly from the inversion function.
 */
SYM_FUNC_START(mpi_sub_x86_64_5_4)
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
SYM_FUNC_END(mpi_sub_x86_64_5_4)

SYM_FUNC_START(mpi_sub_x86_64_4_4)
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
SYM_FUNC_END(mpi_sub_x86_64_4_4)

/**
 * Subtract X = A - B mod P256, where A->used >= B->used.
 *
 * %RDI	- pointer to X;
 * %RSI	- pointer to A (can be the same as X);
 * %RDX	- pointer to B;
 */
SYM_FUNC_START(mpi_sub_mod_p256_x86_64)
	movq	(%rsi), %rax
	movq	8(%rsi), %rcx
	movq	16(%rsi), %r8
	movq	24(%rsi), %r9
	movq	$0xffffffff, %r10
	movq	$0xffffffff00000001, %r11
	subq	(%rdx), %rax
	sbbq	8(%rdx), %rcx
	sbbq	16(%rdx), %r8
	movq	$0x00, %rsi
	sbbq	24(%rdx), %r9
	sbbq	$0x00, %rsi
	andq	%rsi, %r10
	andq	%rsi, %r11
	addq	%rsi, %rax
	adcq	%r10, %rcx
	movq	%rax, (%rdi)
	adcq	$0x00, %r8
	movq	%rcx, 8(%rdi)
	adcq	%r11, %r9
	movq	%r8, 16(%rdi)
	movq	%r9, 24(%rdi)
	retq
SYM_FUNC_END(mpi_sub_mod_p256_x86_64)

SYM_FUNC_START(mpi_sub_x86_64_3_3)
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
SYM_FUNC_END(mpi_sub_x86_64_3_3)

SYM_FUNC_START(mpi_sub_x86_64_2_2)
	movq	(%rdx), %r8
	movq	8(%rdx), %r9
	subq	(%rsi), %r8
	sbbq	8(%rsi), %r9
	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	ret
SYM_FUNC_END(mpi_sub_x86_64_2_2)


/**
 * Shift X left for N < 64 bits.
 *
 * %RDI	- pointer to X;
 * %RSI - pointer to the original MPI;
 * %RDX - size of X (value of X->used for after the shift);
 * %RCX	- N.
 *
 * TODO #1335 it seems we can throw out the generic-length functions.
 */
SYM_FUNC_START(mpi_shift_l_x86_64)
	/*
	 * Frst iteration with zeroed most significant limb propagating its
	 * bits to the extra limb.
	 */
	xorq	%r11, %r11
	movq	-8(%rsi, %rdx, 8), %r8
	shldq	%cl, %r8, %r11
	movq	%r11, (%rdi, %rdx, 8)
	decq	%rdx	/* macro-op fusion */
	jz	.shl_last

	/* The main loop with carying bits from less significant limbs. */
.shl_loop:
	movq	-8(%rsi, %rdx, 8), %r8
	movq	(%rsi, %rdx, 8), %r11
	shldq	%cl, %r8, %r11
	movq	%r11, (%rdi, %rdx, 8)
	decq	%rdx	/* macro-op fusion */
	jnz	.shl_loop

.shl_last:
	movq	(%rsi), %r11
	shlq	%cl, %r11
	movq	%r11, (%rdi)
	ret
SYM_FUNC_END(mpi_shift_l_x86_64)

/**
 * A specialization of the above for 4 limbs MPI with and extra 5th limb.
 *
 * %RDI	- pointer to the resulting MPI;
 * %RSI - pointer to the original MPI;
 * %RDX	- N bits to shift.
 */
SYM_FUNC_START(mpi_shift_l_x86_64_4)
	movq	%rdx, %rcx
	movq	24(%rsi), %r11
	movq	16(%rsi), %r10
	xorq	%rdx, %rdx
	movq	8(%rsi), %r9
	movq	(%rsi), %r8
	shldq	%cl, %r11, %rdx
	shldq	%cl, %r10, %r11
	shldq	%cl, %r9, %r10
	movq	%rdx, 32(%rdi)
	movq	%r11, 24(%rdi)
	shldq	%cl, %r8, %r9
	shlq	%cl, %r8
	movq	%r10, 16(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r8, (%rdi)
	ret
SYM_FUNC_END(mpi_shift_l_x86_64_4)

/**
 * X (%RDI) = A (%RSI) << 1 mod p256, both the MPIs are 4 limbs.
 * Borrowed from WolfSSL _sp_256_mont_dbl_4().
 */
SYM_FUNC_START(mpi_shift_l1_mod_p256_x86_64)
	movq	(%rsi), %rdx
	movq	8(%rsi), %rax
	movq	16(%rsi), %rcx
	movq	24(%rsi), %r8
	movq	$0xffffffff, %r9
	movq	$0xffffffff00000001, %r10
	addq	%rdx, %rdx
	adcq	%rax, %rax
	adcq	%rcx, %rcx
	movq	$0x00, %r11
	adcq	%r8, %r8
	sbbq	$0x00, %r11
	andq	%r11, %r9
	andq	%r11, %r10
	subq	%r11, %rdx
	sbbq	%r9, %rax
	movq	%rdx, (%rdi)
	sbbq	$0x00, %rcx
	movq	%rax, 8(%rdi)
	sbbq	%r10, %r8
	movq	%rcx, 16(%rdi)
	movq	%r8, 24(%rdi)
	retq
SYM_FUNC_END(mpi_shift_l1_mod_p256_x86_64)


/**
 * Shift X right for N < 64 bits.
 *
 * %RDI	- pointer to X;
 * %RSI	- size of X (current X->used);
 * %RDX	- N.
 *
 * TODO #1335 it seems we can throw out the generic-length functions.
 */
SYM_FUNC_START(mpi_shift_r_x86_64)
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
SYM_FUNC_END(mpi_shift_r_x86_64)

/**
 * A specialization of the above for 4 limbs MPI.
 *
 * %RDI	- pointer to X;
 * %RSI	- N bits to shift.
 */
SYM_FUNC_START(mpi_shift_r_x86_64_4)
	movq	%rsi, %rcx
	movq	8(%rdi), %r8
	movq	16(%rdi), %r9
	movq	24(%rdi), %r10
	shrdq	%cl, %r8, (%rdi)
	shrdq	%cl, %r9, 8(%rdi)
	shrdq	%cl, %r10, 16(%rdi)
	shrq	%cl, 24(%rdi)
	ret
SYM_FUNC_END(mpi_shift_r_x86_64_4)


/**
 * Divide the 256-bit MPI in %RSI by 2 mod P256 and store in %RDI.
 * The code is borrowed from WolfSSL, sp_256_div2_4().
 */
SYM_FUNC_START(mpi_div2_x86_64_4)
	movq	(%rsi), %rdx
	movq	8(%rsi), %rax
	movq	16(%rsi), %rcx
	movq	24(%rsi), %r8
	movq	$0xffffffff, %r9
	movq	$0xffffffff00000001, %r10
	movq	%rdx, %r11
	andq	$1, %r11
	negq	%r11
	andq	%r11, %r9
	andq	%r11, %r10
	addq	%r11, %rdx
	adcq	%r9, %rax
	adcq	$0, %rcx
	adcq	%r10, %r8
	movq	$0, %r11
	adcq	$0, %r11
	shrdq	$1, %rax, %rdx
	shrdq	$1, %rcx, %rax
	shrdq	$1, %r8, %rcx
	shrdq	$1, %r11, %r8
	movq	%rdx, (%rdi)
	movq	%rax, 8(%rdi)
	movq	%rcx, 16(%rdi)
	movq	%r8, 24(%rdi)
	retq
SYM_FUNC_END(mpi_div2_x86_64_4)


/**
 * X (%RDI) = 3 * A (%RSI) mod p256, both the MPIs are 4 limbs.
 * Borrowed from WolfSSL sp_256_mont_tpl_4().
 */
SYM_FUNC_START_32(mpi_tpl_mod_p256_x86_64)
	movq	(%rsi), %rdx
	movq	8(%rsi), %rax
	movq	16(%rsi), %rcx
	movq	24(%rsi), %r8
	movq	$0xffffffff, %r9
	movq	$0xffffffff00000001, %r10
	addq	%rdx, %rdx
	adcq	%rax, %rax
	adcq	%rcx, %rcx
	movq	$0x00, %r11
	adcq	%r8, %r8
	sbbq	$0x00, %r11
	andq	%r11, %r9
	andq	%r11, %r10
	subq	%r11, %rdx
	sbbq	%r9, %rax
	sbbq	$0x00, %rcx
	sbbq	%r10, %r8
	movq	$0xffffffff, %r9
	movq	$0xffffffff00000001, %r10
	addq	(%rsi), %rdx
	adcq	8(%rsi), %rax
	adcq	16(%rsi), %rcx
	movq	$0x00, %r11
	adcq	24(%rsi), %r8
	sbbq	$0x00, %r11
	andq	%r11, %r9
	andq	%r11, %r10
	subq	%r11, %rdx
	sbbq	%r9, %rax
	movq	%rdx, (%rdi)
	sbbq	$0x00, %rcx
	movq	%rax, 8(%rdi)
	sbbq	%r10, %r8
	movq	%rcx, 16(%rdi)
	movq	%r8, 24(%rdi)
	retq
SYM_FUNC_END(mpi_tpl_mod_p256_x86_64)


/**
 * Multiply two 4-limbs MPIs (pointed by %RSI and %RDX correspondingly) and
 * store up to 8 limbs by pointer to result %RDI.
 *
 * The function code is borrowed from WolfSSL library
 * (https://github.com/wolfSSL/wolfssl/), sp_256_mul_avx2_4(),
 * wolfssl/wolfcrypt/src/sp_x86_64_asm.S .
 *
 * TODO #1335 The ADCX instructions are 6-byte instructions with 0x66
 * length-changing prefix, so we loose several cycles on decoding. Look for
 * better versions of the instruction.
 * TODO #1335 VPMULUDQ can be used to sepeedup the function, see "Speeding up
 * Elliptic Curve Cryptography on the P-384 Curve" by Hernandez et all, 2016.
 */
SYM_FUNC_START_32(mpi_mul_x86_64_4)
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
SYM_FUNC_END(mpi_mul_x86_64_4)


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
 *
 * Use 32-byte alignment instead of common 4-byte to improve micro-op caching.
 */
SYM_FUNC_START_32(mpi_sqr_x86_64_4)
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
SYM_FUNC_END(mpi_sqr_x86_64_4)


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
 * In opposite to mbedTLS we process the formula by rows, fully exploiting
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
 * %RDI	- pointer to 8 limbs big integer to be reduced.
 */
.section .rodata
.align 64
__P256x:
	/*
	 * The most significant limbs go first.
	 * The carry values give the vector: 0xba98765432100
	 */
	/* P * 0 (carry=0) */
	.quad	0x0000000000000000, 0x0000000000000000
	.quad	0x0000000000000000, 0x0000000000000000
	/* P * 1 (carry=0) */
	.quad	0xffffffff00000001, 0x0000000000000000
	.quad	0x00000000ffffffff, 0xffffffffffffffff
	/* P * 2 (carry=1) */
	.quad	0xfffffffe00000002, 0x0000000000000000
	.quad	0x00000001ffffffff, 0xfffffffffffffffe
	/* P * 3 (carry=2) */
	.quad	0xfffffffd00000003, 0x0000000000000000
	.quad	0x00000002ffffffff, 0xfffffffffffffffd
	/* P * 4 (carry=3) */
	.quad	0xfffffffc00000004, 0x0000000000000000
	.quad	0x00000003ffffffff, 0xfffffffffffffffc
	/* P * 5 (carry=4) */
	.quad	0xfffffffb00000005, 0x0000000000000000
	.quad	0x00000004ffffffff, 0xfffffffffffffffb
	/* P * 6 (carry=5) */
	.quad	0xfffffffa00000006, 0x0000000000000000
	.quad	0x00000005ffffffff, 0xfffffffffffffffa
	/* P * 7 (carry=6) */
	.quad	0xfffffff900000007, 0x0000000000000000
	.quad	0x00000006ffffffff, 0xfffffffffffffff9
	/* P * 8 (carry=7) */
	.quad	0xfffffff800000008, 0x0000000000000000
	.quad	0x00000007ffffffff, 0xfffffffffffffff8
	/* P * 9 (carry=8) */
	.quad	0xfffffff700000009, 0x0000000000000000
	.quad	0x00000008ffffffff, 0xfffffffffffffff7
	/* P * 10 (carry=9) */
	.quad	0xfffffff60000000a, 0x0000000000000000
	.quad	0x00000009ffffffff, 0xfffffffffffffff6
	/* P * 11 (carry=10) */
	.quad	0xfffffff50000000b, 0x0000000000000000
	.quad	0x0000000affffffff, 0xfffffffffffffff5
	/* P * 12 (carry=11) */
	.quad	0xfffffff40000000c, 0x0000000000000000
	.quad	0x0000000bffffffff, 0xfffffffffffffff4
.section .text
SYM_FUNC_START_32(ecp_mod_p256_x86_64)
	prefetcht0 (%rdi)
	prefetcht0 __P256x(%rip)
	prefetcht0 __P256x+128(%rip)
	prefetcht0 __P256x+256(%rip)

	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	xorq	%rcx, %rcx /* carry register for 5th limb */

	/*
	 * Load and add the base and s2 lines.
	 * SH{L,R}D have latency ~3 and throughtput 2, whcih is much worse
	 * than ADC (1 and 1 correspondingly), so use double ADD instead of
	 * shifting s2 and s3.
	 * There is also data dependency on first addition with CF and OF,
	 * so we can't use ADCX and ADOX.
	 */
	movq	11*4(%rdi), %r11
	movq	2*4(%rdi), %rdx
	movq	4*4(%rdi), %r8
	movq	12*4(%rdi), %r12 /* used in s7 */
	shlq	$32, %r11	/* c11, 0 - half used in s5*/
	movq	6*4(%rdi), %r9
	movq	14*4(%rdi), %r10 /* used in s4, s5, s7, s9 */
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
	movq	(%rdi), %rbx
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
	 * It's also the time to start to load 4*P256.
	 */
	movq	13*4(%rdi), %r11
	shldq	$32, %r10, %r13	/* c8,c15 */
	shlq	$32, %r12	/* c12,0 */
	movq	$0xfffffffffffffffb, %rsi
	subq	%r11, %rbx
	movq	$0x4ffffffff, %rax
	sbbq	%r13, %rdx
	sbbq	%r15, %r8
	sbbq	%r12, %r9
	sbbq	$0, %rcx
	movq	$0xfffffffb00000005, %r13

	/* Load and subtract s9. */
	movq	10*4(%rdi), %r14
	shlq	$32, %r11
	shlq	$32, %r15
	subq	%r10, %rbx
	sbbq	%r15, %rdx
	sbbq	%r14, %r8
	sbbq	%r11, %r9
	sbbq	$0, %rcx

	/*
	 * Quasi-reduction is done, add/subtract to get final modulo.
	 * We start with addition of 5 * P256 to guarantee non-negative value
	 * to carry in RCX with the number greater than P256.
	 */
	movq	$0xba98765432100, %r10
	addq	%rsi, %rbx
	adcq	%rax, %rdx
	adcq	$0, %r8
	adcq	%r13, %r9
	adcq	$4, %rcx

	/*
	 * Next, subtract P256 necessary number of times.
	 * Subtract the __P256x table carry from the current one.
	 */
	movq	%rcx, %rsi
	shlq	$2, %rcx
	leaq	__P256x(%rip), %r12
	shrq	%cl, %r10
	subq	24(%r12, %rcx, 8), %rbx
	sbbq	16(%r12, %rcx, 8), %rdx
	sbbq	8(%r12, %rcx, 8), %r8
	andq	$0xf, %r10
	sbbq	(%r12, %rcx, 8), %r9
	sbbq	%r10, %rsi

	movq	$0xffffffff, %r13
	movq	$0xffffffff00000001, %r12
	movq	$0xffffffffffffffff, %r10
	movq	%rbx, (%rdi)
	movq	%rdx, 2*4(%rdi)
	movq	%r8, 4*4(%rdi)
	movq	%r9, 6*4(%rdi)

	/*
	 * Subtract one more P256 in case we have carry and
	 * the 4 limbs with over P256.
	 */
	subq	%r10, %rbx
	sbbq	%r13, %rdx
	sbbq	$0, %r8
	sbbq	%r12, %r9
	sbbq	$0, %rsi
	jb	.mod_p256_done

	movq	%rbx, (%rdi)
	movq	%rdx, 2*4(%rdi)
	movq	%r8, 4*4(%rdi)
	movq	%r9, 6*4(%rdi)

.mod_p256_done:
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbx
	ret
SYM_FUNC_END(ecp_mod_p256_x86_64)

/**
 * Multiply 4-limb MPI in %RSI by a long in %RDX and store the result in %RDI.
 */
SYM_FUNC_START_32(mpi_mul_int_x86_64_4)
	push	%r12
	push	%r13

	mulxq	(%rsi), %r8, %r9
	mulxq	8(%rsi), %r10, %r11
	mulxq	16(%rsi), %rax, %rcx
	movq	%r8, (%rdi)
	mulxq	24(%rsi), %r12, %r13
	addq	%r10, %r9
	adcq	%rax, %r11
	movq	%r9, 8(%rdi)
	movq	%r11, 16(%rdi)
	adcq	%rcx, %r12
	adcq	$0, %r13
	movq	%r12, 24(%rdi)
	movq	%r13, 32(%rdi)

	popq	%r13
	popq	%r12
	retq
SYM_FUNC_END(mpi_mul_int_x86_64_4)

/*
 * The two functions at the below are simple merges of the mudulus reduction
 * from the above with multiplication and squaring correspondingly.
 */
SYM_FUNC_START_32(mpi_mul_mod_p256_x86_64_4)
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx

	movq	%rdx, %rax

	movq	(%rax), %rdx
	mulxq	(%rsi), %r9, %r10
	mulxq	16(%rsi), %r11, %r12
	mulxq	8(%rsi), %rcx, %r8
	xorq	%rbx, %rbx
	adcxq	%rcx, %r10
	movq	24(%rax), %rdx
	mulxq	8(%rsi), %r13, %r14
	adcxq	%r8, %r11
	movq	8(%rax), %rdx
	mulxq	(%rsi), %rcx, %r8
	adoxq	%rcx, %r10
	mulxq	16(%rsi), %rcx, %r15
	adoxq	%r8, %r11
	adcxq	%rcx, %r12
	movq	16(%rax), %rdx
	mulxq	8(%rsi), %rcx, %r8
	adcxq	%r15, %r13
	adoxq	%rcx, %r12
	adcxq	%rbx, %r14
	adoxq	%r8, %r13
	mulxq	(%rsi), %rcx, %r8
	adoxq	%rbx, %r14
	xorq	%r15, %r15
	adcxq	%rcx, %r11
	movq	8(%rax), %rdx
	mulxq	8(%rsi), %rdx, %rcx
	adcxq	%r8, %r12
	adoxq	%rdx, %r11
	movq	8(%rax), %rdx
	adoxq	%rcx, %r12
	mulxq	24(%rsi), %rcx, %r8
	adcxq	%rcx, %r13
	movq	16(%rax), %rdx
	mulxq	16(%rsi), %rdx, %rcx
	adcxq	%r8, %r14
	adoxq	%rdx, %r13
	movq	24(%rax), %rdx
	adoxq	%rcx, %r14
	mulxq	24(%rsi), %rcx, %r8
	adoxq	%rbx, %r15
	adcxq	%rcx, %r15
	mulxq	(%rsi), %rdx, %rcx
	adcxq	%r8, %rbx
	xorq	%r8, %r8
	adcxq	%rdx, %r12
	movq	(%rax), %rdx
	adcxq	%rcx, %r13
	mulxq	24(%rsi), %rdx, %rcx
	adoxq	%rdx, %r12
	adoxq	%rcx, %r13
	movq	24(%rax), %rdx
	mulxq	16(%rsi), %rdx, %rcx
	adcxq	%rdx, %r14
	movq	16(%rax), %rdx
	adcxq	%rcx, %r15
	mulxq	24(%rsi), %rcx, %rdx
	adcxq	%r8, %rbx
	adoxq	%rcx, %r14
	adoxq	%rdx, %r15
	adoxq	%r8, %rbx

	movq	%r13, %rsi
	movq	%r9, (%rdi)
	movq	%r10, 8(%rdi)
	movq	%r11, 16(%rdi)
	movq	%r12, 24(%rdi)
	movq	%r13, 32(%rdi)
	movq	%r14, 40(%rdi)
	movq	%r15, 48(%rdi)
	movq	%rbx, 56(%rdi)
	shrdq	$32, %r14, %rsi

	/* The s3 line, no need to carry on shift. */
	xorq	%rcx, %rcx

	shrq	$32, %r14
	movq	2*4(%rdi), %rdx
	movq	4*4(%rdi), %r8
	movq	12*4(%rdi), %r12
	shlq	$32, %r14
	movq	6*4(%rdi), %r9
	movq	14*4(%rdi), %r10
	addq	%r14, %rdx
	adcq	%r12, %r8
	adcq	%r10, %r9
	adcq	$0, %rcx
	addq	%r14, %rdx
	adcq	%r12, %r8
	adcq	%r10, %r9
	adcq	$0, %rcx

	movl	15*4(%rdi), %eax
	movq	12*4(%rdi), %r13
	shrdq	$32, %rbx, %r15
	shlq	$32, %r13
	addq	%r13, %rdx
	adcq	%r15, %r8
	adcq	%rax, %r9
	adcq	$0, %rcx
	addq	%r13, %rdx
	adcq	%r15, %r8
	adcq	%rax, %r9
	adcq	$0, %rcx

	movq	(%rdi), %rbx
	movq	8*4(%rdi), %r11
	movl	10*4(%rdi), %eax
	addq	%r11, %rbx
	adcq	%rax, %rdx
	adcq	$0, %r8
	adcq	%r10, %r9
	adcq	$0, %rcx

	shrq	$32, %r14
	shlq	$32, %r15
	orq	%r15, %r14
	movl	8*4(%rdi), %eax
	shrq	$32, %r15
	shlq	$32, %rax
	orq	%r15, %rax
	addq	%rsi, %rbx
	adcq	%r14, %rdx
	adcq	%r10, %r8
	adcq	%rax, %r9
	adcq	$0, %rcx

	movq	10*4(%rdi), %r13
	shrq	$32, %rax
	shlq	$32, %r13
	orq	%rax, %r13
	movq	11*4(%rdi), %r14
	subq	%r14, %rbx
	sbbq	%r15, %rdx
	sbbq	$0, %r8
	sbbq	%r13, %r9
	sbbq	$0, %rcx

	movl	9*4(%rdi), %eax
	shlq	$32, %r14
	orq	%rax, %r14
	subq	%r12, %rbx
	sbbq	%r10, %rdx
	sbbq	$0, %r8
	sbbq	%r14, %r9
	sbbq	$0, %rcx

	movq	13*4(%rdi), %r14
	shldq	$32, %r10, %r13
	shlq	$32, %r12
	movq	$0xfffffffffffffffb, %r15
	subq	%r14, %rbx
	movq	$0x4ffffffff, %rax
	sbbq	%r13, %rdx
	sbbq	%rsi, %r8
	sbbq	%r12, %r9
	sbbq	$0, %rcx
	movq	$0xfffffffb00000005, %r13

	movq	10*4(%rdi), %r11
	shlq	$32, %r14
	shlq	$32, %rsi
	subq	%r10, %rbx
	sbbq	%rsi, %rdx
	sbbq	%r11, %r8
	sbbq	%r14, %r9
	sbbq	$0, %rcx

	movq	$0xba98765432100, %r10
	addq	%r15, %rbx
	adcq	%rax, %rdx
	adcq	$0, %r8
	adcq	%r13, %r9
	adcq	$4, %rcx

	movq	%rcx, %r15
	shlq	$2, %rcx
	leaq	__P256x(%rip), %r12
	shrq	%cl, %r10
	subq	24(%r12, %rcx, 8), %rbx
	sbbq	16(%r12, %rcx, 8), %rdx
	sbbq	8(%r12, %rcx, 8), %r8
	andq	$0xf, %r10
	sbbq	(%r12, %rcx, 8), %r9
	sbbq	%r10, %r15

	movq	$0xffffffff, %r13
	movq	$0xffffffff00000001, %r12
	movq	$0xffffffffffffffff, %r10
	movq	%rbx, (%rdi)
	movq	%rdx, 2*4(%rdi)
	movq	%r8, 4*4(%rdi)
	movq	%r9, 6*4(%rdi)

	subq	%r10, %rbx
	sbbq	%r13, %rdx
	sbbq	$0, %r8
	sbbq	%r12, %r9
	sbbq	$0, %r15
	jb	.mul_mod_p256_done

	movq	%rbx, (%rdi)
	movq	%rdx, 2*4(%rdi)
	movq	%r8, 4*4(%rdi)
	movq	%r9, 6*4(%rdi)

.mul_mod_p256_done:
	pop	%rbx
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	ret
SYM_FUNC_END(mpi_mul_mod_p256_x86_64_4)

SYM_FUNC_START_32(mpi_sqr_mod_p256_x86_64_4)
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	movq	(%rsi), %rdx
	mulxq	8(%rsi), %r9, %r10
	mulxq	24(%rsi), %r11, %r12
	movq	16(%rsi), %rdx
	mulxq	8(%rsi), %rcx, %rbx
	xorq	%r15, %r15
	adoxq	%rcx, %r11
	mulxq	24(%rsi), %r13, %r14
	adoxq	%rbx, %r12
	mulxq	(%rsi), %rcx, %rbx
	adoxq	%r15, %r13
	adcxq	%rcx, %r10
	adoxq	%r15, %r14
	movq	8(%rsi), %rdx
	mulxq	24(%rsi), %rax, %r8
	adcxq	%rbx, %r11
	adcxq	%rax, %r12
	adcxq	%r8, %r13
	adcxq	%r15, %r14
	xorq	%r15, %r15
	movq	(%rsi), %rdx
	mulxq	%rdx, %r8, %rax
	adcxq	%r9, %r9
	movq	8(%rsi), %rdx
	mulxq	%rdx, %rcx, %rbx
	adcxq	%r10, %r10
	adoxq	%rax, %r9
	adcxq	%r11, %r11
	adoxq	%rcx, %r10
	movq	16(%rsi), %rdx
	mulxq	%rdx, %rax, %rcx
	adcxq	%r12, %r12
	adoxq	%rbx, %r11
	adcxq	%r13, %r13
	adoxq	%rax, %r12
	movq	24(%rsi), %rdx
	mulxq	%rdx, %rax, %rbx
	adcxq	%r14, %r14
	adoxq	%rcx, %r13
	adcxq	%r15, %r15
	adoxq	%rax, %r14
	adoxq	%rbx, %r15

	movq	%r12, %rsi
	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)
	shrdq	$32, %r13, %rsi

	/* Modular reduction from ecp_mod_p256_x86_64(). */
	xorq	%rcx, %rcx

	shrq	$32, %r13
	movq	2*4(%rdi), %rdx
	movq	4*4(%rdi), %r8
	movq	12*4(%rdi), %r12
	shlq	$32, %r13
	movq	6*4(%rdi), %r9
	movq	14*4(%rdi), %r10
	addq	%r13, %rdx
	adcq	%r12, %r8
	adcq	%r10, %r9
	adcq	$0, %rcx
	addq	%r13, %rdx
	adcq	%r12, %r8
	adcq	%r10, %r9
	adcq	$0, %rcx

	shrdq	$32, %r15, %r14
	movl	15*4(%rdi), %eax
	movq	12*4(%rdi), %r11
	shlq	$32, %r11
	addq	%r11, %rdx
	adcq	%r14, %r8
	adcq	%rax, %r9
	adcq	$0, %rcx
	addq	%r11, %rdx
	adcq	%r14, %r8
	adcq	%rax, %r9
	adcq	$0, %rcx

	movq	(%rdi), %rbx
	movq	8*4(%rdi), %r15
	movl	10*4(%rdi), %eax
	addq	%r15, %rbx
	adcq	%rax, %rdx
	adcq	$0, %r8
	adcq	%r10, %r9
	adcq	$0, %rcx

	shrq	$32, %r13
	shlq	$32, %r14
	orq	%r14, %r13
	movl	8*4(%rdi), %eax
	shrq	$32, %r14
	shlq	$32, %rax
	orq	%r14, %rax
	addq	%rsi, %rbx
	adcq	%r13, %rdx
	adcq	%r10, %r8
	adcq	%rax, %r9
	adcq	$0, %rcx

	movq	10*4(%rdi), %r11
	shrq	$32, %rax
	shlq	$32, %r11
	movq	11*4(%rdi), %r13
	orq	%rax, %r11
	subq	%r13, %rbx
	sbbq	%r14, %rdx
	sbbq	$0, %r8
	sbbq	%r11, %r9
	sbbq	$0, %rcx

	movl	9*4(%rdi), %eax
	shlq	$32, %r13
	orq	%rax, %r13
	subq	%r12, %rbx
	sbbq	%r10, %rdx
	sbbq	$0, %r8
	sbbq	%r13, %r9
	sbbq	$0, %rcx

	movq	13*4(%rdi), %r13
	shldq	$32, %r10, %r11
	shlq	$32, %r12
	movq	$0xfffffffffffffffb, %r15
	subq	%r13, %rbx
	movq	$0x4ffffffff, %rax
	sbbq	%r11, %rdx
	sbbq	%rsi, %r8
	sbbq	%r12, %r9
	sbbq	$0, %rcx
	movq	$0xfffffffb00000005, %r11

	movq	10*4(%rdi), %r14
	shlq	$32, %r13
	shlq	$32, %rsi
	subq	%r10, %rbx
	sbbq	%rsi, %rdx
	sbbq	%r14, %r8
	sbbq	%r13, %r9
	sbbq	$0, %rcx

	movq	$0xba98765432100, %r10
	addq	%r15, %rbx
	adcq	%rax, %rdx
	adcq	$0, %r8
	adcq	%r11, %r9
	adcq	$4, %rcx

	movq	%rcx, %r15
	shlq	$2, %rcx
	leaq	__P256x(%rip), %r12
	shrq	%cl, %r10
	subq	24(%r12, %rcx, 8), %rbx
	sbbq	16(%r12, %rcx, 8), %rdx
	sbbq	8(%r12, %rcx, 8), %r8
	andq	$0xf, %r10
	sbbq	(%r12, %rcx, 8), %r9
	sbbq	%r10, %r15

	movq	$0xffffffff, %r11
	movq	$0xffffffff00000001, %r12
	movq	$0xffffffffffffffff, %r10
	movq	%rbx, (%rdi)
	movq	%rdx, 2*4(%rdi)
	movq	%r8, 4*4(%rdi)
	movq	%r9, 6*4(%rdi)

	subq	%r10, %rbx
	sbbq	%r11, %rdx
	sbbq	$0, %r8
	sbbq	%r12, %r9
	sbbq	$0, %r15
	jb	.sqr_mod_p256_done

	movq	%rbx, (%rdi)
	movq	%rdx, 2*4(%rdi)
	movq	%r8, 4*4(%rdi)
	movq	%r9, 6*4(%rdi)

.sqr_mod_p256_done:
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx
	ret
SYM_FUNC_END(mpi_sqr_mod_p256_x86_64_4)


/**
 * Convert the 4-limbs number in %RDI from Montogomery domain:
 *   r = a * 2^-256 mod P256
 *
 * This is the bit modified tail of WolfSSL sp_256_mont_mul_4(), which uses
 * the special form of the NIST prime, so we can replace MUL with additions
 * and shifts.
 */
.macro MONT_REDUCE
	/*
	 * mu = a[0]-a[3] + a[0]-a[2] << 32 << 64 + (a[0] * 2) << 192
	 *      - a[0] << 32 << 192 + (a[0] * 2) << 192
	 */
	movq	%r8, %rax
	movq	%r11, %rdx
	addq	%r8, %rdx
	movq	%r9, %rsi
	addq	%r8, %rdx
	movq	%r10, %rcx

	/* a[0]-a[2] << 32 */
	shlq	$32, %r8
	shldq	$32, %rsi, %r10
	shldq	$32, %rax, %r9

	/* - a[0] << 32 << 192 */
	subq	%r8, %rdx

	/* + a[0]-a[2] << 32 << 64 */
	addq	%r8, %rsi
	adcq	%r9, %rcx
	adcq	%r10, %rdx

	/*
	 * a += (mu << 256) - (mu << 224) + (mu << 192) + (mu << 96) - mu
	 * a += mu << 256
	 */
	xorq	%r8, %r8
	addq	%rax, %r12
	adcq	%rsi, %r13
	adcq	%rcx, %r14
	adcq	%rdx, %r15

	/* a += mu << 192 */
	sbbq	$0x00, %r8
	addq	%rax, %r11
	adcq	%rsi, %r12
	adcq	%rcx, %r13
	adcq	%rdx, %r14
	adcq	$0x00, %r15
	sbbq	$0x00, %r8

	/* mu <<= 32 */
	movq	%rdx, %rbx
	shldq	$32, %rcx, %rdx
	shldq	$32, %rsi, %rcx
	shldq	$32, %rax, %rsi
	shrq	$32, %rbx
	shlq	$32, %rax

	/* a += (mu << 32) << 64 */
	addq	%rcx, %r11
	adcq	%rdx, %r12
	adcq	%rbx, %r13
	adcq	$0x00, %r14
	adcq	$0x00, %r15
	sbbq	$0x00, %r8

	/* a -= (mu << 32) << 192 */
	subq	%rax, %r11
	sbbq	%rsi, %r12
	sbbq	%rcx, %r13
	sbbq	%rdx, %r14
	sbbq	%rbx, %r15
	adcq	$0x00, %r8

	/*
	 * J.W.Bos, "Montgomery Arithmetic from a Software Perspective", 2017,
	 * chapter 2.4.2 proposes to check whether subtraction is required
	 * (if non-constant time execution is allowed). If we jump from here on
	 * ZF=0 to the end of the function we save several instructions and
	 * will do see up to 10% performance improvement for the multiplication
	 * and squaring benchmark, but the total execution time for point
	 * multiplication operations will increase. There reason is the branch
	 * misprediction - it's cheaper to execute the small code if the data
	 * changes.
	 */
	movq	$0xffffffff, %rax
	movq	$0xffffffff00000001, %rsi
	/*
	 * mask m and sub from result if overflow
	 * m[0] = -1 & mask = mask
	 */
	andq	%r8, %rax
	/* m[2] =  0 & mask = 0 */
	andq	%r8, %rsi
	subq	%r8, %r12
	sbbq	%rax, %r13
	sbbq	$0x00, %r14
	sbbq	%rsi, %r15

	/* Write data to the first input argument. */
	movq	%r12, (%rdi)
	movq	%r13, 8(%rdi)
	movq	%r14, 16(%rdi)
	movq	%r15, 24(%rdi)
.endm

SYM_FUNC_START_32(mpi_from_mont_p256_x86_64)
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	pushq	%rbx

	movq	(%rdi), %r8
	movq	8(%rdi), %r9
	movq	16(%rdi), %r10
	movq	24(%rdi), %r11

	xorq	%r12, %r12
	xorq	%r13, %r13
	xorq	%r14, %r14
	xorq	%r15, %r15

	MONT_REDUCE

	popq	%rbx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	retq
SYM_FUNC_END(mpi_from_mont_p256_x86_64)

/**
 * Montgomery multiplication in NIST p256 domain of %RDI and %RSI 4-limbs MPIs
 * and store the reduced result in %RDI.
 *
 * Based on WolfSSL sp_256_mont_mul_avx2_4().
 */
SYM_FUNC_START_32(mpi_mul_mont_mod_p256_x86_64)
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	movq	%rdx, %rcx
	#  A[0] * B[0]
	movq	(%rcx), %rdx
	mulxq	(%rsi), %r8, %r9
	#  A[2] * B[0]
	mulxq	16(%rsi), %r10, %r11
	#  A[1] * B[0]
	mulxq	8(%rsi), %rax, %rbx
	xorq	%r15, %r15
	adcxq	%rax, %r9
	#  A[1] * B[3]
	movq	24(%rcx), %rdx
	mulxq	8(%rsi), %r12, %r13
	adcxq	%rbx, %r10
	#  A[0] * B[1]
	movq	8(%rcx), %rdx
	mulxq	(%rsi), %rax, %rbx
	adoxq	%rax, %r9
	#  A[2] * B[1]
	mulxq	16(%rsi), %rax, %r14
	adoxq	%rbx, %r10
	adcxq	%rax, %r11
	#  A[1] * B[2]
	movq	16(%rcx), %rdx
	mulxq	8(%rsi), %rax, %rbx
	adcxq	%r14, %r12
	adoxq	%rax, %r11
	adcxq	%r15, %r13
	adoxq	%rbx, %r12
	#  A[0] * B[2]
	mulxq	(%rsi), %rax, %rbx
	adoxq	%r15, %r13
	xorq	%r14, %r14
	adcxq	%rax, %r10
	#  A[1] * B[1]
	movq	8(%rcx), %rdx
	mulxq	8(%rsi), %rdx, %rax
	adcxq	%rbx, %r11
	adoxq	%rdx, %r10
	#  A[3] * B[1]
	movq	8(%rcx), %rdx
	adoxq	%rax, %r11
	mulxq	24(%rsi), %rax, %rbx
	adcxq	%rax, %r12
	#  A[2] * B[2]
	movq	16(%rcx), %rdx
	mulxq	16(%rsi), %rdx, %rax
	adcxq	%rbx, %r13
	adoxq	%rdx, %r12
	#  A[3] * B[3]
	movq	24(%rcx), %rdx
	adoxq	%rax, %r13
	mulxq	24(%rsi), %rax, %rbx
	adoxq	%r15, %r14
	adcxq	%rax, %r14
	#  A[0] * B[3]
	mulxq	(%rsi), %rdx, %rax
	adcxq	%rbx, %r15
	xorq	%rbx, %rbx
	adcxq	%rdx, %r11
	#  A[3] * B[0]
	movq	24(%rsi), %rdx
	adcxq	%rax, %r12
	mulxq	(%rcx), %rbp, %rax
	adoxq	%rbp, %r11
	adoxq	%rax, %r12
	#  A[3] * B[2]
	mulxq	16(%rcx), %rdx, %rax
	adcxq	%rdx, %r13
	#  A[2] * B[3]
	movq	24(%rcx), %rdx
	adcxq	%rax, %r14
	mulxq	16(%rsi), %rax, %rdx
	adcxq	%rbx, %r15
	adoxq	%rax, %r13
	adoxq	%rdx, %r14
	adoxq	%rbx, %r15

	MONT_REDUCE

	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	retq
SYM_FUNC_END(mpi_mul_mont_mod_p256_x86_64)

/**
 * Square a 4-limbs MPI in Montgomery form pointed by %RSI and store the
 * p256 reduced result in %RDI.
 *
 * "Speeding up Big-Numbers Squaring" by Gueron and Krasnov suggest to use SHLD
 * to double all x[i]*x[j] products at once. While this implementation also
 * doebles the products only once, it uses ADCX interleaving with squaring and
 * which also has lower latency and higher throughput.
 *
 * Based on WolfSSL sp_256_mont_sqr_avx2_4().
 */
SYM_FUNC_START_32(mpi_sqr_mont_mod_p256_x86_64)
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	pushq	%rbx

	# A[0] * A[1]
	movq	(%rsi), %rdx
	movq	16(%rsi), %r15
	mulxq	8(%rsi), %r9, %r10
	# A[0] * A[3]
	mulxq	24(%rsi), %r11, %r12
	# A[2] * A[1]
	movq	%r15, %rdx
	mulxq	8(%rsi), %rcx, %rbx
	# A[2] * A[3]
	mulxq	24(%rsi), %r13, %r14
	xorq	%r15, %r15
	adoxq	%rcx, %r11
	adoxq	%rbx, %r12
	# A[2] * A[0]
	mulxq	(%rsi), %rcx, %rbx
	# A[1] * A[3]
	movq	8(%rsi), %rdx
	adoxq	%r15, %r13
	mulxq	24(%rsi), %rax, %r8
	adcxq	%rcx, %r10
	adoxq	%r15, %r14
	adcxq	%rbx, %r11
	adcxq	%rax, %r12
	adcxq	%r8, %r13
	adcxq	%r15, %r14
	# Double with Carry Flag
	xorq	%r15, %r15
	# A[0] * A[0]
	movq	(%rsi), %rdx
	mulxq	%rdx, %r8, %rax
	adcxq	%r9, %r9
	adcxq	%r10, %r10
	adoxq	%rax, %r9
	# A[1] * A[1]
	movq	8(%rsi), %rdx
	mulxq	%rdx, %rcx, %rbx
	adcxq	%r11, %r11
	adoxq	%rcx, %r10
	# A[2] * A[2]
	movq	16(%rsi), %rdx
	mulxq	%rdx, %rax, %rcx
	adcxq	%r12, %r12
	adoxq	%rbx, %r11
	adcxq	%r13, %r13
	adoxq	%rax, %r12
	adcxq	%r14, %r14
	# A[3] * A[3]
	movq	24(%rsi), %rdx
	mulxq	%rdx, %rax, %rbx
	adoxq	%rcx, %r13
	adcxq	%r15, %r15
	adoxq	%rax, %r14
	adoxq	%rbx, %r15

	MONT_REDUCE

	popq	%rbx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	retq
SYM_FUNC_END(mpi_sqr_mont_mod_p256_x86_64)
