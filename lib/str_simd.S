/**
 * x86-64 SIMD routines for HTTP strings processing. See the algorithms'
 * description and performance comparison with other implementations at
 * http://natsys-lab.blogspot.ru/2016/10/http-strings-processing-using-c-sse42.html
 * and https://github.com/natsys/blog/tree/master/kstrings .
 * We have to write the stuff in assembly since GCC sometimes generates not the
 * best code (e.g. with unnecessary vzeroupper calls) and also requires standard
 * includes like stdlib.h.
 *
 * The implementation doesn't use alignment function prologs since aligned
 * version has shown worse performance, see the memcpy.c microbenchmark.
 *
 * Copyright (C) 2018-2021 Tempesta Technologies, Inc.
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

SYM_FUNC_START(__memcpy_fast)
	movq	%rdx, %rax
	leaq	128(%rsi), %rcx
	movq	%rsi, %r8
	andq	$-32, %rax
	addq	%rsi, %rax
	cmpq	%rcx, %rax
	jnb	.L128cpy
	testb	$64, %dl
	jne	.L64cpy
.L32cpy_tail:
	testb	$32, %dl
	jne	.L32cpy
.L16cpy_tail:
	movq	%r8, %rcx
	movq	%rdi, %rax
	testb	$16, %dl
	jne	.L16cpy
.L8cpy_tail:
	testb	$8, %dl
	jne	.L8cpy
.L4cpy_tail:
	testb	$4, %dl
	jne	.L4cpy
.L2cpy_tail:
	testb	$2, %dl
	jne	.L2cpy
.L1cpy_tail:
	andl	$1, %edx
	jne	.L1cpy
	/* Don't clean the registers w/ vzeroupper. */
	RET
	.p2align 4
.Lrepeat128cpy:
	movq	%r8, %rsi
.L128cpy:
	vlddqu	(%rsi), %ymm3
	vlddqu	32(%rsi), %ymm2
	movq	%rcx, %r8
	leaq	96(%rdi), %rcx
	vlddqu	64(%rsi), %ymm1
	vlddqu	96(%rsi), %ymm0
	subq	$-128, %rdi
	vmovdqu	%ymm3, -128(%rdi)
	vmovdqu	%ymm2, -96(%rdi)
	vmovdqu	%ymm1, -64(%rdi)
	vmovdqu	%ymm0, (%rcx)
	leaq	256(%rsi), %rcx
	cmpq	%rcx, %rax
	jnb	.Lrepeat128cpy
	testb	$64, %dl
	je	.L32cpy_tail
.L64cpy:
	leaq	32(%r8), %rax
	vlddqu	(%r8), %ymm1
	vlddqu	(%rax), %ymm0
	leaq	32(%rdi), %rax
	addq	$64, %r8
	addq	$64, %rdi
	vmovdqu	%ymm1, -64(%rdi)
	vmovdqu	%ymm0, (%rax)
	testb	$32, %dl
	je	.L16cpy_tail
.L32cpy:
	vlddqu	(%r8), %ymm0
	addq	$32, %rdi
	addq	$32, %r8
	movq	%r8, %rcx
	vmovdqu	%ymm0, -32(%rdi)
	movq	%rdi, %rax
	testb	$16, %dl
	je	.L8cpy_tail
.L16cpy:
	vlddqu	(%r8), %xmm0
	addq	$16, %rcx
	addq	$16, %rax
	vmovups	%xmm0, (%rdi)
	testb	$8, %dl
	je	.L4cpy_tail
.L8cpy:
	movq	(%rcx), %rsi
	addq	$8, %rax
	addq	$8, %rcx
	movq	%rsi, -8(%rax)
	testb	$4, %dl
	je	.L2cpy_tail
.L4cpy:
	movl	(%rcx), %esi
	addq	$4, %rax
	addq	$4, %rcx
	movl	%esi, -4(%rax)
	testb	$2, %dl
	je	.L1cpy_tail
.L2cpy:
	movzwl	(%rcx), %esi
	addq	$2, %rax
	addq	$2, %rcx
	movw	%si, -2(%rax)
	andl	$1, %edx
	je	.Lcpy_ret
.L1cpy:
	movzbl	(%rcx), %edx
	movb	%dl, (%rax)
.Lcpy_ret:
	RET
SYM_FUNC_END(__memcpy_fast)

SYM_FUNC_START(__memcmp_fast)
	leaq	(%rdi,%rdx), %rax
	leaq	128(%rdi), %rcx
	cmpq	%rcx, %rax
	jnb	.L128cmp_loop
	movq	%rdi, %rcx
.L64cmp_tail:
	testb	$64, %dl
	jne	.L64cmp
.L32cmp_tail:
	testb	$32, %dl
	jne	.L32cmp
.L16cmp_tail:
	testb	$16, %dl
	jne	.L16cmp
.L8cmp_tail:
	testb	$8, %dl
	jne	.L8cmp
.L4cmp_tail:
	testb	$4, %dl
	jne	.L4cmp
.L2cmp_tail:
	testb	$2, %dl
	jne	.L2cmp
.L1cmp_tail:
	xorl	%eax, %eax
	andl	$1, %edx
	jne	.L1cmp
	RET
	.p2align 4
.L128cmp:
	vlddqu	-96(%rcx), %ymm0
	vlddqu	32(%rsi), %ymm1
	vpcmpeqd %ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %edi
	cmpl	$-1, %edi
	jne	.Lret_neq
	vlddqu	-64(%rcx), %ymm0
	vlddqu	64(%rsi), %ymm1
	vpcmpeqd %ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %edi
	cmpl	$-1, %edi
	jne	.Lret_neq
	vlddqu	-32(%rcx), %ymm0
	vlddqu	96(%rsi), %ymm1
	vpcmpeqd %ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %edi
	addl	$1, %edi
	jne	.Lret_neq
	leaq	128(%rcx), %rdi
	subq	$-128, %rsi
	cmpq	%rdi, %rax
	jb	.L64cmp_tail
	movq	%rdi, %rcx
.L128cmp_loop:
	vlddqu	-128(%rcx), %ymm0
	vlddqu	(%rsi), %ymm1
	vpcmpeqd %ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %edi
	cmpl	$-1, %edi
	je	.L128cmp
.Lret_neq:
	movl	$1, %eax
	RET
.L64cmp:
	vlddqu	(%rcx), %ymm0
	vlddqu	(%rsi), %ymm1
	vpcmpeqd %ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %eax
	cmpl	$-1, %eax
	jne	.Lret_neq
	vlddqu	32(%rcx), %ymm0
	vlddqu	32(%rsi), %ymm1
	vpcmpeqd %ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %eax
	cmpl	$-1, %eax
	jne	.Lret_neq
	addq	$64, %rcx
	addq	$64, %rsi
	jmp	.L32cmp_tail
.L32cmp:
	vlddqu	(%rcx), %ymm0
	vlddqu	(%rsi), %ymm1
	movl	$1, %eax
	vpcmpeqd %ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %edi
	cmpl	$-1, %edi
	jne	.Lcmp_ret
	addq	$32, %rcx
	addq	$32, %rsi
	jmp	.L16cmp_tail
.L16cmp:
	vlddqu	(%rcx), %xmm0
	vlddqu	(%rsi), %xmm1
	movl	$1, %eax
	vpcmpeqw %xmm1, %xmm0, %xmm0
	vpmovmskb %xmm0, %edi
	cmpl	$65535, %edi
	jne	.Lcmp_ret
	addq	$16, %rcx
	addq	$16, %rsi
	jmp	.L8cmp_tail
.L8cmp:
	movq	(%rsi), %rax
	cmpq	%rax, (%rcx)
	jne	.Lret_neq
	addq	$8, %rcx
	addq	$8, %rsi
	jmp	.L4cmp_tail
.L4cmp:
	movl	(%rsi), %eax
	cmpl	%eax, (%rcx)
	jne	.Lret_neq
	addq	$4, %rcx
	addq	$4, %rsi
	jmp	.L2cmp_tail
.L2cmp:
	movzwl	(%rsi), %eax
	cmpw	%ax, (%rcx)
	jne	.Lret_neq
	addq	$2, %rcx
	addq	$2, %rsi
	jmp	.L1cmp_tail
.L1cmp:
	movzbl	(%rsi), %eax
	cmpb	%al, (%rcx)
	setne	%al
	movzbl	%al, %eax
.Lcmp_ret:
	RET
SYM_FUNC_END(__memcmp_fast)

SYM_FUNC_START(__bzero_fast)
	movq	%rsi, %rax
	movq	%rdi, %rdx
	andq	$-128, %rax
	addq	%rdi, %rax
	cmpq	%rax, %rdi
	vpxor	%ymm0, %ymm0, %ymm0
	jb	.L128zer
	testb	$64, %sil
	jne	.L64zer
.L32bz_tail:
	testb	$32, %sil
	jne	.L32zer
.L16bz_tail:
	movq	%rdx, %rax
	testb	$16, %sil
	jne	.L16zer
.L8bz_tail:
	testb	$8, %sil
	jne	.L8zer
.L4bz_tail:
	testb	$4, %sil
	jne	.L4zer
.L2bz_tail:
	testb	$2, %sil
	jne	.L2zer
.L1bz_tail:
	andl	$1, %esi
	jne	.L1zer
	/* Don't clean the registers w/ vzeroupper. */
	RET
	.p2align 4
.L128zer:
	vmovdqu	%ymm0, (%rdx)
	subq	$-128, %rdx
	vmovdqu	%ymm0, -96(%rdx)
	vmovdqu	%ymm0, -64(%rdx)
	vmovdqu	%ymm0, -32(%rdx)
	cmpq	%rdx, %rax
	ja	.L128zer
	movq	%rdi, %rdx
	notq	%rdx
	addq	%rdx, %rax
	andq	$-128, %rax
	leaq	128(%rdi,%rax), %rdx
	testb	$64, %sil
	je	.L32bz_tail
.L64zer:
	addq	$64, %rdx
	vmovdqu	%ymm0, -64(%rdx)
	vmovdqu	%ymm0, -32(%rdx)
	testb	$32, %sil
	je	.L16bz_tail
.L32zer:
	addq	$32, %rdx
	vmovdqu	%ymm0, -32(%rdx)
	movq	%rdx, %rax
	testb	$16, %sil
	je	.L8bz_tail
.L16zer:
	addq	$16, %rax
	vmovups	%xmm0, (%rdx)
	testb	$8, %sil
	je	.L4bz_tail
.L8zer:
	movq	$0, (%rax)
	addq	$8, %rax
	testb	$4, %sil
	je	.L2bz_tail
.L4zer:
	movl	$0, (%rax)
	addq	$4, %rax
	testb	$2, %sil
	je	.L1bz_tail
.L2zer:
	movw	$0, (%rax)
	addq	$2, %rax
	andl	$1, %esi
	je	.Lbz_ret
.L1zer:
	movb	$0, (%rax)
.Lbz_ret:
	RET
SYM_FUNC_END(__bzero_fast)
