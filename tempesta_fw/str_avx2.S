/**
 *		Tempesta FW
 *
 * x86-64 SIMD routines for HTTP strings processing. See the algorithms'
 * description and performance comparison with other implementations at
 * http://natsys-lab.blogspot.ru/2016/10/http-strings-processing-using-c-sse42.html
 *
 * Copyright (C) 2016-2019 Tempesta Technologies, Inc.
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

#define CASE	0x2020202020202020

/*
 * Static structure of constants for vector processing.
 *
 * @A		- ASCII 'A' - 1
 * @D		- ASCII 'z' - 'a' + 1
 * @LCASE	- 0x20 converting upper case character to lower case;
 * @ARF		- ASCII rows factors;
 * @LSH		- Mask for least significant half of bytes;
 * @_uri	- ASCII table column bitmaps for HTTP URI abs_path (RFC 3986);
 * @_token	- ASCII table column bitmaps for HTTP token, e.g. header name
 *		  (RFC 7230 3.2.6);
 * @_qetoken	- `token` with double quotes and equal sign;
 * @_nctl	- ASCII VCHAR (RFC RFC 5234, Appendix B.1.) plus SP and HTAB,
 *		  used to accept HTTP header values;
 * @_xff	- ASCII characters for HTTP X-Forwarded-For header (RFC 7239);
 * @_cookie	- cookie-octet as defined in RFC 6265 4.1.1 plus DQUOTE;
 * @ZERO	- ASCII zero upper bound for matching 0 < v < SP;
 * @SP		- ASCII SP low bound for matching 0 < v < SP;
 * @HTAB	- ASCII HTAB;
 * @DEL		- ASCII DEL;
 * @ASCII	- most significant bit to split ASCII table to 2 halves;
 */
.section .rodata
.align 64
__C:
	/* 'A'(0x41) - 0x80 = 0xc1 */
	.quad	0xc1c1c1c1c1c1c1c1, 0xc1c1c1c1c1c1c1c1
	.quad	0xc1c1c1c1c1c1c1c1, 0xc1c1c1c1c1c1c1c1
	/* 'a'(0x61) - 0x80 = 0xe1 */
	.quad	0xe1e1e1e1e1e1e1e1, 0xe1e1e1e1e1e1e1e1
	.quad	0xe1e1e1e1e1e1e1e1, 0xe1e1e1e1e1e1e1e1
	/* 'Z'(0x5a) - 'A'(0x41) + 1 - 0x80 = 0x9a */
	.quad	0x9a9a9a9a9a9a9a9a, 0x9a9a9a9a9a9a9a9a
	.quad	0x9a9a9a9a9a9a9a9a, 0x9a9a9a9a9a9a9a9a
	/* Case conversion. */
	.quad	CASE, CASE, CASE, CASE
	/* ASCII Row IDs. */
	.quad	0x8040201008040201, 0x8040201008040201
	.quad	0x8040201008040201, 0x8040201008040201
	/* ASCII Row ID masks. */
	.quad	0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
	.quad	0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
	/*
	 * ASCII zero character '\0' to use in strict signed comparison.
	 * 0 - 0x80 = 0x80.
	 */
	.quad	0x8080808080808080, 0x8080808080808080
	.quad	0x8080808080808080, 0x8080808080808080
	/*
	 * ASCII space ' ' to use in signed comparison,
	 * ' '(0x20) - 0x80 = 0xa0.
	 */
	.quad	0xa0a0a0a0a0a0a0a0, 0xa0a0a0a0a0a0a0a0
	.quad	0xa0a0a0a0a0a0a0a0, 0xa0a0a0a0a0a0a0a0
	/* Horizontal tab '\t' = 0x9. */
	.quad	0x0909090909090909, 0x0909090909090909
	.quad	0x0909090909090909, 0x0909090909090909
	/* ASCII DEL (0x78). */
	.quad	0x7f7f7f7f7f7f7f7f, 0x7f7f7f7f7f7f7f7f
	.quad	0x7f7f7f7f7f7f7f7f, 0x7f7f7f7f7f7f7f7f
	/*
	 * URI-accepted characters, in little endian.
	 *
	 * ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
	 * !#$%&'*+-._();:@=,/?[]~0123456789
	 */
	.quad	0xfcfcfcfcfcf8fcb8, 0x7cd47c547cfcfcfc
	.quad	0xfcfcfcfcfcf8fcb8, 0x7cd47c547cfcfcfc
	/*
	 * Token: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
	 *	  !#$%&'*+-.^_`|~0123456789
	 */
	.quad	0xfcfcfcfcfcf8fce8, 0x70f454d054f4f8f8
	.quad	0xfcfcfcfcfcf8fce8, 0x70f454d054f4f8f8
	/*
	 * Token with DQUOTE and "=".
	 */
	.quad	0xfcfcfcfcfcfcfce8, 0x70f45cd054f4f8f8
	.quad	0xfcfcfcfcfcfcfce8, 0x70f45cd054f4f8f8
	/*
	 * RFC 7230, Appendix B; RFC 5234, Appendix B.1.:
	 *
	 * 	field-value OWS = VCHAR SP HTAB = %x9 %x20-7E
	 *
	 * , i.e. non-control characters.
	 */
	.quad	0xfcfcfcfcfcfcfcfc, 0x7cfcfcfcfcfcfdfc
	.quad	0xfcfcfcfcfcfcfcfc, 0x7cfcfcfcfcfcfdfc
	/*
	 * Alphabet for X-Forwarded-For Node ID (RFC 7239):
	 *
	 *	ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
	 *	0123456789._-[]:
	 */
	.quad	0xf8f8f8f8f8f8f8a8, 0x7054745070f8f8f8
	.quad	0xf8f8f8f8f8f8f8a8, 0x7054745070f8f8f8
	/*
	 * Cookie-octet w/ DQUOTE: %x21 %x22-2B %x2D-3A %x3C-5B %x5D-7E
	 */
	.quad	0xfcfcfcfcfcfcfcf8, 0x7cfcfcd8f4fcfcfc
	.quad	0xfcfcfcfcfcfcfcf8, 0x7cfcfcd8f4fcfcfc

/* Helping vector data referenced by value. */
#define __A			__C(%rip)
#define __a			__C+0x020(%rip)
#define __D			__C+0x040(%rip)
#define __CASE			__C+0x060(%rip)
#define __ARF			__C+0x080(%rip)
#define __LSH			__C+0x0a0(%rip)
#define __ZERO			__C+0x0c0(%rip)
#define __SP			__C+0x0e0(%rip)
#define __HTAB			__C+0x100(%rip)
#define __DEL			__C+0x120(%rip)
#define __ASCII			__ZERO

/* Allowed alphabet passed to processing functions by pointer. */
#define __URI			$__C+0x140
#define __TOKEN			$__C+0x160
#define __QETOKEN		$__C+0x180
#define __NCTL			$__C+0x1a0
#define __XFF			$__C+0x1c0
#define __COOKIE		$__C+0x1e0

.align 64

/*
 * ASCII codes to accept URI string (byte representation for __URI).
 *
 * While we can pack the array, which is 4 cache lines currently,
 * to just half of a cache line using 4 64-bit masks, it's much
 * faster to access the extra cache lines than to the 4 bit operations
 * (uri_a[c >> 6] & (1UL << (c & 0x3f))).
 */
uri:
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1
	.byte	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

/*
 * ASCII table column bitmaps for HTTP token, e.g. header name (RFC 7230 3.2.6).
 * (Byte representation for __TOKEN).
 */
token:
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0
	.byte	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

/*
 * Token with DQUOTE and "=".
 * (Byte representation for __QETOKEN).
 */
qetoken:
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0
	.byte	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

/*
 * ASCII codes to accept HTTP header values
 * (Byte representation for __NCTL above).
 */
nctl:
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

/*
 * ASCII codes to accept ctext | VCHAR, e.g. User-Agent.
 */
ctext_vchar:
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1

/*
 * ASCII codes to accept X-Forwarded-For values
 * (byte representation for __XFF).
 */
xff:
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0
	.byte	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1
	.byte	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

/*
 * ASCII codes for Cookie value matching by cookie-octet defined
 * by RFC 6265 4.1.1 as
 *
 * 	%x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
 * 	; US-ASCII characters excluding CTLs,
 * 	; whitespace DQUOTE, comma, semicolon,
 * 	; and backslash
 *
 * We add DQUOTES to the set since we don't analyzer cookie value
 * grammar. This is byte representation for __COOKIE above.
 */
cookie:
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	.byte	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

#ifdef DEBUG

dbg_prefix_vec:
	.string "vec32"

#endif

/*
 * Custom character alphabets allowed for various HTTP fields.
 */
.extern __CUSTOM

#define __CUST_URI_0		$__CUSTOM
#define __CUST_URI_1		$__CUSTOM+0x020
#define __CUST_TOKEN_0		$__CUSTOM+0x040
#define __CUST_TOKEN_1		$__CUSTOM+0x060
#define __CUST_QETOKEN_0	$__CUSTOM+0x080
#define __CUST_QETOKEN_1	$__CUSTOM+0x0a0
#define __CUST_NCTL_0		$__CUSTOM+0x0c0
#define __CUST_NCTL_1		$__CUSTOM+0x0e0
#define __CUST_CTVCHAR_0	$__CUSTOM+0x100
#define __CUST_CTVCHAR_1	$__CUSTOM+0x120
#define __CUST_XFF_0		$__CUSTOM+0x140
#define __CUST_XFF_1		$__CUSTOM+0x160
#define __CUST_COOKIE_0		$__CUSTOM+0x180
#define __CUST_COOKIE_1		$__CUSTOM+0x1a0

.extern __tfw_lct

.section .text

#ifdef DEBUG
.extern	tfw_dbg_vprint32

/**
 * Use the debug routine to print 32-byte vector residing by memory address
 * residing in @R. The macro is inserted into a function body to print current
 * function arguments, so we save and restore the registers context.
 * Usage exmple (still good for 16 byte registers since we use 32 byte tables):
 *	...
 *	DPRN_V	%rcx
	vlddqu	(%rcx), %xmm15
 */
.macro DPRN_V	R
	push	%rax
	push	%rdi
	push	%rsi
	push	%rdx
	push	%rcx
	push	%r8
	push	%r9

	movq	$dbg_prefix_vec, %rdi
	movq	\R, %rsi
	call	tfw_dbg_vprint32

	pop	%r9
	pop	%r8
	pop	%rcx
	pop	%rdx
	pop	%rsi
	pop	%rdi
	pop	%rax
.endm

/**
 * The same as the above, but prints any register value.
 * Can be used to any size registers, but top bytes for small register will
 * contain zeros from stack.
 */
.macro __DPRN_R	R MOV
	push	%rsi
	push	%rdi
	subq	$64, %rsp
	/*
	 * Use 32-byte aligned address to avoid #GF.
	 * Do not align RSP directly and do not modify RBP to avoid objtool
	 * claims on stack alignment.
	 */
	lea	32(%rsp), %rsi
	andq	$~0x1f, %rsi
	/* Write zeroes to clear extra space for small registers. */
	xor	%rdi, %rdi
	movq	%rdi, (%rsi)
	movq	%rdi, 0x8(%rsi)
	movq	%rdi, 0x10(%rsi)
	movq	%rdi, 0x18(%rsi)

	\MOV	\R, (%rsi)
	DPRN_V	%rsi

	addq	$64, %rsp
	pop	%rdi
	pop	%rsi
.endm

.macro DPRN_VR	R
	__DPRN_R \R vmovaps
.endm

.macro DPRN_R	R
	/* Use RAX as temporary storage in R is either RSI or RDI. */
	push	%rax
	movq	\R, %rax

	__DPRN_R %rax movq

	pop %rax
.endm
#endif

.macro __STRTOLOWER_SMALL_STR	SZ
	movzbl	\SZ(%rsi), %eax
	movzbl	__tfw_lct(%rax), %eax
	movb	%al, \SZ(%rdi)
.endm

.macro __STRTOLOWER_TEST_LEN	SZ R1 R2 L
	leal	\SZ(%rax), \R1
	movslq	\R1, \R2
	cmpq	\R2, %rdx
	jnb	\L
.endm

/**
 * Convert a string to lower case.
 *
 * The function uses byte by byte case conversion using __tfw_lct table and
 * lookup table for the string length to process string suffix and strings
 * smaller than 9 bytes. Next it uses 128, 64, 32, 16 and 8 byte blocks
 * processing using vector instructions. The pseudocode for 32 byte block:
 *
 *	__m256i v = _mm256_lddqu_si256((void *)src);
 *	__m256i sub = _mm256_sub_epi8(v, __A);
 *	__m256i cmp_r = _mm256_cmpgt_epi8(__D, sub);
 *	__m256i lc = _mm256_and_si256(cmp_r, __CASE);
 *	__m256i r = _mm256_or_si256(v, lc);
 *	_mm256_storeu_si256((__m256i *)dest, r);
 */
ENTRY(__tfw_strtolower_avx2)
	leaq	8(%rsp), %r10
	andq	$-32, %rsp
	xorl	%eax, %eax
	movabsq	$CASE, %rcx
	pushq	-8(%r10)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12
	pushq	%r10
	pushq	%rbx
	subq	$88, %rsp
	movq	__A, %r9
	movq	__D, %r8

	/* Process 8 byte prefix of suffix of the string. */
.str2low_prefix_suffix:
	cmpq	$8, %rdx
	ja	.str2low_test_len128
	movq	.str2low_switch(,%rdx,8), %rax
	jmpq	*%rax
.section .rodata
.align	8
.str2low_switch:
	.quad	.str2low_len0
	.quad	.str2low_len1
	.quad	.str2low_len2
	.quad	.str2low_len3
	.quad	.str2low_len4
	.quad	.str2low_len5
	.quad	.str2low_len6
	.quad	.str2low_len7
	.quad	.str2low_len8

.text
.str2low_len8:
	__STRTOLOWER_SMALL_STR 7
.str2low_len7:
	__STRTOLOWER_SMALL_STR 6
.str2low_len6:
	__STRTOLOWER_SMALL_STR 5
.str2low_len5:
	__STRTOLOWER_SMALL_STR 4
.str2low_len4:
	__STRTOLOWER_SMALL_STR 3
.str2low_len3:
	__STRTOLOWER_SMALL_STR 2
.str2low_len2:
	__STRTOLOWER_SMALL_STR 1
.str2low_len1:
	__STRTOLOWER_SMALL_STR 0
.str2low_len0:
	addq	$88, %rsp
	popq	%rbx
	popq	%r10
	popq	%r12
	popq	%rbp
	leaq	-8(%r10), %rsp
	vzeroupper
	ret

	/*
	 * Place the processing code before the conditions block to avoid 2
	 * jumps: for the 128 byte processing loop and following 64 byte block.
	 */
.str2low_tolower128:
	movslq	%r10d, %rax
	vmovdqa	__A, %ymm4
	leal	-128(%rax), %r10d
	vmovdqa	__D, %ymm2
	vmovdqa	__CASE, %ymm0
	movslq	%r10d, %r10
	leaq	(%rsi,%r10), %r11
	addq	%rdi, %r10
	vlddqu	(%r11), %ymm7
	vlddqu	32(%r11), %ymm6
	vpsubb	%ymm4, %ymm7, %ymm1
	vpcmpgtb %ymm1, %ymm2, %ymm1
	vlddqu	64(%r11), %ymm5
	vlddqu	96(%r11), %ymm3
	vpand	%ymm1, %ymm0, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vmovdqu	%ymm1, (%r10)
	vpsubb	%ymm4, %ymm6, %ymm1
	vpcmpgtb %ymm1, %ymm2, %ymm1
	vpand	%ymm1, %ymm0, %ymm1
	vpor	%ymm6, %ymm1, %ymm1
	vmovdqu	%ymm1, 32(%r10)
	vpsubb	%ymm4, %ymm5, %ymm1
	vpsubb	%ymm4, %ymm3, %ymm4
	vpcmpgtb %ymm1, %ymm2, %ymm1
	vpcmpgtb %ymm4, %ymm2, %ymm2
	vpand	%ymm1, %ymm0, %ymm1
	vpand	%ymm2, %ymm0, %ymm0
	vpor	%ymm5, %ymm1, %ymm1
	vpor	%ymm3, %ymm0, %ymm0
	vmovdqu	%ymm1, 64(%r10)
	vmovdqu	%ymm0, 96(%r10)

.str2low_test_len128:
	__STRTOLOWER_TEST_LEN 128 %r10d %r11 .str2low_tolower128
	__STRTOLOWER_TEST_LEN 64 %r10d %r11 .str2low_tolower64
	movslq	%eax, %r11
.str2low_test_len32:
	__STRTOLOWER_TEST_LEN 32 %r10d %rbx .str2low_tolower32
.str2low_test_len16:
	__STRTOLOWER_TEST_LEN 16 %r10d %rbx .str2low_tolower16
.str2low_test_len8:
	__STRTOLOWER_TEST_LEN 8 %ebx %r10 .str2low_tolower8
	movq	%r11, %r10
.str2low_small_len:
	subq	%r10, %rdx
	addq	%r10, %rdi
	addq	%r10, %rsi
	jmp	.str2low_prefix_suffix

.str2low_tolower64:
	leaq	(%rsi,%rax), %rbx
	vmovdqa	__A, %ymm3
	addq	%rdi, %rax
	vmovdqa	__D, %ymm2
	vlddqu	(%rbx), %ymm5
	vmovdqa	__CASE, %ymm1
	vpsubb	%ymm3, %ymm5, %ymm0
	vpcmpgtb %ymm0, %ymm2, %ymm0
	vlddqu	32(%rbx), %ymm4
	vpand	%ymm0, %ymm1, %ymm0
	vpor	%ymm5, %ymm0, %ymm0
	vmovdqu	%ymm0, (%rax)
	vpsubb	%ymm3, %ymm4, %ymm0
	vpcmpgtb %ymm0, %ymm2, %ymm0
	vpand	%ymm0, %ymm1, %ymm0
	vpor	%ymm4, %ymm0, %ymm0
	vmovdqu	%ymm0, 32(%rax)
	movslq	%r10d, %rax
	jmp	.str2low_test_len32

.str2low_tolower32:
	vlddqu	(%rsi,%r11), %ymm1
	movslq	%r10d, %rax
	vmovdqa	__D, %ymm0
	vpsubb	__A, %ymm1, %ymm2
	vpcmpgtb %ymm2, %ymm0, %ymm0
	vpand	__CASE, %ymm0, %ymm0
	vpor	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, (%rdi,%r11)
	movq	%rbx, %r11
	jmp	.str2low_test_len16

.str2low_tolower16:
	vlddqu	(%rsi,%r11), %xmm1
	movslq	%r10d, %rax
	vmovdqa	__D, %xmm0
	vpsubb	__C(%rip), %xmm1, %xmm2
	vpcmpgtb %xmm2, %xmm0, %xmm0
	vpand	__CASE, %xmm0, %xmm0
	vpor	%xmm1, %xmm0, %xmm0
	vmovups	%xmm0, (%rdi,%r11)
	movq	%rbx, %r11
	jmp	.str2low_test_len8

.str2low_tolower8:
	movq	(%rsi,%r11), %rax
	movq	%r9, -88(%rbp)
	movq	-88(%rbp), %mm2
	movq	%r8, -88(%rbp)
	movq	-88(%rbp), %mm1
	movq	%rax, -72(%rbp)
	movq	-72(%rbp), %mm0
	psubb	%mm2, %mm0
	movq	%mm0, -64(%rbp)
	movq	-64(%rbp), %mm0
	pcmpgtb	%mm0, %mm1
	movq	%mm1, -88(%rbp)
	movq	-88(%rbp), %rax
	movq	%rax, -56(%rbp)
	movq	-72(%rbp), %r12
	movq	-56(%rbp), %rax
	andq	%rcx, %rax
	orq	%r12, %rax
	movq	%rax, (%rdi,%r11)
	movslq	%ebx, %rax
	jmp	.str2low_small_len

ENDPROC(__tfw_strtolower_avx2)

/**
 * Case insensitive comprison of the strings %RDI and %RSI of length %RDX.
 * This function converts both the strings to lower case.
 * Return 0 if strings match and non-zero otherwise.
 * See the benchmark mentioned above for C implementation.
 */
ENTRY(__tfw_stricmp_avx2)
	cmpq	$8, %rdx
	ja	.stricmp_short

	/* Process short strings below 8 bytes in length. */
	movq	.stricmp_switch(,%rdx,8), %rax
	jmpq	*%rax
.section .rodata
.align 8
.stricmp_switch:
	.quad	.stricmp_len0
	.quad	.stricmp_len1
	.quad	.stricmp_len2
	.quad	.stricmp_len3
	.quad	.stricmp_len4
	.quad	.stricmp_len5
	.quad	.stricmp_len6
	.quad	.stricmp_len7
	.quad	.stricmp_len8
.text
.stricmp_len7:
	xorl	%eax, %eax
	/*
	 * The blocks at the below use complex mixture for the registers,
	 * so leave them as they are, w/o macro generalization.
	 */
.stricmp_do_len7:
	movzbl	6(%rdi), %edx
	movzbl	6(%rsi), %ecx
	movzbl	__tfw_lct(%rdx), %edx
	xorb	__tfw_lct(%rcx), %dl
	movzbl	%dl, %edx
	orl	%eax, %edx
.stricmp_do_len6:
	movzbl	5(%rdi), %ecx
	movzbl	5(%rsi), %eax
	movzbl	__tfw_lct(%rcx), %ecx
	xorb	__tfw_lct(%rax), %cl
	movzbl	%cl, %eax
	orl	%eax, %edx
.stricmp_do_len5:
	movzbl	4(%rdi), %eax
	movzbl	4(%rsi), %ecx
	movzbl	__tfw_lct(%rax), %eax
	xorb	__tfw_lct(%rcx), %al
	movzbl	%al, %eax
	orl	%edx, %eax
.stricmp_do_len4:
	movzbl	3(%rdi), %ecx
	movzbl	3(%rsi), %edx
	movzbl	__tfw_lct(%rcx), %ecx
	xorb	__tfw_lct(%rdx), %cl
	movzbl	%cl, %edx
	orl	%edx, %eax
.stricmp_do_len3:
	movzbl	2(%rdi), %edx
	movzbl	2(%rsi), %ecx
	movzbl	__tfw_lct(%rdx), %edx
	xorb	__tfw_lct(%rcx), %dl
	movzbl	%dl, %edx
	orl	%eax, %edx
.stricmp_do_len2:
	movzbl	1(%rdi), %ecx
	movzbl	1(%rsi), %eax
	movzbl	__tfw_lct(%rcx), %ecx
	xorb	__tfw_lct(%rax), %cl
	movzbl	%cl, %eax
	orl	%eax, %edx
.stricmp_do_len1:
	movzbl	(%rdi), %eax
	movzbl	(%rsi), %ecx
	movzbl	__tfw_lct(%rax), %eax
	xorb	__tfw_lct(%rcx), %al
	movzbl	%al, %eax
	orl	%edx, %eax
	ret
.stricmp_len0:
	xorl	%eax, %eax
	ret
.stricmp_len1:
	xorl	%edx, %edx
	jmp	.stricmp_do_len1
.stricmp_len2:
	xorl	%edx, %edx
	jmp	.stricmp_do_len2
.stricmp_len3:
	xorl	%eax, %eax
	jmp	.stricmp_do_len3
.stricmp_len4:
	xorl	%eax, %eax
	jmp	.stricmp_do_len4
.stricmp_len5:
	xorl	%edx, %edx
	jmp	.stricmp_do_len5
.stricmp_len6:
	xorl	%edx, %edx
	jmp	.stricmp_do_len6
.stricmp_len8:
	movzbl	7(%rdi), %edx
	movzbl	7(%rsi), %eax
	movzbl	__tfw_lct(%rdx), %edx
	xorb	__tfw_lct(%rax), %dl
	movzbl	%dl, %eax
	jmp	.stricmp_do_len7

	/*
	 * Process strings shorter than 32 bytes in 2 phases:
	 * the first half of 16 bytes, if the length is more than 16,
	 * and 2nd half, the rest.
	 */
.stricmp_short:
	cmpq	$31, %rdx
	ja	.stricmp_try128
	cmpq	$15, %rdx
	jbe	.stricmp_short_2nd
	/*
	 * 1st half: we have no 256bit half loads in AVX2,
	 * so use 128bit ops here.
	 */
	vlddqu	(%rdi), %xmm2
	cmpq	$16, %rdx
	vlddqu	(%rsi), %xmm0
	vpxor	%xmm0, %xmm2, %xmm5
	vmovdqa	__CASE, %xmm1
	vpor	%xmm2, %xmm1, %xmm3
	vpcmpeqb %xmm1, %xmm5, %xmm0
	vmovdqa	__D, %xmm4
	vpand	%xmm0, %xmm1, %xmm0
	vpsubb	__a, %xmm3, %xmm3
	vpcmpgtb %xmm3, %xmm4, %xmm3
	vpxor	%xmm2, %xmm2, %xmm2
	vpand	%xmm3, %xmm0, %xmm0
	vpxor	%xmm5, %xmm0, %xmm0
	vpcmpeqb %xmm2, %xmm0, %xmm0
	vpmovmskb %xmm0, %eax
	je	.stricmp_short_nomatch
	cmpl	$0xffff, %eax
	jne	.stricmp_short_nomatch
	subq	$16, %rdx
	addq	%rdx, %rdi
	addq	%rdx, %rsi
	movl	$8, %edx
	jmp	.stricmp_do_short_2nd
.stricmp_short_2nd:
	vmovdqa	__CASE, %xmm1
	subq	$8, %rdx
	vmovdqa	__D, %xmm4
.stricmp_do_short_2nd:
	vmovsd	(%rsi,%rdx), %xmm3
	vmovsd	(%rdi,%rdx), %xmm2
	vmovhpd	(%rsi), %xmm3, %xmm0
	vmovhpd	(%rdi), %xmm2, %xmm2
	vpxor	%xmm0, %xmm2, %xmm3
	vpor	%xmm2, %xmm1, %xmm2
	vpcmpeqb %xmm1, %xmm3, %xmm0
	vpsubb	__a, %xmm2, %xmm2
	vpcmpgtb %xmm2, %xmm4, %xmm2
	vpand	%xmm0, %xmm1, %xmm0
	vpxor	%xmm1, %xmm1, %xmm1
	vpand	%xmm2, %xmm0, %xmm0
	vpxor	%xmm3, %xmm0, %xmm0
	vpcmpeqb %xmm1, %xmm0, %xmm0
	vpmovmskb %xmm0, %eax
.stricmp_short_nomatch:
	xorl	$0xffff, %eax
	vzeroupper
	ret

.stricmp_try128:
	vpxor	%xmm2, %xmm2, %xmm2
	xorl	%eax, %eax
.stricmp_128_loop:
	leal	128(%rax), %ecx
	movslq	%ecx, %r8
	cmpq	%r8, %rdx
	jnb	.stricmp_128
	leal	64(%rax), %ecx
	movslq	%ecx, %r8
	cmpq	%r8, %rdx
	jnb	.stricmp_64
.stricmp_try32:
	leal	32(%rax), %ecx
	movslq	%ecx, %r8
	cmpq	%r8, %rdx
	jnb	.stricmp_32

	/*
	 * Process string tail shorter than 32 bytes.
	 * If the tail is shorter than 8 bytes, revert the string pointer back
	 * to get 8 bytes for 1 vector iteration processing.
	 */
.stricmp_tail:
	movslq	%eax, %r8
	cmpq	%r8, %rdx
	je	.stricmp_match
	subq	%r8, %rdx
	vmovdqa	__D, %xmm3
	leal	-8(%rax,%rdx), %ecx
	cmpq	$7, %rdx
	movslq	%ecx, %rcx
	cmova	%r8, %rcx
	vmovsd	-8(%rdi,%rcx), %xmm1
	vmovsd	-8(%rsi,%rcx), %xmm0
	vmovhpd	(%rdi,%rcx), %xmm1, %xmm1
	vmovhpd	(%rsi,%rcx), %xmm0, %xmm0
	vpxor	%xmm0, %xmm1, %xmm2
	vmovdqa	__CASE, %xmm0
	vpor	%xmm1, %xmm0, %xmm1
	vpsubb	__a, %xmm1, %xmm1
	vpcmpgtb %xmm1, %xmm3, %xmm1
	vpcmpeqb %xmm0, %xmm2, %xmm3
	vpand	%xmm3, %xmm0, %xmm0
	vpand	%xmm1, %xmm0, %xmm0
	vpxor	%xmm1, %xmm1, %xmm1
	vpxor	%xmm2, %xmm0, %xmm0
	vpcmpeqb %xmm1, %xmm0, %xmm0
	vpmovmskb %xmm0, %eax
	xorl	$0xffff, %eax
	vzeroupper
	ret

.stricmp_match:
	xorl	%eax, %eax
	ret

.stricmp_128:
	leaq	(%rsi,%rax), %r8
	addq	%rdi, %rax
	vmovdqa	__a, %ymm6
	vlddqu	96(%rax), %ymm5
	vlddqu	96(%r8), %ymm0
	vlddqu	(%rax), %ymm11
	vpxor	%ymm0, %ymm5, %ymm4
	vlddqu	(%r8), %ymm1
	vmovdqa	__CASE, %ymm0
	vpxor	%ymm1, %ymm11, %ymm12
	vmovdqa	__D, %ymm3
	vpor	%ymm11, %ymm0, %ymm11
	vlddqu	32(%rax), %ymm10
	vlddqu	32(%r8), %ymm9
	vpor	%ymm5, %ymm0, %ymm5
	vlddqu	64(%rax), %ymm8
	movslq	%ecx, %rax
	vpsubb	%ymm6, %ymm11, %ymm1
	vpcmpgtb %ymm1, %ymm3, %ymm11
	vpxor	%ymm9, %ymm10, %ymm9
	vpor	%ymm10, %ymm0, %ymm10
	vlddqu	64(%r8), %ymm7
	vpcmpeqb %ymm0, %ymm12, %ymm1
	vpxor	%ymm7, %ymm8, %ymm7
	vpor	%ymm8, %ymm0, %ymm8
	vpand	%ymm1, %ymm0, %ymm1
	vpand	%ymm11, %ymm1, %ymm1
	vpxor	%ymm12, %ymm1, %ymm1
	vpcmpeqb %ymm2, %ymm1, %ymm1
	vpmovmskb %ymm1, %r9d
	vpsubb	%ymm6, %ymm10, %ymm1
	vpcmpgtb %ymm1, %ymm3, %ymm10
	movl	%r9d, %ecx
	vpcmpeqb %ymm9, %ymm0, %ymm1
	vpand	%ymm1, %ymm0, %ymm1
	vpand	%ymm10, %ymm1, %ymm1
	vpxor	%ymm9, %ymm1, %ymm1
	vpcmpeqb %ymm2, %ymm1, %ymm1
	vpmovmskb %ymm1, %r11d
	vpsubb	%ymm6, %ymm8, %ymm1
	vpsubb	%ymm6, %ymm5, %ymm6
	vpcmpgtb %ymm1, %ymm3, %ymm8
	andl	%r11d, %ecx
	vpcmpeqb %ymm7, %ymm0, %ymm1
	vpcmpgtb %ymm6, %ymm3, %ymm3
	vpand	%ymm1, %ymm0, %ymm1
	vpand	%ymm8, %ymm1, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpcmpeqb %ymm2, %ymm1, %ymm1
	vpmovmskb %ymm1, %r10d
	vpcmpeqb %ymm4, %ymm0, %ymm1
	andl	%r10d, %ecx
	vpand	%ymm1, %ymm0, %ymm0
	vpand	%ymm3, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpcmpeqb %ymm2, %ymm0, %ymm0
	vpmovmskb %ymm0, %r8d
	andl	%ecx, %r8d
	cmpl	$~0, %r8d
	je	.stricmp_128_loop

.stricmp_nomatch:
	movl	$1, %eax
	vzeroupper
	ret

.stricmp_64:
	leaq	(%rsi,%rax), %r8
	addq	%rdi, %rax
	vmovdqa	__a, %ymm7
	vlddqu	32(%rax), %ymm3
	vlddqu	32(%r8), %ymm0
	vlddqu	(%rax), %ymm1
	vpxor	%ymm0, %ymm3, %ymm4
	vlddqu	(%r8), %ymm6
	vmovdqa	__CASE, %ymm0
	vpxor	%ymm6, %ymm1, %ymm6
	vmovdqa	__D, %ymm5
	vpor	%ymm1, %ymm0, %ymm1
	vpsubb	%ymm7, %ymm1, %ymm1
	vpcmpgtb %ymm1, %ymm5, %ymm2
	vpcmpeqb %ymm0, %ymm6, %ymm1
	vpand	%ymm1, %ymm0, %ymm1
	vpand	%ymm2, %ymm1, %ymm1
	vpxor	%xmm2, %xmm2, %xmm2
	vpxor	%ymm6, %ymm1, %ymm1
	vpcmpeqb %ymm2, %ymm1, %ymm1
	vpmovmskb %ymm1, %r8d
	vpor	%ymm3, %ymm0, %ymm1
	vpcmpeqb %ymm4, %ymm0, %ymm3
	vpsubb	%ymm7, %ymm1, %ymm1
	vpcmpgtb %ymm1, %ymm5, %ymm1
	vpand	%ymm3, %ymm0, %ymm0
	vpand	%ymm1, %ymm0, %ymm0
	vpxor	%ymm4, %ymm0, %ymm0
	vpcmpeqb %ymm2, %ymm0, %ymm0
	vpmovmskb %ymm0, %eax
	andl	%r8d, %eax
	cmpl	$~0, %eax
	jne	.stricmp_nomatch
	movslq	%ecx, %rax
	jmp	.stricmp_try32

.stricmp_32:
	vlddqu	(%rdi,%rax), %ymm1
	vlddqu	(%rsi,%rax), %ymm0
	vmovdqa	__D, %ymm3
	vpxor	%ymm0, %ymm1, %ymm2
	vmovdqa	__CASE, %ymm0
	vpor	%ymm1, %ymm0, %ymm1
	vpsubb	__a, %ymm1, %ymm1
	vpcmpgtb %ymm1, %ymm3, %ymm1
	vpcmpeqb %ymm0, %ymm2, %ymm3
	vpand	%ymm3, %ymm0, %ymm0
	vpand	%ymm1, %ymm0, %ymm0
	vpxor	%xmm1, %xmm1, %xmm1
	vpxor	%ymm2, %ymm0, %ymm0
	vpcmpeqb %ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %eax
	cmpl	$~0, %eax
	jne	.stricmp_nomatch
	movl	%ecx, %eax
	jmp	.stricmp_tail

ENDPROC(__tfw_stricmp_avx2)

/**
 * Case insensitive comprison of the strings %RDI and %RSI of length %RDX.
 * This function converts ONLY the first string to lower case, so the second
 * is expected to be in lower case.
 * Return 0 if strings match and non-zero otherwise.
 * The implementation is very close to __tfw_stricmp_avx2() above, see also
 * the benchmark mentioned above for C implementation.
 */
ENTRY(__tfw_stricmp_avx2_2lc)
	cmpq	$8, %rdx
	ja	.sic2lc_short

	movq	.sic2lc_switch(,%rdx,8), %rax
	jmpq	*%rax
.section	.rodata
.align 8
.sic2lc_switch:
	.quad	.sic2lc_len0
	.quad	.sic2lc_len1
	.quad	.sic2lc_len2
	.quad	.sic2lc_len3
	.quad	.sic2lc_len4
	.quad	.sic2lc_len5
	.quad	.sic2lc_len6
	.quad	.sic2lc_len7
	.quad	.sic2lc_len8
.text
.sic2lc_len7:
	xorl	%eax, %eax
.sic2lc_do_len7:
	movzbl	6(%rdi), %edx
	movzbl	__tfw_lct(%rdx), %edx
	movl	%edx, %ecx
	xorb	6(%rsi), %cl
	movzbl	%cl, %edx
	orl	%eax, %edx
.sic2lc_do_len6:
	movzbl	5(%rdi), %eax
	movzbl	__tfw_lct(%rax), %ecx
	xorb	5(%rsi), %cl
	movzbl	%cl, %eax
	orl	%eax, %edx
.sic2lc_do_len5:
	movzbl	4(%rdi), %eax
	movzbl	__tfw_lct(%rax), %eax
	xorb	4(%rsi), %al
	movzbl	%al, %eax
	orl	%edx, %eax
.sic2lc_do_len4:
	movzbl	3(%rdi), %edx
	movzbl	__tfw_lct(%rdx), %ecx
	xorb	3(%rsi), %cl
	movzbl	%cl, %edx
	orl	%edx, %eax
.sic2lc_do_len3:
	movzbl	2(%rdi), %edx
	movzbl	__tfw_lct(%rdx), %edx
	movl	%edx, %ecx
	xorb	2(%rsi), %cl
	movzbl	%cl, %edx
	orl	%eax, %edx
.sic2lc_do_len2:
	movzbl	1(%rdi), %eax
	movzbl	__tfw_lct(%rax), %ecx
	xorb	1(%rsi), %cl
	movzbl	%cl, %eax
	orl	%eax, %edx
.sic2lc_do_len1:
	movzbl	(%rdi), %eax
	movzbl	__tfw_lct(%rax), %eax
	xorb	(%rsi), %al
	movzbl	%al, %eax
	orl	%edx, %eax
	ret
.sic2lc_len0:
	xorl	%eax, %eax
	ret
.sic2lc_len1:
	xorl	%edx, %edx
	jmp	.sic2lc_do_len1
.sic2lc_len2:
	xorl	%edx, %edx
	jmp	.sic2lc_do_len2
.sic2lc_len3:
	xorl	%eax, %eax
	jmp	.sic2lc_do_len3
.sic2lc_len4:
	xorl	%eax, %eax
	jmp	.sic2lc_do_len4
.sic2lc_len5:
	xorl	%edx, %edx
	jmp	.sic2lc_do_len5
.sic2lc_len6:
	xorl	%edx, %edx
	jmp	.sic2lc_do_len6
.sic2lc_len8:
	movzbl	7(%rdi), %eax
	movzbl	__tfw_lct(%rax), %edx
	xorb	7(%rsi), %dl
	movzbl	%dl, %eax
	jmp	.sic2lc_do_len7

.sic2lc_short:
	cmpq	$31, %rdx
	ja	.sic2lc_try128
	cmpq	$15, %rdx
	jbe	.sic2lc_short_2nd
	vlddqu	(%rdi), %xmm0
	cmpq	$16, %rdx
	vmovdqa	__D, %xmm3
	vpsubb	__C(%rip), %xmm0, %xmm2
	vpcmpgtb %xmm2, %xmm3, %xmm2
	vlddqu	(%rsi), %xmm1
	vpand	__CASE, %xmm2, %xmm2
	vpor	%xmm0, %xmm2, %xmm2
	vpcmpeqb %xmm2, %xmm1, %xmm1
	vpmovmskb %xmm1, %eax
	je	.sic2lc_short_nomatch
	cmpl	$0xffff, %eax
	jne	.sic2lc_short_nomatch
	subq	$16, %rdx
	addq	%rdx, %rdi
	addq	%rdx, %rsi
	movl	$8, %edx
	jmp	.sic2lc_do_short_2nd
.sic2lc_short_2nd:
	vmovdqa	__D, %xmm3
	subq	$8, %rdx
.sic2lc_do_short_2nd:
	vmovsd	(%rdi,%rdx), %xmm1
	vmovsd	(%rsi,%rdx), %xmm2
	vmovhpd	(%rdi), %xmm1, %xmm1
	vmovhpd	(%rsi), %xmm2, %xmm2
	vpsubb	__C(%rip), %xmm1, %xmm0
	vpcmpgtb %xmm0, %xmm3, %xmm0
	vpand	__CASE, %xmm0, %xmm0
	vpor	%xmm1, %xmm0, %xmm0
	vpcmpeqb %xmm2, %xmm0, %xmm0
	vpmovmskb %xmm0, %eax
.sic2lc_short_nomatch:
	xorl	$0xffff, %eax
	vzeroupper
	ret

.sic2lc_try128:
	xorl	%eax, %eax
.sic2lc_128_loop:
	leal	128(%rax), %ecx
	movslq	%ecx, %r8
	cmpq	%r8, %rdx
	jnb	.sic2lc_128
	leal	64(%rax), %ecx
	movslq	%ecx, %r8
	cmpq	%r8, %rdx
	jnb	.sic2lc_64
.sic2lc_try32:
	leal	32(%rax), %ecx
	movslq	%ecx, %r8
	cmpq	%r8, %rdx
	jnb	.sic2lc_32

.sic2lc_tail:
	movslq	%eax, %r8
	cmpq	%r8, %rdx
	je	.sic2lc_match
	movq	%rdx, %rcx
	subq	%r8, %rcx
	cmpq	$7, %rcx
	ja	.sic2lc_tail_big
	leal	-8(%rax,%rcx), %edx
	vmovdqa	__D, %xmm3
	xorl	%ecx, %ecx
	movslq	%edx, %rdx
	leaq	(%rsi,%rdx), %rax
	addq	%rdi, %rdx
.sic2lc_do_tail_small:
	vmovsd	(%rdx,%rcx), %xmm0
	vmovsd	(%rax,%rcx), %xmm2
	vmovhpd	(%rdx), %xmm0, %xmm1
	vmovhpd	(%rax), %xmm2, %xmm2
	vpsubb	__C(%rip), %xmm1, %xmm0
	vpcmpgtb %xmm0, %xmm3, %xmm0
	vpand	__CASE, %xmm0, %xmm0
	vpor	%xmm1, %xmm0, %xmm0
	vpcmpeqb %xmm2, %xmm0, %xmm0
	vpmovmskb %xmm0, %eax
.sic2lc_tail_maybe_match:
	xorl	$0xffff, %eax
	vzeroupper
	ret
.sic2lc_tail_big:
	addq	%r8, %rsi
	cmpq	$15, %rcx
	leaq	(%rdi,%r8), %rdx
	jbe	.sic2lc_tail_small
	vlddqu	(%rdx), %xmm2
	cmpq	$16, %rcx
	vmovdqa	__D, %xmm3
	vpsubb	__C(%rip), %xmm2, %xmm0
	vpcmpgtb %xmm0, %xmm3, %xmm0
	vlddqu	(%rsi), %xmm1
	vpand	__CASE, %xmm0, %xmm0
	vpor	%xmm2, %xmm0, %xmm0
	vpcmpeqb %xmm0, %xmm1, %xmm1
	vpmovmskb %xmm1, %eax
	je	.sic2lc_tail_maybe_match
	cmpl	$0xffff, %eax
	jne	.sic2lc_tail_maybe_match
	leaq	-16(%rcx), %rax
	movl	$8, %ecx
	addq	%rax, %rdx
	addq	%rsi, %rax
	jmp	.sic2lc_do_tail_small
.sic2lc_tail_small:
	subq	$8, %rcx
	movq	%rsi, %rax
	vmovdqa	__D, %xmm3
	jmp	.sic2lc_do_tail_small

.sic2lc_match:
	xorl	%eax, %eax
	vzeroupper
	ret

.sic2lc_128:
	leaq	(%rsi,%rax), %r8
	addq	%rdi, %rax
	vmovdqa	__A, %ymm3
	vmovdqa	__D, %ymm2
	vlddqu	(%rax), %ymm11
	vmovdqa	__CASE, %ymm1
	vpsubb	%ymm3, %ymm11, %ymm8
	vpcmpgtb %ymm8, %ymm2, %ymm8
	vlddqu	(%r8), %ymm0
	vlddqu	32(%rax), %ymm10
	vlddqu	32(%r8), %ymm9
	vpand	%ymm8, %ymm1, %ymm8
	vlddqu	64(%r8), %ymm6
	vlddqu	96(%r8), %ymm4
	vlddqu	64(%rax), %ymm7
	vpor	%ymm11, %ymm8, %ymm8
	vlddqu	96(%rax), %ymm5
	movslq	%ecx, %rax
	vpcmpeqb %ymm8, %ymm0, %ymm0
	vpmovmskb %ymm0, %r8d
	vpsubb	%ymm3, %ymm10, %ymm0
	vpcmpgtb %ymm0, %ymm2, %ymm0
	movl	%r8d, %ecx
	vpand	%ymm0, %ymm1, %ymm0
	vpor	%ymm10, %ymm0, %ymm0
	vpcmpeqb %ymm0, %ymm9, %ymm0
	vpmovmskb %ymm0, %r11d
	vpsubb	%ymm3, %ymm7, %ymm0
	vpcmpgtb %ymm0, %ymm2, %ymm0
	andl	%r11d, %ecx
	vpand	%ymm0, %ymm1, %ymm0
	vpor	%ymm7, %ymm0, %ymm0
	vpcmpeqb %ymm0, %ymm6, %ymm0
	vpmovmskb %ymm0, %r10d
	vpsubb	%ymm3, %ymm5, %ymm0
	vpcmpgtb %ymm0, %ymm2, %ymm0
	andl	%r10d, %ecx
	vpand	%ymm0, %ymm1, %ymm0
	vpor	%ymm5, %ymm0, %ymm0
	vpcmpeqb %ymm0, %ymm4, %ymm0
	vpmovmskb %ymm0, %r9d
	andl	%r9d, %ecx
	cmpl	$~0, %ecx
	je	.sic2lc_128_loop

.sic2lc_nomatch:
	movl	$1, %eax
	vzeroupper
	ret

.sic2lc_64:
	leaq	(%rsi,%rax), %r8
	addq	%rdi, %rax
	vmovdqa	__A, %ymm5
	vlddqu	(%rax), %ymm7
	vmovdqa	__D, %ymm4
	vpsubb	%ymm5, %ymm7, %ymm1
	vmovdqa	__CASE, %ymm2
	vpcmpgtb %ymm1, %ymm4, %ymm1
	vlddqu	(%r8), %ymm0
	vlddqu	32(%rax), %ymm6
	vlddqu	32(%r8), %ymm3
	vpand	%ymm1, %ymm2, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpcmpeqb %ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %eax
	vpsubb	%ymm5, %ymm6, %ymm0
	vpcmpgtb %ymm0, %ymm4, %ymm0
	vpand	%ymm0, %ymm2, %ymm0
	vpor	%ymm6, %ymm0, %ymm0
	vpcmpeqb %ymm0, %ymm3, %ymm0
	vpmovmskb %ymm0, %r8d
	andl	%r8d, %eax
	cmpl	$~0, %eax
	jne	.sic2lc_nomatch
	movslq	%ecx, %rax
	jmp	.sic2lc_try32

.sic2lc_32:
	vlddqu	(%rdi,%rax), %ymm2
	vmovdqa	__D, %ymm0
	vpsubb	__A, %ymm2, %ymm3
	vlddqu	(%rsi,%rax), %ymm1
	vpcmpgtb %ymm3, %ymm0, %ymm0
	vpand	__CASE, %ymm0, %ymm0
	vpor	%ymm2, %ymm0, %ymm0
	vpcmpeqb %ymm0, %ymm1, %ymm0
	vpmovmskb %ymm0, %eax
	cmpl	$~0, %eax
	jne	.sic2lc_nomatch
	movl	%ecx, %eax
	jmp	.sic2lc_tail

ENDPROC(__tfw_stricmp_avx2_2lc)

/**
 * Match input string %RDI with legth %RSI against custom allowed alphabet
 * encoded in bytes (%RDX) and 2 vectors (%RCX & %R8) and return number of
 * matched characters.
 * See the benchmark mentioned above for C implementation.
 * This implementation differs only in matching 2nd half of ASCII table.
 */
ENTRY(__tfw_match_custom)
	cmpq	$4, %rsi
	vlddqu	(%rcx), %xmm15
	vlddqu	(%r8), %xmm12
	vlddqu	(%rcx), %ymm0
	vlddqu	(%r8), %ymm1
	ja	.mcust_long_str

	/*
	 * Avoid heavyweight vector processing for small strings.
	 * Branch misprediction is more crucial for short strings,
	 * so the code goes first.
	 */
	cmpq	$2, %rsi
	je	.mcust_len2
	jbe	.mcust_len_1_or_0
	cmpq	$3, %rsi
	je	.mcust_len_3
	cmpq	$4, %rsi
	jne	.mcust_len_0
	movzbl	3(%rdi), %eax
	movzbl	(%rdx,%rax), %r8d
.mcust_cmp_long_len:
	movzbl	2(%rdi), %eax
	movzbl	(%rdx,%rax), %ecx
.mcust_cmp_short_len:
	movzbl	(%rdi), %eax
	movzbl	1(%rdi), %esi
	movzbl	(%rdx,%rax), %eax
	testb	%al, (%rdx,%rsi)
	je	.mcust_small_len_done
	leal	2(%rcx,%r8), %eax
	testl	%ecx, %ecx
	movl	$2, %ecx
	cmove	%rcx, %rax
.mcust_small_len_done:
	ret
.mcust_len_1_or_0:
	cmpq	$1, %rsi
	jne	.mcust_len_0
	movzbl	(%rdi), %eax
	movzbl	(%rdx,%rax), %eax
	ret
.mcust_len_0:
	xorl	%eax, %eax
	ret
.mcust_len_3:
	xorl	%r8d, %r8d
	jmp	.mcust_cmp_long_len
.mcust_len2:
	xorl	%r8d, %r8d
	xorl	%ecx, %ecx
	jmp	.mcust_cmp_short_len

	/*
	 * The main matching part split into 128, 64, 32, 16 and the tail
	 * processing blocks.
	 */
.mcust_long_str:
	leaq	8(%rsp), %r10
	andq	$-32, %rsp
	addq	%rdi, %rsi
	vpxor	%xmm6, %xmm6, %xmm6
	movq	%rdi, %rax
	pushq	-8(%r10)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r10
	pushq	%rbx
	subq	$64, %rsp
	vmovaps	%xmm12, -32(%rbp)
	vmovaps	%xmm15, -48(%rbp)
.mcust_try_len128:
	leaq	128(%rax), %r10
	cmpq	%r10, %rsi
	jnb	.mcust_128
	leaq	64(%rax), %rcx
	vmovdqa	-32(%rbp), %xmm12
	cmpq	%rcx, %rsi
	vmovdqa	-48(%rbp), %xmm15
	jnb	.mcust_64
.mcust_try_len32:
	leaq	32(%rax), %r8
	cmpq	%r8, %rsi
	jnb	.mcust_32
.mcust_try_len16:
	vpxor	%xmm4, %xmm4, %xmm4
	leaq	16(%rax), %r8
	cmpq	%r8, %rsi
	jb	.mcust_tail
	jmp	.mcust_16

	/* Vector processing blocks. */
.mcust_128:
	vlddqu	32(%rax), %ymm4
	vmovdqa	__ASCII, %ymm5
	vlddqu	(%rax), %ymm3
	vpshufb	%ymm4, %ymm0, %ymm8
	vpxor	%ymm4, %ymm5, %ymm14
	vmovdqa	__LSH, %ymm10
	vpsrlw	$4, %ymm4, %ymm4
	vpxor	%ymm3, %ymm5, %ymm9
	vlddqu	64(%rax), %ymm2
	vpand	%ymm4, %ymm10, %ymm4
	vlddqu	96(%rax), %ymm11
	vpshufb	%ymm14, %ymm1, %ymm14
	vpshufb	%ymm9, %ymm1, %ymm15
	vmovdqa	__ARF, %ymm9
	vpshufb	%ymm3, %ymm0, %ymm7
	vpsrlw	$4, %ymm3, %ymm3
	vpshufb	%ymm4, %ymm9, %ymm4
	vpor	%ymm14, %ymm8, %ymm8
	vpxor	%ymm2, %ymm5, %ymm13
	vmovdqa	%ymm7, -80(%rbp)
	vpxor	%ymm11, %ymm5, %ymm5
	vpand	%ymm4, %ymm8, %ymm4
	vpshufb	%ymm2, %ymm0, %ymm12
	vpsrlw	$4, %ymm2, %ymm2
	vpshufb	%ymm11, %ymm0, %ymm7
	vpsrlw	$4, %ymm11, %ymm11
	vpcmpeqb %ymm6, %ymm4, %ymm4
	vpshufb	%ymm5, %ymm1, %ymm5
	vpand	%ymm3, %ymm10, %ymm3
	vpand	%ymm2, %ymm10, %ymm2
	vpand	%ymm11, %ymm10, %ymm10
	vpmovmskb %ymm4, %ecx
	vpor	%ymm5, %ymm7, %ymm4
	vpshufb	%ymm13, %ymm1, %ymm13
	salq	$32, %rcx
	vpshufb	%ymm10, %ymm9, %ymm10
	vpshufb	%ymm3, %ymm9, %ymm3
	vpshufb	%ymm2, %ymm9, %ymm2
	vpand	%ymm10, %ymm4, %ymm10
	vpor	%ymm13, %ymm12, %ymm13
	vpcmpeqb %ymm6, %ymm10, %ymm4
	vpand	%ymm2, %ymm13, %ymm2
	vpmovmskb %ymm4, %r9d
	vpor	-80(%rbp), %ymm15, %ymm4
	vpcmpeqb %ymm6, %ymm2, %ymm2
	salq	$32, %r9
	vpmovmskb %ymm2, %r11d
	vpand	%ymm3, %ymm4, %ymm3
	vpcmpeqb %ymm6, %ymm3, %ymm3
	vpmovmskb %ymm3, %r8d
	movslq	%r8d, %r8
	orq	%r8, %rcx
	tzcnt	%rcx, %rcx
	movslq	%r11d, %r8
	orq	%r9, %r8
	tzcnt	%r8, %r8
	cmpq	$63, %rcx
	jbe	.mcust_got_mismatch
	leaq	64(%r8), %rcx
	cmpq	$127, %rcx
	jbe	.mcust_got_mismatch
	movq	%r10, %rax
	jmp	.mcust_try_len128

.mcust_64:
	vlddqu	(%rax), %ymm4
	vlddqu	32(%rax), %ymm6
	vmovdqa	__ASCII, %ymm5
	vpshufb	%ymm4, %ymm0, %ymm3
	vmovdqa	__LSH, %ymm9
	vpshufb	%ymm6, %ymm0, %ymm2
	vpxor	%ymm4, %ymm5, %ymm8
	vpsrlw	$4, %ymm4, %ymm4
	vmovdqa	__ARF, %ymm7
	vpxor	%ymm6, %ymm5, %ymm5
	vpsrlw	$4, %ymm6, %ymm6
	vpand	%ymm4, %ymm9, %ymm4
	vpshufb	%ymm8, %ymm1, %ymm8
	vpshufb	%ymm5, %ymm1, %ymm5
	vpand	%ymm6, %ymm9, %ymm6
	vpshufb	%ymm4, %ymm7, %ymm4
	vpor	%ymm8, %ymm3, %ymm3
	vpshufb	%ymm6, %ymm7, %ymm7
	vpor	%ymm5, %ymm2, %ymm2
	vpand	%ymm4, %ymm3, %ymm3
	vpxor	%xmm4, %xmm4, %xmm4
	vpand	%ymm7, %ymm2, %ymm2
	vpcmpeqb %ymm4, %ymm3, %ymm3
	vpcmpeqb %ymm4, %ymm2, %ymm2
	vpmovmskb %ymm3, %r9d
	vpmovmskb %ymm2, %r8d
	movslq	%r9d, %r9
	salq	$32, %r8
	xorq	%r9, %r8
	tzcnt	%r8, %r8
	subq	%rdi, %rax
	addq	%r8, %rax
	cmpq	$63, %r8
	jbe	.mcust_end
	movq	%rcx, %rax
	jmp	.mcust_try_len32

.mcust_32:
	vlddqu	(%rax), %ymm2
	vpxor	__ASCII, %ymm2, %ymm3
	vpshufb	%ymm2, %ymm0, %ymm0
	vpsrlw	$4, %ymm2, %ymm2
	vpand	__LSH, %ymm2, %ymm2
	vpshufb	%ymm3, %ymm1, %ymm1
	vmovdqa	__ARF, %ymm3
	vpor	%ymm1, %ymm0, %ymm0
	vpshufb	%ymm2, %ymm3, %ymm2
	vpxor	%xmm1, %xmm1, %xmm1
	vpand	%ymm2, %ymm0, %ymm0
	vpcmpeqb %ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %ecx
	tzcnt	%ecx, %ecx
	movl	%ecx, %ecx
	cmpq	$31, %rcx
	jbe	.mcust_got_mismatch
	movq	%r8, %rax
	jmp	.mcust_try_len16

.mcust_16:
	vlddqu	(%rax), %xmm1
	vpxor	__ASCII, %xmm1, %xmm3
	vmovdqa	__ARF, %xmm2
	vpshufb	%xmm1, %xmm15, %xmm0
	vpsrlw	$4, %xmm1, %xmm1
	vpand	__LSH, %xmm1, %xmm1
	vpshufb	%xmm3, %xmm12, %xmm3
	vpshufb	%xmm1, %xmm2, %xmm1
	vpor	%xmm3, %xmm0, %xmm0
	vpand	%xmm1, %xmm0, %xmm0
	vpcmpeqb %xmm4, %xmm0, %xmm0
	vpmovmskb %xmm0, %ecx
	movslq	%ecx, %rcx
	orq	$0xffffffffffff0000, %rcx
	tzcnt	%rcx, %rcx
	cmpq	$15, %rcx
	jbe	.mcust_got_mismatch
	movq	%r8, %rax
	jmp	.mcust_tail

.mcust_got_mismatch:
	subq	%rdi, %rax
	addq	%rcx, %rax
	jmp	.mcust_end

	/* The tail loops processes string lengths in range [4, 15]. */
.mcust_tail_loop:
	movzbl	-4(%r8), %ecx
	movzbl	-3(%r8), %r11d
	movzbl	-2(%r8), %r9d
	movzbl	-1(%r8), %r10d
	movzbl	(%rdx,%rcx), %ecx
	movzbl	(%rdx,%r9), %r9d
	movzbl	(%rdx,%r10), %r10d
	movl	%ecx, %ebx
	andb	(%rdx,%r11), %bl
	movl	%ebx, %r11d
	movl	%r9d, %ebx
	andl	%r10d, %ebx
	testb	%r11b, %bl
	je	.mcust_got_mismatch_tail
	movq	%r8, %rax
.mcust_tail:
	leaq	4(%rax), %r8
	cmpq	%r8, %rsi
	jnb	.mcust_tail_loop
	subq	%rax, %rsi
	cmpq	$2, %rsi
	je	.mcust_2
	cmpq	$3, %rsi
	je	.mcust_3
	cmpq	$1, %rsi
	je	.mcust_1
	subq	%rdi, %rax
	movq	%rax, %rdi
	xorl	%eax, %eax
.mcust_add_len_end:
	addq	%rdi, %rax
.mcust_end:
	vzeroupper
	addq	$64, %rsp
	popq	%rbx
	popq	%r10
	popq	%rbp
	leaq	-8(%r10), %rsp
	ret
.mcust_got_mismatch_tail:
	subq	%rdi, %rax
	testb	%r11b, %r11b
	je	.mcust_mismatch_tail_1
	addl	%r9d, %r10d
	testl	%r9d, %r9d
	cmovne	%r10d, %r9d
	movl	%r9d, %r9d
	leaq	2(%rax,%r9), %rax
	jmp	.mcust_end
.mcust_mismatch_tail_1:
	addq	%rcx, %rax
	jmp	.mcust_end
.mcust_1:
	movzbl	(%rax), %ecx
	subq	%rdi, %rax
	movq	%rax, %rdi
	movzbl	(%rdx,%rcx), %esi
.mcust_add_tail_len:
	movl	%esi, %eax
	jmp	.mcust_add_len_end
.mcust_2:
	xorl	%ecx, %ecx
.do_mcust_2:
	movzbl	(%rax), %esi
	movq	%rax, %rbx
	movzbl	1(%rax), %eax
	subq	%rdi, %rbx
	movq	%rbx, %rdi
	movzbl	(%rdx,%rsi), %esi
	testb	%sil, (%rdx,%rax)
	je	.mcust_add_tail_len
	movl	%ecx, %edx
	leaq	2(%rbx,%rdx), %rax
	jmp	.mcust_end
.mcust_3:
	movzbl	2(%rax), %ecx
	movzbl	(%rdx,%rcx), %ecx
	jmp	.do_mcust_2

ENDPROC(__tfw_match_custom)

/**
 * strspn(3)-like routine to match input string %RDI of length %RSI against
 * particular static alphabet encoded as byte array %RDX or vector %RCX.
 * See strspn.c C implementation in the benchmark.
 */
ENTRY(__tfw_strspn_simd)
	/* Process strings of length not more than 4 bytes separately. */
	cmpq	$4, %rsi
	vlddqu	(%rcx), %xmm1
	vlddqu	(%rcx), %ymm0
	ja	.strspn_long_str
	cmpq	$2, %rsi
	je	.strspn_len_2
	jbe	.strspn_len_1or0
	cmpq	$3, %rsi
	je	.strspn_len_3
	cmpq	$4, %rsi
	jne	.strspn_len_0
	movzbl	3(%rdi), %eax
	movzbl	(%rdx,%rax), %r8d
.strspn_do_len_3:
	movzbl	2(%rdi), %eax
	movzbl	(%rdx,%rax), %ecx
.strspn_do_len_2:
	movzbl	(%rdi), %eax
	movzbl	1(%rdi), %esi
	movzbl	(%rdx,%rax), %eax
	testb	%al, (%rdx,%rsi)
	je	.strspn_small_len_done
	leal	2(%rcx,%r8), %eax
	testl	%ecx, %ecx
	movl	$2, %ecx
	cmove	%rcx, %rax
.strspn_small_len_done:
	ret
.strspn_len_1or0:
	cmpq	$1, %rsi
	jne	.strspn_len_0
	movzbl	(%rdi), %eax
	movzbl	(%rdx,%rax), %eax
	ret
.strspn_len_0:
	xorl	%eax, %eax
	ret
.strspn_len_3:
	xorl	%r8d, %r8d
	jmp	.strspn_do_len_3
.strspn_len_2:
	xorl	%r8d, %r8d
	xorl	%ecx, %ecx
	jmp	.strspn_do_len_2

	/*
	 * The main matching part split into 128, 64, 32, 16 and the tail
	 * processing blocks.
	 */
.strspn_long_str:
	leaq	8(%rsp), %r10
	andq	$-32, %rsp
	addq	%rdi, %rsi
	vpxor	%xmm5, %xmm5, %xmm5
	movq	%rdi, %rax
	pushq	-8(%r10)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r10
	pushq	%rbx
.strspn_try_len128:
	leaq	128(%rax), %r9
	cmpq	%r9, %rsi
	jnb	.strspn_128
	leaq	64(%rax), %rcx
	cmpq	%rcx, %rsi
	jnb	.strspn_64
.strspn_try_len32:
	leaq	32(%rax), %rcx
	cmpq	%rcx, %rsi
	jnb	.strspn_32
.strspn_try_len16_cleanup:
	vpxor	%xmm2, %xmm2, %xmm2
.strspn_try_len16:
	leaq	16(%rax), %rcx
	cmpq	%rcx, %rsi
	jb	.strspn_tail
	jmp	.strspn_16

.strspn_128:
	vmovdqa	__LSH, %ymm6
	vlddqu	(%rax), %ymm2
	vlddqu	32(%rax), %ymm4
	vpshufb	%ymm2, %ymm0, %ymm9
	vpsrlw	$4, %ymm2, %ymm2
	vmovdqa	__ARF, %ymm3
	vpand	%ymm2, %ymm6, %ymm2
	vlddqu	64(%rax), %ymm8
	vlddqu	96(%rax), %ymm12
	vpshufb	%ymm4, %ymm0, %ymm11
	vpsrlw	$4, %ymm4, %ymm4
	vpand	%ymm4, %ymm6, %ymm4
	vpshufb	%ymm2, %ymm3, %ymm2
	vpshufb	%ymm8, %ymm0, %ymm7
	vpsrlw	$4, %ymm8, %ymm8
	vpshufb	%ymm12, %ymm0, %ymm10
	vpsrlw	$4, %ymm12, %ymm12
	vpand	%ymm8, %ymm6, %ymm8
	vpand	%ymm12, %ymm6, %ymm6
	vpshufb	%ymm4, %ymm3, %ymm4
	vpand	%ymm9, %ymm2, %ymm2
	vpshufb	%ymm8, %ymm3, %ymm8
	vpshufb	%ymm6, %ymm3, %ymm3
	vpand	%ymm11, %ymm4, %ymm4
	vpcmpeqb %ymm5, %ymm2, %ymm2
	vpand	%ymm10, %ymm3, %ymm3
	vpcmpeqb %ymm5, %ymm4, %ymm4
	vpmovmskb %ymm2, %r8d
	vpand	%ymm7, %ymm8, %ymm2
	vpcmpeqb %ymm5, %ymm3, %ymm3
	vpmovmskb %ymm4, %ecx
	vpcmpeqb %ymm5, %ymm2, %ymm2
	vpmovmskb %ymm3, %r10d
	movq	%rcx, %rbx
	movslq	%r8d, %rcx
	salq	$32, %rbx
	salq	$32, %r10
	vpmovmskb %ymm2, %r11d
	orq	%rbx, %rcx
	tzcnt	%rcx, %rcx
	movslq	%r11d, %r8
	orq	%r8, %r10
	tzcnt	%r10, %r10
	cmpq	$63, %rcx
	jbe	.strspn_mismatch_rcx
	leaq	64(%r10), %rcx
	cmpq	$127, %rcx
	jbe	.strspn_mismatch_rcx
	movq	%r9, %rax
	jmp	.strspn_try_len128

.strspn_64:
	vlddqu	(%rax), %ymm2
	vlddqu	32(%rax), %ymm5
	vmovdqa	__LSH, %ymm4
	vpsrlw	$4, %ymm2, %ymm3
	vpshufb	%ymm2, %ymm0, %ymm7
	vpshufb	%ymm5, %ymm0, %ymm6
	vpsrlw	$4, %ymm5, %ymm5
	vmovdqa	__ARF, %ymm2
	vpand	%ymm3, %ymm4, %ymm3
	vpand	%ymm5, %ymm4, %ymm4
	vpshufb	%ymm3, %ymm2, %ymm3
	vpshufb	%ymm4, %ymm2, %ymm2
	vpxor	%xmm4, %xmm4, %xmm4
	vpand	%ymm7, %ymm3, %ymm3
	vpand	%ymm6, %ymm2, %ymm2
	vpcmpeqb %ymm4, %ymm3, %ymm3
	vpcmpeqb %ymm4, %ymm2, %ymm2
	vpmovmskb %ymm3, %r9d
	vpmovmskb %ymm2, %r8d
	movslq	%r9d, %r9
	salq	$32, %r8
	xorq	%r9, %r8
	tzcnt	%r8, %r8
	cmpq	$63, %r8
	jbe	.strspn_mismatch_r8
	movq	%rcx, %rax
	jmp	.strspn_try_len32

.strspn_32:
	vlddqu	(%rax), %ymm2
	vpshufb	%ymm2, %ymm0, %ymm0
	vpsrlw	$4, %ymm2, %ymm2
	vpand	__LSH, %ymm2, %ymm3
	vmovdqa	__ARF, %ymm2
	vpshufb	%ymm3, %ymm2, %ymm2
	vpand	%ymm0, %ymm2, %ymm0
	vpxor	%xmm2, %xmm2, %xmm2
	vpcmpeqb %ymm2, %ymm0, %ymm0
	vpmovmskb %ymm0, %r8d
	tzcnt	%r8d, %r8d
	movl	%r8d, %r8d
	cmpq	$31, %r8
	jbe	.strspn_mismatch_r8
	movq	%rcx, %rax
	jmp	.strspn_try_len16_cleanup

.strspn_16:
	vlddqu	(%rax), %xmm0
	vpshufb	%xmm0, %xmm1, %xmm4
	vpsrlw	$4, %xmm0, %xmm0
	vpand	__LSH, %xmm0, %xmm3
	vmovdqa	__ARF, %xmm0
	vpshufb	%xmm3, %xmm0, %xmm0
	vpand	%xmm4, %xmm0, %xmm0
	vpcmpeqb %xmm2, %xmm0, %xmm0
	vpmovmskb %xmm0, %r8d
	movslq	%r8d, %r8
	orq	$0xffffffffffff0000, %r8
	tzcnt	%r8, %r8
	cmpq	$15, %r8
	jbe	.strspn_mismatch_r8
	movq	%rcx, %rax
	jmp	.strspn_tail

.strspn_mismatch_r8:
	subq	%rdi, %rax
	addq	%r8, %rax
	jmp	.strspn_end
.strspn_mismatch_rcx:
	subq	%rdi, %rax
	addq	%rcx, %rax
	jmp	.strspn_end

	/* The tail loops processes string lengths in range [4, 15]. */
.strspn_tail_loop:
	movzbl	-4(%r8), %ecx
	movzbl	-3(%r8), %r11d
	movzbl	-2(%r8), %r9d
	movzbl	-1(%r8), %r10d
	movzbl	(%rdx,%rcx), %ecx
	movzbl	(%rdx,%r9), %r9d
	movzbl	(%rdx,%r10), %r10d
	movl	%ecx, %ebx
	andb	(%rdx,%r11), %bl
	movl	%ebx, %r11d
	movl	%r9d, %ebx
	andl	%r10d, %ebx
	testb	%r11b, %bl
	je	.strspn_tail_loop_nomatch
	movq	%r8, %rax
.strspn_tail:
	leaq	4(%rax), %r8
	cmpq	%r8, %rsi
	jnb	.strspn_tail_loop
	subq	%rax, %rsi
	cmpq	$2, %rsi
	je	.strspn_tail_2
	cmpq	$3, %rsi
	je	.strspn_tail_3
	cmpq	$1, %rsi
	je	.strspn_tail_1
	subq	%rdi, %rax
	movq	%rax, %rdi
	xorl	%eax, %eax
.strspn_add_len:
	addq	%rdi, %rax
.strspn_end:
	vzeroupper
	popq	%rbx
	popq	%r10
	popq	%rbp
	leaq	-8(%r10), %rsp
	ret
.strspn_tail_loop_nomatch:
	subq	%rdi, %rax
	testb	%r11b, %r11b
	je	.strspn_tail_loop_nomatch_01
	addl	%r9d, %r10d
	testl	%r9d, %r9d
	cmovne	%r10d, %r9d
	movl	%r9d, %r9d
	leaq	2(%rax,%r9), %rax
	jmp	.strspn_end
.strspn_tail_loop_nomatch_01:
	addq	%rcx, %rax
	jmp	.strspn_end
.strspn_tail_1:
	movzbl	(%rax), %ecx
	subq	%rdi, %rax
	movq	%rax, %rdi
	movzbl	(%rdx,%rcx), %esi
.strspn_tail_done:
	movl	%esi, %eax
	jmp	.strspn_add_len
.strspn_tail_2:
	xorl	%ecx, %ecx
.strspn_do_tail_2:
	movzbl	(%rax), %esi
	movq	%rax, %rbx
	movzbl	1(%rax), %eax
	subq	%rdi, %rbx
	movq	%rbx, %rdi
	movzbl	(%rdx,%rsi), %esi
	testb	%sil, (%rdx,%rax)
	je	.strspn_tail_done
	movl	%ecx, %edx
	leaq	2(%rbx,%rdx), %rax
	jmp	.strspn_end
.strspn_tail_3:
	movzbl	2(%rax), %ecx
	movzbl	(%rdx,%rcx), %ecx
	jmp	.strspn_do_tail_2

END(__tfw_strspn_simd) /* for local sibling calls only */

/**
 * CTEXT | VCHAR handles both the halves of ASCII table, so we use
 * separate logic to match the characters set.
 * %RDI - the string pointer, %RSI - the string length.
 * See strspn.c C implementation in the benchmark.
 */
ENTRY(__tfw_match_ctext_vchar)
	/* Process strings of length not more than 4 bytes separately. */
	cmpq	$4, %rsi
	ja	.ctxt_vchr_long_str
	cmpq	$2, %rsi
	je	.ctxt_vchr_len_2
	jbe	.ctxt_vchr_len_10
	cmpq	$3, %rsi
	je	.ctxt_vchr_len_3
	cmpq	$4, %rsi
	jne	.ctxt_vchr_len_0
	movzbl	3(%rdi), %eax
	movzbl	ctext_vchar(%rax), %esi
.ctxt_vchr_do_len_3:
	movzbl	2(%rdi), %eax
	movzbl	ctext_vchar(%rax), %edx
.ctxt_vchr_do_len_2:
	movzbl	(%rdi), %eax
	movzbl	1(%rdi), %ecx
	movzbl	ctext_vchar(%rax), %eax
	testb	%al, ctext_vchar(%rcx)
	je	.ctxt_vchr_match1
	leal	2(%rdx,%rsi), %eax
	testl	%edx, %edx
	movl	$2, %edx
	cmove	%rdx, %rax
	ret
.ctxt_vchr_len_10:
	cmpq	$1, %rsi
	jne	.ctxt_vchr_len_0
	movzbl	(%rdi), %eax
	movzbl	ctext_vchar(%rax), %eax
	ret
.ctxt_vchr_len_0:
	xorl	%eax, %eax
	ret
.ctxt_vchr_match1:
	rep ret
.ctxt_vchr_len_3:
	xorl	%esi, %esi
	jmp	.ctxt_vchr_do_len_3
.ctxt_vchr_len_2:
	xorl	%esi, %esi
	xorl	%edx, %edx
	jmp	.ctxt_vchr_do_len_2

	/*
	 * The main matching part split into 128, 64, 32, 16 and the tail
	 * processing blocks.
	 */
.ctxt_vchr_long_str:
	addq	%rdi, %rsi
	movq	%rdi, %rax
.ctxt_vchr_try_128:
	leaq	128(%rax), %rdx
	cmpq	%rdx, %rsi
	jnb	.ctxt_vchr_128
	leaq	64(%rax), %rdx
	cmpq	%rdx, %rsi
	jnb	.ctxt_vchr_64
.ctxt_vchr_try_32:
	leaq	32(%rax), %rdx
	cmpq	%rdx, %rsi
	jnb	.ctxt_vchr_32
.ctxt_vchr_try_16:
	leaq	16(%rax), %rdx
	cmpq	%rdx, %rsi
	jb	.ctxt_vchr_tail
	jmp	.ctxt_vchr_16

	/* Vector processing blocks. */
.ctxt_vchr_128:
	vmovdqa	__ZERO, %ymm5
	vmovdqa	__DEL, %ymm4
	vmovdqa	__SP, %ymm1
	vlddqu	(%rax), %ymm7
	vlddqu	32(%rax), %ymm9
	vpcmpeqb %ymm4, %ymm7, %ymm2
	vpsubb	%ymm5, %ymm7, %ymm0
	vlddqu	64(%rax), %ymm6
	vpsubb	%ymm5, %ymm9, %ymm3
	vlddqu	96(%rax), %ymm8
	vpcmpgtb %ymm0, %ymm1, %ymm0
	vpcmpgtb %ymm3, %ymm1, %ymm3
	vpor	%ymm2, %ymm0, %ymm0
	vpcmpeqb %ymm4, %ymm9, %ymm2
	vpcmpeqb %ymm4, %ymm6, %ymm10
	vpor	%ymm2, %ymm3, %ymm3
	vpsubb	%ymm5, %ymm6, %ymm2
	vpsubb	%ymm5, %ymm8, %ymm5
	vpcmpeqb %ymm4, %ymm8, %ymm4
	vpcmpgtb %ymm2, %ymm1, %ymm2
	vpcmpgtb %ymm5, %ymm1, %ymm1
	vpor	%ymm10, %ymm2, %ymm2
	vpor	%ymm4, %ymm1, %ymm1
	vmovdqa	__HTAB, %ymm4
	vpcmpeqb %ymm4, %ymm7, %ymm7
	vpcmpeqb %ymm4, %ymm9, %ymm9
	vpxor	%ymm7, %ymm0, %ymm0
	vpcmpeqb %ymm4, %ymm8, %ymm8
	vpxor	%ymm9, %ymm3, %ymm3
	vpmovmskb %ymm0, %r8d
	vpcmpeqb %ymm4, %ymm6, %ymm0
	vpxor	%ymm8, %ymm1, %ymm1
	vpmovmskb %ymm3, %ecx
	vpxor	%ymm0, %ymm2, %ymm0
	vpmovmskb %ymm1, %r9d
	movq	%rcx, %r11
	movslq	%r8d, %rcx
	salq	$32, %r11
	salq	$32, %r9
	vpmovmskb %ymm0, %r10d
	orq	%r11, %rcx
	tzcnt	%rcx, %rcx
	movslq	%r10d, %r8
	orq	%r8, %r9
	tzcnt	%r9, %r9
	cmpq	$63, %rcx
	jbe	.ctxt_vchr_mistmatch
	leaq	64(%r9), %rcx
	cmpq	$127, %rcx
	jbe	.ctxt_vchr_mistmatch
	movq	%rdx, %rax
	jmp	.ctxt_vchr_try_128

.ctxt_vchr_64:
	vlddqu	(%rax), %ymm3
	vlddqu	32(%rax), %ymm2
	vmovdqa	__ZERO, %ymm5
	vmovdqa	__DEL, %ymm4
	vmovdqa	__SP, %ymm0
	vpsubb	%ymm5, %ymm3, %ymm1
	vpsubb	%ymm5, %ymm2, %ymm5
	vpcmpeqb %ymm4, %ymm3, %ymm6
	vpcmpgtb %ymm1, %ymm0, %ymm1
	vpcmpeqb %ymm4, %ymm2, %ymm4
	vpor	%ymm6, %ymm1, %ymm1
	vpcmpgtb %ymm5, %ymm0, %ymm0
	vpor	%ymm4, %ymm0, %ymm0
	vmovdqa	__HTAB, %ymm4
	vpcmpeqb %ymm4, %ymm3, %ymm3
	vpcmpeqb %ymm4, %ymm2, %ymm2
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	%ymm2, %ymm0, %ymm0
	vpmovmskb %ymm1, %r8d
	vpmovmskb %ymm0, %ecx
	movslq	%r8d, %r8
	salq	$32, %rcx
	orq	%r8, %rcx
	tzcnt	%rcx, %rcx
	cmpq	$63, %rcx
	jbe	.ctxt_vchr_mistmatch
	movq	%rdx, %rax
	jmp	.ctxt_vchr_try_32

.ctxt_vchr_32:
	vlddqu	(%rax), %ymm1
	vmovdqa	__SP, %ymm0
	vpsubb	__ZERO, %ymm1, %ymm2
	vpcmpgtb %ymm2, %ymm0, %ymm0
	vpcmpeqb __DEL, %ymm1, %ymm2
	vpcmpeqb __HTAB, %ymm1, %ymm1
	vpor	%ymm2, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vpmovmskb %ymm0, %ecx
	tzcnt	%ecx, %ecx
	movl	%ecx, %ecx
	cmpq	$31, %rcx
	jbe	.ctxt_vchr_mistmatch
	movq	%rdx, %rax
	jmp	.ctxt_vchr_try_16

.ctxt_vchr_16:
	vlddqu	(%rax), %xmm1
	vmovdqa	__SP, %xmm0
	vpsubb	__ZERO, %xmm1, %xmm2
	vpcmpgtb %xmm2, %xmm0, %xmm0
	vpcmpeqb __DEL, %xmm1, %xmm2
	vpcmpeqb __HTAB, %xmm1, %xmm1
	vpor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm1, %xmm0, %xmm0
	vpmovmskb %xmm0, %ecx
	orl	$0xffffffffffff0000, %ecx
	tzcnt	%ecx, %ecx
	movl	%ecx, %ecx
	cmpq	$15, %rcx
	jbe	.ctxt_vchr_mistmatch
	movq	%rdx, %rax
	jmp	.ctxt_vchr_tail

.ctxt_vchr_mistmatch:
	vzeroupper
	subq	%rdi, %rax
	addq	%rcx, %rax
	ret

	/* The tail loops processes string lengths in range [4, 15]. */
.ctxt_vchr_tail_loop:
	movzbl	-4(%rcx), %edx
	movzbl	-3(%rcx), %r10d
	movzbl	-2(%rcx), %r8d
	movzbl	-1(%rcx), %r9d
	movzbl	ctext_vchar(%rdx), %edx
	movzbl	ctext_vchar(%r8), %r8d
	movzbl	ctext_vchar(%r9), %r9d
	movl	%edx, %r11d
	andb	ctext_vchar(%r10), %r11b
	movl	%r11d, %r10d
	movl	%r8d, %r11d
	andl	%r9d, %r11d
	testb	%r10b, %r11b
	je	.ctxt_vchr_end
	movq	%rcx, %rax
.ctxt_vchr_tail:
	leaq	4(%rax), %rcx
	cmpq	%rcx, %rsi
	jnb	.ctxt_vchr_tail_loop
	subq	%rax, %rsi
	cmpq	$2, %rsi
	je	.ctxt_vchr_tail_2
	cmpq	$3, %rsi
	je	.ctxt_vchr_tail_3
	cmpq	$1, %rsi
	je	.ctxt_vchr_tail_1
	subq	%rdi, %rax
	movq	%rax, %rsi
	xorl	%eax, %eax
.ctxt_vchr_add_len:
	vzeroupper
	addq	%rsi, %rax
	ret
.ctxt_vchr_end:
	subq	%rdi, %rax
	testb	%r10b, %r10b
	je	.ctxt_vchr_mismatch_1
	addl	%r8d, %r9d
	testl	%r8d, %r8d
	cmovne	%r9d, %r8d
	movl	%r8d, %r8d
	leaq	2(%rax,%r8), %rax
	vzeroupper
	ret
.ctxt_vchr_mismatch_1:
	addq	%rdx, %rax
	vzeroupper
	ret
.ctxt_vchr_tail_1:
	movzbl	(%rax), %edx
	subq	%rdi, %rax
	movq	%rax, %rsi
	movzbl	ctext_vchar(%rdx), %ecx
.ctxt_vchr_add_tail_len:
	movl	%ecx, %eax
	jmp	.ctxt_vchr_add_len
.ctxt_vchr_tail_2:
	xorl	%edx, %edx
.ctxt_vchr_do_tail_2:
	movzbl	(%rax), %ecx
	movq	%rax, %rsi
	movzbl	1(%rax), %eax
	subq	%rdi, %rsi
	movzbl	ctext_vchar(%rcx), %ecx
	testb	%cl, ctext_vchar(%rax)
	je	.ctxt_vchr_add_tail_len
	leaq	2(%rsi,%rdx), %rax
	vzeroupper
	ret
.ctxt_vchr_tail_3:
	movzbl	2(%rax), %edx
	movzbl	ctext_vchar(%rdx), %edx
	jmp	.ctxt_vchr_do_tail_2

ENDPROC(__tfw_match_ctext_vchar)

/*
 * The following group of functions tfw_match_X() must be in this file to
 * to not to export __CUSTOM with complex offsets.
 */

ENTRY(tfw_match_uri)
	cmpb	$0, custom_uri_enabled(%rip)
	jne	.match_cust_uri
	movq	__URI, %rcx
	movq	$uri, %rdx
	jmp	__tfw_strspn_simd
.match_cust_uri:
	movq	__CUST_URI_0, %rcx
	movq	__CUST_URI_1, %r8
	movq	$custom_uri, %rdx
	jmp	__tfw_match_custom
ENDPROC(tfw_match_uri)

ENTRY(tfw_match_token)
	cmpb	$0, custom_token_enabled(%rip)
	jne	.match_cust_token
	movq	__TOKEN, %rcx
	movq	$token, %rdx
	jmp	__tfw_strspn_simd
.match_cust_token:
	movq	__CUST_TOKEN_0, %rcx
	movq	__CUST_TOKEN_1, %r8
	movq	$custom_token, %rdx
	jmp	__tfw_match_custom
ENDPROC(tfw_match_token)

ENTRY(tfw_match_qetoken)
	cmpb	$0, custom_qetoken_enabled(%rip)
	jne	.match_cust_qetoken
	movq	__QETOKEN, %rcx
	movq	$qetoken, %rdx
	jmp	__tfw_strspn_simd
.match_cust_qetoken:
	movq	__CUST_QETOKEN_0, %rcx
	movq	__CUST_QETOKEN_1, %r8
	movq	$custom_qetoken, %rdx
	jmp	__tfw_match_custom
ENDPROC(tfw_match_qetoken)

ENTRY(tfw_match_nctl)
	cmpb	$0, custom_nctl_enabled(%rip)
	jne	.match_cust_nctl
	movq	__NCTL, %rcx
	movq	$nctl, %rdx
	jmp	__tfw_strspn_simd
.match_cust_nctl:
	movq	__CUST_NCTL_0, %rcx
	movq	__CUST_NCTL_1, %r8
	movq	$custom_nctl, %rdx
	jmp	__tfw_match_custom
ENDPROC(tfw_match_nctl)

ENTRY(tfw_match_xff)
	cmpb	$0, custom_xff_enabled(%rip)
	jne	.match_cust_xff
	movq	__XFF, %rcx
	movq	$xff, %rdx
	jmp	__tfw_strspn_simd
.match_cust_xff:
	movq	__CUST_XFF_0, %rcx
	movq	__CUST_XFF_1, %r8
	movq	$custom_xff, %rdx
	jmp	__tfw_match_custom
ENDPROC(tfw_match_xff)

ENTRY(tfw_match_cookie)
	cmpb	$0, custom_cookie_enabled(%rip)
	jne	.match_cust_cookie
	movq	__COOKIE, %rcx
	movq	$cookie, %rdx
	jmp	__tfw_strspn_simd
.match_cust_cookie:
	movq	__CUST_COOKIE_0, %rcx
	movq	__CUST_COOKIE_1, %r8
	movq	$custom_cookie, %rdx
	jmp	__tfw_match_custom
ENDPROC(tfw_match_cookie)
