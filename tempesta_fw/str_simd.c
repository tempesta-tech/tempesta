/**
 *		Tempesta FW
 *
 * x86-64 SIMD routines for HTTP strings processing.
 *
 * Copyright (C) 2016 Tempesta Technologies, Inc.
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
#ifdef AVX2
#pragma GCC target("mmx", "sse4.2", "avx2")
#else
#pragma GCC target("mmx", "sse4.2")
#endif
#include <asm/bitops.h>
#include <asm/fpu/api.h>
#include <x86intrin.h>

#include "htype.h"
#include "log.h"

/*
 * Static structure of constants for vector processing.
 *
 * @A		- ASCII 'A' - 1
 * @D		- ASCII 'z' - 'a' + 1
 * @LCASE	- 0x20 converting upper case character to lower case;
 * @ARF		- ASCII rows factors;
 * @LSH		- Mask for least sigificant half of bytes;
 * @URI		- ASCII table column bitmaps for HTTP URI abs_path (RFC 3986);
 * @TOKEN	- ASCII table column bitmaps for HTTP token, e.g. header name
 *		  (RFC 7230 3.2.6);
 * @QETOKEN	- `token` with double quotes and equal sign;
 * @NCTL	- ASCII VCHAR (RFC RFC 5234, Apendix B.1.) plus SP and HTAB,
 *		  used to accept HTTP header values;
 * @CTVCH	- union of ctext and VCHAR, example usage is User-Agent;
 * @XFF		- ASCII characters for HTTP X-Forwarded-For header (RFC 7239);
 * @CO		- cookie-octet as defined in RFC 6265 4.1.1 plus DQUOTE;
 */
static struct {
	__m128i A128;
	__m128i a128;
	__m128i D128;
	__m128i CASE128;
	__m128i	ARF128;
	__m128i	LSH128;
	__m128i URI128;
	__m128i TOKEN128;
	__m128i QETOKEN128;
	__m128i NCTL128;
	__m128i CTVCH128;
	__m128i XFF128;
	__m128i CO128;
#ifdef AVX2
	__m256i A256;
	__m256i a256;
	__m256i D256;
	__m256i CASE256;
	__m256i	ARF256;
	__m256i	LSH256;
	__m256i URI256;
	__m256i TOKEN256;
	__m256i QETOKEN256;
	__m256i NCTL256;
	__m256i CTVCH256;
	__m256i XFF256;
	__m256i CO256;
#endif
} __C;

void
tfw_str_init_const(void)
{
	__C.A128 = _mm_set1_epi8('A' - 0x80);
	__C.a128 = _mm_set1_epi8('a' - 0x80);
	__C.D128 = _mm_set1_epi8('Z' - 'A' + 1 - 0x80);
	__C.CASE128 = _mm_set1_epi8(0x20);
	__C.ARF128 = _mm_setr_epi8(
		0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80,
		0, 0, 0, 0, 0, 0, 0, 0);
	__C.LSH128 = _mm_set1_epi8(0xf);
	/*
	 * ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
	 * !#$%&'*+-._();:@=,/?[]~0123456789
	 */
	__C.URI128 = _mm_setr_epi8(
		0xb8, 0xfc, 0xf8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfc, 0xfc, 0x7c, 0x54, 0x7c, 0xd4, 0x7c);
	/*
	 * ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
	 * !#$%&'*+-.^_`|~0123456789
	 */
	__C.TOKEN128 = _mm_setr_epi8(
		0xe8, 0xfc, 0xf8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xf8, 0xf8, 0xf4, 0x54, 0xd0, 0x54, 0xf4, 0x70);
	/*
	 * Token with DQUOTE and "=".
	 */
	__C.QETOKEN128 = _mm_setr_epi8(
		0xe8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xf8, 0xf8, 0xf4, 0x54, 0xd0, 0x5c, 0xf4, 0x70);
	/*
	 * RFC 7230, Apendix B; RFC 5234, Apendix B.1.:
	 * 
	 * 	field-value OWS = VCHAR SP HTAB = %x9 %x20-7E
	 *
	 * , i.e. non-control characters.
	 */
	__C.NCTL128 = _mm_setr_epi8(
		0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfd, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0x7c);
	/*
	 * Union of ctext and VCHAR, RFC 7230.
	 */
	__C.CTVCH128 = _mm_setr_epi8(
		0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfd, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0x7c);
	/*
	 * Alphabet for X-Forwarded-For Node ID (RFC 7239):
	 *
	 *	ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
	 *	0123456789._-[]:
	 */
	__C.XFF128 = _mm_setr_epi8(
		0xa8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8,
		0xf8, 0xf8, 0xf8, 0x70, 0x50, 0x74, 0x54, 0x70);
	/*
	 * Cookie-octet w/ DQUOTE: %x21 %x22-2B %x2D-3A %x3C-5B %x5D-7E
	 */
	__C.CO128 = _mm_setr_epi8(
		0xf8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfc, 0xfc, 0xf4, 0xd8, 0xfc, 0xfc, 0x7c);

#ifdef AVX2
	__C.A256 = _mm256_set1_epi8('A' - 0x80);
	__C.a256 = _mm256_set1_epi8('a' - 0x80);
	__C.D256 = _mm256_set1_epi8('Z' - 'A' + 1 - 0x80);
	__C.CASE256 = _mm256_set1_epi8(0x20);
	__C.ARF256 = _mm256_setr_epi8(
		0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80,
		0, 0, 0, 0, 0, 0, 0, 0,
		0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80,
		0, 0, 0, 0, 0, 0, 0, 0);
	__C.LSH256 = _mm256_set1_epi8(0xf);
	__C.URI256 = _mm256_setr_epi8(
		0xb8, 0xfc, 0xf8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfc, 0xfc, 0x7c, 0x54, 0x7c, 0xd4, 0x7c,
		0xb8, 0xfc, 0xf8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfc, 0xfc, 0x7c, 0x54, 0x7c, 0xd4, 0x7c);
	__C.TOKEN256 = _mm256_setr_epi8(
		0xe8, 0xfc, 0xf8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xf8, 0xf8, 0xf4, 0x54, 0xd0, 0x54, 0xf4, 0x70,
		0xe8, 0xfc, 0xf8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xf8, 0xf8, 0xf4, 0x54, 0xd0, 0x54, 0xf4, 0x70);
	__C.QETOKEN256 = _mm256_setr_epi8(
		0xe8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xf8, 0xf8, 0xf4, 0x54, 0xd0, 0x5c, 0xf4, 0x70,
		0xe8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xf8, 0xf8, 0xf4, 0x54, 0xd0, 0x5c, 0xf4, 0x70);
	__C.NCTL256 = _mm256_setr_epi8(
		0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfd, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0x7c,
		0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfd, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0x7c);
	__C.CTVCH256 = _mm256_setr_epi8(
		0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfd, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0x7c,
		0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfd, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0x7c);
	__C.XFF256 = _mm256_setr_epi8(
		0xa8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8,
		0xf8, 0xf8, 0xf8, 0x70, 0x50, 0x74, 0x54, 0x70,
		0xa8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8,
		0xf8, 0xf8, 0xf8, 0x70, 0x50, 0x74, 0x54, 0x70);
	__C.CO256 = _mm256_setr_epi8(
		0xf8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfc, 0xfc, 0xf4, 0xd8, 0xfc, 0xfc, 0x7c,
		0xf8, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc,
		0xfc, 0xfc, 0xfc, 0xf4, 0xd8, 0xfc, 0xfc, 0x7c);
#endif
}
EXPORT_SYMBOL(tfw_str_init_const);

/*
 * ASCII codes to accept URI string (C representation for __C.URI).
 *
 * While we can pack the array, which is 4 cache lines currently,
 * to just half of a cache line using 4 64-bit masks, it's much
 * faster to access the extra cache lines than to the 4 bit operations
 * (uri_a[c >> 6] & (1UL << (c & 0x3f))).
 */
static const unsigned char uri[] ____cacheline_aligned = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * ASCII table column bitmaps for HTTP token, e.g. header name (RFC 7230 3.2.6).
 * (C representation for __C.TOKEN).
 */
static const unsigned char token[] ____cacheline_aligned = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * Token with DQUOTE and "=".
 * (C representation for __C.QETOKEN).
 */
static const unsigned char qetoken[] ____cacheline_aligned = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * ASCII codes to accept HTTP header values
 * (C representation for __C.NCTL).
 */
static const unsigned char nctl[] ____cacheline_aligned = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * ASCII codes to accept ctext | VCHAR, e.g. User-Agent.
 * (C representation for __C.CTVCH).
 */
static const unsigned char ctext_vchar[] ____cacheline_aligned = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

/*
 * ASCII codes to accept X-Forwarded-For values
 * (C representation for __C.XFF).
 */
static const unsigned char xff[] ____cacheline_aligned = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

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
 * grammar. This is C representation for __C.CO.
 */
static const unsigned char cookie_octet[] ____cacheline_aligned = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static unsigned long
__tzcnt(unsigned long x)
{
#ifdef AVX2
	unsigned long r;

	asm volatile ("tzcnt %1, %0\n"
		      : "=r"(r)
		      : "r"(x));

	return r;
#else
	return x ? __ffs(x) : 64;
#endif
}

#ifdef AVX2

static inline void
__strtolower_avx2_8(unsigned char *dest, const unsigned char *src)
{
	static const __m64 _A = (__m64)0xc1c1c1c1c1c1c1c1UL;
	static const __m64 _D = (__m64)0x9a9a9a9a9a9a9a9aUL;
	static const unsigned long CASE = 0x2020202020202020UL;

	volatile __m64 v, sub;
	volatile unsigned long cmp_r;

	v = *(__m64 *)src;

	sub = _mm_sub_pi8(v, _A);
	cmp_r = (unsigned long)_mm_cmpgt_pi8(_D, sub);

	*(unsigned long *)dest = (unsigned long)v | (cmp_r & CASE);
}

static inline void
__strtolower_avx2_16(unsigned char *dest, const unsigned char *src)
{
	__m128i v = _mm_lddqu_si128((void *)src);

	__m128i sub = _mm_sub_epi8(v, __C.A128);
	__m128i cmp_r = _mm_cmpgt_epi8(__C.D128, sub);
	__m128i lc = _mm_and_si128(cmp_r, __C.CASE128);
	__m128i r = _mm_or_si128(v, lc);

	_mm_storeu_si128((__m128i *)dest, r);
}

static inline void
__strtolower_avx2_32(unsigned char *dest, const unsigned char *src)
{
	__m256i v = _mm256_lddqu_si256((void *)src);

	__m256i sub = _mm256_sub_epi8(v, __C.A256);
	__m256i cmp_r = _mm256_cmpgt_epi8(__C.D256, sub);
	__m256i lc = _mm256_and_si256(cmp_r, __C.CASE256);
	__m256i r = _mm256_or_si256(v, lc);

	_mm256_storeu_si256((__m256i *)dest, r);
}

static inline void
__strtolower_avx2_64(unsigned char *dest, const unsigned char *src)
{
	__m256i v0 = _mm256_lddqu_si256((void *)src);
	__m256i v1 = _mm256_lddqu_si256((void *)(src + 32));

	__m256i sub0 = _mm256_sub_epi8(v0, __C.A256);
	__m256i sub1 = _mm256_sub_epi8(v1, __C.A256);
	__m256i cmp_r0 = _mm256_cmpgt_epi8(__C.D256, sub0);
	__m256i cmp_r1 = _mm256_cmpgt_epi8(__C.D256, sub1);
	__m256i lc0 = _mm256_and_si256(cmp_r0, __C.CASE256);
	__m256i lc1 = _mm256_and_si256(cmp_r1, __C.CASE256);
	__m256i r0 = _mm256_or_si256(v0, lc0);
	__m256i r1 = _mm256_or_si256(v1, lc1);

	_mm256_storeu_si256((__m256i *)dest, r0);
	_mm256_storeu_si256((__m256i *)(dest + 32), r1);
}

static inline void
__strtolower_avx2_128(unsigned char *dest, const unsigned char *src)
{
	__m256i v0 = _mm256_lddqu_si256((void *)src);
	__m256i v1 = _mm256_lddqu_si256((void *)(src + 32));
	__m256i v2 = _mm256_lddqu_si256((void *)(src + 64));
	__m256i v3 = _mm256_lddqu_si256((void *)(src + 96));

	__m256i sub0 = _mm256_sub_epi8(v0, __C.A256);
	__m256i sub1 = _mm256_sub_epi8(v1, __C.A256);
	__m256i sub2 = _mm256_sub_epi8(v2, __C.A256);
	__m256i sub3 = _mm256_sub_epi8(v3, __C.A256);

	__m256i cmp_r0 = _mm256_cmpgt_epi8(__C.D256, sub0);
	__m256i cmp_r1 = _mm256_cmpgt_epi8(__C.D256, sub1);
	__m256i cmp_r2 = _mm256_cmpgt_epi8(__C.D256, sub2);
	__m256i cmp_r3 = _mm256_cmpgt_epi8(__C.D256, sub3);

	__m256i lc0 = _mm256_and_si256(cmp_r0, __C.CASE256);
	__m256i lc1 = _mm256_and_si256(cmp_r1, __C.CASE256);
	__m256i lc2 = _mm256_and_si256(cmp_r2, __C.CASE256);
	__m256i lc3 = _mm256_and_si256(cmp_r3, __C.CASE256);

	__m256i r0 = _mm256_or_si256(v0, lc0);
	__m256i r1 = _mm256_or_si256(v1, lc1);
	__m256i r2 = _mm256_or_si256(v2, lc2);
	__m256i r3 = _mm256_or_si256(v3, lc3);

	_mm256_storeu_si256((__m256i *)dest, r0);
	_mm256_storeu_si256((__m256i *)(dest + 32), r1);
	_mm256_storeu_si256((__m256i *)(dest + 64), r2);
	_mm256_storeu_si256((__m256i *)(dest + 96), r3);
}

void
__tfw_strtolower_avx2(unsigned char *dest, const unsigned char *src, size_t len)
{
	int i = 0;

	/* Quickly process short strings and find differences dest first bytes. */
process_tail:
	switch (len) {
	case 0:
		return;
	case 8:
		dest[7] = __tfw_lct[src[7]];
	case 7:
		dest[6] = __tfw_lct[src[6]];
	case 6:
		dest[5] = __tfw_lct[src[5]];
	case 5:
		dest[4] = __tfw_lct[src[4]];
	case 4:
		dest[3] = __tfw_lct[src[3]];
	case 3:
		dest[2] = __tfw_lct[src[2]];
	case 2:
		dest[1] = __tfw_lct[src[1]];
	case 1:
		dest[0] = __tfw_lct[src[0]];
		return;
	}

	for ( ; unlikely(i + 128 <= len); i += 128)
		__strtolower_avx2_128(dest + i, src + i);
	if (unlikely(i + 64 <= len)) {
		__strtolower_avx2_64(dest + i, src + i);
		i += 64;
	}
	if (unlikely(i + 32 <= len)) {
		__strtolower_avx2_32(dest + i, src + i);
		i += 32;
	}
	if (unlikely(i + 16 <= len)) {
		__strtolower_avx2_16(dest + i, src + i);
		i += 16;
	}
	if (unlikely(i + 8 <= len)) {
		__strtolower_avx2_8(dest + i, src + i);
		i += 8;
	}

	len -= i;
	dest += i;
	src += i;
	goto process_tail;
}
EXPORT_SYMBOL(__tfw_strtolower_avx2);

static inline unsigned int
__stricmp_avx2_xor_32(const char *s0, const char *s1)
{
	__m256i v0 = _mm256_lddqu_si256((void *)s0);
	__m256i v1 = _mm256_lddqu_si256((void *)s1);

	__m256i xor = _mm256_xor_si256(v0, v1);
	__m256i vl0 = _mm256_or_si256(v0, __C.CASE256);
	__m256i lc = _mm256_cmpeq_epi8(xor, __C.CASE256);
	__m256i sub = _mm256_sub_epi8(vl0, __C.a256);
	__m256i cmp_r = _mm256_cmpgt_epi8(__C.D256, sub);
	__m256i good = _mm256_and_si256(lc, cmp_r);
	__m256i good_xor = _mm256_and_si256(good, __C.CASE256);
	__m256i match = _mm256_xor_si256(good_xor, xor);
	match = _mm256_cmpeq_epi8(match, _mm256_setzero_si256());

	return ~_mm256_movemask_epi8(match);
}

static inline unsigned int
__stricmp_avx2_xor_64(const char *s0, const char *s1)
{
	__m256i v00 = _mm256_lddqu_si256((void *)s0);
	__m256i v01 = _mm256_lddqu_si256((void *)(s0 + 32));
	__m256i v10 = _mm256_lddqu_si256((void *)s1);
	__m256i v11 = _mm256_lddqu_si256((void *)(s1 + 32));

	__m256i xor0 = _mm256_xor_si256(v00, v10);
	__m256i xor1 = _mm256_xor_si256(v01, v11);

	__m256i vl00 = _mm256_or_si256(v00, __C.CASE256);
	__m256i vl01 = _mm256_or_si256(v01, __C.CASE256);

	__m256i lc0 = _mm256_cmpeq_epi8(xor0, __C.CASE256);
	__m256i lc1 = _mm256_cmpeq_epi8(xor1, __C.CASE256);

	__m256i sub0 = _mm256_sub_epi8(vl00, __C.a256);
	__m256i sub1 = _mm256_sub_epi8(vl01, __C.a256);

	__m256i cmp_r0 = _mm256_cmpgt_epi8(__C.D256, sub0);
	__m256i cmp_r1 = _mm256_cmpgt_epi8(__C.D256, sub1);

	__m256i good0 = _mm256_and_si256(lc0, cmp_r0);
	__m256i good1 = _mm256_and_si256(lc1, cmp_r1);

	__m256i good_xor0 = _mm256_and_si256(good0, __C.CASE256);
	__m256i good_xor1 = _mm256_and_si256(good1, __C.CASE256);

	__m256i match0 = _mm256_xor_si256(good_xor0, xor0);
	__m256i match1 = _mm256_xor_si256(good_xor1, xor1);

	match0 = _mm256_cmpeq_epi8(match0, _mm256_setzero_si256());
	match1 = _mm256_cmpeq_epi8(match1, _mm256_setzero_si256());

	return ~(_mm256_movemask_epi8(match0) & _mm256_movemask_epi8(match1));
}

static inline unsigned int
__stricmp_avx2_xor_128(const char *s0, const char *s1)
{
	__m256i v00 = _mm256_lddqu_si256((void *)s0);
	__m256i v01 = _mm256_lddqu_si256((void *)(s0 + 32));
	__m256i v02 = _mm256_lddqu_si256((void *)(s0 + 64));
	__m256i v03 = _mm256_lddqu_si256((void *)(s0 + 96));
	__m256i v10 = _mm256_lddqu_si256((void *)s1);
	__m256i v11 = _mm256_lddqu_si256((void *)(s1 + 32));
	__m256i v12 = _mm256_lddqu_si256((void *)(s1 + 64));
	__m256i v13 = _mm256_lddqu_si256((void *)(s1 + 96));

	__m256i xor0 = _mm256_xor_si256(v00, v10);
	__m256i xor1 = _mm256_xor_si256(v01, v11);
	__m256i xor2 = _mm256_xor_si256(v02, v12);
	__m256i xor3 = _mm256_xor_si256(v03, v13);

	__m256i vl00 = _mm256_or_si256(v00, __C.CASE256);
	__m256i vl01 = _mm256_or_si256(v01, __C.CASE256);
	__m256i vl02 = _mm256_or_si256(v02, __C.CASE256);
	__m256i vl03 = _mm256_or_si256(v03, __C.CASE256);

	__m256i lc0 = _mm256_cmpeq_epi8(xor0, __C.CASE256);
	__m256i lc1 = _mm256_cmpeq_epi8(xor1, __C.CASE256);
	__m256i lc2 = _mm256_cmpeq_epi8(xor2, __C.CASE256);
	__m256i lc3 = _mm256_cmpeq_epi8(xor3, __C.CASE256);

	__m256i sub0 = _mm256_sub_epi8(vl00, __C.a256);
	__m256i sub1 = _mm256_sub_epi8(vl01, __C.a256);
	__m256i sub2 = _mm256_sub_epi8(vl02, __C.a256);
	__m256i sub3 = _mm256_sub_epi8(vl03, __C.a256);

	__m256i cmp_r0 = _mm256_cmpgt_epi8(__C.D256, sub0);
	__m256i cmp_r1 = _mm256_cmpgt_epi8(__C.D256, sub1);
	__m256i cmp_r2 = _mm256_cmpgt_epi8(__C.D256, sub2);
	__m256i cmp_r3 = _mm256_cmpgt_epi8(__C.D256, sub3);

	__m256i good0 = _mm256_and_si256(lc0, cmp_r0);
	__m256i good1 = _mm256_and_si256(lc1, cmp_r1);
	__m256i good2 = _mm256_and_si256(lc2, cmp_r2);
	__m256i good3 = _mm256_and_si256(lc3, cmp_r3);

	__m256i good_xor0 = _mm256_and_si256(good0, __C.CASE256);
	__m256i good_xor1 = _mm256_and_si256(good1, __C.CASE256);
	__m256i good_xor2 = _mm256_and_si256(good2, __C.CASE256);
	__m256i good_xor3 = _mm256_and_si256(good3, __C.CASE256);

	__m256i match0 = _mm256_xor_si256(good_xor0, xor0);
	__m256i match1 = _mm256_xor_si256(good_xor1, xor1);
	__m256i match2 = _mm256_xor_si256(good_xor2, xor2);
	__m256i match3 = _mm256_xor_si256(good_xor3, xor3);

	match0 = _mm256_cmpeq_epi8(match0, _mm256_setzero_si256());
	match1 = _mm256_cmpeq_epi8(match1, _mm256_setzero_si256());
	match2 = _mm256_cmpeq_epi8(match2, _mm256_setzero_si256());
	match3 = _mm256_cmpeq_epi8(match3, _mm256_setzero_si256());

	return ~(_mm256_movemask_epi8(match0) & _mm256_movemask_epi8(match1)
		 & _mm256_movemask_epi8(match2) & _mm256_movemask_epi8(match3));
}

static inline int
__stricmp_avx2_xor_tail(const char *s1, const char *s2, size_t len)
{
	__m128i xor, vl0, lc, sub, cmp_r, good, match;
	__m128d v0, v1;

	/* We have no 256bit half loads in AVX2, so use 128bit ops here. */
	if (len >= 16) {
		int r;

		__m128i v0 = _mm_lddqu_si128((void *)s1);
		__m128i v1 = _mm_lddqu_si128((void *)s2);
		xor = _mm_xor_si128(v0, v1);
		vl0 = _mm_or_si128(v0, __C.CASE128);
		lc = _mm_cmpeq_epi8(xor, __C.CASE128);
		sub = _mm_sub_epi8(vl0, __C.a128);
		cmp_r = _mm_cmpgt_epi8(__C.D128, sub);
		good = _mm_and_si128(lc, cmp_r);
		good = _mm_and_si128(good, __C.CASE128);
		match = _mm_xor_si128(good, xor);
		match = _mm_cmpeq_epi8(match, _mm_setzero_si128());
		r = _mm_movemask_epi8(match) ^ 0xffff;
		if (len == 16 || r)
			return r;
		s1 += len - 16;
		s2 += len - 16;
		len = 16;
	}

	/* 8 < len <= 16. */
	v0 = _mm_loadh_pd(v0, (double *)s1);
	v1 = _mm_loadh_pd(v1, (double *)s2);
	v0 = _mm_loadl_pd(v0, (double *)(s1 + len - 8));
	v1 = _mm_loadl_pd(v1, (double *)(s2 + len - 8));

	xor = _mm_xor_si128((__m128i)v0, (__m128i)v1);
	vl0 = _mm_or_si128((__m128i)v0, __C.CASE128);
	lc = _mm_cmpeq_epi8(xor, __C.CASE128);
	sub = _mm_sub_epi8(vl0, __C.a128);
	cmp_r = _mm_cmpgt_epi8(__C.D128, sub);
	good = _mm_and_si128(lc, cmp_r);
	good = _mm_and_si128(good, __C.CASE128);
	match = _mm_xor_si128(good, xor);
	match = _mm_cmpeq_epi8(match, _mm_setzero_si128());

	return _mm_movemask_epi8(match) ^ 0xffff;
}

int
__tfw_stricmp_avx2(const unsigned char *s1, const unsigned char *s2, size_t len)
{
	int i = 0, c = 0;

	/*
	 * This switch runs slower than in stricmp_avx2_64(), but it guarantees
	 * that we processed 8 bytes when we're in AVX routines, such that we
	 * can efficiently process tail.
	 */
	switch (len) {
	case 0:
		return 0;
	case 8:
		c |= __tfw_lct[s1[7]] ^ __tfw_lct[s2[7]];
	case 7:
		c |= __tfw_lct[s1[6]] ^ __tfw_lct[s2[6]];
	case 6:
		c |= __tfw_lct[s1[5]] ^ __tfw_lct[s2[5]];
	case 5:
		c |= __tfw_lct[s1[4]] ^ __tfw_lct[s2[4]];
	case 4:
		c |= __tfw_lct[s1[3]] ^ __tfw_lct[s2[3]];
	case 3:
		c |= __tfw_lct[s1[2]] ^ __tfw_lct[s2[2]];
	case 2:
		c |= __tfw_lct[s1[1]] ^ __tfw_lct[s2[1]];
	case 1:
		c |= __tfw_lct[s1[0]] ^ __tfw_lct[s2[0]];
		return c;
	}

	if (likely(len < 32))
		return __stricmp_avx2_xor_tail(s1, s2, len);

	for ( ; unlikely(i + 128 <= len); i += 128)
		if (__stricmp_avx2_xor_128(s1 + i, s2 + i))
			return 1;
	if (unlikely(i + 64 <= len)) {
		if (__stricmp_avx2_xor_64(s1 + i, s2 + i))
			return 1;
		i += 64;
	}
	if (unlikely(i + 32 <= len)) {
		if (__stricmp_avx2_xor_32(s1 + i, s2 + i))
			return 1;
		i += 32;
	}
	if (i == len)
		return 0;
	len -= i;
	if (len < 8) {
		i -= 8 - len;
		len = 8;
	}

	return __stricmp_avx2_xor_tail(s1 + i, s2 + i, c);
}
EXPORT_SYMBOL(__tfw_stricmp_avx2);

static inline unsigned int
__stricmp_avx2_2lc_32(const char *s0, const char *s1)
{
	__m256i v0 = _mm256_lddqu_si256((void *)s0);
	__m256i v1 = _mm256_lddqu_si256((void *)s1);

	__m256i sub = _mm256_sub_epi8(v0, __C.A256);
	__m256i cmp_r = _mm256_cmpgt_epi8(__C.D256, sub);
	__m256i lc = _mm256_and_si256(cmp_r, __C.CASE256);
	__m256i vl = _mm256_or_si256(v0, lc);

	__m256i eq = _mm256_cmpeq_epi8(vl, v1);

	return ~_mm256_movemask_epi8(eq);
}

static inline unsigned int
__stricmp_avx2_2lc_64(const char *s0, const char *s1)
{
	__m256i v00 = _mm256_lddqu_si256((void *)s0);
	__m256i v01 = _mm256_lddqu_si256((void *)(s0 + 32));
	__m256i v10 = _mm256_lddqu_si256((void *)s1);
	__m256i v11 = _mm256_lddqu_si256((void *)(s1 + 32));

	__m256i sub00 = _mm256_sub_epi8(v00, __C.A256);
	__m256i sub01 = _mm256_sub_epi8(v01, __C.A256);
	__m256i cmp_r00 = _mm256_cmpgt_epi8(__C.D256, sub00);
	__m256i cmp_r01 = _mm256_cmpgt_epi8(__C.D256, sub01);

	__m256i lc00 = _mm256_and_si256(cmp_r00, __C.CASE256);
	__m256i lc01 = _mm256_and_si256(cmp_r01, __C.CASE256);

	__m256i vl00 = _mm256_or_si256(v00, lc00);
	__m256i vl01 = _mm256_or_si256(v01, lc01);

	__m256i eq0 = _mm256_cmpeq_epi8(vl00, v10);
	__m256i eq1 = _mm256_cmpeq_epi8(vl01, v11);

	return ~(_mm256_movemask_epi8(eq0) & _mm256_movemask_epi8(eq1));
}

static inline unsigned int
__stricmp_avx2_2lc_128(const char *s0, const char *s1)
{
	__m256i v00 = _mm256_lddqu_si256((void *)s0);
	__m256i v01 = _mm256_lddqu_si256((void *)(s0 + 32));
	__m256i v02 = _mm256_lddqu_si256((void *)(s0 + 64));
	__m256i v03 = _mm256_lddqu_si256((void *)(s0 + 96));
	__m256i v10 = _mm256_lddqu_si256((void *)s1);
	__m256i v11 = _mm256_lddqu_si256((void *)(s1 + 32));
	__m256i v12 = _mm256_lddqu_si256((void *)(s1 + 64));
	__m256i v13 = _mm256_lddqu_si256((void *)(s1 + 96));

	__m256i sub00 = _mm256_sub_epi8(v00, __C.A256);
	__m256i sub01 = _mm256_sub_epi8(v01, __C.A256);
	__m256i sub02 = _mm256_sub_epi8(v02, __C.A256);
	__m256i sub03 = _mm256_sub_epi8(v03, __C.A256);

	__m256i cmp_r00 = _mm256_cmpgt_epi8(__C.D256, sub00);
	__m256i cmp_r01 = _mm256_cmpgt_epi8(__C.D256, sub01);
	__m256i cmp_r02 = _mm256_cmpgt_epi8(__C.D256, sub02);
	__m256i cmp_r03 = _mm256_cmpgt_epi8(__C.D256, sub03);

	__m256i lc00 = _mm256_and_si256(cmp_r00, __C.CASE256);
	__m256i lc01 = _mm256_and_si256(cmp_r01, __C.CASE256);
	__m256i lc02 = _mm256_and_si256(cmp_r02, __C.CASE256);
	__m256i lc03 = _mm256_and_si256(cmp_r03, __C.CASE256);

	__m256i vl00 = _mm256_or_si256(v00, lc00);
	__m256i vl01 = _mm256_or_si256(v01, lc01);
	__m256i vl02 = _mm256_or_si256(v02, lc02);
	__m256i vl03 = _mm256_or_si256(v03, lc03);

	__m256i eq0 = _mm256_cmpeq_epi8(vl00, v10);
	__m256i eq1 = _mm256_cmpeq_epi8(vl01, v11);
	__m256i eq2 = _mm256_cmpeq_epi8(vl02, v12);
	__m256i eq3 = _mm256_cmpeq_epi8(vl03, v13);

	return ~(_mm256_movemask_epi8(eq0) & _mm256_movemask_epi8(eq1)
		 & _mm256_movemask_epi8(eq2) & _mm256_movemask_epi8(eq3));
}

static inline int
__stricmp_avx2_2lc_tail(const char *s1, const char *s2, size_t len)
{
	__m128i sub, cmp_r, lc, vl, eq;
	__m128d v0, v1;

	/*  We have no 256bit half loads in AVX2, so use 128bit ops here. */
	if (len >= 16) {
		int r;
		__m128i v0 = _mm_lddqu_si128((void *)s1);
		__m128i v1 = _mm_lddqu_si128((void *)s2);
		sub = _mm_sub_epi8(v0, __C.A128);
		cmp_r = _mm_cmpgt_epi8(__C.D128, sub);
		lc = _mm_and_si128(cmp_r, __C.CASE128);
		vl = _mm_or_si128(v0, lc);
		eq = _mm_cmpeq_epi8(vl, v1);
		r = _mm_movemask_epi8(eq) ^ 0xffff;
		if (len == 16 || r)
			return r;
		s1 += len - 16;
		s2 += len - 16;
		len = 16;
	}

	/* 8 < len <= 16. */
	v0 = _mm_loadh_pd(v0, (double *)s1);
	v1 = _mm_loadh_pd(v1, (double *)s2);
	v0 = _mm_loadl_pd(v0, (double *)(s1 + len - 8));
	v1 = _mm_loadl_pd(v1, (double *)(s2 + len - 8));

	sub = _mm_sub_epi8((__m128i)v0, __C.A128);
	cmp_r = _mm_cmpgt_epi8(__C.D128, (__m128i)sub);
	lc = _mm_and_si128(cmp_r, __C.CASE128);
	vl = _mm_or_si128((__m128i)v0, lc);
	eq = _mm_cmpeq_epi8(vl, (__m128i)v1);

	return _mm_movemask_epi8(eq) ^ 0xffff;
}

int
__tfw_stricmp_avx2_2lc(const unsigned char *s1, const unsigned char *s2, size_t len)
{
	int i = 0, c = 0;

	switch (len) {
	case 0:
		return 0;
	case 8:
		c |= __tfw_lct[s1[7]] ^ s2[7];
	case 7:
		c |= __tfw_lct[s1[6]] ^ s2[6];
	case 6:
		c |= __tfw_lct[s1[5]] ^ s2[5];
	case 5:
		c |= __tfw_lct[s1[4]] ^ s2[4];
	case 4:
		c |= __tfw_lct[s1[3]] ^ s2[3];
	case 3:
		c |= __tfw_lct[s1[2]] ^ s2[2];
	case 2:
		c |= __tfw_lct[s1[1]] ^ s2[1];
	case 1:
		c |= __tfw_lct[s1[0]] ^ s2[0];
		return c;
	}

	if (likely(len < 32))
		return __stricmp_avx2_2lc_tail(s1, s2, len);

	for ( ; unlikely(i + 128 <= len); i += 128)
		if (__stricmp_avx2_2lc_128(s1 + i, s2 + i))
			return 1;
	if (unlikely(i + 64 <= len)) {
		if (__stricmp_avx2_2lc_64(s1 + i, s2 + i))
			return 1;
		i += 64;
	}
	if (unlikely(i + 32 <= len)) {
		if (__stricmp_avx2_2lc_32(s1 + i, s2 + i))
			return 1;
		i += 32;
	}
	if (i == len)
		return 0;
	len -= i;
	if (len < 8) {
		i -= 8 - len;
		len = 8;
	}

	return __stricmp_avx2_2lc_tail(s1 + i, s2 + i, len);
}
EXPORT_SYMBOL(__tfw_stricmp_avx2_2lc);

static inline size_t
__tfw_strspn_avx2_32(const char *str, __m256i sm)
{
	unsigned long r;

	__m256i v = _mm256_lddqu_si256((void *)str);
	/*
	 * Arrange ASCII column bitmaps by
	 * ASCII column indexes of characters from @str.
	 */
	__m256i acbm = _mm256_shuffle_epi8(sm, v);
	/* Determine ASCII rows for all @str characters. */
	__m256i arows = _mm256_and_si256(__C.LSH256, _mm256_srli_epi16(v, 4));
	/* Arrange bits defining ASCII symbols in the column bitmaps. */
	__m256i arbits = _mm256_shuffle_epi8(__C.ARF256, arows);
	/*
	 * Determine whether bits for @str characters are set in
	 * appropriate bitmaps.
	 */
	__m256i sbits = _mm256_and_si256(arbits, acbm);
	/*
	 * Set most significant bits for bytes which contain set bitmap bits
	 * such that following PMOVMSKB gathers the bitmap matching results
	 * to 64bit integer.
	 */
	v = _mm256_cmpeq_epi8(sbits, _mm256_setzero_si256());
	r = 0xffffffff00000000UL | _mm256_movemask_epi8(v);

	return __tzcnt(r);
}

static inline size_t
__tfw_strspn_avx2_64(const char *str, __m256i sm)
{
	unsigned long r0, r1;

	__m256i v0 = _mm256_lddqu_si256((void *)str);
	__m256i v1 = _mm256_lddqu_si256((void *)(str + 32));

	__m256i acbm0 = _mm256_shuffle_epi8(sm, v0);
	__m256i acbm1 = _mm256_shuffle_epi8(sm, v1);

	__m256i arows0 = _mm256_and_si256(__C.LSH256, _mm256_srli_epi16(v0, 4));
	__m256i arows1 = _mm256_and_si256(__C.LSH256, _mm256_srli_epi16(v1, 4));

	__m256i arbits0 = _mm256_shuffle_epi8(__C.ARF256, arows0);
	__m256i arbits1 = _mm256_shuffle_epi8(__C.ARF256, arows1);

	__m256i sbits0 = _mm256_and_si256(arbits0, acbm0);
	__m256i sbits1 = _mm256_and_si256(arbits1, acbm1);

	v0 = _mm256_cmpeq_epi8(sbits0, _mm256_setzero_si256());
	v1 = _mm256_cmpeq_epi8(sbits1, _mm256_setzero_si256());

	r0 = _mm256_movemask_epi8(v0);
	r1 = _mm256_movemask_epi8(v1);

	return __tzcnt(r0 ^ (r1 << 32));
}

static inline size_t
__tfw_strspn_avx2_128(const char *str, __m256i sm)
{
	unsigned long r0, r1;

	__m256i v0 = _mm256_lddqu_si256((void *)str);
	__m256i v1 = _mm256_lddqu_si256((void *)(str + 32));
	__m256i v2 = _mm256_lddqu_si256((void *)(str + 64));
	__m256i v3 = _mm256_lddqu_si256((void *)(str + 96));

	__m256i acbm0 = _mm256_shuffle_epi8(sm, v0);
	__m256i acbm1 = _mm256_shuffle_epi8(sm, v1);
	__m256i acbm2 = _mm256_shuffle_epi8(sm, v2);
	__m256i acbm3 = _mm256_shuffle_epi8(sm, v3);

	__m256i arows0 = _mm256_and_si256(__C.LSH256, _mm256_srli_epi16(v0, 4));
	__m256i arows1 = _mm256_and_si256(__C.LSH256, _mm256_srli_epi16(v1, 4));
	__m256i arows2 = _mm256_and_si256(__C.LSH256, _mm256_srli_epi16(v2, 4));
	__m256i arows3 = _mm256_and_si256(__C.LSH256, _mm256_srli_epi16(v3, 4));

	__m256i arbits0 = _mm256_shuffle_epi8(__C.ARF256, arows0);
	__m256i arbits1 = _mm256_shuffle_epi8(__C.ARF256, arows1);
	__m256i arbits2 = _mm256_shuffle_epi8(__C.ARF256, arows2);
	__m256i arbits3 = _mm256_shuffle_epi8(__C.ARF256, arows3);

	__m256i sbits0 = _mm256_and_si256(arbits0, acbm0);
	__m256i sbits1 = _mm256_and_si256(arbits1, acbm1);
	__m256i sbits2 = _mm256_and_si256(arbits2, acbm2);
	__m256i sbits3 = _mm256_and_si256(arbits3, acbm3);

	v0 = _mm256_cmpeq_epi8(sbits0, _mm256_setzero_si256());
	v1 = _mm256_cmpeq_epi8(sbits1, _mm256_setzero_si256());
	v2 = _mm256_cmpeq_epi8(sbits2, _mm256_setzero_si256());
	v3 = _mm256_cmpeq_epi8(sbits3, _mm256_setzero_si256());

	r0 = _mm256_movemask_epi8(v1);
	r1 = _mm256_movemask_epi8(v3);
	r0 = (r0 << 32) | _mm256_movemask_epi8(v0);
	r1 = (r1 << 32) | _mm256_movemask_epi8(v2);
	r0 = __tzcnt(r0);
	r1 = __tzcnt(r1);

	return r0 < 64 ? r0 : 64 + r1;
}
#endif

static inline size_t
__tfw_strspn_sse_16(const char *str, __m128i sm)
{
	unsigned long r;

	__m128i v = _mm_lddqu_si128((void *)str);
	__m128i acbm = _mm_shuffle_epi8(sm, v);
	__m128i arows = _mm_and_si128(__C.LSH128, _mm_srli_epi16(v, 4));
	__m128i arbits = _mm_shuffle_epi8(__C.ARF128, arows);
	__m128i sbits = _mm_and_si128(arbits, acbm);
	v = _mm_cmpeq_epi8(sbits, _mm_setzero_si128());
	r = 0xffffffffffff0000UL | _mm_movemask_epi8(v);

	return __tzcnt(r);
}

static size_t
__tfw_strspn_simd(const char *str, size_t len, const unsigned char *tbl,
		  __m128i sm128
#ifdef AVX2
		  , __m256i sm256
#endif
		  )
{
	unsigned char *s = (unsigned char *)str;
	const unsigned char *end = s + len;
	unsigned int c0 = 0, c1 = 0, c2 = 0, c3 = 0;
	size_t n;

	/*
	 * Avoid heavyweight vector processing for small strings.
	 * Branch misprediction is more crucial for short strings.
	 */
	if (likely(len <= 4)) {
		switch (len) {
		case 0:
			return 0;
		case 4:
			c3 = tbl[s[3]];
		case 3:
			c2 = tbl[s[2]];
		case 2:
			c1 = tbl[s[1]];
		case 1:
			c0 = tbl[s[0]];
		}
		return (c0 & c1) == 0 ? c0 : 2 + (c2 ? c2 + c3 : 0);
	}
#ifdef AVX2
	/* Use unlikely() to speedup short strings processing. */
	for ( ; unlikely(s + 128 <= end); s += 128) {
		n = __tfw_strspn_avx2_128(s, sm256);
		if (n < 128)
			return s - (unsigned char *)str + n;
	}
	if (unlikely(s + 64 <= end)) {
		n = __tfw_strspn_avx2_64(s, sm256);
		if (n < 64)
			return s - (unsigned char *)str + n;
		s += 64;
	}
	if (unlikely(s + 32 <= end)) {
		n = __tfw_strspn_avx2_32(s, sm256);
		if (n < 32)
			return s - (unsigned char *)str + n;
		s += 32;
	}
#endif
	for ( ; unlikely(s + 16 <= end); s += 16) {
		n = __tfw_strspn_sse_16(s, sm128);
		if (n < 16)
			return s - (unsigned char *)str + n;
	}

	while (s + 4 <= end) {
		c0 = tbl[s[0]];
		c1 = tbl[s[1]];
		c2 = tbl[s[2]];
		c3 = tbl[s[3]];
		if (!(c0 & c1 & c2 & c3)) {
			n = s - (unsigned char *)str;
			return !(c0 & c1) ? n + c0 : n + 2 + (c2 ? c2 + c3 : 0);
		}
		s += 4;
	}
	c0 = c1 = c2 = 0;
	switch (end - s) {
	case 3:
		c2 = tbl[s[2]];
	case 2:
		c1 = tbl[s[1]];
	case 1:
		c0 = tbl[s[0]];
	}

	n = s - (unsigned char *)str;
	return !(c0 & c1) ? n + c0 : n + 2 + c2;
}

size_t
tfw_match_uri(const char *str, size_t len)
{
	size_t r;
#ifdef AVX2
	r = __tfw_strspn_simd(str, len, uri, __C.URI128, __C.URI256);
#else
	r = __tfw_strspn_simd(str, len, uri, __C.URI128);
#endif
	TFW_DBG3("%s: str[0]=%#x len=%lu r=%lu\n", __func__, str[0], len, r);

	return r;
}
EXPORT_SYMBOL(tfw_match_uri);

size_t
tfw_match_token(const char *str, size_t len)
{
	size_t r;
#ifdef AVX2
	r = __tfw_strspn_simd(str, len, token, __C.TOKEN128, __C.TOKEN256);
#else
	r = __tfw_strspn_simd(str, len, token, __C.TOKEN128);
#endif
	TFW_DBG3("%s: str[0]=%#x len=%lu r=%lu\n", __func__, str[0], len, r);

	return r;
}
EXPORT_SYMBOL(tfw_match_token);

size_t
tfw_match_qetoken(const char *str, size_t len)
{
	size_t r;
#ifdef AVX2
	r = __tfw_strspn_simd(str, len, qetoken, __C.QETOKEN128,
				 __C.QETOKEN256);
#else
	r = __tfw_strspn_simd(str, len, qetoken, __C.QETOKEN128);
#endif
	TFW_DBG3("%s: str[0]=%#x len=%lu r=%lu\n", __func__, str[0], len, r);

	return r;
}
EXPORT_SYMBOL(tfw_match_qetoken);

size_t
tfw_match_nctl(const char *str, size_t len)
{
	size_t r;
#ifdef AVX2
	r = __tfw_strspn_simd(str, len, nctl, __C.NCTL128, __C.NCTL256);
#else
	r = __tfw_strspn_simd(str, len, nctl, __C.NCTL128);
#endif
	TFW_DBG3("%s: str[0]=%#x len=%lu r=%lu\n", __func__, str[0], len, r);

	return r;
}
EXPORT_SYMBOL(tfw_match_nctl);

size_t
tfw_match_ctext_vchar(const char *str, size_t len)
{
	size_t r;
#ifdef AVX2
	r = __tfw_strspn_simd(str, len, ctext_vchar, __C.CTVCH128,
				 __C.CTVCH256);
#else
	r = __tfw_strspn_simd(str, len, ctext_vchar, __C.CTVCH128);
#endif
	TFW_DBG3("%s: str[0]=%#x len=%lu r=%lu\n", __func__, str[0], len, r);

	return r;
}
EXPORT_SYMBOL(tfw_match_ctext_vchar);

size_t
tfw_match_xff(const char *str, size_t len)
{
	size_t r;
#ifdef AVX2
	r = __tfw_strspn_simd(str, len, xff, __C.XFF128, __C.XFF256);
#else
	r = __tfw_strspn_simd(str, len, xff, __C.XFF128);
#endif
	TFW_DBG3("%s: str[0]=%#x len=%lu r=%lu\n", __func__, str[0], len, r);

	return r;
}
EXPORT_SYMBOL(tfw_match_xff);

size_t
tfw_match_cookie(const char *str, size_t len)
{
	size_t r;
#ifdef AVX2
	r = __tfw_strspn_simd(str, len, cookie_octet, __C.CO128, __C.CO256);
#else
	r = __tfw_strspn_simd(str, len, cookie_octet, __C.CO128);
#endif
	TFW_DBG3("%s: str[0]=%#x len=%lu r=%lu\n", __func__, str[0], len, r);

	return r;
}
EXPORT_SYMBOL(tfw_match_cookie);
