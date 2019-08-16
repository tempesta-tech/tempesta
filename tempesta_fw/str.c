/**
 *		Tempesta FW
 *
 * Tempesta chunked strings. The strings use SIMD instructions, so use them
 * carefully to not to call casually from sleepable context, e.g. on
 * configuration phase.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/crc32.h>

#include "lib/str.h"
#include "htype.h"
#include "str.h"

/**
 * Lower case conversion table.
 */
const unsigned char __tfw_lct[256] ____cacheline_aligned = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/* Tables for custom alphabets. */
bool custom_uri_enabled = false;
bool custom_token_enabled = false;
bool custom_qetoken_enabled = false;
bool custom_nctl_enabled = false;
bool custom_ctext_vchar_enabled = false;
bool custom_xff_enabled = false;
bool custom_cookie_enabled = false;

unsigned char custom_uri[256] ____cacheline_aligned __read_mostly;
unsigned char custom_token[256] ____cacheline_aligned __read_mostly;
unsigned char custom_qetoken[256] ____cacheline_aligned __read_mostly;
unsigned char custom_nctl[256] ____cacheline_aligned __read_mostly;
unsigned char custom_ctext_vchar[256] ____cacheline_aligned __read_mostly;
unsigned char custom_xff[256] ____cacheline_aligned __read_mostly;
unsigned char custom_cookie[256] ____cacheline_aligned __read_mostly;

#ifdef AVX2

/**
 * Custom alphabets (top and bottom ASCII halves) for AVX2 processing:
 * uri, token, qetoken, nctl, ctext_vchar, xff, cookie.
 */
unsigned char __CUSTOM[14][32] ____cacheline_aligned __read_mostly = {{0}};

extern size_t __tfw_match_custom(const char *str, size_t len,
				 const unsigned char *a,
				 const unsigned char *va0,
				 const unsigned char *va1);
extern size_t __tfw_match_ctext_vchar(const char *str, size_t len);

size_t
tfw_match_ctext_vchar(const char *str, size_t len)
{
	size_t r;

	if (custom_ctext_vchar_enabled)
		r = __tfw_match_custom(str, len, custom_ctext_vchar,
				       __CUSTOM[4], __CUSTOM[5]);
	else
		r = __tfw_match_ctext_vchar(str, len);

	TFW_DBG3("%s: str[0]=%#x len=%lu r=%lu\n", __func__, str[0], len, r);

	return r;
}
EXPORT_SYMBOL(tfw_match_ctext_vchar);

static void
__init_custom_a(const unsigned char *cfg_a, unsigned char *a, size_t c_off)
{
	unsigned char *a0 = __CUSTOM[c_off * 2], *a1 = __CUSTOM[c_off * 2 + 1];
	int i;

	memcpy(a, cfg_a, 256);

	/* Initializes an alphabet bit mask a0 by the byte set @a. */
	for (i = 0; i < 256; ++i) {
		if (!cfg_a[i])
			continue;
		a0[(i & 0xf) + 16 * !!(i & 0x80)] |= 1 << ((i & 0x70) >> 4);
	}
	/* Split ASCII table to 2 duplicate halves. */
	memcpy(a1, &a0[16], 16);
	memcpy(&a1[16], &a0[16], 16);
	memcpy(&a0[16], a0, 16);
}

#define TFW_INIT_CUSTOM_A(a_name, off)					\
void tfw_init_custom_##a_name(const unsigned char *a)			\
{									\
	custom_##a_name##_enabled = !!a;				\
	if (!!a)							\
		__init_custom_a(a, custom_##a_name, off);		\
}									\
EXPORT_SYMBOL(tfw_init_custom_##a_name);

TFW_INIT_CUSTOM_A(uri, 0);
TFW_INIT_CUSTOM_A(token, 1);
TFW_INIT_CUSTOM_A(qetoken, 2);
TFW_INIT_CUSTOM_A(nctl, 3);
TFW_INIT_CUSTOM_A(ctext_vchar, 4);
TFW_INIT_CUSTOM_A(xff, 5);
TFW_INIT_CUSTOM_A(cookie, 6);

#else
/**
 * Slow dummy C strings matching implementations just for compatibility
 * with old systems.
 */
/*
 * ASCII codes to accept URI string.
 *
 * While we can pack the array, which is 4 cache lines currently,
 * to just half of a cache line using 4 64-bit masks, it's much
 * faster to access the extra cache lines than to the 4 bit operations
 * (uri_a[c >> 6] & (1UL << (c & 0x3f))).
 */
static const unsigned char uri[] = {
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
 */
static const unsigned char token[] = {
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
 */
static const unsigned char qetoken[] = {
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
 */
static const unsigned char nctl[] = {
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
 */
static const unsigned char ctext_vchar[] = {
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
 * ASCII codes to accept X-Forwarded-For values.
 */
static const unsigned char xff[] = {
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
 * grammar.
 */
static const unsigned char cookie[] = {
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

static size_t
__tfw_match_slow(const char *str, size_t len, const unsigned char *tbl)
{
	unsigned char *s = (unsigned char *)str;
	size_t n;

	for (n = 0; n < len; ++n)
		if (!tbl[s[n]])
			break;

	return n;
}

#define TFW_MATCH(a_name)						\
size_t tfw_match_##a_name(const char *str, size_t len)			\
{									\
	size_t r;							\
	r = __tfw_match_slow(str, len, custom_##a_name##_enabled	\
					? custom_##a_name : a_name);	\
	TFW_DBG3("%s: str[0]=%#x len=%lu r=%lu\n",			\
		 __func__, str[0], len, r);				\
	return r;							\
}									\
EXPORT_SYMBOL(tfw_match_##a_name);

#define TFW_INIT_CUSTOM_A(a_name)					\
void tfw_init_custom_##a_name(const unsigned char a[256])		\
{									\
	custom_##a_name##_enabled = !!a;				\
	if (!!a)							\
		memcpy(custom_##a_name, a, 256);			\
}									\
EXPORT_SYMBOL(tfw_init_custom_##a_name);

TFW_MATCH(uri);
TFW_MATCH(token);
TFW_MATCH(qetoken);
TFW_MATCH(nctl);
TFW_MATCH(ctext_vchar);
TFW_MATCH(xff);
TFW_MATCH(cookie);

TFW_INIT_CUSTOM_A(uri);
TFW_INIT_CUSTOM_A(token);
TFW_INIT_CUSTOM_A(qetoken);
TFW_INIT_CUSTOM_A(nctl);
TFW_INIT_CUSTOM_A(ctext_vchar);
TFW_INIT_CUSTOM_A(xff);
TFW_INIT_CUSTOM_A(cookie);

#endif /* AVX2 */

/**
 * Quickly get number of digits - 1, e.g. returns '0' for '7' and '2' for '333'.
 * It's assumed that small numbers are likely.
 */
static inline unsigned int
__dig_num_dec(unsigned long a)
{
	if (a < 10)
		return 0;
	if (a < 100)
		return 1;
	if (a < 1000)
		return 2;
	if (a < 10000)
		return 3;
	if (a < 100000)
		return 4;
	if (a < 1000000)
		return 5;
	if (a < 10000000)
		return 6;
	if (a < 100000000)
		return 7;
	if (a < 1000000000)
		return 8;
	if (a < 10000000000)
		return 9;
	if (a < 100000000000UL)
		return 10;
	if (a < 1000000000000UL)
		return 11;
	if (a < 10000000000000UL)
		return 12;
	if (a < 100000000000000UL)
		return 13;
	if (a < 1000000000000000UL)
		return 14;
	if (a < 10000000000000000UL)
		return 15;
	if (a < 100000000000000000UL)
		return 16;
	if (a < 1000000000000000000UL)
		return 17;
	if (a < 10000000000000000000UL)
		return 18;
	return 19;
}

/**
 * Same as __dig_num_dec() but for hex conversion.
 */
static inline unsigned int
__dig_num_hex(unsigned long a)
{
	if (a == 0)
		return 0;
	return __fls(a) / 4;
}

/**
 * Convert an integer @ai to a string @buf, don't insert training '\0'.
 * @len - maximum string length.
 * @return number of characters written.
 */
size_t
tfw_ultoa(unsigned long ai, char *buf, unsigned int len)
{
	size_t n = __dig_num_dec(ai);
	char *p = buf + n;

	if (unlikely(n + 1 > len))
		return 0;

	do {
		/* Compiled to only one MUL instruction with -O2. */
		*p-- = "0123456789"[ai % 10];
		ai /= 10;
	} while (ai);

	return n + 1;
}
EXPORT_SYMBOL(tfw_ultoa);

/**
 * Same as @tfw_ultoa() but constructs hexadecimal value.
 */
size_t
tfw_ultohex(unsigned long ai, char *buf, unsigned int len)
{
	size_t n = __dig_num_hex(ai);
	char *p = buf + n;

	if (unlikely(n + 1 > len))
		return 0;

	do {
		/* Compiled to only one MUL instruction with -O2. */
		*p-- = "0123456789abcdef"[ai % 16];
		ai /= 16;
	} while (ai);

	return n + 1;
}
EXPORT_SYMBOL(tfw_ultohex);

void
tfw_str_del_chunk(TfwStr *str, int id)
{
	unsigned int cn = str->nchunks;

	if (unlikely(TFW_STR_PLAIN(str)))
		return;
	BUG_ON(TFW_STR_DUP(str));
	BUG_ON(id >= cn);

	if (str->nchunks == 2) {
		/* Just fall back to plain string. */
		*str = *(str->chunks + (id ^ 1));
		return;
	}

	str->len -= TFW_STR_CHUNK(str, id)->len;
	str->nchunks--;
	/* Move all chunks after @id. */
	memmove(str->chunks + id, str->chunks + id + 1,
		(cn - id - 1) * sizeof(TfwStr));
}

/**
 * Collect string chunks into @out beginning from @chunk to the @end or
 * until the @stop char is found (at the beginning of some chunk).
 *
 * NOTE: this function is intended to collect subchunks of compound
 * strings, so the @chunk must be the plain string only.
 */
void tfw_str_collect_cmp(TfwStr *chunk, TfwStr *end, TfwStr *out,
			 const char *stop)
{
	TfwStr *next;

	BUG_ON(!TFW_STR_PLAIN(chunk));

	if (unlikely(chunk == end)) {
		bzero_fast(out, sizeof(*out));
		return;
	}

	/* If this is last chunk, just return it in this case. */
	next = chunk + 1;
	if (likely(next == end || (stop && *next->data == *stop))) {
		*out = *chunk;
		return;
	}

	/* Add chunks to out-string. */
	out->chunks = chunk;
	out->flags = 0;
	out->len = 0;
	out->eolen = 0;
	out->nchunks = 0;

	for (; chunk != end; ++chunk) {
		if (stop && *chunk->data == *stop)
			break;
		out->nchunks++;
		out->len += chunk->len;
	}
	BUG_ON(out->nchunks < 2);
}

/**
 * Grow @str for @n new chunks.
 * New branches of the string tree are created on 2nd level only,
 * i.e. there is no possibility to grow number of chunks of duplicate string.
 * Pass pointer to one of the duplicates to do so.
 * @flag - 0 or TFW_STR_DUPLICATE. 0 - grow as compound string,
 * TFW_STR_DUPLICATE - grow as duplicate string
 * @return pointer to the first of newly added chunk.
 *
 * TODO do we need exponential growing?
 */
static TfwStr *
__str_grow_tree(TfwPool *pool, TfwStr *str, unsigned int flag, int n)
{
	if (str->flags & flag ||
	    (!flag && str->nchunks)) {
		unsigned int l;
		void *p;

		if (unlikely(str->nchunks >= __TFW_STR_CN_MAX)) {
			TFW_WARN("Reaching chunks hard limit\n");
			return NULL;
		}

		l = str->nchunks * sizeof(TfwStr);
		p = tfw_pool_realloc(pool, str->data, l,
				     l + n * sizeof(TfwStr));
		if (!p)
			return NULL;
		str->data = p;
		str->nchunks += n;
	}
	else {
		TfwStr *a = tfw_pool_alloc(pool, (n + 1) * sizeof(TfwStr));
		if (!a)
			return NULL;
		a[0] = *str;
		str->chunks = a;
		str->nchunks = n + 1;
	}

	str = str->chunks + str->nchunks - n;
	bzero_fast(str, sizeof(TfwStr) * n);

	return str;
}

/**
 * Add compound piece to @str and return pointer to the piece.
 */
TfwStr *
tfw_str_add_compound(TfwPool *pool, TfwStr *str)
{
	/* Need to specify exact string duplicate to grow. */
	BUG_ON(TFW_STR_DUP(str));

	return __str_grow_tree(pool, str, 0, 1);
}

/**
 * Add place for a new duplicate to string tree @str,
 * the string is probably already a set of duplicate compound strings.
 */
TfwStr *
tfw_str_add_duplicate(TfwPool *pool, TfwStr *str)
{
	TfwStr *dup_str = __str_grow_tree(pool, str, TFW_STR_DUPLICATE, 1);

	/* Length for set of duplicate strings has no sense. */
	str->len = 0;
	str->flags |= TFW_STR_DUPLICATE;

	return dup_str;
}

/**
 * Function for deep TfwStr copying.
 */
int
tfw_strcpy(TfwStr *dst, const TfwStr *src)
{
	int n1, n2, o1 = 0, o2 = 0, chunks = 0;
	int mode = (TFW_STR_PLAIN(src) << 1) | TFW_STR_PLAIN(dst);
	TfwStr *c1, *c2, *end;

	BUG_ON(TFW_STR_DUP(dst));
	BUG_ON(TFW_STR_DUP(src));

	/* After the check we don't need to control @dst chunks overrun. */
	if (unlikely(src->len > dst->len))
		return -E2BIG;

	switch (mode) {
	case 3: /* The both are plain. */
		memcpy_fast(dst->data, src->data, min(src->len, dst->len));
		break;
	case 1: /* @src is compound, @dst is plain. */
		n1 = src->nchunks;
		end = src->chunks + n1;
		for (c1 = src->chunks; c1 < end; ++c1) {
			memcpy_fast(dst->data + o2, c1->data, c1->len);
			o2 += c1->len;
		}
		BUG_ON(o2 != src->len);
		break;
	case 2: /* @src is plain, @dst is compound. */
		for (c2 = dst->chunks; o1 < src->len; ++c2) {
			/* Update length of the last chunk. */
			c2->len = min(c2->len, src->len - o1);
			memcpy_fast(c2->data, src->data + o1, c2->len);
			++chunks;
			o1 += c2->len;
		}
		break;
	case 0: /* The both are compound. */
		n1 = src->nchunks;
		n2 = dst->nchunks;
		c1 = src->chunks;
		c2 = dst->chunks;
		end = c1 + n1 - 1;
		while (1) {
			int _n = min(c1->len - o1, c2->len - o2);
			memcpy_fast(c2->data + o2, c1->data + o1,
				    _n);
			if (c1 == end && _n == c1->len - o1) {
				/* Adjust @dst last chunk length. */
				c2->len = o2 + _n;
				++chunks;
				break;
			}
			if (c1->len - o1 == c2->len - o2) {
				++c1;
				++c2;
				++chunks;
				o1 = o2 = 0;
			}
			else if (_n == c1->len - o1) {
				++c1;
				o1 = 0;
				o2 += _n;
			}
			else {
				++c2;
				++chunks;
				o2 = 0;
				o1 += _n;
			}
		}
	}

	/* Set resulting number of chunks, forget about others. */
	dst->nchunks = chunks;
	dst->len = src->len;

	return 0;
}
EXPORT_SYMBOL(tfw_strcpy);

/**
 * Same as tfw_strcpy but allocate chunks to create exact copy of the string,
 * including number of chunks.
 */
TfwStr *
tfw_strdup(TfwPool *pool, const TfwStr *src)
{
	size_t n;
	TfwStr *dst, *d_c;
	const TfwStr *s_c, *end;
	char *data;

	n = (src->nchunks + 1) * sizeof(TfwStr) + src->len;
	dst = (TfwStr *)tfw_pool_alloc(pool, n);
	if (!dst)
		return NULL;

	*dst = *src;
	dst->chunks = dst + 1;
	data = (char *)(TFW_STR_LAST(dst) + 1);

	d_c = TFW_STR_CHUNK(dst, 0);
	TFW_STR_FOR_EACH_CHUNK(s_c, src, end) {
		*d_c = *s_c;
		d_c->data = data;
		memcpy_fast(data, s_c->data, s_c->len);
		data += s_c->len;
		++d_c;
	}

	return dst;
}

/**
 * Function for copying of TfwStr descriptors only.
 */
int
tfw_strcpy_desc(TfwStr *dst, TfwStr *src)
{
	TfwStr *c1, *c2, *end;
	int src_num = src->nchunks;
	int dst_num = dst->nchunks;

	/*
	 * Only TfwStr descriptors with identical complexity
	 * and chunks number are allowed.
	 */
	if (unlikely(src_num != dst_num))
		return -E2BIG;

	c2 = dst_num ? dst->chunks : dst;
	TFW_STR_FOR_EACH_CHUNK(c1, src, end) {
		*c2 = *c1;
		++c2;
	}
	if (dst_num) {
		/* The src and dst are compound. */
		dst->len = src->len;
		dst->flags = src->flags;
	}

	return 0;
}
EXPORT_SYMBOL(tfw_strcpy_desc);

static inline int
__tfw_str_insert(TfwPool *pool, TfwStr *dst, TfwStr *src, unsigned int chunk)
{
	int n = src->nchunks ? : 1;
	int last_chunk = TFW_STR_PLAIN(dst) ? 1 : dst->nchunks;
	TfwStr *to, *c, *end;

	BUG_ON(TFW_STR_DUP(dst));
	BUG_ON(TFW_STR_DUP(src));

	to = __str_grow_tree(pool, dst, 0, n);
	if (!to)
		return -ENOMEM;

	if (chunk != last_chunk) {
		memmove(dst->chunks + chunk + n, dst->chunks + chunk,
			sizeof(TfwStr) * (dst->nchunks - chunk - n));
		to = dst->chunks + chunk;
	}

	n = 0;
	TFW_STR_FOR_EACH_CHUNK(c, src, end) {
		n += c->len;
		*to = *c;
		++to;
	}
	dst->len += n;

	return 0;
}

/**
 * Insert string @src into @dst string before chunk @chunk.
 */
int
tfw_str_insert(TfwPool *pool, TfwStr *dst, TfwStr *src, unsigned int chunk)
{
	if (unlikely(chunk > (TFW_STR_PLAIN(dst) ? 1 : dst->nchunks)))
		return -ERANGE;

	return __tfw_str_insert(pool, dst, src, chunk);
}
EXPORT_SYMBOL(tfw_str_insert);

int
tfw_strcat(TfwPool *pool, TfwStr *dst, TfwStr *src)
{
	return __tfw_str_insert(pool, dst, src,
				TFW_STR_PLAIN(dst) ? 1 : dst->nchunks);
}
EXPORT_SYMBOL(tfw_strcat);

/**
 * Like strcmp/strcasecmp(3) for TfwStr, but returns 0 the strings match
 * and non-zero otherwise. If the strings have equal prefix, but different
 * length, then the large string is considered bigger.
 *
 * Do not use it for duplicate strings, rather call it for each duplicate
 * substring separately.
 * @cs - case sensitive
 */
int
__tfw_strcmp(const TfwStr *s1, const TfwStr *s2, int cs)
{
	int i1, i2, off1, off2;
	long n;
	const TfwStr *c1, *c2;
	typeof(&strncmp) cmp = cs ? (typeof(&strncmp))memcmp_fast
				  : tfw_cstricmp;

	BUG_ON((s1->flags | s2->flags) & TFW_STR_DUPLICATE);
	if (unlikely(!s1->len || !s2->len))
		goto out;

	i1 = i2 = 0;
	off1 = off2 = 0;
	n = min(s1->len, s2->len);
	c1 = TFW_STR_CHUNK(s1, 0);
	c2 = TFW_STR_CHUNK(s2, 0);
	while (n) {
		int cn = min(c1->len - off1, c2->len - off2);
		int r = (*cmp)(c1->data + off1,
			       c2->data + off2, cn);
		if (r)
			return r;

		n -= cn;
		if (cn == c1->len - off1) {
			off1 = 0;
			++i1;
			c1 = TFW_STR_CHUNK(s1, i1);
		} else {
			off1 += cn;
		}
		if (cn == c2->len - off2) {
			off2 = 0;
			++i2;
			c2 = TFW_STR_CHUNK(s2, i2);
		} else {
			off2 += cn;
		}
		BUG_ON(n && (!c1 || !c2));
	}
out:
	return s1->len == s2->len ? 0 : (long)s1->len - (long)s2->len;
}
EXPORT_SYMBOL(__tfw_strcmp);

/**
 * Core routine for tfw_stricmpspn() working on flat C strings.
 * For now the function is used for very small strings, like matching HTTP
 * headers until ':', so plain C is Ok for now.
 *
 * Returns:
 *   0		- strings match;
 *   INT_MAX	- strings match and @stop is found;
 *   -1		- strings do not match, @s1 < @s2;
 *   1		- strings do not match, @s1 > @s2;
 *
 * While the function isn't so fast, we've never seen it in perf top, so leave
 * it as is until we have some performance issues with it.
 */
static inline int
__cstricmpspn(const unsigned char *s1, const unsigned char *s2, int n, int stop,
	      int cs)
{
	unsigned char c1, c2;

	while (n) {
		if (cs) {
			c1 = *s1++;
			c2 = *s2++;
		}
		else {
			c1 = TFW_LC(*s1++);
			c2 = TFW_LC(*s2++);
		}
		if (c1 != c2)
			return (c1 < c2) ? -1 : 1;
		if (unlikely(c1 == stop))
			return INT_MAX;
		n--;
	}

	return 0;
}

/**
 * Like strcmp/strcasecmp(3) for TfwStr, but stops matching when faces @stop.
 * Do not use it for duplicate strings, rather call it for each duplicate
 * substring separately. Note that it uses slow C-implemented string matcher,
 * so use it for short strings only.
 *
 * @cs - case sensitive
 * @returns 0 if the stings match, 1 if @s1 > @s2 and -1 otherwise, so the
 * function can be used for binary search. If the strings have equal prefix,
 * but different length, then the large string is considered bigger. Comparison
 * ends on meeting @stop symbol or end of the shorter string.
 */
int
__tfw_strcmpspn(const TfwStr *s1, const TfwStr *s2, int stop, int cs)
{
	int i1, i2, off1, off2;
	long n;
	const TfwStr *c1, *c2;

	BUG_ON((s1->flags | s2->flags) & TFW_STR_DUPLICATE);
	BUG_ON(!stop);
	if (unlikely(!s1->len || !s2->len))
		goto out;

	i1 = i2 = 0;
	off1 = off2 = 0;
	n = min(s1->len, s2->len);
	c1 = TFW_STR_CHUNK(s1, 0);
	c2 = TFW_STR_CHUNK(s2, 0);
	while (n) {
		int cn = min(c1->len - off1, c2->len - off2);
		int r = __cstricmpspn((unsigned char *)c1->data + off1,
				      (unsigned char *)c2->data + off2,
				      cn, stop, cs);
		if (r == INT_MAX)
			return 0;
		if (r)
			return r;

		n -= cn;
		if (cn == c1->len - off1) {
			off1 = 0;
			++i1;
			c1 = TFW_STR_CHUNK(s1, i1);
		} else {
			off1 += cn;
		}
		if (cn == c2->len - off2) {
			off2 = 0;
			++i2;
			c2 = TFW_STR_CHUNK(s2, i2);
		} else {
			off2 += cn;
		}
		BUG_ON(n && (!c1 || !c2));
	}
out:
	return s1->len == s2->len ? 0 : (long)s1->len - (long)s2->len;
}
EXPORT_SYMBOL(__tfw_strcmpspn);

/**
 * Generic function for comparing TfwStr and C strings.
 *
 * @str may be either plain or compound.
 *
 * @cstr_len is used for performance purposes.
 * The length may be pre-computed by the caller and saved between calls.
 *
 * @cstr is not required to be terminated.
 *
 * @flags allow to specify the following options:
 *  - TFW_STR_EQ_PREFIX
 *      The @cstr is a prefix, only first @cstr_len chars are compared, and the
 *      rest of @str is ignored.
 *  - TFW_STR_EQ_CASEI
 *      Use case-insensitive comparison function.
 *
 * @return true if the strings are equal and false otherwise.
 */
bool
tfw_str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len,
		tfw_str_eq_flags_t flags)
{
	int len, clen = cstr_len;
	const TfwStr *chunk, *end;
	typeof(&strncmp) cmp = (flags & TFW_STR_EQ_CASEI)
			       ? tfw_cstricmp
			       : (typeof(&strncmp))memcmp_fast;

	BUG_ON(str->len && !str->data);
	TFW_STR_FOR_EACH_CHUNK(chunk, str, end) {
		BUG_ON(chunk->len &&  !chunk->data);

		len = min(clen, (int)chunk->len);
		if (cmp(cstr, chunk->data, len))
			return false;

		/*
		 * Relatively specific case, so leave it here and
		 * don't move it to begin of the function.
		 */
		if ((int)chunk->len > clen)
			return (flags & TFW_STR_EQ_PREFIX);

		cstr += len;
		clen -= len;
	}

	return !clen;
}
EXPORT_SYMBOL(tfw_str_eq_cstr);

/**
 * Same as @tfw_str_eq_cstr, but compares a substring of @str taken from the
 * position @pos with linear @cstr of length @cstr_len.
 *
 * Beware! The function has side effects and may and likely will **modify** a
 * chunk of the source @str for a while...
 *
 * Uses the @tfw_str_eq_cstr as the basis.
 */
bool
tfw_str_eq_cstr_pos(const TfwStr *str, const char *pos, const char *cstr,
		    int cstr_len, tfw_str_eq_flags_t flags)
{
	bool r = false;
	TfwStr tmp = *str;
	const TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(str));
	BUG_ON(!pos || !cstr || !cstr_len);

	TFW_STR_FOR_EACH_CHUNK(c, &tmp, end) {
		long offset = pos - c->data;

		if (offset >= 0 && (offset < c->len)) {
			TfwStr t = *c, *v = (TfwStr *)c;

			v->data += offset;
			v->len -= offset;

			r = tfw_str_eq_cstr(&tmp, cstr, cstr_len, flags);

			*v = t; /* Restore the chunk */
			goto out;
		}

		tmp.len -= c->len;
		tmp.chunks++;

		tmp.nchunks--;
	}
out:
	return r;
}
EXPORT_SYMBOL(tfw_str_eq_cstr_pos);

/**
 * Compare @str starting at offset @offset with a plain C string
 * @cstr of size @len. Obey the comparison flags @flags.
 *
 * The function prepares a substring of @str and then calls
 * tfw_str_eq_cstr(). Note that a chunk of @str is modified in the
 * process, but the original contents is restored before the result
 * is returned to the caller.
 */
bool
tfw_str_eq_cstr_off(const TfwStr *str, ssize_t offset, const char *cstr,
		    int cstr_len, tfw_str_eq_flags_t flags)
{
	bool ret = false;
	TfwStr t, tmp = *str;
	TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(str));
	BUG_ON(!cstr || !cstr_len);

	if (offset < 0)
		return false;
	if (offset == 0)
		return tfw_str_eq_cstr(str, cstr, cstr_len, flags);
	if (unlikely(offset + cstr_len > str->len))
		return false;

	TFW_STR_FOR_EACH_CHUNK(c, &tmp, end) {
		if (offset >= c->len) {
			offset -= c->len;
			tmp.len -= c->len;
			tmp.chunks++;
			tmp.nchunks--;
			continue;
		}
		t = *c;
		c->data += offset;
		c->len -= offset;

		ret = tfw_str_eq_cstr(&tmp, cstr, cstr_len, flags);

		*c = t; /* Restore the chunk */
		break;
	}

	return ret;
}
EXPORT_SYMBOL(tfw_str_eq_cstr_off);

/**
 * The function intentionally breaks zero-copy string design. And should
 * be used for short-strings only.
 *
 * Join all chunks of @str to a single plain C string.
 *
 * The function copies all chunks of the @str to the @out_buf.
 * If the buffer has not enough space to fit all chunks, then the output string
 * is cropped (at most @buf_size - 1 bytes is written). The output string is
 * always terminated with '\0'.
 *
 * Caveat: Be sure to free memory block as soon as possible. Leaving it
 * allocated could ruin successful tfw_pool_realloc() sequence, and cause
 * excessive copying. Since TfwPool is using stack-like approach, it's
 * possible to allocate temporary storage for tfw_str_to_cstr() result,
 * then free it, and successfully continue tfw_pool_realloc() sequence.
 *
 * Returns length of the output string.
 *
 */
size_t
tfw_str_to_cstr(const TfwStr *str, char *out_buf, int buf_size)
{
	const TfwStr *chunk, *end;
	char *pos = out_buf;
	int len;

	BUG_ON(!out_buf || buf_size <= 0);

	--buf_size; /* Reserve one byte for '\0'. */

	TFW_STR_FOR_EACH_CHUNK(chunk, str, end) {
		len = min(buf_size, (int)chunk->len);
		strncpy(pos, chunk->data, len);
		pos += len;
		buf_size -= len;

		if (unlikely(!buf_size))
			break;
	}

	*pos = '\0';

	return (pos - out_buf);
}
EXPORT_SYMBOL(tfw_str_to_cstr);

/**
 * HTTP parser can break strings into several chunks and mark some of them
 * with TFW_STR_VALUE flag. Single string value may occupy more than one chunk,
 * independent string values divided by non-flagged chunks.
 *
 * Return compound TfwStr starting at next string value.
 */
TfwStr
tfw_str_next_str_val(const TfwStr *str)
{
	TfwStr r_str = { 0 }, *chunk, *end;
	bool skip = true;

	BUG_ON(TFW_STR_DUP(str));
	if (!str || TFW_STR_PLAIN(str))
		return r_str;

	end =  str->chunks + str->nchunks;
	r_str.nchunks = str->nchunks;
	r_str.len = str->len;

	for (chunk = str->chunks; chunk != end; ++chunk) {
		if (!skip && (chunk->flags & TFW_STR_VALUE))
			break;
		if (!(chunk->flags & TFW_STR_VALUE))
			skip = false;
		r_str.len -= chunk->len;
		r_str.nchunks--;
	}
	if (unlikely(chunk == end))
		TFW_STR_INIT(&r_str);
	else
		r_str.chunks = chunk;

	return r_str;
}
EXPORT_SYMBOL(tfw_str_next_str_val);

/**
 * Function for crc32 calculation from TfwStr object.
 */
u32
tfw_str_crc32_calc(const TfwStr *str)
{
	const TfwStr *c, *end;
	u32 crc = 0;

	BUG_ON(str->len && !str->data);
	TFW_STR_FOR_EACH_CHUNK(c, str, end)
		crc = crc32(crc, c->data, c->len);

	return crc;
}
EXPORT_SYMBOL(tfw_str_crc32_calc);

#ifdef DEBUG
void
tfw_str_dprint(const TfwStr *str, const char *msg)
{
	const TfwStr *dup, *dup_end, *c, *chunk_end;

	TFW_DBG("%s: addr=%p skb=%p len=%lu flags=%x eolen=%u:\n", msg,
		str, str->skb, str->len, str->flags, str->eolen);
	TFW_STR_FOR_EACH_DUP(dup, str, dup_end) {
		TFW_DBG("  duplicate %p, len=%lu, flags=%x eolen=%u:\n",
			dup, dup->len, dup->flags, dup->eolen);
		TFW_STR_FOR_EACH_CHUNK(c, dup, chunk_end)
			TFW_DBG("   len=%lu, eolen=%u ptr=%p flags=%x '%.*s'\n",
				c->len, c->eolen, c->data, c->flags,
				(int)c->len, c->data);
	}
}
EXPORT_SYMBOL(tfw_str_dprint);

#define D(n)	(unsigned int)v[n]

void
tfw_dbg_vprint32(const char *prefix, const unsigned char *v)
{
	if (IS_ERR(v)) {
		T_DBG3("%s: bad ptr (%pK)\n", prefix, v);
		return;
	}
	T_DBG3("%s (ptr=%pK): %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x"
	       " %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x"
	       " %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x"
	       " %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",
	       prefix, v, D(0), D(1), D(2), D(3), D(4), D(5), D(6), D(7),
	       D(8), D(9), D(10), D(11), D(12), D(13), D(14), D(15),
	       D(16), D(17), D(18), D(19), D(20), D(21), D(22), D(23),
	       D(24), D(25), D(26), D(27), D(28), D(29), D(30), D(31));
}
EXPORT_SYMBOL(tfw_dbg_vprint32);

#endif
