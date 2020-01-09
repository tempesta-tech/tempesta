/*
 *		Tempesta TLS
 *
 * Privacy Enhanced Mail (PEM) decoding
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "crypto.h"
#include "pem.h"
#include "tls_internal.h"

static const unsigned char base64_dec_map[128] = {
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
	127, 127, 127,  62, 127, 127, 127,  63,  52,  53,
	 54,  55,  56,  57,  58,  59,  60,  61, 127, 127,
	127,  64, 127, 127, 127,   0,   1,   2,   3,   4,
	  5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
	 15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
	 25, 127, 127, 127, 127, 127, 127,  26,  27,  28,
	 29,  30,  31,  32,  33,  34,  35,  36,  37,  38,
	 39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
	 49,  50,  51, 127, 127, 127, 127, 127
};

static int
ttls_base64_decode(unsigned char *dst, size_t dlen, size_t *olen,
		   const unsigned char *src, size_t slen)
{
	size_t i, n;
	uint32_t j, x;
	unsigned char *p;

	/* First pass: check for validity and get output length */
	for (i = n = j = 0; i < slen; i++) {
		/* Skip spaces before checking for EOL */
		x = 0;
		while (i < slen && src[i] == ' ') {
			++i;
			++x;
		}

		/* Spaces at end of buffer are OK */
		if (i == slen)
			break;

		if ((slen - i) >= 2 && src[i] == '\r' && src[i + 1] == '\n')
			continue;

		if (src[i] == '\n')
			continue;

		/* Space inside a line is an error */
		if (x)
			return TTLS_ERR_BASE64_INVALID_CHARACTER;
		if (src[i] == '=' && ++j > 2)
			return TTLS_ERR_BASE64_INVALID_CHARACTER;
		if (src[i] > 127 || base64_dec_map[src[i]] == 127)
			return TTLS_ERR_BASE64_INVALID_CHARACTER;

		if (base64_dec_map[src[i]] < 64 && j)
			return TTLS_ERR_BASE64_INVALID_CHARACTER;

		n++;
	}

	if (!n) {
		*olen = 0;
		return 0;
	}

	/* The following expression is to calculate the following formula
	 * without risk of integer overflow in n:
	 *	 n = ((n * 6) + 7) >> 3;
	 */
	n = (6 * (n >> 3)) + ((6 * (n & 0x7) + 7) >> 3);
	n -= j;

	if (!dst || dlen < n) {
		*olen = n;
		return TTLS_ERR_BASE64_BUFFER_TOO_SMALL;
	}

	for (j = 3, n = x = 0, p = dst; i > 0; i--, src++) {
		if (*src == '\r' || *src == '\n' || *src == ' ')
			continue;

		j -= (base64_dec_map[*src] == 64);
		x  = (x << 6) | (base64_dec_map[*src] & 0x3F);

		if (++n == 4) {
			n = 0;
			if (j > 0)
				*p++ = (unsigned char)(x >> 16);
			if (j > 1)
				*p++ = (unsigned char)(x >> 8);
			if (j > 2)
				*p++ = (unsigned char)x;
		}
	}

	*olen = p - dst;

	return 0;
}

/**
 * @return length of decoded data or negative value on error.
 */
int
ttls_pem_read_buffer(const char *header, const char *footer,
		     unsigned char *data, size_t *use_len)
{
	int ret;
	size_t len;
	const unsigned char *s1, *s2, *end;

	s1 = (unsigned char *)strstr((const char *)data, header);
	if (!s1)
		return TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;

	s2 = (unsigned char *)strstr((const char *)data, footer);
	if (!s2 || s2 <= s1)
		return TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;

	s1 += strlen(header);
	if (*s1 == ' ' )
		s1++;
	if (*s1 == '\r')
		s1++;
	if (*s1 == '\n')
		s1++;
	else
		return TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;

	end = s2;
	end += strlen(footer);
	if (*end == ' ')
		end++;
	if (*end == '\r')
		end++;
	if (*end == '\n')
		end++;
	*use_len = end - data;

	if (s2 - s1 >= 22 && !memcmp(s1, "Proc-Type: 4,ENCRYPTED", 22))
		return TTLS_ERR_PEM_FEATURE_UNAVAILABLE;

	if (s1 >= s2)
		return TTLS_ERR_PEM_INVALID_DATA;

	ret = ttls_base64_decode(NULL, 0, &len, s1, s2 - s1);
	if (ret == TTLS_ERR_BASE64_INVALID_CHARACTER)
		return TTLS_ERR_PEM_INVALID_DATA + ret;
	BUG_ON(len > *use_len);

	/* Overwrite the buffer content by decoded data. */
	if ((ret = ttls_base64_decode(data, len, &len, s1, s2 - s1)))
		return TTLS_ERR_PEM_INVALID_DATA + ret;

	return len;
}
