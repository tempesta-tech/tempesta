/*
 *  Privacy Enhanced Mail (PEM) decoding
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#include "pem.h"
#include "base64.h"
#include "cipher.h"

/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}

void ttls_pem_init(ttls_pem_context *ctx)
{
	memset(ctx, 0, sizeof(ttls_pem_context));
}

int ttls_pem_read_buffer(ttls_pem_context *ctx, const char *header, const char *footer,
		 const unsigned char *data, size_t *use_len)
{
	int ret, enc;
	size_t len;
	unsigned char *buf;
	const unsigned char *s1, *s2, *end;

	if (ctx == NULL)
		return(TTLS_ERR_PEM_BAD_INPUT_DATA);

	s1 = (unsigned char *) strstr((const char *) data, header);

	if (s1 == NULL)
		return(TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT);

	s2 = (unsigned char *) strstr((const char *) data, footer);

	if (s2 == NULL || s2 <= s1)
		return(TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT);

	s1 += strlen(header);
	if (*s1 == ' ' ) s1++;
	if (*s1 == '\r') s1++;
	if (*s1 == '\n') s1++;
	else return(TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT);

	end = s2;
	end += strlen(footer);
	if (*end == ' ' ) end++;
	if (*end == '\r') end++;
	if (*end == '\n') end++;
	*use_len = end - data;

	enc = 0;

	if (s2 - s1 >= 22 && memcmp(s1, "Proc-Type: 4,ENCRYPTED", 22) == 0)
		return(TTLS_ERR_PEM_FEATURE_UNAVAILABLE);

	if (s1 >= s2)
		return(TTLS_ERR_PEM_INVALID_DATA);

	ret = ttls_base64_decode(NULL, 0, &len, s1, s2 - s1);

	if (ret == TTLS_ERR_BASE64_INVALID_CHARACTER)
		return(TTLS_ERR_PEM_INVALID_DATA + ret);

	if ((buf = ttls_calloc(1, len)) == NULL)
		return(TTLS_ERR_PEM_ALLOC_FAILED);

	if ((ret = ttls_base64_decode(buf, len, &len, s1, s2 - s1)) != 0)
	{
		ttls_zeroize(buf, len);
		ttls_free(buf);
		return(TTLS_ERR_PEM_INVALID_DATA + ret);
	}

	if (enc != 0)
	{
		ttls_zeroize(buf, len);
		ttls_free(buf);
		return(TTLS_ERR_PEM_FEATURE_UNAVAILABLE);
	}

	ctx->buf = buf;
	ctx->buflen = len;

	return 0;
}

void ttls_pem_free(ttls_pem_context *ctx)
{
	if (ctx->buf != NULL)
		ttls_zeroize(ctx->buf, ctx->buflen);
	ttls_free(ctx->buf);
	ttls_free(ctx->info);

	ttls_zeroize(ctx, sizeof(ttls_pem_context));
}
