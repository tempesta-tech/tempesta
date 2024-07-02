/**
 *		Tempesta TLS mocks for the unit tests
 *
 * Copyright (C) 2018-2024 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TTLS_MOCKS_H__
#define __TTLS_MOCKS_H__

#define NR_CPUS 1
#include "ktest.h"

#define TLS_MAX_PAYLOAD_SIZE	((size_t)1 << 14)

#include "ttls.h"

#define EXPECT_FALSE(c)		BUG_ON(c)
#define EXPECT_TRUE(c)		BUG_ON(!(c))
#define EXPECT_ZERO(c)		BUG_ON((c) != 0)
#define EXPECT_EQ(c, v)		BUG_ON((c) != (v))
#define EXPECT_NOT_NULL(v)	BUG_ON((v) == NULL)

#ifndef NO_RSA_FUNC
size_t
ttls_rsa_get_len(const TlsRSACtx *ctx)
{
	return 0;
}

void
ttls_rsa_init(TlsRSACtx *ctx, int padding, int hash_id)
{
}

void
ttls_rsa_free(TlsRSACtx *ctx)
{
}

int
ttls_rsa_rsassa_pss_verify_ext(TlsRSACtx *ctx, ttls_md_type_t md_alg,
			       unsigned int hashlen,
			       const unsigned char *hash,
			       ttls_md_type_t mgf1_hash_id,
			       int expected_salt_len,
			       const unsigned char *sig)
{
	return 0;
}

int
ttls_rsa_pkcs1_verify(TlsRSACtx *ctx, ttls_md_type_t md_alg,
		      unsigned int hashlen, const unsigned char *hash,
		      const unsigned char *sig)
{
	return 0;
}

int
ttls_rsa_pkcs1_sign(TlsRSACtx *ctx, ttls_md_type_t md_alg,
		    const unsigned char *hash, size_t hashlen,
		    unsigned char *sig)
{
	return 0;
}
#endif /* NO_RSA_FUNC */

#endif /* __TTLS_MOCKS_H__ */
