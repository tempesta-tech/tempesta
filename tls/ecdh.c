/*
 *		Tempesta TLS
 *
 * Elliptic curve Diffie-Hellman.
 *
 * References:
 *
 * 1. SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 *
 * 2. RFC 8422
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0
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
#include "lib/str.h"

#include "ecdh.h"

/**
 * Compute shared secret (SEC1 3.3.1).
 * This function performs the second of two core computations implemented
 * during the ECDH key exchange. The first core computation is performed by
 * ttls_ecp_gen_keypair().
 *
 * @grp		- the ECP group;
 * @_P		- temporary point used in the computation. @_P.X is pointing to
 *		  to TlsECDHCtx->z - the destination MPI (shared secret);
 * @Q		- the public key from another party;
 * @d		- our secret exponent (private key).
 */
static int
ttls_ecdh_compute_shared(TlsEcpGrp *grp, TlsEcpPoint *_P, const TlsEcpPoint *Q,
			 const TlsMpi *d)
{
	int r;

	/* Make sure Q is a valid pubkey before using it. */
	if ((r = ttls_ecp_check_pubkey(grp, Q)))
		return r;

	/*
	 * Compute the shared secret.
	 * @_P is used as temproary point such that _P.X (which is also
	 * TlsECDHCtx->z) after the computation contains the secret.
	 */
	if ((r = ttls_ecp_mul(grp, _P, d, Q, true)))
		return r;

	return ttls_ecp_is_zero(_P) ? -EINVAL : 0;
}

/**
 * Setup and write the ServerKeyExhange parameters (RFC 8422 5.4):
 *	struct {
 *		ECParameters	curve_params;
 *		ECPoint		public;
 *	} ServerECDHParams;
 *
 * This function generates a public key and a TLS ServerKeyExchange payload.
 * This is the first function used by a TLS server for ECDHE ciphersuites.
 * It's assumed that the ECP group (grp) of the ctx context has already been
 * properly set.
 */
int
ttls_ecdh_make_params(TlsECDHCtx *ctx, size_t *olen, unsigned char *buf,
		      size_t blen)
{
	int r;
	size_t grp_len, pt_len;

	BUG_ON(!ctx || !ctx->grp.pbits);

	if ((r = ttls_ecp_gen_keypair(&ctx->grp, &ctx->d, &ctx->Q)))
		return r;

	if ((r = ttls_ecp_tls_write_group(&ctx->grp, &grp_len, buf, blen)))
		return r;

	buf += grp_len;
	blen -= grp_len;

	r = ttls_ecp_tls_write_point(&ctx->grp, &ctx->Q, &pt_len, buf, blen);
	if (r)
		return r;

	*olen = grp_len + pt_len;
	return 0;
}

/**
 * Read the ServerKeyExhange parameters (RFC 8422 5.4)
 *	struct {
 *		ECParameters	curve_params;
 *		ECPoint		public;
 *	} ServerECDHParams;
 */
int
ttls_ecdh_read_params(TlsECDHCtx *ctx, const unsigned char **buf,
		      const unsigned char *end)
{
	int r;

	if ((r = ttls_ecp_tls_read_group(&ctx->grp, buf, end - *buf)))
		return r;

	if ((r = ttls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, buf, end - *buf)))
		return r;

	return 0;
}

/**
 * Get parameters from a keypair.
 */
int
ttls_ecdh_get_params(TlsECDHCtx *ctx, const TlsEcpKeypair *key,
		     ttls_ecdh_side side)
{
	int r;

	BUG_ON(side != TTLS_ECDH_THEIRS && side != TTLS_ECDH_OURS);

	if ((r = ttls_ecp_group_load(&ctx->grp, key->grp.id)))
		return r;

	/* If it's not our key, just import the public part as Qp */
	if (side == TTLS_ECDH_THEIRS)
		return ttls_ecp_copy(&ctx->Qp, &key->Q);

	if ((r = ttls_ecp_copy(&ctx->Q, &key->Q))
	    || (r = ttls_mpi_copy(&ctx->d, &key->d)))
		return r;

	return 0;
}

/**
 * Setup and export the client public value.
 * Used for ClientKeyExchange generation on client side.
 * This is the second function used by a TLS client for ECDH(E) ciphersuites.
 */
int
ttls_ecdh_make_public(TlsECDHCtx *ctx, size_t *olen, unsigned char *buf,
		      size_t blen)
{
	int r;

	if (WARN_ON_ONCE(!ctx || !ctx->grp.pbits))
		return -EINVAL;

	if ((r = ttls_ecp_gen_keypair(&ctx->grp, &ctx->d, &ctx->Q)))
		return r;
	return ttls_ecp_tls_write_point(&ctx->grp, &ctx->Q, olen, buf, blen);
}

/**
 * Parse and import the client's public value.
 */
int
ttls_ecdh_read_public(TlsECDHCtx *ctx, const unsigned char *buf,
		      size_t blen)
{
	int r;
	const unsigned char *p = buf;

	if (!ctx)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	if ((r = ttls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, &p, blen)))
		return r;

	if ((size_t)(p - buf) != blen)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	return 0;
}

/*
 * Derive and export the shared secret
 */
int
ttls_ecdh_calc_secret(TlsECDHCtx *ctx, size_t *olen, unsigned char *buf,
		      size_t blen)
{
	int r;

	r = ttls_ecdh_compute_shared(&ctx->grp, &ctx->_P, &ctx->Qp, &ctx->d);
	if (r)
		return r;

	if (WARN_ON_ONCE(ttls_mpi_size(&ctx->z) > blen))
		return -EINVAL;

	*olen = ctx->grp.pbits / 8 + ((ctx->grp.pbits % 8) != 0);

	return ttls_mpi_write_binary(&ctx->z, buf, *olen);
}
