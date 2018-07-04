/*
 *  Elliptic curve Diffie-Hellman
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
/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * RFC 4492
 */
#include "config.h"
#include "ecdh.h"

#if !defined(TTLS_ECDH_GEN_PUBLIC_ALT)
/*
 * Generate public key: simple wrapper around ttls_ecp_gen_keypair
 */
int ttls_ecdh_gen_public(ttls_ecp_group *grp, ttls_mpi *d, ttls_ecp_point *Q,
		 int (*f_rng)(void *, unsigned char *, size_t),
		 void *p_rng)
{
	return ttls_ecp_gen_keypair(grp, d, Q, f_rng, p_rng);
}
#endif /* TTLS_ECDH_GEN_PUBLIC_ALT */

#if !defined(TTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
int
ttls_ecdh_compute_shared(ttls_ecp_group *grp, ttls_mpi *z,
			 const ttls_ecp_point *Q, const ttls_mpi *d)
{
	int ret;
	ttls_ecp_point P;

	ttls_ecp_point_init(&P);

	/*
	 * Make sure Q is a valid pubkey before using it
	 */
	TTLS_MPI_CHK(ttls_ecp_check_pubkey(grp, Q));

	TTLS_MPI_CHK(ttls_ecp_mul(grp, &P, d, Q));

	if (ttls_ecp_is_zero(&P)) {
		ret = TTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	TTLS_MPI_CHK(ttls_mpi_copy(z, &P.X));

cleanup:
	ttls_ecp_point_free(&P);

	return ret;
}
#endif /* TTLS_ECDH_COMPUTE_SHARED_ALT */

/*
 * Initialize context
 */
void ttls_ecdh_init(ttls_ecdh_context *ctx)
{
	memset(ctx, 0, sizeof(ttls_ecdh_context));
}

/*
 * Free context
 */
void ttls_ecdh_free(ttls_ecdh_context *ctx)
{
	if (ctx == NULL)
		return;

	ttls_ecp_group_free(&ctx->grp);
	ttls_ecp_point_free(&ctx->Q  );
	ttls_ecp_point_free(&ctx->Qp );
	ttls_ecp_point_free(&ctx->Vi );
	ttls_ecp_point_free(&ctx->Vf );
	ttls_mpi_free(&ctx->d );
	ttls_mpi_free(&ctx->z );
	ttls_mpi_free(&ctx->_d);
}

/*
 * Setup and write the ServerKeyExhange parameters (RFC 4492)
 *	  struct {
 *		  ECParameters	curve_params;
 *		  ECPoint		 public;
 *	  } ServerECDHParams;
 */
int ttls_ecdh_make_params(ttls_ecdh_context *ctx, size_t *olen,
		  unsigned char *buf, size_t blen,
		  int (*f_rng)(void *, unsigned char *, size_t),
		  void *p_rng)
{
	int ret;
	size_t grp_len, pt_len;

	if (ctx == NULL || ctx->grp.pbits == 0)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	if ((ret = ttls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng))
				!= 0)
		return ret;

	if ((ret = ttls_ecp_tls_write_group(&ctx->grp, &grp_len, buf, blen))
				!= 0)
		return ret;

	buf += grp_len;
	blen -= grp_len;

	if ((ret = ttls_ecp_tls_write_point(&ctx->grp, &ctx->Q, ctx->point_format,
			 &pt_len, buf, blen)) != 0)
		return ret;

	*olen = grp_len + pt_len;
	return 0;
}

/*
 * Read the ServerKeyExhange parameters (RFC 4492)
 *	  struct {
 *		  ECParameters	curve_params;
 *		  ECPoint		 public;
 *	  } ServerECDHParams;
 */
int ttls_ecdh_read_params(ttls_ecdh_context *ctx,
		  const unsigned char **buf, const unsigned char *end)
{
	int ret;

	if ((ret = ttls_ecp_tls_read_group(&ctx->grp, buf, end - *buf)) != 0)
		return ret;

	if ((ret = ttls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, buf, end - *buf))
				!= 0)
		return ret;

	return 0;
}

/*
 * Get parameters from a keypair
 */
int ttls_ecdh_get_params(ttls_ecdh_context *ctx, const ttls_ecp_keypair *key,
		 ttls_ecdh_side side)
{
	int ret;

	if ((ret = ttls_ecp_group_copy(&ctx->grp, &key->grp)) != 0)
		return ret;

	/* If it's not our key, just import the public part as Qp */
	if (side == TTLS_ECDH_THEIRS)
		return(ttls_ecp_copy(&ctx->Qp, &key->Q));

	/* Our key: import public (as Q) and private parts */
	if (side != TTLS_ECDH_OURS)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	if ((ret = ttls_ecp_copy(&ctx->Q, &key->Q)) != 0 ||
		(ret = ttls_mpi_copy(&ctx->d, &key->d)) != 0)
		return ret;

	return 0;
}

/*
 * Setup and export the client public value
 */
int ttls_ecdh_make_public(ttls_ecdh_context *ctx, size_t *olen,
		  unsigned char *buf, size_t blen,
		  int (*f_rng)(void *, unsigned char *, size_t),
		  void *p_rng)
{
	int ret;

	if (ctx == NULL || ctx->grp.pbits == 0)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	if ((ret = ttls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng))
				!= 0)
		return ret;

	return ttls_ecp_tls_write_point(&ctx->grp, &ctx->Q, ctx->point_format,
		olen, buf, blen);
}

/*
 * Parse and import the client's public value
 */
int ttls_ecdh_read_public(ttls_ecdh_context *ctx,
		  const unsigned char *buf, size_t blen)
{
	int ret;
	const unsigned char *p = buf;

	if (ctx == NULL)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	if ((ret = ttls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, &p, blen)) != 0)
		return ret;

	if ((size_t)(p - buf) != blen)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	return 0;
}

/*
 * Derive and export the shared secret
 */
int
ttls_ecdh_calc_secret(ttls_ecdh_context *ctx, size_t *olen, unsigned char *buf,
		      size_t blen)
{
	int r;

	if (!ctx)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	r = ttls_ecdh_compute_shared(&ctx->grp, &ctx->z, &ctx->Qp, &ctx->d);
	if (r)
		return r;

	if (ttls_mpi_size(&ctx->z) > blen)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	*olen = ctx->grp.pbits / 8 + ((ctx->grp.pbits % 8) != 0);

	return ttls_mpi_write_binary(&ctx->z, buf, *olen);
}
