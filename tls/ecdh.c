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
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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
 * @z		- a point, which X coordinage is a shared secret;
 * @Q		- the public key from another party;
 * @d		- our secret exponent (private key).
 */
static int
ttls_ecdh_compute_shared(const TlsEcpGrp *grp, TlsEcpPoint *z,
			 unsigned long *Q, const TlsMpi *d)
{
	int r;

	/* Compute the shared secret. */
	if ((r = grp->mul(z, d, Q)))
		return r;

	return ttls_ecp_is_zero(z) ? -EINVAL : 0;
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

	if ((r = ctx->grp->gen_keypair(&ctx->d, &ctx->Q)))
		return r;

	if ((r = ttls_ecp_tls_write_group(ctx->grp->id, &grp_len, buf, blen)))
		return r;

	buf += grp_len;
	blen -= grp_len;

	r = ttls_ecp_tls_write_point(ctx->grp, &ctx->Q, &pt_len, buf, blen);
	if (r)
		return r;

	*olen = grp_len + pt_len;
	return 0;
}

/**
 * Parse and import the client's public value TlsECDHCtx->Qp.
 */
int
ttls_ecdh_read_public(TlsECDHCtx *ctx, const unsigned char *buf, size_t blen)
{
	int i;
	unsigned char data_len;
	unsigned long *xp, *yp;
	const size_t glen = BITS_TO_LIMBS(ctx->grp->bits);
	const size_t pk_len = glen * CIL * 2;

	/*
	 * We must have at least two bytes
	 * (1 for length and at least one for data).
	 */
	if (unlikely(blen != 2 && blen != pk_len + 2))
		return -EINVAL;

	data_len = *buf++;
	if (unlikely(data_len != 1 && data_len != pk_len + 1))
		return -EINVAL;

	/* See ttls_ecp_point_read_binary(). */
	if (unlikely(buf[0] == 0x00)) {
		if (data_len == 1) {
			bzero_fast(ctx->Qp, pk_len); /* zero point */
			return 0;
		}
		return -EINVAL;
	}
	if (unlikely(buf[0] != 0x04))
		return TTLS_ERR_ECP_FEATURE_UNAVAILABLE;

	/* Reverse MPIs from network byte order. */
	buf++;
	xp = (unsigned long *)buf;
	yp = (unsigned long *)(buf + glen * CIL);
	for (i = 0; i < glen; ++i) {
		ctx->Qp[i] = be64_to_cpu(xp[glen - 1 - i]);
		ctx->Qp[glen + i] = be64_to_cpu(yp[glen - 1 - i]);
	}

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

	if (!(ctx->grp = ttls_ecp_tls_read_group(buf, end - *buf)))
		return -EINVAL;

	/*
	 * Import a point from a TLS ECPoint record (RFC 8443 5.4)
	 *	struct {
	 *		opaque point <1..2^8-1>;
	 *	} ECPoint;
	 */
	if (!(r = ttls_ecdh_read_public(ctx, *buf, end - *buf)))
		*buf += end - *buf;

	return r;
}

/**
 * Get parameters from a keypair: set up an ECDH context from an EC key.
 * It is used by clients and servers in place of the ServerKeyExchange for
 * static ECDH, and imports ECDH parameters from the EC key information of a
 * certificate.
 *
 * TODO #769 used in client mode only - fix the ECP group destination address.
 */
int
ttls_ecdh_get_params(TlsECDHCtx *ctx, const TlsEcpKeypair *key)
{
	const size_t n = key->Q.X.used * CIL;

	if (!(ctx->grp = ttls_ecp_group_lookup(key->grp->id)))
		return -EINVAL;

	memcpy_fast(ctx->Qp, MPI_P(&key->Q.X), n);
	memcpy_fast(&ctx->Qp[key->Q.X.used], MPI_P(&key->Q.Y), n);

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

	if ((r = ctx->grp->gen_keypair(&ctx->d, &ctx->Q)))
		return r;
	return ttls_ecp_tls_write_point(ctx->grp, &ctx->Q, olen, buf, blen);
}

/*
 * Derive and export the shared secret
 */
int
ttls_ecdh_calc_secret(TlsECDHCtx *ctx, size_t *olen, unsigned char *buf,
		      size_t blen)
{
	int r;

	if ((r = ttls_ecdh_compute_shared(ctx->grp, &ctx->z, ctx->Qp, &ctx->d)))
		return r;

	if (WARN_ON_ONCE(ttls_mpi_size(&ctx->z.X) > blen))
		return -EINVAL;

	*olen = (ctx->grp->bits + 7) / 8;

	return ttls_mpi_write_binary(&ctx->z.X, buf, *olen);
}
