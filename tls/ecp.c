/*
 *		Tempesta TLS
 *
 * Elliptic curves over GF(p): generic functions.
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
#include <linux/types.h>

#include "tls_internal.h"
#include "bignum_asm.h"
#include "ecp.h"
#include "mpool.h"

/*
 * List of supported curves (RFC 8422):
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 8422 5.1.1, RFC 7071 sec. 2)
 *  - size in bits
 *  - readable name
 *
 * Secp256r1 is at the first postion as the most used one.
 *
 * TODO #1335 add Curve25519 and Curve448.
 *
 * Reminder: update profiles in x509_crt.c when adding a new curves!
 */
static const TlsEcpCurveInfo ecp_supported_curves[] = {
	{ TTLS_ECP_DP_SECP256R1,	23,	 256,	"secp256r1"},
	{ TTLS_ECP_DP_SECP384R1,	24,	 384,	"secp384r1"},
	{ TTLS_ECP_DP_NONE,		0,	 0,	NULL},
};

ttls_ecp_group_id ttls_preset_curves[] = {
	TTLS_ECP_DP_SECP256R1,
	TTLS_ECP_DP_SECP384R1,
	TTLS_ECP_DP_NONE
};

/**
 * Get the curve info for the internal identifier.
 */
const TlsEcpCurveInfo *
ttls_ecp_curve_info_from_grp_id(ttls_ecp_group_id grp_id)
{
	const TlsEcpCurveInfo *curve_info;

	for (curve_info = ecp_supported_curves;
	     curve_info->grp_id != TTLS_ECP_DP_NONE;
	     curve_info++)
	{
		if (curve_info->grp_id == grp_id)
			return curve_info;
	}

	return NULL;
}

/**
 * Get the curve info from the TLS identifier.
 */
const TlsEcpCurveInfo *
ttls_ecp_curve_info_from_tls_id(uint16_t tls_id)
{
	const TlsEcpCurveInfo *curve_info;

	T_DBG3("try curve id %#x from the client\n", tls_id);
	for (curve_info = ecp_supported_curves;
	     curve_info->grp_id != TTLS_ECP_DP_NONE;
	     curve_info++)
	{
		if (curve_info->tls_id == tls_id)
			return curve_info;
	}
	return NULL;
}

void
ttls_ecp_point_init(TlsEcpPoint *pt)
{
	ttls_mpi_init_next(&pt->X, 0);
	ttls_mpi_init_next(&pt->Y, 0);
	ttls_mpi_init_next(&pt->Z, 0);
}

/**
 * Called after ttls_mpi_pool_create() using __GFP_ZERO, so all the @key
 * members are zero here.
 */
void
ttls_ecp_keypair_init(TlsEcpKeypair *key)
{
	ttls_mpi_init_next(&key->d, 0);
	ttls_ecp_point_init(&key->Q);
}

void
ttls_ecp_keypair_free(TlsEcpKeypair *key)
{
	if (WARN_ON_ONCE(!key))
		return;
	ttls_mpi_pool_free(key);
}

void
ttls_ecp_copy(TlsEcpPoint *P, const TlsEcpPoint *Q)
{
	ttls_mpi_copy(&P->X, &Q->X);
	ttls_mpi_copy(&P->Y, &Q->Y);
	ttls_mpi_copy(&P->Z, &Q->Z);
}

/*
 * Export a point into unsigned binary data (SEC1 2.3.3).
 * Uncompressed is the only point format supported by RFC 8422.
 *
 * @grp		- Group to which the point should belong;
 * @p		- Point to export;
 * @olen	- Length of the actual output;
 * @buf		- Output buffer;
 * @buflen	- Length of the output buffer.
 */
static int
ttls_ecp_point_write_binary(const TlsEcpGrp *grp, const TlsEcpPoint *P,
			    size_t *olen, unsigned char *buf, size_t buflen)
{
	size_t plen = (grp->bits + 7) / 8;

	/* Common case: P == 0 . */
	if (!ttls_mpi_cmp_int(&P->Z, 0)) {
		if (buflen < 1)
			return -ENOSPC;

		buf[0] = 0x00;
		*olen = 1;

		return 0;
	}

	*olen = 2 * plen + 1;

	if (buflen < *olen)
		return -ENOSPC;

	buf[0] = 0x04;
	if (ttls_mpi_write_binary(&P->X, buf + 1, plen)
	    || ttls_mpi_write_binary(&P->Y, buf + 1 + plen, plen))
		return -ENOSPC;

	return 0;
}

/**
 * Import a point from unsigned binary data (SEC1 2.3.4).
 */
int
ttls_ecp_point_read_binary(const TlsEcpGrp *grp, TlsEcpPoint *pt,
			   const unsigned char *buf, size_t ilen)
{
	size_t plen = BITS_TO_CHARS(grp->bits);

	if (ilen < 1)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	if (buf[0] == 0x00) {
		if (ilen == 1) {
			ttls_ecp_set_zero(pt);
			return 0;
		}
		return TTLS_ERR_ECP_BAD_INPUT_DATA;
	}

	if (buf[0] != 0x04)
		return TTLS_ERR_ECP_FEATURE_UNAVAILABLE;

	if (ilen != 2 * plen + 1)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	ttls_mpi_read_binary(&pt->X, buf + 1, plen);
	ttls_mpi_read_binary(&pt->Y, buf + 1 + plen, plen);
	ttls_mpi_lset(&pt->Z, 1);

	return 0;
}

/**
 * Export a point as a TLS ECPoint record (RFC 8422 5.4)
 *	struct {
 *		opaque point <1..2^8-1>;
 *	} ECPoint;
 */
int
ttls_ecp_tls_write_point(const TlsEcpGrp *grp, const TlsEcpPoint *pt,
			 size_t *olen, unsigned char *buf, size_t blen)
{
	int r;

	/* Buffer length must be at least one, for our length byte. */
	if (blen < 1)
		return -EINVAL;

	r = ttls_ecp_point_write_binary(grp, pt, olen, buf + 1, blen - 1);
	if (r)
		return r;

	/* Write length to the first byte and update total length. */
	buf[0] = (unsigned char) *olen;
	++*olen;

	return 0;
}

/**
 * Write the ECParameters record corresponding to a group (RFC 8422 5.4).
 */
int
ttls_ecp_tls_write_group(ttls_ecp_group_id gid, size_t *olen,
			 unsigned char *buf, size_t blen)
{
	const TlsEcpCurveInfo *curve_info;

	if (!(curve_info = ttls_ecp_curve_info_from_grp_id(gid)))
		return -EINVAL;

	/* We are going to write 3 bytes (see below). */
	*olen = 3;
	if (blen < *olen)
		return -ENOSPC;

	/* First byte is curve_type, always named_curve. */
	*buf++ = TTLS_ECP_TLS_NAMED_CURVE;

	/* Next two bytes are the namedcurve value. */
	buf[0] = curve_info->tls_id >> 8;
	buf[1] = curve_info->tls_id & 0xFF;

	return 0;
}

int
ttls_ecp_muladd(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsMpi *m,
		const TlsMpi *n, const TlsEcpPoint *Q)
{
	if (WARN_ON_ONCE(!grp->muladd))
		return -EINVAL;

	return grp->muladd(R, m, Q, n);
}

extern const TlsEcpGrp SECP256_G;
extern const TlsEcpGrp SECP384_G;
extern const TlsEcpGrp CURVE25519_G;

const TlsEcpGrp *
ttls_ecp_group_lookup(ttls_ecp_group_id id)
{
	switch(id) {
	case TTLS_ECP_DP_SECP256R1:
		return &SECP256_G;
	case TTLS_ECP_DP_SECP384R1:
		return &SECP384_G;
	case TTLS_ECP_DP_CURVE25519:
		return &CURVE25519_G;
	default:
		T_WARN("Trying to load unsupported curve %d\n", id);
	}
	return NULL;
}

/**
 * Set a group from an ECParameters record (RFC 8422 5.4).
 *
 * TODO #769 used in client mode only - fix the ECP group destination address.
 */
const TlsEcpGrp *
ttls_ecp_tls_read_group(const unsigned char **buf, size_t len)
{
	uint16_t tls_id;
	const TlsEcpCurveInfo *curve_info;

	/* We expect at least three bytes (see below). */
	if (len < 3)
		return NULL;

	/* First byte is curve_type; only named_curve is handled. */
	if (*(*buf)++ != TTLS_ECP_TLS_NAMED_CURVE)
		return NULL;

	/* Next two bytes are the namedcurve value. */
	tls_id = *(*buf)++;
	tls_id <<= 8;
	tls_id |= *(*buf)++;

	if (!(curve_info = ttls_ecp_curve_info_from_tls_id(tls_id)))
		return NULL;

	return ttls_ecp_group_lookup(curve_info->grp_id);
}
