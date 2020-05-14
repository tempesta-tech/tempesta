/*
 *		Tempesta TLS
 *
 * Elliptic curves over GF(p): generic functions.
 *
 * References:
 *
 * 1. SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 *
 * 2. GECC = Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
 *
 * 3. FIPS 186-3 http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
 *
 * 4. RFC 8422 for the related TLS structures and constants
 *
 * 5. [Curve25519] http://cr.yp.to/ecdh/curve25519-20060209.pdf
 *
 * 6. CORON, Jean-S'ebastien. Resistance against differential power analysis
 *    for elliptic curve cryptosystems. In : Cryptographic Hardware and
 *    Embedded Systems. Springer Berlin Heidelberg, 1999. p. 292-302.
 *    <http://link.springer.com/chapter/10.1007/3-540-48059-5_25>
 *
 * 7. HEDABOU, Mustapha, PINEL, Pierre, et B'EN'ETEAU, Lucien. A comb method to
 *    render ECC resistant against Side Channel Attacks. IACR Cryptology
 *    ePrint Archive, 2004, vol. 2004, p. 342.
 *    <http://eprint.iacr.org/2004/342.pdf>
 *
 * 8. Jacobian coordinates for short Weierstrass curves,
 *    http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
 *
 * 9. S.Gueron, V.Krasnov, "Fast prime field elliptic-curve cryptography with
 *    256-bit primes", 2014.
 *
 * 10. NIST: Mathematical routines for the NIST prime elliptic curves, 2010.
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

typedef enum {
	ECP_TYPE_SHORT_WEIERSTRASS,	/* y^2 = x^3 + a x + b */
	ECP_TYPE_MONTGOMERY,		/* y^2 = x^3 + a x^2 + x */
} ecp_curve_type;

/*
 * List of supported curves (RFC 8422):
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 8422 5.1.1, RFC 7071 sec. 2)
 *  - size in bits
 *  - readable name
 *
 * Secp256r1 is at the first postion as the most used one.
 *
 * TODO #1031 add Curve25519 and Curve448.
 *
 * Reminder: update profiles in x509_crt.c when adding a new curves!
 */
static const TlsEcpCurveInfo ecp_supported_curves[] = {
	{ TTLS_ECP_DP_SECP256R1,	23,	 256,	"secp256r1"},
	{ TTLS_ECP_DP_SECP384R1,	24,	 384,	"secp384r1"},
	{ TTLS_ECP_DP_NONE,		0,	 0,	NULL},
};

#define ECP_NB_CURVES   sizeof(ecp_supported_curves) /	\
			sizeof(ecp_supported_curves[0])

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

static inline ecp_curve_type
ecp_get_type(const TlsEcpGrp *grp)
{
	return ttls_mpi_empty(&grp->G.Y)
		? ECP_TYPE_MONTGOMERY
		: ECP_TYPE_SHORT_WEIERSTRASS;
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
	size_t plen;

	/* Common case: P == 0 . */
	if (!ttls_mpi_cmp_int(&P->Z, 0)) {
		if (buflen < 1)
			return -ENOSPC;

		buf[0] = 0x00;
		*olen = 1;

		return 0;
	}

	plen = ttls_mpi_size(&grp->P);

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
	size_t plen;

	if (ilen < 1)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	if (buf[0] == 0x00) {
		if (ilen == 1) {
			ttls_ecp_set_zero(pt);
			return 0;
		}
		return TTLS_ERR_ECP_BAD_INPUT_DATA;
	}

	plen = ttls_mpi_size(&grp->P);

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
 * Import a point from a TLS ECPoint record (RFC 8443 5.4)
 *	struct {
 *		opaque point <1..2^8-1>;
 *	} ECPoint;
 */
int
ttls_ecp_tls_read_point(const TlsEcpGrp *grp, TlsEcpPoint *pt,
			const unsigned char **buf, size_t buf_len)
{
	unsigned char data_len;
	const unsigned char *buf_start;

	/*
	 * We must have at least two bytes (1 for length,
	 * at least one for data).
	 */
	if (buf_len < 2)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	data_len = *(*buf)++;
	if (data_len < 1 || data_len > buf_len - 1)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	/* Save buffer start for read_binary and update buf. */
	buf_start = *buf;
	*buf += data_len;

	return ttls_ecp_point_read_binary(grp, pt, buf_start, data_len);
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
ttls_ecp_tls_write_group(const TlsEcpGrp *grp, size_t *olen,
			 unsigned char *buf, size_t blen)
{
	const TlsEcpCurveInfo *curve_info;

	if (!(curve_info = ttls_ecp_curve_info_from_grp_id(grp->id)))
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
	if (WARN_ON_ONCE(ecp_get_type(grp) != ECP_TYPE_SHORT_WEIERSTRASS))
		return -EINVAL;

	return grp->muladd(grp, R, m, Q, n);
}

/**
 * Check that an TlsMpi is valid as a private key.
 *
 * Uses bare components rather than an TlsEcpKeypair structure in order to ease
 * use with other structures such as TlsECDHCtx of TlsEcpKeypair.
 */
int
ttls_ecp_check_privkey(const TlsEcpGrp *grp, const TlsMpi *d)
{
	switch (ecp_get_type(grp)) {
	case ECP_TYPE_MONTGOMERY:
		/* see [Curve25519] page 5 */
		if (ttls_mpi_get_bit(d, 0)
		    || ttls_mpi_get_bit(d, 1)
		    || ttls_mpi_get_bit(d, 2)
		    /* ttls_mpi_bitlen is one-based! */
		    || ttls_mpi_bitlen(d) - 1 != grp->bits)
		{
			T_DBG_MPI1("ECP bad montgomery priv key", d);
			return -EINVAL;
		}
		return 0;
	case ECP_TYPE_SHORT_WEIERSTRASS:
		/* see SEC1 3.2 */
		if (ttls_mpi_cmp_int(d, 1) < 0
		    || ttls_mpi_cmp_mpi(d, &grp->N) >= 0)
		{
			T_DBG_MPI2("ECP bad weierstrass priv key", d, &grp->N);
			return -EINVAL;
		}
		return 0;
	}
	BUG();
}

/**
 * Generate a keypair with configurable base point.
 */
int
ttls_ecp_gen_keypair(const TlsEcpGrp *grp, TlsMpi *d, TlsEcpPoint *Q)
{
	size_t n_size = (grp->bits + 7) / 8;

	if (ecp_get_type(grp) == ECP_TYPE_MONTGOMERY) {
		/* [M225] page 5 */
		size_t b;

		do {
			ttls_mpi_fill_random(d, n_size);
		} while (!ttls_mpi_bitlen(d));

		/* Make sure the most significant bit is bits */
		b = ttls_mpi_bitlen(d) - 1; /* ttls_mpi_bitlen is one-based */
		if (b > grp->bits)
			ttls_mpi_shift_r(d, b - grp->bits);
		else
			ttls_mpi_set_bit(d, grp->bits, 1);

		/* Make sure the last three bits are unset */
		ttls_mpi_set_bit(d, 0, 0);
		ttls_mpi_set_bit(d, 1, 0);
		ttls_mpi_set_bit(d, 2, 0);
	} else {
		/* SEC1 3.2.1: Generate d such that 1 <= n < N */
		int count = 0;

		/*
		 * Match the procedure given in RFC 6979 (deterministic ECDSA):
		 * - use the same byte ordering;
		 * - keep the leftmost bits bits of the generated octet string;
		 * - try until result is in the desired range.
		 * This also avoids any biais, which is especially important
		 * for ECDSA.
		 */
		do {
			ttls_mpi_fill_random(d, n_size);
			ttls_mpi_shift_r(d, 8 * n_size - grp->bits);

			/*
			 * Each try has at worst a probability 1/2 of failing
			 * (the msb has a probability 1/2 of being 0, and then
			 * the result will be < N), so after 30 tries failure
			 * probability is a most 2**(-30).
			 *
			 * For most curves, 1 try is enough with overwhelming
			 * probability, since N starts with a lot of 1s in
			 * binary, but some curves such as secp224k1 are
			 * actually very close to the worst case.
			 */
			if (WARN_ON_ONCE(++count > 10))
				return TTLS_ERR_ECP_RANDOM_FAILED;
		}
		while (!ttls_mpi_cmp_int(d, 0)
		       || ttls_mpi_cmp_mpi(d, &grp->N) >= 0)
			;
	}

	return grp->mul_g(grp, Q, d, true);
}

static TlsEcpGrp *ec_groups[__TTLS_ECP_DP_N];

/**
 * Create an MPI from embedded constants
 * (assumes len is an exact multiple of sizeof unsigned long).
 */
static void
ecp_mpi_load(TlsMpi *X, const unsigned long *p, size_t len)
{
	size_t const limbs = len / CIL;

	ttls_mpi_alloc(X, limbs);

	X->s = 1;
	X->limbs = X->used = limbs;
	memcpy(MPI_P(X), p, len);
}

/*
 * Make group available from embedded constants
 */
void
__ecp_group_load(TlsEcpGrp *grp, size_t sz, const unsigned long *p,
		 const unsigned long *b, const unsigned long *gx,
		 const unsigned long *gy, const unsigned long *n)
{
	int i;

	ecp_mpi_load(&grp->P, p, sz);
	ecp_mpi_load(&grp->B, b, sz);
	ecp_mpi_load(&grp->G.X, gx, sz);
	ecp_mpi_load(&grp->G.Y, gy, sz);
	ecp_mpi_load(&grp->N, n, sz);

	grp->bits = sz / CIL * BIL;

	/*
	 * Most of the time the point is normalized, so Z stores 1, but
	 * is some calculations the size can grow up to the curve size.
	 */
	ttls_mpi_alloc(&grp->G.Z, grp->bits / BIL);
	ttls_mpi_lset(&grp->G.Z, 1);

	/*
	 * ecp_normalize_jac_many() performs multiplication on X and Y
	 * coordinates, so we need double sizes.
	 */
	for (i = 0; i < ARRAY_SIZE(grp->T); i++) {
		ttls_mpi_alloc(&grp->T[i].X, grp->G.X.limbs * 2);
		ttls_mpi_alloc(&grp->T[i].Y, grp->G.Y.limbs * 2);
	}
	/*
	 * Allocate Z coordinates separately to shrink them later,
	 * see ttls_mpool_shrink_tailtmp().
	 */
	for (i = 0; i < ARRAY_SIZE(grp->T); i++)
		ttls_mpi_alloc_tmp(&grp->T[i].Z, grp->G.Z.limbs);
}

TlsEcpGrp *
ttls_ecp_group_lookup(ttls_ecp_group_id id)
{
	return ec_groups[id];
}

/**
 * Set a group using well-known domain parameters.
 *
 * @id should be a value of RFC 8422's NamedCurve (see ecp_supported_curves).
 */
int
ttls_ecp_group_load(TlsEcpGrp *grp, ttls_ecp_group_id id)
{
	if (ec_groups[id])
		T_WARN("Try to load already initialized EC group %d, shouldn't"
		       " have used ttls_ecp_group_lookup() instead?\n", id);

	switch(id) {
	case TTLS_ECP_DP_SECP256R1:
		ec_grp_init_p256(grp);
		break;
	case TTLS_ECP_DP_SECP384R1:
		ec_grp_init_p384(grp);
		break;
	case TTLS_ECP_DP_CURVE25519:
		ec_grp_init_curve25519(grp);
		break;
	default:
		T_WARN("Trying to load unsupported curve %d\n", id);
		return -EINVAL;
	}

	grp->id = id;
	ec_groups[id] = grp;

	return 0;
}

/**
 * Set a group from an ECParameters record (RFC 8422 5.4).
 * TODO #769 used in client mode only - fix the ECP group destination address.
 */
int
ttls_ecp_tls_read_group(TlsEcpGrp *grp, const unsigned char **buf, size_t len)
{
	uint16_t tls_id;
	const TlsEcpCurveInfo *curve_info;

	/* We expect at least three bytes (see below). */
	if (len < 3)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	/* First byte is curve_type; only named_curve is handled. */
	if (*(*buf)++ != TTLS_ECP_TLS_NAMED_CURVE)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	/* Next two bytes are the namedcurve value. */
	tls_id = *(*buf)++;
	tls_id <<= 8;
	tls_id |= *(*buf)++;

	if (!(curve_info = ttls_ecp_curve_info_from_tls_id(tls_id)))
		return TTLS_ERR_ECP_FEATURE_UNAVAILABLE;

	return ttls_ecp_group_load(grp, curve_info->grp_id);
}
