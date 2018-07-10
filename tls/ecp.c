/*
 *  Elliptic curves over GF(p): generic functions
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
 * GECC = Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
 * FIPS 186-3 http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
 * RFC 4492 for the related TLS structures and constants
 *
 * [Curve25519] http://cr.yp.to/ecdh/curve25519-20060209.pdf
 *
 * [2] CORON, Jean-S'ebastien. Resistance against differential power analysis
 *	 for elliptic curve cryptosystems. In : Cryptographic Hardware and
 *	 Embedded Systems. Springer Berlin Heidelberg, 1999. p. 292-302.
 *	 <http://link.springer.com/chapter/10.1007/3-540-48059-5_25>
 *
 * [3] HEDABOU, Mustapha, PINEL, Pierre, et B'EN'ETEAU, Lucien. A comb method to
 *	 render ECC resistant against Side Channel Attacks. IACR Cryptology
 *	 ePrint Archive, 2004, vol. 2004, p. 342.
 *	 <http://eprint.iacr.org/2004/342.pdf>
 */
#include "config.h"
#include "ecp.h"
#include "ecp_internal.h"

/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}

/*
 * Counts of point addition and doubling, and field multiplications.
 * Used to test resistance of point multiplication to simple timing attacks.
 */
static unsigned long add_count, dbl_count, mul_count;

/*
 * Curve types: internal for now, might be exposed later
 */
typedef enum
{
	ECP_TYPE_NONE = 0,
	ECP_TYPE_SHORT_WEIERSTRASS,	/* y^2 = x^3 + a x + b	  */
	ECP_TYPE_MONTGOMERY,		   /* y^2 = x^3 + a x^2 + x	*/
} ecp_curve_type;

/*
 * List of supported curves:
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 4492 sec. 5.1.1, RFC 7071 sec. 2)
 *  - size in bits
 *  - readable name
 *
 * Curves are listed in order: largest curves first, and for a given size,
 * fastest curves first. This provides the default order for the SSL module.
 *
 * Reminder: update profiles in x509_crt.c when adding a new curves!
 */
static const ttls_ecp_curve_info ecp_supported_curves[] =
{
	{ TTLS_ECP_DP_SECP521R1,	25,	 521,	"secp521r1"},
	{ TTLS_ECP_DP_BP512R1,		28,	 512,	"brainpoolP512r1"},
	{ TTLS_ECP_DP_SECP384R1,	24,	 384,	"secp384r1"},
	{ TTLS_ECP_DP_BP384R1,		27,	 384,	"brainpoolP384r1"},
	{ TTLS_ECP_DP_SECP256R1,	23,	 256,	"secp256r1"},
	{ TTLS_ECP_DP_SECP256K1,	22,	 256,	"secp256k1"},
	{ TTLS_ECP_DP_BP256R1,		26,	 256,	"brainpoolP256r1"},
	{ TTLS_ECP_DP_SECP224R1,	21,	 224,	"secp224r1"},
	{ TTLS_ECP_DP_SECP224K1,	20,	 224,	"secp224k1"},
	{ TTLS_ECP_DP_SECP192R1,	19,	 192,	"secp192r1"},
	{ TTLS_ECP_DP_SECP192K1,	18,	 192,	"secp192k1"},
	{ TTLS_ECP_DP_NONE,		0,	 0,	NULL},
};

#define ECP_NB_CURVES   sizeof(ecp_supported_curves) /	\
			sizeof(ecp_supported_curves[0])

static ttls_ecp_group_id ecp_supported_grp_id[ECP_NB_CURVES];

/*
 * List of supported curves and associated info
 */
const ttls_ecp_curve_info *ttls_ecp_curve_list(void)
{
	return(ecp_supported_curves);
}

/*
 * List of supported curves, group ID only
 */
const ttls_ecp_group_id *ttls_ecp_grp_id_list(void)
{
	static int init_done = 0;

	if (! init_done)
	{
		size_t i = 0;
		const ttls_ecp_curve_info *curve_info;

		for (curve_info = ttls_ecp_curve_list();
			 curve_info->grp_id != TTLS_ECP_DP_NONE;
			 curve_info++)
		{
			ecp_supported_grp_id[i++] = curve_info->grp_id;
		}
		ecp_supported_grp_id[i] = TTLS_ECP_DP_NONE;

		init_done = 1;
	}

	return(ecp_supported_grp_id);
}

/*
 * Get the curve info for the internal identifier
 */
const ttls_ecp_curve_info *ttls_ecp_curve_info_from_grp_id(ttls_ecp_group_id grp_id)
{
	const ttls_ecp_curve_info *curve_info;

	for (curve_info = ttls_ecp_curve_list();
		 curve_info->grp_id != TTLS_ECP_DP_NONE;
		 curve_info++)
	{
		if (curve_info->grp_id == grp_id)
			return(curve_info);
	}

	return(NULL);
}

/**
 * Get the curve info from the TLS identifier
 */
const ttls_ecp_curve_info *
ttls_ecp_curve_info_from_tls_id(uint16_t tls_id)
{
	const ttls_ecp_curve_info *curve_info;

	for (curve_info = ttls_ecp_curve_list();
	     curve_info->grp_id != TTLS_ECP_DP_NONE;
	     curve_info++)
	{
		if (curve_info->tls_id == tls_id)
			return curve_info;
	}
	return NULL;
}

/*
 * Get the curve info from the name
 */
const ttls_ecp_curve_info *ttls_ecp_curve_info_from_name(const char *name)
{
	const ttls_ecp_curve_info *curve_info;

	for (curve_info = ttls_ecp_curve_list();
		 curve_info->grp_id != TTLS_ECP_DP_NONE;
		 curve_info++)
	{
		if (strcmp(curve_info->name, name) == 0)
			return(curve_info);
	}

	return(NULL);
}

/*
 * Get the type of a curve
 */
static inline ecp_curve_type ecp_get_type(const ttls_ecp_group *grp)
{
	if (grp->G.X.p == NULL)
		return(ECP_TYPE_NONE);

	if (grp->G.Y.p == NULL)
		return(ECP_TYPE_MONTGOMERY);
	else
		return(ECP_TYPE_SHORT_WEIERSTRASS);
}

/*
 * Initialize (the components of) a point
 */
void ttls_ecp_point_init(ttls_ecp_point *pt)
{
	if (pt == NULL)
		return;

	ttls_mpi_init(&pt->X);
	ttls_mpi_init(&pt->Y);
	ttls_mpi_init(&pt->Z);
}

/*
 * Initialize (the components of) a group
 */
void ttls_ecp_group_init(ttls_ecp_group *grp)
{
	if (grp == NULL)
		return;

	memset(grp, 0, sizeof(ttls_ecp_group));
}

/*
 * Initialize (the components of) a key pair
 */
void ttls_ecp_keypair_init(ttls_ecp_keypair *key)
{
	if (key == NULL)
		return;

	ttls_ecp_group_init(&key->grp);
	ttls_mpi_init(&key->d);
	ttls_ecp_point_init(&key->Q);
}

/*
 * Unallocate (the components of) a point
 */
void ttls_ecp_point_free(ttls_ecp_point *pt)
{
	if (pt == NULL)
		return;

	ttls_mpi_free(&(pt->X));
	ttls_mpi_free(&(pt->Y));
	ttls_mpi_free(&(pt->Z));
}

/*
 * Unallocate (the components of) a group
 */
void ttls_ecp_group_free(ttls_ecp_group *grp)
{
	size_t i;

	if (grp == NULL)
		return;

	if (grp->h != 1)
	{
		ttls_mpi_free(&grp->P);
		ttls_mpi_free(&grp->A);
		ttls_mpi_free(&grp->B);
		ttls_ecp_point_free(&grp->G);
		ttls_mpi_free(&grp->N);
	}

	if (grp->T != NULL)
	{
		for (i = 0; i < grp->T_size; i++)
			ttls_ecp_point_free(&grp->T[i]);
		ttls_free(grp->T);
	}

	ttls_zeroize(grp, sizeof(ttls_ecp_group));
}

/*
 * Unallocate (the components of) a key pair
 */
void ttls_ecp_keypair_free(ttls_ecp_keypair *key)
{
	if (key == NULL)
		return;

	ttls_ecp_group_free(&key->grp);
	ttls_mpi_free(&key->d);
	ttls_ecp_point_free(&key->Q);
}

/*
 * Copy the contents of a point
 */
int ttls_ecp_copy(ttls_ecp_point *P, const ttls_ecp_point *Q)
{
	int ret;

	TTLS_MPI_CHK(ttls_mpi_copy(&P->X, &Q->X));
	TTLS_MPI_CHK(ttls_mpi_copy(&P->Y, &Q->Y));
	TTLS_MPI_CHK(ttls_mpi_copy(&P->Z, &Q->Z));

cleanup:
	return ret;
}

/*
 * Copy the contents of a group object
 */
int ttls_ecp_group_copy(ttls_ecp_group *dst, const ttls_ecp_group *src)
{
	return ttls_ecp_group_load(dst, src->id);
}

/*
 * Set point to zero
 */
int ttls_ecp_set_zero(ttls_ecp_point *pt)
{
	int ret;

	TTLS_MPI_CHK(ttls_mpi_lset(&pt->X , 1));
	TTLS_MPI_CHK(ttls_mpi_lset(&pt->Y , 1));
	TTLS_MPI_CHK(ttls_mpi_lset(&pt->Z , 0));

cleanup:
	return ret;
}

/*
 * Tell if a point is zero
 */
int ttls_ecp_is_zero(ttls_ecp_point *pt)
{
	return(ttls_mpi_cmp_int(&pt->Z, 0) == 0);
}

/*
 * Compare two points lazyly
 */
int ttls_ecp_point_cmp(const ttls_ecp_point *P,
			   const ttls_ecp_point *Q)
{
	if (ttls_mpi_cmp_mpi(&P->X, &Q->X) == 0 &&
		ttls_mpi_cmp_mpi(&P->Y, &Q->Y) == 0 &&
		ttls_mpi_cmp_mpi(&P->Z, &Q->Z) == 0)
	{
		return 0;
	}

	return(TTLS_ERR_ECP_BAD_INPUT_DATA);
}

/*
 * Import a non-zero point from ASCII strings
 */
int ttls_ecp_point_read_string(ttls_ecp_point *P, int radix,
			   const char *x, const char *y)
{
	int ret;

	TTLS_MPI_CHK(ttls_mpi_read_string(&P->X, radix, x));
	TTLS_MPI_CHK(ttls_mpi_read_string(&P->Y, radix, y));
	TTLS_MPI_CHK(ttls_mpi_lset(&P->Z, 1));

cleanup:
	return ret;
}

/*
 * Export a point into unsigned binary data (SEC1 2.3.3)
 */
int ttls_ecp_point_write_binary(const ttls_ecp_group *grp, const ttls_ecp_point *P,
				int format, size_t *olen,
				unsigned char *buf, size_t buflen)
{
	int ret = 0;
	size_t plen;

	if (format != TTLS_ECP_PF_UNCOMPRESSED &&
		format != TTLS_ECP_PF_COMPRESSED)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	/*
	 * Common case: P == 0
	 */
	if (ttls_mpi_cmp_int(&P->Z, 0) == 0)
	{
		if (buflen < 1)
			return(TTLS_ERR_ECP_BUFFER_TOO_SMALL);

		buf[0] = 0x00;
		*olen = 1;

		return 0;
	}

	plen = ttls_mpi_size(&grp->P);

	if (format == TTLS_ECP_PF_UNCOMPRESSED)
	{
		*olen = 2 * plen + 1;

		if (buflen < *olen)
			return(TTLS_ERR_ECP_BUFFER_TOO_SMALL);

		buf[0] = 0x04;
		TTLS_MPI_CHK(ttls_mpi_write_binary(&P->X, buf + 1, plen));
		TTLS_MPI_CHK(ttls_mpi_write_binary(&P->Y, buf + 1 + plen, plen));
	}
	else if (format == TTLS_ECP_PF_COMPRESSED)
	{
		*olen = plen + 1;

		if (buflen < *olen)
			return(TTLS_ERR_ECP_BUFFER_TOO_SMALL);

		buf[0] = 0x02 + ttls_mpi_get_bit(&P->Y, 0);
		TTLS_MPI_CHK(ttls_mpi_write_binary(&P->X, buf + 1, plen));
	}

cleanup:
	return ret;
}

/*
 * Import a point from unsigned binary data (SEC1 2.3.4)
 */
int ttls_ecp_point_read_binary(const ttls_ecp_group *grp, ttls_ecp_point *pt,
				   const unsigned char *buf, size_t ilen)
{
	int ret;
	size_t plen;

	if (ilen < 1)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	if (buf[0] == 0x00)
	{
		if (ilen == 1)
			return(ttls_ecp_set_zero(pt));
		else
			return(TTLS_ERR_ECP_BAD_INPUT_DATA);
	}

	plen = ttls_mpi_size(&grp->P);

	if (buf[0] != 0x04)
		return(TTLS_ERR_ECP_FEATURE_UNAVAILABLE);

	if (ilen != 2 * plen + 1)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	TTLS_MPI_CHK(ttls_mpi_read_binary(&pt->X, buf + 1, plen));
	TTLS_MPI_CHK(ttls_mpi_read_binary(&pt->Y, buf + 1 + plen, plen));
	TTLS_MPI_CHK(ttls_mpi_lset(&pt->Z, 1));

cleanup:
	return ret;
}

/*
 * Import a point from a TLS ECPoint record (RFC 4492)
 *	  struct {
 *		  opaque point <1..2^8-1>;
 *	  } ECPoint;
 */
int ttls_ecp_tls_read_point(const ttls_ecp_group *grp, ttls_ecp_point *pt,
			const unsigned char **buf, size_t buf_len)
{
	unsigned char data_len;
	const unsigned char *buf_start;

	/*
	 * We must have at least two bytes (1 for length, at least one for data)
	 */
	if (buf_len < 2)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	data_len = *(*buf)++;
	if (data_len < 1 || data_len > buf_len - 1)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	/*
	 * Save buffer start for read_binary and update buf
	 */
	buf_start = *buf;
	*buf += data_len;

	return ttls_ecp_point_read_binary(grp, pt, buf_start, data_len);
}

/*
 * Export a point as a TLS ECPoint record (RFC 4492)
 *	  struct {
 *		  opaque point <1..2^8-1>;
 *	  } ECPoint;
 */
int ttls_ecp_tls_write_point(const ttls_ecp_group *grp, const ttls_ecp_point *pt,
			 int format, size_t *olen,
			 unsigned char *buf, size_t blen)
{
	int ret;

	/*
	 * buffer length must be at least one, for our length byte
	 */
	if (blen < 1)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	if ((ret = ttls_ecp_point_write_binary(grp, pt, format,
		olen, buf + 1, blen - 1)) != 0)
		return ret;

	/*
	 * write length to the first byte and update total length
	 */
	buf[0] = (unsigned char) *olen;
	++*olen;

	return 0;
}

/*
 * Set a group from an ECParameters record (RFC 4492)
 */
int ttls_ecp_tls_read_group(ttls_ecp_group *grp, const unsigned char **buf, size_t len)
{
	uint16_t tls_id;
	const ttls_ecp_curve_info *curve_info;

	/*
	 * We expect at least three bytes (see below)
	 */
	if (len < 3)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	/*
	 * First byte is curve_type; only named_curve is handled
	 */
	if (*(*buf)++ != TTLS_ECP_TLS_NAMED_CURVE)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	/*
	 * Next two bytes are the namedcurve value
	 */
	tls_id = *(*buf)++;
	tls_id <<= 8;
	tls_id |= *(*buf)++;

	if ((curve_info = ttls_ecp_curve_info_from_tls_id(tls_id)) == NULL)
		return(TTLS_ERR_ECP_FEATURE_UNAVAILABLE);

	return ttls_ecp_group_load(grp, curve_info->grp_id);
}

/*
 * Write the ECParameters record corresponding to a group (RFC 4492)
 */
int ttls_ecp_tls_write_group(const ttls_ecp_group *grp, size_t *olen,
			 unsigned char *buf, size_t blen)
{
	const ttls_ecp_curve_info *curve_info;

	if ((curve_info = ttls_ecp_curve_info_from_grp_id(grp->id)) == NULL)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	/*
	 * We are going to write 3 bytes (see below)
	 */
	*olen = 3;
	if (blen < *olen)
		return(TTLS_ERR_ECP_BUFFER_TOO_SMALL);

	/*
	 * First byte is curve_type, always named_curve
	 */
	*buf++ = TTLS_ECP_TLS_NAMED_CURVE;

	/*
	 * Next two bytes are the namedcurve value
	 */
	buf[0] = curve_info->tls_id >> 8;
	buf[1] = curve_info->tls_id & 0xFF;

	return 0;
}

/*
 * Wrapper around fast quasi-modp functions, with fall-back to ttls_mpi_mod_mpi.
 * See the documentation of struct ttls_ecp_group.
 *
 * This function is in the critial loop for ttls_ecp_mul, so pay attention to perf.
 */
static int ecp_modp(ttls_mpi *N, const ttls_ecp_group *grp)
{
	int ret;

	if (grp->modp == NULL)
		return(ttls_mpi_mod_mpi(N, N, &grp->P));

	/* N->s < 0 is a much faster test, which fails only if N is 0 */
	if ((N->s < 0 && ttls_mpi_cmp_int(N, 0) != 0) ||
		ttls_mpi_bitlen(N) > 2 * grp->pbits)
	{
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);
	}

	TTLS_MPI_CHK(grp->modp(N));

	/* N->s < 0 is a much faster test, which fails only if N is 0 */
	while (N->s < 0 && ttls_mpi_cmp_int(N, 0) != 0)
		TTLS_MPI_CHK(ttls_mpi_add_mpi(N, N, &grp->P));

	while (ttls_mpi_cmp_mpi(N, &grp->P) >= 0)
		/* we known P, N and the result are positive */
		TTLS_MPI_CHK(ttls_mpi_sub_abs(N, N, &grp->P));

cleanup:
	return ret;
}

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * ttls_mpi_mul_mpi are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a ttls_mpi mod p in-place, general case, to use after ttls_mpi_mul_mpi
 */
#define INC_MUL_COUNT   mul_count++;

#define MOD_MUL(N)	do { TTLS_MPI_CHK(ecp_modp(&N, grp)); INC_MUL_COUNT } \
			while (0)

/*
 * Reduce a ttls_mpi mod p in-place, to use after ttls_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
#define MOD_SUB(N)		\
	while (N.s < 0 && ttls_mpi_cmp_int(&N, 0) != 0)   \
		TTLS_MPI_CHK(ttls_mpi_add_mpi(&N, &N, &grp->P))

/*
 * Reduce a ttls_mpi mod p in-place, to use after ttls_mpi_add_mpi and ttls_mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD(N)		\
	while (ttls_mpi_cmp_mpi(&N, &grp->P) >= 0)		\
		TTLS_MPI_CHK(ttls_mpi_sub_abs(&N, &N, &grp->P))

/*
 * For curves in short Weierstrass form, we do all the internal operations in
 * Jacobian coordinates.
 *
 * For multiplication, we'll use a comb method with coutermeasueres against
 * SPA, hence timing attacks.
 */

/*
 * Normalize jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
 */
static int ecp_normalize_jac(const ttls_ecp_group *grp, ttls_ecp_point *pt)
{
	int ret;
	ttls_mpi Zi, ZZi;

	if (ttls_mpi_cmp_int(&pt->Z, 0) == 0)
		return 0;

	ttls_mpi_init(&Zi); ttls_mpi_init(&ZZi);

	/*
	 * X = X / Z^2  mod p
	 */
	TTLS_MPI_CHK(ttls_mpi_inv_mod(&Zi,	  &pt->Z,	 &grp->P));
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&ZZi,	 &Zi,		&Zi	)); MOD_MUL(ZZi);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&pt->X,   &pt->X,	 &ZZi	)); MOD_MUL(pt->X);

	/*
	 * Y = Y / Z^3  mod p
	 */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&pt->Y,   &pt->Y,	 &ZZi	)); MOD_MUL(pt->Y);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&pt->Y,   &pt->Y,	 &Zi	)); MOD_MUL(pt->Y);

	/*
	 * Z = 1
	 */
	TTLS_MPI_CHK(ttls_mpi_lset(&pt->Z, 1));

cleanup:

	ttls_mpi_free(&Zi); ttls_mpi_free(&ZZi);

	return ret;
}

/*
 * Normalize jacobian coordinates of an array of (pointers to) points,
 * using Montgomery's trick to perform only one inversion mod P.
 * (See for example Cohen's "A Course in Computational Algebraic Number
 * Theory", Algorithm 10.3.4.)
 *
 * Warning: fails (returning an error) if one of the points is zero!
 * This should never happen, see choice of w in ecp_mul_comb().
 *
 * Cost: 1N(t) := 1I + (6t - 3)M + 1S
 */
static int ecp_normalize_jac_many(const ttls_ecp_group *grp,
		   ttls_ecp_point *T[], size_t t_len)
{
	int ret;
	size_t i;
	ttls_mpi *c, u, Zi, ZZi;

	if (t_len < 2)
		return(ecp_normalize_jac(grp, *T));

#if defined(TTLS_ECP_NORMALIZE_JAC_MANY_ALT)
	if (ttls_internal_ecp_grp_capable(grp))
	{
		return ttls_internal_ecp_normalize_jac_many(grp, T, t_len);
	}
#endif

	if ((c = ttls_calloc(t_len, sizeof(ttls_mpi))) == NULL)
		return(TTLS_ERR_ECP_ALLOC_FAILED);

	ttls_mpi_init(&u); ttls_mpi_init(&Zi); ttls_mpi_init(&ZZi);

	/*
	 * c[i] = Z_0 * ... * Z_i
	 */
	TTLS_MPI_CHK(ttls_mpi_copy(&c[0], &T[0]->Z));
	for (i = 1; i < t_len; i++)
	{
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&c[i], &c[i-1], &T[i]->Z));
		MOD_MUL(c[i]);
	}

	/*
	 * u = 1 / (Z_0 * ... * Z_n) mod P
	 */
	TTLS_MPI_CHK(ttls_mpi_inv_mod(&u, &c[t_len-1], &grp->P));

	for (i = t_len - 1; ; i--)
	{
		/*
		 * Zi = 1 / Z_i mod p
		 * u = 1 / (Z_0 * ... * Z_i) mod P
		 */
		if (i == 0) {
			TTLS_MPI_CHK(ttls_mpi_copy(&Zi, &u));
		}
		else
		{
			TTLS_MPI_CHK(ttls_mpi_mul_mpi(&Zi, &u, &c[i-1] )); MOD_MUL(Zi);
			TTLS_MPI_CHK(ttls_mpi_mul_mpi(&u,  &u, &T[i]->Z)); MOD_MUL(u);
		}

		/*
		 * proceed as in normalize()
		 */
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&ZZi,	 &Zi,	  &Zi )); MOD_MUL(ZZi);
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T[i]->X, &T[i]->X, &ZZi)); MOD_MUL(T[i]->X);
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T[i]->Y, &T[i]->Y, &ZZi)); MOD_MUL(T[i]->Y);
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T[i]->Y, &T[i]->Y, &Zi )); MOD_MUL(T[i]->Y);

		/*
		 * Post-precessing: reclaim some memory by shrinking coordinates
		 * - not storing Z (always 1)
		 * - shrinking other coordinates, but still keeping the same number of
		 *   limbs as P, as otherwise it will too likely be regrown too fast.
		 */
		TTLS_MPI_CHK(ttls_mpi_shrink(&T[i]->X, grp->P.n));
		TTLS_MPI_CHK(ttls_mpi_shrink(&T[i]->Y, grp->P.n));
		ttls_mpi_free(&T[i]->Z);

		if (i == 0)
			break;
	}

cleanup:

	ttls_mpi_free(&u); ttls_mpi_free(&Zi); ttls_mpi_free(&ZZi);
	for (i = 0; i < t_len; i++)
		ttls_mpi_free(&c[i]);
	ttls_free(c);

	return ret;
}

/*
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid
 */
static int ecp_safe_invert_jac(const ttls_ecp_group *grp,
				ttls_ecp_point *Q,
				unsigned char inv)
{
	int ret;
	unsigned char nonzero;
	ttls_mpi mQY;

	ttls_mpi_init(&mQY);

	/* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&mQY, &grp->P, &Q->Y));
	nonzero = ttls_mpi_cmp_int(&Q->Y, 0) != 0;
	TTLS_MPI_CHK(ttls_mpi_safe_cond_assign(&Q->Y, &mQY, inv & nonzero));

cleanup:
	ttls_mpi_free(&mQY);

	return ret;
}

/*
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * Based on http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2 .
 *
 * We follow the variable naming fairly closely. The formula variations that trade a MUL for a SQR
 * (plus a few ADDs) aren't useful as our bignum implementation doesn't distinguish squaring.
 *
 * Standard optimizations are applied when curve parameter A is one of { 0, -3 }.
 *
 * Cost: 1D := 3M + 4S		  (A ==  0)
 *			 4M + 4S		  (A == -3)
 *			 3M + 6S + 1a	 otherwise
 */
static int ecp_double_jac(const ttls_ecp_group *grp, ttls_ecp_point *R,
			   const ttls_ecp_point *P)
{
	int ret;
	ttls_mpi M, S, T, U;

	dbl_count++;

#if defined(TTLS_ECP_DOUBLE_JAC_ALT)
	if (ttls_internal_ecp_grp_capable(grp))
	{
		return ttls_internal_ecp_double_jac(grp, R, P);
	}
#endif /* TTLS_ECP_DOUBLE_JAC_ALT */

	ttls_mpi_init(&M); ttls_mpi_init(&S); ttls_mpi_init(&T); ttls_mpi_init(&U);

	/* Special case for A = -3 */
	if (grp->A.p == NULL)
	{
		/* M = 3(X + Z^2)(X - Z^2) */
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&S,  &P->Z,  &P->Z  )); MOD_MUL(S);
		TTLS_MPI_CHK(ttls_mpi_add_mpi(&T,  &P->X,  &S	 )); MOD_ADD(T);
		TTLS_MPI_CHK(ttls_mpi_sub_mpi(&U,  &P->X,  &S	 )); MOD_SUB(U);
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&S,  &T,	 &U	 )); MOD_MUL(S);
		TTLS_MPI_CHK(ttls_mpi_mul_int(&M,  &S,	 3	  )); MOD_ADD(M);
	}
	else
	{
		/* M = 3.X^2 */
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&S,  &P->X,  &P->X  )); MOD_MUL(S);
		TTLS_MPI_CHK(ttls_mpi_mul_int(&M,  &S,	 3	  )); MOD_ADD(M);

		/* Optimize away for "koblitz" curves with A = 0 */
		if (ttls_mpi_cmp_int(&grp->A, 0) != 0)
		{
			/* M += A.Z^4 */
			TTLS_MPI_CHK(ttls_mpi_mul_mpi(&S,  &P->Z,  &P->Z  )); MOD_MUL(S);
			TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T,  &S,	 &S	 )); MOD_MUL(T);
			TTLS_MPI_CHK(ttls_mpi_mul_mpi(&S,  &T,	 &grp->A)); MOD_MUL(S);
			TTLS_MPI_CHK(ttls_mpi_add_mpi(&M,  &M,	 &S	 )); MOD_ADD(M);
		}
	}

	/* S = 4.X.Y^2 */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T,  &P->Y,  &P->Y  )); MOD_MUL(T);
	TTLS_MPI_CHK(ttls_mpi_shift_l(&T,  1			  )); MOD_ADD(T);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&S,  &P->X,  &T	 )); MOD_MUL(S);
	TTLS_MPI_CHK(ttls_mpi_shift_l(&S,  1			  )); MOD_ADD(S);

	/* U = 8.Y^4 */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&U,  &T,	 &T	 )); MOD_MUL(U);
	TTLS_MPI_CHK(ttls_mpi_shift_l(&U,  1			  )); MOD_ADD(U);

	/* T = M^2 - 2.S */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T,  &M,	 &M	 )); MOD_MUL(T);
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&T,  &T,	 &S	 )); MOD_SUB(T);
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&T,  &T,	 &S	 )); MOD_SUB(T);

	/* S = M(S - T) - U */
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&S,  &S,	 &T	 )); MOD_SUB(S);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&S,  &S,	 &M	 )); MOD_MUL(S);
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&S,  &S,	 &U	 )); MOD_SUB(S);

	/* U = 2.Y.Z */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&U,  &P->Y,  &P->Z  )); MOD_MUL(U);
	TTLS_MPI_CHK(ttls_mpi_shift_l(&U,  1			  )); MOD_ADD(U);

	TTLS_MPI_CHK(ttls_mpi_copy(&R->X, &T));
	TTLS_MPI_CHK(ttls_mpi_copy(&R->Y, &S));
	TTLS_MPI_CHK(ttls_mpi_copy(&R->Z, &U));

cleanup:
	ttls_mpi_free(&M); ttls_mpi_free(&S); ttls_mpi_free(&T); ttls_mpi_free(&U);

	return ret;
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Special cases: (1) P or Q is zero, (2) R is zero, (3) P == Q.
 * None of these cases can happen as intermediate step in ecp_mul_comb():
 * - at each step, P, Q and R are multiples of the base point, the factor
 *   being less than its order, so none of them is zero;
 * - Q is an odd multiple of the base point, P an even multiple,
 *   due to the choice of precomputed points in the modified comb method.
 * So branches for these cases do not leak secret information.
 *
 * We accept Q->Z being unset (saving memory in tables) as meaning 1.
 *
 * Cost: 1A := 8M + 3S
 */
static int ecp_add_mixed(const ttls_ecp_group *grp, ttls_ecp_point *R,
			  const ttls_ecp_point *P, const ttls_ecp_point *Q)
{
	int ret;
	ttls_mpi T1, T2, T3, T4, X, Y, Z;

	add_count++;

#if defined(TTLS_ECP_ADD_MIXED_ALT)
	if (ttls_internal_ecp_grp_capable(grp))
	{
		return ttls_internal_ecp_add_mixed(grp, R, P, Q);
	}
#endif /* TTLS_ECP_ADD_MIXED_ALT */

	/*
	 * Trivial cases: P == 0 or Q == 0 (case 1)
	 */
	if (ttls_mpi_cmp_int(&P->Z, 0) == 0)
		return(ttls_ecp_copy(R, Q));

	if (Q->Z.p != NULL && ttls_mpi_cmp_int(&Q->Z, 0) == 0)
		return(ttls_ecp_copy(R, P));

	/*
	 * Make sure Q coordinates are normalized
	 */
	if (Q->Z.p != NULL && ttls_mpi_cmp_int(&Q->Z, 1) != 0)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	ttls_mpi_init(&T1); ttls_mpi_init(&T2); ttls_mpi_init(&T3); ttls_mpi_init(&T4);
	ttls_mpi_init(&X); ttls_mpi_init(&Y); ttls_mpi_init(&Z);

	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T1,  &P->Z,  &P->Z));  MOD_MUL(T1);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T2,  &T1,	&P->Z));  MOD_MUL(T2);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T1,  &T1,	&Q->X));  MOD_MUL(T1);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T2,  &T2,	&Q->Y));  MOD_MUL(T2);
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&T1,  &T1,	&P->X));  MOD_SUB(T1);
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&T2,  &T2,	&P->Y));  MOD_SUB(T2);

	/* Special cases (2) and (3) */
	if (ttls_mpi_cmp_int(&T1, 0) == 0)
	{
		if (ttls_mpi_cmp_int(&T2, 0) == 0)
		{
			ret = ecp_double_jac(grp, R, P);
			goto cleanup;
		}
		else
		{
			ret = ttls_ecp_set_zero(R);
			goto cleanup;
		}
	}

	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&Z,   &P->Z,  &T1  ));  MOD_MUL(Z );
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T3,  &T1,	&T1  ));  MOD_MUL(T3);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T4,  &T3,	&T1  ));  MOD_MUL(T4);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T3,  &T3,	&P->X));  MOD_MUL(T3);
	TTLS_MPI_CHK(ttls_mpi_mul_int(&T1,  &T3,	2	));  MOD_ADD(T1);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&X,   &T2,	&T2  ));  MOD_MUL(X );
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&X,   &X,	 &T1  ));  MOD_SUB(X );
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&X,   &X,	 &T4  ));  MOD_SUB(X );
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&T3,  &T3,	&X	));  MOD_SUB(T3);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T3,  &T3,	&T2  ));  MOD_MUL(T3);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T4,  &T4,	&P->Y));  MOD_MUL(T4);
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&Y,   &T3,	&T4  ));  MOD_SUB(Y );

	TTLS_MPI_CHK(ttls_mpi_copy(&R->X, &X));
	TTLS_MPI_CHK(ttls_mpi_copy(&R->Y, &Y));
	TTLS_MPI_CHK(ttls_mpi_copy(&R->Z, &Z));

cleanup:

	ttls_mpi_free(&T1); ttls_mpi_free(&T2); ttls_mpi_free(&T3); ttls_mpi_free(&T4);
	ttls_mpi_free(&X); ttls_mpi_free(&Y); ttls_mpi_free(&Z);

	return ret;
}

/*
 * Randomize jacobian coordinates:
 * (X, Y, Z) -> (l^2 X, l^3 Y, l Z) for random l
 * This is sort of the reverse operation of ecp_normalize_jac().
 *
 * This countermeasure was first suggested in [2].
 */
static int ecp_randomize_jac(const ttls_ecp_group *grp, ttls_ecp_point *pt)
{
	int ret;
	ttls_mpi l, ll;
	size_t p_size;
	int count = 0;

#if defined(TTLS_ECP_RANDOMIZE_JAC_ALT)
	if (ttls_internal_ecp_grp_capable(grp))
	{
		return ttls_internal_ecp_randomize_jac(grp, pt);
	}
#endif /* TTLS_ECP_RANDOMIZE_JAC_ALT */

	p_size = (grp->pbits + 7) / 8;
	ttls_mpi_init(&l); ttls_mpi_init(&ll);

	/* Generate l such that 1 < l < p */
	do
	{
		TTLS_MPI_CHK(ttls_mpi_fill_random(&l, p_size));

		while (ttls_mpi_cmp_mpi(&l, &grp->P) >= 0)
			TTLS_MPI_CHK(ttls_mpi_shift_r(&l, 1));

		if (count++ > 10)
			return(TTLS_ERR_ECP_RANDOM_FAILED);
	}
	while (ttls_mpi_cmp_int(&l, 1) <= 0);

	/* Z = l * Z */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&pt->Z,   &pt->Z,	 &l )); MOD_MUL(pt->Z);

	/* X = l^2 * X */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&ll,	  &l,		 &l )); MOD_MUL(ll);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&pt->X,   &pt->X,	 &ll)); MOD_MUL(pt->X);

	/* Y = l^3 * Y */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&ll,	  &ll,		&l )); MOD_MUL(ll);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&pt->Y,   &pt->Y,	 &ll)); MOD_MUL(pt->Y);

cleanup:
	ttls_mpi_free(&l); ttls_mpi_free(&ll);

	return ret;
}

/*
 * Check and define parameters used by the comb method (see below for details)
 */
#if TTLS_ECP_WINDOW_SIZE < 2 || TTLS_ECP_WINDOW_SIZE > 7
#error "TTLS_ECP_WINDOW_SIZE out of bounds"
#endif

/* d = ceil(n / w) */
#define COMB_MAX_D	  (TTLS_ECP_MAX_BITS + 1) / 2

/* number of precomputed points */
#define COMB_MAX_PRE	(1 << (TTLS_ECP_WINDOW_SIZE - 1))

/*
 * Compute the representation of m that will be used with our comb method.
 *
 * The basic comb method is described in GECC 3.44 for example. We use a
 * modified version that provides resistance to SPA by avoiding zero
 * digits in the representation as in [3]. We modify the method further by
 * requiring that all K_i be odd, which has the small cost that our
 * representation uses one more K_i, due to carries.
 *
 * Also, for the sake of compactness, only the seven low-order bits of x[i]
 * are used to represent K_i, and the msb of x[i] encodes the the sign (s_i in
 * the paper): it is set if and only if if s_i == -1;
 *
 * Calling conventions:
 * - x is an array of size d + 1
 * - w is the size, ie number of teeth, of the comb, and must be between
 *   2 and 7 (in practice, between 2 and TTLS_ECP_WINDOW_SIZE)
 * - m is the MPI, expected to be odd and such that bitlength(m) <= w * d
 *   (the result will be incorrect if these assumptions are not satisfied)
 */
static void ecp_comb_fixed(unsigned char x[], size_t d,
				unsigned char w, const ttls_mpi *m)
{
	size_t i, j;
	unsigned char c, cc, adjust;

	memset(x, 0, d+1);

	/* First get the classical comb values (except for x_d = 0) */
	for (i = 0; i < d; i++)
		for (j = 0; j < w; j++)
			x[i] |= ttls_mpi_get_bit(m, i + d * j) << j;

	/* Now make sure x_1 .. x_d are odd */
	c = 0;
	for (i = 1; i <= d; i++)
	{
		/* Add carry and update it */
		cc   = x[i] & c;
		x[i] = x[i] ^ c;
		c = cc;

		/* Adjust if needed, avoiding branches */
		adjust = 1 - (x[i] & 0x01);
		c   |= x[i] & (x[i-1] * adjust);
		x[i] = x[i] ^ (x[i-1] * adjust);
		x[i-1] |= adjust << 7;
	}
}

/*
 * Precompute points for the comb method
 *
 * If i = i_{w-1} ... i_1 is the binary representation of i, then
 * T[i] = i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + P
 *
 * T must be able to hold 2^{w - 1} elements
 *
 * Cost: d(w-1) D + (2^{w-1} - 1) A + 1 N(w-1) + 1 N(2^{w-1} - 1)
 */
static int ecp_precompute_comb(const ttls_ecp_group *grp,
		ttls_ecp_point T[], const ttls_ecp_point *P,
		unsigned char w, size_t d)
{
	int ret;
	unsigned char i, k;
	size_t j;
	ttls_ecp_point *cur, *TT[COMB_MAX_PRE - 1];

	/*
	 * Set T[0] = P and
	 * T[2^{l-1}] = 2^{dl} P for l = 1 .. w-1 (this is not the final value)
	 */
	TTLS_MPI_CHK(ttls_ecp_copy(&T[0], P));

	k = 0;
	for (i = 1; i < (1U << (w - 1)); i <<= 1)
	{
		cur = T + i;
		TTLS_MPI_CHK(ttls_ecp_copy(cur, T + (i >> 1)));
		for (j = 0; j < d; j++)
			TTLS_MPI_CHK(ecp_double_jac(grp, cur, cur));

		TT[k++] = cur;
	}

	TTLS_MPI_CHK(ecp_normalize_jac_many(grp, TT, k));

	/*
	 * Compute the remaining ones using the minimal number of additions
	 * Be careful to update T[2^l] only after using it!
	 */
	k = 0;
	for (i = 1; i < (1U << (w - 1)); i <<= 1)
	{
		j = i;
		while (j--)
		{
			TTLS_MPI_CHK(ecp_add_mixed(grp, &T[i + j], &T[j], &T[i]));
			TT[k++] = &T[i + j];
		}
	}

	TTLS_MPI_CHK(ecp_normalize_jac_many(grp, TT, k));

cleanup:

	return ret;
}

/*
 * Select precomputed point: R = sign(i) * T[ abs(i) / 2 ]
 */
static int ecp_select_comb(const ttls_ecp_group *grp, ttls_ecp_point *R,
				const ttls_ecp_point T[], unsigned char t_len,
				unsigned char i)
{
	int ret;
	unsigned char ii, j;

	/* Ignore the "sign" bit and scale down */
	ii =  (i & 0x7Fu) >> 1;

	/* Read the whole table to thwart cache-based timing attacks */
	for (j = 0; j < t_len; j++)
	{
		TTLS_MPI_CHK(ttls_mpi_safe_cond_assign(&R->X, &T[j].X, j == ii));
		TTLS_MPI_CHK(ttls_mpi_safe_cond_assign(&R->Y, &T[j].Y, j == ii));
	}

	/* Safely invert result if i is "negative" */
	TTLS_MPI_CHK(ecp_safe_invert_jac(grp, R, i >> 7));

cleanup:
	return ret;
}

/*
 * Core multiplication algorithm for the (modified) comb method.
 * This part is actually common with the basic comb method (GECC 3.44)
 *
 * Cost: d A + d D + 1 R
 */
static int ecp_mul_comb_core(const ttls_ecp_group *grp, ttls_ecp_point *R,
				  const ttls_ecp_point T[], unsigned char t_len,
				  const unsigned char x[], size_t d, bool rnd)
{
	int ret;
	ttls_ecp_point Txi;
	size_t i;

	ttls_ecp_point_init(&Txi);

	/* Start with a non-zero point and randomize its coordinates */
	i = d;
	TTLS_MPI_CHK(ecp_select_comb(grp, R, T, t_len, x[i]));
	TTLS_MPI_CHK(ttls_mpi_lset(&R->Z, 1));
	if (rnd)
		TTLS_MPI_CHK(ecp_randomize_jac(grp, R));

	while (i-- != 0)
	{
		TTLS_MPI_CHK(ecp_double_jac(grp, R, R));
		TTLS_MPI_CHK(ecp_select_comb(grp, &Txi, T, t_len, x[i]));
		TTLS_MPI_CHK(ecp_add_mixed(grp, R, R, &Txi));
	}

cleanup:

	ttls_ecp_point_free(&Txi);

	return ret;
}

/*
 * Multiplication using the comb method,
 * for curves in short Weierstrass form
 */
static int ecp_mul_comb(ttls_ecp_group *grp, ttls_ecp_point *R,
			 const ttls_mpi *m, const ttls_ecp_point *P, bool rnd)
{
	int ret;
	unsigned char w, m_is_odd, p_eq_g, pre_len, i;
	size_t d;
	unsigned char k[COMB_MAX_D + 1];
	ttls_ecp_point *T;
	ttls_mpi M, mm;

	ttls_mpi_init(&M);
	ttls_mpi_init(&mm);

	/* we need N to be odd to trnaform m in an odd number, check now */
	if (ttls_mpi_get_bit(&grp->N, 0) != 1)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	/*
	 * Minimize the number of multiplications, that is minimize
	 * 10 * d * w + 18 * 2^(w-1) + 11 * d + 7 * w, with d = ceil(nbits / w)
	 * (see costs of the various parts, with 1S = 1M)
	 */
	w = grp->nbits >= 384 ? 5 : 4;

	/*
	 * If P == G, pre-compute a bit more, since this may be re-used later.
	 * Just adding one avoids upping the cost of the first mul too much,
	 * and the memory cost too.
	 */
#if TTLS_ECP_FIXED_POINT_OPTIM == 1
	p_eq_g = (ttls_mpi_cmp_mpi(&P->Y, &grp->G.Y) == 0 &&
			   ttls_mpi_cmp_mpi(&P->X, &grp->G.X) == 0);
	if (p_eq_g)
		w++;
#else
	p_eq_g = 0;
#endif

	/*
	 * Make sure w is within bounds.
	 * (The last test is useful only for very small curves in the test suite.)
	 */
	if (w > TTLS_ECP_WINDOW_SIZE)
		w = TTLS_ECP_WINDOW_SIZE;
	if (w >= grp->nbits)
		w = 2;

	/* Other sizes that depend on w */
	pre_len = 1U << (w - 1);
	d = (grp->nbits + w - 1) / w;

	/*
	 * Prepare precomputed points: if P == G we want to
	 * use grp->T if already initialized, or initialize it.
	 */
	T = p_eq_g ? grp->T : NULL;

	if (T == NULL)
	{
		T = ttls_calloc(pre_len, sizeof(ttls_ecp_point));
		if (T == NULL)
		{
			ret = TTLS_ERR_ECP_ALLOC_FAILED;
			goto cleanup;
		}

		TTLS_MPI_CHK(ecp_precompute_comb(grp, T, P, w, d));

		if (p_eq_g)
		{
			grp->T = T;
			grp->T_size = pre_len;
		}
	}

	/*
	 * Make sure M is odd (M = m or M = N - m, since N is odd)
	 * using the fact that m * P = - (N - m) * P
	 */
	m_is_odd = (ttls_mpi_get_bit(m, 0) == 1);
	TTLS_MPI_CHK(ttls_mpi_copy(&M, m));
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&mm, &grp->N, m));
	TTLS_MPI_CHK(ttls_mpi_safe_cond_assign(&M, &mm, ! m_is_odd));

	/*
	 * Go for comb multiplication, R = M * P
	 */
	ecp_comb_fixed(k, d, w, &M);
	TTLS_MPI_CHK(ecp_mul_comb_core(grp, R, T, pre_len, k, d, rnd));

	/*
	 * Now get m * P from M * P and normalize it
	 */
	TTLS_MPI_CHK(ecp_safe_invert_jac(grp, R, ! m_is_odd));
	TTLS_MPI_CHK(ecp_normalize_jac(grp, R));

cleanup:

	if (T != NULL && ! p_eq_g)
	{
		for (i = 0; i < pre_len; i++)
			ttls_ecp_point_free(&T[i]);
		ttls_free(T);
	}

	ttls_mpi_free(&M);
	ttls_mpi_free(&mm);

	if (ret != 0)
		ttls_ecp_point_free(R);

	return ret;
}

/*
 * For Montgomery curves, we do all the internal arithmetic in projective
 * coordinates. Import/export of points uses only the x coordinates, which is
 * internaly represented as X / Z.
 *
 * For scalar multiplication, we'll use a Montgomery ladder.
 */

/*
 * Normalize Montgomery x/z coordinates: X = X/Z, Z = 1
 * Cost: 1M + 1I
 */
static int ecp_normalize_mxz(const ttls_ecp_group *grp, ttls_ecp_point *P)
{
	int ret;

	TTLS_MPI_CHK(ttls_mpi_inv_mod(&P->Z, &P->Z, &grp->P));
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&P->X, &P->X, &P->Z)); MOD_MUL(P->X);
	TTLS_MPI_CHK(ttls_mpi_lset(&P->Z, 1));

cleanup:
	return ret;
}

/*
 * Randomize projective x/z coordinates:
 * (X, Z) -> (l X, l Z) for random l
 * This is sort of the reverse operation of ecp_normalize_mxz().
 *
 * This countermeasure was first suggested in [2].
 * Cost: 2M
 */
static int ecp_randomize_mxz(const ttls_ecp_group *grp, ttls_ecp_point *P)
{
	int ret;
	ttls_mpi l;
	size_t p_size;
	int count = 0;

	p_size = (grp->pbits + 7) / 8;
	ttls_mpi_init(&l);

	/* Generate l such that 1 < l < p */
	do
	{
		TTLS_MPI_CHK(ttls_mpi_fill_random(&l, p_size));

		while (ttls_mpi_cmp_mpi(&l, &grp->P) >= 0)
			TTLS_MPI_CHK(ttls_mpi_shift_r(&l, 1));

		if (count++ > 10)
			return(TTLS_ERR_ECP_RANDOM_FAILED);
	}
	while (ttls_mpi_cmp_int(&l, 1) <= 0);

	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&P->X, &P->X, &l)); MOD_MUL(P->X);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&P->Z, &P->Z, &l)); MOD_MUL(P->Z);

cleanup:
	ttls_mpi_free(&l);

	return ret;
}

/*
 * Double-and-add: R = 2P, S = P + Q, with d = X(P - Q),
 * for Montgomery curves in x/z coordinates.
 *
 * http://www.hyperelliptic.org/EFD/g1p/auto-code/montgom/xz/ladder/mladd-1987-m.op3
 * with
 * d =  X1
 * P = (X2, Z2)
 * Q = (X3, Z3)
 * R = (X4, Z4)
 * S = (X5, Z5)
 * and eliminating temporary variables tO, ..., t4.
 *
 * Cost: 5M + 4S
 */
static int ecp_double_add_mxz(const ttls_ecp_group *grp,
				   ttls_ecp_point *R, ttls_ecp_point *S,
				   const ttls_ecp_point *P, const ttls_ecp_point *Q,
				   const ttls_mpi *d)
{
	int ret;
	ttls_mpi A, AA, B, BB, E, C, D, DA, CB;

	ttls_mpi_init(&A); ttls_mpi_init(&AA); ttls_mpi_init(&B);
	ttls_mpi_init(&BB); ttls_mpi_init(&E); ttls_mpi_init(&C);
	ttls_mpi_init(&D); ttls_mpi_init(&DA); ttls_mpi_init(&CB);

	TTLS_MPI_CHK(ttls_mpi_add_mpi(&A,	&P->X,   &P->Z)); MOD_ADD(A	);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&AA,   &A,	  &A	)); MOD_MUL(AA  );
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&B,	&P->X,   &P->Z)); MOD_SUB(B	);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&BB,   &B,	  &B	)); MOD_MUL(BB  );
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&E,	&AA,	 &BB  )); MOD_SUB(E	);
	TTLS_MPI_CHK(ttls_mpi_add_mpi(&C,	&Q->X,   &Q->Z)); MOD_ADD(C	);
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&D,	&Q->X,   &Q->Z)); MOD_SUB(D	);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&DA,   &D,	  &A	)); MOD_MUL(DA  );
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&CB,   &C,	  &B	)); MOD_MUL(CB  );
	TTLS_MPI_CHK(ttls_mpi_add_mpi(&S->X, &DA,	 &CB  )); MOD_MUL(S->X);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&S->X, &S->X,   &S->X)); MOD_MUL(S->X);
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&S->Z, &DA,	 &CB  )); MOD_SUB(S->Z);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&S->Z, &S->Z,   &S->Z)); MOD_MUL(S->Z);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&S->Z, d,	   &S->Z)); MOD_MUL(S->Z);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&R->X, &AA,	 &BB  )); MOD_MUL(R->X);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&R->Z, &grp->A, &E	)); MOD_MUL(R->Z);
	TTLS_MPI_CHK(ttls_mpi_add_mpi(&R->Z, &BB,	 &R->Z)); MOD_ADD(R->Z);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&R->Z, &E,	  &R->Z)); MOD_MUL(R->Z);

cleanup:
	ttls_mpi_free(&A); ttls_mpi_free(&AA); ttls_mpi_free(&B);
	ttls_mpi_free(&BB); ttls_mpi_free(&E); ttls_mpi_free(&C);
	ttls_mpi_free(&D); ttls_mpi_free(&DA); ttls_mpi_free(&CB);

	return ret;
}

/*
 * Multiplication with Montgomery ladder in x/z coordinates,
 * for curves in Montgomery form
 */
static int ecp_mul_mxz(ttls_ecp_group *grp, ttls_ecp_point *R,
			const ttls_mpi *m, const ttls_ecp_point *P, bool rng)
{
	int ret;
	size_t i;
	unsigned char b;
	ttls_ecp_point RP;
	ttls_mpi PX;

	ttls_ecp_point_init(&RP); ttls_mpi_init(&PX);

	/* Save PX and read from P before writing to R, in case P == R */
	TTLS_MPI_CHK(ttls_mpi_copy(&PX, &P->X));
	TTLS_MPI_CHK(ttls_ecp_copy(&RP, P));

	/* Set R to zero in modified x/z coordinates */
	TTLS_MPI_CHK(ttls_mpi_lset(&R->X, 1));
	TTLS_MPI_CHK(ttls_mpi_lset(&R->Z, 0));
	ttls_mpi_free(&R->Y);

	/* RP.X might be sligtly larger than P, so reduce it */
	MOD_ADD(RP.X);

	/* Randomize coordinates of the starting point */
	if (rng)
		TTLS_MPI_CHK(ecp_randomize_mxz(grp, &RP));

	/* Loop invariant: R = result so far, RP = R + P */
	i = ttls_mpi_bitlen(m); /* one past the (zero-based) most significant bit */
	while (i-- > 0)
	{
		b = ttls_mpi_get_bit(m, i);
		/*
		 *  if (b) R = 2R + P else R = 2R,
		 * which is:
		 *  if (b) double_add(RP, R, RP, R)
		 *  else   double_add(R, RP, R, RP)
		 * but using safe conditional swaps to avoid leaks
		 */
		TTLS_MPI_CHK(ttls_mpi_safe_cond_swap(&R->X, &RP.X, b));
		TTLS_MPI_CHK(ttls_mpi_safe_cond_swap(&R->Z, &RP.Z, b));
		TTLS_MPI_CHK(ecp_double_add_mxz(grp, R, &RP, R, &RP, &PX));
		TTLS_MPI_CHK(ttls_mpi_safe_cond_swap(&R->X, &RP.X, b));
		TTLS_MPI_CHK(ttls_mpi_safe_cond_swap(&R->Z, &RP.Z, b));
	}

	TTLS_MPI_CHK(ecp_normalize_mxz(grp, R));

cleanup:
	ttls_ecp_point_free(&RP); ttls_mpi_free(&PX);

	return ret;
}

/*
 * Multiplication R = m * P
 */
int
ttls_ecp_mul(ttls_ecp_group *grp, ttls_ecp_point *R, const ttls_mpi *m,
	     const ttls_ecp_point *P, bool rnd)
{
	int ret = TTLS_ERR_ECP_BAD_INPUT_DATA;

	/* Common sanity checks */
	if (ttls_mpi_cmp_int(&P->Z, 1) != 0)
		return TTLS_ERR_ECP_BAD_INPUT_DATA;

	if ((ret = ttls_ecp_check_privkey(grp, m)) != 0 ||
		(ret = ttls_ecp_check_pubkey(grp, P)) != 0)
		return ret;

	if (ecp_get_type(grp) == ECP_TYPE_MONTGOMERY)
		ret = ecp_mul_mxz(grp, R, m, P, rnd);

	if (ecp_get_type(grp) == ECP_TYPE_SHORT_WEIERSTRASS)
		ret = ecp_mul_comb(grp, R, m, P, rnd);

	return ret;
}

/*
 * Check that an affine point is valid as a public key,
 * short weierstrass curves (SEC1 3.2.3.1)
 */
static int ecp_check_pubkey_sw(const ttls_ecp_group *grp, const ttls_ecp_point *pt)
{
	int ret;
	ttls_mpi YY, RHS;

	/* pt coordinates must be normalized for our checks */
	if (ttls_mpi_cmp_int(&pt->X, 0) < 0 ||
		ttls_mpi_cmp_int(&pt->Y, 0) < 0 ||
		ttls_mpi_cmp_mpi(&pt->X, &grp->P) >= 0 ||
		ttls_mpi_cmp_mpi(&pt->Y, &grp->P) >= 0)
		return(TTLS_ERR_ECP_INVALID_KEY);

	ttls_mpi_init(&YY); ttls_mpi_init(&RHS);

	/*
	 * YY = Y^2
	 * RHS = X (X^2 + A) + B = X^3 + A X + B
	 */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&YY,  &pt->Y,   &pt->Y ));  MOD_MUL(YY );
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&RHS, &pt->X,   &pt->X ));  MOD_MUL(RHS);

	/* Special case for A = -3 */
	if (grp->A.p == NULL)
	{
		TTLS_MPI_CHK(ttls_mpi_sub_int(&RHS, &RHS, 3	  ));  MOD_SUB(RHS);
	}
	else
	{
		TTLS_MPI_CHK(ttls_mpi_add_mpi(&RHS, &RHS, &grp->A));  MOD_ADD(RHS);
	}

	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&RHS, &RHS,	 &pt->X ));  MOD_MUL(RHS);
	TTLS_MPI_CHK(ttls_mpi_add_mpi(&RHS, &RHS,	 &grp->B));  MOD_ADD(RHS);

	if (ttls_mpi_cmp_mpi(&YY, &RHS) != 0)
		ret = TTLS_ERR_ECP_INVALID_KEY;

cleanup:
	ttls_mpi_free(&YY); ttls_mpi_free(&RHS);

	return ret;
}

/*
 * R = m * P with shortcuts for m == 1 and m == -1
 * NOT constant-time - ONLY for short Weierstrass!
 */
static int ttls_ecp_mul_shortcuts(ttls_ecp_group *grp,
			  ttls_ecp_point *R,
			  const ttls_mpi *m,
			  const ttls_ecp_point *P)
{
	int ret;

	if (ttls_mpi_cmp_int(m, 1) == 0)
	{
		TTLS_MPI_CHK(ttls_ecp_copy(R, P));
	}
	else if (ttls_mpi_cmp_int(m, -1) == 0)
	{
		TTLS_MPI_CHK(ttls_ecp_copy(R, P));
		if (ttls_mpi_cmp_int(&R->Y, 0) != 0)
			TTLS_MPI_CHK(ttls_mpi_sub_mpi(&R->Y, &grp->P, &R->Y));
	}
	else
	{
		TTLS_MPI_CHK(ttls_ecp_mul(grp, R, m, P, false));
	}

cleanup:
	return ret;
}

/*
 * Linear combination
 * NOT constant-time
 */
int ttls_ecp_muladd(ttls_ecp_group *grp, ttls_ecp_point *R,
			 const ttls_mpi *m, const ttls_ecp_point *P,
			 const ttls_mpi *n, const ttls_ecp_point *Q)
{
	int ret;
	ttls_ecp_point mP;
#if defined(TTLS_ECP_INTERNAL_ALT)
	char is_grp_capable = 0;
#endif

	if (ecp_get_type(grp) != ECP_TYPE_SHORT_WEIERSTRASS)
		return(TTLS_ERR_ECP_FEATURE_UNAVAILABLE);

	ttls_ecp_point_init(&mP);

	TTLS_MPI_CHK(ttls_ecp_mul_shortcuts(grp, &mP, m, P));
	TTLS_MPI_CHK(ttls_ecp_mul_shortcuts(grp, R,   n, Q));

#if defined(TTLS_ECP_INTERNAL_ALT)
	if ( is_grp_capable = ttls_internal_ecp_grp_capable(grp) )
	{
		TTLS_MPI_CHK(ttls_internal_ecp_init(grp));
	}

#endif /* TTLS_ECP_INTERNAL_ALT */
	TTLS_MPI_CHK(ecp_add_mixed(grp, R, &mP, R));
	TTLS_MPI_CHK(ecp_normalize_jac(grp, R));

cleanup:

#if defined(TTLS_ECP_INTERNAL_ALT)
	if (is_grp_capable)
	{
		ttls_internal_ecp_free(grp);
	}

#endif /* TTLS_ECP_INTERNAL_ALT */
	ttls_ecp_point_free(&mP);

	return ret;
}


/*
 * Check validity of a public key for Montgomery curves with x-only schemes
 */
static int ecp_check_pubkey_mx(const ttls_ecp_group *grp, const ttls_ecp_point *pt)
{
	/* [Curve25519 p. 5] Just check X is the correct number of bytes */
	if (ttls_mpi_size(&pt->X) > (grp->nbits + 7) / 8)
		return(TTLS_ERR_ECP_INVALID_KEY);

	return 0;
}

/*
 * Check that a point is valid as a public key
 */
int ttls_ecp_check_pubkey(const ttls_ecp_group *grp, const ttls_ecp_point *pt)
{
	/* Must use affine coordinates */
	if (ttls_mpi_cmp_int(&pt->Z, 1) != 0)
		return(TTLS_ERR_ECP_INVALID_KEY);

	if (ecp_get_type(grp) == ECP_TYPE_MONTGOMERY)
		return(ecp_check_pubkey_mx(grp, pt));
	if (ecp_get_type(grp) == ECP_TYPE_SHORT_WEIERSTRASS)
		return(ecp_check_pubkey_sw(grp, pt));
	return(TTLS_ERR_ECP_BAD_INPUT_DATA);
}

/*
 * Check that an ttls_mpi is valid as a private key
 */
int ttls_ecp_check_privkey(const ttls_ecp_group *grp, const ttls_mpi *d)
{
	if (ecp_get_type(grp) == ECP_TYPE_MONTGOMERY)
	{
		/* see [Curve25519] page 5 */
		if (ttls_mpi_get_bit(d, 0) != 0 ||
			ttls_mpi_get_bit(d, 1) != 0 ||
			ttls_mpi_get_bit(d, 2) != 0 ||
			ttls_mpi_bitlen(d) - 1 != grp->nbits) /* ttls_mpi_bitlen is one-based! */
			return(TTLS_ERR_ECP_INVALID_KEY);
		else
			return 0;
	}
	if (ecp_get_type(grp) == ECP_TYPE_SHORT_WEIERSTRASS)
	{
		/* see SEC1 3.2 */
		if (ttls_mpi_cmp_int(d, 1) < 0 ||
			ttls_mpi_cmp_mpi(d, &grp->N) >= 0)
			return(TTLS_ERR_ECP_INVALID_KEY);
		else
			return 0;
	}

	return(TTLS_ERR_ECP_BAD_INPUT_DATA);
}

/*
 * Generate a keypair with configurable base point
 */
static int
ttls_ecp_gen_keypair_base(ttls_ecp_group *grp, const ttls_ecp_point *G,
			  ttls_mpi *d, ttls_ecp_point *Q, bool rnd)
{
	int ret;
	size_t n_size = (grp->nbits + 7) / 8;

	if (ecp_get_type(grp) == ECP_TYPE_MONTGOMERY)
	{
		/* [M225] page 5 */
		size_t b;

		do {
			TTLS_MPI_CHK(ttls_mpi_fill_random(d, n_size));
		} while (ttls_mpi_bitlen(d) == 0);

		/* Make sure the most significant bit is nbits */
		b = ttls_mpi_bitlen(d) - 1; /* ttls_mpi_bitlen is one-based */
		if (b > grp->nbits)
			TTLS_MPI_CHK(ttls_mpi_shift_r(d, b - grp->nbits));
		else
			TTLS_MPI_CHK(ttls_mpi_set_bit(d, grp->nbits, 1));

		/* Make sure the last three bits are unset */
		TTLS_MPI_CHK(ttls_mpi_set_bit(d, 0, 0));
		TTLS_MPI_CHK(ttls_mpi_set_bit(d, 1, 0));
		TTLS_MPI_CHK(ttls_mpi_set_bit(d, 2, 0));
	}
	else
	if (ecp_get_type(grp) == ECP_TYPE_SHORT_WEIERSTRASS)
	{
		/* SEC1 3.2.1: Generate d such that 1 <= n < N */
		int count = 0;

		/*
		 * Match the procedure given in RFC 6979 (deterministic ECDSA):
		 * - use the same byte ordering;
		 * - keep the leftmost nbits bits of the generated octet string;
		 * - try until result is in the desired range.
		 * This also avoids any biais, which is especially important for ECDSA.
		 */
		do
		{
			TTLS_MPI_CHK(ttls_mpi_fill_random(d, n_size));
			TTLS_MPI_CHK(ttls_mpi_shift_r(d, 8 * n_size - grp->nbits));

			/*
			 * Each try has at worst a probability 1/2 of failing (the msb has
			 * a probability 1/2 of being 0, and then the result will be < N),
			 * so after 30 tries failure probability is a most 2**(-30).
			 *
			 * For most curves, 1 try is enough with overwhelming probability,
			 * since N starts with a lot of 1s in binary, but some curves
			 * such as secp224k1 are actually very close to the worst case.
			 */
			if (++count > 30)
				return(TTLS_ERR_ECP_RANDOM_FAILED);
		}
		while (ttls_mpi_cmp_int(d, 1) < 0 ||
			   ttls_mpi_cmp_mpi(d, &grp->N) >= 0);
	}
	else
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

cleanup:
	if (ret != 0)
		return ret;

	return ttls_ecp_mul(grp, Q, d, G, rnd);
}

/*
 * Generate key pair, wrapper for conventional base point
 */
int ttls_ecp_gen_keypair(ttls_ecp_group *grp,
		 ttls_mpi *d, ttls_ecp_point *Q)
{
	return ttls_ecp_gen_keypair_base(grp, &grp->G, d, Q, true);
}

/*
 * Generate a keypair, prettier wrapper
 */
int ttls_ecp_gen_key(ttls_ecp_group_id grp_id, ttls_ecp_keypair *key)
{
	int ret;

	if ((ret = ttls_ecp_group_load(&key->grp, grp_id)) != 0)
		return ret;

	return(ttls_ecp_gen_keypair(&key->grp, &key->d, &key->Q));
}

/*
 * Check a public-private key pair
 */
int ttls_ecp_check_pub_priv(const ttls_ecp_keypair *pub, const ttls_ecp_keypair *prv)
{
	int ret;
	ttls_ecp_point Q;
	ttls_ecp_group grp;

	if (pub->grp.id == TTLS_ECP_DP_NONE ||
		pub->grp.id != prv->grp.id ||
		ttls_mpi_cmp_mpi(&pub->Q.X, &prv->Q.X) ||
		ttls_mpi_cmp_mpi(&pub->Q.Y, &prv->Q.Y) ||
		ttls_mpi_cmp_mpi(&pub->Q.Z, &prv->Q.Z))
	{
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);
	}

	ttls_ecp_point_init(&Q);
	ttls_ecp_group_init(&grp);

	/* ttls_ecp_mul() needs a non-const group... */
	ttls_ecp_group_copy(&grp, &prv->grp);

	/* Also checks d is valid */
	TTLS_MPI_CHK(ttls_ecp_mul(&grp, &Q, &prv->d, &prv->grp.G, false));

	if (ttls_mpi_cmp_mpi(&Q.X, &prv->Q.X) ||
		ttls_mpi_cmp_mpi(&Q.Y, &prv->Q.Y) ||
		ttls_mpi_cmp_mpi(&Q.Z, &prv->Q.Z))
	{
		ret = TTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

cleanup:
	ttls_ecp_point_free(&Q);
	ttls_ecp_group_free(&grp);

	return ret;
}

/*
 * Checkup routine
 */
int ttls_ecp_self_test(int verbose)
{
	int ret;
	size_t i;
	ttls_ecp_group grp;
	ttls_ecp_point R, P;
	ttls_mpi m;
	unsigned long add_c_prev, dbl_c_prev, mul_c_prev;
	/* exponents especially adapted for secp192r1 */
	const char *exponents[] =
	{
		"000000000000000000000000000000000000000000000001", /* one */
		"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22830", /* N - 1 */
		"5EA6F389A38B8BC81E767753B15AA5569E1782E30ABE7D25", /* random */
		"400000000000000000000000000000000000000000000000", /* one and zeros */
		"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", /* all ones */
		"555555555555555555555555555555555555555555555555", /* 101010... */
	};

	ttls_ecp_group_init(&grp);
	ttls_ecp_point_init(&R);
	ttls_ecp_point_init(&P);
	ttls_mpi_init(&m);

	/* Use secp192r1 if available, or any available curve */
	TTLS_MPI_CHK(ttls_ecp_group_load(&grp, TTLS_ECP_DP_SECP192R1));

	if (verbose != 0)
		ttls_printf("  ECP test #1 (constant op_count, base point G): ");

	/* Do a dummy multiplication first to trigger precomputation */
	TTLS_MPI_CHK(ttls_mpi_lset(&m, 2));
	TTLS_MPI_CHK(ttls_ecp_mul(&grp, &P, &m, &grp.G, false));

	add_count = 0;
	dbl_count = 0;
	mul_count = 0;
	TTLS_MPI_CHK(ttls_mpi_read_string(&m, 16, exponents[0]));
	TTLS_MPI_CHK(ttls_ecp_mul(&grp, &R, &m, &grp.G, false));

	for (i = 1; i < sizeof(exponents) / sizeof(exponents[0]); i++)
	{
		add_c_prev = add_count;
		dbl_c_prev = dbl_count;
		mul_c_prev = mul_count;
		add_count = 0;
		dbl_count = 0;
		mul_count = 0;

		TTLS_MPI_CHK(ttls_mpi_read_string(&m, 16, exponents[i]));
		TTLS_MPI_CHK(ttls_ecp_mul(&grp, &R, &m, &grp.G, false));

		if (add_count != add_c_prev ||
			dbl_count != dbl_c_prev ||
			mul_count != mul_c_prev)
		{
			if (verbose != 0)
				ttls_printf("failed (%u)\n", (unsigned int) i);

			ret = 1;
			goto cleanup;
		}
	}

	if (verbose != 0)
		ttls_printf("passed\n");

	if (verbose != 0)
		ttls_printf("  ECP test #2 (constant op_count, other point): ");
	/* We computed P = 2G last time, use it */

	add_count = 0;
	dbl_count = 0;
	mul_count = 0;
	TTLS_MPI_CHK(ttls_mpi_read_string(&m, 16, exponents[0]));
	TTLS_MPI_CHK(ttls_ecp_mul(&grp, &R, &m, &P, false));

	for (i = 1; i < sizeof(exponents) / sizeof(exponents[0]); i++)
	{
		add_c_prev = add_count;
		dbl_c_prev = dbl_count;
		mul_c_prev = mul_count;
		add_count = 0;
		dbl_count = 0;
		mul_count = 0;

		TTLS_MPI_CHK(ttls_mpi_read_string(&m, 16, exponents[i]));
		TTLS_MPI_CHK(ttls_ecp_mul(&grp, &R, &m, &P, false));

		if (add_count != add_c_prev ||
			dbl_count != dbl_c_prev ||
			mul_count != mul_c_prev)
		{
			if (verbose != 0)
				ttls_printf("failed (%u)\n", (unsigned int) i);

			ret = 1;
			goto cleanup;
		}
	}

	if (verbose != 0)
		ttls_printf("passed\n");

cleanup:

	if (ret < 0 && verbose != 0)
		ttls_printf("Unexpected error, return code = %08X\n", ret);

	ttls_ecp_group_free(&grp);
	ttls_ecp_point_free(&R);
	ttls_ecp_point_free(&P);
	ttls_mpi_free(&m);

	if (verbose != 0)
		ttls_printf("\n");

	return ret;
}
