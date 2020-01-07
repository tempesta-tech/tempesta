/*
 *		Tempesta TLS
 *
 * Elliptic curves over GF(p).
 *
 * References:
 *
 * [1] BERNSTEIN, Daniel J. Curve25519: new Diffie-Hellman speed records.
 *	 <http://cr.yp.to/ecdh/curve25519-20060209.pdf>
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
 *
 * [4] Certicom Research. SEC 2: Recommended Elliptic Curve Domain Parameters.
 *	 <http://www.secg.org/sec2-v2.pdf>
 *
 * [5] HANKERSON, Darrel, MENEZES, Alfred J., VANSTONE, Scott. Guide to Elliptic
 *	 Curve Cryptography.
 *
 * [6] Digital Signature Standard (DSS), FIPS 186-4.
 *	 <http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
 *
 * [7] Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer 
 *	 Security (TLS) Versions 1.2 and Earlier, RFC 8422.
 *
 * [8] <http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html>
 *
 * [9] COHEN, Henri. A Course in Computational Algebraic Number Theory.
 *	 Springer Science & Business Media, 1 Aug 2000
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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
#ifndef TTLS_ECP_H
#define TTLS_ECP_H

#include "bignum.h"

/*
 * ECP error codes
 */
#define TTLS_ERR_ECP_BAD_INPUT_DATA		-0x4F80  /**< Bad input parameters to function. */
#define TTLS_ERR_ECP_FEATURE_UNAVAILABLE			   -0x4E80  /**< Requested curve not available. */
#define TTLS_ERR_ECP_VERIFY_FAILED		 -0x4E00  /**< The signature is not valid. */
#define TTLS_ERR_ECP_RANDOM_FAILED		 -0x4D00  /**< Generation of random value, such as (ephemeral) key, failed. */
#define TTLS_ERR_ECP_SIG_LEN_MISMATCH				  -0x4C00  /**< Signature is valid but shorter than the user-supplied length. */

/**
 * Domain parameters (curve, subgroup and generator) identifiers.
 *
 * Only curves over prime fields and recommended by IANA are supported.
 * See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
 *
 * WARNING This library does not support validation of arbitrary domain
 * parameters. Therefore, only well-known domain parameters from trusted
 * sources should be used. See ttls_ecp_group_load().
 */
typedef enum {
	TTLS_ECP_DP_NONE = 0,
	__TTLS_ECP_DP_FIRST,
	TTLS_ECP_DP_SECP256R1 = __TTLS_ECP_DP_FIRST, /* 256-bits NIST curve */
	TTLS_ECP_DP_SECP384R1,			     /* 384-bits NIST curve */
	TTLS_ECP_DP_CURVE25519,			     /* Curve25519, 128 bit */
	__TTLS_ECP_DP_N
} ttls_ecp_group_id;

extern ttls_ecp_group_id ttls_preset_curves[];

/**
 * Number of supported curves (plus one for NONE).
 *
 * (Montgomery curves excluded for now.)
 */
#define TTLS_ECP_DP_MAX	 12

/*
 * Maximum "window" size used for point multiplication.
 * Default: 6. Minimum value: 2. Maximum value: 7.
 *
 * Result is an array of at most TTLS_ECP_WINDOW_SIZE points used for point
 * multiplication. This value is directly tied to EC peak memory usage, so
 * decreasing it by one should roughly cut memory usage by two (if large curves
 * are in use).
 *
 * Reduction in size may reduce speed, but larger curves are impacted first.
 */
#define TTLS_ECP_WINDOW_ORDER	6
#define TTLS_ECP_WINDOW_SIZE	(1 << (TTLS_ECP_WINDOW_ORDER - 1))

/**
 * Curve information for use by other modules.
 *
 * @grp_id		- nternal identifier;
 * @tls_id		- TLS NamedCurve identifier;
 * @bit_size		- urve size in bits;
 * @name		- human-friendly name;
 */
typedef struct {
	ttls_ecp_group_id	grp_id;
	uint16_t		tls_id;
	uint16_t		bit_size;
	const char		*name;
} TlsEcpCurveInfo;

/**
 * ECP point structure (Jacobian coordinates).
 *
 * All functions expect and return points satisfying the following condition:
 * Z == 0 or Z == 1. (Other values of Z are used by internal functions only.)
 * The point is zero, or "at infinity", if Z == 0. Otherwise, X and Y are its
 * standard (affine) coordinates.
 *
 * @X	- the point's X coordinate;
 * @Y	- the point's Y coordinate;
 * @Z	- the point's Z coordinate;
 */
typedef struct {
	TlsMpi		X;
	TlsMpi		Y;
	TlsMpi		Z;
} TlsEcpPoint;

/**
 * ECP group structure.
 *
 * We consider two types of curves equations:
 * 1. Short Weierstrass,  y^2 = x^3 + A x + B    mod P  (SEC1)
 * 2. Montgomery,	  y^2 = x^3 + A x^2 + x  mod P  (Curve25519 + draft)
 *
 * In both cases, a generator G for a prime-order subgroup is fixed. In the
 * short weierstrass, this subgroup is actually the whole curve, and its
 * cardinal is denoted by N.
 *
 * In the case of Short Weierstrass curves, our code requires that N is an odd
 * prime. (Use odd in ttls_ecp_mul() and prime in ECDSA signature for blinding.)
 *
 * In the case of Montgomery curves, we don't store A but (A + 2) / 4 which is
 * the quantity actually used in the formulas. Also, nbits is not the size of N
 * but the required size for private keys.
 *
 * If modp is NULL, reduction modulo P is done using a generic algorithm.
 * Otherwise, it must point to a function that takes an TlsMpi in the range
 * 0..2^(2*pbits)-1 and transforms it in-place in an integer of little more
 * than pbits, so that the integer may be efficiently brought in the 0..P-1
 * range by a few additions or substractions. It must return 0 on success and
 * non-zero on failure.
 *
 * @id		- internal group identifier;
 * @h		- internal: 1 if the constants are static;
 * @pbits	- number of bits in P;
 * @nbits	- number of bits in 1. P, or 2. private keys;
 * @modp	- function for fast reduction mod P;
 * @P		- prime modulus of the base field;
 * @A		- 1. A in the equation, or 2. (A + 2) / 4;
 * @B		- 1. B in the equation, or 2. unused;
 * @N		- 1. the order of G, or 2. unused;
 * @G		- generator of the (sub)group used;
 * @T		- pre-computed points for ecp_mul_comb(). While X and Y
 *		  coordinates are the only used, we still have to keep the full
 *		  3D points as they're need for points doubling in Jacobian
 *		  coordinates with following normalization, see
 *		  ecp_precompute_comb().
 *		  TODO #1064: probably we can double the points w/o 3D
 *			      normalization immediately in 2D format.
 */
typedef struct {
	ttls_ecp_group_id	id;
	unsigned int		h;
	unsigned int		pbits;
	unsigned int		nbits;
	int			(*modp)(TlsMpi *);
	TlsMpi			P;
	TlsMpi			A;
	TlsMpi			B;
	TlsMpi			N;
	TlsEcpPoint		G;
	TlsEcpPoint		T[TTLS_ECP_WINDOW_SIZE];
} TlsEcpGrp;

/*
 * ECP key pair structure - a generic key pair that could be used for ECDSA,
 * fixed ECDH, etc.
 *
 * @grp		- Elliptic curve and base point;
 * @Q		- our public value;
 * @d		- our secret value;
 */
typedef struct {
	TlsEcpGrp		*grp;
	TlsEcpPoint		Q;
	TlsMpi			d;
} TlsEcpKeypair;

/* Maximum bit size of the groups (that is, of N and P). */
#define TTLS_ECP_MAX_BITS	384
#define TTLS_ECP_MAX_BYTES	((TTLS_ECP_MAX_BITS + 7) / 8)

/* Uncompressed is the only point format supported by RFC 8422. */
#define TTLS_ECP_PF_UNCOMPRESSED	0

/* The only allowed ECCurveType by RFC 8422 5.4. */
#define TTLS_ECP_TLS_NAMED_CURVE	3

const TlsEcpCurveInfo *ttls_ecp_curve_info_from_grp_id(ttls_ecp_group_id grp_id);
const TlsEcpCurveInfo *ttls_ecp_curve_info_from_tls_id(uint16_t tls_id);

void ttls_ecp_point_init(TlsEcpPoint *pt);
void ttls_ecp_keypair_init(TlsEcpKeypair *key);
void ttls_ecp_keypair_free(TlsEcpKeypair *key);

int ttls_ecp_copy(TlsEcpPoint *P, const TlsEcpPoint *Q);
int ttls_ecp_set_zero(TlsEcpPoint *pt);
int ttls_ecp_is_zero(TlsEcpPoint *pt);

int ttls_ecp_point_read_binary(const TlsEcpGrp *grp, TlsEcpPoint *P,
			       const unsigned char *buf, size_t ilen);
int ttls_ecp_tls_read_point(const TlsEcpGrp *grp, TlsEcpPoint *pt,
			    const unsigned char **buf, size_t len);
int ttls_ecp_tls_write_point(const TlsEcpGrp *grp, const TlsEcpPoint *pt,
			     size_t *olen, unsigned char *buf, size_t blen);
int ttls_ecp_tls_read_group(TlsEcpGrp *grp, const unsigned char **buf,
			    size_t len);
int ttls_ecp_tls_write_group(const TlsEcpGrp *grp, size_t *olen,
			     unsigned char *buf, size_t blen);

TlsEcpGrp * ttls_ecp_group_lookup(ttls_ecp_group_id id);
int ttls_ecp_group_load(TlsEcpGrp *grp, ttls_ecp_group_id id);

int ecp_precompute_comb(const TlsEcpGrp *grp, TlsEcpPoint T[],
			const TlsEcpPoint *P,unsigned char w, size_t d);

int ttls_ecp_mul(TlsEcpGrp *grp, TlsEcpPoint *R, const TlsMpi *m,
		 const TlsEcpPoint *P, bool rnd);
int ttls_ecp_muladd(TlsEcpGrp *grp, TlsEcpPoint *R, const TlsMpi *m,
		    const TlsMpi *n, const TlsEcpPoint *Q);

int ttls_ecp_check_pubkey(const TlsEcpGrp *grp, const TlsEcpPoint *pt);
int ttls_ecp_check_privkey(const TlsEcpGrp *grp, const TlsMpi *d);
int ttls_ecp_gen_keypair(TlsEcpGrp *grp, TlsMpi *d, TlsEcpPoint *Q);

#if defined(DEBUG) && DEBUG == 3
/* Print data structures containing MPIs on higest debug level only. */
#define T_DBG_ECP(msg, x)		__log_mpis(2, msg, (x)->X, (x)->Y)
#else
#define T_DBG_ECP(msg, x)
#endif

#endif /* ecp.h */
