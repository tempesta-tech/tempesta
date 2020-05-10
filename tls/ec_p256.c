/**
 *		Tempesta TLS
 *
 * Elliptic curve NIST secp256r1 (prime256v1).
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
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

/*
 * Domain parameters for secp256r1 (prime256v1) - Generalized Mersenne primes.
 * The constants are in little-endian order to be directly copied into MPIs.
 */
const unsigned long secp256r1_p[] = {
	0xffffffffffffffffUL, 0xffffffffUL, 0UL, 0xffffffff00000001UL
};
const unsigned long secp256r1_b[] = {
	0x3bce3c3e27d2604bUL, 0x651d06b0cc53b0f6UL,
	0xb3ebbd55769886bcUL, 0x5ac635d8aa3a93e7UL
};
const unsigned long secp256r1_gx[] = {
	0xf4a13945d898c296UL, 0x77037d812deb33a0UL,
	0xf8bce6e563a440f2UL, 0x6b17d1f2e12c4247UL
};
const unsigned long secp256r1_gy[] = {
	0xcbb6406837bf51f5UL, 0x2bce33576b315eceUL,
	0x8ee7eb4a7c0f9e16UL, 0x4fe342e2fe1a7f9bUL
};
const unsigned long secp256r1_n[] = {
	0xf3b9cac2fc632551UL, 0xbce6faada7179e84UL,
	0xffffffffffffffffUL, 0xffffffff00000000UL
};
