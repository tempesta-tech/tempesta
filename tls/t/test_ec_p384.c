/**
 *		Tempesta TLS EC NIST secp384r1 unit test
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
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
#include "ttls_mocks.h"
/* mpool.c requires DHM routines. */
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c"
#include "../asn1.c"
#include "../ec_p384.c"
#include "../ecp.c"
#include "../mpool.c"

/* Mock irrelevant groups. */
const TlsEcpGrp SECP256_G = {};
const TlsEcpGrp CURVE25519_G = {};

int
main(int argc, char *argv[])
{
	BUG_ON(ttls_mpool_init());

	/* TODO #1335 no real tests, just check initialization for now. */

	ttls_mpool_exit();

	printf("success\n");

	return 0;
}
