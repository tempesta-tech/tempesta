/**
 *		Tempesta TLS
 *
 * TLS ciphersuites.
 *
 * Only IANA recommended (RFC 8447) cipher suites are presented here.
 * See also https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2021 Tempesta Technologies, Inc.
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
#include "ciphersuites.h"
#include "mpool.h"
#include "ttls.h"

/*
 * TLS memory profiles for all supported key exchanges.
 * All the profiles are small enough, so one page (order=0) is enough.
 */
static union {
	TlsMpiPool	mp;
	unsigned char	_[PAGE_SIZE];
}
cs_mp_ecdhe_secp256 __page_aligned_data = {
	.mp = { .curr = sizeof(TlsMpiPool) }
},
cs_mp_ecdhe_curve25519 __page_aligned_data = {
	.mp = { .curr = sizeof(TlsMpiPool) }
},
cs_mp_dhe __page_aligned_data = {
	.mp = { .curr = sizeof(TlsMpiPool) }
};

static TlsCiphersuite ciphersuite_definitions[] = {
	{ TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	  "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
	  TTLS_CIPHER_AES_128_GCM, TTLS_MD_SHA256,
	  TTLS_KEY_EXCHANGE_ECDHE_ECDSA,
	  0, { &cs_mp_ecdhe_secp256.mp, &cs_mp_ecdhe_curve25519.mp } },
	{ TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	  "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384",
	  TTLS_CIPHER_AES_256_GCM, TTLS_MD_SHA384,
	  TTLS_KEY_EXCHANGE_ECDHE_ECDSA,
	  0, { &cs_mp_ecdhe_secp256.mp, &cs_mp_ecdhe_curve25519.mp } },
	{ TTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	  "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
	  TTLS_CIPHER_AES_128_GCM, TTLS_MD_SHA256,
	  TTLS_KEY_EXCHANGE_ECDHE_RSA,
	  0, { &cs_mp_ecdhe_secp256.mp, &cs_mp_ecdhe_curve25519.mp } },
	{ TTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	  "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
	  TTLS_CIPHER_AES_256_GCM, TTLS_MD_SHA384,
	  TTLS_KEY_EXCHANGE_ECDHE_RSA,
	  0, { &cs_mp_ecdhe_secp256.mp, &cs_mp_ecdhe_curve25519.mp } },
	{ TTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	  "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384",
	  TTLS_CIPHER_AES_256_GCM, TTLS_MD_SHA384,
	  TTLS_KEY_EXCHANGE_DHE_RSA,
	  0, { &cs_mp_dhe.mp, NULL } },
	{ TTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	  "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256",
	  TTLS_CIPHER_AES_128_GCM, TTLS_MD_SHA256,
	  TTLS_KEY_EXCHANGE_DHE_RSA,
	  0, { &cs_mp_dhe.mp, NULL } },
	{ TTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
	  "TLS-DHE-RSA-WITH-AES-256-CCM",
	  TTLS_CIPHER_AES_256_CCM, TTLS_MD_SHA256,
	  TTLS_KEY_EXCHANGE_DHE_RSA,
	  0, { &cs_mp_dhe.mp, NULL } },
	{ TTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
	  "TLS-DHE-RSA-WITH-AES-128-CCM",
	  TTLS_CIPHER_AES_128_CCM, TTLS_MD_SHA256,
	  TTLS_KEY_EXCHANGE_DHE_RSA,
	  0, { &cs_mp_dhe.mp, NULL } },
	{ 0, "", TTLS_CIPHER_NONE, TTLS_MD_NONE, TTLS_KEY_EXCHANGE_NONE,
	  0, { NULL, NULL } }
};

#define __CS_ADDR_MP(mp_name, x)					\
do {									\
	if (x > (unsigned long)&cs_mp_##mp_name				\
	    && x < (unsigned long)&cs_mp_##mp_name + PAGE_SIZE)		\
		return &cs_mp_##mp_name.mp;				\
} while (0)

/**
 * @return MPI pool by an address from it.
 */
TlsMpiPool *
ttls_ciphersuite_addr_mp(void *addr)
{
	unsigned long x = (unsigned long)addr;

	__CS_ADDR_MP(ecdhe_secp256, x);
	__CS_ADDR_MP(dhe, x);

	return NULL;
}

int
ttls_ciphersuite_for_all(int (*actor)(TlsCiphersuite *cs))
{
	TlsCiphersuite *cur = ciphersuite_definitions;

	while (cur->id) {
		int r = actor(cur);
		if (r)
			return r;
		cur++;
	}

	return 0;
}

const TlsCiphersuite *
ttls_ciphersuite_from_id(int ciphersuite)
{
	const TlsCiphersuite *cur = ciphersuite_definitions;

	while (cur->id) {
		if (cur->id == ciphersuite)
			return cur;
		cur++;
	}

	return NULL;
}

const char *
ttls_get_ciphersuite_name(const int ciphersuite_id)
{
	const TlsCiphersuite *cur;

	if (!(cur = ttls_ciphersuite_from_id(ciphersuite_id)))
		return "unknown";

	return cur->name;
}

ttls_pk_type_t
ttls_get_ciphersuite_sig_pk_alg(const TlsCiphersuite *info)
{
	switch (info->key_exchange) {
	case TTLS_KEY_EXCHANGE_DHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDHE_RSA:
		return TTLS_PK_RSA;
	case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
		return TTLS_PK_ECDSA;
	default:
		return TTLS_PK_NONE;
	}
}

ttls_pk_type_t
ttls_get_ciphersuite_sig_alg(const TlsCiphersuite *info)
{
	switch (info->key_exchange) {
	case TTLS_KEY_EXCHANGE_DHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDHE_RSA:
		return TTLS_PK_RSA;
	case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
		return TTLS_PK_ECDSA;
	default:
		return TTLS_PK_NONE;
	}
}

int
ttls_ciphersuite_uses_ec(const TlsCiphersuite *info)
{
	switch (info->key_exchange) {
	case TTLS_KEY_EXCHANGE_ECDHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
		return 1;
	default:
		return 0;
	}
}
