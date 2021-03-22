/**
 *		Tempesta TLS
 *
 * TLS Ciphersuites definitions.
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
#ifndef TTLS_CIPHERSUITES_H
#define TTLS_CIPHERSUITES_H

#include "bignum.h"
#include "crypto.h"
#include "pk.h"

/*
 * Supported ciphersuites and/or recommended by IANA ciphersuites
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
 */
#define TTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256	0x9E
#define TTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384	0x9F
#define TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256	0xC02B
#define TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384	0xC02C
#define TTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	0xC02F
#define TTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	0xC030
#define TTLS_TLS_DHE_RSA_WITH_AES_128_CCM		0xC09E
#define TTLS_TLS_DHE_RSA_WITH_AES_256_CCM		0xC09F

/*
 * Reminder: update ttls_premaster_secret when adding a new key exchange.
 * Reminder: update TTLS_KEY_EXCHANGE__xxx below
 */
typedef enum {
	TTLS_KEY_EXCHANGE_NONE = 0,
	TTLS_KEY_EXCHANGE_DHE_RSA,
	TTLS_KEY_EXCHANGE_ECDHE_RSA,
	TTLS_KEY_EXCHANGE_ECDHE_ECDSA,
} ttls_key_exchange_type_t;

/**
 * This structure is used for storing ciphersuite information.
 *
 * @mpi_profile		- memory profiles for the corresponding key exchange.
 *			  EC ciphersuites use __TTLS_ECP_DP_N profiles.
 */
typedef struct {
	int				id;
	const char			*name;
	ttls_cipher_type_t		cipher;
	ttls_md_type_t			mac;
	ttls_key_exchange_type_t	key_exchange;
	unsigned char			flags;
	TlsMpiPool			*mpi_profile[__TTLS_ECP_DP_N - 1];
} TlsCiphersuite;

TlsMpiPool *ttls_ciphersuite_addr_mp(void *addr);
int ttls_ciphersuite_for_all(int (*actor)(TlsCiphersuite *cs));

const TlsCiphersuite *ttls_ciphersuite_from_id(int ciphersuite_id);
ttls_pk_type_t ttls_get_ciphersuite_sig_pk_alg(const TlsCiphersuite *info);
ttls_pk_type_t ttls_get_ciphersuite_sig_alg(const TlsCiphersuite *info);
int ttls_ciphersuite_uses_ec(const TlsCiphersuite *info);

static inline int
ttls_ciphersuite_cert_req_allowed(const TlsCiphersuite *info)
{
	switch (info->key_exchange) {
	case TTLS_KEY_EXCHANGE_DHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
		return 1;
	default:
		return 0;
	}
}

#endif /* TTLS_CIPHERSUITES_H */
