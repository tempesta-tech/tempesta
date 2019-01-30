/*
 *		Tempesta TLS
 *
 * TLS Ciphersuites definitions.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#ifndef TTLS_CIPHERSUITES_H
#define TTLS_CIPHERSUITES_H

#include "pk.h"
#include "crypto.h"

/*
 * Supported ciphersuites (Official IANA names)
 */
#define TTLS_TLS_RSA_WITH_AES_128_GCM_SHA256		0x9C
#define TTLS_TLS_RSA_WITH_AES_256_GCM_SHA384		0x9D
#define TTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256	0x9E
#define TTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384	0x9F

#define TTLS_TLS_PSK_WITH_AES_128_GCM_SHA256		0xA8
#define TTLS_TLS_PSK_WITH_AES_256_GCM_SHA384		0xA9
#define TTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256	0xAA
#define TTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384	0xAB
#define TTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256	0xAC
#define TTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384	0xAD

#define TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256	0xC02B
#define TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384	0xC02C
#define TTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256	0xC02D
#define TTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384	0xC02E
#define TTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	0xC02F
#define TTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	0xC030
#define TTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256	0xC031
#define TTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384	0xC032

#define TTLS_TLS_RSA_WITH_AES_128_CCM			0xC09C
#define TTLS_TLS_RSA_WITH_AES_256_CCM			0xC09D
#define TTLS_TLS_DHE_RSA_WITH_AES_128_CCM		0xC09E
#define TTLS_TLS_DHE_RSA_WITH_AES_256_CCM		0xC09F
#define TTLS_TLS_RSA_WITH_AES_128_CCM_8			0xC0A0
#define TTLS_TLS_RSA_WITH_AES_256_CCM_8			0xC0A1
#define TTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8		0xC0A2
#define TTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8		0xC0A3
#define TTLS_TLS_PSK_WITH_AES_128_CCM			0xC0A4
#define TTLS_TLS_PSK_WITH_AES_256_CCM			0xC0A5
#define TTLS_TLS_DHE_PSK_WITH_AES_128_CCM		0xC0A6
#define TTLS_TLS_DHE_PSK_WITH_AES_256_CCM		0xC0A7
#define TTLS_TLS_PSK_WITH_AES_128_CCM_8			0xC0A8
#define TTLS_TLS_PSK_WITH_AES_256_CCM_8			0xC0A9
#define TTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8		0xC0AA
#define TTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8		0xC0AB
/* The last two are named with PSK_DHE in the RFC, which looks like a typo */

#define TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM		0xC0AC
#define TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM		0xC0AD
#define TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8		0xC0AE
#define TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8		0xC0AF

/* Reminder: update ttls_premaster_secret when adding a new key exchange.
 * Reminder: update TTLS_KEY_EXCHANGE__xxx below
 */
typedef enum {
	TTLS_KEY_EXCHANGE_NONE = 0,
	TTLS_KEY_EXCHANGE_RSA,
	TTLS_KEY_EXCHANGE_DHE_RSA,
	TTLS_KEY_EXCHANGE_ECDHE_RSA,
	TTLS_KEY_EXCHANGE_ECDHE_ECDSA,
	TTLS_KEY_EXCHANGE_PSK,
	TTLS_KEY_EXCHANGE_DHE_PSK,
	TTLS_KEY_EXCHANGE_RSA_PSK,
	TTLS_KEY_EXCHANGE_ECDHE_PSK,
	TTLS_KEY_EXCHANGE_ECDH_RSA,
	TTLS_KEY_EXCHANGE_ECDH_ECDSA,
} ttls_key_exchange_type_t;

/* Key exchanges allowing client certificate requests */
//#define TTLS_KEY_EXCHANGE__CERT_REQ_ALLOWED__ENABLED

/* Weak ciphersuite flag  */
#define TTLS_CIPHERSUITE_WEAK		0x01
/* Short authentication tag, eg for CCM_8 */
#define TTLS_CIPHERSUITE_SHORT_TAG	0x02

/**
 * This structure is used for storing ciphersuite information.
 */
typedef struct {
	int				id;
	const char			*name;
	ttls_cipher_type_t		cipher;
	ttls_md_type_t			mac;
	ttls_key_exchange_type_t	key_exchange;
	int				min_major_ver;
	int				min_minor_ver;
	int				max_major_ver;
	int				max_minor_ver;
	unsigned char			flags;
} TlsCiphersuite;

const TlsCiphersuite *ttls_ciphersuite_from_id(int ciphersuite_id);

ttls_pk_type_t ttls_get_ciphersuite_sig_pk_alg(const TlsCiphersuite *info);
ttls_pk_type_t ttls_get_ciphersuite_sig_alg(const TlsCiphersuite *info);

int ttls_ciphersuite_uses_ec(const TlsCiphersuite *info);
int ttls_ciphersuite_uses_psk(const TlsCiphersuite *info);

static inline int
ttls_ciphersuite_has_pfs(const TlsCiphersuite *info)
{
	switch (info->key_exchange) {
	case TTLS_KEY_EXCHANGE_DHE_RSA:
	case TTLS_KEY_EXCHANGE_DHE_PSK:
	case TTLS_KEY_EXCHANGE_ECDHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDHE_PSK:
	case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
		return 1;
	default:
		return 0;
	}
}

static inline int
ttls_ciphersuite_no_pfs(const TlsCiphersuite *info)
{
	switch (info->key_exchange) {
	case TTLS_KEY_EXCHANGE_ECDH_RSA:
	case TTLS_KEY_EXCHANGE_ECDH_ECDSA:
	case TTLS_KEY_EXCHANGE_RSA:
	case TTLS_KEY_EXCHANGE_PSK:
	case TTLS_KEY_EXCHANGE_RSA_PSK:
		return 1;
	default:
		return 0;
	}
}

static inline int
ttls_ciphersuite_uses_ecdh(const TlsCiphersuite *info)
{
	switch (info->key_exchange) {
	case TTLS_KEY_EXCHANGE_ECDH_RSA:
	case TTLS_KEY_EXCHANGE_ECDH_ECDSA:
		return 1;
	default:
		return 0;
	}
}

static inline int
ttls_ciphersuite_cert_req_allowed(const TlsCiphersuite *info)
{
	switch (info->key_exchange) {
	case TTLS_KEY_EXCHANGE_RSA:
	case TTLS_KEY_EXCHANGE_DHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDH_RSA:
	case TTLS_KEY_EXCHANGE_ECDHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDH_ECDSA:
	case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
		return 1;
	default:
		return 0;
	}
}

static inline int
ttls_ciphersuite_uses_dhe(const TlsCiphersuite *info)
{
	switch (info->key_exchange) {
	case TTLS_KEY_EXCHANGE_DHE_RSA:
	case TTLS_KEY_EXCHANGE_DHE_PSK:
		return 1;
	default:
		return 0;
	}
}

static inline int
ttls_ciphersuite_uses_ecdhe(const TlsCiphersuite *info)
{
	switch (info->key_exchange) {
	case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
	case TTLS_KEY_EXCHANGE_ECDHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDHE_PSK:
		return 1;
	default:
		return 0;
	}
}

static inline int
ttls_ciphersuite_uses_server_signature(const TlsCiphersuite *info)
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
