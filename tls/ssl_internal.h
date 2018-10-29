/*
 *		Tempesta TLS
 *
 * Internal functions shared by the TLS modules.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#ifndef TTLS_INTERNAL_H
#define TTLS_INTERNAL_H

#include <asm/fpu/api.h>

#include "debug.h"
#include "lib/fsm.h"
#include "lib/str.h"

#include "cipher.h"
#include "ttls.h"

/* Determine minimum supported version */
#define TTLS_MIN_MAJOR_VERSION		TTLS_MAJOR_VERSION_3
#define TTLS_MIN_MINOR_VERSION		TTLS_MINOR_VERSION_3

#define TTLS_MIN_VALID_MINOR_VERSION	TTLS_MINOR_VERSION_1
#define TTLS_MIN_VALID_MAJOR_VERSION	TTLS_MAJOR_VERSION_3

/* Determine maximum supported version */
#define TTLS_MAX_MAJOR_VERSION		TTLS_MAJOR_VERSION_3
#define TTLS_MAX_MINOR_VERSION		TTLS_MINOR_VERSION_3

#define TTLS_INITIAL_HANDSHAKE		0

#define TTLS_HS_HDR_LEN			4

/*
 * Allow extra bytes for record, authentication and encryption overhead:
 * counter (8) + header (5) + IV(16) + MAC (16-48) + padding (0-256)
 * and allow for a maximum of 1024 of compression expansion if
 * enabled.
 */
#define TTLS_COMPRESSION_ADD		0
/* AEAD ciphersuites: GCM and CCM use a 128 bits tag */
#define TTLS_MAC_ADD			16
#define TTLS_PADDING_ADD		0

#define TTLS_PAYLOAD_LEN	(TLS_MAX_PAYLOAD_SIZE		\
				 + TTLS_COMPRESSION_ADD		\
				 + TTLS_MAX_IV_LENGTH		\
				 + TTLS_MAC_ADD			\
				 + TTLS_PADDING_ADD)

#define TTLS_BUF_LEN		(TLS_HEADER_SIZE + TTLS_PAYLOAD_LEN)
/*
 * There is currently no ciphersuite using another length with TLS 1.2.
 * RFC 5246 7.4.9 (Page 63) says 12 is the default length and ciphersuites
 * may define some other value. Currently (early 2016), no defined
 * ciphersuite does this (and this is unlikely to change as activity has
 * moved to TLS 1.3 now) so we can keep the hardcoded 12 here.
 */
#define TLS_MAX_HASH_LEN	12

/*
 * Abstraction for a grid of allowed signature-hash-algorithm pairs.
 */
struct ttls_sig_hash_set_t
{
	/* At the moment, we only need to remember a single suitable
	 * hash algorithm per signature algorithm. As long as that's
	 * the case - and we don't need a general lookup function -
	 * we can implement the sig-hash-set as a map from signatures
	 * to hash algorithms. */
	ttls_md_type_t rsa;
	ttls_md_type_t ecdsa;
};

/*
 * This structure contains the parameters only needed during handshake.
 *
 * @hash_algs	- set of suitable sig-hash pairs;
 * @fin_sha{256,512} - checksum contexts;
 * @point_form	- TLS extension flags (for extensions with outgoing ServerHello
 * 		  content that need it (e.g. for RENEGOTIATION_INFO the server
 * 		  already knows because of state of the renegotiation flag, so
 * 		  no indicator is required);
 * @extended_ms	- use Extended Master Secret (RFC 7627)?
 * @new_session_ticket - use NewSessionTicket?
 * @resume	- session resume indicator;
 * @cli_exts	- client extension presence;
 * @curves	- supported elliptic curves;
 * @randbytes	- random bytes;
 * @finished	- temporal buffer for chunks of Finished message,
 *		  @randbytes were used in prvious messages, so we can reuse it
 * @premaster	- premaster secret;
 * @tmp		- buffer to store temporary data between data chunks;
 */
typedef struct tls_handshake_t {
	ttls_sig_hash_set_t		hash_algs;

#if defined(TTLS_DHM_C)
	ttls_dhm_context dhm_ctx;	/*!<  DHM key exchange		*/
#endif
	ttls_ecdh_context ecdh_ctx;	  /*!<  ECDH key exchange	   */
	ttls_key_cert *key_cert;	 /*!< chosen key/cert pair (server)  */
	int sni_authmode;		   /*!< authmode from SNI callback	 */
	ttls_key_cert *sni_key_cert; /*!< key/cert list from SNI		 */
	ttls_x509_crt *sni_ca_chain;	 /*!< trusted CAs from SNI callback  */
	ttls_x509_crl *sni_ca_crl;	   /*!< trusted CAs CRLs from SNI	  */

	union {
		struct shash_desc	desc; /* common for both the contexts */
		ttls_sha256_context	fin_sha256;
		ttls_sha512_context	fin_sha512;
	};

	void (*update_checksum)(ttls_context *, const unsigned char *, size_t);
	void (*calc_verify)(ttls_context *, unsigned char *);
	void (*calc_finished)(ttls_context *, unsigned char *, int);
	int  (*tls_prf)(const unsigned char *, size_t, const char *,
		const unsigned char *, size_t,
		unsigned char *, size_t);

	size_t pmslen;	  /*!<  premaster length*/
	unsigned char		point_form:1,
				extended_ms:1,
				new_session_ticket:1,
				resume:1,
				cli_exts:1,
				curves_ext:1;

	const ttls_ecp_curve_info	*curves[TTLS_ECP_DP_MAX];
	union {
		unsigned char		randbytes[64];
		unsigned char		finished[64];
	};
	union {
		unsigned char		premaster[TTLS_PREMASTER_SIZE];
		unsigned char		tmp[TTLS_HS_RBUF_SZ];
	};
} TlsHandshake;

/*
 * List of certificate + private key pairs
 */
struct ttls_key_cert
{
	ttls_x509_crt			*cert;
	ttls_pk_context			*key;
	ttls_key_cert			*next;
};

/* Find an entry in a signature-hash set matching a given hash algorithm. */
ttls_md_type_t ttls_sig_hash_set_find(ttls_sig_hash_set_t *set,
			 ttls_pk_type_t sig_alg);
/* Add a signature-hash-pair to a signature-hash set */
void ttls_sig_hash_set_add(ttls_sig_hash_set_t *set,
			   ttls_pk_type_t sig_alg,
			   ttls_md_type_t md_alg);
void ttls_set_default_sig_hash(TlsCtx *tls);

int ttls_handshake_client_step(ttls_context *tls, unsigned char *buf,
			       size_t len, unsigned int *read);
int ttls_handshake_server_step(ttls_context *tls, unsigned char *buf,
			       size_t len, unsigned int *read);
void ttls_handshake_wrapup(ttls_context *tls);

int ttls_derive_keys(ttls_context *tls);

int ttls_handle_message_type(TlsCtx *tls);

void __ttls_add_record(TlsCtx *tls, struct sg_table *sgt, int sg_i,
		       unsigned char *hdr_buf);
int __ttls_send_record(TlsCtx *tls, struct sg_table *sgt, bool close);
int ttls_write_record(TlsCtx *tls, struct sg_table *sgt, bool close);
int ttls_sendmsg(TlsCtx *tls, const char *buf, size_t len);

int ttls_parse_certificate(ttls_context *tls, unsigned char *buf, size_t len,
			   unsigned int *read);
int ttls_write_certificate(ttls_context *tls, struct sg_table *sgt,
			   unsigned char **in_buf);

int ttls_parse_change_cipher_spec(ttls_context *tls, unsigned char *buf,
				  size_t len, unsigned int *read);
int ttls_write_change_cipher_spec(ttls_context *tls, struct sg_table *sgt,
				  unsigned char **in_buf);

int ttls_parse_finished(TlsCtx *tls, unsigned char *buf, size_t len,
			unsigned int *read);
int ttls_write_finished(ttls_context *tls, struct sg_table *sgt,
			unsigned char **in_buf);

unsigned char ttls_sig_from_pk_alg(ttls_pk_type_t type);
ttls_pk_type_t ttls_pk_alg_from_sig(unsigned char sig);

ttls_md_type_t ttls_md_alg_from_hash(unsigned char hash);
unsigned char ttls_hash_from_md_alg(int md);
int ttls_set_calc_verify_md(ttls_context *tls, int md);

int ttls_check_curve(const ttls_context *tls, ttls_ecp_group_id grp_id);

int ttls_check_sig_hash(const ttls_context *tls, ttls_md_type_t md);

/**
 * Implementation that should never be optimized out by the compiler.
 * Use this only for preemptable contexts and prefer bzero_fast() for siftirq.
 */
static inline void
ttls_zeroize(void *v, size_t n)
{
	volatile unsigned char *p = v;

	while (n--)
		*p++ = 0;
}

static inline ttls_pk_context *
ttls_own_key(ttls_context *tls)
{
	ttls_key_cert *key_cert;

	if (tls->hs && tls->hs->key_cert)
		key_cert = tls->hs->key_cert;
	else
		key_cert = tls->conf->key_cert;

	return key_cert ? key_cert->key : NULL;
}

static inline ttls_x509_crt *
ttls_own_cert(TlsCtx *tls)
{
	ttls_key_cert *key_cert;

	if (tls->hs && tls->hs->key_cert)
		key_cert = tls->hs->key_cert;
	else
		key_cert = tls->conf->key_cert;

	return key_cert ? key_cert->cert : NULL;
}

/*
 * Check usage of a certificate wrt extensions:
 * keyUsage, extendedKeyUsage (later), and nSCertType (later).
 *
 * Warning: cert_endpoint is the endpoint of the cert (ie, of our peer when we
 * check a cert we received from them)!
 *
 * Return 0 if everything is OK, -1 if not.
 */
int ttls_check_cert_usage(const ttls_x509_crt *cert,
			  const ttls_ciphersuite_t *ciphersuite,
			  int cert_endpoint,
			  uint32_t *flags);

void ttls_write_version(TlsCtx *tls, unsigned char ver[2]);
void ttls_read_version(TlsCtx *tls, const unsigned char ver[2]);

int ttls_get_key_exchange_md_tls1_2(ttls_context *tls,
		unsigned char *output,
		unsigned char *data, size_t data_len,
		ttls_md_type_t md_alg);

/**
 * Use the zeroing function for process context. Softirq context should use
 * just bzero_fast().
 */
static inline void
ttls_bzero_safe(void *v, size_t n)
{
	kernel_fpu_begin();
	bzero_fast(v, n);
	kernel_fpu_end();
}

#if defined(DEBUG) && (DEBUG >= 3)
/*
 * Make the things repeatable, simple and INSECURE on largest debug level -
 * this helps to debug TLS (thanks to reproducable records payload), but
 * must not be used in any security sensitive installations.
 */
static inline void
ttls_rnd(void *buf, size_t len)
{
	memset(buf, 0x55, len);
}

unsigned long ttls_time_debug(void);

#define ttls_time()		ttls_time_debug()

#else
#define ttls_time()		get_seconds()
#define ttls_rnd(buf, len)	get_random_bytes_arch(buf, len)
#endif

/*
 * TLS state machine (common states & definitions for client and server).
 */
#define __TTLS_FSM_ST_SHIFT		24
#define __TTLS_FSM_ST(st)		((st) << __TTLS_FSM_ST_SHIFT)
#define __TTLS_FSM_ST_MASK		(~((1U << 24) - 1))
#define __TTLS_FSM_SUBST(st, sst)	(__TTLS_FSM_ST(TTLS_##st) | sst)
#define __TTLS_FSM_SUBST_MASK		((1U << 24) - 1)
enum {
	TTLS_CLIENT_HELLO,
	TTLS_SERVER_HELLO		= __TTLS_FSM_ST(1),
	TTLS_SERVER_CERTIFICATE		= __TTLS_FSM_ST(2),
	TTLS_SERVER_KEY_EXCHANGE	= __TTLS_FSM_ST(3),
	TTLS_CERTIFICATE_REQUEST	= __TTLS_FSM_ST(4),
	TTLS_SERVER_HELLO_DONE		= __TTLS_FSM_ST(5),
	TTLS_CLIENT_CERTIFICATE		= __TTLS_FSM_ST(6),
	TTLS_CLIENT_KEY_EXCHANGE	= __TTLS_FSM_ST(7),
	TTLS_CERTIFICATE_VERIFY		= __TTLS_FSM_ST(8),
	TTLS_CLIENT_CHANGE_CIPHER_SPEC	= __TTLS_FSM_ST(9),
	TTLS_CLIENT_FINISHED		= __TTLS_FSM_ST(10),
	TTLS_SERVER_CHANGE_CIPHER_SPEC	= __TTLS_FSM_ST(11),
	TTLS_SERVER_FINISHED		= __TTLS_FSM_ST(12),
	TTLS_HANDSHAKE_WRAPUP		= __TTLS_FSM_ST(13),
	TTLS_HANDSHAKE_OVER		= __TTLS_FSM_ST(14),
	TTLS_SERVER_NEW_SESSION_TICKET	= __TTLS_FSM_ST(15),
	TTLS_SERVER_HELLO_VERIFY_REQUEST_SENT = __TTLS_FSM_ST(16),
};

/*
 * Extend the common FSM for hanshake parsing.
 */
#define TTLS_HS_FSM_FINISH()						\
	T_FSM_FINISH(r, tls->state);					\
	*read += p - buf;						\
	io->rlen += p - buf;

/* Move to @st if we have at least @need bytes. */
#define TTLS_HS_FSM_MOVE(st)						\
do {									\
	WARN_ON_ONCE(p - buf > len);					\
	io->rlen = 0;							\
	T_FSM_MOVE(st, if (unlikely(p - buf >= len)) T_FSM_EXIT(); );	\
} while (0)

/*
 * Size of temporary storage in TlsCtx->hs->tmp.
 * The temporary buffer is used to store 2 types of temporary data: utility
 * data to store 'state' between chunks of data while the FSM is being in
 * the same state (i.e. stack-based FSM reduces number of states using the
 * stack) and 'memory' used between states, e.g. ciphersuites parsed in
 * one state, but must be processed at the end, when all extensions are also
 * parsed. So we split @tmp buffer to 2 segments and the constant defines size
 * of the FSM stack.
 */
#define TTLS_HS_TMP_STORE_SZ	8
/* Minimum size reserved for extension parsing. */
#define TTLS_HS_EXT_RES_SZ	32
/* Maximum length of cipher suites buffer. */
#define TTLS_HS_CS_MAX_SZ	(TTLS_HS_RBUF_SZ - TTLS_HS_EXT_RES_SZ	\
				 -  TTLS_HS_TMP_STORE_SZ)

/* Server specific TLS handshake states. */
enum {
	/* ClientHello intermediary states. */
	TTLS_CH_HS_VER		= __TTLS_FSM_SUBST(CLIENT_HELLO, 0),
	TTLS_CH_HS_RND		= __TTLS_FSM_SUBST(CLIENT_HELLO, 1),
	TTLS_CH_HS_SLEN		= __TTLS_FSM_SUBST(CLIENT_HELLO, 2),
	TTLS_CH_HS_SESS		= __TTLS_FSM_SUBST(CLIENT_HELLO, 3),
	TTLS_CH_HS_CSLEN	= __TTLS_FSM_SUBST(CLIENT_HELLO, 4),
	TTLS_CH_HS_CS		= __TTLS_FSM_SUBST(CLIENT_HELLO, 5),
	TTLS_CH_HS_COMPN	= __TTLS_FSM_SUBST(CLIENT_HELLO, 6),
	TTLS_CH_HS_COMP		= __TTLS_FSM_SUBST(CLIENT_HELLO, 7),
	TTLS_CH_HS_EXTLEN	= __TTLS_FSM_SUBST(CLIENT_HELLO, 8),
	TTLS_CH_HS_EXT		= __TTLS_FSM_SUBST(CLIENT_HELLO, 9),
	TTLS_CH_HS_EXS		= __TTLS_FSM_SUBST(CLIENT_HELLO, 10),
	TTLS_CH_HS_EX		= __TTLS_FSM_SUBST(CLIENT_HELLO, 11),
	/* ClientCertificate intermediary states. */
	TTLS_CC_HS_ALLOC	= __TTLS_FSM_SUBST(CLIENT_CERTIFICATE, 0),
	TTLS_CC_HS_READ		= __TTLS_FSM_SUBST(CLIENT_CERTIFICATE, 1),
	TTLS_CC_HS_PARSE	= __TTLS_FSM_SUBST(CLIENT_CERTIFICATE, 2),
};

static inline unsigned int
ttls_state(const TlsCtx *tls)
{
	return tls->state & __TTLS_FSM_ST_MASK;
}

static inline unsigned int
ttls_substate(const TlsCtx *tls)
{
	return tls->state & __TTLS_FSM_SUBST_MASK;
}

#endif /* ssl_internal.h */
