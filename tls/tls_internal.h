/**
 *		Tempesta TLS
 *
 * Internal functions shared by the TLS modules.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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

#include <linux/types.h>
#include <asm/fpu/api.h>

#include "lib/fsm.h"
#include "lib/str.h"

#include "crypto.h"
#include "ttls.h"
#include "x509_crt.h"

struct aead_request *ttls_aead_req_alloc(struct crypto_aead *tfm);
void ttls_aead_req_free(struct crypto_aead *tfm, struct aead_request *req);

#define TTLS_MAJOR_VERSION_3		3
#define TTLS_MINOR_VERSION_3		3 /* TLS v1.2 */
#define TTLS_MINOR_VERSION_4		4 /* TLS v1.3 */
/* Determine minimum and maximum supported versions. */
#define TTLS_MIN_MINOR_VERSION		TTLS_MINOR_VERSION_3
#define TTLS_MAX_MINOR_VERSION		TTLS_MINOR_VERSION_3

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

#define TTLS_PAYLOAD_LEN		(TLS_MAX_PAYLOAD_SIZE		\
					 + TTLS_COMPRESSION_ADD		\
					 + TTLS_MAX_IV_LENGTH		\
					 + TTLS_MAC_ADD			\
					 + TTLS_PADDING_ADD)
/*
 * There is currently no ciphersuite using another length with TLS 1.2.
 * RFC 5246 7.4.9 (Page 63) says 12 is the default length and ciphersuites
 * may define some other value. Currently, no defined ciphersuite does this
 * (and this is unlikely to change as activity has moved to TLS 1.3 now),
 * so we can keep the hardcoded 12 here.
 */
#define TLS_HASH_LEN			12
/*
 * Hash of the whole handshake session for AES-GCM is 40 bytes:
 *
 *  explicit IV  handshake header    hash      tag
 *  -----------  ----------------  --------  --------
 *    8 bytes        4 bytes       12 bytes  16 bytes
 */
#define TTLS_HS_FINISHED_BODY_LEN	40

/*
 * Abstraction for a grid of allowed signature-hash-algorithm pairs.
 *
 * @rsa			- bitmap to store values from ttls_md_type_t;
 * @ecdsa		- bitmap to store values from ttls_md_type_t;
 *
 * When signature_algorithm extension in ClientHello is parsed, target server
 * is not known, and the grid contain all (known) client capabilities.
 * After target server is determined, the most preferred hash function is
 * stored in the grid while others are dropped.
 *
 * At the moment, we only need to remember and use a single suitable
 * hash algorithm per signature algorithm. As long as that's
 * the case - and we don't need a general lookup function -
 * we can implement the sig-hash-set as a map from signatures
 * to hash algorithms
 */
typedef struct {
	unsigned int rsa;
	unsigned int ecdsa;
} TlsSigHashSet;

/*
 * This structure contains the parameters only needed during handshake.
 *
 * @hash_algs	- set of suitable sig-hash pairs;
 * @sni_authmode - authmode from SNI callback;
 * @point_form	- TLS extension flags (for extensions with outgoing ServerHello
 * 		  content that need it (e.g. for RENEGOTIATION_INFO the server
 * 		  already knows because of state of the renegotiation flag, so
 * 		  no indicator is required);
 * @extended_ms	- use Extended Master Secret (RFC 7627)?
 * @new_session_ticket - use NewSessionTicket?
 * @resume	- session resume indicator;
 * @cli_exts	- client extension presence;
 * @pmslen	- premaster length;
 * @key_cert	- chosen key/cert pair (server);
 * @fin_sha{256,512} - checksum contexts;
 * @tmp_sha256	- temporal checksum buffer to handle both the checksum types on
 *		  early handhsahe steps;
 * @curves	- supported elliptic curves;
 * @randbytes	- random bytes;
 * @finished	- temporal buffer for chunks of Finished message,
 *		  @randbytes were used in previous messages, so we can reuse it
 * @premaster	- premaster secret;
 * @tmp		- buffer to store temporary data between data chunks;
 * @ecdh_ctx	- ECDH key exchange;
 * @dhm_ctx	- DHM key exchange;
 * @ticket_ctx	- tls session ticket context.
 */
struct tls_handshake_t {
	TlsSigHashSet			hash_algs;
	int				sni_authmode;

	unsigned char			point_form		: 1,
					extended_ms		: 1,
					new_session_ticket	: 1,
					resume			: 1,
					cli_exts		: 1,
					curves_ext		: 1,
					secure_renegotiation	: 1;

	size_t				pmslen;
	TlsKeyCert			*key_cert;

	void (*calc_verify)(TlsCtx *, unsigned char *);
	void (*calc_finished)(TlsCtx *, unsigned char *, int);
	int  (*tls_prf)(const unsigned char *, size_t, const char *, size_t,
			const unsigned char *, size_t, unsigned char *, size_t);

	union {
		struct shash_desc	desc; /* common for both the contexts */
		ttls_sha256_context	fin_sha256;
		ttls_sha512_context	fin_sha512;
	};
	ttls_sha256_context	tmp_sha256;

	const TlsEcpCurveInfo	*curves[TTLS_ECP_DP_MAX];
	union {
		unsigned char		randbytes[64];
		unsigned char		finished[64];
	};
	union {
		unsigned char		premaster[TTLS_PREMASTER_SIZE];
		struct {
			union {
				unsigned short cs_cur_len;
				struct {
					unsigned char compr_n;
					unsigned char compr_has_null;
				};
				struct {
					unsigned short ext_rem_sz;
					unsigned short ext_type;
					unsigned short ext_sz;
				};
				unsigned char *cert_page_address;
			};
			unsigned short cs_total_len;
			struct {
				u16 css[(TTLS_HS_RBUF_SZ - 10 - 256)/2];
				unsigned char ext[256];
			};
		};
		unsigned char key_exchange_tmp[TTLS_HS_RBUF_SZ];
	};

	union {
		void			*crypto_ctx;
		TlsECDHCtx		*ecdh_ctx;
		TlsDHMCtx		*dhm_ctx;
	};

	TlSTicketCtx			ticket_ctx;
};

extern int ttls_preset_hashes[];

/* Find an entry in a signature-hash set matching a given hash algorithm. */
ttls_md_type_t ttls_sig_hash_set_find(TlsSigHashSet *set,
				      ttls_pk_type_t sig_alg);
/* Add a signature-hash-pair to a signature-hash set */
void ttls_sig_hash_set_add(TlsSigHashSet *set,
			   ttls_pk_type_t sig_alg,
			   ttls_md_type_t md_alg);

int ttls_handshake_client_step(TlsCtx *tls, unsigned char *buf,
			       size_t len, size_t hh_len, unsigned int *read);
int ttls_handshake_server_step(TlsCtx *tls, unsigned char *buf,
			       size_t len, size_t hh_len, unsigned int *read);
void ttls_handshake_wrapup(TlsCtx *tls);

int ttls_derive_keys(TlsCtx *tls);

void __ttls_add_record(TlsCtx *tls, struct sg_table *sgt, int sg_i,
		       unsigned char *hdr_buf);
int __ttls_send_record(TlsCtx *tls, struct sg_table *sgt);
int ttls_sendmsg(TlsCtx *tls, const char *buf, size_t len);

int ttls_parse_certificate(TlsCtx *tls, unsigned char *buf, size_t len,
			   unsigned int *read);
int ttls_write_certificate(TlsCtx *tls, struct sg_table *sgt,
			   unsigned char **in_buf);

int ttls_parse_change_cipher_spec(TlsCtx *tls, unsigned char *buf,
				  size_t len, unsigned int *read);
void ttls_write_change_cipher_spec(TlsCtx *tls, struct sg_table *sgt,
				   unsigned char **in_buf);

int ttls_parse_finished(TlsCtx *tls, unsigned char *buf, size_t len,
			unsigned int *read);
int ttls_write_finished(TlsCtx *tls, struct sg_table *sgt,
			unsigned char **in_buf);

unsigned char ttls_sig_from_pk_alg(ttls_pk_type_t type);
ttls_pk_type_t ttls_pk_alg_from_sig(unsigned char sig);

ttls_md_type_t ttls_md_alg_from_hash(unsigned char hash);
unsigned char ttls_hash_from_md_alg(int md);
int ttls_set_calc_verify_md(TlsCtx *tls, int md);

int ttls_check_curve(const TlsCtx *tls, ttls_ecp_group_id grp_id);

int ttls_check_sig_hash(const TlsCtx *tls, ttls_md_type_t md);
int ttls_match_sig_hashes(const TlsCtx *tls);
void ttls_update_checksum(TlsCtx *tls, const unsigned char *buf, size_t len);

static inline TlsX509Crt *
ttls_own_cert(TlsCtx *tls)
{
	TlsKeyCert *key_cert;

	if (tls->hs && tls->hs->key_cert)
		key_cert = tls->hs->key_cert;
	else
		key_cert = tls->peer_conf ? tls->peer_conf->key_cert : NULL;

	return key_cert ? key_cert->cert : NULL;
}

int ttls_check_cert_usage(const TlsX509Crt *cert,
			  const TlsCiphersuite *ciphersuite,
			  int cert_endpoint);

void ttls_read_version(TlsCtx *tls, const unsigned char ver[2]);

int ttls_get_key_exchange_md_tls1_2(TlsCtx *tls, unsigned char *output,
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

static inline void
ttls_write_version(const TlsCtx *tls, unsigned char ver[2])
{
	/*
	 * RFC 8446 5.1: "legacy_record_version: MUST be set to 0x0303 for
	 * all records generated by a TLS 1.3 implementation other than an
	 * initial ClientHello".
	 */
	ver[0] = 0x03;
	ver[1] = 0x03;
}

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
 * Extend the common FSM for handshake parsing.
 */
#define TTLS_HS_FSM_FINISH()						\
	T_FSM_FINISH(r, tls->state);					\
	*read += p - buf;						\
	io->rlen += p - state_p;

/* Move to @st if we have some bytes to process. */
#define TTLS_HS_FSM_MOVE(st)						\
do {									\
	WARN_ON_ONCE(p - buf > len);					\
	io->rlen = 0;							\
	state_p = p;							\
	if (unlikely(p - buf >= len)) {					\
		__fsm_const_state = ttls_state(tls) + st;		\
		T_FSM_EXIT();						\
	}								\
	T_FSM_MOVE(st, {});						\
} while (0)

/* Unconditional jump to state @st w/o additional logic and/or eating data. */
#define TTLS_HS_FSM_JMP(st)						\
do {									\
	io->rlen = 0;							\
	state_p = p;							\
	T_FSM_JMP(st);							\
} while (0)

/* Server specific TLS handshake states. */
enum {
	/* ClientHello intermediary states. */
	TTLS_CH_HS_VER		= __TTLS_FSM_SUBST(CLIENT_HELLO, 0),
	TTLS_CH_HS_RND		= __TTLS_FSM_SUBST(CLIENT_HELLO, 1),
	TTLS_CH_HS_SLEN		= __TTLS_FSM_SUBST(CLIENT_HELLO, 2),
	TTLS_CH_HS_SESS		= __TTLS_FSM_SUBST(CLIENT_HELLO, 3),
	TTLS_CH_HS_CSLEN	= __TTLS_FSM_SUBST(CLIENT_HELLO, 4),
	TTLS_CH_HS_CS		= __TTLS_FSM_SUBST(CLIENT_HELLO, 5),
	TTLS_CH_HS_CS_SKIP	= __TTLS_FSM_SUBST(CLIENT_HELLO, 6),
	TTLS_CH_HS_COMPN	= __TTLS_FSM_SUBST(CLIENT_HELLO, 7),
	TTLS_CH_HS_COMP		= __TTLS_FSM_SUBST(CLIENT_HELLO, 8),
	TTLS_CH_HS_EXTLEN	= __TTLS_FSM_SUBST(CLIENT_HELLO, 9),
	TTLS_CH_HS_EXT		= __TTLS_FSM_SUBST(CLIENT_HELLO, 10),
	TTLS_CH_HS_EXS		= __TTLS_FSM_SUBST(CLIENT_HELLO, 11),
	TTLS_CH_HS_EX		= __TTLS_FSM_SUBST(CLIENT_HELLO, 12),
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

#if DBG_TLS == 3
/*
 * Make the things repeatable, simple and INSECURE on largest debug level -
 * this helps to debug TLS (thanks to reproducible records payload), but
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
/*
 * CPUs since Intel Ice Lake are safe against SRBDS attack, so we're good
 * with the hardware random generator.
 *
 * The random number generator is extremely important for ECDSA, see
 * M.Macchetti, "A Novel Related Nonce Attack for ECDSA", 2023,
 * https://eprint.iacr.org/2023/305.pdf
 */
static inline void
ttls_rnd(void *buf, int len)
{
	int n = get_random_bytes_arch(buf, len);

	if (unlikely(n < len))
		get_random_bytes((char *)buf + n, len - n);
}
#endif

static inline char *
tls_state_to_str(unsigned int state) {
	switch (state) {
	case TTLS_CLIENT_HELLO:
		return "Client Hello";
	case TTLS_SERVER_HELLO:
		return "Server Hello";
	case TTLS_SERVER_CERTIFICATE:
		return "Server Certificate";
	case TTLS_SERVER_KEY_EXCHANGE:
		return "Server Key Exchange";
	case TTLS_CERTIFICATE_REQUEST:
		return "Certificate Request";
	case TTLS_SERVER_HELLO_DONE:
		return "Server Hello Done";
	case TTLS_CLIENT_CERTIFICATE:
		return "Client Certificate";
	case TTLS_CLIENT_KEY_EXCHANGE:
		return "Client Key Exchange";
	case TTLS_CERTIFICATE_VERIFY:
		return "Certificate Verify";
	case TTLS_CLIENT_CHANGE_CIPHER_SPEC:
		return "Client Change Cipher Spec";
	case TTLS_CLIENT_FINISHED:
		return "Client Finished";
	case TTLS_SERVER_CHANGE_CIPHER_SPEC:
		return "Server Change Cipher Spec";
	case TTLS_SERVER_FINISHED:
		return "Server Finished";
	case TTLS_HANDSHAKE_WRAPUP:
		return "Handshake Wrapup";
	case TTLS_HANDSHAKE_OVER:
		return "Handshake Over";
	case TTLS_SERVER_NEW_SESSION_TICKET:
		return "Server New Session Ticket";
	case TTLS_SERVER_HELLO_VERIFY_REQUEST_SENT:
		return "Server Hello Veriy Request Sent";
	default:
		return "Unknown";
	}
}

#endif
