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
#ifndef TTLS_SSL_INTERNAL_H
#define TTLS_SSL_INTERNAL_H

#include "cipher.h"
#include "ttls.h"
#if defined(TTLS_SHA256_C)
#include "sha256.h"
#endif
#if defined(TTLS_SHA512_C)
#include "sha512.h"
#endif
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#include "ecjpake.h"
#endif

/* Determine minimum supported version */
#define TTLS_SSL_MIN_MAJOR_VERSION		TTLS_SSL_MAJOR_VERSION_3
#define TTLS_SSL_MIN_MINOR_VERSION		TTLS_SSL_MINOR_VERSION_3

#define TTLS_SSL_MIN_VALID_MINOR_VERSION	TTLS_SSL_MINOR_VERSION_1
#define TTLS_SSL_MIN_VALID_MAJOR_VERSION	TTLS_SSL_MAJOR_VERSION_3

/* Determine maximum supported version */
#define TTLS_SSL_MAX_MAJOR_VERSION		TTLS_SSL_MAJOR_VERSION_3
#define TTLS_SSL_MAX_MINOR_VERSION		TTLS_SSL_MINOR_VERSION_3

#define TTLS_SSL_INITIAL_HANDSHAKE		0
#define TTLS_SSL_RENEGOTIATION_IN_PROGRESS	1 /* In progress */
#define TTLS_SSL_RENEGOTIATION_DONE		2 /* Done or aborted */
#define TTLS_SSL_RENEGOTIATION_PENDING		3 /* Requested (server only) */

/*
 * DTLS retransmission states, see RFC 6347 4.2.4
 *
 * The SENDING state is merged in PREPARING for initial sends,
 * but is distinct for resends.
 *
 * Note: initial state is wrong for server, but is not used anyway.
 */
#define TTLS_SSL_RETRANS_PREPARING		0
#define TTLS_SSL_RETRANS_SENDING		1
#define TTLS_SSL_RETRANS_WAITING		2
#define TTLS_SSL_RETRANS_FINISHED		3

/*
 * Allow extra bytes for record, authentication and encryption overhead:
 * counter (8) + header (5) + IV(16) + MAC (16-48) + padding (0-256)
 * and allow for a maximum of 1024 of compression expansion if
 * enabled.
 */
#define TTLS_SSL_COMPRESSION_ADD		0
/* AEAD ciphersuites: GCM and CCM use a 128 bits tag */
#define TTLS_SSL_MAC_ADD			16
#define TTLS_SSL_PADDING_ADD			0

#define TTLS_PAYLOAD_LEN	(TTLS_SSL_MAX_CONTENT_LEN		\
				 + TTLS_SSL_COMPRESSION_ADD		\
				 + TTLS_MAX_IV_LENGTH			\
				 + TTLS_SSL_MAC_ADD			\
				 + TTLS_SSL_PADDING_ADD)
#if defined(TTLS_SSL_PROTO_DTLS)
#define TTLS_HDR_LEN		13
#else
#define TTLS_HDR_LEN		5
#endif
#define TTLS_BUF_LEN		(TTLS_HDR_LEN + TTLS_PAYLOAD_LEN)
#define TTLS_IV_LEN		16

/*
 * TLS extension flags (for extensions with outgoing ServerHello content
 * that need it (e.g. for RENEGOTIATION_INFO the server already knows because
 * of state of the renegotiation flag, so no indicator is required)
 */
#define TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT (1 << 0)
#define TTLS_TLS_EXT_ECJPAKE_KKPP_OK				 (1 << 1)

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
/*
 * Abstraction for a grid of allowed signature-hash-algorithm pairs.
 */
struct ttls_ssl_sig_hash_set_t
{
	/* At the moment, we only need to remember a single suitable
	 * hash algorithm per signature algorithm. As long as that's
	 * the case - and we don't need a general lookup function -
	 * we can implement the sig-hash-set as a map from signatures
	 * to hash algorithms. */
	ttls_md_type_t rsa;
	ttls_md_type_t ecdsa;
};
#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/*
 * This structure contains the parameters only needed during handshake.
 */
struct ttls_ssl_handshake_params
{
	/*
	 * Handshake specific crypto variables
	 */

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
	ttls_ssl_sig_hash_set_t hash_algs;			 /*!<  Set of suitable sig-hash pairs */
#endif
#if defined(TTLS_DHM_C)
	ttls_dhm_context dhm_ctx;				/*!<  DHM key exchange		*/
#endif
#if defined(TTLS_ECDH_C)
	ttls_ecdh_context ecdh_ctx;			  /*!<  ECDH key exchange	   */
#endif
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	ttls_ecjpake_context ecjpake_ctx;		/*!< EC J-PAKE key exchange */
#if defined(TTLS_SSL_CLI_C)
	unsigned char *ecjpake_cache;			   /*!< Cache for ClientHello ext */
	size_t ecjpake_cache_len;				   /*!< Length of cached data */
#endif
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	const ttls_ecp_curve_info **curves;	  /*!<  Supported elliptic curves */
#endif
#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	unsigned char *psk;				 /*!<  PSK from the callback		 */
	size_t psk_len;					 /*!<  Length of PSK from callback   */
#endif
	ttls_ssl_key_cert *key_cert;	 /*!< chosen key/cert pair (server)  */
	int sni_authmode;				   /*!< authmode from SNI callback	 */
	ttls_ssl_key_cert *sni_key_cert; /*!< key/cert list from SNI		 */
	ttls_x509_crt *sni_ca_chain;	 /*!< trusted CAs from SNI callback  */
	ttls_x509_crl *sni_ca_crl;	   /*!< trusted CAs CRLs from SNI	  */
#if defined(TTLS_SSL_PROTO_DTLS)
	unsigned int out_msg_seq;		   /*!<  Outgoing handshake sequence number */
	unsigned int in_msg_seq;			/*!<  Incoming handshake sequence number */

	unsigned char *verify_cookie;	   /*!<  Cli: HelloVerifyRequest cookie
											  Srv: unused					*/
	unsigned char verify_cookie_len;	/*!<  Cli: cookie length
											  Srv: flag for sending a cookie */

	unsigned char *hs_msg;			  /*!<  Reassembled handshake message  */

	uint32_t retransmit_timeout;		/*!<  Current value of timeout	   */
	unsigned char retransmit_state;	 /*!<  Retransmission state		   */
	ttls_ssl_flight_item *flight;			/*!<  Current outgoing flight		*/
	ttls_ssl_flight_item *cur_msg;		   /*!<  Current message in flight	  */
	unsigned int in_flight_start_seq;   /*!<  Minimum message sequence in the
											  flight being received		  */
	TtlsXfrm *alt_transform_out;   /*!<  Alternative transform for
											  resending messages			 */
	unsigned char alt_out_ctr[8];	   /*!<  Alternative record epoch/counter
											  for resending messages		 */
#endif /* TTLS_SSL_PROTO_DTLS */

	/*
	 * Checksum contexts
	 */
#if defined(TTLS_SHA256_C)
	ttls_sha256_context fin_sha256;
#endif
#if defined(TTLS_SHA512_C)
	ttls_sha512_context fin_sha512;
#endif

	void (*update_checksum)(ttls_ssl_context *, const unsigned char *, size_t);
	void (*calc_verify)(ttls_ssl_context *, unsigned char *);
	void (*calc_finished)(ttls_ssl_context *, unsigned char *, int);
	int  (*tls_prf)(const unsigned char *, size_t, const char *,
					const unsigned char *, size_t,
					unsigned char *, size_t);

	size_t pmslen;					  /*!<  premaster length		*/

	unsigned char randbytes[64];		/*!<  random bytes			*/
	unsigned char premaster[TTLS_PREMASTER_SIZE];
										/*!<  premaster secret		*/

	int resume;						 /*!<  session resume indicator*/
	int max_major_ver;				  /*!< max. major version client*/
	int max_minor_ver;				  /*!< max. minor version client*/
	int cli_exts;					   /*!< client extension presence*/

#if defined(TTLS_SSL_SESSION_TICKETS)
	int new_session_ticket;			 /*!< use NewSessionTicket?	*/
#endif /* TTLS_SSL_SESSION_TICKETS */
#if defined(TTLS_SSL_EXTENDED_MASTER_SECRET)
	int extended_ms;					/*!< use Extended Master Secret? */
#endif
};

/*
 * Session specific crypto layer.
 *
 * This structure contains a full set of runtime transform parameters
 * either in negotiation or active.
 *
 * @ciphersuite_info	- chosen cipersuite_info;
 * @md_ctx		- MAC context;
 * @cipher_ctx		- crypto context;
 * @keylen		- symmetric key length (bytes);
 * @minlen		- min. ciphertext length;
 * @ivlen		- IV length;
 * @fixed_ivlen		- fixed part of IV (AEAD);
 * @maclen		- MAC length;
 * @iv			- IV;
 */
struct TtlsXfrm
{
	const ttls_ssl_ciphersuite_t	*ciphersuite_info;
	ttls_md_context_t		md_ctx;
	ttls_cipher_context_t		cipher_ctx;
	union {
		// TODO AK call crypto_alloc_aead() on handshake
		// TODO AK crypto_alloc_aead() uses GFP_KERNEL - fix
		struct crypto_aead		*aead;
		struct {
			struct crypto_ahash	*ahash;
			struct crypto_cipher	*cipher;
		}
	}
	unsigned int			keylen;
	size_t				minlen;
	size_t				ivlen;
	size_t				fixed_ivlen;
	size_t				maclen;
	unsigned char			iv[16];
};

/*
 * List of certificate + private key pairs
 */
struct ttls_ssl_key_cert
{
	ttls_x509_crt *cert;				 /*!< cert					   */
	ttls_pk_context *key;				/*!< private key				*/
	ttls_ssl_key_cert *next;			 /*!< next key/cert pair		 */
};

#if defined(TTLS_SSL_PROTO_DTLS)
/*
 * List of handshake messages kept around for resending
 */
struct ttls_ssl_flight_item
{
	unsigned char *p;	   /*!< message, including handshake headers   */
	size_t len;			 /*!< length of p							*/
	unsigned char type;	 /*!< type of the message: handshake or CCS  */
	ttls_ssl_flight_item *next;  /*!< next handshake message(s)			  */
};
#endif /* TTLS_SSL_PROTO_DTLS */

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

/* Find an entry in a signature-hash set matching a given hash algorithm. */
ttls_md_type_t ttls_ssl_sig_hash_set_find(ttls_ssl_sig_hash_set_t *set,
												 ttls_pk_type_t sig_alg);
/* Add a signature-hash-pair to a signature-hash set */
void ttls_ssl_sig_hash_set_add(ttls_ssl_sig_hash_set_t *set,
								   ttls_pk_type_t sig_alg,
								   ttls_md_type_t md_alg);
/* Allow exactly one hash algorithm for each signature. */
void ttls_ssl_sig_hash_set_const_hash(ttls_ssl_sig_hash_set_t *set,
										  ttls_md_type_t md_alg);

/* Setup an empty signature-hash set */
static inline void ttls_ssl_sig_hash_set_init(ttls_ssl_sig_hash_set_t *set)
{
	ttls_ssl_sig_hash_set_const_hash(set, TTLS_MD_NONE);
}

#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/**
 * \brief		   Free referenced items in an SSL transform context and clear
 *				  memory
 *
 * \param transform SSL transform context
 */
void ttls_ssl_transform_free(TtlsXfrm *transform);

/**
 * \brief   Free referenced items in an SSL handshake context and clear
 *	  memory
 *
 * \param handshake SSL handshake context
 */
void ttls_ssl_handshake_free(ttls_ssl_handshake_params *handshake);

int ttls_ssl_handshake_client_step(ttls_ssl_context *tls);
int ttls_ssl_handshake_server_step(ttls_ssl_context *tls);
void ttls_ssl_handshake_wrapup(ttls_ssl_context *tls);

int ttls_ssl_send_fatal_handshake_failure(ttls_ssl_context *tls);

void ttls_ssl_reset_checksum(ttls_ssl_context *tls);
int ttls_ssl_derive_keys(ttls_ssl_context *tls);

int ttls_read_record_layer(TtlsCtx *tls, unsigned char *buf, size_t len,
			   unsigned int *read);
int ttls_handle_message_type(TtlsCtx *tls);
int ttls_ssl_prepare_handshake_record(ttls_ssl_context *tls);
void ttls_ssl_update_handshake_status(ttls_ssl_context *tls);

/**
 * \brief	   Update record layer
 *
 *		  This function roughly separates the implementation
 *		  of the logic of (D)TLS from the implementation
 *		  of the secure transport.
 *
 * \param  tls  SSL context to use
 *
 * \return	0 or non-zero error code.
 *
 * \note	A clarification on what is called 'record layer' here
 *		is in order, as many sensible definitions are possible:
 *
 *		The record layer takes as input an untrusted underlying
 *		transport (stream or datagram) and transforms it into
 *		a serially multiplexed, secure transport, which
 *		conceptually provides the following:
 *
 *		  (1) Three datagram based, content-agnostic transports
 *			  for handshake, alert and CCS messages.
 *		  (2) One stream- or datagram-based transport
 *			  for application data.
 *		  (3) Functionality for changing the underlying transform
 *			  securing the contents.
 *
 *		  The interface to this functionality is given as follows:
 *
 *		  a Updating
 *			[Currently implemented by ttls_read_record]
 *
 *			Check if and on which of the four 'ports' data is pending:
 *			Nothing, a controlling datagram of type (1), or application
 *			data (2). In any case data is present, internal buffers
 *			provide access to the data for the user to process it.
 *			Consumption of type (1) datagrams is done automatically
 *			on the next update, invalidating that the internal buffers
 *			for previous datagrams, while consumption of application
 *			data (2) is user-controlled.
 *
 *		  b Reading of application data
 *			[Currently manual adaption of tls->in_offt pointer]
 *
 *			As mentioned in the last paragraph, consumption of data
 *			is different from the automatic consumption of control
 *			datagrams (1) because application data is treated as a stream.
 *
 *		  c Tracking availability of application data
 *			[Currently manually through decreasing tls->in_msglen]
 *
 *			For efficiency and to retain datagram semantics for
 *			application data in case of DTLS, the record layer
 *			provides functionality for checking how much application
 *			data is still available in the internal buffer.
 *
 *		  d Changing the transformation securing the communication.
 *
 *		  Given an opaque implementation of the record layer in the
 *		  above sense, it should be possible to implement the logic
 *		  of (D)TLS on top of it without the need to know anything
 *		  about the record layer's internals. This is done e.g.
 *		  in all the handshake handling functions, and in the
 *		  application data reading function ttls_ssl_read.
 *
 * \note	The above tries to give a conceptual picture of the
 *		  record layer, but the current implementation deviates
 *		  from it in some places. For example, our implementation of
 *		  the update functionality through ttls_read_record
 *		  discards datagrams depending on the current state, which
 *		  wouldn't fall under the record layer's responsibility
 *		  following the above definition.
 */
int ttls_read_record(TtlsCtx *tls, unsigned char *buf, size_t len,
		     unsigned int *read);

int ttls_ssl_write_record(ttls_ssl_context *tls);
int ttls_ssl_flush_output(ttls_ssl_context *tls);

int ttls_ssl_parse_certificate(ttls_ssl_context *tls);
int ttls_ssl_write_certificate(ttls_ssl_context *tls);

int ttls_ssl_parse_change_cipher_spec(ttls_ssl_context *tls);
int ttls_ssl_write_change_cipher_spec(ttls_ssl_context *tls);

int ttls_ssl_parse_finished(ttls_ssl_context *tls);
int ttls_ssl_write_finished(ttls_ssl_context *tls);

void ttls_ssl_optimize_checksum(ttls_ssl_context *tls,
							const ttls_ssl_ciphersuite_t *ciphersuite_info);

#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int ttls_ssl_psk_derive_premaster(ttls_ssl_context *tls, ttls_key_exchange_type_t key_ex);
#endif

unsigned char ttls_ssl_sig_from_pk(ttls_pk_context *pk);
unsigned char ttls_ssl_sig_from_pk_alg(ttls_pk_type_t type);
ttls_pk_type_t ttls_ssl_pk_alg_from_sig(unsigned char sig);

ttls_md_type_t ttls_ssl_md_alg_from_hash(unsigned char hash);
unsigned char ttls_ssl_hash_from_md_alg(int md);
int ttls_ssl_set_calc_verify_md(ttls_ssl_context *tls, int md);

int ttls_ssl_check_curve(const ttls_ssl_context *tls, ttls_ecp_group_id grp_id);

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
int ttls_ssl_check_sig_hash(const ttls_ssl_context *tls,
								ttls_md_type_t md);
#endif

static inline ttls_pk_context *ttls_ssl_own_key(ttls_ssl_context *tls)
{
	ttls_ssl_key_cert *key_cert;

	if (tls->handshake != NULL && tls->handshake->key_cert != NULL)
		key_cert = tls->handshake->key_cert;
	else
		key_cert = tls->conf->key_cert;

	return(key_cert == NULL ? NULL : key_cert->key);
}

static inline ttls_x509_crt *ttls_ssl_own_cert(ttls_ssl_context *tls)
{
	ttls_ssl_key_cert *key_cert;

	if (tls->handshake != NULL && tls->handshake->key_cert != NULL)
		key_cert = tls->handshake->key_cert;
	else
		key_cert = tls->conf->key_cert;

	return(key_cert == NULL ? NULL : key_cert->cert);
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
int ttls_ssl_check_cert_usage(const ttls_x509_crt *cert,
						  const ttls_ssl_ciphersuite_t *ciphersuite,
						  int cert_endpoint,
						  uint32_t *flags);

void ttls_ssl_write_version(int major, int minor, int transport,
						unsigned char ver[2]);
void ttls_ssl_read_version(int *major, int *minor, int transport,
					   const unsigned char ver[2]);

static inline size_t
ttls_hdr_len(const TtlsCtx *tls)
{
#if defined(TTLS_SSL_PROTO_DTLS)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
		return 13;
#endif
	return 5;
}

static inline size_t ttls_ssl_hs_hdr_len(const ttls_ssl_context *tls)
{
#if defined(TTLS_SSL_PROTO_DTLS)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
		return(12);
#endif
	return(4);
}

#if defined(TTLS_SSL_PROTO_DTLS)
void ttls_ssl_send_flight_completed(ttls_ssl_context *tls);
void ttls_ssl_recv_flight_completed(ttls_ssl_context *tls);
int ttls_ssl_resend(ttls_ssl_context *tls);
#endif

/* Visible for testing purposes only */
#if defined(TTLS_SSL_DTLS_ANTI_REPLAY)
int ttls_ssl_dtls_replay_check(ttls_ssl_context *tls);
void ttls_ssl_dtls_replay_update(ttls_ssl_context *tls);
#endif

int ttls_ssl_get_key_exchange_md_tls1_2(ttls_ssl_context *tls,
					unsigned char *output,
					unsigned char *data, size_t data_len,
					ttls_md_type_t md_alg);

#endif /* ssl_internal.h */
