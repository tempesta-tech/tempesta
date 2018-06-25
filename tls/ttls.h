/*
 *		Tempesta TLS
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __TTLS_H__
#define __TTLS_H__

#include <linux/scatterlist.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/tls.h>

#include "lib/log.h"

#include "config.h"
#include "bignum.h"
#include "ecp.h"
#include "ssl_ciphersuites.h"
#include "x509_crt.h"
#include "x509_crl.h"
#if defined(TTLS_DHM_C)
#include "dhm.h"
#endif
#if defined(TTLS_ECDH_C)
#include "ecdh.h"
#endif

/*
 * SSL Error codes
 */
#define TTLS_ERR_FEATURE_UNAVAILABLE	-0x7080 /**< The requested feature is not available. */
#define TTLS_ERR_BAD_INPUT_DATA		-0x7100 /**< Bad input parameters to function. */
#define TTLS_ERR_INVALID_MAC		-0x7180 /**< Verification of the message MAC failed. */
#define TTLS_ERR_INVALID_RECORD		-0x7200 /**< An invalid SSL record was received. */
#define TTLS_ERR_CONN_EOF		-0x7280 /**< The connection indicated an EOF. */
#define TTLS_ERR_UNKNOWN_CIPHER		-0x7300 /**< An unknown cipher was received. */
#define TTLS_ERR_NO_CIPHER_CHOSEN	-0x7380 /**< The server has no ciphersuites in common with the client. */
#define TTLS_ERR_NO_RNG			-0x7400 /**< No RNG was provided to the SSL module. */
#define TTLS_ERR_NO_CLIENT_CERTIFICATE	-0x7480 /**< No client certification received from the client, but required by the authentication mode. */
#define TTLS_ERR_CERTIFICATE_TOO_LARGE	-0x7500 /**< Our own certificate(s) is/are too large to send in an SSL message. */
#define TTLS_ERR_CERTIFICATE_REQUIRED	-0x7580 /**< The own certificate is not set, but needed by the server. */
#define TTLS_ERR_PRIVATE_KEY_REQUIRED	-0x7600 /**< The own private key or pre-shared key is not set, but needed. */
#define TTLS_ERR_CA_CHAIN_REQUIRED	-0x7680 /**< No CA Chain is set, but required to operate. */
#define TTLS_ERR_UNEXPECTED_MESSAGE	-0x7700 /**< An unexpected message was received from our peer. */
#define TTLS_ERR_FATAL_ALERT_MESSAGE	-0x7780 /**< A fatal alert message was received from our peer. */
#define TTLS_ERR_PEER_VERIFY_FAILED	-0x7800 /**< Verification of our peer failed. */
#define TTLS_ERR_PEER_CLOSE_NOTIFY	-0x7880 /**< The peer notified us that the connection is going to be closed. */
#define TTLS_ERR_BAD_HS_CLIENT_HELLO	-0x7900 /**< Processing of the ClientHello handshake message failed. */
#define TTLS_ERR_BAD_HS_SERVER_HELLO	-0x7980 /**< Processing of the ServerHello handshake message failed. */
#define TTLS_ERR_BAD_HS_CERTIFICATE	-0x7A00 /**< Processing of the Certificate handshake message failed. */
#define TTLS_ERR_BAD_HS_CERTIFICATE_REQUEST	-0x7A80 /**< Processing of the CertificateRequest handshake message failed. */
#define TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE	-0x7B00 /**< Processing of the ServerKeyExchange handshake message failed. */
#define TTLS_ERR_BAD_HS_SERVER_HELLO_DONE	-0x7B80 /**< Processing of the ServerHelloDone handshake message failed. */
#define TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE	-0x7C00 /**< Processing of the ClientKeyExchange handshake message failed. */
#define TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_RP	-0x7C80 /**< Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public. */
#define TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_CS	-0x7D00 /**< Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret. */
#define TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY	-0x7D80 /**< Processing of the CertificateVerify handshake message failed. */
#define TTLS_ERR_BAD_HS_CHANGE_CIPHER_SPEC	-0x7E00 /**< Processing of the ChangeCipherSpec handshake message failed. */
#define TTLS_ERR_BAD_HS_FINISHED		-0x7E80 /**< Processing of the Finished handshake message failed. */
#define TTLS_ERR_ALLOC_FAILED		-0x7F00 /**< Memory allocation failed */
#define TTLS_ERR_HW_ACCEL_FAILED		-0x7F80 /**< Hardware acceleration function returned with error */
#define TTLS_ERR_HW_ACCEL_FALLTHROUGH	-0x6F80 /**< Hardware acceleration function skipped / left alone data */
#define TTLS_ERR_COMPRESSION_FAILED	-0x6F00 /**< Processing of the compression / decompression failed */
#define TTLS_ERR_BAD_HS_PROTOCOL_VERSION	-0x6E80 /**< Handshake protocol not within min/max boundaries */
#define TTLS_ERR_BAD_HS_NEW_SESSION_TICKET	-0x6E00 /**< Processing of the NewSessionTicket handshake message failed. */
#define TTLS_ERR_SESSION_TICKET_EXPIRED	-0x6D80 /**< Session ticket has expired. */
#define TTLS_ERR_PK_TYPE_MISMATCH	-0x6D00 /**< Public key type mismatch (eg, asked for RSA key exchange and presented EC key) */
#define TTLS_ERR_UNKNOWN_IDENTITY	-0x6C80 /**< Unknown identity received (eg, PSK identity) */
#define TTLS_ERR_INTERNAL_ERROR		-0x6C00 /**< Internal error (eg, unexpected failure in lower-level module) */
#define TTLS_ERR_COUNTER_WRAPPING	-0x6B80 /**< A counter would wrap (eg, too many messages exchanged). */
#define TTLS_ERR_WAITING_SERVER_HELLO_RENEGO	-0x6B00 /**< Unexpected message at ServerHello in renegotiation. */
#define TTLS_ERR_HELLO_VERIFY_REQUIRED	-0x6A80 /**< DTLS client must retry for hello verification */
#define TTLS_ERR_BUFFER_TOO_SMALL	-0x6A00 /**< A buffer is too small to receive or write a message */
#define TTLS_ERR_NO_USABLE_CIPHERSUITE	-0x6980 /**< None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages). */
#define TTLS_ERR_WANT_READ		-0x6900 /**< Connection requires a read call. */
#define TTLS_ERR_WANT_WRITE		-0x6880 /**< Connection requires a write call. */
#define TTLS_ERR_TIMEOUT			-0x6800 /**< The operation timed out. */
#define TTLS_ERR_CLIENT_RECONNECT	-0x6780 /**< The client initiated a reconnect from the same port. */
#define TTLS_ERR_UNEXPECTED_RECORD	-0x6700 /**< Record header looks valid but is not expected. */
#define TTLS_ERR_NON_FATAL		-0x6680 /**< The alert message received indicates a non-fatal error. */
#define TTLS_ERR_INVALID_VERIFY_HASH	-0x6600 /**< Couldn't set the hash for verifying CertificateVerify */

/*
 * Various constants
 */
#define TTLS_MAJOR_VERSION_3	3
#define TTLS_MINOR_VERSION_0	0 /* SSL v3.0 */
#define TTLS_MINOR_VERSION_1	1 /* TLS v1.0 */
#define TTLS_MINOR_VERSION_2	2 /* TLS v1.1 */
#define TTLS_MINOR_VERSION_3	3 /* TLS v1.2 */
#define TTLS_MINOR_VERSION_4	4 /* TLS v1.3, not supported yet */

#define TTLS_TRANSPORT_STREAM	0 /*!< TLS	*/
#define TTLS_TRANSPORT_DATAGRAM	1 /*!< DTLS	*/

#define TTLS_MAX_HOST_NAME_LEN	255 /*!< Maximum host name defined in RFC 1035 */

/* RFC 6066 section 4, see also mfl_code_to_length in ssl_tls.c
 * NONE must be zero so that memset()ing structure to zero works */
#define TTLS_MAX_FRAG_LEN_NONE	0 /*!< don't use this extension */
#define TTLS_MAX_FRAG_LEN_512	1 /*!< MaxFragmentLength 2^9	*/
#define TTLS_MAX_FRAG_LEN_1024	2 /*!< MaxFragmentLength 2^10	*/
#define TTLS_MAX_FRAG_LEN_2048	3 /*!< MaxFragmentLength 2^11	*/
#define TTLS_MAX_FRAG_LEN_4096	4 /*!< MaxFragmentLength 2^12	*/
#define TTLS_MAX_FRAG_LEN_INVALID	5 /*!< first invalid value	*/

#define TTLS_IS_CLIENT	0
#define TTLS_IS_SERVER	1

#define TTLS_IS_NOT_FALLBACK	0
#define TTLS_IS_FALLBACK	1

#define TTLS_EXTENDED_MS_DISABLED	0
#define TTLS_EXTENDED_MS_ENABLED	1

#define TTLS_COMPRESS_NULL	0
#define TTLS_COMPRESS_DEFLATE	1

#define TTLS_VERIFY_NONE	0
#define TTLS_VERIFY_OPTIONAL	1
#define TTLS_VERIFY_REQUIRED	2
#define TTLS_VERIFY_UNSET	3 /* Used only for sni_authmode */

#define TTLS_LEGACY_RENEGOTIATION	0
#define TTLS_SECURE_RENEGOTIATION	1

#define TTLS_RENEGOTIATION_DISABLED	0
#define TTLS_RENEGOTIATION_ENABLED	1

#define TTLS_ANTI_REPLAY_DISABLED	0
#define TTLS_ANTI_REPLAY_ENABLED	1

#define TTLS_RENEGOTIATION_NOT_ENFORCED -1
#define TTLS_RENEGO_MAX_RECORDS_DEFAULT 16

#define TTLS_LEGACY_NO_RENEGOTIATION	0
#define TTLS_LEGACY_ALLOW_RENEGOTIATION 1
#define TTLS_LEGACY_BREAK_HANDSHAKE	2

#define TTLS_TRUNC_HMAC_DISABLED	0
#define TTLS_TRUNC_HMAC_ENABLED	1

#define TTLS_SESSION_TICKETS_DISABLED	0
#define TTLS_SESSION_TICKETS_ENABLED	1

#define TTLS_ARC4_ENABLED	0
#define TTLS_ARC4_DISABLED	1

#define TTLS_PRESET_DEFAULT	0
#define TTLS_PRESET_SUITEB	2

#define TTLS_CERT_REQ_CA_LIST_ENABLED	1
#define TTLS_CERT_REQ_CA_LIST_DISABLED	0

/*
 * Default range for DTLS retransmission timer value, in milliseconds.
 * RFC 6347 4.2.4.1 says from 1 second to 60 seconds.
 */
#define TTLS_DTLS_TIMEOUT_DFL_MIN	1000
#define TTLS_DTLS_TIMEOUT_DFL_MAX 	60000

#if !defined(TTLS_DEFAULT_TICKET_LIFETIME)
#define TTLS_DEFAULT_TICKET_LIFETIME	86400 /**< Lifetime of session tickets (if enabled) */
#endif

/*
 * Maxium fragment length in bytes, determines the size of each of the two
 * internal I/O buffers.
 */
#define TTLS_MAX_CONTENT_LEN		16384

/*
 * Length of the verify data for secure renegotiation
 */
#define TTLS_VERIFY_DATA_MAX_LEN		12

/*
 * Signaling ciphersuite values (SCSV)
 */
#define TTLS_EMPTY_RENEGOTIATION_INFO	0xFF /**< renegotiation info ext */
#define TTLS_FALLBACK_SCSV_VALUE	0x5600 /**< RFC 7507 section 2 */

/*
 * Supported Signature and Hash algorithms (For TLS 1.2)
 * RFC 5246 section 7.4.1.4.1
 */
#define TTLS_HASH_NONE	0
#define TTLS_HASH_MD5	1
#define TTLS_HASH_SHA1	2
#define TTLS_HASH_SHA224	3
#define TTLS_HASH_SHA256	4
#define TTLS_HASH_SHA384	5
#define TTLS_HASH_SHA512	6

#define TTLS_SIG_ANON	0
#define TTLS_SIG_RSA	1
#define TTLS_SIG_ECDSA	3

/*
 * Client Certificate Types
 * RFC 5246 section 7.4.4 plus RFC 4492 section 5.5
 */
#define TTLS_CERT_TYPE_RSA_SIGN		1
#define TTLS_CERT_TYPE_ECDSA_SIGN		64

/*
 * Message, alert and handshake types
 */
#define TTLS_MSG_CHANGE_CIPHER_SPEC		20
#define TTLS_MSG_ALERT				21
#define TTLS_MSG_HANDSHAKE			22
#define TTLS_MSG_APPLICATION_DATA		23

#define TTLS_ALERT_LEVEL_WARNING		1
#define TTLS_ALERT_LEVEL_FATAL		2

#define TTLS_ALERT_MSG_CLOSE_NOTIFY	0 /* 0x00 */
#define TTLS_ALERT_MSG_UNEXPECTED_MESSAGE	10 /* 0x0A */
#define TTLS_ALERT_MSG_BAD_RECORD_MAC	20 /* 0x14 */
#define TTLS_ALERT_MSG_DECRYPTION_FAILED	21 /* 0x15 */
#define TTLS_ALERT_MSG_RECORD_OVERFLOW	22 /* 0x16 */
#define TTLS_ALERT_MSG_DECOMPRESSION_FAILURE 30 /* 0x1E */
#define TTLS_ALERT_MSG_HANDSHAKE_FAILURE	40 /* 0x28 */
#define TTLS_ALERT_MSG_NO_CERT	41 /* 0x29 */
#define TTLS_ALERT_MSG_BAD_CERT	42 /* 0x2A */
#define TTLS_ALERT_MSG_UNSUPPORTED_CERT	43 /* 0x2B */
#define TTLS_ALERT_MSG_CERT_REVOKED	44 /* 0x2C */
#define TTLS_ALERT_MSG_CERT_EXPIRED	45 /* 0x2D */
#define TTLS_ALERT_MSG_CERT_UNKNOWN	46 /* 0x2E */
#define TTLS_ALERT_MSG_ILLEGAL_PARAMETER	47 /* 0x2F */
#define TTLS_ALERT_MSG_UNKNOWN_CA	48 /* 0x30 */
#define TTLS_ALERT_MSG_ACCESS_DENIED	49 /* 0x31 */
#define TTLS_ALERT_MSG_DECODE_ERROR	50 /* 0x32 */
#define TTLS_ALERT_MSG_DECRYPT_ERROR	51 /* 0x33 */
#define TTLS_ALERT_MSG_EXPORT_RESTRICTION	60 /* 0x3C */
#define TTLS_ALERT_MSG_PROTOCOL_VERSION	70 /* 0x46 */
#define TTLS_ALERT_MSG_INSUFFICIENT_SECURITY 71 /* 0x47 */
#define TTLS_ALERT_MSG_INTERNAL_ERROR	80 /* 0x50 */
#define TTLS_ALERT_MSG_INAPROPRIATE_FALLBACK 86 /* 0x56 */
#define TTLS_ALERT_MSG_USER_CANCELED	90 /* 0x5A */
#define TTLS_ALERT_MSG_NO_RENEGOTIATION	100 /* 0x64 */
#define TTLS_ALERT_MSG_UNSUPPORTED_EXT	110 /* 0x6E */
#define TTLS_ALERT_MSG_UNRECOGNIZED_NAME	112 /* 0x70 */
#define TTLS_ALERT_MSG_UNKNOWN_PSK_IDENTITY 115 /* 0x73 */
#define TTLS_ALERT_MSG_NO_APPLICATION_PROTOCOL 120 /* 0x78 */

#define TTLS_HS_HELLO_REQUEST	0
#define TTLS_HS_CLIENT_HELLO	1
#define TTLS_HS_SERVER_HELLO	2
#define TTLS_HS_HELLO_VERIFY_REQUEST	3
#define TTLS_HS_NEW_SESSION_TICKET	4
#define TTLS_HS_CERTIFICATE	11
#define TTLS_HS_SERVER_KEY_EXCHANGE	12
#define TTLS_HS_CERTIFICATE_REQUEST	13
#define TTLS_HS_SERVER_HELLO_DONE	14
#define TTLS_HS_CERTIFICATE_VERIFY	15
#define TTLS_HS_CLIENT_KEY_EXCHANGE	16
#define TTLS_HS_FINISHED	20

/*
 * TLS extensions
 */
#define TTLS_TLS_EXT_SERVERNAME	0
#define TTLS_TLS_EXT_SERVERNAME_HOSTNAME	0

#define TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH	1

#define TTLS_TLS_EXT_TRUNCATED_HMAC	4

#define TTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES 10
#define TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS	11

#define TTLS_TLS_EXT_SIG_ALG	13

#define TTLS_TLS_EXT_ALPN	16

#define TTLS_TLS_EXT_ENCRYPT_THEN_MAC	22 /* 0x16 */
#define TTLS_TLS_EXT_EXTENDED_MASTER_SECRET 0x0017 /* 23 */

#define TTLS_TLS_EXT_SESSION_TICKET	35

#define TTLS_TLS_EXT_ECJPAKE_KKPP	256 /* experimental */

#define TTLS_TLS_EXT_RENEGOTIATION_INFO	0xFF01

/*
 * Size defines
 */
#if !defined(TTLS_PSK_MAX_LEN)
#define TTLS_PSK_MAX_LEN	32 /* 256 bits */
#endif

/* Dummy type used only for its size */
union ttls_premaster_secret
{
	unsigned char _pms_rsa[48];	/* RFC 5246 8.1.1 */
	unsigned char _pms_dhm[TTLS_MPI_MAX_SIZE];	/* RFC 5246 8.1.2 */
	unsigned char _pms_ecdh[TTLS_ECP_MAX_BYTES];	/* RFC 4492 5.10 */
};

#define TTLS_PREMASTER_SIZE	sizeof(union ttls_premaster_secret)

/*
 * SSL state machine
 */
typedef enum {
	TTLS_CLIENT_HELLO = 0,
	TTLS_SERVER_HELLO = TTLS_CLIENT_HELLO,
	TTLS_SERVER_CERTIFICATE,
	TTLS_SERVER_KEY_EXCHANGE,
	TTLS_CERTIFICATE_REQUEST,
	TTLS_SERVER_HELLO_DONE,
	TTLS_CLIENT_CERTIFICATE,
	TTLS_CLIENT_KEY_EXCHANGE,
	TTLS_CERTIFICATE_VERIFY,
	TTLS_CLIENT_CHANGE_CIPHER_SPEC,
	TTLS_CLIENT_FINISHED,
	TTLS_SERVER_CHANGE_CIPHER_SPEC,
	TTLS_SERVER_FINISHED,
	TTLS_FLUSH_BUFFERS,
	TTLS_HANDSHAKE_WRAPUP,
	TTLS_HANDSHAKE_OVER,
	TTLS_SERVER_NEW_SESSION_TICKET,
	TTLS_SERVER_HELLO_VERIFY_REQUEST_SENT,
};

/* Defined below */
typedef struct TtlsSess ttls_session;
typedef struct ttls_context ttls_context;
typedef struct ttls_config ttls_config;

/* Defined in ssl_internal.h */
typedef struct TtlsXfrm ttls_transform;
typedef struct ttls_handshake_params ttls_handshake_params;
typedef struct ttls_sig_hash_set_t ttls_sig_hash_set_t;
typedef struct ttls_key_cert ttls_key_cert;
#if defined(TTLS_PROTO_DTLS)
typedef struct ttls_flight_item ttls_flight_item;
#endif

/*
 * This structure is used for storing current session data.
 */
typedef struct {
	time_t start;	/*!< starting time	*/
	int ciphersuite;	/*!< chosen ciphersuite */
	int compression;	/*!< chosen compression */
	size_t id_len;	/*!< session id length */
	unsigned char id[32];	/*!< session identifier */
	unsigned char master[48]; /*!< the master secret */

	ttls_x509_crt *peer_cert;	/*!< peer X.509 cert chain */
	uint32_t verify_result;	/*!< verification result	*/

#if defined(TTLS_SESSION_TICKETS) && defined(TTLS_CLI_C)
	unsigned char *ticket;	/*!< RFC 5077 session ticket */
	size_t ticket_len;	/*!< session ticket length */
	uint32_t ticket_lifetime; /*!< ticket lifetime hint	*/
#endif /* TTLS_SESSION_TICKETS && TTLS_CLI_C */

#if defined(TTLS_MAX_FRAGMENT_LENGTH)
	unsigned char mfl_code;	/*!< MaxFragmentLength negotiated by peer */
#endif /* TTLS_MAX_FRAGMENT_LENGTH */
	int encrypt_then_mac;	/*!< flag for EtM activation	*/
} TlsSess;

/**
 * SSL/TLS configuration to be shared between ttls_context structures.
 */
struct ttls_config
{
	/* Group items by size (largest first) to minimize padding overhead */

	/*
	* Pointers
	*/

	const int *ciphersuite_list[4]; /*!< allowed ciphersuites per version */

	/** Callback for getting (pseudo-)random numbers	*/
	int (*f_rng)(void *, unsigned char *, size_t);
	void *p_rng;	/*!< context for the RNG function	*/

	/** Callback to retrieve a session from the cache	*/
	int (*f_get_cache)(void *, TtlsSess *);
	/** Callback to store a session into the cache	*/
	int (*f_set_cache)(void *, const TtlsSess *);
	void *p_cache;	/*!< context for cache callbacks	*/

	/** Callback for setting cert according to SNI extension	*/
	int (*f_sni)(void *, ttls_context *, const unsigned char *, size_t);
	void *p_sni;	/*!< context for SNI callback	*/
	/** Callback to customize X.509 certificate chain verification	*/
	int (*f_vrfy)(void *, ttls_x509_crt *, int, uint32_t *);
	void *p_vrfy;	/*!< context for X.509 verify calllback */

#if defined(TTLS_DTLS_HELLO_VERIFY)
	/** Callback to create & write a cookie for ClientHello veirifcation	*/
	int (*f_cookie_write)(void *, unsigned char **, unsigned char *,
	const unsigned char *, size_t);
	/** Callback to verify validity of a ClientHello cookie	*/
	int (*f_cookie_check)(void *, const unsigned char *, size_t,
	const unsigned char *, size_t);
	void *p_cookie;	/*!< context for the cookie callbacks */
#endif

#if defined(TTLS_SESSION_TICKETS)
	/** Callback to create & write a session ticket	*/
	int (*f_ticket_write)(void *, const TtlsSess *,
	unsigned char *, const unsigned char *, size_t *, uint32_t *);
	/** Callback to parse a session ticket into a session structure	*/
	int (*f_ticket_parse)(void *, TtlsSess *, unsigned char *, size_t);
	void *p_ticket;	/*!< context for the ticket callbacks */
#endif /* TTLS_SESSION_TICKETS */

#if defined(TTLS_EXPORT_KEYS)
	/** Callback to export key block and master secret	*/
	int (*f_export_keys)(void *, const unsigned char *,
	const unsigned char *, size_t, size_t, size_t);
	void *p_export_keys;	/*!< context for key export callback	*/
#endif

	const ttls_x509_crt_profile *cert_profile; /*!< verification profile */
	ttls_key_cert *key_cert; /*!< own certificate/key pair(s)	*/
	ttls_x509_crt *ca_chain;	/*!< trusted CAs	*/
	ttls_x509_crl *ca_crl;	/*!< trusted CAs CRLs	*/

	const int *sig_hashes;	/*!< allowed signature hashes	*/

	const ttls_ecp_group_id *curve_list; /*!< allowed curves	*/

#if defined(TTLS_DHM_C)
	ttls_mpi dhm_P;	/*!< prime modulus for DHM	*/
	ttls_mpi dhm_G;	/*!< generator for DHM	*/
#endif

	const char **alpn_list;	/*!< ordered list of protocols	*/

	/*
	* Numerical settings (int then char)
	*/

	uint32_t read_timeout;	/*!< timeout for ttls_recv (ms) */

#if defined(TTLS_PROTO_DTLS)
	uint32_t hs_timeout_min;	/*!< initial value of the handshake
	retransmission timeout (ms)	*/
	uint32_t hs_timeout_max;	/*!< maximum value of the handshake
	retransmission timeout (ms)	*/
#endif

#if defined(TTLS_DTLS_BADMAC_LIMIT)
	unsigned int badmac_limit;	/*!< limit of records with a bad MAC	*/
#endif

#if defined(TTLS_DHM_C) && defined(TTLS_CLI_C)
	unsigned int dhm_min_bitlen;	/*!< min. bit length of the DHM prime */
#endif

	unsigned char max_major_ver;	/*!< max. major version used	*/
	unsigned char max_minor_ver;	/*!< max. minor version used	*/
	unsigned char min_major_ver;	/*!< min. major version used	*/
	unsigned char min_minor_ver;	/*!< min. minor version used	*/

	/*
	* Flags (bitfields)
	*/

	unsigned int endpoint : 1;	/*!< 0: client, 1: server	*/
	unsigned int transport : 1;	/*!< stream (TLS) or datagram (DTLS)	*/
	unsigned int authmode : 2;	/*!< TTLS_VERIFY_XXX	*/
	/* needed even with renego disabled for LEGACY_BREAK_HANDSHAKE	*/
	unsigned int allow_legacy_renegotiation : 2 ; /*!< TTLS_LEGACY_XXX */
#if defined(TTLS_MAX_FRAGMENT_LENGTH)
	unsigned int mfl_code : 3;	/*!< desired fragment length	*/
#endif
	unsigned int encrypt_then_mac : 1 ; /*!< negotiate encrypt-then-mac?	*/
#if defined(TTLS_EXTENDED_MASTER_SECRET)
	unsigned int extended_ms : 1; /*!< negotiate extended master secret? */
#endif
#if defined(TTLS_DTLS_ANTI_REPLAY)
	unsigned int anti_replay : 1; /*!< detect and prevent replay?	*/
#endif
#if defined(TTLS_SESSION_TICKETS)
	unsigned int session_tickets : 1; /*!< use session tickets?	*/
#endif
#if defined(TTLS_FALLBACK_SCSV) && defined(TTLS_CLI_C)
	unsigned int fallback : 1;	/*!< is this a fallback?	*/
#endif
	unsigned int cert_req_ca_list : 1; /*!< enable sending CA list in
	Certificate Request messages?	*/
};

/* TLS state flags. */
#define TTLS_F_ST_HDRIV		1 /* header [and IV] parsed */

/**
 * I/O context for a TLS context.
 *
 * @sess	- current session data;
 * @xfrm	- current transform params;
 * @__cp_start	- start to copy temporal buffer for message header and IV,
 *		  used to reduce fragmentation complexity;
 * @ctr		- 64-bit incoming message counter maintained by us for TLS and
 * 		  read from peer for DTLS;
 * @hdr		- TLS message header;
 * @iv		- TLS message initialization vector;
 * @hdr_iv_cpsz	- how many bytes are copied to @__in_cp_start;
 * @aad_buf	- temporary buffers for associated authentication data;
 * @msgtype	- record header: message type;
 * @msglen	- record header: message length;
 * @rlen	- read bytes of the message body so far;
 * @skb_list	- list of skbs attachd to the current I/O context;
 * @off		- data offset within first skb in @skb_list;
 * @chunks	- number of contigious memory chunks in all skbs in @skb_list;
 */
typedef struct {
	TlsSess		*sess;
	TlsXfrm		*xfrm
#if defined(MBEDTLS_PROTO_DTLS)
	unsigned char	__cp_start[0];
	union {
		unsigned char	hdr[TTLS_HDR_LEN];
		struct {
			unsigned char	__padding[3];
			unsigned char	ctr[8];
		};
	}
#else
	unsigned char	ctr[8];
	unsigned char	__cp_start[0];
	unsigned char	hdr[TTLS_HDR_LEN];
#endif
	union {
		unsigned char	iv[TTLS_IV_LEN];
		unsigned char	alert[2];
	}
	unsigned char	hdr_iv_cpsz;
	unsigned char	aad_buf[TLS_AAD_SPACE_SIZE];
	unsigned char	msgtype;
	unsigned short	msglen;
	unsigned short	rlen;
	struct sk_buff	*skb_list;
	unsigned int	off;
	unsigned int	chunks;
} TlsIOCtx;

/**
 * TLS context.
 *
 * We do our best to process sockets in per-cpu basis using TfwRBQueues, but
 * sockets still can migrate between CPUs and downcalls (e.g. connection
 * closing) can be run concurrently with upcalls (e.g. message reception), so
 * we need @lock to protect the TLS context just like we use locks in TfwConn
 * heirs. Since most of the work is done per-cpu, we can not pay much attention
 * to the lock granularity.
 *
 * @lock	- protects the TLS context changes;
 * @conf	- global TLS configuration;
 * @hs		- params required only during the handshake process;
 * @state	- TLS handshake: current TLS FSM state;
 * @st_flags	- state flags;
 * @major_ver	- the context TLS major version, currently equal to
 *		  TTLS_MAJOR_VERSION_3;
 * @minor_ver	- either 0 (SSL3) or 1 (TLS1.0);
 * @io_{in,out}	- I/O contexts for ingress and egress messages correspondingly;
 *		  TODO if we can not process ingress data concurrently with
 *		       transmission, then we need only one IO context; if we can,
 *		       then @lock should be split to 2 or 3 locks (for each
 *		       IO plust the whole structure operations).
 * @sess	- session data;
 * @xfrm	- transform params;
 * @nb_zero	-  # of 0-length encrypted messages;
 */
typedef struct ttls_context {
	spinlock_t		lock;
	const ttls_config	*conf;
	TlsHandshake		*hs;

	int			state;
	unsigned short		st_flags;
	unsigned char		major_ver;
	unsigned char		minor_ver;

	TlsIOCtx		io_in;
	TlsIOCtx		io_out;
	TlsSess			sess;
	TtlsXfrm		xfrm;

	unsigned int		nb_zero;

	TlsSess *session;	/*!< negotiated session data	*/
	TtlsXfrm *transform_negotiate; /*!< transform params in negotiation */



	/*
	* Timers
	*/
	void *p_timer;	/*!< context for the timer callbacks */
	ttls_set_timer_t *f_set_timer;	/*!< set timer callback */
	ttls_get_timer_t *f_get_timer;	/*!< get timer callback */

	size_t in_hslen;	/*!< current handshake message length,
					including the handshake header */

	int keep_current_message; /*!< drop or reuse current message
					on next call to record layer? */

	/*
	* PKI layer
	*/
	int client_auth;	/*!< flag for client auth. */

	/*
	* User settings
	*/
	char *hostname;	/*!< expected peer CN for verification
	(and SNI if available)	*/

	const char *alpn_chosen;	/*!< negotiated protocol	*/

	/*
	* Secure renegotiation
	*/
	/* needed to know when to send extension on server */
	int secure_renegotiation;	/*!< does peer support legacy or
						secure renegotiation	*/

#if defined(TTLS_DTLS_HELLO_VERIFY)
	/* Information for DTLS hello verify. */
	unsigned char	*cli_id;	/* transport-level ID of the client */
	size_t		cli_id_len;	/* length of cli_id */
#endif
#if defined(TTLS_DTLS_BADMAC_LIMIT)
	unsigned	badmac_seen;	/* records with a bad MAC received */
#endif
#if defined(TTLS_PROTO_DTLS)
	/* DTLS epoch for incoming records. */
	uint16_t	in_epoch;
	/* Offset of the next record in datagram. */
	size_t		next_record_offset;
#endif
#if defined(TTLS_DTLS_ANTI_REPLAY)
	uint64_t	in_window_top;	/* last validated record seq_num */
	uint64_t	in_window;	/* bitmask for replay detection */
#endif
} TlsCtx;

typedef int *ttls_send_sb_t(TlsCtx *tls, const unsigned char *buf, size_t len,
			    bool encrypt);

static inline size_t
ttls_hdr_len(const TlsCtx *tls)
{
#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		return 13;
#endif
	return 5;
}

/**
 * Convert version numbers to/from wire format and, for DTLS, to/from
 * TLS equivalent.
 *
 * For TLS this is the identity.
 * For DTLS, use 1's complement (v -> 255 - v, and then map as follows:
 *	1.0 <-> 3.2	(DTLS 1.0 is based on TLS 1.1)
 *	1.x <-> 3.x+1	for x != 0 (DTLS 1.2 based on TLS 1.2)
 */
static inline void
ttls_write_version(TlsCtx *tls, unsigned char ver[2])
{
#if defined(TTLS_PROTO_DTLS)
	if (tls->conf->transport == TTLS_TRANSPORT_DATAGRAM) {
		unsigned char minor = tls->minor - 1;
		if (tls->minor_ver == TTLS_MINOR_VERSION_2)
			--minor; /* DTLS 1.0 stored as TLS 1.1 internally */
		ver[0] = (unsigned char)(255 - (tls->major_ver - 2));
		ver[1] = (unsigned char)(255 - minor);
	} else
#endif
	{
		ver[0] = (unsigned char)tls->major_ver;
		ver[1] = (unsigned char)tls->minor_ver;
	}
}

static inline void
ttls_write_hdr(TlsCtx *tls, unsigned char type, unsigned short len,
	       unsigned char *buf)
{
	buf[0] = type;
	ttls_write_version(tls, buf + 1);
	buf[3] = (unsigned char)(len >> 8);
	buf[4] = (unsigned char)len;
}

static inline unsigned char
ttls_xfrm_taglen(TlsXfrm *xfrm)
{
	return xfrm->ciphersuite_info->flags & TTLS_CIPHERSUITE_SHORT_TAG
		? 8 : 16;
}

void *ttls_alloc_crypto_req(unsigned int extra_size, unsigned int *rsz);
void ttls_register_bio(ttls_send_cb_t *send_cb);

void ttls_init_msg_ctx(TlsCtx *tls);

/**
 * \brief Returns the list of ciphersuites supported by the SSL/TLS module.
 *
 * \return	a statically allocated array of ciphersuites, the last
 *	entry is 0.
 */
const int *ttls_list_ciphersuites(void);

/**
 * \brief	Return the name of the ciphersuite associated with the
 *		given ID
 *
 * \param 	ciphersuite_id SSL ciphersuite ID
 *
 * \return	a string containing the ciphersuite name
 */
const char *ttls_get_ciphersuite_name(const int ciphersuite_id);

/**
 * \brief	Return the ID of the ciphersuite associated with the
 *		given name
 *
 * \param ciphersuite_name SSL ciphersuite name
 *
 * \return	the ID with the ciphersuite or 0 if not found
 */
int ttls_get_ciphersuite_id(const char *ciphersuite_name);

int ttls_ctx_init(TlsCtx *tls, const ttls_config *conf);

/**
 * \brief	Set the current endpoint type
 *
 * \param conf	SSL configuration
 * \param endpoint must be TTLS_IS_CLIENT or TTLS_IS_SERVER
 */
void ttls_conf_endpoint(ttls_config *conf, int endpoint);

/**
 * \brief	Set the transport type (TLS or DTLS).
 *		Default: TLS
 *
 * \note	For DTLS, you must either provide a recv callback that
 *		doesn't block, or one that handles timeouts, see
 *		\c ttls_register_bio(). You also need to provide timer
 *		callbacks with \c ttls_set_timer_cb().
 *
 * \param conf	SSL configuration
 * \param transport transport type:
 *		TTLS_TRANSPORT_STREAM for TLS,
 *		TTLS_TRANSPORT_DATAGRAM for DTLS.
 */
void ttls_conf_transport(ttls_config *conf, int transport);

/**
 * \brief	Set the certificate verification mode
 *		Default: NONE on server, REQUIRED on client
 *
 * \param conf	SSL configuration
 * \param authmode can be:
 *
 * TTLS_VERIFY_NONE:	peer certificate is not checked
 *		(default on server)
 *		(insecure on client)
 *
 * TTLS_VERIFY_OPTIONAL: peer certificate is checked, however the
 *		handshake continues even if verification failed;
 *		ttls_get_verify_result() can be called after the
 *		handshake is complete.
 *
 * TTLS_VERIFY_REQUIRED: peer *must* present a valid certificate,
 *		handshake is aborted if verification failed.
 *		(default on client)
 *
 * \note On client, TTLS_VERIFY_REQUIRED is the recommended mode.
 * With TTLS_VERIFY_OPTIONAL, the user needs to call ttls_get_verify_result() at
 * the right time(s), which may not be obvious, while REQUIRED always perform
 * the verification as soon as possible. For example, REQUIRED was protecting
 * against the "triple handshake" attack even before it was found.
 */
void ttls_conf_authmode(ttls_config *conf, int authmode);

/**
 * \brief	Set the verification callback (Optional).
 *
 *		If set, the verify callback is called for each
 *		certificate in the chain. For implementation
 *		information, please see \c ttls_x509_crt_verify()
 *
 * \param conf	SSL configuration
 * \param f_vrfy verification function
 * \param p_vrfy verification parameter
 */
void ttls_conf_verify(ttls_config *conf,
	int (*f_vrfy)(void *, ttls_x509_crt *, int, uint32_t *),
	void *p_vrfy);

/**
 * \brief	Set the random number generator callback
 *
 * \param conf	SSL configuration
 * \param f_rng	RNG function
 * \param p_rng	RNG parameter
 */
void ttls_conf_rng(ttls_config *conf,
	int (*f_rng)(void *, unsigned char *, size_t),
	void *p_rng);

/**
 * \brief	Set the timer callbacks (Mandatory for DTLS.)
 *
 * \param ssl	SSL context
 * \param p_timer parameter (context) shared by timer callbacks
 * \param f_set_timer set timer callback
 * \param f_get_timer get timer callback. Must return:
 *
 * \note	See the documentation of \c ttls_set_timer_t and
 *		\c ttls_get_timer_t for the conventions this pair of
 *		callbacks must follow.
 *
 * \note	On some platforms, timing.c provides
 *		\c ttls_timing_set_delay() and
 *		\c ttls_timing_get_delay() that are suitable for using
 *		here, except if using an event-driven style.
 *
 * \note	See also the "DTLS tutorial" article in our knowledge base.
 *		https://tls.mbed.org/kb/how-to/dtls-tutorial
 */
void ttls_set_timer_cb(ttls_context *ssl,
	void *p_timer,
	ttls_set_timer_t *f_set_timer,
	ttls_get_timer_t *f_get_timer);

/**
 * \brief	Callback type: generate and write session ticket
 *
 * \note	This describes what a callback implementation should do.
 *		This callback should generate an encrypted and
 *		authenticated ticket for the session and write it to the
 *		output buffer. Here, ticket means the opaque ticket part
 *		of the NewSessionTicket structure of RFC 5077.
 *
 * \param p_ticket Context for the callback
 * \param session SSL session to be written in the ticket
 * \param start	Start of the output buffer
 * \param end	End of the output buffer
 * \param tlen	On exit, holds the length written
 * \param lifetime On exit, holds the lifetime of the ticket in seconds
 *
 * \return	0 if successful, or
 *		a specific TTLS_ERR_XXX code.
 */
typedef int ttls_ticket_write_t(void *p_ticket,
	const TtlsSess *session,
	unsigned char *start,
	const unsigned char *end,
	size_t *tlen,
	uint32_t *lifetime);

#if defined(TTLS_EXPORT_KEYS)
/**
 * \brief	Callback type: Export key block and master secret
 *
 * \note	This is required for certain uses of TLS, e.g. EAP-TLS
 *		(RFC 5216) and Thread. The key pointers are ephemeral and
 *		therefore must not be stored. The master secret and keys
 *		should not be used directly except as an input to a key
 *		derivation function.
 *
 * \param p_expkey Context for the callback
 * \param ms	Pointer to master secret (fixed length: 48 bytes)
 * \param kb	Pointer to key block, see RFC 5246 section 6.3
 *		(variable length: 2 * maclen + 2 * keylen + 2 * ivlen).
 * \param maclen	MAC length
 * \param keylen	Key length
 * \param ivlen	IV length
 *
 * \return	0 if successful, or
 *		a specific TTLS_ERR_XXX code.
 */
typedef int ttls_export_keys_t(void *p_expkey,
	const unsigned char *ms,
	const unsigned char *kb,
	size_t maclen,
	size_t keylen,
	size_t ivlen);
#endif /* TTLS_EXPORT_KEYS */

/**
 * \brief	Callback type: parse and load session ticket
 *
 * \note	This describes what a callback implementation should do.
 *		This callback should parse a session ticket as generated
 *		by the corresponding ttls_ticket_write_t function,
 *		and, if the ticket is authentic and valid, load the
 *		session.
 *
 * \note	The implementation is allowed to modify the first len
 *		bytes of the input buffer, eg to use it as a temporary
 *		area for the decrypted ticket contents.
 *
 * \param p_ticket Context for the callback
 * \param session SSL session to be loaded
 * \param buf	Start of the buffer containing the ticket
 * \param len	Length of the ticket.
 *
 * \return	0 if successful, or
 *		TTLS_ERR_INVALID_MAC if not authentic, or
 *		TTLS_ERR_SESSION_TICKET_EXPIRED if expired, or
 *		any other non-zero code for other failures.
 */
typedef int ttls_ticket_parse_t(void *p_ticket,
	TtlsSess *session,
	unsigned char *buf,
	size_t len);

#if defined(TTLS_SESSION_TICKETS)
/**
 * \brief	Configure SSL session ticket callbacks (server only).
 *		(Default: none.)
 *
 * \note	On server, session tickets are enabled by providing
 *		non-NULL callbacks.
 *
 * \note	On client, use \c ttls_conf_session_tickets().
 *
 * \param conf	SSL configuration context
 * \param f_ticket_write	Callback for writing a ticket
 * \param f_ticket_parse	Callback for parsing a ticket
 * \param p_ticket	Context shared by the two callbacks
 */
void ttls_conf_session_tickets_cb(ttls_config *conf,
	ttls_ticket_write_t *f_ticket_write,
	ttls_ticket_parse_t *f_ticket_parse,
	void *p_ticket);
#endif /* TTLS_SESSION_TICKETS */

#if defined(TTLS_EXPORT_KEYS)
/**
 * \brief	Configure key export callback.
 *		(Default: none.)
 *
 * \note	See \c ttls_export_keys_t.
 *
 * \param conf	SSL configuration context
 * \param f_export_keys	Callback for exporting keys
 * \param p_export_keys	Context for the callback
 */
void ttls_conf_export_keys_cb(ttls_config *conf,
	ttls_export_keys_t *f_export_keys,
	void *p_export_keys);
#endif /* TTLS_EXPORT_KEYS */

/**
 * \brief	Callback type: generate a cookie
 *
 * \param ctx	Context for the callback
 * \param p	Buffer to write to,
 *		must be updated to point right after the cookie
 * \param end	Pointer to one past the end of the output buffer
 * \param info	Client ID info that was passed to
 *		\c ttls_set_client_transport_id()
 * \param ilen	Length of info in bytes
 *
 * \return	The callback must return 0 on success,
 *		or a negative error code.
 */
typedef int ttls_cookie_write_t(void *ctx,
	unsigned char **p, unsigned char *end,
	const unsigned char *info, size_t ilen);

/**
 * \brief	Callback type: verify a cookie
 *
 * \param ctx	Context for the callback
 * \param cookie Cookie to verify
 * \param clen	Length of cookie
 * \param info	Client ID info that was passed to
 *		\c ttls_set_client_transport_id()
 * \param ilen	Length of info in bytes
 *
 * \return	The callback must return 0 if cookie is valid,
 *		or a negative error code.
 */
typedef int ttls_cookie_check_t(void *ctx,
	const unsigned char *cookie, size_t clen,
	const unsigned char *info, size_t ilen);

#if defined(TTLS_DTLS_HELLO_VERIFY)
/**
 * \brief	Register callbacks for DTLS cookies
 *		(Server only. DTLS only.)
 *
 *		Default: dummy callbacks that fail, in order to force you to
 *		register working callbacks (and initialize their context).
 *
 *		To disable HelloVerifyRequest, register NULL callbacks.
 *
 * \warning	Disabling hello verification allows your server to be used
 *		for amplification in DoS attacks against other hosts.
 *		Only disable if you known this can't happen in your
 *		particular environment.
 *
 * \note	See comments on \c ttls_handshake() about handling
 *		the TTLS_ERR_HELLO_VERIFY_REQUIRED that is expected
 *		on the first handshake attempt when this is enabled.
 *
 * \note	This is also necessary to handle client reconnection from
 *		the same port as described in RFC 6347 section 4.2.8 (only
 *		the variant with cookies is supported currently). See
 *		comments on \c ttls_recv() for details.
 *
 * \param conf	SSL configuration
 * \param f_cookie_write	Cookie write callback
 * \param f_cookie_check	Cookie check callback
 * \param p_cookie	Context for both callbacks
 */
void ttls_conf_dtls_cookies(ttls_config *conf,
	ttls_cookie_write_t *f_cookie_write,
	ttls_cookie_check_t *f_cookie_check,
	void *p_cookie);

/**
 * \brief	Set client's transport-level identification info.
 *		(Server only. DTLS only.)
 *
 *		This is usually the IP address (and port), but could be
 *		anything identify the client depending on the underlying
 *		network stack. Used for HelloVerifyRequest with DTLS.
 *		This is *not* used to route the actual packets.
 *
 * \param ssl	SSL context
 * \param info	Transport-level info identifying the client (eg IP + port)
 * \param ilen	Length of info in bytes
 *
 * \note	An internal copy is made, so the info buffer can be reused.
 *
 * \return	0 on success,
 *		TTLS_ERR_BAD_INPUT_DATA if used on client,
 *		TTLS_ERR_ALLOC_FAILED if out of memory.
 */
int ttls_set_client_transport_id(ttls_context *ssl,
	const unsigned char *info,
	size_t ilen);

#endif /* TTLS_DTLS_HELLO_VERIFY */

#if defined(TTLS_DTLS_ANTI_REPLAY)
/**
 * \brief	Enable or disable anti-replay protection for DTLS.
 *		(DTLS only, no effect on TLS.)
 *		Default: enabled.
 *
 * \param conf	SSL configuration
 * \param mode	TTLS_ANTI_REPLAY_ENABLED or TTLS_ANTI_REPLAY_DISABLED.
 *
 * \warning	Disabling this is a security risk unless the application
 *		protocol handles duplicated packets in a safe way. You
 *		should not disable this without careful consideration.
 *		However, if your application already detects duplicated
 *		packets and needs information about them to adjust its
 *		transmission strategy, then you'll want to disable this.
 */
void ttls_conf_dtls_anti_replay(ttls_config *conf, char mode);
#endif /* TTLS_DTLS_ANTI_REPLAY */

#if defined(TTLS_DTLS_BADMAC_LIMIT)
/**
 * \brief	Set a limit on the number of records with a bad MAC
 *		before terminating the connection.
 *		(DTLS only, no effect on TLS.)
 *		Default: 0 (disabled).
 *
 * \param conf	SSL configuration
 * \param limit	Limit, or 0 to disable.
 *
 * \note	If the limit is N, then the connection is terminated when
 *		the Nth non-authentic record is seen.
 *
 * \note	Records with an invalid header are not counted, only the
 *		ones going through the authentication-decryption phase.
 *
 * \note	This is a security trade-off related to the fact that it's
 *		often relatively easy for an active attacker ot inject UDP
 *		datagrams. On one hand, setting a low limit here makes it
 *		easier for such an attacker to forcibly terminated a
 *		connection. On the other hand, a high limit or no limit
 *		might make us waste resources checking authentication on
 *		many bogus packets.
 */
void ttls_conf_dtls_badmac_limit(ttls_config *conf, unsigned limit);
#endif /* TTLS_DTLS_BADMAC_LIMIT */

#if defined(TTLS_PROTO_DTLS)
/**
 * \brief	Set retransmit timeout values for the DTLS handshake.
 *		(DTLS only, no effect on TLS.)
 *
 * \param conf	SSL configuration
 * \param min	Initial timeout value in milliseconds.
 *		Default: 1000 (1 second).
 * \param max	Maximum timeout value in milliseconds.
 *		Default: 60000 (60 seconds).
 *
 * \note	Default values are from RFC 6347 section 4.2.4.1.
 *
 * \note	The 'min' value should typically be slightly above the
 *		expected round-trip time to your peer, plus whatever time
 *		it takes for the peer to process the message. For example,
 *		if your RTT is about 600ms and you peer needs up to 1s to
 *		do the cryptographic operations in the handshake, then you
 *		should set 'min' slightly above 1600. Lower values of 'min'
 *		might cause spurious resends which waste network resources,
 *		while larger value of 'min' will increase overall latency
 *		on unreliable network links.
 *
 * \note	The more unreliable your network connection is, the larger
 *		your max / min ratio needs to be in order to achieve
 *		reliable handshakes.
 *
 * \note	Messages are retransmitted up to log2(ceil(max/min)) times.
 *		For example, if min = 1s and max = 5s, the retransmit plan
 *		goes: send ... 1s -> resend ... 2s -> resend ... 4s ->
 *		resend ... 5s -> give up and return a timeout error.
 */
void ttls_conf_handshake_timeout(ttls_config *conf, uint32_t min, uint32_t max);
#endif /* TTLS_PROTO_DTLS */

/**
 * \brief	Set the session cache callbacks (server-side only)
 *		If not set, no session resuming is done (except if session
 *		tickets are enabled too).
 *
 *		The session cache has the responsibility to check for stale
 *		entries based on timeout. See RFC 5246 for recommendations.
 *
 *		Warning: session.peer_cert is cleared by the SSL/TLS layer on
 *		connection shutdown, so do not cache the pointer! Either set
 *		it to NULL or make a full copy of the certificate.
 *
 *		The get callback is called once during the initial handshake
 *		to enable session resuming. The get function has the
 *		following parameters: (void *parameter, TtlsSess *session)
 *		If a valid entry is found, it should fill the master of
 *		the session object with the cached values and return 0,
 *		return 1 otherwise. Optionally peer_cert can be set as well
 *		if it is properly present in cache entry.
 *
 *		The set callback is called once during the initial handshake
 *		to enable session resuming after the entire handshake has
 *		been finished. The set function has the following parameters:
 *		(void *parameter, const TtlsSess *session). The function
 *		should create a cache entry for future retrieval based on
 *		the data in the session structure and should keep in mind
 *		that the TtlsSess object presented (and all its referenced
 *		data) is cleared by the SSL/TLS layer when the connection is
 *		terminated. It is recommended to add metadata to determine if
 *		an entry is still valid in the future. Return 0 if
 *		successfully cached, return 1 otherwise.
 *
 * \param conf	SSL configuration
 * \param p_cache	parmater (context) for both callbacks
 * \param f_get_cache	session get callback
 * \param f_set_cache	session set callback
 */
void ttls_conf_session_cache(ttls_config *conf,
	void *p_cache,
	int (*f_get_cache)(void *, TtlsSess *),
	int (*f_set_cache)(void *, const TtlsSess *));

#if defined(TTLS_CLI_C)
/**
 * \brief	Request resumption of session (client-side only)
 *		Session data is copied from presented session structure.
 *
 * \param ssl	SSL context
 * \param session session context
 *
 * \return	0 if successful,
 *		TTLS_ERR_ALLOC_FAILED if memory allocation failed,
 *		TTLS_ERR_BAD_INPUT_DATA if used server-side or
 *		arguments are otherwise invalid
 *
 * \sa	ttls_get_session()
 */
int ttls_set_session(ttls_context *ssl, const TtlsSess *session);
#endif /* TTLS_CLI_C */

/**
 * \brief	Set the list of allowed ciphersuites and the preference
 *		order. First in the list has the highest preference.
 *		(Overrides all version-specific lists)
 *
 *		The ciphersuites array is not copied, and must remain
 *		valid for the lifetime of the ssl_config.
 *
 *		Note: The server uses its own preferences
 *		over the preference of the client unless
 *		TTLS_SRV_RESPECT_CLIENT_PREFERENCE is defined!
 *
 * \param conf	SSL configuration
 * \param ciphersuites 0-terminated list of allowed ciphersuites
 */
void ttls_conf_ciphersuites(ttls_config *conf,
	const int *ciphersuites);

/**
 * \brief	Set the list of allowed ciphersuites and the
 *		preference order for a specific version of the protocol.
 *		(Only useful on the server side)
 *
 *		The ciphersuites array is not copied, and must remain
 *		valid for the lifetime of the ssl_config.
 *
 * \param conf	SSL configuration
 * \param ciphersuites 0-terminated list of allowed ciphersuites
 * \param major	Major version number (only TTLS_MAJOR_VERSION_3
 *		supported)
 * \param minor	Minor version number (TTLS_MINOR_VERSION_0,
 *		TTLS_MINOR_VERSION_1 and TTLS_MINOR_VERSION_2,
 *		TTLS_MINOR_VERSION_3 supported)
 *
 * \note	With DTLS, use TTLS_MINOR_VERSION_2 for DTLS 1.0
 *		and TTLS_MINOR_VERSION_3 for DTLS 1.2
 */
void ttls_conf_ciphersuites_for_version(ttls_config *conf,
	const int *ciphersuites,
	int major, int minor);

/**
 * \brief	Set the X.509 security profile used for verification
 *
 * \note	The restrictions are enforced for all certificates in the
 *		chain. However, signatures in the handshake are not covered
 *		by this setting but by \b ttls_conf_sig_hashes().
 *
 * \param conf	SSL configuration
 * \param profile Profile to use
 */
void ttls_conf_cert_profile(ttls_config *conf,
	const ttls_x509_crt_profile *profile);

/**
 * \brief	Set the data required to verify peer certificate
 *
 * \param conf	SSL configuration
 * \param ca_chain trusted CA chain (meaning all fully trusted top-level CAs)
 * \param ca_crl trusted CA CRLs
 */
void ttls_conf_ca_chain(ttls_config *conf,
	ttls_x509_crt *ca_chain,
	ttls_x509_crl *ca_crl);

/**
 * \brief	Set own certificate chain and private key
 *
 * \note	own_cert should contain in order from the bottom up your
 *		certificate chain. The top certificate (self-signed)
 *		can be omitted.
 *
 * \note	On server, this function can be called multiple times to
 *		provision more than one cert/key pair (eg one ECDSA, one
 *		RSA with SHA-256, one RSA with SHA-1). An adequate
 *		certificate will be selected according to the client's
 *		advertised capabilities. In case mutliple certificates are
 *		adequate, preference is given to the one set by the first
 *		call to this function, then second, etc.
 *
 * \note	On client, only the first call has any effect. That is,
 *		only one client certificate can be provisioned. The
 *		server's preferences in its CertficateRequest message will
 *		be ignored and our only cert will be sent regardless of
 *		whether it matches those preferences - the server can then
 *		decide what it wants to do with it.
 *
 * \param conf	SSL configuration
 * \param own_cert own public certificate chain
 * \param pk_key own private key
 *
 * \return	0 on success or TTLS_ERR_ALLOC_FAILED
 */
int ttls_conf_own_cert(ttls_config *conf,
	ttls_x509_crt *own_cert,
	ttls_pk_context *pk_key);

#if defined(TTLS_DHM_C)

/**
 * \brief	Set the Diffie-Hellman public P and G values
 *		from big-endian binary presentations.
 *		(Default values: TTLS_DHM_RFC3526_MODP_2048_[PG]_BIN)
 *
 * \param conf	SSL configuration
 * \param dhm_P	Diffie-Hellman-Merkle modulus in big-endian binary form
 * \param P_len	Length of DHM modulus
 * \param dhm_G	Diffie-Hellman-Merkle generator in big-endian binary form
 * \param G_len	Length of DHM generator
 *
 * \return	0 if successful
 */
int ttls_conf_dh_param_bin(ttls_config *conf,
	const unsigned char *dhm_P, size_t P_len,
	const unsigned char *dhm_G, size_t G_len);

/**
 * \brief	Set the Diffie-Hellman public P and G values,
 *		read from existing context (server-side only)
 *
 * \param conf	SSL configuration
 * \param dhm_ctx Diffie-Hellman-Merkle context
 *
 * \return	0 if successful
 */
int ttls_conf_dh_param_ctx(ttls_config *conf, ttls_dhm_context *dhm_ctx);
#endif /* TTLS_DHM_C */

#if defined(TTLS_DHM_C) && defined(TTLS_CLI_C)
/**
 * \brief	Set the minimum length for Diffie-Hellman parameters.
 *		(Client-side only.)
 *		(Default: 1024 bits.)
 *
 * \param conf	SSL configuration
 * \param bitlen Minimum bit length of the DHM prime
 */
void ttls_conf_dhm_min_bitlen(ttls_config *conf,
	unsigned int bitlen);
#endif /* TTLS_DHM_C && TTLS_CLI_C */

/**
 * \brief	Set the allowed curves in order of preference.
 *		(Default: all defined curves.)
 *
 *		On server: this only affects selection of the ECDHE curve;
 *		the curves used for ECDH and ECDSA are determined by the
 *		list of available certificates instead.
 *
 *		On client: this affects the list of curves offered for any
 *		use. The server can override our preference order.
 *
 *		Both sides: limits the set of curves accepted for use in
 *		ECDHE and in the peer's end-entity certificate.
 *
 * \note	This has no influence on which curves are allowed inside the
 *		certificate chains, see \c ttls_conf_cert_profile()
 *		for that. For the end-entity certificate however, the key
 *		will be accepted only if it is allowed both by this list
 *		and by the cert profile.
 *
 * \note	This list should be ordered by decreasing preference
 *		(preferred curve first).
 *
 * \param conf	SSL configuration
 * \param curves Ordered list of allowed curves,
 *		terminated by TTLS_ECP_DP_NONE.
 */
void ttls_conf_curves(ttls_config *conf,
	const ttls_ecp_group_id *curves);

/**
 * \brief	Set the allowed hashes for signatures during the handshake.
 *		(Default: all available hashes except MD5.)
 *
 * \note	This only affects which hashes are offered and can be used
 *		for signatures during the handshake. Hashes for message
 *		authentication and the TLS PRF are controlled by the
 *		ciphersuite, see \c ttls_conf_ciphersuites(). Hashes
 *		used for certificate signature are controlled by the
 *		verification profile, see \c ttls_conf_cert_profile().
 *
 * \note	This list should be ordered by decreasing preference
 *		(preferred hash first).
 *
 * \param conf	SSL configuration
 * \param hashes Ordered list of allowed signature hashes,
 *		terminated by \c TTLS_MD_NONE.
 */
void ttls_conf_sig_hashes(ttls_config *conf,
	const int *hashes);

/**
 * \brief	Set or reset the hostname to check against the received 
 *		server certificate. It sets the ServerName TLS extension, 
 *		too, if that extension is enabled. (client-side only)
 *
 * \param ssl	SSL context
 * \param hostname the server hostname, may be NULL to clear hostname
 
 * \note	Maximum hostname length TTLS_MAX_HOST_NAME_LEN.
 *
 * \return	0 if successful, TTLS_ERR_ALLOC_FAILED on 
 *		allocation failure, TTLS_ERR_BAD_INPUT_DATA on 
 *		too long input hostname.
 *
 *		Hostname set to the one provided on success (cleared
 *		when NULL). On allocation failure hostname is cleared. 
 *		On too long input failure, old hostname is unchanged.
 */
int ttls_set_hostname(ttls_context *ssl, const char *hostname);

/**
 * \brief	Set own certificate and key for the current handshake
 *
 * \note	Same as \c ttls_conf_own_cert() but for use within
 *		the SNI callback.
 *
 * \param ssl	SSL context
 * \param own_cert own public certificate chain
 * \param pk_key own private key
 *
 * \return	0 on success or TTLS_ERR_ALLOC_FAILED
 */
int ttls_set_hs_own_cert(ttls_context *ssl,
	ttls_x509_crt *own_cert,
	ttls_pk_context *pk_key);

/**
 * \brief	Set the data required to verify peer certificate for the
 *		current handshake
 *
 * \note	Same as \c ttls_conf_ca_chain() but for use within
 *		the SNI callback.
 *
 * \param ssl	SSL context
 * \param ca_chain trusted CA chain (meaning all fully trusted top-level CAs)
 * \param ca_crl trusted CA CRLs
 */
void ttls_set_hs_ca_chain(ttls_context *ssl,
	ttls_x509_crt *ca_chain,
	ttls_x509_crl *ca_crl);

/**
 * \brief	Set authmode for the current handshake.
 *
 * \note	Same as \c ttls_conf_authmode() but for use within
 *		the SNI callback.
 *
 * \param ssl	SSL context
 * \param authmode TTLS_VERIFY_NONE, TTLS_VERIFY_OPTIONAL or
 *		TTLS_VERIFY_REQUIRED
 */
void ttls_set_hs_authmode(ttls_context *ssl,
	int authmode);

/**
 * \brief	Set server side ServerName TLS extension callback
 *		(optional, server-side only).
 *
 *		If set, the ServerName callback is called whenever the
 *		server receives a ServerName TLS extension from the client
 *		during a handshake. The ServerName callback has the
 *		following parameters: (void *parameter, ttls_context *ssl,
 *		const unsigned char *hostname, size_t len). If a suitable
 *		certificate is found, the callback must set the
 *		certificate(s) and key(s) to use with \c
 *		ttls_set_hs_own_cert() (can be called repeatedly),
 *		and may optionally adjust the CA and associated CRL with \c
 *		ttls_set_hs_ca_chain() as well as the client
 *		authentication mode with \c ttls_set_hs_authmode(),
 *		then must return 0. If no matching name is found, the
 *		callback must either set a default cert, or
 *		return non-zero to abort the handshake at this point.
 *
 * \param conf	SSL configuration
 * \param f_sni	verification function
 * \param p_sni	verification parameter
 */
void ttls_conf_sni(ttls_config *conf,
	int (*f_sni)(void *, ttls_context *, const unsigned char *,
	size_t),
	void *p_sni);

/**
 * \brief	Set the supported Application Layer Protocols.
 *
 * \param conf	SSL configuration
 * \param protos Pointer to a NULL-terminated list of supported protocols,
 *		in decreasing preference order. The pointer to the list is
 *		recorded by the library for later reference as required, so
 *		the lifetime of the table must be atleast as long as the
 *		lifetime of the SSL configuration structure.
 *
 * \return	0 on success, or TTLS_ERR_BAD_INPUT_DATA.
 */
int ttls_conf_alpn_protocols(ttls_config *conf, const char **protos);

/**
 * \brief	Get the name of the negotiated Application Layer Protocol.
 *		This function should be called after the handshake is
 *		completed.
 *
 * \param ssl	SSL context
 *
 * \return	Protcol name, or NULL if no protocol was negotiated.
 */
const char *ttls_get_alpn_protocol(const ttls_context *ssl);

/**
 * \brief	Set the maximum supported version sent from the client side
 *		and/or accepted at the server side
 *		(Default: TTLS_MAX_MAJOR_VERSION, TTLS_MAX_MINOR_VERSION)
 *
 * \note	This ignores ciphersuites from higher versions.
 *
 * \note	With DTLS, use TTLS_MINOR_VERSION_2 for DTLS 1.0 and
 *		TTLS_MINOR_VERSION_3 for DTLS 1.2
 *
 * \param conf	SSL configuration
 * \param major	Major version number (only TTLS_MAJOR_VERSION_3 supported)
 * \param minor	Minor version number (TTLS_MINOR_VERSION_0,
 *		TTLS_MINOR_VERSION_1 and TTLS_MINOR_VERSION_2,
 *		TTLS_MINOR_VERSION_3 supported)
 */
void ttls_conf_max_version(ttls_config *conf, int major, int minor);

/**
 * \brief	Set the minimum accepted SSL/TLS protocol version
 *		(Default: TLS 1.0)
 *
 * \note	Input outside of the SSL_MAX_XXXXX_VERSION and
 *		SSL_MIN_XXXXX_VERSION range is ignored.
 *
 * \note	TTLS_MINOR_VERSION_0 (SSL v3) should be avoided.
 *
 * \note	With DTLS, use TTLS_MINOR_VERSION_2 for DTLS 1.0 and
 *		TTLS_MINOR_VERSION_3 for DTLS 1.2
 *
 * \param conf	SSL configuration
 * \param major	Major version number (only TTLS_MAJOR_VERSION_3 supported)
 * \param minor	Minor version number (TTLS_MINOR_VERSION_0,
 *		TTLS_MINOR_VERSION_1 and TTLS_MINOR_VERSION_2,
 *		TTLS_MINOR_VERSION_3 supported)
 */
void ttls_conf_min_version(ttls_config *conf, int major, int minor);

#if defined(TTLS_FALLBACK_SCSV) && defined(TTLS_CLI_C)
/**
 * \brief	Set the fallback flag (client-side only).
 *		(Default: TTLS_IS_NOT_FALLBACK).
 *
 * \note	Set to TTLS_IS_FALLBACK when preparing a fallback
 *		connection, that is a connection with max_version set to a
 *		lower value than the value you're willing to use. Such
 *		fallback connections are not recommended but are sometimes
 *		necessary to interoperate with buggy (version-intolerant)
 *		servers.
 *
 * \warning	You should NOT set this to TTLS_IS_FALLBACK for
 *		non-fallback connections! This would appear to work for a
 *		while, then cause failures when the server is upgraded to
 *		support a newer TLS version.
 *
 * \param conf	SSL configuration
 * \param fallback TTLS_IS_NOT_FALLBACK or TTLS_IS_FALLBACK
 */
void ttls_conf_fallback(ttls_config *conf, char fallback);
#endif /* TTLS_FALLBACK_SCSV && TTLS_CLI_C */

#if defined(TTLS_EXTENDED_MASTER_SECRET)
/**
 * \brief	Enable or disable Extended Master Secret negotiation.
 *		(Default: TTLS_EXTENDED_MS_ENABLED)
 *
 * \note	This should always be enabled, it is a security fix to the
 *		protocol, and should not cause any interoperability issue
 *		(used only if the peer supports it too).
 *
 * \param conf	SSL configuration
 * \param ems	TTLS_EXTENDED_MS_ENABLED or TTLS_EXTENDED_MS_DISABLED
 */
void ttls_conf_extended_master_secret(ttls_config *conf, char ems);
#endif /* TTLS_EXTENDED_MASTER_SECRET */

/**
 * \brief	Whether to send a list of acceptable CAs in
 *		CertificateRequest messages.
 *		(Default: do send)
 *
 * \param conf	SSL configuration
 * \param cert_req_ca_list TTLS_CERT_REQ_CA_LIST_ENABLED or
 *		TTLS_CERT_REQ_CA_LIST_DISABLED
 */
void ttls_conf_cert_req_ca_list(ttls_config *conf,
	char cert_req_ca_list);

#if defined(TTLS_MAX_FRAGMENT_LENGTH)
/**
 * \brief	Set the maximum fragment length to emit and/or negotiate
 *		(Default: TTLS_MAX_CONTENT_LEN, usually 2^14 bytes)
 *		(Server: set maximum fragment length to emit,
 *		usually negotiated by the client during handshake
 *		(Client: set maximum fragment length to emit *and*
 *		negotiate with the server during handshake)
 *
 * \param conf	SSL configuration
 * \param mfl_code Code for maximum fragment length (allowed values:
 *		TTLS_MAX_FRAG_LEN_512, TTLS_MAX_FRAG_LEN_1024,
 *		TTLS_MAX_FRAG_LEN_2048, TTLS_MAX_FRAG_LEN_4096)
 *
 * \return	0 if successful or TTLS_ERR_BAD_INPUT_DATA
 */
int ttls_conf_max_frag_len(ttls_config *conf, unsigned char mfl_code);
#endif /* TTLS_MAX_FRAGMENT_LENGTH */

#if defined(TTLS_SESSION_TICKETS) && defined(TTLS_CLI_C)
/**
 * \brief	Enable / Disable session tickets (client only).
 *		(Default: TTLS_SESSION_TICKETS_ENABLED.)
 *
 * \note	On server, use \c ttls_conf_session_tickets_cb().
 *
 * \param conf	SSL configuration
 * \param use_tickets Enable or disable (TTLS_SESSION_TICKETS_ENABLED or
 *		TTLS_SESSION_TICKETS_DISABLED)
 */
void ttls_conf_session_tickets(ttls_config *conf, int use_tickets);
#endif /* TTLS_SESSION_TICKETS && TTLS_CLI_C */

/**
 * \brief	Prevent or allow legacy renegotiation.
 *		(Default: TTLS_LEGACY_NO_RENEGOTIATION)
 *
 *		TTLS_LEGACY_NO_RENEGOTIATION allows connections to
 *		be established even if the peer does not support
 *		secure renegotiation, but does not allow renegotiation
 *		to take place if not secure.
 *		(Interoperable and secure option)
 *
 *		TTLS_LEGACY_ALLOW_RENEGOTIATION allows renegotiations
 *		with non-upgraded peers. Allowing legacy renegotiation
 *		makes the connection vulnerable to specific man in the
 *		middle attacks. (See RFC 5746)
 *		(Most interoperable and least secure option)
 *
 *		TTLS_LEGACY_BREAK_HANDSHAKE breaks off connections
 *		if peer does not support secure renegotiation. Results
 *		in interoperability issues with non-upgraded peers
 *		that do not support renegotiation altogether.
 *		(Most secure option, interoperability issues)
 *
 * \param conf	SSL configuration
 * \param allow_legacy Prevent or allow (SSL_NO_LEGACY_RENEGOTIATION,
 *		SSL_ALLOW_LEGACY_RENEGOTIATION or
 *		TTLS_LEGACY_BREAK_HANDSHAKE)
 */
void ttls_conf_legacy_renegotiation(ttls_config *conf, int allow_legacy);

/**
 * \brief	Return the result of the certificate verification
 *
 * \param ssl	SSL context
 *
 * \return	0 if successful,
 *		-1 if result is not available (eg because the handshake was
 *		aborted too early), or
 *		a combination of BADCERT_xxx and BADCRL_xxx flags, see
 *		x509.h
 */
uint32_t ttls_get_verify_result(const ttls_context *ssl);

/**
 * \brief	Return the name of the current ciphersuite
 *
 * \param ssl	SSL context
 *
 * \return	a string containing the ciphersuite name
 */
const char *ttls_get_ciphersuite(const ttls_context *ssl);

/**
 * \brief	Return the (maximum) number of bytes added by the record
 *		layer: header + encryption/MAC overhead (inc. padding)
 *
 * \param ssl	SSL context
 *
 * \return	Current maximum record expansion in bytes, or
 *		TTLS_ERR_FEATURE_UNAVAILABLE if compression is
 *		enabled, which makes expansion much less predictable
 */
int ttls_get_record_expansion(const ttls_context *ssl);

#if defined(TTLS_MAX_FRAGMENT_LENGTH)
/**
 * \brief	Return the maximum fragment length (payload, in bytes).
 *		This is the value negotiated with peer if any,
 *		or the locally configured value.
 *
 * \note	With DTLS, \c ttls_write() will return an error if
 *		called with a larger length value.
 *		With TLS, \c ttls_write() will fragment the input if
 *		necessary and return the number of bytes written; it is up
 *		to the caller to call \c ttls_write() again in
 *		order to send the remaining bytes if any.
 *
 * \param ssl	SSL context
 *
 * \return	Current maximum fragment length.
 */
size_t ttls_get_max_frag_len(const ttls_context *ssl);
#endif /* TTLS_MAX_FRAGMENT_LENGTH */

/**
 * \brief	Return the peer certificate from the current connection
 *
 *		Note: Can be NULL in case no certificate was sent during
 *		the handshake. Different calls for the same connection can
 *		return the same or different pointers for the same
 *		certificate and even a different certificate altogether.
 *		The peer cert CAN change in a single connection if
 *		renegotiation is performed.
 *
 * \param ssl	SSL context
 *
 * \return	the current peer certificate
 */
const ttls_x509_crt *ttls_get_peer_cert(const ttls_context *ssl);

#if defined(TTLS_CLI_C)
/**
 * \brief	Save session in order to resume it later (client-side only)
 *		Session data is copied to presented session structure.
 *
 * \warning	Currently, peer certificate is lost in the operation.
 *
 * \param ssl	SSL context
 * \param session session context
 *
 * \return	0 if successful,
 *		TTLS_ERR_ALLOC_FAILED if memory allocation failed,
 *		TTLS_ERR_BAD_INPUT_DATA if used server-side or
 *		arguments are otherwise invalid
 *
 * \sa	ttls_set_session()
 */
int ttls_get_session(const ttls_context *ssl, TtlsSess *session);
#endif /* TTLS_CLI_C */

int ttls_recv(void *tls_data, unsigned char *buf, size_t len,
	      unsigned int *read);
int ttls_encrypt_skb(TlsCtx *tls, struct sk_buff *skb);

int ttls_send_alert_msg(TlsCtx *tls, unsigned char lvl, unsigned char msg);

/**
 * \brief	Notify the peer that the connection is being closed
 *
 * \param ssl	SSL context
 *
 * \return	0 if successful, or a specific SSL error code.
 *
 * \note	If this function returns something other than 0 or
 *		TTLS_ERR_WANT_READ/WRITE, then the ssl context
 *		becomes unusable, and you should either free it or call
 *		\c ttls_session_reset() on it before re-using it for
 *		a new connection; the current connection must be closed.
 */
int ttls_close_notify(TlsCtx *ssl);

/**
 * \brief	Free referenced items in an SSL context and clear memory
 *
 * \param ssl	SSL context
 */
void ttls_free(ttls_context *ssl);

/**
 * \brief	Initialize an SSL configuration context
 *		Just makes the context ready for
 *		ttls_config_defaults() or ttls_config_free().
 *
 * \note	You need to call ttls_config_defaults() unless you
 *		manually set all of the relevent fields yourself.
 *
 * \param conf	SSL configuration context
 */
void ttls_config_init(ttls_config *conf);

/**
 * \brief	Load reasonnable default SSL configuration values.
 *		(You need to call ttls_config_init() first.)
 *
 * \param conf	SSL configuration context
 * \param endpoint TTLS_IS_CLIENT or TTLS_IS_SERVER
 * \param transport TTLS_TRANSPORT_STREAM for TLS, or
 *		TTLS_TRANSPORT_DATAGRAM for DTLS
 * \param preset a TTLS_PRESET_XXX value
 *
 * \note	See \c ttls_conf_transport() for notes on DTLS.
 *
 * \return	0 if successful, or
 *		TTLS_ERR_XXX_ALLOC_FAILED on memory allocation error.
 */
int ttls_config_defaults(ttls_config *conf,
	int endpoint, int transport, int preset);

/**
 * \brief	Free an SSL configuration context
 *
 * \param conf	SSL configuration context
 */
void ttls_config_free(ttls_config *conf);

/**
 * \brief	Initialize SSL session structure
 *
 * \param 	session SSL session
 */
void ttls_session_init(TtlsSess *session);

/**
 * \brief	Free referenced items in an SSL session including the
 *		peer certificate and clear memory
 *
 * \param session SSL session
 */
void ttls_session_free(TtlsSess *session);

#endif /* __TTLS_H__ */
