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

#include "config.h"
#include "bignum.h"
#include "ciphersuites.h"
#include "ecp.h"
#include "x509_crt.h"
#include "x509_crl.h"
#if defined(TTLS_DHM_C)
#include "dhm.h"
#endif
#include "ecdh.h"

/* The requested feature is not available. */
#define TTLS_ERR_FEATURE_UNAVAILABLE		-0x7080
/* Bad input parameters to function. */
#define TTLS_ERR_BAD_INPUT_DATA			-0x7100
/* Verification of the message MAC failed. */
#define TTLS_ERR_INVALID_MAC			-0x7180
/* An invalid SSL record was received. */
#define TTLS_ERR_INVALID_RECORD			-0x7200
/* The connection indicated an EOF. */
#define TTLS_ERR_CONN_EOF			-0x7280
/*
 * No client certification received from the client, but required by the
 * authentication mode.
 */
#define TTLS_ERR_NO_CLIENT_CERTIFICATE		-0x7480
/* Our own certificate(s) is/are too large to send in an SSL message. */
#define TTLS_ERR_CERTIFICATE_TOO_LARGE		-0x7500
/* The own certificate is not set, but needed by the server. */
#define TTLS_ERR_CERTIFICATE_REQUIRED		-0x7580
/* The own private key or pre-shared key is not set, but needed. */
#define TTLS_ERR_PRIVATE_KEY_REQUIRED		-0x7600
/* No CA Chain is set, but required to operate. */
#define TTLS_ERR_CA_CHAIN_REQUIRED		-0x7680
/* An unexpected message was received from our peer. */
#define TTLS_ERR_UNEXPECTED_MESSAGE		-0x7700
/* Processing of the ClientHello handshake message failed. */
#define TTLS_ERR_BAD_HS_CLIENT_HELLO		-0x7900
/* Processing of the ServerHello handshake message failed. */
#define TTLS_ERR_BAD_HS_SERVER_HELLO		-0x7980
/* Processing of the Certificate handshake message failed. */
#define TTLS_ERR_BAD_HS_CERTIFICATE		-0x7A00
/* Processing of the CertificateRequest handshake message failed. */
#define TTLS_ERR_BAD_HS_CERTIFICATE_REQUEST	-0x7A80
/* Processing of the ServerKeyExchange handshake message failed. */
#define TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE	-0x7B00
/* Processing of the ServerHelloDone handshake message failed. */
#define TTLS_ERR_BAD_HS_SERVER_HELLO_DONE	-0x7B80
/* Processing of the ClientKeyExchange handshake message failed. */
#define TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE	-0x7C00
/*
 * Processing of the ClientKeyExchange handshake message failed in
 * DHM / ECDH Read Public.
 */
#define TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_RP	-0x7C80
/*
 * Processing of the ClientKeyExchange handshake message failed in
 * DHM / ECDH Calculate Secret.
 */
#define TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_CS	-0x7D00
/* Processing of the CertificateVerify handshake message failed. */
#define TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY	-0x7D80
/* Processing of the ChangeCipherSpec handshake message failed. */
#define TTLS_ERR_BAD_HS_CHANGE_CIPHER_SPEC	-0x7E00
/* Processing of the Finished handshake message failed. */
#define TTLS_ERR_BAD_HS_FINISHED		-0x7E80
/* Memory allocation failed */
#define TTLS_ERR_ALLOC_FAILED			-0x7F00
/* Handshake protocol not within min/max boundaries */
#define TTLS_ERR_BAD_HS_PROTOCOL_VERSION	-0x6E80
/* Processing of the NewSessionTicket handshake message failed. */
#define TTLS_ERR_BAD_HS_NEW_SESSION_TICKET	-0x6E00
/* Session ticket has expired. */
#define TTLS_ERR_SESSION_TICKET_EXPIRED		-0x6D80
/* Internal error (eg, unexpected failure in lower-level module). */
#define TTLS_ERR_INTERNAL_ERROR			-0x6C00
/* A buffer is too small to receive or write a message. */
#define TTLS_ERR_BUFFER_TOO_SMALL		-0x6A00
/* Couldn't set the hash for verifying CertificateVerify. */
#define TTLS_ERR_INVALID_VERIFY_HASH		-0x6600

#define TTLS_IV_LEN				8 /* explicit IV size */
#define TTLS_ALERT_LEN				2

#define TTLS_MAJOR_VERSION_3			3
#define TTLS_MINOR_VERSION_0			0 /* SSL v3.0 */
#define TTLS_MINOR_VERSION_1			1 /* TLS v1.0 */
#define TTLS_MINOR_VERSION_2			2 /* TLS v1.1 */
#define TTLS_MINOR_VERSION_3			3 /* TLS v1.2 */
#define TTLS_MINOR_VERSION_4			4 /* TLS v1.3 */

/* Maximum host name defined in RFC 1035. */
#define TTLS_MAX_HOST_NAME_LEN			255

#define TTLS_IS_CLIENT				0
#define TTLS_IS_SERVER				1

#define TTLS_COMPRESS_NULL			0

#define TTLS_VERIFY_NONE			0
#define TTLS_VERIFY_OPTIONAL			1
#define TTLS_VERIFY_REQUIRED			2
/* Used only for sni_authmode */
#define TTLS_VERIFY_UNSET			3

#define TTLS_SESSION_TICKETS_DISABLED		0
#define TTLS_SESSION_TICKETS_ENABLED		1

#if !defined(TTLS_DEFAULT_TICKET_LIFETIME)
/* Lifetime of session tickets (if enabled) */
#define TTLS_DEFAULT_TICKET_LIFETIME		86400
#endif

/*
 * Signaling ciphersuite values (SCSV)
 */
/* Renegotiation info ext. */
#define TTLS_EMPTY_RENEGOTIATION_INFO		0xFF
/* RFC 7507 section 2. */
#define TTLS_FALLBACK_SCSV_VALUE		0x5600

/*
 * Supported Signature and Hash algorithms (For TLS 1.2)
 * RFC 5246 section 7.4.1.4.1
 */
#define TTLS_HASH_NONE				0
#define TTLS_HASH_SHA224			3
#define TTLS_HASH_SHA256			4
#define TTLS_HASH_SHA384			5
#define TTLS_HASH_SHA512			6

#define TTLS_SIG_ANON				0
#define TTLS_SIG_RSA				1
#define TTLS_SIG_ECDSA				3

/*
 * Client Certificate Types
 * RFC 5246 section 7.4.4 plus RFC 4492 section 5.5
 */
#define TTLS_CERT_TYPE_RSA_SIGN			1
#define TTLS_CERT_TYPE_ECDSA_SIGN		64

/*
 * Message, alert and handshake types
 */
#define TTLS_MSG_CHANGE_CIPHER_SPEC		20
#define TTLS_MSG_ALERT				21
#define TTLS_MSG_HANDSHAKE			22
#define TTLS_MSG_APPLICATION_DATA		23

#define TTLS_ALERT_LEVEL_WARNING		1
#define TTLS_ALERT_LEVEL_FATAL			2

#define TTLS_ALERT_MSG_CLOSE_NOTIFY		0 /* 0x00 */
#define TTLS_ALERT_MSG_UNEXPECTED_MESSAGE	10 /* 0x0A */
#define TTLS_ALERT_MSG_BAD_RECORD_MAC		20 /* 0x14 */
#define TTLS_ALERT_MSG_DECRYPTION_FAILED	21 /* 0x15 */
#define TTLS_ALERT_MSG_RECORD_OVERFLOW		22 /* 0x16 */
#define TTLS_ALERT_MSG_DECOMPRESSION_FAILURE	30 /* 0x1E */
#define TTLS_ALERT_MSG_HANDSHAKE_FAILURE	40 /* 0x28 */
#define TTLS_ALERT_MSG_NO_CERT			41 /* 0x29 */
#define TTLS_ALERT_MSG_BAD_CERT			42 /* 0x2A */
#define TTLS_ALERT_MSG_UNSUPPORTED_CERT		43 /* 0x2B */
#define TTLS_ALERT_MSG_CERT_REVOKED		44 /* 0x2C */
#define TTLS_ALERT_MSG_CERT_EXPIRED		45 /* 0x2D */
#define TTLS_ALERT_MSG_CERT_UNKNOWN		46 /* 0x2E */
#define TTLS_ALERT_MSG_ILLEGAL_PARAMETER	47 /* 0x2F */
#define TTLS_ALERT_MSG_UNKNOWN_CA		48 /* 0x30 */
#define TTLS_ALERT_MSG_ACCESS_DENIED		49 /* 0x31 */
#define TTLS_ALERT_MSG_DECODE_ERROR		50 /* 0x32 */
#define TTLS_ALERT_MSG_DECRYPT_ERROR		51 /* 0x33 */
#define TTLS_ALERT_MSG_EXPORT_RESTRICTION	60 /* 0x3C */
#define TTLS_ALERT_MSG_PROTOCOL_VERSION		70 /* 0x46 */
#define TTLS_ALERT_MSG_INSUFFICIENT_SECURITY	71 /* 0x47 */
#define TTLS_ALERT_MSG_INTERNAL_ERROR		80 /* 0x50 */
#define TTLS_ALERT_MSG_INAPROPRIATE_FALLBACK	86 /* 0x56 */
#define TTLS_ALERT_MSG_USER_CANCELED		90 /* 0x5A */
#define TTLS_ALERT_MSG_NO_RENEGOTIATION		100 /* 0x64 */
#define TTLS_ALERT_MSG_UNSUPPORTED_EXT		110 /* 0x6E */
#define TTLS_ALERT_MSG_UNRECOGNIZED_NAME	112 /* 0x70 */
#define TTLS_ALERT_MSG_UNKNOWN_PSK_IDENTITY	115 /* 0x73 */
#define TTLS_ALERT_MSG_NO_APPLICATION_PROTOCOL	120 /* 0x78 */

#define TTLS_HS_HELLO_REQUEST			0
#define TTLS_HS_CLIENT_HELLO			1
#define TTLS_HS_SERVER_HELLO			2
#define TTLS_HS_HELLO_VERIFY_REQUEST		3
#define TTLS_HS_NEW_SESSION_TICKET		4
#define TTLS_HS_CERTIFICATE			11
#define TTLS_HS_SERVER_KEY_EXCHANGE		12
#define TTLS_HS_CERTIFICATE_REQUEST		13
#define TTLS_HS_SERVER_HELLO_DONE		14
#define TTLS_HS_CERTIFICATE_VERIFY		15
#define TTLS_HS_CLIENT_KEY_EXCHANGE		16
#define TTLS_HS_FINISHED			20
#define TTLS_HS_INVALID				0xff

/*
 * TLS extensions.
 * Do not support Encrypt-then-Mac since we don't support CBC modes.
 */
#define TTLS_TLS_EXT_SERVERNAME			0
#define TTLS_TLS_EXT_SERVERNAME_HOSTNAME	0
#define TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH	1
#define TTLS_TLS_EXT_TRUNCATED_HMAC		4
#define TTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES	10
#define TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS	11
#define TTLS_TLS_EXT_SIG_ALG			13
#define TTLS_TLS_EXT_ALPN			16
#define TTLS_TLS_EXT_EXTENDED_MASTER_SECRET	23
#define TTLS_TLS_EXT_SESSION_TICKET		35
#define TTLS_TLS_EXT_RENEGOTIATION_INFO		0xFF01

/* Dummy type used only for its size */
union ttls_premaster_secret
{
	unsigned char _pms_rsa[48];			/* RFC 5246 8.1.1 */
	unsigned char _pms_dhm[TTLS_MPI_MAX_SIZE];	/* RFC 5246 8.1.2 */
	unsigned char _pms_ecdh[TTLS_ECP_MAX_BYTES];	/* RFC 4492 5.10 */
};

#define TTLS_PREMASTER_SIZE	sizeof(union ttls_premaster_secret)
#define TTLS_HS_RBUF_SZ		TTLS_PREMASTER_SIZE

/* Defined below */
typedef struct ttls_context ttls_context;
typedef struct ttls_config ttls_config;

/* Defined in tls_internal.h */
typedef struct TtlsXfrm ttls_transform;
typedef struct ttls_handshake_params ttls_handshake_params;
typedef struct ttls_sig_hash_set_t ttls_sig_hash_set_t;
typedef struct ttls_key_cert ttls_key_cert;

/*
 * This structure is used for storing current session data.
 *
 * @start		- starting time;
 * @id_len		- session id length;
 * @peer_cert		- peer X.509 cert chain;
 * @ciphersuite		- chosen ciphersuite;
 * @etm			- flag for Encrypt-then-MAC activation;
 * @verify_result	- verification result;
 * @id			- session identifier;
 * @master		- the master secret;
 */
typedef struct {
	ttls_x509_crt	*peer_cert;
	time_t		start;
	int		etm;
	uint32_t	verify_result;
	unsigned short	ciphersuite;
	unsigned char	id_len;
	unsigned char	id[32];
	unsigned char	master[48];
#if defined(TTLS_CLI_C)
	unsigned char *ticket;	/*!< RFC 5077 session ticket */
	size_t ticket_len;	/*!< session ticket length */
	uint32_t ticket_lifetime; /*!< ticket lifetime hint	*/
#endif /* TTLS_SESSION_TICKETS && TTLS_CLI_C */
} TlsSess;

/*
 * Session specific crypto layer.
 *
 * This structure contains a full set of runtime transform parameters
 * either in negotiation or active.
 *
 * @ciphersuite_info	- chosen cipersuite_info;
 * @md_ctx_enc		- MAC encryption context;
 * @md_ctx_dec		- MAC decryption context;
 * @cipher_ctx_enc	- encryption crypto context;
 * @cipher_ctx_dec	- decryption crypto context;
 * @keylen		- symmetric key length (bytes);
 * @minlen		- min. ciphertext length;
 * @ivlen		- IV length;
 * @fixed_ivlen		- fixed part of IV (AEAD);
 * @maclen		- MAC length;
 * @iv_enc		- IV for encryption;
 * @iv_dec		- IV for decryption;
 */
typedef struct {
	const TlsCiphersuite	*ciphersuite_info;
	TlsMdCtx			md_ctx_enc;
	TlsMdCtx			md_ctx_dec;
	TlsCipherCtx			cipher_ctx_enc;
	TlsCipherCtx			cipher_ctx_dec;
	unsigned int			keylen;
	unsigned int			minlen;
	unsigned char			ivlen;
	unsigned char			fixed_ivlen;
	unsigned char			maclen;
	unsigned char			iv_enc[16];
	unsigned char			iv_dec[16];
} TlsXfrm;

/**
 * SSL/TLS configuration to be shared between ttls_context structures.
 *
 * @min_minor_ver	- minimum allowed minor version;
 * @max_minor_ver	- always 3 for now, and used for SCSV fallbacks only.
 *			  Preserved for TLS 1.3.
 */
struct ttls_config
{
	/* Group items by size (largest first) to minimize padding overhead */

	const int *ciphersuite_list[4]; /*!< allowed ciphersuites per version */

	/** Callback to retrieve a session from the cache	*/
	int (*f_get_cache)(void *, TlsSess *);
	/** Callback to store a session into the cache	*/
	int (*f_set_cache)(void *, const TlsSess *);
	void *p_cache;	/*!< context for cache callbacks	*/

	/** Callback for setting cert according to SNI extension	*/
	int (*f_sni)(void *, ttls_context *, const unsigned char *, size_t);
	void *p_sni;	/*!< context for SNI callback	*/
	/** Callback to customize X.509 certificate chain verification	*/
	int (*f_vrfy)(void *, ttls_x509_crt *, int, uint32_t *);
	void *p_vrfy;	/*!< context for X.509 verify calllback */

	/** Callback to create & write a session ticket	*/
	int (*f_ticket_write)(void *, const TlsSess *,
	unsigned char *, const unsigned char *, size_t *, uint32_t *);
	/** Callback to parse a session ticket into a session structure	*/
	int (*f_ticket_parse)(void *, TlsSess *, unsigned char *, size_t);
	void *p_ticket;	/*!< context for the ticket callbacks */

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

#if defined(TTLS_DHM_C) && defined(TTLS_CLI_C)
	unsigned int dhm_min_bitlen;	/*!< min. bit length of the DHM prime */
#endif

	unsigned char	min_minor_ver;
	unsigned char	max_minor_ver;

	/*
	* Flags (bitfields)
	*/

	unsigned int endpoint : 1;	/*!< 0: client, 1: server	*/
	unsigned int authmode : 2;	/*!< TTLS_VERIFY_XXX	*/
	unsigned int session_tickets : 1; /*!< use session tickets?	*/
	unsigned int cert_req_ca_list : 1; /*!< enable sending CA list in
	Certificate Request messages?	*/
};

/* I/O state flags. */
#define TTLS_F_ST_HDRIV		1 /* header [and IV] parsed */

/**
 * I/O context for a TLS context.
 *
 * @ctr		- 64-bit egress message counter maintained by us;
 * @__initoff	- per message offset to reinitialize the I/O context;
 * @hdr		- TLS message header;
 * @iv		- TLS message initialization vector (@ctr value);
 * @hdr_cpsz	- how many bytes are copied to a header;
 * @st_flags	- state flags;
 * @aad_buf	- temporary buffers for associated authentication data;
 * @msgtype	- record header: message type;
 * @hstype	- record header: handhsake type;
 * @msglen	- record header: message length;
 * @hslen	- current handshake message length, including the handshake
 *		  header. For egress data used as length of @__msg (copied
 *		  data);
 * @rlen	- read bytes of the message body so far;
 * @skb_list	- list of skbs attached to the current I/O context;
 * @off		- data offset within @skb_list, can be after the 1st skb;
 * @chunks	- number of contiguous memory chunks in all skbs in @skb_list;
 */
typedef struct {
	unsigned long	ctr;
	char		__initoff[0];
	unsigned char	hdr[TLS_HEADER_SIZE];
	union {
		unsigned char	__msg[16];
		unsigned char	iv[TTLS_IV_LEN];
		unsigned char	alert[TTLS_ALERT_LEN];
		unsigned char	hs_hdr[4];
	};
	unsigned char	hdr_cpsz;
	unsigned char	st_flags;
	unsigned char	msgtype;
	unsigned char	hstype;
	unsigned short	msglen;
	unsigned short	hslen;
	unsigned short	rlen;
	struct sk_buff	*skb_list;
	unsigned int	off;
	unsigned int	chunks;
} TlsIOCtx;

/* Declarations of internal TLS data structures. */
typedef struct tls_handshake_t TlsHandshake;

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
 * @alpn_chosen	- negotiated protocol;
 * @state	- TLS handshake: current TLS FSM state;
 * @major	- the context TLS major version, currently equal to
 *		  TTLS_MAJOR_VERSION_3;
 * @minor	- currently equal to 3 (TLS 1.2), 4 (TLS 1.3) is possible in
 *		  future;
 * @io_{in,out}	- I/O contexts for ingress and egress messages correspondingly;
 * @sess	- session data;
 * @xfrm	- transform params;
 * @nb_zero	-  # of 0-length encrypted messages;
 */
typedef struct ttls_context {
	spinlock_t		lock;
	const ttls_config	*conf;
	TlsHandshake		*hs;
	const char		*alpn_chosen;

	unsigned int		state;
	unsigned char		major;
	unsigned char		minor;

	TlsIOCtx		io_in;
	TlsIOCtx		io_out;
	TlsSess			sess;
	TlsXfrm			xfrm;

	unsigned int		nb_zero;

	/*
	* PKI layer
	*/
	int client_auth;	/*!< flag for client auth. */

	/*
	* User settings
	*/
	char *hostname;	/*!< expected peer CN for verification
	(and SNI if available)	*/
} TlsCtx;

typedef int ttls_send_cb_t(TlsCtx *tls, struct sg_table *sgt, bool close);

bool ttls_xfrm_ready(TlsCtx *tls);
void ttls_write_hshdr(unsigned char type, unsigned char *buf,
		      unsigned short len);
void *ttls_alloc_crypto_req(unsigned int extra_size, unsigned int *rsz);
void ttls_register_bio(ttls_send_cb_t *send_cb);

const char *ttls_get_ciphersuite_name(const int ciphersuite_id);

int ttls_ctx_init(TlsCtx *tls, const ttls_config *conf);

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
	const TlsSess *session,
	unsigned char *start,
	const unsigned char *end,
	size_t *tlen,
	uint32_t *lifetime);

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
typedef int ttls_ticket_parse_t(void *p_ticket, TlsSess *session,
				unsigned char *buf, size_t len);

/**
 * \brief	Configure SSL session ticket callbacks (server only).
 *		(Default: none.)
 *
 * \note	On server, session tickets are enabled by providing
 *		non-NULL callbacks.
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
int ttls_set_session(ttls_context *ssl, const TlsSess *session);
#endif /* TTLS_CLI_C */

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
 * \param minor	Minor version number (TTLS_MINOR_VERSION_3 and
 *  			TTLS_MINOR_VERSION_2 supported)
 */
void ttls_conf_ciphersuites_for_version(ttls_config *conf,
					const int *ciphersuites, int minor);

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
 *		advertised capabilities. In case multiple certificates are
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
 *		ciphersuite, see \c ttls_conf_ciphersuites_for_version(). Hashes
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
void ttls_conf_sig_hashes(ttls_config *conf, const int *hashes);

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
int ttls_set_hs_own_cert(ttls_context *ssl, ttls_x509_crt *own_cert,
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
void ttls_set_hs_ca_chain(ttls_context *ssl, ttls_x509_crt *ca_chain,
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
void ttls_set_hs_authmode(ttls_context *ssl, int authmode);

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
 * \return	Protocol name, or NULL if no protocol was negotiated.
 */
const char *ttls_get_alpn_protocol(const ttls_context *ssl);

void ttls_conf_version(ttls_config *conf, int min_minor, int max_minor);

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
int ttls_get_session(const ttls_context *ssl, TlsSess *session);
#endif /* TTLS_CLI_C */

int ttls_recv(void *tls_data, unsigned char *buf, size_t len,
	      unsigned int *read);
int ttls_encrypt(TlsCtx *tls, struct sg_table *sgt);

int ttls_send_alert(TlsCtx *tls, unsigned char lvl, unsigned char msg);

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

void ttls_ctx_clear(ttls_context *ssl);

void ttls_config_init(ttls_config *conf);
int ttls_config_defaults(ttls_config *conf, int endpoint);
void ttls_config_free(ttls_config *conf);

void ttls_strerror(int errnum, char *buffer, size_t buflen);

void ttls_aad2hdriv(TlsXfrm *xfrm, unsigned char *buf);

static inline unsigned char
ttls_xfrm_taglen(const TlsXfrm *xfrm)
{
	return xfrm->ciphersuite_info->flags & TTLS_CIPHERSUITE_SHORT_TAG
		? 8 : 16;
}

static inline size_t
ttls_expiv_len(const TlsXfrm *xfrm)
{
	BUG_ON(xfrm->ivlen - xfrm->fixed_ivlen != TTLS_IV_LEN);
	return xfrm->ivlen - xfrm->fixed_ivlen;
}

static inline size_t
ttls_payload_off(const TlsXfrm *xfrm)
{
	return TLS_HEADER_SIZE + ttls_expiv_len(xfrm);
}

#endif /* __TTLS_H__ */
