/*
 *		Tempesta TLS
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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

#include "bignum.h"
#include "ciphersuites.h"
#include "ecp.h"
#include "x509_crt.h"
#include "x509_crl.h"
#include "dhm.h"
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

/* Lifetime of session tickets (if enabled) */
#define TTLS_DEFAULT_TICKET_LIFETIME		86400

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

/*
 * Supported protocols for APLN extension. Currently only two
 * protocols for ALPN are supported: HTTP/1.1 and HTTP/2.
 * NOTE: according RFC 7301 3.1 the length of each protocol's name
 * must be not greater than 255 and the total length of all names
 * in the list must not exceed 65535.
 */
#define TTLS_ALPN_HTTP1				"http/1.1"
#define TTLS_ALPN_HTTP2				"h2"

/* Number of protocols for negotiation in APLN extension. */
#define TTLS_ALPN_PROTOS			1

/* The id numbers of supported protocols for APLN extension. */
typedef enum {
	TTLS_ALPN_ID_HTTP1,
	TTLS_ALPN_ID_HTTP2
} ttls_alpn_proto_id;

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
typedef struct ttls_alpn_proto ttls_alpn_proto;
typedef struct ttls_context ttls_context;

/* Defined in tls_internal.h */
typedef struct ttls_key_cert ttls_key_cert;

/*
 * ALPN protocol descriptor.
 *
 * @name		- protocol name;
 * @len			- length of @name string;
 * @id			- protocol's internal number;
 */
struct ttls_alpn_proto {
	const char *name;
	unsigned int len;
	int id;
};

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
 * @ticket		- RFC 5077 session ticket (client-only);
 * @ticket_len		- session ticket length (client-only);
 * @ticket_lifetime	- ticket lifetime hint (client-only);
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
	unsigned char	*ticket;
	size_t		ticket_len;
	uint32_t	ticket_lifetime;
} TlsSess;

/*
 * Session specific crypto layer.
 *
 * This structure contains a full set of runtime transform parameters
 * either in negotiation or active.
 *
 * @ciphersuite_info	- chosen ciphersuite_info;
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
 * Peer TLS configuration. Each virtual server (vhost) inside Tempesta
 * may have its own settings and limitations.
 *
 * @ciphersuite_list	- Allowed ciphersuites per TLS version;
 * @key_cert		- Own certificate/key list;
 * @priv		- Private section, used for configuration storing;
 * @min_minor_ver	- Minimum supported TLS version;
 * @max_minor_ver	- Maximum supported TLS version;
 *
 * @endpoint		- Peer type: 0: client, 1: server;
 * @authmode		- TTLS_VERIFY_XXX;
 * @cert_req_ca_list	- Enable sending CA list in Certificate Request messages;
 *
 * The structure is to be populated by more fields from the TlsCfg, arrange
 * them by size to reduce padding overhead.
 */
typedef struct {
	const int			*ciphersuite_list[4];
	ttls_key_cert			*key_cert;
	void				*priv;

	unsigned char			min_minor_ver;
	unsigned char			max_minor_ver;

	unsigned int			endpoint : 1;
	unsigned int			authmode : 2;
	unsigned int			cert_req_ca_list : 1;
} TlsPeerCfg;

/**
 * Global TLS configuration to be shared between all vhosts and to be used in
 * ttls_context structures.
 *
 * @f_sni		- Callback for setting cert according to SNI extension;
 * @p_sni		- Context for SNI callback;
 * @f_vrfy		- Callback to customize X.509 certificate chain
 *			  verification;
 * @p_vrfy		- Context for X.509 verify callback;
 *
 * @f_ticket_write	- Callback to create & write a session ticket;
 * @f_ticket_parse	- Callback to parse a session ticket into a session
 *			  structure;
 * @p_ticket		- Context for the ticket callbacks;
 *
 * @dhm_P		- prime modulus for DHM;
 * @dhm_G		- generator for DHM;
 *
 * @alpn_list		- Ordered list of protocols;
 * @read_timeout	- timeout for ttls_recv (ms);
 *
 * @min_minor_ver	- minimum allowed minor version;
 * @max_minor_ver	- always 3 for now, and used for SCSV fallbacks only.
 *			  Preserved for TLS 1.3.
 *
 * @dhm_min_bitlen	- Minimum bit length of the DHM prime;
 *
 * @endpoint		- Peer type: 0: client, 1: server;
 * @authmode		- TTLS_VERIFY_XXX;
 * @cert_req_ca_list	- Enable sending CA list in Certificate Request messages;
 *
 * Members are grouped by size (largest first) to minimize padding overhead.
 */
typedef struct
{
	int (*f_sni)(void *, ttls_context *, const unsigned char *, size_t);
	void *p_sni;
	int (*f_vrfy)(void *, ttls_x509_crt *, int, uint32_t *);
	void *p_vrfy;
	int (*f_ticket_write)(void *, const TlsSess *,
	unsigned char *, const unsigned char *, size_t *, uint32_t *);
	int (*f_ticket_parse)(void *, TlsSess *, unsigned char *, size_t);
	void *p_ticket;

	TlsMpi				dhm_P;
	TlsMpi				dhm_G;
	const ttls_alpn_proto		*alpn_list;

	uint32_t			read_timeout;
	unsigned char			min_minor_ver;
	unsigned char			max_minor_ver;
	unsigned int			dhm_min_bitlen;
	unsigned int			endpoint : 1;
	unsigned int			authmode : 2;
	unsigned int			cert_req_ca_list : 1;
} TlsCfg;

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
	const TlsCfg		*conf;
	const TlsPeerCfg	*peer_conf;
	TlsHandshake		*hs;
	const ttls_alpn_proto	*alpn_chosen;

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
bool ttls_xfrm_need_encrypt(TlsCtx *tls);
void ttls_write_hshdr(unsigned char type, unsigned char *buf,
		      unsigned short len);
void *ttls_alloc_crypto_req(unsigned int extra_size, unsigned int *rsz);
void ttls_register_bio(ttls_send_cb_t *send_cb);

const char *ttls_get_ciphersuite_name(const int ciphersuite_id);

int ttls_ctx_init(TlsCtx *tls, const TlsCfg *conf);

void ttls_conf_authmode(TlsCfg *conf, int authmode);

typedef int ttls_ticket_write_t(void *p_ticket, const TlsSess *session,
				unsigned char *start, const unsigned char *end,
				size_t *tlen, uint32_t *lifetime);

typedef int ttls_ticket_parse_t(void *p_ticket, TlsSess *session,
				unsigned char *buf, size_t len);

void ttls_conf_session_tickets_cb(TlsCfg *conf,
				  ttls_ticket_write_t *f_ticket_write,
				  ttls_ticket_parse_t *f_ticket_parse,
				  void *p_ticket);
int ttls_set_session(ttls_context *ssl, const TlsSess *session);

int ttls_conf_own_cert(TlsPeerCfg *conf, ttls_x509_crt *own_cert,
		       ttls_pk_context *pk_key, ttls_x509_crt *ca_chain,
		       ttls_x509_crl *ca_crl);

int ttls_conf_dh_param_bin(TlsCfg *conf,
			   const unsigned char *dhm_P, size_t P_len,
			   const unsigned char *dhm_G, size_t G_len);
int ttls_conf_dh_param_ctx(TlsCfg *conf, ttls_dhm_context *dhm_ctx);
void ttls_conf_dhm_min_bitlen(TlsCfg *conf,
			      unsigned int bitlen);

int ttls_set_hostname(ttls_context *ssl, const char *hostname);
void ttls_set_hs_authmode(ttls_context *ssl, int authmode);
void ttls_conf_sni(TlsCfg *conf,
		   int (*f_sni)(void *, ttls_context *, const unsigned char *,
				size_t),
		   void *p_sni);
const char *ttls_get_alpn_protocol(const ttls_context *ssl);
void ttls_conf_version(TlsCfg *conf, int min_minor, int max_minor);

int ttls_get_session(const ttls_context *ssl, TlsSess *session);

int ttls_recv(void *tls_data, unsigned char *buf, size_t len,
	      unsigned int *read);
int ttls_encrypt(TlsCtx *tls, struct sg_table *sgt, struct sg_table *out_sgt);

int ttls_send_alert(TlsCtx *tls, unsigned char lvl, unsigned char msg);
int ttls_close_notify(TlsCtx *tls);

void ttls_ctx_clear(ttls_context *tls);
void ttls_key_cert_free(ttls_key_cert *key_cert);

void ttls_config_init(TlsCfg *conf);
int ttls_config_defaults(TlsCfg *conf, int endpoint);
int ttls_config_peer_defaults(TlsPeerCfg *conf, int endpoint);
void ttls_config_free(TlsCfg *conf);
void ttls_config_peer_free(TlsPeerCfg *conf);

void ttls_strerror(int errnum, char *buffer, size_t buflen);

void ttls_aad2hdriv(TlsXfrm *xfrm, unsigned char *buf);

bool ttls_alpn_ext_eq(const ttls_alpn_proto *proto, const unsigned char *buf,
		      size_t len);

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
