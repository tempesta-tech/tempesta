/*
 *		Tempesta TLS
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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
#include <linux/timer.h>
#include <net/tls.h>

#include "lib/str.h"
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
#define TTLS_DEFAULT_TICKET_LIFETIME		3600

/*
 * Signaling ciphersuite values (SCSV)
 */
/* Renegotiation info ext. */
#define TTLS_EMPTY_RENEGOTIATION_INFO		0xFF
/* RFC 7507 section 2. */
#define TTLS_FALLBACK_SCSV_VALUE		0x5600

/*
 * Supported Signature and Hash algorithms (For TLS 1.2)
 * RFC 5246 section 7.4.1.4.1.
 * SHA 224 isn't here as weak.
 */
#define TTLS_HASH_NONE				0
#define TTLS_HASH_SHA256			4
#define TTLS_HASH_SHA384			5
#define TTLS_HASH_SHA512			6

#define TTLS_SIG_ANON				0
#define TTLS_SIG_RSA				1
#define TTLS_SIG_ECDSA				3

/*
 * Client Certificate Types
 * RFC 5246 section 7.4.4 and RFC 8422 5.5: ecdsa_sign(64) is only allowed.
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

/*
 * Defined as the maximum of:
 * 1. RSA pre-master secret RFC 5246 8.1.1 (48 bytes);
 * 2. Maximum ECP size (48 bytes for 384-bit curve).
 * 3. Maximum MPI size for DHM by RFC 5246 8.1.2.
 */
#define TTLS_PREMASTER_SIZE	512
#define TTLS_HS_RBUF_SZ		TTLS_PREMASTER_SIZE

/* Defined below */
typedef struct ttls_alpn_proto ttls_alpn_proto;

/*
 * ALPN protocol descriptor.
 *
 * @name		- protocol name;
 * @len			- length of @name string;
 * @id			- protocol's internal number;
 */
struct ttls_alpn_proto {
	const char	*name;
	unsigned int	len;
	int		id;
};

#define TTLS_SESS_ID_LEN	32
#define TTLS_SESS_SECRET_LEN	48
/**
 * This structure is used for storing current session data.
 *
 * @peer_cert		- peer X.509 cert chain;
 * @start		- starting time;
 * @etm			- flag for Encrypt-then-MAC activation;
 * @verify_result	- verification result;
 * @ciphersuite		- chosen ciphersuite;
 * @id_len		- session id length;
 * @id			- session identifier;
 * @master		- the master secret (must be here to restore a session
 *			  from TLS ticket);
 */
typedef struct {
	TlsX509Crt	*peer_cert;
	time_t		start;
	int		etm;
	uint32_t	verify_result;
	unsigned short	ciphersuite;
	unsigned char	id_len;
	unsigned char	id[TTLS_SESS_ID_LEN];
	unsigned char	master[48];
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
	const TlsCiphersuite		*ciphersuite_info;
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
 * List of certificate + private key pairs
 *
 * @cert		- Server certificate;
 * @key			- private key for the certificate;
 * @ca_chain		- trusted CA chain for the issues certificate;
 * @ca_crl		- trusted CAs CRLs;
 * @next		- next certificate in list;
 */
typedef struct ttls_key_cert {
	TlsX509Crt			*cert;
	TlsPkCtx			*key;
	TlsX509Crt			*ca_chain;
	ttls_x509_crl			*ca_crl;
	struct ttls_key_cert		*next;
} TlsKeyCert;

#define TTLS_TICKET_KEY_LEN		16 /* 128 bits */
#define TTLS_TICKET_KEY_NAME_LEN	16
#define TTLS_TICKET_MAX_SZ		512

/**
 * Ticket key - single key used to protect TLS session tickets.
 *
 * @name		- key name, pseudo random number unique
 *			  for every virtual server, depends on SNI value,
 *			  used as index in key hash table;
 * @ts			- key generation time, round up to minutes or hours,
 *			  depends to key lifetime;
 * @key			- key for TLS ticket opaque part;
 * @lock		- usage lock for encrypt and key update operations;
 */
typedef struct {
	unsigned char		name[TTLS_TICKET_KEY_NAME_LEN];
	unsigned long		ts;
	unsigned char		key[TTLS_TICKET_KEY_LEN];
	rwlock_t		lock;
} TlsTicketKey;

/**
 * Peer session ticket configuration: set of active and outdated keys and
 * necessary information for secure key rotation.
 *
 * @keys		- Active and outdated keys;
 * @active_key		- Currently active key;
 * @key_lock		- Lock for key use/update operations;
 * @lifetime		- Session ticket (and keys) lifetime;
 * @secret		- User-defined secret for secure key rotation, stored
 *			  as hmac to provide better entropy and fixed size;
 * @timer		- key update timer.
 *
 * Since multiple Tempesta nodes can use the same configuration and share
 * Tickets between the nodes, all keys must be updated at any time, lazy key
 * renewal during handshake processing sounds good, but it prevent to load
 * tickets generated by foreign node while local keys wasn't updated for a long
 * time.
 */
typedef struct {
	TlsTicketKey		keys[2];
	unsigned char		active_key;
	rwlock_t		key_lock;
	unsigned long		lifetime;
	unsigned char		secret[TTLS_TICKET_KEY_LEN];
	struct timer_list	timer;
} TlsTicketPeerCfg;

/**
 * TLS Session ticket context.
 *
 * Unlike other extensions, ticket can't be parsed immediately, instead it's
 * required to know about target SNI first.
 *
 * @t_len			- ticket length;
 * @ticket			- ticket data, sent by client;
 */
typedef struct {
	size_t			t_len;
	char			ticket[TTLS_TICKET_MAX_SZ];
} TlSTicketCtx;

/**
 * Peer TLS configuration. Each virtual server (vhost) inside Tempesta
 * may have its own settings and limitations.
 *
 * @ciphersuite_list	- Allowed ciphersuites per TLS version;
 *			  TODO #1031: reduce the list.
 * @tickets		- Session tickets configuration;
 * @key_cert		- Own certificate/key list;
 * @priv		- Private section, used for configuration storing;
 * @min_minor_ver	- Minimum supported TLS version;
 * @max_minor_ver	- Maximum supported TLS version;
 *
 * @endpoint		- Peer type: 0: client, 1: server;
 * @authmode		- TTLS_VERIFY_XXX;
 * @cert_req_ca_list	- Enable sending CA list in Certificate Request messages;
 * @sess_tickets	- Enable session tickets (RFC 5077);
 *
 * The structure is to be populated by more fields from the TlsCfg, arrange
 * them by size to reduce padding overhead.
 */
typedef struct {
	const int			*ciphersuite_list[4];
	TlsTicketPeerCfg		tickets;
	TlsKeyCert			*key_cert;
	void				*priv;

	unsigned char			min_minor_ver;
	unsigned char			max_minor_ver;

	unsigned int			endpoint : 1;
	unsigned int			authmode : 2;
	unsigned int			cert_req_ca_list : 1;
	unsigned int			sess_tickets : 1;
} TlsPeerCfg;

/**
 * Global TLS configuration to be shared between all vhosts and to be used in
 * TlsCtx structures.
 *
 * @alpn_list		- Ordered list of protocols;
 * @read_timeout	- timeout for ttls_recv (ms);
 * @dhm_min_bitlen	- Minimum bit length of the DHM prime;
 * @endpoint		- Peer type: 0: client, 1: server;
 * @authmode		- TTLS_VERIFY_XXX;
 * @cert_req_ca_list	- Enable sending CA list in Certificate Request messages;
 * @min_minor_ver	- minimum allowed minor version;
 * @max_minor_ver	- always 3 for now, and used for SCSV fallbacks only.
 *			  Preserved for TLS 1.3.
 *
 * Members are grouped by size (largest first) to minimize padding overhead.
 */
typedef struct {
	const ttls_alpn_proto		*alpn_list;
	uint32_t			read_timeout;
	unsigned int			dhm_min_bitlen;
	unsigned int			endpoint : 1;
	unsigned int			authmode : 2;
	unsigned int			cert_req_ca_list : 1;
	unsigned char			min_minor_ver;
	unsigned char			max_minor_ver;
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
 * @peer_conf	- Vhost specific TLS configuration;
 * @hs		- params required only during the handshake process;
 * @alpn_chosen	- negotiated protocol;
 * @state	- TLS handshake: current TLS FSM state;
 * @io_{in,out}	- I/O contexts for ingress and egress messages correspondingly;
 * @sess	- session data;
 * @xfrm	- transform params;
 * @sni_hash	- hash of requested server names;
 * @nb_zero	-  # of 0-length encrypted messages;
 * @client_auth	- flag for client authentication (client side only);
 * @hostname	- expected peer CN for verification (and SNI if available);
 */
typedef struct ttls_context {
	spinlock_t		lock;
	const TlsCfg		*conf;
	TlsPeerCfg		*peer_conf;
	TlsHandshake		*hs;
	const ttls_alpn_proto	*alpn_chosen;

	unsigned int		state;

	TlsIOCtx		io_in;
	TlsIOCtx		io_out;
	TlsSess			sess;
	TlsXfrm			xfrm;

	unsigned long		sni_hash;
	unsigned int		nb_zero;
	int			client_auth;
	char			*hostname;
} TlsCtx;

typedef int ttls_send_cb_t(TlsCtx *tls, struct sg_table *sgt, bool close);
typedef int ttls_sni_cb_t(TlsCtx *tls, const unsigned char *data, size_t len);
typedef unsigned long ttls_cli_id_t(TlsCtx *tls, unsigned long hash);

enum {
	TTLS_HS_CB_FINISHED_NEW,
	TTLS_HS_CB_FINISHED_RESUMED,
	TTLS_HS_CB_UNCOMPLETE,
};
typedef int ttls_hs_over_cb_t(TlsCtx *tls, int state);

void ttls_hs_add_sni_hash(TlsCtx *tls, const char* data, size_t len);
bool ttls_hs_done(TlsCtx *tls);
bool ttls_xfrm_ready(TlsCtx *tls);
bool ttls_xfrm_need_encrypt(TlsCtx *tls);
void ttls_write_hshdr(unsigned char type, unsigned char *buf,
		      unsigned short len);
void *ttls_alloc_crypto_req(unsigned int extra_size, unsigned int *rsz);
void ttls_register_callbacks(ttls_send_cb_t *send_cb, ttls_sni_cb_t *sni_cb,
			     ttls_hs_over_cb_t *hs_over_cb, ttls_cli_id_t *cli_id_cb);

const char *ttls_get_ciphersuite_name(const int ciphersuite_id);

int ttls_ctx_init(TlsCtx *tls, const TlsCfg *conf);

void ttls_conf_authmode(TlsCfg *conf, int authmode);

int ttls_set_session(TlsCtx *ssl, const TlsSess *session);

int ttls_conf_own_cert(TlsPeerCfg *conf, TlsX509Crt *own_cert,
		       TlsPkCtx *pk_key, TlsX509Crt *ca_chain,
		       ttls_x509_crl *ca_crl);
int ttls_conf_tickets(TlsPeerCfg *conf, bool enable, unsigned long lifetime,
		      const char *secret_str, size_t len,
		      const char *vhost_name, size_t vn_len);

int ttls_set_hostname(TlsCtx *ssl, const char *hostname);
void ttls_set_hs_authmode(TlsCtx *ssl, int authmode);
const char *ttls_get_alpn_protocol(const TlsCtx *ssl);
void ttls_conf_version(TlsCfg *conf, int min_minor, int max_minor);

int ttls_get_session(const TlsCtx *ssl, TlsSess *session);

int ttls_recv(void *tls_data, unsigned char *buf, size_t len,
	      unsigned int *read);
int ttls_encrypt(TlsCtx *tls, struct sg_table *sgt, struct sg_table *out_sgt);

int ttls_send_alert(TlsCtx *tls, unsigned char lvl, unsigned char msg);
int ttls_close_notify(TlsCtx *tls);

void ttls_ctx_clear(TlsCtx *tls);
void ttls_key_cert_free(TlsKeyCert *key_cert);

void ttls_config_init(TlsCfg *conf);
int ttls_config_defaults(TlsCfg *conf, int endpoint);
int ttls_config_peer_defaults(TlsPeerCfg *conf, int endpoint);
void ttls_config_free(TlsCfg *conf);
void ttls_config_peer_free(TlsPeerCfg *conf);

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

static inline void
ttls_reset_io_ctx(TlsIOCtx *io)
{
	/* Note: it's up to the caller if io->skb_list must be cleared or not.*/
	bzero_fast(io->__initoff, sizeof(*io) - offsetof(TlsIOCtx, __initoff));
}

#endif /* __TTLS_H__ */
