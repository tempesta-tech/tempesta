/*
 * TLS client-side functions.
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
#include "config.h"

#if defined(TTLS_CLI_C)

#include "debug.h"
#include "ttls.h"
#include "tls_internal.h"

#if defined(TTLS_SESSION_TICKETS)
/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}
#endif

static void ssl_write_hostname_ext(ttls_context *ssl,
		unsigned char *buf,
		size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TLS_MAX_PAYLOAD_SIZE;
	size_t hostname_len;

	*olen = 0;

	if (ssl->hostname == NULL)
		return;

	T_DBG3("client hello, adding server name extension: %s\n",
				   ssl->hostname);

	hostname_len = strlen(ssl->hostname);

	if (end < p || (size_t)(end - p) < hostname_len + 9)
	{
		T_DBG("buffer too small\n");
		return;
	}

	/*
	 * Sect. 3, RFC 6066 (TLS Extensions Definitions)
	 *
	 * In order to provide any of the server names, clients MAY include an
	 * extension of type "server_name" in the (extended) client hello. The
	 * "extension_data" field of this extension SHALL contain
	 * "ServerNameList" where:
	 *
	 * struct {
	 *	 NameType name_type;
	 *	 select (name_type) {
	 *		 case host_name: HostName;
	 *	 } name;
	 * } ServerName;
	 *
	 * enum {
	 *	 host_name(0), (255)
	 * } NameType;
	 *
	 * opaque HostName<1..2^16-1>;
	 *
	 * struct {
	 *	 ServerName server_name_list<1..2^16-1>
	 * } ServerNameList;
	 *
	 */
	*p++ = (unsigned char)((TTLS_TLS_EXT_SERVERNAME >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_SERVERNAME	 ) & 0xFF);

	*p++ = (unsigned char)(((hostname_len + 5) >> 8) & 0xFF);
	*p++ = (unsigned char)(((hostname_len + 5)	 ) & 0xFF);

	*p++ = (unsigned char)(((hostname_len + 3) >> 8) & 0xFF);
	*p++ = (unsigned char)(((hostname_len + 3)	 ) & 0xFF);

	*p++ = (unsigned char)((TTLS_TLS_EXT_SERVERNAME_HOSTNAME) & 0xFF);
	*p++ = (unsigned char)((hostname_len >> 8) & 0xFF);
	*p++ = (unsigned char)((hostname_len	 ) & 0xFF);

	memcpy(p, ssl->hostname, hostname_len);

	*olen = hostname_len + 9;
}

/*
 * Only if we handle at least one key exchange that needs signatures.
 */
static void ssl_write_signature_algorithms_ext(ttls_context *ssl,
		unsigned char *buf,
		size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TLS_MAX_PAYLOAD_SIZE;
	size_t sig_alg_len = 0;
	const int *md;
	unsigned char *sig_alg_list = buf + 6;

	*olen = 0;

	if (ssl->conf->max_minor_ver != TTLS_MINOR_VERSION_3)
		return;

	T_DBG3("client hello, adding signature_algorithms extension\n");

	for (md = ssl->conf->sig_hashes; *md != TTLS_MD_NONE; md++)
	{
		sig_alg_len += 2;
		sig_alg_len += 2;
	}

	if (end < p || (size_t)(end - p) < sig_alg_len + 6)
	{
		T_DBG("buffer too small\n");
		return;
	}

	/*
	 * Prepare signature_algorithms extension (TLS 1.2)
	 */
	sig_alg_len = 0;

	for (md = ssl->conf->sig_hashes; *md != TTLS_MD_NONE; md++)
	{
		sig_alg_list[sig_alg_len++] = ttls_hash_from_md_alg(*md);
		sig_alg_list[sig_alg_len++] = TTLS_SIG_ECDSA;
		sig_alg_list[sig_alg_len++] = ttls_hash_from_md_alg(*md);
		sig_alg_list[sig_alg_len++] = TTLS_SIG_RSA;
	}

	/*
	 * enum {
	 *	 none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
	 *	 sha512(6), (255)
	 * } HashAlgorithm;
	 *
	 * enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
	 *   SignatureAlgorithm;
	 *
	 * struct {
	 *	 HashAlgorithm hash;
	 *	 SignatureAlgorithm signature;
	 * } SignatureAndHashAlgorithm;
	 *
	 * SignatureAndHashAlgorithm
	 *   supported_signature_algorithms<2..2^16-2>;
	 */
	*p++ = (unsigned char)((TTLS_TLS_EXT_SIG_ALG >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_SIG_ALG	 ) & 0xFF);

	*p++ = (unsigned char)(((sig_alg_len + 2) >> 8) & 0xFF);
	*p++ = (unsigned char)(((sig_alg_len + 2)	 ) & 0xFF);

	*p++ = (unsigned char)((sig_alg_len >> 8) & 0xFF);
	*p++ = (unsigned char)((sig_alg_len	 ) & 0xFF);

	*olen = 6 + sig_alg_len;
}

static void ssl_write_supported_elliptic_curves_ext(ttls_context *ssl,
		 unsigned char *buf,
		 size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TLS_MAX_PAYLOAD_SIZE;
	unsigned char *elliptic_curve_list = p + 6;
	size_t elliptic_curve_len = 0;
	const ttls_ecp_curve_info *info;
	const ttls_ecp_group_id *grp_id;

	*olen = 0;

	T_DBG3("client hello, adding supported_elliptic_curves extension\n");

	for (grp_id = ssl->conf->curve_list; *grp_id != TTLS_ECP_DP_NONE; grp_id++)
	{
		info = ttls_ecp_curve_info_from_grp_id(*grp_id);
		if (info == NULL)
		{
			T_DBG("invalid curve in ssl configuration\n");
			return;
		}

		elliptic_curve_len += 2;
	}

	if (end < p || (size_t)(end - p) < 6 + elliptic_curve_len)
	{
		T_DBG("buffer too small\n");
		return;
	}

	elliptic_curve_len = 0;

	for (grp_id = ssl->conf->curve_list; *grp_id != TTLS_ECP_DP_NONE; grp_id++)
	{
		info = ttls_ecp_curve_info_from_grp_id(*grp_id);
		elliptic_curve_list[elliptic_curve_len++] = info->tls_id >> 8;
		elliptic_curve_list[elliptic_curve_len++] = info->tls_id & 0xFF;
	}

	if (elliptic_curve_len == 0)
		return;

	*p++ = (unsigned char)((TTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES	 ) & 0xFF);

	*p++ = (unsigned char)(((elliptic_curve_len + 2) >> 8) & 0xFF);
	*p++ = (unsigned char)(((elliptic_curve_len + 2)	 ) & 0xFF);

	*p++ = (unsigned char)(((elliptic_curve_len	) >> 8) & 0xFF);
	*p++ = (unsigned char)(((elliptic_curve_len	)	 ) & 0xFF);

	*olen = 6 + elliptic_curve_len;
}

static void ssl_write_supported_point_formats_ext(ttls_context *ssl,
		unsigned char *buf,
		size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TLS_MAX_PAYLOAD_SIZE;

	*olen = 0;

	T_DBG3("client hello, adding supported_point_formats extension\n");

	if (end < p || (size_t)(end - p) < 6)
	{
		T_DBG("buffer too small\n");
		return;
	}

	*p++ = (unsigned char)((TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 2;

	*p++ = 1;
	*p++ = TTLS_ECP_PF_UNCOMPRESSED;

	*olen = 6;
}

static void ssl_write_encrypt_then_mac_ext(ttls_context *ssl,
		unsigned char *buf, size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TLS_MAX_PAYLOAD_SIZE;

	*olen = 0;

	T_DBG3("client hello, adding encrypt_then_mac "
			"extension\n");

	if (end < p || (size_t)(end - p) < 4)
	{
		T_DBG("buffer too small\n");
		return;
	}

	*p++ = (unsigned char)((TTLS_TLS_EXT_ENCRYPT_THEN_MAC >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_ENCRYPT_THEN_MAC	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
}

static void ssl_write_extended_ms_ext(ttls_context *ssl,
		unsigned char *buf, size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TLS_MAX_PAYLOAD_SIZE;

	*olen = 0;

	if (!ssl->conf->extended_ms)
		return;

	T_DBG3("client hello, adding extended_master_secret "
			"extension\n");

	if (end < p || (size_t)(end - p) < 4)
	{
		T_DBG("buffer too small\n");
		return;
	}

	*p++ = (unsigned char)((TTLS_TLS_EXT_EXTENDED_MASTER_SECRET >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_EXTENDED_MASTER_SECRET	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
}

#if defined(TTLS_SESSION_TICKETS)
static void ssl_write_session_ticket_ext(ttls_context *ssl,
		unsigned char *buf, size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TLS_MAX_PAYLOAD_SIZE;
	size_t tlen = ssl->session_negotiate->ticket_len;

	*olen = 0;

	if (ssl->conf->session_tickets == TTLS_SESSION_TICKETS_DISABLED)
	{
		return;
	}

	T_DBG3("client hello, adding session ticket extension\n");

	if (end < p || (size_t)(end - p) < 4 + tlen)
	{
		T_DBG("buffer too small\n");
		return;
	}

	*p++ = (unsigned char)((TTLS_TLS_EXT_SESSION_TICKET >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_SESSION_TICKET	 ) & 0xFF);

	*p++ = (unsigned char)((tlen >> 8) & 0xFF);
	*p++ = (unsigned char)((tlen	 ) & 0xFF);

	*olen = 4;

	if (ssl->session_negotiate->ticket == NULL || tlen == 0)
	{
		return;
	}

	T_DBG3("sending session ticket of length %d\n", tlen);

	memcpy(p, ssl->session_negotiate->ticket, tlen);

	*olen += tlen;
}
#endif /* TTLS_SESSION_TICKETS */

static void ssl_write_alpn_ext(ttls_context *ssl,
		unsigned char *buf, size_t *olen)
{
	int i;
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TLS_MAX_PAYLOAD_SIZE;
	size_t alpnlen = 0;
	const ttls_alpn_proto *cur;

	*olen = 0;

	BUG_ON(!ssl->conf->alpn_list);

	T_DBG3("client hello, adding alpn extension\n");

	for (i = 0; i < TTLS_ALPN_PROTOS; ++i) {
		cur = &ssl->conf->alpn_list[i];
		alpnlen += (unsigned char)(cur->len & 0xFF) + 1;
	}

	if (end < p || (size_t)(end - p) < 6 + alpnlen)	{
		T_DBG("buffer too small\n");
		return;
	}

	*p++ = (unsigned char)((TTLS_TLS_EXT_ALPN >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_ALPN	 ) & 0xFF);

	/*
	 * opaque ProtocolName<1..2^8-1>;
	 *
	 * struct {
	 *	 ProtocolName protocol_name_list<2..2^16-1>
	 * } ProtocolNameList;
	 */

	/* Skip writing extension and list length for now */
	p += 4;

	for (i = 0; i < TTLS_ALPN_PROTOS; ++i) {
		cur = &ssl->conf->alpn_list[i];
		*p = (unsigned char)(cur->len & 0xFF);
		memcpy(p + 1, cur->name, *p);
		p += 1 + *p;
	}

	*olen = p - buf;

	/* List length = olen - 2 (ext_type) - 2 (ext_len) - 2 (list_len) */
	buf[4] = (unsigned char)(((*olen - 6) >> 8) & 0xFF);
	buf[5] = (unsigned char)(((*olen - 6)	 ) & 0xFF);

	/* Extension length = olen - 2 (ext_type) - 2 (ext_len) */
	buf[2] = (unsigned char)(((*olen - 4) >> 8) & 0xFF);
	buf[3] = (unsigned char)(((*olen - 4)	 ) & 0xFF);
}

/*
 * Generate random bytes for ClientHello
 */
static int ssl_generate_random(ttls_context *ssl)
{
	unsigned char *p = ssl->handshake->randbytes;
	time_t t;

	t = ttls_time();
	*p++ = (unsigned char)(t >> 24);
	*p++ = (unsigned char)(t >> 16);
	*p++ = (unsigned char)(t >>  8);
	*p++ = (unsigned char)(t	  );

	T_DBG3("client hello, current time: %lu\n", t);

	ttls_rnd(p, 28);

	return 0;
}

static int ssl_write_client_hello(ttls_context *ssl)
{
	int ret;
	size_t i, n, olen, ext_len = 0;
	unsigned char *buf;
	unsigned char *p, *q;
	unsigned char offer_compress;
	const int *ciphersuites;
	const TlsCiphersuite *ciphersuite_info;

	T_DBG2("=> write client hello\n");

	ssl->major_ver = ssl->conf->min_major_ver;
	ssl->minor_ver = ssl->conf->min_minor_ver;

	if (ssl->conf->max_major_ver == 0)
	{
		T_DBG("configured max major version is invalid, "
				"consider using ttls_config_defaults()\n");
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	/*
	 *	 0  .   0   handshake type
	 *	 1  .   3   handshake length
	 *	 4  .   5   highest version supported
	 *	 6  .   9   current UNIX time
	 *	10  .  37   random bytes
	 */
	buf = ssl->out_msg;
	p = buf + 4;

	ttls_write_version(ssl->conf->max_major_ver, ssl->conf->max_minor_ver,
		   ssl->conf->transport, p);
	p += 2;

	T_DBG3("client hello, max version: [%d:%d]\n",
				   buf[4], buf[5]);

	if ((ret = ssl_generate_random(ssl)) != 0)
		return ret;

	memcpy(p, ssl->handshake->randbytes, 32);
	T_DBG3_BUF("client hello, random bytes", p, 32);
	p += 32;

	/*
	 *	38  .  38   session id length
	 *	39  . 39+n  session id
	 *   39+n . 39+n  DTLS only: cookie length (1 byte)
	 *   40+n .  ..   DTSL only: cookie
	 *   ..   . ..	ciphersuitelist length (2 bytes)
	 *   ..   . ..	ciphersuitelist
	 *   ..   . ..	compression methods length (1 byte)
	 *   ..   . ..	compression methods
	 *   ..   . ..	extensions length (2 bytes)
	 *   ..   . ..	extensions
	 */
	n = ssl->session_negotiate->id_len;

	if (n < 16 || n > 32 ||
		ssl->handshake->resume == 0)
	{
		n = 0;
	}

#if defined(TTLS_SESSION_TICKETS)
	/*
	 * RFC 5077 section 3.4: "When presenting a ticket, the client MAY
	 * generate and include a Session ID in the TLS ClientHello."
	 */
	if (ssl->session_negotiate->ticket != NULL &&
			ssl->session_negotiate->ticket_len != 0)
	{
		ttls_rnd(ssl->session_negotiate->id, 32);
		ssl->session_negotiate->id_len = n = 32;
	}
#endif /* TTLS_SESSION_TICKETS */

	*p++ = (unsigned char) n;

	for (i = 0; i < n; i++)
		*p++ = ssl->session_negotiate->id[i];

	T_DBG3("client hello, session id len.: %d\n", n);
	T_DBG3_BUF("client hello, session id\n", buf + 39, n);

	/*
	 * Ciphersuite list
	 */
	ciphersuites = ssl->conf->ciphersuite_list[ssl->minor_ver];

	/* Skip writing ciphersuite length for now */
	n = 0;
	q = p;
	p += 2;

	for (i = 0; ciphersuites[i] != 0; i++)
	{
		ciphersuite_info = ttls_ciphersuite_from_id(ciphersuites[i]);

		if (ciphersuite_info == NULL)
			continue;

		if (ciphersuite_info->min_minor_ver > ssl->conf->max_minor_ver ||
			ciphersuite_info->max_minor_ver < ssl->conf->min_minor_ver)
			continue;

		T_DBG3("client hello, add ciphersuite: %04x\n",
				ciphersuites[i]);

		n++;
		*p++ = (unsigned char)(ciphersuites[i] >> 8);
		*p++ = (unsigned char)(ciphersuites[i]	 );
	}

	T_DBG3("client hello, got %d ciphersuites (excluding SCSVs)\n", n);

	/*
	 * Add TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	 */
	T_DBG3("adding EMPTY_RENEGOTIATION_INFO_SCSV\n");
	*p++ = (unsigned char)(TTLS_EMPTY_RENEGOTIATION_INFO >> 8);
	*p++ = (unsigned char)(TTLS_EMPTY_RENEGOTIATION_INFO	 );
	n++;

	*q++ = (unsigned char)(n >> 7);
	*q++ = (unsigned char)(n << 1);

	offer_compress = 0;

	if (offer_compress)
	{
		T_DBG3("client hello, compress len.: %d\n", 2);
		T_DBG3("client hello, compress alg.: %d %d\n",
			TTLS_COMPRESS_DEFLATE, TTLS_COMPRESS_NULL);

		*p++ = 2;
		*p++ = TTLS_COMPRESS_DEFLATE;
		*p++ = TTLS_COMPRESS_NULL;
	}
	else
	{
		T_DBG3("client hello, compress len.: %d\n", 1);
		T_DBG3("client hello, compress alg.: %d\n",
			TTLS_COMPRESS_NULL);

		*p++ = 1;
		*p++ = TTLS_COMPRESS_NULL;
	}

	// First write extensions, then the total length
	//
	ssl_write_hostname_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

	/* Note that TLS_EMPTY_RENEGOTIATION_INFO_SCSV is always added
	 * even if there is no renegotiation is not defined. */

	ssl_write_signature_algorithms_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

	ssl_write_supported_elliptic_curves_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

	ssl_write_supported_point_formats_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

	ssl_write_encrypt_then_mac_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

	ssl_write_extended_ms_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

	ssl_write_alpn_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

#if defined(TTLS_SESSION_TICKETS)
	ssl_write_session_ticket_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

	/* olen unused if all extensions are disabled */
	((void) olen);

	T_DBG3("client hello, total extension length: %d\n", ext_len);

	if (ext_len > 0)
	{
		*p++ = (unsigned char)((ext_len >> 8) & 0xFF);
		*p++ = (unsigned char)((ext_len	 ) & 0xFF);
		p += ext_len;
	}

	ssl->out_msglen  = p - buf;
	ssl->out_msgtype = TTLS_MSG_HANDSHAKE;
	ssl->out_msg[0]  = TTLS_HS_CLIENT_HELLO;

	ssl->state++;

	if ((ret = ttls_write_record(ssl, /* TODO: sgt, close */)) != 0)
		return ret;

	T_DBG2("<= write client hello\n");

	return 0;
}

static int ssl_parse_renegotiation_info(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	if (len != 1 || buf[0] != 0x00)
	{
		T_DBG("non-zero length renegotiation info\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	return 0;
}

static int ssl_parse_encrypt_then_mac_ext(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	if (len) {
		T_DBG("non-matching encrypt-then-MAC extension\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	ssl->session_negotiate->encrypt_then_mac = 1;

	return 0;
}

static int ssl_parse_extended_ms_ext(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	if (!ssl->conf->extended_ms || len) {
		T_DBG("non-matching extended master secret extension\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	ssl->handshake->extended_ms = 1;

	return 0;
}

#if defined(TTLS_SESSION_TICKETS)
static int ssl_parse_session_ticket_ext(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	if (ssl->conf->session_tickets == TTLS_SESSION_TICKETS_DISABLED ||
		len != 0)
	{
		T_DBG("non-matching session ticket extension\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	((void) buf);

	ssl->handshake->new_session_ticket = 1;

	return 0;
}
#endif /* TTLS_SESSION_TICKETS */

static int ssl_parse_supported_point_formats_ext(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	size_t list_size;
	const unsigned char *p;

	list_size = buf[0];
	if (list_size + 1 != len)
	{
		T_DBG("bad server hello message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	p = buf + 1;
	while (list_size > 0)
	{
		if (p[0] == TTLS_ECP_PF_UNCOMPRESSED ||
			p[0] == TTLS_ECP_PF_COMPRESSED)
		{
			ssl->handshake->ecdh_ctx.point_format = p[0];
			T_DBG3("point format selected: %d\n", p[0]);
			return 0;
		}

		list_size--;
		p++;
	}

	T_DBG("no point format in common\n");
	ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
	return(TTLS_ERR_BAD_HS_SERVER_HELLO);
}

static int ssl_parse_alpn_ext(ttls_context *ssl,
		const unsigned char *buf, size_t len)
{
	int i;
	size_t list_len, name_len;
	const ttls_alpn_proto *p;

	/* If we didn't send it, the server shouldn't send it */
	if (ssl->conf->alpn_list == NULL)
	{
		T_DBG("non-matching ALPN extension\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	/*
	 * opaque ProtocolName<1..2^8-1>;
	 *
	 * struct {
	 *	 ProtocolName protocol_name_list<2..2^16-1>
	 * } ProtocolNameList;
	 *
	 * the "ProtocolNameList" MUST contain exactly one "ProtocolName"
	 */

	/* Min length is 2 (list_len) + 1 (name_len) + 1 (name) */
	if (len < 4)
	{
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	list_len = (buf[0] << 8) | buf[1];
	if (list_len != len - 2)
	{
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	name_len = buf[2];
	if (name_len != list_len - 1)
	{
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	/* Check that the server chosen protocol was in our list and save it */
	for (i = 0; i < TTLS_ALPN_PROTOS; ++i) {
		p = &ssl->conf->alpn_list[i];
		if (ttls_alpn_ext_eq(p, buf + 3, name_len)) {
			ssl->alpn_chosen = p;
			return 0;
		}
	}

	T_DBG("ALPN extension: no matching protocol\n");
	ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
	return(TTLS_ERR_BAD_HS_SERVER_HELLO);
}

static int ssl_parse_server_hello(ttls_context *ssl)
{
	int ret, i;
	size_t n;
	size_t ext_len;
	unsigned char *buf, *ext;
	unsigned char comp;
	int handshake_failure = 0;
	const TlsCiphersuite *suite_info;

	T_DBG2("=> parse server hello\n");

	buf = ssl->in_msg;

	if ((ret = ttls_read_record(ssl)) != 0)
		/* No alert on a read error. */
		return ret;

	if (ssl->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		T_DBG("bad server hello message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	if (ssl->in_hslen < 38 + TTLS_HS_HDR_LEN ||
		buf[0] != TTLS_HS_SERVER_HELLO)
	{
		T_DBG("bad server hello message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	/*
	 *  0   .  1	server_version
	 *  2   . 33	random (maybe including 4 bytes of Unix time)
	 * 34   . 34	session_id length = n
	 * 35   . 34+n  session_id
	 * 35+n . 36+n  cipher_suite
	 * 37+n . 37+n  compression_method
	 *
	 * 38+n . 39+n  extensions length (optional)
	 * 40+n .  ..   extensions
	 */
	buf += TTLS_HS_HDR_LEN;

	T_DBG3_BUF("server hello, version", buf + 0, 2);
	ttls_read_version(&ssl->major_ver, &ssl->minor_ver,
				  ssl->conf->transport, buf + 0);

	if (ssl->major_ver < ssl->conf->min_major_ver ||
		ssl->minor_ver < ssl->conf->min_minor_ver ||
		ssl->major_ver > ssl->conf->max_major_ver ||
		ssl->minor_ver > ssl->conf->max_minor_ver)
	{
		T_DBG("server version out of bounds - "
		" min: [%d:%d], server: [%d:%d], max: [%d:%d]\n",
		ssl->conf->min_major_ver, ssl->conf->min_minor_ver,
		ssl->major_ver, ssl->minor_ver,
		ssl->conf->max_major_ver, ssl->conf->max_minor_ver);

		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		 TTLS_ALERT_MSG_PROTOCOL_VERSION);

		return(TTLS_ERR_BAD_HS_PROTOCOL_VERSION);
	}

	T_DBG3("server hello, current time: %lu\n",
			   ((uint32_t) buf[2] << 24) |
			   ((uint32_t) buf[3] << 16) |
			   ((uint32_t) buf[4] <<  8) |
			   ((uint32_t) buf[5]	  ));

	memcpy(ssl->handshake->randbytes + 32, buf + 2, 32);

	n = buf[34];

	T_DBG3_BUF("server hello, random bytes", buf + 2, 32);

	if (n > 32)
	{
		T_DBG("bad server hello message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	if (ssl->in_hslen > TTLS_HS_HDR_LEN + 39 + n)
	{
		ext_len = ((buf[38 + n] <<  8)
				  | (buf[39 + n]	  ));

		if ((ext_len > 0 && ext_len < 4) ||
			ssl->in_hslen != TTLS_HS_HDR_LEN + 40 + n + ext_len)
		{
			T_DBG("bad server hello message\n");
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_SERVER_HELLO);
		}
	}
	else if (ssl->in_hslen == TTLS_HS_HDR_LEN + 38 + n)
	{
		ext_len = 0;
	}
	else
	{
		T_DBG("bad server hello message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	/* ciphersuite (used later) */
	i = (buf[35 + n] << 8) | buf[36 + n];

	/*
	 * Read and check compression
	 */
	comp = buf[37 + n];

	if (comp != TTLS_COMPRESS_NULL)
	{
		T_DBG("server hello, bad compression: %d\n", comp);
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
		return(TTLS_ERR_FEATURE_UNAVAILABLE);
	}

	/*
	 * Initialize update checksum functions
	 */
	ssl->transform_negotiate->ciphersuite_info = ttls_ciphersuite_from_id(i);

	if (ssl->transform_negotiate->ciphersuite_info == NULL)
	{
		T_DBG("ciphersuite info for %04x not found\n", i);
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_INTERNAL_ERROR);
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	/*
	 * TODO the handshake hash context must be initialized in ttls_ctx_init().
	 *
	 * ttls_optimize_checksum(ssl, ssl->transform_negotiate->ciphersuite_info);
	 */

	T_DBG3("server hello, session id len.: %d\n", n);
	T_DBG3_BUF("server hello, session id", buf + 35, n);

	/*
	 * Check if the session can be resumed
	 */
	if (ssl->handshake->resume == 0 || n == 0 ||
		ssl->session_negotiate->ciphersuite != i ||
		ssl->session_negotiate->compression != comp ||
		ssl->session_negotiate->id_len != n ||
		memcmp(ssl->session_negotiate->id, buf + 35, n) != 0)
	{
		ssl->state++;
		ssl->handshake->resume = 0;
		ssl->session_negotiate->start = ttls_time();
		ssl->session_negotiate->ciphersuite = i;
		ssl->session_negotiate->compression = comp;
		ssl->session_negotiate->id_len = n;
		memcpy(ssl->session_negotiate->id, buf + 35, n);
	}
	else
	{
		ssl->state = TTLS_SERVER_CHANGE_CIPHER_SPEC;

		if ((ret = ttls_derive_keys(ssl)) != 0)
		{
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_INTERNAL_ERROR);
			return ret;
		}
	}

	T_DBG3("%s session has been resumed",
				   ssl->handshake->resume ? "a" : "no\n");

	T_DBG3("server hello, chosen ciphersuite: %04x\n", i);
	T_DBG3("server hello, compress alg.: %d\n", buf[37 + n]);

	suite_info = ttls_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);
	if (!suite_info) {
		T_DBG("bad server hello message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	T_DBG3("server hello, chosen ciphersuite: %s\n", suite_info->name);

	i = 0;
	while (1)
	{
		if (ssl->conf->ciphersuite_list[ssl->minor_ver][i] == 0)
		{
			T_DBG("bad server hello message\n");
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
			return(TTLS_ERR_BAD_HS_SERVER_HELLO);
		}

		if (ssl->conf->ciphersuite_list[ssl->minor_ver][i++] ==
			ssl->session_negotiate->ciphersuite)
		{
			break;
		}
	}

	if (comp != TTLS_COMPRESS_NULL) {
		T_DBG("bad server hello message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}
	ssl->session_negotiate->compression = comp;

	ext = buf + 40 + n;

	T_DBG2("server hello, total extension length: %d\n", ext_len);

	while (ext_len)
	{
		unsigned int ext_id   = ((ext[0] <<  8)
		| (ext[1]	  ));
		unsigned int ext_size = ((ext[2] <<  8)
		| (ext[3]	  ));

		if (ext_size + 4 > ext_len)
		{
			T_DBG("bad server hello message\n");
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_SERVER_HELLO);
		}

		switch(ext_id)
		{
		case TTLS_TLS_EXT_ENCRYPT_THEN_MAC:
			T_DBG3("found encrypt_then_mac extension\n");

			if ((ret = ssl_parse_encrypt_then_mac_ext(ssl,
				ext + 4, ext_size)) != 0)
			{
				return ret;
			}

			break;

		case TTLS_TLS_EXT_EXTENDED_MASTER_SECRET:
			T_DBG3("found extended_master_secret extension\n");

			if ((ret = ssl_parse_extended_ms_ext(ssl,
				ext + 4, ext_size)) != 0)
			{
				return ret;
			}

			break;

#if defined(TTLS_SESSION_TICKETS)
		case TTLS_TLS_EXT_SESSION_TICKET:
			T_DBG3("found session_ticket extension\n");

			if ((ret = ssl_parse_session_ticket_ext(ssl,
				ext + 4, ext_size)) != 0)
			{
				return ret;
			}

			break;
#endif /* TTLS_SESSION_TICKETS */

		case TTLS_TLS_EXT_ALPN:
			T_DBG3("found alpn extension\n");

			if ((ret = ssl_parse_alpn_ext(ssl, ext + 4, ext_size)) != 0)
				return ret;

			break;

		default:
			T_DBG3("unknown extension found: %d (ignoring)\n",
			   ext_id);
		}

		ext_len -= 4 + ext_size;
		ext += 4 + ext_size;

		if (ext_len > 0 && ext_len < 4)
		{
			T_DBG("bad server hello message\n");
			return(TTLS_ERR_BAD_HS_SERVER_HELLO);
		}
	}

	if (handshake_failure == 1)
	{
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	T_DBG2("<= parse server hello\n");

	return 0;
}

static int ssl_parse_server_dh_params(ttls_context *ssl, unsigned char **p,
		unsigned char *end)
{
	int ret = TTLS_ERR_FEATURE_UNAVAILABLE;

	/*
	 * Ephemeral DH parameters:
	 *
	 * struct {
	 *	 opaque dh_p<1..2^16-1>;
	 *	 opaque dh_g<1..2^16-1>;
	 *	 opaque dh_Ys<1..2^16-1>;
	 * } ServerDHParams;
	 */
	if ((ret = ttls_dhm_read_params(&ssl->handshake->dhm_ctx, p, end)) != 0)
		return ret;

	if (ssl->handshake->dhm_ctx.len * 8 < ssl->conf->dhm_min_bitlen)
	{
		T_DBG("DHM prime too short: %d < %d\n",
			ssl->handshake->dhm_ctx.len * 8,
			ssl->conf->dhm_min_bitlen);
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	TTLS_DEBUG_MPI("DHM: P ", &ssl->handshake->dhm_ctx.P );
	TTLS_DEBUG_MPI("DHM: G ", &ssl->handshake->dhm_ctx.G );
	TTLS_DEBUG_MPI("DHM: GY", &ssl->handshake->dhm_ctx.GY);

	return ret;
}

static int ssl_check_server_ecdh_params(const ttls_context *ssl)
{
	const ttls_ecp_curve_info *curve_info;

	curve_info = ttls_ecp_curve_info_from_grp_id(ssl->handshake->ecdh_ctx.grp.id);
	if (curve_info == NULL)
	{
		T_DBG("should never happen\n");
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	T_DBG2("ECDH curve: %s\n", curve_info->name);

	if (ttls_check_curve(ssl, ssl->handshake->ecdh_ctx.grp.id) != 0)
		return(-1);

	TTLS_DEBUG_ECP("ECDH: Qp", &ssl->handshake->ecdh_ctx.Qp);

	return 0;
}

static int ssl_parse_server_ecdh_params(ttls_context *ssl,
		unsigned char **p,
		unsigned char *end)
{
	int ret = TTLS_ERR_FEATURE_UNAVAILABLE;

	/*
	 * Ephemeral ECDH parameters:
	 *
	 * struct {
	 *	 ECParameters curve_params;
	 *	 ECPoint	  public;
	 * } ServerECDHParams;
	 */
	if ((ret = ttls_ecdh_read_params(&ssl->handshake->ecdh_ctx,
				  (const unsigned char **) p, end)) != 0)
	{
		return ret;
	}

	if (ssl_check_server_ecdh_params(ssl) != 0)
	{
		T_DBG("bad server key exchange message (ECDHE curve)\n");
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	return ret;
}

/*
 * Generate a pre-master secret and encrypt it with the server's RSA key
 */
static int ssl_write_encrypted_pms(ttls_context *ssl,
		size_t offset, size_t *olen,
		size_t pms_offset)
{
	int ret;
	size_t len_bytes = ssl->minor_ver == TTLS_MINOR_VERSION_0 ? 0 : 2;
	unsigned char *p = ssl->handshake->premaster + pms_offset;

	if (offset + len_bytes > TLS_MAX_PAYLOAD_SIZE)
	{
		T_DBG("buffer too small for encrypted pms\n");
		return(TTLS_ERR_BUFFER_TOO_SMALL);
	}

	/*
	 * Generate (part of) the pre-master as
	 *  struct {
	 *	  ProtocolVersion client_version;
	 *	  opaque random[46];
	 *  } PreMasterSecret;
	 */
	ttls_write_version(ssl->conf->max_major_ver, ssl->conf->max_minor_ver,
		   ssl->conf->transport, p);

	ttls_rnd(p + 2, 46);

	ssl->handshake->pmslen = 48;

	if (ssl->session_negotiate->peer_cert == NULL)
	{
		T_DBG2("certificate required\n");
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	/*
	 * Now write it out, encrypted
	 */
	if (! ttls_pk_can_do(&ssl->session_negotiate->peer_cert->pk,
				TTLS_PK_RSA))
	{
		T_DBG("certificate key type mismatch\n");
		return(TTLS_ERR_PK_TYPE_MISMATCH);
	}

	if ((ret = ttls_pk_encrypt(&ssl->session_negotiate->peer_cert->pk,
			p, ssl->handshake->pmslen,
			ssl->out_msg + offset + len_bytes, olen,
			TLS_MAX_PAYLOAD_SIZE - offset - len_bytes)) != 0)
	{
		return ret;
	}

	if (len_bytes == 2)
	{
		ssl->out_msg[offset+0] = (unsigned char)(*olen >> 8);
		ssl->out_msg[offset+1] = (unsigned char)(*olen	 );
		*olen += 2;
	}

	return 0;
}

static int ssl_parse_signature_algorithm(ttls_context *ssl,
		  unsigned char **p,
		  unsigned char *end,
		  ttls_md_type_t *md_alg,
		  ttls_pk_type_t *pk_alg)
{
	((void) ssl);
	*md_alg = TTLS_MD_NONE;
	*pk_alg = TTLS_PK_NONE;

	/* Only in TLS 1.2 */
	if (ssl->minor_ver != TTLS_MINOR_VERSION_3)
	{
		return 0;
	}

	if ((*p) + 2 > end)
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);

	/*
	 * Get hash algorithm
	 */
	if ((*md_alg = ttls_md_alg_from_hash((*p)[0])) == TTLS_MD_NONE)
	{
		T_DBG("Server used unsupported HashAlgorithm %d\n", *(p)[0]);
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	/*
	 * Get signature algorithm
	 */
	if ((*pk_alg = ttls_pk_alg_from_sig((*p)[1])) == TTLS_PK_NONE)
	{
		T_DBG("server used unsupported SignatureAlgorithm %d\n", (*p)[1]);
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	/*
	 * Check if the hash is acceptable
	 */
	if (ttls_check_sig_hash(ssl, *md_alg) != 0)
	{
		T_DBG("server used HashAlgorithm %d that was not offered\n",
			*(p)[0]);
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	T_DBG2("Server used SignatureAlgorithm %d\n", (*p)[1]);
	T_DBG2("Server used HashAlgorithm %d\n", (*p)[0]);
	*p += 2;

	return 0;
}

static int ssl_get_ecdh_params_from_cert(ttls_context *ssl)
{
	int ret;
	const ttls_ecp_keypair *peer_key;

	if (ssl->session_negotiate->peer_cert == NULL)
	{
		T_DBG2("certificate required\n");
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	if (! ttls_pk_can_do(&ssl->session_negotiate->peer_cert->pk,
		 TTLS_PK_ECKEY))
	{
		T_DBG("server key not ECDH capable\n");
		return(TTLS_ERR_PK_TYPE_MISMATCH);
	}

	peer_key = ttls_pk_ec(ssl->session_negotiate->peer_cert->pk);

	if ((ret = ttls_ecdh_get_params(&ssl->handshake->ecdh_ctx, peer_key,
		 TTLS_ECDH_THEIRS)) != 0)
	{
		return ret;
	}

	if (ssl_check_server_ecdh_params(ssl) != 0)
	{
		T_DBG("bad server certificate (ECDH curve)\n");
		return(TTLS_ERR_BAD_HS_CERTIFICATE);
	}

	return ret;
}

static int ssl_parse_server_key_exchange(ttls_context *ssl)
{
	int ret;
	const TlsCiphersuite *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;
	unsigned char *p = NULL, *end = NULL;

	T_DBG2("=> parse server key exchange\n");

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA)
	{
		T_DBG2("<= skip parse server key exchange\n");
		ssl->state++;
		return 0;
	}

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDH_RSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDH_ECDSA)
	{
		if ((ret = ssl_get_ecdh_params_from_cert(ssl)) != 0)
		{
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
			return ret;
		}

		T_DBG2("<= skip parse server key exchange\n");
		ssl->state++;
		return 0;
	}

	if ((ret = ttls_read_record(ssl)) != 0)
		return ret;

	if (ssl->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		T_DBG("bad server key exchange message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	/*
	 * ServerKeyExchange may be skipped with PSK and RSA-PSK when the server
	 * doesn't use a psk_identity_hint
	 */
	if (ssl->in_msg[0] != TTLS_HS_SERVER_KEY_EXCHANGE)
	{
		if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
			ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK)
		{
			/* Current message is probably either
			 * CertificateRequest or ServerHelloDone */
			ssl->keep_current_message = 1;
			goto exit;
		}

		T_DBG("server key exchange message must "
			"not be skipped\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);

		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	p   = ssl->in_msg + TTLS_HS_HDR_LEN;
	end = ssl->in_msg + ssl->in_hslen;
	T_DBG3_BUF("server key exchange", p, end - p);

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_RSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK)
	{
		if (ssl_parse_server_dh_params(ssl, &p, end) != 0)
		{
			T_DBG("bad server key exchange message\n");
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
			return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
		}
	}
	else
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_RSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_ECDSA)
	{
		if (ssl_parse_server_ecdh_params(ssl, &p, end) != 0)
		{
			T_DBG("bad server key exchange message\n");
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
			return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
		}
	}
	else
	{
		T_DBG("should never happen\n");
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	if (ttls_ciphersuite_uses_server_signature(ciphersuite_info))
	{
		size_t sig_len, hashlen;
		unsigned char hash[64];
		ttls_md_type_t md_alg = TTLS_MD_NONE;
		ttls_pk_type_t pk_alg = TTLS_PK_NONE;
		unsigned char *params = ssl->in_msg + TTLS_HS_HDR_LEN;
		size_t params_len = p - params;

		/*
		 * Handle the digitally-signed structure
		 */
		if (ssl->minor_ver == TTLS_MINOR_VERSION_3)
		{
			if (ssl_parse_signature_algorithm(ssl, &p, end,
			   &md_alg, &pk_alg) != 0)
			{
				T_DBG("bad server key exchange message\n");
				ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
				return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
			}

			if (pk_alg != ttls_get_ciphersuite_sig_pk_alg(ciphersuite_info))
			{
				T_DBG("bad server key exchange message\n");
				ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
				return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
			}
		}
		else
		{
			T_DBG("should never happen\n");
			return(TTLS_ERR_INTERNAL_ERROR);
		}

		/*
		 * Read signature
		 */

		if (p > end - 2)
		{
			T_DBG("bad server key exchange message\n");
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
		}
		sig_len = (p[0] << 8) | p[1];
		p += 2;

		if (p != end - sig_len)
		{
			T_DBG("bad server key exchange message\n");
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
		}

		T_DBG3_BUF("signature", p, sig_len);

		/*
		 * Compute the hash that has been signed
		 */
		if (md_alg != TTLS_MD_NONE)
		{
			/* Info from md_alg will be used instead */
			hashlen = 0;
			ret = ttls_get_key_exchange_md_tls1_2(ssl, hash, params,
		  params_len, md_alg);
			if (ret != 0)
				return ret;
		}
		else
		{
			T_DBG("should never happen\n");
			return(TTLS_ERR_INTERNAL_ERROR);
		}

		T_DBG3_BUF("parameters hash\n", hash, hashlen != 0 ? hashlen :
			(unsigned int) (ttls_md_get_size(ttls_md_info_from_type(md_alg))));

		if (ssl->session_negotiate->peer_cert == NULL)
		{
			T_DBG2("certificate required\n");
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
			return(TTLS_ERR_UNEXPECTED_MESSAGE);
		}

		/*
		 * Verify signature
		 */
		if (! ttls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, pk_alg))
		{
			T_DBG("bad server key exchange message\n");
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
			return(TTLS_ERR_PK_TYPE_MISMATCH);
		}

		if ((ret = ttls_pk_verify(&ssl->session_negotiate->peer_cert->pk,
		   md_alg, hash, hashlen, p, sig_len)) != 0)
		{
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_DECRYPT_ERROR);
			return ret;
		}
	}

exit:
	ssl->state++;

	T_DBG2("<= parse server key exchange\n");

	return 0;
}

#if ! defined(TTLS_KEY_EXCHANGE__CERT_REQ_ALLOWED__ENABLED)
static int ssl_parse_certificate_request(ttls_context *ssl)
{
	const TlsCiphersuite *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;

	T_DBG2("=> parse certificate request\n");

	if (! ttls_ciphersuite_cert_req_allowed(ciphersuite_info))
	{
		T_DBG2("<= skip parse certificate request\n");
		ssl->state++;
		return 0;
	}

	T_DBG("should never happen\n");
	return(TTLS_ERR_INTERNAL_ERROR);
}
#else /* TTLS_KEY_EXCHANGE__CERT_REQ_ALLOWED__ENABLED */
static int ssl_parse_certificate_request(ttls_context *ssl)
{
	int ret;
	unsigned char *buf;
	size_t n = 0;
	size_t cert_type_len = 0, dn_len = 0;
	const TlsCiphersuite *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;

	T_DBG2("=> parse certificate request\n");

	if (! ttls_ciphersuite_cert_req_allowed(ciphersuite_info))
	{
		T_DBG2("<= skip parse certificate request\n");
		ssl->state++;
		return 0;
	}

	if ((ret = ttls_read_record(ssl)) != 0)
		return ret;

	if (ssl->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		T_DBG("bad certificate request message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	ssl->state++;
	ssl->client_auth = (ssl->in_msg[0] == TTLS_HS_CERTIFICATE_REQUEST);

	T_DBG3("got %s certificate request",
				ssl->client_auth ? "a" : "no\n");

	if (ssl->client_auth == 0)
	{
		/* Current message is probably the ServerHelloDone */
		ssl->keep_current_message = 1;
		goto exit;
	}

	/*
	 *  struct {
	 *	  ClientCertificateType certificate_types<1..2^8-1>;
	 *	  SignatureAndHashAlgorithm
	 *		supported_signature_algorithms<2^16-1>; -- TLS 1.2 only
	 *	  DistinguishedName certificate_authorities<0..2^16-1>;
	 *  } CertificateRequest;
	 *
	 *  Since we only support a single certificate on clients, let's just
	 *  ignore all the information that's supposed to help us pick a
	 *  certificate.
	 *
	 *  We could check that our certificate matches the request, and bail out
	 *  if it doesn't, but it's simpler to just send the certificate anyway,
	 *  and give the server the opportunity to decide if it should terminate
	 *  the connection when it doesn't like our certificate.
	 *
	 *  Same goes for the hash in TLS 1.2's signature_algorithms: at this
	 *  point we only have one hash available (see comments in
	 *  write_certificate_verify), so let's just use what we have.
	 *
	 *  However, we still minimally parse the message to check it is at least
	 *  superficially sane.
	 */
	buf = ssl->in_msg;

	/* certificate_types */
	cert_type_len = buf[TTLS_HS_HDR_LEN];
	n = cert_type_len;

	if (ssl->in_hslen < TTLS_HS_HDR_LEN + 2 + n)
	{
		T_DBG("bad certificate request message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_CERTIFICATE_REQUEST);
	}

	/* supported_signature_algorithms */
	if (ssl->minor_ver == TTLS_MINOR_VERSION_3)
	{
		size_t sig_alg_len = ((buf[TTLS_HS_HDR_LEN + 1 + n] <<  8)
		 | (buf[TTLS_HS_HDR_LEN + 2 + n]));
#if defined(DEBUG) && (DEBUG == 3)
		unsigned char* sig_alg = buf + TTLS_HS_HDR_LEN + 3 + n;
		size_t i;

		for (i = 0; i < sig_alg_len; i += 2)
		{
			T_DBG3("Supported Signature Algorithm found: %d\n"
				",%d", sig_alg[i], sig_alg[i + 1] );
		}
#endif

		n += 2 + sig_alg_len;

		if (ssl->in_hslen < TTLS_HS_HDR_LEN + 2 + n)
		{
			T_DBG("bad certificate request message\n");
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_CERTIFICATE_REQUEST);
		}
	}

	/* certificate_authorities */
	dn_len = ((buf[TTLS_HS_HDR_LEN + 1 + n] <<  8)
			 | (buf[TTLS_HS_HDR_LEN + 2 + n]	  ));

	n += dn_len;
	if (ssl->in_hslen != TTLS_HS_HDR_LEN + 3 + n)
	{
		T_DBG("bad certificate request message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_CERTIFICATE_REQUEST);
	}

exit:
	T_DBG2("<= parse certificate request\n");

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE__CERT_REQ_ALLOWED__ENABLED */

static int ssl_parse_server_hello_done(ttls_context *ssl)
{
	int ret;

	T_DBG2("=> parse server hello done\n");

	if ((ret = ttls_read_record(ssl)) != 0)
		return ret;

	if (ssl->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		T_DBG("bad server hello done message\n");
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	if (ssl->in_hslen  != TTLS_HS_HDR_LEN ||
		ssl->in_msg[0] != TTLS_HS_SERVER_HELLO_DONE)
	{
		T_DBG("bad server hello done message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO_DONE);
	}

	ssl->state++;

	T_DBG2("<= parse server hello done\n");

	return 0;
}

static int ssl_write_client_key_exchange(ttls_context *ssl)
{
	int ret;
	size_t i, n;
	const TlsCiphersuite *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;

	T_DBG2("=> write client key exchange\n");

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_RSA)
	{
		/*
		 * DHM key exchange -- send G^X mod P
		 */
		n = ssl->handshake->dhm_ctx.len;

		ssl->out_msg[4] = (unsigned char)(n >> 8);
		ssl->out_msg[5] = (unsigned char)(n	 );
		i = 6;

		ret = ttls_dhm_make_public(&ssl->handshake->dhm_ctx,
				(int) ttls_mpi_size(&ssl->handshake->dhm_ctx.P),
				&ssl->out_msg[i], n);
		if (ret != 0)
			return ret;

		TTLS_DEBUG_MPI("DHM: X ", &ssl->handshake->dhm_ctx.X );
		TTLS_DEBUG_MPI("DHM: GX", &ssl->handshake->dhm_ctx.GX);

		if ((ret = ttls_dhm_calc_secret(&ssl->handshake->dhm_ctx,
			ssl->handshake->premaster,
			TTLS_PREMASTER_SIZE,
			&ssl->handshake->pmslen)) != 0)
		{
			return ret;
		}

		TTLS_DEBUG_MPI("DHM: K ", &ssl->handshake->dhm_ctx.K );
	}
	else
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_RSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_ECDSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDH_RSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDH_ECDSA)
	{
		/*
		 * ECDH key exchange -- send client public value
		 */
		i = 4;

		ret = ttls_ecdh_make_public(&ssl->handshake->ecdh_ctx,
					&n, &ssl->out_msag[i], 1000);
		if (ret != 0)
			return ret;

		TTLS_DEBUG_ECP("ECDH: Q", &ssl->handshake->ecdh_ctx.Q);

		if ((ret = ttls_ecdh_calc_secret(&ssl->handshake->ecdh_ctx,
					  &ssl->handshake->pmslen,
					   ssl->handshake->premaster,
					   TTLS_MPI_MAX_SIZE)) != 0)
		{
			return ret;
		}

		TTLS_DEBUG_MPI("ECDH: z", &ssl->handshake->ecdh_ctx.z);
	}
	else
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA)
	{
		i = 4;
		if ((ret = ssl_write_encrypted_pms(ssl, i, &n, 0)) != 0)
			return ret;
	}
	else
	{
		((void) ciphersuite_info);
		T_DBG("should never happen\n");
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	ssl->out_msglen  = i + n;
	ssl->out_msgtype = TTLS_MSG_HANDSHAKE;
	ssl->out_msg[0]  = TTLS_HS_CLIENT_KEY_EXCHANGE;

	ssl->state++;

	if ((ret = ttls_write_record(ssl, /* TODO sgt, close */)) != 0)
		return ret;

	T_DBG2("<= write client key exchange\n");

	return 0;
}

static int ssl_write_certificate_verify(ttls_context *ssl)
{
	const TlsCiphersuite *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;
	int ret;

	T_DBG2("=> write certificate verify\n");

	if ((ret = ttls_derive_keys(ssl)) != 0)
		return ret;

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		T_DBG2("<= skip write certificate verify\n");
		ssl->state++;
		return 0;
	}

	T_DBG("should never happen\n");
	return(TTLS_ERR_INTERNAL_ERROR);
}

#if defined(TTLS_SESSION_TICKETS)
static int ssl_parse_new_session_ticket(ttls_context *ssl)
{
	int ret;
	uint32_t lifetime;
	size_t ticket_len;
	unsigned char *ticket;
	const unsigned char *msg;

	T_DBG2("=> parse new session ticket\n");

	if ((ret = ttls_read_record(ssl)) != 0)
		return ret;

	if (ssl->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		T_DBG("bad new session ticket message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	/*
	 * struct {
	 *	 uint32 ticket_lifetime_hint;
	 *	 opaque ticket<0..2^16-1>;
	 * } NewSessionTicket;
	 *
	 * 0  .  3   ticket_lifetime_hint
	 * 4  .  5   ticket_len (n)
	 * 6  .  5+n ticket content
	 */
	if (ssl->in_msg[0] != TTLS_HS_NEW_SESSION_TICKET ||
		ssl->in_hslen < 6 + TTLS_HS_HDR_LEN)
	{
		T_DBG("bad new session ticket message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_NEW_SESSION_TICKET);
	}

	msg = ssl->in_msg + TTLS_HS_HDR_LEN;

	lifetime = (msg[0] << 24) | (msg[1] << 16) |
			   (msg[2] <<  8) | (msg[3]	  );

	ticket_len = (msg[4] << 8) | (msg[5]);

	if (ticket_len + 6 + TTLS_HS_HDR_LEN != ssl->in_hslen)
	{
		T_DBG("bad new session ticket message\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_NEW_SESSION_TICKET);
	}

	T_DBG3("ticket length: %d\n", ticket_len);

	/* We're not waiting for a NewSessionTicket message any more */
	ssl->handshake->new_session_ticket = 0;
	ssl->state = TTLS_SERVER_CHANGE_CIPHER_SPEC;

	/*
	 * Zero-length ticket means the server changed his mind and doesn't want
	 * to send a ticket after all, so just forget it
	 */
	if (ticket_len == 0)
		return 0;

	ttls_zeroize(ssl->session_negotiate->ticket,
		  ssl->session_negotiate->ticket_len);
	ttls_free(ssl->session_negotiate->ticket);
	ssl->session_negotiate->ticket = NULL;
	ssl->session_negotiate->ticket_len = 0;

	if ((ticket = ttls_calloc(1, ticket_len)) == NULL)
	{
		T_DBG("ticket alloc failed\n");
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
		TTLS_ALERT_MSG_INTERNAL_ERROR);
		return(TTLS_ERR_ALLOC_FAILED);
	}

	memcpy(ticket, msg + 6, ticket_len);

	ssl->session_negotiate->ticket = ticket;
	ssl->session_negotiate->ticket_len = ticket_len;
	ssl->session_negotiate->ticket_lifetime = lifetime;

	/*
	 * RFC 5077 section 3.4:
	 * "If the client receives a session ticket from the server, then it
	 * discards any Session ID that was sent in the ServerHello."
	 */
	T_DBG3("ticket in use, discarding session id\n");
	ssl->session_negotiate->id_len = 0;

	T_DBG2("<= parse new session ticket\n");

	return 0;
}
#endif /* TTLS_SESSION_TICKETS */

/*
 * SSL handshake -- client side -- single step
 */
int ttls_handshake_client_step(ttls_context *ssl)
{
	int ret = 0;

	if (ssl->state == TTLS_HANDSHAKE_OVER || ssl->handshake == NULL)
		return(TTLS_ERR_BAD_INPUT_DATA);

	T_DBG2("client state: %d\n", ssl->state);

	BUG_ON(tls->conf->endpoint != TTLS_IS_CLIENT);

	/* Change state now, so that it is right in ttls_read_record(), used
	 * by DTLS for dropping out-of-sequence ChangeCipherSpec records */
#if defined(TTLS_SESSION_TICKETS)
	if (ssl->state == TTLS_SERVER_CHANGE_CIPHER_SPEC &&
		ssl->handshake->new_session_ticket != 0)
	{
		ssl->state = TTLS_SERVER_NEW_SESSION_TICKET;
	}
#endif

	switch(ssl->state)
	{
	   /*
		*  ==>   ClientHello
		*/
	   case TTLS_CLIENT_HELLO:
		   ret = ssl_write_client_hello(ssl);
		   break;

	   /*
		*  <==   ServerHello
		*		Certificate
		*	  (ServerKeyExchange )
		*	  (CertificateRequest)
		*		ServerHelloDone
		*/
	   case TTLS_SERVER_HELLO:
		   ret = ssl_parse_server_hello(ssl);
		   break;

	   case TTLS_SERVER_CERTIFICATE:
		   ret = ttls_parse_certificate(ssl);
		   break;

	   case TTLS_SERVER_KEY_EXCHANGE:
		   ret = ssl_parse_server_key_exchange(ssl);
		   break;

	   case TTLS_CERTIFICATE_REQUEST:
		   ret = ssl_parse_certificate_request(ssl);
		   break;

	   case TTLS_SERVER_HELLO_DONE:
		   ret = ssl_parse_server_hello_done(ssl);
		   break;

	   /*
		*  ==> (Certificate/Alert )
		*		ClientKeyExchange
		*	  (CertificateVerify )
		*		ChangeCipherSpec
		*		Finished
		*/
	   case TTLS_CLIENT_CERTIFICATE: {
		   ret = ttls_write_certificate(ssl);
		   /* TODO move to next state */
	}

	   case TTLS_CLIENT_KEY_EXCHANGE:
		   ret = ssl_write_client_key_exchange(ssl);
		   break;

	   case TTLS_CERTIFICATE_VERIFY:
		   ret = ssl_write_certificate_verify(ssl);
		   break;

	   case TTLS_CLIENT_CHANGE_CIPHER_SPEC:
		   ret = ttls_write_change_cipher_spec(ssl);
		   tls->state++;
		   break;

	   case TTLS_CLIENT_FINISHED:
		   ret = ttls_write_finished(ssl);
		/*
		 * In case of session resuming, invert the client and server
		 * ChangeCipherSpec messages order.
		 */
		tls->state = tls->hs->resume
			     ? TTLS_HANDSHAKE_WRAPUP
			     : TTLS_SERVER_CHANGE_CIPHER_SPEC;
		   break;

	   /*
		*  <==   (NewSessionTicket)
		*		ChangeCipherSpec
		*		Finished
		*/
#if defined(TTLS_SESSION_TICKETS)
	   case TTLS_SERVER_NEW_SESSION_TICKET:
		   ret = ssl_parse_new_session_ticket(ssl);
		   break;
#endif

	   case TTLS_SERVER_CHANGE_CIPHER_SPEC:
		   ret = ttls_parse_change_cipher_spec(ssl);
		   break;

	   case TTLS_SERVER_FINISHED:
		ret = ttls_parse_finished(ssl);
		if (tls->hs->resume)
			tls->state = TTLS_CLIENT_CHANGE_CIPHER_SPEC;
		else
			tls->state++;
		break;

	   case TTLS_HANDSHAKE_WRAPUP:
		ttls_handshake_wrapup(ssl);
		tls->state = TTLS_HANDSHAKE_OVER;
		break;

	   default:
		   T_DBG("invalid state %d\n", ssl->state);
		   return(TTLS_ERR_BAD_INPUT_DATA);
   }

	return ret;
}
#endif /* TTLS_CLI_C */
