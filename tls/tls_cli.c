/*
 *  SSLv3/TLSv1 client-side functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "config.h"

#if defined(TTLS_CLI_C)

#include "debug.h"
#include "ttls.h"
#include "ssl_internal.h"

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
	const unsigned char *end = ssl->out_msg + TTLS_MAX_CONTENT_LEN;
	size_t hostname_len;

	*olen = 0;

	if (ssl->hostname == NULL)
		return;

	TTLS_DEBUG_MSG(3, ("client hello, adding server name extension: %s",
				   ssl->hostname));

	hostname_len = strlen(ssl->hostname);

	if (end < p || (size_t)(end - p) < hostname_len + 9)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small"));
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
#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
static void ssl_write_signature_algorithms_ext(ttls_context *ssl,
		unsigned char *buf,
		size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TTLS_MAX_CONTENT_LEN;
	size_t sig_alg_len = 0;
	const int *md;
	unsigned char *sig_alg_list = buf + 6;

	*olen = 0;

	if (ssl->conf->max_minor_ver != TTLS_MINOR_VERSION_3)
		return;

	TTLS_DEBUG_MSG(3, ("client hello, adding signature_algorithms extension"));

	for (md = ssl->conf->sig_hashes; *md != TTLS_MD_NONE; md++)
	{
#if defined(TTLS_ECDSA_C)
		sig_alg_len += 2;
#endif
		sig_alg_len += 2;
	}

	if (end < p || (size_t)(end - p) < sig_alg_len + 6)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small"));
		return;
	}

	/*
	 * Prepare signature_algorithms extension (TLS 1.2)
	 */
	sig_alg_len = 0;

	for (md = ssl->conf->sig_hashes; *md != TTLS_MD_NONE; md++)
	{
#if defined(TTLS_ECDSA_C)
		sig_alg_list[sig_alg_len++] = ttls_hash_from_md_alg(*md);
		sig_alg_list[sig_alg_len++] = TTLS_SIG_ECDSA;
#endif
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
#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static void ssl_write_supported_elliptic_curves_ext(ttls_context *ssl,
		 unsigned char *buf,
		 size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TTLS_MAX_CONTENT_LEN;
	unsigned char *elliptic_curve_list = p + 6;
	size_t elliptic_curve_len = 0;
	const ttls_ecp_curve_info *info;
	const ttls_ecp_group_id *grp_id;

	*olen = 0;

	TTLS_DEBUG_MSG(3, ("client hello, adding supported_elliptic_curves extension"));

	for (grp_id = ssl->conf->curve_list; *grp_id != TTLS_ECP_DP_NONE; grp_id++)
	{
		info = ttls_ecp_curve_info_from_grp_id(*grp_id);
		if (info == NULL)
		{
			TTLS_DEBUG_MSG(1, ("invalid curve in ssl configuration"));
			return;
		}

		elliptic_curve_len += 2;
	}

	if (end < p || (size_t)(end - p) < 6 + elliptic_curve_len)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small"));
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
	const unsigned char *end = ssl->out_msg + TTLS_MAX_CONTENT_LEN;

	*olen = 0;

	TTLS_DEBUG_MSG(3, ("client hello, adding supported_point_formats extension"));

	if (end < p || (size_t)(end - p) < 6)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small"));
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
#endif /* TTLS_ECDH_C || TTLS_ECDSA_C || 
		  TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static void ssl_write_ecjpake_kkpp_ext(ttls_context *ssl,
		unsigned char *buf,
		size_t *olen)
{
	int ret;
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TTLS_MAX_CONTENT_LEN;
	size_t kkpp_len;

	*olen = 0;

	/* Skip costly extension if we can't use EC J-PAKE anyway */
	if (ttls_ecjpake_check(&ssl->handshake->ecjpake_ctx) != 0)
		return;

	TTLS_DEBUG_MSG(3, ("client hello, adding ecjpake_kkpp extension"));

	if (end - p < 4)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small"));
		return;
	}

	*p++ = (unsigned char)((TTLS_TLS_EXT_ECJPAKE_KKPP >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_ECJPAKE_KKPP	 ) & 0xFF);

	/*
	 * We may need to send ClientHello multiple times for Hello verification.
	 * We don't want to compute fresh values every time (both for performance
	 * and consistency reasons), so cache the extension content.
	 */
	if (ssl->handshake->ecjpake_cache == NULL ||
		ssl->handshake->ecjpake_cache_len == 0)
	{
		TTLS_DEBUG_MSG(3, ("generating new ecjpake parameters"));

		ret = ttls_ecjpake_write_round_one(&ssl->handshake->ecjpake_ctx,
						p + 2, end - p - 2, &kkpp_len,
						ssl->conf->f_rng, ssl->conf->p_rng);
		if (ret != 0)
		{
			TTLS_DEBUG_RET(1 , "ttls_ecjpake_write_round_one", ret);
			return;
		}

		ssl->handshake->ecjpake_cache = ttls_calloc(1, kkpp_len);
		if (ssl->handshake->ecjpake_cache == NULL)
		{
			TTLS_DEBUG_MSG(1, ("allocation failed"));
			return;
		}

		memcpy(ssl->handshake->ecjpake_cache, p + 2, kkpp_len);
		ssl->handshake->ecjpake_cache_len = kkpp_len;
	}
	else
	{
		TTLS_DEBUG_MSG(3, ("re-using cached ecjpake parameters"));

		kkpp_len = ssl->handshake->ecjpake_cache_len;

		if ((size_t)(end - p - 2) < kkpp_len)
		{
			TTLS_DEBUG_MSG(1, ("buffer too small"));
			return;
		}

		memcpy(p + 2, ssl->handshake->ecjpake_cache, kkpp_len);
	}

	*p++ = (unsigned char)((kkpp_len >> 8) & 0xFF);
	*p++ = (unsigned char)((kkpp_len	 ) & 0xFF);

	*olen = kkpp_len + 4;
}
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_MAX_FRAGMENT_LENGTH)
static void ssl_write_max_fragment_length_ext(ttls_context *ssl,
		unsigned char *buf,
		size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TTLS_MAX_CONTENT_LEN;

	*olen = 0;

	if (ssl->conf->mfl_code == TTLS_MAX_FRAG_LEN_NONE) {
		return;
	}

	TTLS_DEBUG_MSG(3, ("client hello, adding max_fragment_length extension"));

	if (end < p || (size_t)(end - p) < 5)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small"));
		return;
	}

	*p++ = (unsigned char)((TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 1;

	*p++ = ssl->conf->mfl_code;

	*olen = 5;
}
#endif /* TTLS_MAX_FRAGMENT_LENGTH */

static void ssl_write_encrypt_then_mac_ext(ttls_context *ssl,
		unsigned char *buf, size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TTLS_MAX_CONTENT_LEN;

	*olen = 0;

	TTLS_DEBUG_MSG(3, ("client hello, adding encrypt_then_mac "
						"extension"));

	if (end < p || (size_t)(end - p) < 4)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small"));
		return;
	}

	*p++ = (unsigned char)((TTLS_TLS_EXT_ENCRYPT_THEN_MAC >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_ENCRYPT_THEN_MAC	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
}

#if defined(TTLS_EXTENDED_MASTER_SECRET)
static void ssl_write_extended_ms_ext(ttls_context *ssl,
		unsigned char *buf, size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TTLS_MAX_CONTENT_LEN;

	*olen = 0;

	if (ssl->conf->extended_ms == TTLS_EXTENDED_MS_DISABLED ||
		ssl->conf->max_minor_ver == TTLS_MINOR_VERSION_0)
	{
		return;
	}

	TTLS_DEBUG_MSG(3, ("client hello, adding extended_master_secret "
						"extension"));

	if (end < p || (size_t)(end - p) < 4)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small"));
		return;
	}

	*p++ = (unsigned char)((TTLS_TLS_EXT_EXTENDED_MASTER_SECRET >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_EXTENDED_MASTER_SECRET	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
}
#endif /* TTLS_EXTENDED_MASTER_SECRET */

#if defined(TTLS_SESSION_TICKETS)
static void ssl_write_session_ticket_ext(ttls_context *ssl,
		unsigned char *buf, size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TTLS_MAX_CONTENT_LEN;
	size_t tlen = ssl->session_negotiate->ticket_len;

	*olen = 0;

	if (ssl->conf->session_tickets == TTLS_SESSION_TICKETS_DISABLED)
	{
		return;
	}

	TTLS_DEBUG_MSG(3, ("client hello, adding session ticket extension"));

	if (end < p || (size_t)(end - p) < 4 + tlen)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small"));
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

	TTLS_DEBUG_MSG(3, ("sending session ticket of length %d", tlen));

	memcpy(p, ssl->session_negotiate->ticket, tlen);

	*olen += tlen;
}
#endif /* TTLS_SESSION_TICKETS */

static void ssl_write_alpn_ext(ttls_context *ssl,
		unsigned char *buf, size_t *olen)
{
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TTLS_MAX_CONTENT_LEN;
	size_t alpnlen = 0;
	const char **cur;

	*olen = 0;

	if (ssl->conf->alpn_list == NULL)
	{
		return;
	}

	TTLS_DEBUG_MSG(3, ("client hello, adding alpn extension"));

	for (cur = ssl->conf->alpn_list; *cur != NULL; cur++)
		alpnlen += (unsigned char)(strlen(*cur) & 0xFF) + 1;

	if (end < p || (size_t)(end - p) < 6 + alpnlen)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small"));
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

	for (cur = ssl->conf->alpn_list; *cur != NULL; cur++)
	{
		*p = (unsigned char)(strlen(*cur) & 0xFF);
		memcpy(p + 1, *cur, *p);
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
	int ret;
	unsigned char *p = ssl->handshake->randbytes;
	time_t t;

	/*
	 * When responding to a verify request, MUST reuse random (RFC 6347 4.2.1)
	 */
#if defined(TTLS_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_TRANSPORT_DATAGRAM &&
		ssl->handshake->verify_cookie != NULL)
	{
		return 0;
	}
#endif

	t = ttls_time(NULL);
	*p++ = (unsigned char)(t >> 24);
	*p++ = (unsigned char)(t >> 16);
	*p++ = (unsigned char)(t >>  8);
	*p++ = (unsigned char)(t	  );

	TTLS_DEBUG_MSG(3, ("client hello, current time: %lu", t));

	if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, p, 28)) != 0)
		return ret;

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
	const ttls_ciphersuite_t *ciphersuite_info;

	TTLS_DEBUG_MSG(2, ("=> write client hello"));

	if (ssl->conf->f_rng == NULL)
	{
		TTLS_DEBUG_MSG(1, ("no RNG provided"));
		return(TTLS_ERR_NO_RNG);
	}

	ssl->major_ver = ssl->conf->min_major_ver;
	ssl->minor_ver = ssl->conf->min_minor_ver;

	if (ssl->conf->max_major_ver == 0)
	{
		TTLS_DEBUG_MSG(1, ("configured max major version is invalid, "
				"consider using ttls_config_defaults()"));
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

	TTLS_DEBUG_MSG(3, ("client hello, max version: [%d:%d]",
				   buf[4], buf[5]));

	if ((ret = ssl_generate_random(ssl)) != 0)
	{
		TTLS_DEBUG_RET(1, "ssl_generate_random", ret);
		return ret;
	}

	memcpy(p, ssl->handshake->randbytes, 32);
	TTLS_DEBUG_BUF(3, "client hello, random bytes", p, 32);
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
		ret = ssl->conf->f_rng(ssl->conf->p_rng, ssl->session_negotiate->id, 32);

		if (ret != 0)
			return ret;

		ssl->session_negotiate->id_len = n = 32;
	}
#endif /* TTLS_SESSION_TICKETS */

	*p++ = (unsigned char) n;

	for (i = 0; i < n; i++)
		*p++ = ssl->session_negotiate->id[i];

	TTLS_DEBUG_MSG(3, ("client hello, session id len.: %d", n));
	TTLS_DEBUG_BUF(3,   "client hello, session id", buf + 39, n);

	/*
	 * DTLS cookie
	 */
#if defined(TTLS_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_TRANSPORT_DATAGRAM)
	{
		if (ssl->handshake->verify_cookie == NULL)
		{
			TTLS_DEBUG_MSG(3, ("no verify cookie to send"));
			*p++ = 0;
		}
		else
		{
			TTLS_DEBUG_BUF(3, "client hello, cookie",
				  ssl->handshake->verify_cookie,
				  ssl->handshake->verify_cookie_len);

			*p++ = ssl->handshake->verify_cookie_len;
			memcpy(p, ssl->handshake->verify_cookie,
					   ssl->handshake->verify_cookie_len);
			p += ssl->handshake->verify_cookie_len;
		}
	}
#endif

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

#if defined(TTLS_PROTO_DTLS)
		if (ssl->conf->transport == TTLS_TRANSPORT_DATAGRAM &&
			(ciphersuite_info->flags & TTLS_CIPHERSUITE_NODTLS))
			continue;
#endif

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
		if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE &&
			ttls_ecjpake_check(&ssl->handshake->ecjpake_ctx) != 0)
			continue;
#endif

		TTLS_DEBUG_MSG(3, ("client hello, add ciphersuite: %04x",
							ciphersuites[i]));

		n++;
		*p++ = (unsigned char)(ciphersuites[i] >> 8);
		*p++ = (unsigned char)(ciphersuites[i]	 );
	}

	TTLS_DEBUG_MSG(3, ("client hello, got %d ciphersuites (excluding SCSVs)", n));

	/*
	 * Add TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	 */
	TTLS_DEBUG_MSG(3, ("adding EMPTY_RENEGOTIATION_INFO_SCSV"));
	*p++ = (unsigned char)(TTLS_EMPTY_RENEGOTIATION_INFO >> 8);
	*p++ = (unsigned char)(TTLS_EMPTY_RENEGOTIATION_INFO	 );
	n++;

	/* Some versions of OpenSSL don't handle it correctly if not at end */
#if defined(TTLS_FALLBACK_SCSV)
	if (ssl->conf->fallback == TTLS_IS_FALLBACK)
	{
		TTLS_DEBUG_MSG(3, ("adding FALLBACK_SCSV"));
		*p++ = (unsigned char)(TTLS_FALLBACK_SCSV_VALUE >> 8);
		*p++ = (unsigned char)(TTLS_FALLBACK_SCSV_VALUE	 );
		n++;
	}
#endif

	*q++ = (unsigned char)(n >> 7);
	*q++ = (unsigned char)(n << 1);

	offer_compress = 0;

	/*
	 * We don't support compression with DTLS right now: is many records come
	 * in the same datagram, uncompressing one could overwrite the next one.
	 * We don't want to add complexity for handling that case unless there is
	 * an actual need for it.
	 */
#if defined(TTLS_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		offer_compress = 0;
#endif

	if (offer_compress)
	{
		TTLS_DEBUG_MSG(3, ("client hello, compress len.: %d", 2));
		TTLS_DEBUG_MSG(3, ("client hello, compress alg.: %d %d",
			TTLS_COMPRESS_DEFLATE, TTLS_COMPRESS_NULL));

		*p++ = 2;
		*p++ = TTLS_COMPRESS_DEFLATE;
		*p++ = TTLS_COMPRESS_NULL;
	}
	else
	{
		TTLS_DEBUG_MSG(3, ("client hello, compress len.: %d", 1));
		TTLS_DEBUG_MSG(3, ("client hello, compress alg.: %d",
						TTLS_COMPRESS_NULL));

		*p++ = 1;
		*p++ = TTLS_COMPRESS_NULL;
	}

	// First write extensions, then the total length
	//
	ssl_write_hostname_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

	/* Note that TLS_EMPTY_RENEGOTIATION_INFO_SCSV is always added
	 * even if there is no renegotiation is not defined. */

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
	ssl_write_signature_algorithms_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	ssl_write_supported_elliptic_curves_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

	ssl_write_supported_point_formats_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	ssl_write_ecjpake_kkpp_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_MAX_FRAGMENT_LENGTH)
	ssl_write_max_fragment_length_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

	ssl_write_encrypt_then_mac_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

#if defined(TTLS_EXTENDED_MASTER_SECRET)
	ssl_write_extended_ms_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

	ssl_write_alpn_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

#if defined(TTLS_SESSION_TICKETS)
	ssl_write_session_ticket_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

	/* olen unused if all extensions are disabled */
	((void) olen);

	TTLS_DEBUG_MSG(3, ("client hello, total extension length: %d",
				   ext_len));

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

#if defined(TTLS_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		ttls_send_flight_completed(ssl);
#endif

	if ((ret = ttls_write_record(ssl)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_write_record", ret);
		return ret;
	}

	TTLS_DEBUG_MSG(2, ("<= write client hello"));

	return 0;
}

static int ssl_parse_renegotiation_info(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	if (len != 1 || buf[0] != 0x00)
	{
		TTLS_DEBUG_MSG(1, ("non-zero length renegotiation info"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	ssl->secure_renegotiation = TTLS_SECURE_RENEGOTIATION;

	return 0;
}

#if defined(TTLS_MAX_FRAGMENT_LENGTH)
static int ssl_parse_max_fragment_length_ext(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	/*
	 * server should use the extension only if we did,
	 * and if so the server's value should match ours (and len is always 1)
	 */
	if (ssl->conf->mfl_code == TTLS_MAX_FRAG_LEN_NONE ||
		len != 1 ||
		buf[0] != ssl->conf->mfl_code)
	{
		TTLS_DEBUG_MSG(1, ("non-matching max fragment length extension"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	return 0;
}
#endif /* TTLS_MAX_FRAGMENT_LENGTH */

static int ssl_parse_encrypt_then_mac_ext(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	if (len) {
		TTLS_DEBUG_MSG(1, ("non-matching encrypt-then-MAC extension"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	ssl->session_negotiate->encrypt_then_mac = 1;

	return 0;
}

#if defined(TTLS_EXTENDED_MASTER_SECRET)
static int ssl_parse_extended_ms_ext(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	if (ssl->conf->extended_ms == TTLS_EXTENDED_MS_DISABLED ||
		ssl->minor_ver == TTLS_MINOR_VERSION_0 ||
		len != 0)
	{
		TTLS_DEBUG_MSG(1, ("non-matching extended master secret extension"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	((void) buf);

	ssl->handshake->extended_ms = TTLS_EXTENDED_MS_ENABLED;

	return 0;
}
#endif /* TTLS_EXTENDED_MASTER_SECRET */

#if defined(TTLS_SESSION_TICKETS)
static int ssl_parse_session_ticket_ext(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	if (ssl->conf->session_tickets == TTLS_SESSION_TICKETS_DISABLED ||
		len != 0)
	{
		TTLS_DEBUG_MSG(1, ("non-matching session ticket extension"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	((void) buf);

	ssl->handshake->new_session_ticket = 1;

	return 0;
}
#endif /* TTLS_SESSION_TICKETS */

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static int ssl_parse_supported_point_formats_ext(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	size_t list_size;
	const unsigned char *p;

	list_size = buf[0];
	if (list_size + 1 != len)
	{
		TTLS_DEBUG_MSG(1, ("bad server hello message"));
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
#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C)
			ssl->handshake->ecdh_ctx.point_format = p[0];
#endif
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
			ssl->handshake->ecjpake_ctx.point_format = p[0];
#endif
			TTLS_DEBUG_MSG(4, ("point format selected: %d", p[0]));
			return 0;
		}

		list_size--;
		p++;
	}

	TTLS_DEBUG_MSG(1, ("no point format in common"));
	ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
	return(TTLS_ERR_BAD_HS_SERVER_HELLO);
}
#endif /* TTLS_ECDH_C || TTLS_ECDSA_C || 
		  TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static int ssl_parse_ecjpake_kkpp(ttls_context *ssl,
		const unsigned char *buf,
		size_t len)
{
	int ret;

	if (ssl->transform_negotiate->ciphersuite_info->key_exchange !=
		TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		TTLS_DEBUG_MSG(3, ("skip ecjpake kkpp extension"));
		return 0;
	}

	/* If we got here, we no longer need our cached extension */
	ttls_free(ssl->handshake->ecjpake_cache);
	ssl->handshake->ecjpake_cache = NULL;
	ssl->handshake->ecjpake_cache_len = 0;

	if ((ret = ttls_ecjpake_read_round_one(&ssl->handshake->ecjpake_ctx,
						buf, len)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_ecjpake_read_round_one", ret);
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return ret;
	}

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

static int ssl_parse_alpn_ext(ttls_context *ssl,
		const unsigned char *buf, size_t len)
{
	size_t list_len, name_len;
	const char **p;

	/* If we didn't send it, the server shouldn't send it */
	if (ssl->conf->alpn_list == NULL)
	{
		TTLS_DEBUG_MSG(1, ("non-matching ALPN extension"));
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
	for (p = ssl->conf->alpn_list; *p != NULL; p++)
	{
		if (name_len == strlen(*p) &&
			memcmp(buf + 3, *p, name_len) == 0)
		{
			ssl->alpn_chosen = *p;
			return 0;
		}
	}

	TTLS_DEBUG_MSG(1, ("ALPN extension: no matching protocol"));
	ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
	return(TTLS_ERR_BAD_HS_SERVER_HELLO);
}

/*
 * Parse HelloVerifyRequest.  Only called after verifying the HS type.
 */
#if defined(TTLS_PROTO_DTLS)
static int ssl_parse_hello_verify_request(ttls_context *ssl)
{
	const unsigned char *p = ssl->in_msg + ttls_hs_hdr_len(ssl);
	int major_ver, minor_ver;
	unsigned char cookie_len;

	TTLS_DEBUG_MSG(2, ("=> parse hello verify request"));

	/*
	 * struct {
	 *   ProtocolVersion server_version;
	 *   opaque cookie<0..2^8-1>;
	 * } HelloVerifyRequest;
	 */
	TTLS_DEBUG_BUF(3, "server version", p, 2);
	ttls_read_version(&major_ver, &minor_ver, ssl->conf->transport, p);
	p += 2;

	/*
	 * Since the RFC is not clear on this point, accept DTLS 1.0 (TLS 1.1)
	 * even is lower than our min version.
	 */
	if (major_ver < TTLS_MAJOR_VERSION_3 ||
		minor_ver < TTLS_MINOR_VERSION_2 ||
		major_ver > ssl->conf->max_major_ver  ||
		minor_ver > ssl->conf->max_minor_ver )
	{
		TTLS_DEBUG_MSG(1, ("bad server version"));

		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					 TTLS_ALERT_MSG_PROTOCOL_VERSION);

		return(TTLS_ERR_BAD_HS_PROTOCOL_VERSION);
	}

	cookie_len = *p++;
	TTLS_DEBUG_BUF(3, "cookie", p, cookie_len);

	if ((ssl->in_msg + ssl->in_msglen) - p < cookie_len)
	{
		TTLS_DEBUG_MSG(1,
			("cookie length does not match incoming message size"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	ttls_free(ssl->handshake->verify_cookie);

	ssl->handshake->verify_cookie = ttls_calloc(1, cookie_len);
	if (ssl->handshake->verify_cookie  == NULL)
	{
		TTLS_DEBUG_MSG(1, ("alloc failed (%d bytes)", cookie_len));
		return(TTLS_ERR_ALLOC_FAILED);
	}

	memcpy(ssl->handshake->verify_cookie, p, cookie_len);
	ssl->handshake->verify_cookie_len = cookie_len;

	/* Start over at ClientHello */
	ssl->state = TTLS_CLIENT_HELLO;
	ttls_reset_checksum(ssl);

	ttls_recv_flight_completed(ssl);

	TTLS_DEBUG_MSG(2, ("<= parse hello verify request"));

	return 0;
}
#endif /* TTLS_PROTO_DTLS */

static int ssl_parse_server_hello(ttls_context *ssl)
{
	int ret, i;
	size_t n;
	size_t ext_len;
	unsigned char *buf, *ext;
	unsigned char comp;
	int handshake_failure = 0;
	const ttls_ciphersuite_t *suite_info;

	TTLS_DEBUG_MSG(2, ("=> parse server hello"));

	buf = ssl->in_msg;

	if ((ret = ttls_read_record(ssl)) != 0)
	{
		/* No alert on a read error. */
		TTLS_DEBUG_RET(1, "ttls_read_record", ret);
		return ret;
	}

	if (ssl->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		TTLS_DEBUG_MSG(1, ("bad server hello message"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

#if defined(TTLS_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_TRANSPORT_DATAGRAM)
	{
		if (buf[0] == TTLS_HS_HELLO_VERIFY_REQUEST)
		{
			TTLS_DEBUG_MSG(2, ("received hello verify request"));
			TTLS_DEBUG_MSG(2, ("<= parse server hello"));
			return(ssl_parse_hello_verify_request(ssl));
		}
		else
		{
			/* We made it through the verification process */
			ttls_free(ssl->handshake->verify_cookie);
			ssl->handshake->verify_cookie = NULL;
			ssl->handshake->verify_cookie_len = 0;
		}
	}
#endif /* TTLS_PROTO_DTLS */

	if (ssl->in_hslen < 38 + ttls_hs_hdr_len(ssl) ||
		buf[0] != TTLS_HS_SERVER_HELLO)
	{
		TTLS_DEBUG_MSG(1, ("bad server hello message"));
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
	buf += ttls_hs_hdr_len(ssl);

	TTLS_DEBUG_BUF(3, "server hello, version", buf + 0, 2);
	ttls_read_version(&ssl->major_ver, &ssl->minor_ver,
				  ssl->conf->transport, buf + 0);

	if (ssl->major_ver < ssl->conf->min_major_ver ||
		ssl->minor_ver < ssl->conf->min_minor_ver ||
		ssl->major_ver > ssl->conf->max_major_ver ||
		ssl->minor_ver > ssl->conf->max_minor_ver)
	{
		TTLS_DEBUG_MSG(1, ("server version out of bounds - "
					" min: [%d:%d], server: [%d:%d], max: [%d:%d]",
					ssl->conf->min_major_ver, ssl->conf->min_minor_ver,
					ssl->major_ver, ssl->minor_ver,
					ssl->conf->max_major_ver, ssl->conf->max_minor_ver));

		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					 TTLS_ALERT_MSG_PROTOCOL_VERSION);

		return(TTLS_ERR_BAD_HS_PROTOCOL_VERSION);
	}

	TTLS_DEBUG_MSG(3, ("server hello, current time: %lu",
			   ((uint32_t) buf[2] << 24) |
			   ((uint32_t) buf[3] << 16) |
			   ((uint32_t) buf[4] <<  8) |
			   ((uint32_t) buf[5]	  )));

	memcpy(ssl->handshake->randbytes + 32, buf + 2, 32);

	n = buf[34];

	TTLS_DEBUG_BUF(3,   "server hello, random bytes", buf + 2, 32);

	if (n > 32)
	{
		TTLS_DEBUG_MSG(1, ("bad server hello message"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	if (ssl->in_hslen > ttls_hs_hdr_len(ssl) + 39 + n)
	{
		ext_len = ((buf[38 + n] <<  8)
				  | (buf[39 + n]	  ));

		if ((ext_len > 0 && ext_len < 4) ||
			ssl->in_hslen != ttls_hs_hdr_len(ssl) + 40 + n + ext_len)
		{
			TTLS_DEBUG_MSG(1, ("bad server hello message"));
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_SERVER_HELLO);
		}
	}
	else if (ssl->in_hslen == ttls_hs_hdr_len(ssl) + 38 + n)
	{
		ext_len = 0;
	}
	else
	{
		TTLS_DEBUG_MSG(1, ("bad server hello message"));
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
		TTLS_DEBUG_MSG(1, ("server hello, bad compression: %d", comp));
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
		TTLS_DEBUG_MSG(1, ("ciphersuite info for %04x not found", i));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_INTERNAL_ERROR);
		return(TTLS_ERR_BAD_INPUT_DATA);
	}

	ttls_optimize_checksum(ssl, ssl->transform_negotiate->ciphersuite_info);

	TTLS_DEBUG_MSG(3, ("server hello, session id len.: %d", n));
	TTLS_DEBUG_BUF(3,   "server hello, session id", buf + 35, n);

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
		ssl->session_negotiate->start = ttls_time(NULL);
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
			TTLS_DEBUG_RET(1, "ttls_derive_keys", ret);
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_INTERNAL_ERROR);
			return ret;
		}
	}

	TTLS_DEBUG_MSG(3, ("%s session has been resumed",
				   ssl->handshake->resume ? "a" : "no"));

	TTLS_DEBUG_MSG(3, ("server hello, chosen ciphersuite: %04x", i));
	TTLS_DEBUG_MSG(3, ("server hello, compress alg.: %d", buf[37 + n]));

	suite_info = ttls_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);
	if (!suite_info) {
		TTLS_DEBUG_MSG(1, ("bad server hello message"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	TTLS_DEBUG_MSG(3, ("server hello, chosen ciphersuite: %s", suite_info->name));

	i = 0;
	while (1)
	{
		if (ssl->conf->ciphersuite_list[ssl->minor_ver][i] == 0)
		{
			TTLS_DEBUG_MSG(1, ("bad server hello message"));
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
		TTLS_DEBUG_MSG(1, ("bad server hello message"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}
	ssl->session_negotiate->compression = comp;

	ext = buf + 40 + n;

	TTLS_DEBUG_MSG(2, ("server hello, total extension length: %d", ext_len));

	while (ext_len)
	{
		unsigned int ext_id   = ((ext[0] <<  8)
					| (ext[1]	  ));
		unsigned int ext_size = ((ext[2] <<  8)
					| (ext[3]	  ));

		if (ext_size + 4 > ext_len)
		{
			TTLS_DEBUG_MSG(1, ("bad server hello message"));
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_SERVER_HELLO);
		}

		switch(ext_id)
		{
		case TTLS_TLS_EXT_RENEGOTIATION_INFO:
			TTLS_DEBUG_MSG(3, ("found renegotiation extension"));

			if ((ret = ssl_parse_renegotiation_info(ssl, ext + 4,
							  ext_size)) != 0)
				return ret;

			break;

#if defined(TTLS_MAX_FRAGMENT_LENGTH)
		case TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
			TTLS_DEBUG_MSG(3, ("found max_fragment_length extension"));

			if ((ret = ssl_parse_max_fragment_length_ext(ssl,
							ext + 4, ext_size)) != 0)
			{
				return ret;
			}

			break;
#endif /* TTLS_MAX_FRAGMENT_LENGTH */

		case TTLS_TLS_EXT_ENCRYPT_THEN_MAC:
			TTLS_DEBUG_MSG(3, ("found encrypt_then_mac extension"));

			if ((ret = ssl_parse_encrypt_then_mac_ext(ssl,
							ext + 4, ext_size)) != 0)
			{
				return ret;
			}

			break;

#if defined(TTLS_EXTENDED_MASTER_SECRET)
		case TTLS_TLS_EXT_EXTENDED_MASTER_SECRET:
			TTLS_DEBUG_MSG(3, ("found extended_master_secret extension"));

			if ((ret = ssl_parse_extended_ms_ext(ssl,
							ext + 4, ext_size)) != 0)
			{
				return ret;
			}

			break;
#endif /* TTLS_EXTENDED_MASTER_SECRET */

#if defined(TTLS_SESSION_TICKETS)
		case TTLS_TLS_EXT_SESSION_TICKET:
			TTLS_DEBUG_MSG(3, ("found session_ticket extension"));

			if ((ret = ssl_parse_session_ticket_ext(ssl,
							ext + 4, ext_size)) != 0)
			{
				return ret;
			}

			break;
#endif /* TTLS_SESSION_TICKETS */

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
		case TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS:
			TTLS_DEBUG_MSG(3, ("found supported_point_formats extension"));

			if ((ret = ssl_parse_supported_point_formats_ext(ssl,
							ext + 4, ext_size)) != 0)
			{
				return ret;
			}

			break;
#endif /* TTLS_ECDH_C || TTLS_ECDSA_C ||
		  TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
		case TTLS_TLS_EXT_ECJPAKE_KKPP:
			TTLS_DEBUG_MSG(3, ("found ecjpake_kkpp extension"));

			if ((ret = ssl_parse_ecjpake_kkpp(ssl,
							ext + 4, ext_size)) != 0)
			{
				return ret;
			}

			break;
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

		case TTLS_TLS_EXT_ALPN:
			TTLS_DEBUG_MSG(3, ("found alpn extension"));

			if ((ret = ssl_parse_alpn_ext(ssl, ext + 4, ext_size)) != 0)
				return ret;

			break;

		default:
			TTLS_DEBUG_MSG(3, ("unknown extension found: %d (ignoring)",
						   ext_id));
		}

		ext_len -= 4 + ext_size;
		ext += 4 + ext_size;

		if (ext_len > 0 && ext_len < 4)
		{
			TTLS_DEBUG_MSG(1, ("bad server hello message"));
			return(TTLS_ERR_BAD_HS_SERVER_HELLO);
		}
	}

	/*
	 * Renegotiation security checks
	 */
	if (ssl->secure_renegotiation == TTLS_LEGACY_RENEGOTIATION &&
		ssl->conf->allow_legacy_renegotiation == TTLS_LEGACY_BREAK_HANDSHAKE)
	{
		TTLS_DEBUG_MSG(1, ("legacy renegotiation, breaking off handshake"));
		handshake_failure = 1;
	}

	if (handshake_failure == 1)
	{
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO);
	}

	TTLS_DEBUG_MSG(2, ("<= parse server hello"));

	return 0;
}

#if defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) ||	   \
	defined(TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
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
	{
		TTLS_DEBUG_RET(2, ("ttls_dhm_read_params"), ret);
		return ret;
	}

	if (ssl->handshake->dhm_ctx.len * 8 < ssl->conf->dhm_min_bitlen)
	{
		TTLS_DEBUG_MSG(1, ("DHM prime too short: %d < %d",
					ssl->handshake->dhm_ctx.len * 8,
					ssl->conf->dhm_min_bitlen));
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	TTLS_DEBUG_MPI(3, "DHM: P ", &ssl->handshake->dhm_ctx.P );
	TTLS_DEBUG_MPI(3, "DHM: G ", &ssl->handshake->dhm_ctx.G );
	TTLS_DEBUG_MPI(3, "DHM: GY", &ssl->handshake->dhm_ctx.GY);

	return ret;
}
#endif /* TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
static int ssl_check_server_ecdh_params(const ttls_context *ssl)
{
	const ttls_ecp_curve_info *curve_info;

	curve_info = ttls_ecp_curve_info_from_grp_id(ssl->handshake->ecdh_ctx.grp.id);
	if (curve_info == NULL)
	{
		TTLS_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	TTLS_DEBUG_MSG(2, ("ECDH curve: %s", curve_info->name));

	if (ttls_check_curve(ssl, ssl->handshake->ecdh_ctx.grp.id) != 0)
		return(-1);

	TTLS_DEBUG_ECP(3, "ECDH: Qp", &ssl->handshake->ecdh_ctx.Qp);

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
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
		TTLS_DEBUG_RET(1, ("ttls_ecdh_read_params"), ret);
		return ret;
	}

	if (ssl_check_server_ecdh_params(ssl) != 0)
	{
		TTLS_DEBUG_MSG(1, ("bad server key exchange message (ECDHE curve)"));
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	return ret;
}
#endif /* TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */

#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
static int ssl_parse_server_psk_hint(ttls_context *ssl,
		  unsigned char **p,
		  unsigned char *end)
{
	int ret = TTLS_ERR_FEATURE_UNAVAILABLE;
	size_t  len;
	((void) ssl);

	/*
	 * PSK parameters:
	 *
	 * opaque psk_identity_hint<0..2^16-1>;
	 */
	if ((*p) > end - 2)
	{
		TTLS_DEBUG_MSG(1, ("bad server key exchange message "
					"(psk_identity_hint length)"));
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}
	len = (*p)[0] << 8 | (*p)[1];
	*p += 2;

	if ((*p) > end - len)
	{
		TTLS_DEBUG_MSG(1, ("bad server key exchange message "
					"(psk_identity_hint length)"));
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	/*
	 * Note: we currently ignore the PKS identity hint, as we only allow one
	 * PSK to be provisionned on the client. This could be changed later if
	 * someone needs that feature.
	 */
	*p += len;
	ret = 0;

	return ret;
}
#endif /* TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_RSA_ENABLED) ||						   \
	defined(TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
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

	if (offset + len_bytes > TTLS_MAX_CONTENT_LEN)
	{
		TTLS_DEBUG_MSG(1, ("buffer too small for encrypted pms"));
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

	if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, p + 2, 46)) != 0)
	{
		TTLS_DEBUG_RET(1, "f_rng", ret);
		return ret;
	}

	ssl->handshake->pmslen = 48;

	if (ssl->session_negotiate->peer_cert == NULL)
	{
		TTLS_DEBUG_MSG(2, ("certificate required"));
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	/*
	 * Now write it out, encrypted
	 */
	if (! ttls_pk_can_do(&ssl->session_negotiate->peer_cert->pk,
				TTLS_PK_RSA))
	{
		TTLS_DEBUG_MSG(1, ("certificate key type mismatch"));
		return(TTLS_ERR_PK_TYPE_MISMATCH);
	}

	if ((ret = ttls_pk_encrypt(&ssl->session_negotiate->peer_cert->pk,
			p, ssl->handshake->pmslen,
			ssl->out_msg + offset + len_bytes, olen,
			TTLS_MAX_CONTENT_LEN - offset - len_bytes,
			ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_rsa_pkcs1_encrypt", ret);
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
#endif /* TTLS_KEY_EXCHANGE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
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
		TTLS_DEBUG_MSG(1, ("Server used unsupported "
					"HashAlgorithm %d", *(p)[0]));
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	/*
	 * Get signature algorithm
	 */
	if ((*pk_alg = ttls_pk_alg_from_sig((*p)[1])) == TTLS_PK_NONE)
	{
		TTLS_DEBUG_MSG(1, ("server used unsupported "
					"SignatureAlgorithm %d", (*p)[1]));
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	/*
	 * Check if the hash is acceptable
	 */
	if (ttls_check_sig_hash(ssl, *md_alg) != 0)
	{
		TTLS_DEBUG_MSG(1, ("server used HashAlgorithm %d that was not offered",
									*(p)[0]));
		return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
	}

	TTLS_DEBUG_MSG(2, ("Server used SignatureAlgorithm %d", (*p)[1]));
	TTLS_DEBUG_MSG(2, ("Server used HashAlgorithm %d", (*p)[0]));
	*p += 2;

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
static int ssl_get_ecdh_params_from_cert(ttls_context *ssl)
{
	int ret;
	const ttls_ecp_keypair *peer_key;

	if (ssl->session_negotiate->peer_cert == NULL)
	{
		TTLS_DEBUG_MSG(2, ("certificate required"));
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	if (! ttls_pk_can_do(&ssl->session_negotiate->peer_cert->pk,
					 TTLS_PK_ECKEY))
	{
		TTLS_DEBUG_MSG(1, ("server key not ECDH capable"));
		return(TTLS_ERR_PK_TYPE_MISMATCH);
	}

	peer_key = ttls_pk_ec(ssl->session_negotiate->peer_cert->pk);

	if ((ret = ttls_ecdh_get_params(&ssl->handshake->ecdh_ctx, peer_key,
					 TTLS_ECDH_THEIRS)) != 0)
	{
		TTLS_DEBUG_RET(1, ("ttls_ecdh_get_params"), ret);
		return ret;
	}

	if (ssl_check_server_ecdh_params(ssl) != 0)
	{
		TTLS_DEBUG_MSG(1, ("bad server certificate (ECDH curve)"));
		return(TTLS_ERR_BAD_HS_CERTIFICATE);
	}

	return ret;
}
#endif /* TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) ||
		  TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED */

static int ssl_parse_server_key_exchange(ttls_context *ssl)
{
	int ret;
	const ttls_ciphersuite_t *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;
	unsigned char *p = NULL, *end = NULL;

	TTLS_DEBUG_MSG(2, ("=> parse server key exchange"));

#if defined(TTLS_KEY_EXCHANGE_RSA_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA)
	{
		TTLS_DEBUG_MSG(2, ("<= skip parse server key exchange"));
		ssl->state++;
		return 0;
	}
	((void) p);
	((void) end);
#endif

#if defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDH_RSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDH_ECDSA)
	{
		if ((ret = ssl_get_ecdh_params_from_cert(ssl)) != 0)
		{
			TTLS_DEBUG_RET(1, "ssl_get_ecdh_params_from_cert", ret);
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
			return ret;
		}

		TTLS_DEBUG_MSG(2, ("<= skip parse server key exchange"));
		ssl->state++;
		return 0;
	}
	((void) p);
	((void) end);
#endif /* TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED */

	if ((ret = ttls_read_record(ssl)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_read_record", ret);
		return ret;
	}

	if (ssl->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		TTLS_DEBUG_MSG(1, ("bad server key exchange message"));
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

		TTLS_DEBUG_MSG(1, ("server key exchange message must "
									"not be skipped"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);

		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	p   = ssl->in_msg + ttls_hs_hdr_len(ssl);
	end = ssl->in_msg + ssl->in_hslen;
	TTLS_DEBUG_BUF(3,   "server key exchange", p, end - p);

#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK)
	{
		if (ssl_parse_server_psk_hint(ssl, &p, end) != 0)
		{
			TTLS_DEBUG_MSG(1, ("bad server key exchange message"));
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
			return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
		}
	} /* FALLTROUGH */
#endif /* TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_PSK_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK)
		; /* nothing more to do */
	else
#endif /* TTLS_KEY_EXCHANGE_PSK_ENABLED ||
		  TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_RSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK)
	{
		if (ssl_parse_server_dh_params(ssl, &p, end) != 0)
		{
			TTLS_DEBUG_MSG(1, ("bad server key exchange message"));
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
			return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_RSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_ECDSA)
	{
		if (ssl_parse_server_ecdh_params(ssl, &p, end) != 0)
		{
			TTLS_DEBUG_MSG(1, ("bad server key exchange message"));
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
			return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		ret = ttls_ecjpake_read_round_two(&ssl->handshake->ecjpake_ctx,
						  p, end - p);
		if (ret != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_ecjpake_read_round_two", ret);
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
			return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
	{
		TTLS_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_INTERNAL_ERROR);
	}

#if defined(TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED)
	if (ttls_ciphersuite_uses_server_signature(ciphersuite_info))
	{
		size_t sig_len, hashlen;
		unsigned char hash[64];
		ttls_md_type_t md_alg = TTLS_MD_NONE;
		ttls_pk_type_t pk_alg = TTLS_PK_NONE;
		unsigned char *params = ssl->in_msg + ttls_hs_hdr_len(ssl);
		size_t params_len = p - params;

		/*
		 * Handle the digitally-signed structure
		 */
		if (ssl->minor_ver == TTLS_MINOR_VERSION_3)
		{
			if (ssl_parse_signature_algorithm(ssl, &p, end,
						   &md_alg, &pk_alg) != 0)
			{
				TTLS_DEBUG_MSG(1, ("bad server key exchange message"));
				ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
							TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
				return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
			}

			if (pk_alg != ttls_get_ciphersuite_sig_pk_alg(ciphersuite_info))
			{
				TTLS_DEBUG_MSG(1, ("bad server key exchange message"));
				ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
							TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
				return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
			}
		}
		else
		{
			TTLS_DEBUG_MSG(1, ("should never happen"));
			return(TTLS_ERR_INTERNAL_ERROR);
		}

		/*
		 * Read signature
		 */

		if (p > end - 2)
		{
			TTLS_DEBUG_MSG(1, ("bad server key exchange message"));
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
		}
		sig_len = (p[0] << 8) | p[1];
		p += 2;

		if (p != end - sig_len)
		{
			TTLS_DEBUG_MSG(1, ("bad server key exchange message"));
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE);
		}

		TTLS_DEBUG_BUF(3, "signature", p, sig_len);

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
			TTLS_DEBUG_MSG(1, ("should never happen"));
			return(TTLS_ERR_INTERNAL_ERROR);
		}

		TTLS_DEBUG_BUF(3, "parameters hash", hash, hashlen != 0 ? hashlen :
			(unsigned int) (ttls_md_get_size(ttls_md_info_from_type(md_alg))));

		if (ssl->session_negotiate->peer_cert == NULL)
		{
			TTLS_DEBUG_MSG(2, ("certificate required"));
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
			return(TTLS_ERR_UNEXPECTED_MESSAGE);
		}

		/*
		 * Verify signature
		 */
		if (! ttls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, pk_alg))
		{
			TTLS_DEBUG_MSG(1, ("bad server key exchange message"));
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
			return(TTLS_ERR_PK_TYPE_MISMATCH);
		}

		if ((ret = ttls_pk_verify(&ssl->session_negotiate->peer_cert->pk,
					   md_alg, hash, hashlen, p, sig_len)) != 0)
		{
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_DECRYPT_ERROR);
			TTLS_DEBUG_RET(1, "ttls_pk_verify", ret);
			return ret;
		}
	}
#endif /* TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED */

exit:
	ssl->state++;

	TTLS_DEBUG_MSG(2, ("<= parse server key exchange"));

	return 0;
}

#if ! defined(TTLS_KEY_EXCHANGE__CERT_REQ_ALLOWED__ENABLED)
static int ssl_parse_certificate_request(ttls_context *ssl)
{
	const ttls_ciphersuite_t *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;

	TTLS_DEBUG_MSG(2, ("=> parse certificate request"));

	if (! ttls_ciphersuite_cert_req_allowed(ciphersuite_info))
	{
		TTLS_DEBUG_MSG(2, ("<= skip parse certificate request"));
		ssl->state++;
		return 0;
	}

	TTLS_DEBUG_MSG(1, ("should never happen"));
	return(TTLS_ERR_INTERNAL_ERROR);
}
#else /* TTLS_KEY_EXCHANGE__CERT_REQ_ALLOWED__ENABLED */
static int ssl_parse_certificate_request(ttls_context *ssl)
{
	int ret;
	unsigned char *buf;
	size_t n = 0;
	size_t cert_type_len = 0, dn_len = 0;
	const ttls_ciphersuite_t *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;

	TTLS_DEBUG_MSG(2, ("=> parse certificate request"));

	if (! ttls_ciphersuite_cert_req_allowed(ciphersuite_info))
	{
		TTLS_DEBUG_MSG(2, ("<= skip parse certificate request"));
		ssl->state++;
		return 0;
	}

	if ((ret = ttls_read_record(ssl)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_read_record", ret);
		return ret;
	}

	if (ssl->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		TTLS_DEBUG_MSG(1, ("bad certificate request message"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_UNEXPECTED_MESSAGE);
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	ssl->state++;
	ssl->client_auth = (ssl->in_msg[0] == TTLS_HS_CERTIFICATE_REQUEST);

	TTLS_DEBUG_MSG(3, ("got %s certificate request",
				ssl->client_auth ? "a" : "no"));

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
	cert_type_len = buf[ttls_hs_hdr_len(ssl)];
	n = cert_type_len;

	if (ssl->in_hslen < ttls_hs_hdr_len(ssl) + 2 + n)
	{
		TTLS_DEBUG_MSG(1, ("bad certificate request message"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_CERTIFICATE_REQUEST);
	}

	/* supported_signature_algorithms */
	if (ssl->minor_ver == TTLS_MINOR_VERSION_3)
	{
		size_t sig_alg_len = ((buf[ttls_hs_hdr_len(ssl) + 1 + n] <<  8)
					 | (buf[ttls_hs_hdr_len(ssl) + 2 + n]));
#if defined(DEBUG) && (DEBUG == 3)
		unsigned char* sig_alg = buf + ttls_hs_hdr_len(ssl) + 3 + n;
		size_t i;

		for (i = 0; i < sig_alg_len; i += 2)
		{
			TTLS_DEBUG_MSG(3, ("Supported Signature Algorithm found: %d"
						",%d", sig_alg[i], sig_alg[i + 1] ));
		}
#endif

		n += 2 + sig_alg_len;

		if (ssl->in_hslen < ttls_hs_hdr_len(ssl) + 2 + n)
		{
			TTLS_DEBUG_MSG(1, ("bad certificate request message"));
			ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_BAD_HS_CERTIFICATE_REQUEST);
		}
	}

	/* certificate_authorities */
	dn_len = ((buf[ttls_hs_hdr_len(ssl) + 1 + n] <<  8)
			 | (buf[ttls_hs_hdr_len(ssl) + 2 + n]	  ));

	n += dn_len;
	if (ssl->in_hslen != ttls_hs_hdr_len(ssl) + 3 + n)
	{
		TTLS_DEBUG_MSG(1, ("bad certificate request message"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_CERTIFICATE_REQUEST);
	}

exit:
	TTLS_DEBUG_MSG(2, ("<= parse certificate request"));

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE__CERT_REQ_ALLOWED__ENABLED */

static int ssl_parse_server_hello_done(ttls_context *ssl)
{
	int ret;

	TTLS_DEBUG_MSG(2, ("=> parse server hello done"));

	if ((ret = ttls_read_record(ssl)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_read_record", ret);
		return ret;
	}

	if (ssl->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		TTLS_DEBUG_MSG(1, ("bad server hello done message"));
		return(TTLS_ERR_UNEXPECTED_MESSAGE);
	}

	if (ssl->in_hslen  != ttls_hs_hdr_len(ssl) ||
		ssl->in_msg[0] != TTLS_HS_SERVER_HELLO_DONE)
	{
		TTLS_DEBUG_MSG(1, ("bad server hello done message"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_SERVER_HELLO_DONE);
	}

	ssl->state++;

#if defined(TTLS_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_TRANSPORT_DATAGRAM)
		ttls_recv_flight_completed(ssl);
#endif

	TTLS_DEBUG_MSG(2, ("<= parse server hello done"));

	return 0;
}

static int ssl_write_client_key_exchange(ttls_context *ssl)
{
	int ret;
	size_t i, n;
	const ttls_ciphersuite_t *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;

	TTLS_DEBUG_MSG(2, ("=> write client key exchange"));

#if defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
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
				&ssl->out_msg[i], n,
				ssl->conf->f_rng, ssl->conf->p_rng);
		if (ret != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_dhm_make_public", ret);
			return ret;
		}

		TTLS_DEBUG_MPI(3, "DHM: X ", &ssl->handshake->dhm_ctx.X );
		TTLS_DEBUG_MPI(3, "DHM: GX", &ssl->handshake->dhm_ctx.GX);

		if ((ret = ttls_dhm_calc_secret(&ssl->handshake->dhm_ctx,
						ssl->handshake->premaster,
						TTLS_PREMASTER_SIZE,
						&ssl->handshake->pmslen,
						ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_dhm_calc_secret", ret);
			return ret;
		}

		TTLS_DEBUG_MPI(3, "DHM: K ", &ssl->handshake->dhm_ctx.K );
	}
	else
#endif /* TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
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
					&n,
					&ssl->out_msg[i], 1000,
					ssl->conf->f_rng, ssl->conf->p_rng);
		if (ret != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_ecdh_make_public", ret);
			return ret;
		}

		TTLS_DEBUG_ECP(3, "ECDH: Q", &ssl->handshake->ecdh_ctx.Q);

		if ((ret = ttls_ecdh_calc_secret(&ssl->handshake->ecdh_ctx,
					  &ssl->handshake->pmslen,
					   ssl->handshake->premaster,
					   TTLS_MPI_MAX_SIZE,
					   ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_ecdh_calc_secret", ret);
			return ret;
		}

		TTLS_DEBUG_MPI(3, "ECDH: z", &ssl->handshake->ecdh_ctx.z);
	}
	else
#endif /* TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED */
#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	if (ttls_ciphersuite_uses_psk(ciphersuite_info))
	{
		/*
		 * opaque psk_identity<0..2^16-1>;
		 */
		if (ssl->conf->psk == NULL || ssl->conf->psk_identity == NULL)
		{
			TTLS_DEBUG_MSG(1, ("got no private key for PSK"));
			return(TTLS_ERR_PRIVATE_KEY_REQUIRED);
		}

		i = 4;
		n = ssl->conf->psk_identity_len;

		if (i + 2 + n > TTLS_MAX_CONTENT_LEN)
		{
			TTLS_DEBUG_MSG(1, ("psk identity too long or "
						"SSL buffer too short"));
			return(TTLS_ERR_BUFFER_TOO_SMALL);
		}

		ssl->out_msg[i++] = (unsigned char)(n >> 8);
		ssl->out_msg[i++] = (unsigned char)(n	 );

		memcpy(ssl->out_msg + i, ssl->conf->psk_identity, ssl->conf->psk_identity_len);
		i += ssl->conf->psk_identity_len;

#if defined(TTLS_KEY_EXCHANGE_PSK_ENABLED)
		if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK)
		{
			n = 0;
		}
		else
#endif
#if defined(TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
		if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK)
		{
			if ((ret = ssl_write_encrypted_pms(ssl, i, &n, 2)) != 0)
				return ret;
		}
		else
#endif
#if defined(TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
		if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK)
		{
			/*
			 * ClientDiffieHellmanPublic public (DHM send G^X mod P)
			 */
			n = ssl->handshake->dhm_ctx.len;

			if (i + 2 + n > TTLS_MAX_CONTENT_LEN)
			{
				TTLS_DEBUG_MSG(1, ("psk identity or DHM size too long"
							" or SSL buffer too short"));
				return(TTLS_ERR_BUFFER_TOO_SMALL);
			}

			ssl->out_msg[i++] = (unsigned char)(n >> 8);
			ssl->out_msg[i++] = (unsigned char)(n	 );

			ret = ttls_dhm_make_public(&ssl->handshake->dhm_ctx,
					(int) ttls_mpi_size(&ssl->handshake->dhm_ctx.P),
					&ssl->out_msg[i], n,
					ssl->conf->f_rng, ssl->conf->p_rng);
			if (ret != 0)
			{
				TTLS_DEBUG_RET(1, "ttls_dhm_make_public", ret);
				return ret;
			}
		}
		else
#endif /* TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
		if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK)
		{
			/*
			 * ClientECDiffieHellmanPublic public;
			 */
			ret = ttls_ecdh_make_public(&ssl->handshake->ecdh_ctx, &n,
					&ssl->out_msg[i], TTLS_MAX_CONTENT_LEN - i,
					ssl->conf->f_rng, ssl->conf->p_rng);
			if (ret != 0)
			{
				TTLS_DEBUG_RET(1, "ttls_ecdh_make_public", ret);
				return ret;
			}

			TTLS_DEBUG_ECP(3, "ECDH: Q", &ssl->handshake->ecdh_ctx.Q);
		}
		else
#endif /* TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */
		{
			TTLS_DEBUG_MSG(1, ("should never happen"));
			return(TTLS_ERR_INTERNAL_ERROR);
		}

		if ((ret = ttls_psk_derive_premaster(ssl,
						ciphersuite_info->key_exchange)) != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_psk_derive_premaster", ret);
			return ret;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_RSA_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA)
	{
		i = 4;
		if ((ret = ssl_write_encrypted_pms(ssl, i, &n, 0)) != 0)
			return ret;
	}
	else
#endif /* TTLS_KEY_EXCHANGE_RSA_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		i = 4;

		ret = ttls_ecjpake_write_round_two(&ssl->handshake->ecjpake_ctx,
				ssl->out_msg + i, TTLS_MAX_CONTENT_LEN - i, &n,
				ssl->conf->f_rng, ssl->conf->p_rng);
		if (ret != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_ecjpake_write_round_two", ret);
			return ret;
		}

		ret = ttls_ecjpake_derive_secret(&ssl->handshake->ecjpake_ctx,
				ssl->handshake->premaster, 32, &ssl->handshake->pmslen,
				ssl->conf->f_rng, ssl->conf->p_rng);
		if (ret != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_ecjpake_derive_secret", ret);
			return ret;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_RSA_ENABLED */
	{
		((void) ciphersuite_info);
		TTLS_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	ssl->out_msglen  = i + n;
	ssl->out_msgtype = TTLS_MSG_HANDSHAKE;
	ssl->out_msg[0]  = TTLS_HS_CLIENT_KEY_EXCHANGE;

	ssl->state++;

	if ((ret = ttls_write_record(ssl)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_write_record", ret);
		return ret;
	}

	TTLS_DEBUG_MSG(2, ("<= write client key exchange"));

	return 0;
}

#if !defined(TTLS_KEY_EXCHANGE_RSA_ENABLED)	   && \
	!defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)   && \
	!defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)  && \
	!defined(TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) && \
	!defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)&& \
	!defined(TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_write_certificate_verify(ttls_context *ssl)
{
	const ttls_ciphersuite_t *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;
	int ret;

	TTLS_DEBUG_MSG(2, ("=> write certificate verify"));

	if ((ret = ttls_derive_keys(ssl)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_derive_keys", ret);
		return ret;
	}

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		TTLS_DEBUG_MSG(2, ("<= skip write certificate verify"));
		ssl->state++;
		return 0;
	}

	TTLS_DEBUG_MSG(1, ("should never happen"));
	return(TTLS_ERR_INTERNAL_ERROR);
}
#else
static int ssl_write_certificate_verify(ttls_context *ssl)
{
	int ret = TTLS_ERR_FEATURE_UNAVAILABLE;
	const ttls_ciphersuite_t *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;
	size_t n = 0, offset = 0;
	unsigned char hash[48];
	unsigned char *hash_start = hash;
	ttls_md_type_t md_alg = TTLS_MD_NONE;
	unsigned int hashlen;

	TTLS_DEBUG_MSG(2, ("=> write certificate verify"));

	if ((ret = ttls_derive_keys(ssl)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_derive_keys", ret);
		return ret;
	}

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		TTLS_DEBUG_MSG(2, ("<= skip write certificate verify"));
		ssl->state++;
		return 0;
	}

	if (ssl->client_auth == 0 || ttls_own_cert(ssl) == NULL)
	{
		TTLS_DEBUG_MSG(2, ("<= skip write certificate verify"));
		ssl->state++;
		return 0;
	}

	if (ttls_own_key(ssl) == NULL)
	{
		TTLS_DEBUG_MSG(1, ("got no private key for certificate"));
		return(TTLS_ERR_PRIVATE_KEY_REQUIRED);
	}

	/*
	 * Make an RSA signature of the handshake digests
	 */
	ssl->handshake->calc_verify(ssl, hash);

	if (ssl->minor_ver == TTLS_MINOR_VERSION_3)
	{
		/*
		 * digitally-signed struct {
		 *	 opaque handshake_messages[handshake_messages_length];
		 * };
		 *
		 * Taking shortcut here. We assume that the server always allows the
		 * PRF Hash function and has sent it in the allowed signature
		 * algorithms list received in the Certificate Request message.
		 *
		 * Until we encounter a server that does not, we will take this
		 * shortcut.
		 *
		 * Reason: Otherwise we should have running hashes for SHA512 and SHA224
		 *		 in order to satisfy 'weird' needs from the server side.
		 */
		if (ssl->transform_negotiate->ciphersuite_info->mac ==
			TTLS_MD_SHA384)
		{
			md_alg = TTLS_MD_SHA384;
			ssl->out_msg[4] = TTLS_HASH_SHA384;
		}
		else
		{
			md_alg = TTLS_MD_SHA256;
			ssl->out_msg[4] = TTLS_HASH_SHA256;
		}
		ssl->out_msg[5] = ttls_sig_from_pk(ttls_own_key(ssl));

		/* Info from md_alg will be used instead */
		hashlen = 0;
		offset = 2;
	}
	else
	{
		TTLS_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	if ((ret = ttls_pk_sign(ttls_own_key(ssl), md_alg, hash_start, hashlen,
						 ssl->out_msg + 6 + offset, &n,
						 ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_pk_sign", ret);
		return ret;
	}

	ssl->out_msg[4 + offset] = (unsigned char)(n >> 8);
	ssl->out_msg[5 + offset] = (unsigned char)(n	 );

	ssl->out_msglen  = 6 + n + offset;
	ssl->out_msgtype = TTLS_MSG_HANDSHAKE;
	ssl->out_msg[0]  = TTLS_HS_CERTIFICATE_VERIFY;

	ssl->state++;

	if ((ret = ttls_write_record(ssl)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_write_record", ret);
		return ret;
	}

	TTLS_DEBUG_MSG(2, ("<= write certificate verify"));

	return ret;
}
#endif /* !TTLS_KEY_EXCHANGE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

#if defined(TTLS_SESSION_TICKETS)
static int ssl_parse_new_session_ticket(ttls_context *ssl)
{
	int ret;
	uint32_t lifetime;
	size_t ticket_len;
	unsigned char *ticket;
	const unsigned char *msg;

	TTLS_DEBUG_MSG(2, ("=> parse new session ticket"));

	if ((ret = ttls_read_record(ssl)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_read_record", ret);
		return ret;
	}

	if (ssl->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		TTLS_DEBUG_MSG(1, ("bad new session ticket message"));
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
		ssl->in_hslen < 6 + ttls_hs_hdr_len(ssl))
	{
		TTLS_DEBUG_MSG(1, ("bad new session ticket message"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_NEW_SESSION_TICKET);
	}

	msg = ssl->in_msg + ttls_hs_hdr_len(ssl);

	lifetime = (msg[0] << 24) | (msg[1] << 16) |
			   (msg[2] <<  8) | (msg[3]	  );

	ticket_len = (msg[4] << 8) | (msg[5]);

	if (ticket_len + 6 + ttls_hs_hdr_len(ssl) != ssl->in_hslen)
	{
		TTLS_DEBUG_MSG(1, ("bad new session ticket message"));
		ttls_send_alert_msg(ssl, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_BAD_HS_NEW_SESSION_TICKET);
	}

	TTLS_DEBUG_MSG(3, ("ticket length: %d", ticket_len));

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
		TTLS_DEBUG_MSG(1, ("ticket alloc failed"));
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
	TTLS_DEBUG_MSG(3, ("ticket in use, discarding session id"));
	ssl->session_negotiate->id_len = 0;

	TTLS_DEBUG_MSG(2, ("<= parse new session ticket"));

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

	TTLS_DEBUG_MSG(2, ("client state: %d", ssl->state));

#if defined(TTLS_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_TRANSPORT_DATAGRAM &&
		ssl->handshake->retransmit_state == TTLS_RETRANS_SENDING)
	{
		if ((ret = ttls_resend(ssl)) != 0)
			return ret;
	}
#endif

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
	   case TTLS_CLIENT_CERTIFICATE:
		   ret = ttls_write_certificate(ssl);
		   break;

	   case TTLS_CLIENT_KEY_EXCHANGE:
		   ret = ssl_write_client_key_exchange(ssl);
		   break;

	   case TTLS_CERTIFICATE_VERIFY:
		   ret = ssl_write_certificate_verify(ssl);
		   break;

	   case TTLS_CLIENT_CHANGE_CIPHER_SPEC:
		   ret = ttls_write_change_cipher_spec(ssl);
		   break;

	   case TTLS_CLIENT_FINISHED:
		   ret = ttls_write_finished(ssl);
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
		   break;

	   case TTLS_FLUSH_BUFFERS:
		   TTLS_DEBUG_MSG(2, ("handshake: done"));
		   ssl->state = TTLS_HANDSHAKE_WRAPUP;
		   break;

	   case TTLS_HANDSHAKE_WRAPUP:
		   ttls_handshake_wrapup(ssl);
		   break;

	   default:
		   TTLS_DEBUG_MSG(1, ("invalid state %d", ssl->state));
		   return(TTLS_ERR_BAD_INPUT_DATA);
   }

	return ret;
}
#endif /* TTLS_CLI_C */
