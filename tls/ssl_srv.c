/*
 *  SSLv3/TLSv1 server-side functions
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#include "config.h"
#include "debug.h"
#include "ssl.h"
#include "ssl_internal.h"
#include "ecp.h"

#if defined(TTLS_SSL_SESSION_TICKETS)
/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}
#endif

#if defined(TTLS_SSL_DTLS_HELLO_VERIFY)
int ttls_ssl_set_client_transport_id(ttls_ssl_context *ssl,
					 const unsigned char *info,
					 size_t ilen)
{
	if (ssl->conf->endpoint != TTLS_SSL_IS_SERVER)
		return(TTLS_ERR_SSL_BAD_INPUT_DATA);

	ttls_free(ssl->cli_id);

	if ((ssl->cli_id = ttls_calloc(1, ilen)) == NULL)
		return(TTLS_ERR_SSL_ALLOC_FAILED);

	memcpy(ssl->cli_id, info, ilen);
	ssl->cli_id_len = ilen;

	return 0;
}

void ttls_ssl_conf_dtls_cookies(ttls_ssl_config *conf,
				   ttls_ssl_cookie_write_t *f_cookie_write,
				   ttls_ssl_cookie_check_t *f_cookie_check,
				   void *p_cookie)
{
	conf->f_cookie_write = f_cookie_write;
	conf->f_cookie_check = f_cookie_check;
	conf->p_cookie	   = p_cookie;
}
#endif /* TTLS_SSL_DTLS_HELLO_VERIFY */

static int ssl_parse_servername_ext(ttls_ssl_context *ssl,
				 const unsigned char *buf,
				 size_t len)
{
	int ret;
	size_t servername_list_size, hostname_len;
	const unsigned char *p;

	TTLS_SSL_DEBUG_MSG(3, ("parse ServerName extension"));

	servername_list_size = ((buf[0] << 8) | (buf[1]));
	if (servername_list_size + 2 != len)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	p = buf + 2;
	while (servername_list_size > 0)
	{
		hostname_len = ((p[1] << 8) | p[2]);
		if (hostname_len + 3 > servername_list_size)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
			ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}

		if (p[0] == TTLS_TLS_EXT_SERVERNAME_HOSTNAME)
		{
			ret = ssl->conf->f_sni(ssl->conf->p_sni,
						ssl, p + 3, hostname_len);
			if (ret != 0)
			{
				TTLS_SSL_DEBUG_RET(1, "ssl_sni_wrapper", ret);
				ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME);
				return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
			}
			return 0;
		}

		servername_list_size -= hostname_len + 3;
		p += hostname_len + 3;
	}

	if (servername_list_size != 0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	return 0;
}

static int ssl_parse_renegotiation_info(ttls_ssl_context *ssl,
					 const unsigned char *buf,
					 size_t len)
{
	if (len != 1 || buf[0] != 0x0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("non-zero length renegotiation info"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	ssl->secure_renegotiation = TTLS_SSL_SECURE_RENEGOTIATION;

	return 0;
}

#if defined(TTLS_SSL_PROTO_TLS1_2) && \
	defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

/*
 * Status of the implementation of signature-algorithms extension:
 *
 * Currently, we are only considering the signature-algorithm extension
 * to pick a ciphersuite which allows us to send the ServerKeyExchange
 * message with a signature-hash combination that the user allows.
 *
 * We do *not* check whether all certificates in our certificate
 * chain are signed with an allowed signature-hash pair.
 * This needs to be done at a later stage.
 *
 */
static int ssl_parse_signature_algorithms_ext(ttls_ssl_context *ssl,
					   const unsigned char *buf,
					   size_t len)
{
	size_t sig_alg_list_size;

	const unsigned char *p;
	const unsigned char *end = buf + len;

	ttls_md_type_t md_cur;
	ttls_pk_type_t sig_cur;

	sig_alg_list_size = ((buf[0] << 8) | (buf[1]));
	if (sig_alg_list_size + 2 != len ||
		sig_alg_list_size % 2 != 0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/* Currently we only guarantee signing the ServerKeyExchange message according
	 * to the constraints specified in this extension (see above), so it suffices
	 * to remember only one suitable hash for each possible signature algorithm.
	 *
	 * This will change when we also consider certificate signatures,
	 * in which case we will need to remember the whole signature-hash
	 * pair list from the extension.
	 */

	for (p = buf + 2; p < end; p += 2)
	{
		/* Silently ignore unknown signature or hash algorithms. */

		if ((sig_cur = ttls_ssl_pk_alg_from_sig(p[1])) == TTLS_PK_NONE)
		{
			TTLS_SSL_DEBUG_MSG(3, ("client hello v3, signature_algorithm ext"
						" unknown sig alg encoding %d", p[1]));
			continue;
		}

		/* Check if we support the hash the user proposes */
		md_cur = ttls_ssl_md_alg_from_hash(p[0]);
		if (md_cur == TTLS_MD_NONE)
		{
			TTLS_SSL_DEBUG_MSG(3, ("client hello v3, signature_algorithm ext:"
						" unknown hash alg encoding %d", p[0]));
			continue;
		}

		if (ttls_ssl_check_sig_hash(ssl, md_cur) == 0)
		{
			ttls_ssl_sig_hash_set_add(&ssl->handshake->hash_algs, sig_cur, md_cur);
			TTLS_SSL_DEBUG_MSG(3, ("client hello v3, signature_algorithm ext:"
						" match sig %d and hash %d",
						sig_cur, md_cur));
		}
		else
		{
			TTLS_SSL_DEBUG_MSG(3, ("client hello v3, signature_algorithm ext: "
						"hash alg %d not supported", md_cur));
		}
	}

	return 0;
}
#endif /* TTLS_SSL_PROTO_TLS1_2 &&
		  TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static int ssl_parse_supported_elliptic_curves(ttls_ssl_context *ssl,
						const unsigned char *buf,
						size_t len)
{
	size_t list_size, our_size;
	const unsigned char *p;
	const ttls_ecp_curve_info *curve_info, **curves;

	list_size = ((buf[0] << 8) | (buf[1]));
	if (list_size + 2 != len ||
		list_size % 2 != 0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/* Should never happen unless client duplicates the extension */
	if (ssl->handshake->curves != NULL)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/* Don't allow our peer to make us allocate too much memory,
	 * and leave room for a final 0 */
	our_size = list_size / 2 + 1;
	if (our_size > TTLS_ECP_DP_MAX)
		our_size = TTLS_ECP_DP_MAX;

	if ((curves = ttls_calloc(our_size, sizeof(*curves))) == NULL)
	{
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
		return(TTLS_ERR_SSL_ALLOC_FAILED);
	}

	ssl->handshake->curves = curves;

	p = buf + 2;
	while (list_size > 0 && our_size > 1)
	{
		curve_info = ttls_ecp_curve_info_from_tls_id((p[0] << 8) | p[1]);

		if (curve_info != NULL)
		{
			*curves++ = curve_info;
			our_size--;
		}

		list_size -= 2;
		p += 2;
	}

	return 0;
}

static int ssl_parse_supported_point_formats(ttls_ssl_context *ssl,
					  const unsigned char *buf,
					  size_t len)
{
	size_t list_size;
	const unsigned char *p;

	list_size = buf[0];
	if (list_size + 1 != len)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
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
			TTLS_SSL_DEBUG_MSG(4, ("point format selected: %d", p[0]));
			return 0;
		}

		list_size--;
		p++;
	}

	return 0;
}
#endif /* TTLS_ECDH_C || TTLS_ECDSA_C ||
		  TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static int ssl_parse_ecjpake_kkpp(ttls_ssl_context *ssl,
			   const unsigned char *buf,
			   size_t len)
{
	int ret;

	if (ttls_ecjpake_check(&ssl->handshake->ecjpake_ctx) != 0)
	{
		TTLS_SSL_DEBUG_MSG(3, ("skip ecjpake kkpp extension"));
		return 0;
	}

	if ((ret = ttls_ecjpake_read_round_one(&ssl->handshake->ecjpake_ctx,
						buf, len)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ecjpake_read_round_one", ret);
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
		return ret;
	}

	/* Only mark the extension as OK when we're sure it is */
	ssl->handshake->cli_exts |= TTLS_TLS_EXT_ECJPAKE_KKPP_OK;

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_SSL_MAX_FRAGMENT_LENGTH)
static int ssl_parse_max_fragment_length_ext(ttls_ssl_context *ssl,
					  const unsigned char *buf,
					  size_t len)
{
	if (len != 1 || buf[0] >= TTLS_SSL_MAX_FRAG_LEN_INVALID)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	ssl->session_negotiate->mfl_code = buf[0];

	return 0;
}
#endif /* TTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(TTLS_SSL_TRUNCATED_HMAC)
static int ssl_parse_truncated_hmac_ext(ttls_ssl_context *ssl,
					 const unsigned char *buf,
					 size_t len)
{
	if (len != 0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	((void) buf);

	if (ssl->conf->trunc_hmac == TTLS_SSL_TRUNC_HMAC_ENABLED)
		ssl->session_negotiate->trunc_hmac = TTLS_SSL_TRUNC_HMAC_ENABLED;

	return 0;
}
#endif /* TTLS_SSL_TRUNCATED_HMAC */

#if defined(TTLS_SSL_ENCRYPT_THEN_MAC)
static int ssl_parse_encrypt_then_mac_ext(ttls_ssl_context *ssl,
					  const unsigned char *buf,
					  size_t len)
{
	if (len != 0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	((void) buf);

	if (ssl->conf->encrypt_then_mac == TTLS_SSL_ETM_ENABLED &&
		ssl->minor_ver != TTLS_SSL_MINOR_VERSION_0)
	{
		ssl->session_negotiate->encrypt_then_mac = TTLS_SSL_ETM_ENABLED;
	}

	return 0;
}
#endif /* TTLS_SSL_ENCRYPT_THEN_MAC */

#if defined(TTLS_SSL_EXTENDED_MASTER_SECRET)
static int ssl_parse_extended_ms_ext(ttls_ssl_context *ssl,
				  const unsigned char *buf,
				  size_t len)
{
	if (len != 0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	((void) buf);

	if (ssl->conf->extended_ms == TTLS_SSL_EXTENDED_MS_ENABLED &&
		ssl->minor_ver != TTLS_SSL_MINOR_VERSION_0)
	{
		ssl->handshake->extended_ms = TTLS_SSL_EXTENDED_MS_ENABLED;
	}

	return 0;
}
#endif /* TTLS_SSL_EXTENDED_MASTER_SECRET */

#if defined(TTLS_SSL_SESSION_TICKETS)
static int ssl_parse_session_ticket_ext(ttls_ssl_context *ssl,
					 unsigned char *buf,
					 size_t len)
{
	int ret;
	ttls_ssl_session session;

	ttls_ssl_session_init(&session);

	if (ssl->conf->f_ticket_parse == NULL ||
		ssl->conf->f_ticket_write == NULL)
	{
		return 0;
	}

	/* Remember the client asked us to send a new ticket */
	ssl->handshake->new_session_ticket = 1;

	TTLS_SSL_DEBUG_MSG(3, ("ticket length: %d", len));

	if (len == 0)
		return 0;

	/*
	 * Failures are ok: just ignore the ticket and proceed.
	 */
	if ((ret = ssl->conf->f_ticket_parse(ssl->conf->p_ticket, &session,
					   buf, len)) != 0)
	{
		ttls_ssl_session_free(&session);

		if (ret == TTLS_ERR_SSL_INVALID_MAC)
			TTLS_SSL_DEBUG_MSG(3, ("ticket is not authentic"));
		else if (ret == TTLS_ERR_SSL_SESSION_TICKET_EXPIRED)
			TTLS_SSL_DEBUG_MSG(3, ("ticket is expired"));
		else
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_ticket_parse", ret);

		return 0;
	}

	/*
	 * Keep the session ID sent by the client, since we MUST send it back to
	 * inform them we're accepting the ticket  (RFC 5077 section 3.4)
	 */
	session.id_len = ssl->session_negotiate->id_len;
	memcpy(&session.id, ssl->session_negotiate->id, session.id_len);

	ttls_ssl_session_free(ssl->session_negotiate);
	memcpy(ssl->session_negotiate, &session, sizeof(ttls_ssl_session));

	/* Zeroize instead of free as we copied the content */
	ttls_zeroize(&session, sizeof(ttls_ssl_session));

	TTLS_SSL_DEBUG_MSG(3, ("session successfully restored from ticket"));

	ssl->handshake->resume = 1;

	/* Don't send a new ticket after all, this one is OK */
	ssl->handshake->new_session_ticket = 0;

	return 0;
}
#endif /* TTLS_SSL_SESSION_TICKETS */

static int ssl_parse_alpn_ext(ttls_ssl_context *ssl,
			   const unsigned char *buf, size_t len)
{
	size_t list_len, cur_len, ours_len;
	const unsigned char *theirs, *start, *end;
	const char **ours;

	/* If ALPN not configured, just ignore the extension */
	if (ssl->conf->alpn_list == NULL)
		return 0;

	/*
	 * opaque ProtocolName<1..2^8-1>;
	 *
	 * struct {
	 *	 ProtocolName protocol_name_list<2..2^16-1>
	 * } ProtocolNameList;
	 */

	/* Min length is 2 (list_len) + 1 (name_len) + 1 (name) */
	if (len < 4)
	{
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
					TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	list_len = (buf[0] << 8) | buf[1];
	if (list_len != len - 2)
	{
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/*
	 * Validate peer's list (lengths)
	 */
	start = buf + 2;
	end = buf + len;
	for (theirs = start; theirs != end; theirs += cur_len)
	{
		cur_len = *theirs++;

		/* Current identifier must fit in list */
		if (cur_len > (size_t)(end - theirs))
		{
			ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}

		/* Empty strings MUST NOT be included */
		if (cur_len == 0)
		{
			ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}
	}

	/*
	 * Use our order of preference
	 */
	for (ours = ssl->conf->alpn_list; *ours != NULL; ours++)
	{
		ours_len = strlen(*ours);
		for (theirs = start; theirs != end; theirs += cur_len)
		{
			cur_len = *theirs++;

			if (cur_len == ours_len &&
				memcmp(theirs, *ours, cur_len) == 0)
			{
				ssl->alpn_chosen = *ours;
				return 0;
			}
		}
	}

	/* If we get there, no match was found */
	ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
					TTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL);
	return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
}

/*
 * Auxiliary functions for ServerHello parsing and related actions
 */

/*
 * Return 0 if the given key uses one of the acceptable curves, -1 otherwise
 */
#if defined(TTLS_ECDSA_C)
static int ssl_check_key_curve(ttls_pk_context *pk,
				const ttls_ecp_curve_info **curves)
{
	const ttls_ecp_curve_info **crv = curves;
	ttls_ecp_group_id grp_id = ttls_pk_ec(*pk)->grp.id;

	while (*crv != NULL)
	{
		if ((*crv)->grp_id == grp_id)
			return 0;
		crv++;
	}

	return(-1);
}
#endif /* TTLS_ECDSA_C */

/*
 * Try picking a certificate for this ciphersuite,
 * return 0 on success and -1 on failure.
 */
static int ssl_pick_cert(ttls_ssl_context *ssl,
			  const ttls_ssl_ciphersuite_t * ciphersuite_info)
{
	ttls_ssl_key_cert *cur, *list, *fallback = NULL;
	ttls_pk_type_t pk_alg =
		ttls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info);
	uint32_t flags;

	if (ssl->handshake->sni_key_cert != NULL)
		list = ssl->handshake->sni_key_cert;
	else
		list = ssl->conf->key_cert;

	if (pk_alg == TTLS_PK_NONE)
		return 0;

	TTLS_SSL_DEBUG_MSG(3, ("ciphersuite requires certificate"));

	if (list == NULL)
	{
		TTLS_SSL_DEBUG_MSG(3, ("server has no certificate"));
		return(-1);
	}

	for (cur = list; cur != NULL; cur = cur->next)
	{
		TTLS_SSL_DEBUG_CRT(3, "candidate certificate chain, certificate",
						  cur->cert);

		if (! ttls_pk_can_do(cur->key, pk_alg))
		{
			TTLS_SSL_DEBUG_MSG(3, ("certificate mismatch: key type"));
			continue;
		}

		/*
		 * This avoids sending the client a cert it'll reject based on
		 * keyUsage or other extensions.
		 *
		 * It also allows the user to provision different certificates for
		 * different uses based on keyUsage, eg if they want to avoid signing
		 * and decrypting with the same RSA key.
		 */
		if (ttls_ssl_check_cert_usage(cur->cert, ciphersuite_info,
						  TTLS_SSL_IS_SERVER, &flags) != 0)
		{
			TTLS_SSL_DEBUG_MSG(3, ("certificate mismatch: "
						"(extended) key usage extension"));
			continue;
		}

#if defined(TTLS_ECDSA_C)
		if (pk_alg == TTLS_PK_ECDSA &&
			ssl_check_key_curve(cur->key, ssl->handshake->curves) != 0)
		{
			TTLS_SSL_DEBUG_MSG(3, ("certificate mismatch: elliptic curve"));
			continue;
		}
#endif

		/*
		 * Try to select a SHA-1 certificate for pre-1.2 clients, but still
		 * present them a SHA-higher cert rather than failing if it's the only
		 * one we got that satisfies the other conditions.
		 */
		if (ssl->minor_ver < TTLS_SSL_MINOR_VERSION_3 &&
			cur->cert->sig_md != TTLS_MD_SHA1)
		{
			if (fallback == NULL)
				fallback = cur;
			TTLS_SSL_DEBUG_MSG(3, ("certificate not preferred: "
					"sha-2 with pre-TLS 1.2 client"));
			continue;
		}

		/* If we get there, we got a winner */
		break;
	}

	if (cur == NULL)
		cur = fallback;

	/* Do not update ssl->handshake->key_cert unless there is a match */
	if (cur != NULL)
	{
		ssl->handshake->key_cert = cur;
		TTLS_SSL_DEBUG_CRT(3, "selected certificate chain, certificate",
						  ssl->handshake->key_cert->cert);
		return 0;
	}

	return(-1);
}

/*
 * Check if a given ciphersuite is suitable for use with our config/keys/etc
 * Sets ciphersuite_info only if the suite matches.
 */
static int ssl_ciphersuite_match(ttls_ssl_context *ssl, int suite_id,
				  const ttls_ssl_ciphersuite_t **ciphersuite_info)
{
	const ttls_ssl_ciphersuite_t *suite_info;

#if defined(TTLS_SSL_PROTO_TLS1_2) && \
	defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)	
	ttls_pk_type_t sig_type;
#endif

	suite_info = ttls_ssl_ciphersuite_from_id(suite_id);
	if (suite_info == NULL)
	{
		TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_SSL_INTERNAL_ERROR);
	}

	TTLS_SSL_DEBUG_MSG(3, ("trying ciphersuite: %s", suite_info->name));

	if (suite_info->min_minor_ver > ssl->minor_ver ||
		suite_info->max_minor_ver < ssl->minor_ver)
	{
		TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: version"));
		return 0;
	}

#if defined(TTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM &&
		(suite_info->flags & TTLS_CIPHERSUITE_NODTLS))
		return 0;
#endif

#if defined(TTLS_ARC4_C)
	if (ssl->conf->arc4_disabled == TTLS_SSL_ARC4_DISABLED &&
			suite_info->cipher == TTLS_CIPHER_ARC4_128)
	{
		TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: rc4"));
		return 0;
	}
#endif

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	if (suite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE &&
		(ssl->handshake->cli_exts & TTLS_TLS_EXT_ECJPAKE_KKPP_OK) == 0)
	{
		TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: ecjpake "
					"not configured or ext missing"));
		return 0;
	}
#endif


#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C)
	if (ttls_ssl_ciphersuite_uses_ec(suite_info) &&
		(ssl->handshake->curves == NULL ||
		  ssl->handshake->curves[0] == NULL))
	{
		TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: "
					"no common elliptic curve"));
		return 0;
	}
#endif

#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	/* If the ciphersuite requires a pre-shared key and we don't
	 * have one, skip it now rather than failing later */
	if (ttls_ssl_ciphersuite_uses_psk(suite_info) &&
		ssl->conf->f_psk == NULL &&
		(ssl->conf->psk == NULL || ssl->conf->psk_identity == NULL ||
		  ssl->conf->psk_identity_len == 0 || ssl->conf->psk_len == 0))
	{
		TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: no pre-shared key"));
		return 0;
	}
#endif

#if defined(TTLS_SSL_PROTO_TLS1_2) && \
	defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
	/* If the ciphersuite requires signing, check whether
	 * a suitable hash algorithm is present. */
	if (ssl->minor_ver == TTLS_SSL_MINOR_VERSION_3)
	{
		sig_type = ttls_ssl_get_ciphersuite_sig_alg(suite_info);
		if (sig_type != TTLS_PK_NONE &&
			ttls_ssl_sig_hash_set_find(&ssl->handshake->hash_algs, sig_type) == TTLS_MD_NONE)
		{
			TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: no suitable hash algorithm "
						"for signature algorithm %d", sig_type));
			return 0;
		}
	}

#endif /* TTLS_SSL_PROTO_TLS1_2 &&
		  TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

	/*
	 * Final check: if ciphersuite requires us to have a
	 * certificate/key of a particular type:
	 * - select the appropriate certificate if we have one, or
	 * - try the next ciphersuite if we don't
	 * This must be done last since we modify the key_cert list.
	 */
	if (ssl_pick_cert(ssl, suite_info) != 0)
	{
		TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: "
					"no suitable certificate"));
		return 0;
	}

	*ciphersuite_info = suite_info;
	return 0;
}

#if defined(TTLS_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO)
static int ssl_parse_client_hello_v2(ttls_ssl_context *ssl)
{
	int ret, got_common_suite;
	unsigned int i, j;
	size_t n;
	unsigned int ciph_len, sess_len, chal_len;
	unsigned char *buf, *p;
	const int *ciphersuites;
	const ttls_ssl_ciphersuite_t *ciphersuite_info;

	TTLS_SSL_DEBUG_MSG(2, ("=> parse client hello v2"));

	buf = ssl->in_hdr;

	TTLS_SSL_DEBUG_BUF(4, "record header", buf, 5);

	TTLS_SSL_DEBUG_MSG(3, ("client hello v2, message type: %d",
				   buf[2]));
	TTLS_SSL_DEBUG_MSG(3, ("client hello v2, message len.: %d",
				   ((buf[0] & 0x7F) << 8) | buf[1]));
	TTLS_SSL_DEBUG_MSG(3, ("client hello v2, max. version: [%d:%d]",
				   buf[3], buf[4]));

	/*
	 * SSLv2 Client Hello
	 *
	 * Record layer:
	 *	 0  .   1   message length
	 *
	 * SSL layer:
	 *	 2  .   2   message type
	 *	 3  .   4   protocol version
	 */
	if (buf[2] != TTLS_SSL_HS_CLIENT_HELLO ||
		buf[3] != TTLS_SSL_MAJOR_VERSION_3)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	n = ((buf[0] << 8) | buf[1]) & 0x7FFF;

	if (n < 17 || n > 512)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	ssl->major_ver = TTLS_SSL_MAJOR_VERSION_3;
	ssl->minor_ver = (buf[4] <= ssl->conf->max_minor_ver)
					 ? buf[4]  : ssl->conf->max_minor_ver;

	if (ssl->minor_ver < ssl->conf->min_minor_ver)
	{
		TTLS_SSL_DEBUG_MSG(1, ("client only supports ssl smaller than minimum"
							" [%d:%d] < [%d:%d]",
							ssl->major_ver, ssl->minor_ver,
							ssl->conf->min_major_ver, ssl->conf->min_minor_ver));

		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						 TTLS_SSL_ALERT_MSG_PROTOCOL_VERSION);
		return(TTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION);
	}

	ssl->handshake->max_major_ver = buf[3];
	ssl->handshake->max_minor_ver = buf[4];

	if ((ret = ttls_ssl_fetch_input(ssl, 2 + n)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_fetch_input", ret);
		return ret;
	}

	ssl->handshake->update_checksum(ssl, buf + 2, n);

	buf = ssl->in_msg;
	n = ssl->in_left - 5;

	/*
	 *	0  .   1   ciphersuitelist length
	 *	2  .   3   session id length
	 *	4  .   5   challenge length
	 *	6  .  ..   ciphersuitelist
	 *   ..  .  ..   session id
	 *   ..  .  ..   challenge
	 */
	TTLS_SSL_DEBUG_BUF(4, "record contents", buf, n);

	ciph_len = (buf[0] << 8) | buf[1];
	sess_len = (buf[2] << 8) | buf[3];
	chal_len = (buf[4] << 8) | buf[5];

	TTLS_SSL_DEBUG_MSG(3, ("ciph_len: %d, sess_len: %d, chal_len: %d",
				   ciph_len, sess_len, chal_len));

	/*
	 * Make sure each parameter length is valid
	 */
	if (ciph_len < 3 || (ciph_len % 3) != 0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	if (sess_len > 32)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	if (chal_len < 8 || chal_len > 32)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	if (n != 6 + ciph_len + sess_len + chal_len)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	TTLS_SSL_DEBUG_BUF(3, "client hello, ciphersuitelist",
				   buf + 6, ciph_len);
	TTLS_SSL_DEBUG_BUF(3, "client hello, session id",
				   buf + 6 + ciph_len, sess_len);
	TTLS_SSL_DEBUG_BUF(3, "client hello, challenge",
				   buf + 6 + ciph_len + sess_len, chal_len);

	p = buf + 6 + ciph_len;
	ssl->session_negotiate->id_len = sess_len;
	memset(ssl->session_negotiate->id, 0,
			sizeof(ssl->session_negotiate->id));
	memcpy(ssl->session_negotiate->id, p, ssl->session_negotiate->id_len);

	p += sess_len;
	memset(ssl->handshake->randbytes, 0, 64);
	memcpy(ssl->handshake->randbytes + 32 - chal_len, p, chal_len);

	/*
	 * Check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	 */
	for (i = 0, p = buf + 6; i < ciph_len; i += 3, p += 3)
	{
		if (p[0] == 0 && p[1] == 0 && p[2] == TTLS_SSL_EMPTY_RENEGOTIATION_INFO)
		{
			TTLS_SSL_DEBUG_MSG(3, ("received TLS_EMPTY_RENEGOTIATION_INFO "));
			ssl->secure_renegotiation = TTLS_SSL_SECURE_RENEGOTIATION;
			break;
		}
	}

#if defined(TTLS_SSL_FALLBACK_SCSV)
	for (i = 0, p = buf + 6; i < ciph_len; i += 3, p += 3)
	{
		if (p[0] == 0 &&
			p[1] == (unsigned char)((TTLS_SSL_FALLBACK_SCSV_VALUE >> 8) & 0xff) &&
			p[2] == (unsigned char)((TTLS_SSL_FALLBACK_SCSV_VALUE	 ) & 0xff))
		{
			TTLS_SSL_DEBUG_MSG(3, ("received FALLBACK_SCSV"));

			if (ssl->minor_ver < ssl->conf->max_minor_ver)
			{
				TTLS_SSL_DEBUG_MSG(1, ("inapropriate fallback"));

				ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
								TTLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK);

				return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
			}

			break;
		}
	}
#endif /* TTLS_SSL_FALLBACK_SCSV */

	got_common_suite = 0;
	ciphersuites = ssl->conf->ciphersuite_list[ssl->minor_ver];
	ciphersuite_info = NULL;
#if defined(TTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE)
	for (j = 0, p = buf + 6; j < ciph_len; j += 3, p += 3)
		for (i = 0; ciphersuites[i] != 0; i++)
#else
	for (i = 0; ciphersuites[i] != 0; i++)
		for (j = 0, p = buf + 6; j < ciph_len; j += 3, p += 3)
#endif
		{
			if (p[0] != 0 ||
				p[1] != ((ciphersuites[i] >> 8) & 0xFF) ||
				p[2] != ((ciphersuites[i]	 ) & 0xFF))
				continue;

			got_common_suite = 1;

			if ((ret = ssl_ciphersuite_match(ssl, ciphersuites[i],
							   &ciphersuite_info)) != 0)
				return ret;

			if (ciphersuite_info != NULL)
				goto have_ciphersuite_v2;
		}

	if (got_common_suite)
	{
		TTLS_SSL_DEBUG_MSG(1, ("got ciphersuites in common, "
					"but none of them usable"));
		return(TTLS_ERR_SSL_NO_USABLE_CIPHERSUITE);
	}
	else
	{
		TTLS_SSL_DEBUG_MSG(1, ("got no ciphersuites in common"));
		return(TTLS_ERR_SSL_NO_CIPHER_CHOSEN);
	}

have_ciphersuite_v2:
	TTLS_SSL_DEBUG_MSG(2, ("selected ciphersuite: %s", ciphersuite_info->name));

	ssl->session_negotiate->ciphersuite = ciphersuites[i];
	ssl->transform_negotiate->ciphersuite_info = ciphersuite_info;

	/*
	 * SSLv2 Client Hello relevant renegotiation security checks
	 */
	if (ssl->secure_renegotiation == TTLS_SSL_LEGACY_RENEGOTIATION &&
		ssl->conf->allow_legacy_renegotiation == TTLS_SSL_LEGACY_BREAK_HANDSHAKE)
	{
		TTLS_SSL_DEBUG_MSG(1, ("legacy renegotiation, breaking off handshake"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	ssl->in_left = 0;
	ssl->state++;

	TTLS_SSL_DEBUG_MSG(2, ("<= parse client hello v2"));

	return 0;
}
#endif /* TTLS_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO */

/* This function doesn't alert on errors that happen early during
   ClientHello parsing because they might indicate that the client is
   not talking SSL/TLS at all and would not understand our alert. */
static int ssl_parse_client_hello(ttls_ssl_context *ssl)
{
	int ret, got_common_suite;
	size_t i, j;
	size_t ciph_offset, comp_offset, ext_offset;
	size_t msg_len, ciph_len, sess_len, comp_len, ext_len;
#if defined(TTLS_SSL_PROTO_DTLS)
	size_t cookie_offset, cookie_len;
#endif
	unsigned char *buf, *p, *ext;
	int handshake_failure = 0;
	const int *ciphersuites;
	const ttls_ssl_ciphersuite_t *ciphersuite_info;
	int major, minor;

	/* If there is no signature-algorithm extension present,
	 * we need to fall back to the default values for allowed
	 * signature-hash pairs. */
#if defined(TTLS_SSL_PROTO_TLS1_2) && \
	defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
	int sig_hash_alg_ext_present = 0;
#endif /* TTLS_SSL_PROTO_TLS1_2 &&
		  TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

	TTLS_SSL_DEBUG_MSG(2, ("=> parse client hello"));

#if defined(TTLS_SSL_DTLS_ANTI_REPLAY)
read_record_header:
#endif
	/*
	 * Read the input ourselves manually in order to support SSLv2
	 * ClientHello, which doesn't use the same record layer format.
	 */
	if ((ret = ttls_ssl_fetch_input(ssl, 5)) != 0) {
		/* No alert on a read error. */
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_fetch_input", ret);
		return ret;
	}

	buf = ssl->in_hdr;

#if defined(TTLS_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO)
#if defined(TTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_STREAM)
#endif
		if ((buf[0] & 0x80) != 0)
			return(ssl_parse_client_hello_v2(ssl));
#endif

	TTLS_SSL_DEBUG_BUF(4, "record header", buf, ttls_ssl_hdr_len(ssl));

	/*
	 * SSLv3/TLS Client Hello
	 *
	 * Record layer:
	 *	 0  .   0   message type
	 *	 1  .   2   protocol version
	 *	 3  .   11  DTLS: epoch + record sequence number
	 *	 3  .   4   message length
	 */
	TTLS_SSL_DEBUG_MSG(3, ("client hello v3, message type: %d",
				   buf[0]));

	if (buf[0] != TTLS_SSL_MSG_HANDSHAKE)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	TTLS_SSL_DEBUG_MSG(3, ("client hello v3, message len.: %d",
				   (ssl->in_len[0] << 8) | ssl->in_len[1]));

	TTLS_SSL_DEBUG_MSG(3, ("client hello v3, protocol version: [%d:%d]",
				   buf[1], buf[2]));

	ttls_ssl_read_version(&major, &minor, ssl->conf->transport, buf + 1);

	/* According to RFC 5246 Appendix E.1, the version here is typically
	 * "{03,00}, the lowest version number supported by the client, [or] the
	 * value of ClientHello.client_version", so the only meaningful check here
	 * is the major version shouldn't be less than 3 */
	if (major < TTLS_SSL_MAJOR_VERSION_3)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/* For DTLS if this is the initial handshake, remember the client sequence
	 * number to use it in our next message (RFC 6347 4.2.1) */
#if defined(TTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM) {
		/* Epoch should be 0 for initial handshakes */
		if (ssl->in_ctr[0] != 0 || ssl->in_ctr[1] != 0)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}

		memcpy(ssl->out_ctr + 2, ssl->in_ctr + 2, 6);

#if defined(TTLS_SSL_DTLS_ANTI_REPLAY)
		if (ttls_ssl_dtls_replay_check(ssl) != 0)
		{
			TTLS_SSL_DEBUG_MSG(1, ("replayed record, discarding"));
			ssl->next_record_offset = 0;
			ssl->in_left = 0;
			goto read_record_header;
		}

		/* No MAC to check yet, so we can update right now */
		ttls_ssl_dtls_replay_update(ssl);
#endif
	}
#endif /* TTLS_SSL_PROTO_DTLS */

	msg_len = (ssl->in_len[0] << 8) | ssl->in_len[1];

	if (msg_len > TTLS_SSL_MAX_CONTENT_LEN)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	if ((ret = ttls_ssl_fetch_input(ssl,
				   ttls_ssl_hdr_len(ssl) + msg_len)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_fetch_input", ret);
		return ret;
	}

	/* Done reading this record, get ready for the next one */
#if defined(TTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
		ssl->next_record_offset = msg_len + ttls_ssl_hdr_len(ssl);
	else
#endif
		ssl->in_left = 0;

	buf = ssl->in_msg;

	TTLS_SSL_DEBUG_BUF(4, "record contents", buf, msg_len);

	ssl->handshake->update_checksum(ssl, buf, msg_len);

	/*
	 * Handshake layer:
	 *	 0  .   0   handshake type
	 *	 1  .   3   handshake length
	 *	 4  .   5   DTLS only: message seqence number
	 *	 6  .   8   DTLS only: fragment offset
	 *	 9  .  11   DTLS only: fragment length
	 */
	if (msg_len < ttls_ssl_hs_hdr_len(ssl))
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	TTLS_SSL_DEBUG_MSG(3, ("client hello v3, handshake type: %d", buf[0]));

	if (buf[0] != TTLS_SSL_HS_CLIENT_HELLO)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	TTLS_SSL_DEBUG_MSG(3, ("client hello v3, handshake len.: %d",
				   (buf[1] << 16) | (buf[2] << 8) | buf[3]));

	/* We don't support fragmentation of ClientHello (yet?) */
	if (buf[1] != 0 ||
		msg_len != ttls_ssl_hs_hdr_len(ssl) + ((buf[2] << 8) | buf[3]))
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

#if defined(TTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
	{
		/*
		 * Copy the client's handshake message_seq on initial handshakes,
		 * check sequence number on renego.
		 */
		unsigned int cli_msg_seq = (ssl->in_msg[4] << 8) | ssl->in_msg[5];
		ssl->handshake->out_msg_seq = cli_msg_seq;
		ssl->handshake->in_msg_seq  = cli_msg_seq + 1;

		/*
		 * For now we don't support fragmentation, so make sure
		 * fragment_offset == 0 and fragment_length == length
		 */
		if (ssl->in_msg[6] != 0 || ssl->in_msg[7] != 0 || ssl->in_msg[8] != 0 ||
			memcmp(ssl->in_msg + 1, ssl->in_msg + 9, 3) != 0)
		{
			TTLS_SSL_DEBUG_MSG(1, ("ClientHello fragmentation not supported"));
			return(TTLS_ERR_SSL_FEATURE_UNAVAILABLE);
		}
	}
#endif /* TTLS_SSL_PROTO_DTLS */

	buf += ttls_ssl_hs_hdr_len(ssl);
	msg_len -= ttls_ssl_hs_hdr_len(ssl);

	/*
	 * ClientHello layer:
	 *	 0  .   1   protocol version
	 *	 2  .  33   random bytes (starting with 4 bytes of Unix time)
	 *	34  .  35   session id length (1 byte)
	 *	35  . 34+x  session id
	 *   35+x . 35+x  DTLS only: cookie length (1 byte)
	 *   36+x .  ..   DTLS only: cookie
	 *	..  .  ..   ciphersuite list length (2 bytes)
	 *	..  .  ..   ciphersuite list
	 *	..  .  ..   compression alg. list length (1 byte)
	 *	..  .  ..   compression alg. list
	 *	..  .  ..   extensions length (2 bytes, optional)
	 *	..  .  ..   extensions (optional)
	 */

	/*
	 * Minimal length (with everything empty and extensions ommitted) is
	 * 2 + 32 + 1 + 2 + 1 = 38 bytes. Check that first, so that we can
	 * read at least up to session id length without worrying.
	 */
	if (msg_len < 38)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/*
	 * Check and save the protocol version
	 */
	TTLS_SSL_DEBUG_BUF(3, "client hello, version", buf, 2);

	ttls_ssl_read_version(&ssl->major_ver, &ssl->minor_ver,
					  ssl->conf->transport, buf);

	ssl->handshake->max_major_ver = ssl->major_ver;
	ssl->handshake->max_minor_ver = ssl->minor_ver;

	if (ssl->major_ver < ssl->conf->min_major_ver ||
		ssl->minor_ver < ssl->conf->min_minor_ver)
	{
		TTLS_SSL_DEBUG_MSG(1, ("client only supports ssl smaller than minimum"
					" [%d:%d] < [%d:%d]",
					ssl->major_ver, ssl->minor_ver,
					ssl->conf->min_major_ver, ssl->conf->min_minor_ver));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						 TTLS_SSL_ALERT_MSG_PROTOCOL_VERSION);
		return(TTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION);
	}

	if (ssl->major_ver > ssl->conf->max_major_ver)
	{
		ssl->major_ver = ssl->conf->max_major_ver;
		ssl->minor_ver = ssl->conf->max_minor_ver;
	}
	else if (ssl->minor_ver > ssl->conf->max_minor_ver)
		ssl->minor_ver = ssl->conf->max_minor_ver;

	/*
	 * Save client random (inc. Unix time)
	 */
	TTLS_SSL_DEBUG_BUF(3, "client hello, random bytes", buf + 2, 32);

	memcpy(ssl->handshake->randbytes, buf + 2, 32);

	/*
	 * Check the session ID length and save session ID
	 */
	sess_len = buf[34];

	if (sess_len > sizeof(ssl->session_negotiate->id) ||
		sess_len + 34 + 2 > msg_len) /* 2 for cipherlist length field */
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	TTLS_SSL_DEBUG_BUF(3, "client hello, session id", buf + 35, sess_len);

	ssl->session_negotiate->id_len = sess_len;
	memset(ssl->session_negotiate->id, 0,
			sizeof(ssl->session_negotiate->id));
	memcpy(ssl->session_negotiate->id, buf + 35,
			ssl->session_negotiate->id_len);

	/*
	 * Check the cookie length and content
	 */
#if defined(TTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
	{
		cookie_offset = 35 + sess_len;
		cookie_len = buf[cookie_offset];

		if (cookie_offset + 1 + cookie_len + 2 > msg_len)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
			ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_PROTOCOL_VERSION);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}

		TTLS_SSL_DEBUG_BUF(3, "client hello, cookie",
					   buf + cookie_offset + 1, cookie_len);

#if defined(TTLS_SSL_DTLS_HELLO_VERIFY)
		if (ssl->conf->f_cookie_check != NULL) {
			if (ssl->conf->f_cookie_check(ssl->conf->p_cookie,
							 buf + cookie_offset + 1, cookie_len,
							 ssl->cli_id, ssl->cli_id_len) != 0)
			{
				TTLS_SSL_DEBUG_MSG(2, ("cookie verification failed"));
				ssl->handshake->verify_cookie_len = 1;
			}
			else
			{
				TTLS_SSL_DEBUG_MSG(2, ("cookie verification passed"));
				ssl->handshake->verify_cookie_len = 0;
			}
		}
		else
#endif /* TTLS_SSL_DTLS_HELLO_VERIFY */
		{
			/* We know we didn't send a cookie, so it should be empty */
			if (cookie_len != 0)
			{
				/* This may be an attacker's probe, so don't send an alert */
				TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
				return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
			}

			TTLS_SSL_DEBUG_MSG(2, ("cookie verification skipped"));
		}

	/*
	 * Check the ciphersuitelist length (will be parsed later)
	 */
		ciph_offset = cookie_offset + 1 + cookie_len;
	}
	else
#endif /* TTLS_SSL_PROTO_DTLS */
		ciph_offset = 35 + sess_len;

	ciph_len = (buf[ciph_offset + 0] << 8)
			 | (buf[ciph_offset + 1]	 );

	if (ciph_len < 2 ||
		ciph_len + 2 + ciph_offset + 1 > msg_len || /* 1 for comp. alg. len */
		(ciph_len % 2) != 0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	TTLS_SSL_DEBUG_BUF(3, "client hello, ciphersuitelist",
				   buf + ciph_offset + 2,  ciph_len);

	/*
	 * Check the compression algorithms length and pick one
	 */
	comp_offset = ciph_offset + 2 + ciph_len;

	comp_len = buf[comp_offset];

	if (comp_len < 1 ||
		comp_len > 16 ||
		comp_len + comp_offset + 1 > msg_len)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	TTLS_SSL_DEBUG_BUF(3, "client hello, compression",
					  buf + comp_offset + 1, comp_len);

	ssl->session_negotiate->compression = TTLS_SSL_COMPRESS_NULL;
#if defined(TTLS_ZLIB_SUPPORT)
	for (i = 0; i < comp_len; ++i)
	{
		if (buf[comp_offset + 1 + i] == TTLS_SSL_COMPRESS_DEFLATE)
		{
			ssl->session_negotiate->compression = TTLS_SSL_COMPRESS_DEFLATE;
			break;
		}
	}
#endif

	/* See comments in ssl_write_client_hello() */
#if defined(TTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
		ssl->session_negotiate->compression = TTLS_SSL_COMPRESS_NULL;
#endif

	/* Do not parse the extensions if the protocol is SSLv3 */
#if defined(TTLS_SSL_PROTO_SSL3)
	if ((ssl->major_ver != 3) || (ssl->minor_ver != 0))
	{
#endif
		/*
		 * Check the extension length
		 */
		ext_offset = comp_offset + 1 + comp_len;
		if (msg_len > ext_offset)
		{
			if (msg_len < ext_offset + 2)
			{
				TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
				ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
								TTLS_SSL_ALERT_MSG_DECODE_ERROR);
				return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
			}

			ext_len = (buf[ext_offset + 0] << 8)
					| (buf[ext_offset + 1]	 );

			if ((ext_len > 0 && ext_len < 4) ||
				msg_len != ext_offset + 2 + ext_len)
			{
				TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
				ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
								TTLS_SSL_ALERT_MSG_DECODE_ERROR);
				return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
			}
		}
		else
			ext_len = 0;

		ext = buf + ext_offset + 2;
		TTLS_SSL_DEBUG_BUF(3, "client hello extensions", ext, ext_len);

		while (ext_len != 0)
		{
			unsigned int ext_id   = ((ext[0] <<  8)
									| (ext[1]	  ));
			unsigned int ext_size = ((ext[2] <<  8)
									| (ext[3]	  ));

			if (ext_size + 4 > ext_len)
			{
				TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
				ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
								TTLS_SSL_ALERT_MSG_DECODE_ERROR);
				return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
			}
			switch(ext_id)
			{
			case TTLS_TLS_EXT_SERVERNAME:
				TTLS_SSL_DEBUG_MSG(3, ("found ServerName extension"));
				if (ssl->conf->f_sni == NULL)
					break;

				ret = ssl_parse_servername_ext(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;

			case TTLS_TLS_EXT_RENEGOTIATION_INFO:
				TTLS_SSL_DEBUG_MSG(3, ("found renegotiation extension"));
				ret = ssl_parse_renegotiation_info(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;

#if defined(TTLS_SSL_PROTO_TLS1_2) && \
	defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
			case TTLS_TLS_EXT_SIG_ALG:
				TTLS_SSL_DEBUG_MSG(3, ("found signature_algorithms extension"));

				ret = ssl_parse_signature_algorithms_ext(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;

				sig_hash_alg_ext_present = 1;
				break;
#endif /* TTLS_SSL_PROTO_TLS1_2 &&
		  TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
			case TTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES:
				TTLS_SSL_DEBUG_MSG(3, ("found supported elliptic curves extension"));

				ret = ssl_parse_supported_elliptic_curves(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;

			case TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS:
				TTLS_SSL_DEBUG_MSG(3, ("found supported point formats extension"));
				ssl->handshake->cli_exts |= TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT;

				ret = ssl_parse_supported_point_formats(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;
#endif /* TTLS_ECDH_C || TTLS_ECDSA_C ||
		  TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
			case TTLS_TLS_EXT_ECJPAKE_KKPP:
				TTLS_SSL_DEBUG_MSG(3, ("found ecjpake kkpp extension"));

				ret = ssl_parse_ecjpake_kkpp(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_SSL_MAX_FRAGMENT_LENGTH)
			case TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
				TTLS_SSL_DEBUG_MSG(3, ("found max fragment length extension"));

				ret = ssl_parse_max_fragment_length_ext(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;
#endif /* TTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(TTLS_SSL_TRUNCATED_HMAC)
			case TTLS_TLS_EXT_TRUNCATED_HMAC:
				TTLS_SSL_DEBUG_MSG(3, ("found truncated hmac extension"));

				ret = ssl_parse_truncated_hmac_ext(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;
#endif /* TTLS_SSL_TRUNCATED_HMAC */

#if defined(TTLS_SSL_ENCRYPT_THEN_MAC)
			case TTLS_TLS_EXT_ENCRYPT_THEN_MAC:
				TTLS_SSL_DEBUG_MSG(3, ("found encrypt then mac extension"));

				ret = ssl_parse_encrypt_then_mac_ext(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;
#endif /* TTLS_SSL_ENCRYPT_THEN_MAC */

#if defined(TTLS_SSL_EXTENDED_MASTER_SECRET)
			case TTLS_TLS_EXT_EXTENDED_MASTER_SECRET:
				TTLS_SSL_DEBUG_MSG(3, ("found extended master secret extension"));

				ret = ssl_parse_extended_ms_ext(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;
#endif /* TTLS_SSL_EXTENDED_MASTER_SECRET */

#if defined(TTLS_SSL_SESSION_TICKETS)
			case TTLS_TLS_EXT_SESSION_TICKET:
				TTLS_SSL_DEBUG_MSG(3, ("found session ticket extension"));

				ret = ssl_parse_session_ticket_ext(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;
#endif /* TTLS_SSL_SESSION_TICKETS */

			case TTLS_TLS_EXT_ALPN:
				TTLS_SSL_DEBUG_MSG(3, ("found alpn extension"));

				ret = ssl_parse_alpn_ext(ssl, ext + 4, ext_size);
				if (ret != 0)
					return ret;
				break;

			default:
				TTLS_SSL_DEBUG_MSG(3, ("unknown extension found: %d (ignoring)",
							   ext_id));
			}

			ext_len -= 4 + ext_size;
			ext += 4 + ext_size;

			if (ext_len > 0 && ext_len < 4)
			{
				TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
				ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
								TTLS_SSL_ALERT_MSG_DECODE_ERROR);
				return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
			}
		}
#if defined(TTLS_SSL_PROTO_SSL3)
	}
#endif

#if defined(TTLS_SSL_FALLBACK_SCSV)
	for (i = 0, p = buf + ciph_offset + 2; i < ciph_len; i += 2, p += 2)
	{
		if (p[0] == (unsigned char)((TTLS_SSL_FALLBACK_SCSV_VALUE >> 8) & 0xff) &&
			p[1] == (unsigned char)((TTLS_SSL_FALLBACK_SCSV_VALUE	 ) & 0xff))
		{
			TTLS_SSL_DEBUG_MSG(2, ("received FALLBACK_SCSV"));

			if (ssl->minor_ver < ssl->conf->max_minor_ver)
			{
				TTLS_SSL_DEBUG_MSG(1, ("inapropriate fallback"));

				ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
								TTLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK);

				return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
			}

			break;
		}
	}
#endif /* TTLS_SSL_FALLBACK_SCSV */

#if defined(TTLS_SSL_PROTO_TLS1_2) && \
	defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

	/*
	 * Try to fall back to default hash SHA1 if the client
	 * hasn't provided any preferred signature-hash combinations.
	 */
	if (sig_hash_alg_ext_present == 0)
	{
		ttls_md_type_t md_default = TTLS_MD_SHA1;

		if (ttls_ssl_check_sig_hash(ssl, md_default) != 0)
			md_default = TTLS_MD_NONE;

		ttls_ssl_sig_hash_set_const_hash(&ssl->handshake->hash_algs, md_default);
	}

#endif /* TTLS_SSL_PROTO_TLS1_2 &&
		  TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

	/*
	 * Check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	 */
	for (i = 0, p = buf + ciph_offset + 2; i < ciph_len; i += 2, p += 2)
	{
		if (p[0] == 0 && p[1] == TTLS_SSL_EMPTY_RENEGOTIATION_INFO)
		{
			TTLS_SSL_DEBUG_MSG(3, ("received TLS_EMPTY_RENEGOTIATION_INFO "));
			ssl->secure_renegotiation = TTLS_SSL_SECURE_RENEGOTIATION;
			break;
		}
	}

	/*
	 * Renegotiation security checks
	 */
	if (ssl->secure_renegotiation != TTLS_SSL_SECURE_RENEGOTIATION &&
		ssl->conf->allow_legacy_renegotiation == TTLS_SSL_LEGACY_BREAK_HANDSHAKE)
	{
		TTLS_SSL_DEBUG_MSG(1, ("legacy renegotiation, breaking off handshake"));
		handshake_failure = 1;
	}

	if (handshake_failure == 1)
	{
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/*
	 * Search for a matching ciphersuite
	 * (At the end because we need information from the EC-based extensions
	 * and certificate from the SNI callback triggered by the SNI extension.)
	 */
	got_common_suite = 0;
	ciphersuites = ssl->conf->ciphersuite_list[ssl->minor_ver];
	ciphersuite_info = NULL;
#if defined(TTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE)
	for (j = 0, p = buf + ciph_offset + 2; j < ciph_len; j += 2, p += 2)
		for (i = 0; ciphersuites[i] != 0; i++)
#else
	for (i = 0; ciphersuites[i] != 0; i++)
		for (j = 0, p = buf + ciph_offset + 2; j < ciph_len; j += 2, p += 2)
#endif
		{
			if (p[0] != ((ciphersuites[i] >> 8) & 0xFF) ||
				p[1] != ((ciphersuites[i]	 ) & 0xFF))
				continue;

			got_common_suite = 1;

			if ((ret = ssl_ciphersuite_match(ssl, ciphersuites[i],
							   &ciphersuite_info)) != 0)
				return ret;

			if (ciphersuite_info != NULL)
				goto have_ciphersuite;
		}

	if (got_common_suite)
	{
		TTLS_SSL_DEBUG_MSG(1, ("got ciphersuites in common, "
					"but none of them usable"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_SSL_NO_USABLE_CIPHERSUITE);
	}
	else
	{
		TTLS_SSL_DEBUG_MSG(1, ("got no ciphersuites in common"));
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_SSL_NO_CIPHER_CHOSEN);
	}

have_ciphersuite:
	TTLS_SSL_DEBUG_MSG(2, ("selected ciphersuite: %s", ciphersuite_info->name));

	ssl->session_negotiate->ciphersuite = ciphersuites[i];
	ssl->transform_negotiate->ciphersuite_info = ciphersuite_info;

	ssl->state++;

#if defined(TTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
		ttls_ssl_recv_flight_completed(ssl);
#endif

	/* Debugging-only output for testsuite */
#if defined(TTLS_DEBUG_C)		 	&& \
	defined(TTLS_SSL_PROTO_TLS1_2)	&& \
	defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
	if (ssl->minor_ver == TTLS_SSL_MINOR_VERSION_3)
	{
		ttls_pk_type_t sig_alg = ttls_ssl_get_ciphersuite_sig_alg(ciphersuite_info);
		if (sig_alg != TTLS_PK_NONE)
		{
			ttls_md_type_t md_alg = ttls_ssl_sig_hash_set_find(&ssl->handshake->hash_algs,
										  sig_alg);
			TTLS_SSL_DEBUG_MSG(3, ("client hello v3, signature_algorithm ext: %d",
						ttls_ssl_hash_from_md_alg(md_alg)));
		}
		else
		{
			TTLS_SSL_DEBUG_MSG(3, ("no hash algorithm for signature algorithm "
						"%d - should not happen", sig_alg));
		}
	}
#endif

	TTLS_SSL_DEBUG_MSG(2, ("<= parse client hello"));

	return 0;
}

#if defined(TTLS_SSL_TRUNCATED_HMAC)
static void ssl_write_truncated_hmac_ext(ttls_ssl_context *ssl,
					  unsigned char *buf,
					  size_t *olen)
{
	unsigned char *p = buf;

	if (ssl->session_negotiate->trunc_hmac == TTLS_SSL_TRUNC_HMAC_DISABLED)
	{
		*olen = 0;
		return;
	}

	TTLS_SSL_DEBUG_MSG(3, ("server hello, adding truncated hmac extension"));

	*p++ = (unsigned char)((TTLS_TLS_EXT_TRUNCATED_HMAC >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_TRUNCATED_HMAC	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
}
#endif /* TTLS_SSL_TRUNCATED_HMAC */

#if defined(TTLS_SSL_ENCRYPT_THEN_MAC)
static void ssl_write_encrypt_then_mac_ext(ttls_ssl_context *ssl,
					unsigned char *buf,
					size_t *olen)
{
	unsigned char *p = buf;
	const ttls_ssl_ciphersuite_t *suite = NULL;
	const ttls_cipher_info_t *cipher = NULL;

	if (ssl->session_negotiate->encrypt_then_mac == TTLS_SSL_ETM_DISABLED ||
		ssl->minor_ver == TTLS_SSL_MINOR_VERSION_0)
	{
		*olen = 0;
		return;
	}

	/*
	 * RFC 7366: "If a server receives an encrypt-then-MAC request extension
	 * from a client and then selects a stream or Authenticated Encryption
	 * with Associated Data (AEAD) ciphersuite, it MUST NOT send an
	 * encrypt-then-MAC response extension back to the client."
	 */
	if ((suite = ttls_ssl_ciphersuite_from_id(
			ssl->session_negotiate->ciphersuite)) == NULL ||
		(cipher = ttls_cipher_info_from_type(suite->cipher)) == NULL ||
		cipher->mode != TTLS_MODE_CBC)
	{
		*olen = 0;
		return;
	}

	TTLS_SSL_DEBUG_MSG(3, ("server hello, adding encrypt then mac extension"));

	*p++ = (unsigned char)((TTLS_TLS_EXT_ENCRYPT_THEN_MAC >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_ENCRYPT_THEN_MAC	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
}
#endif /* TTLS_SSL_ENCRYPT_THEN_MAC */

#if defined(TTLS_SSL_EXTENDED_MASTER_SECRET)
static void ssl_write_extended_ms_ext(ttls_ssl_context *ssl,
				   unsigned char *buf,
				   size_t *olen)
{
	unsigned char *p = buf;

	if (ssl->handshake->extended_ms == TTLS_SSL_EXTENDED_MS_DISABLED ||
		ssl->minor_ver == TTLS_SSL_MINOR_VERSION_0)
	{
		*olen = 0;
		return;
	}

	TTLS_SSL_DEBUG_MSG(3, ("server hello, adding extended master secret "
						"extension"));

	*p++ = (unsigned char)((TTLS_TLS_EXT_EXTENDED_MASTER_SECRET >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_EXTENDED_MASTER_SECRET	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
}
#endif /* TTLS_SSL_EXTENDED_MASTER_SECRET */

#if defined(TTLS_SSL_SESSION_TICKETS)
static void ssl_write_session_ticket_ext(ttls_ssl_context *ssl,
					  unsigned char *buf,
					  size_t *olen)
{
	unsigned char *p = buf;

	if (ssl->handshake->new_session_ticket == 0)
	{
		*olen = 0;
		return;
	}

	TTLS_SSL_DEBUG_MSG(3, ("server hello, adding session ticket extension"));

	*p++ = (unsigned char)((TTLS_TLS_EXT_SESSION_TICKET >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_SESSION_TICKET	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
}
#endif /* TTLS_SSL_SESSION_TICKETS */

static void ssl_write_renegotiation_ext(ttls_ssl_context *ssl,
					 unsigned char *buf,
					 size_t *olen)
{
	unsigned char *p = buf;

	if (ssl->secure_renegotiation != TTLS_SSL_SECURE_RENEGOTIATION)
	{
		*olen = 0;
		return;
	}

	TTLS_SSL_DEBUG_MSG(3, ("server hello, secure renegotiation extension"));

	*p++ = (unsigned char)((TTLS_TLS_EXT_RENEGOTIATION_INFO >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_RENEGOTIATION_INFO	 ) & 0xFF);
	*p++ = 0x00;
	*p++ = 0x01;
	*p++ = 0x00;

	*olen = p - buf;
}

#if defined(TTLS_SSL_MAX_FRAGMENT_LENGTH)
static void ssl_write_max_fragment_length_ext(ttls_ssl_context *ssl,
					   unsigned char *buf,
					   size_t *olen)
{
	unsigned char *p = buf;

	if (ssl->session_negotiate->mfl_code == TTLS_SSL_MAX_FRAG_LEN_NONE)
	{
		*olen = 0;
		return;
	}

	TTLS_SSL_DEBUG_MSG(3, ("server hello, max_fragment_length extension"));

	*p++ = (unsigned char)((TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 1;

	*p++ = ssl->session_negotiate->mfl_code;

	*olen = 5;
}
#endif /* TTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static void ssl_write_supported_point_formats_ext(ttls_ssl_context *ssl,
						   unsigned char *buf,
						   size_t *olen)
{
	unsigned char *p = buf;
	((void) ssl);

	if ((ssl->handshake->cli_exts &
		  TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT) == 0)
	{
		*olen = 0;
		return;
	}

	TTLS_SSL_DEBUG_MSG(3, ("server hello, supported_point_formats extension"));

	*p++ = (unsigned char)((TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 2;

	*p++ = 1;
	*p++ = TTLS_ECP_PF_UNCOMPRESSED;

	*olen = 6;
}
#endif /* TTLS_ECDH_C || TTLS_ECDSA_C || TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static void ssl_write_ecjpake_kkpp_ext(ttls_ssl_context *ssl,
					unsigned char *buf,
					size_t *olen)
{
	int ret;
	unsigned char *p = buf;
	const unsigned char *end = ssl->out_msg + TTLS_SSL_MAX_CONTENT_LEN;
	size_t kkpp_len;

	*olen = 0;

	/* Skip costly computation if not needed */
	if (ssl->transform_negotiate->ciphersuite_info->key_exchange !=
		TTLS_KEY_EXCHANGE_ECJPAKE)
		return;

	TTLS_SSL_DEBUG_MSG(3, ("server hello, ecjpake kkpp extension"));

	if (end - p < 4)
	{
		TTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
		return;
	}

	*p++ = (unsigned char)((TTLS_TLS_EXT_ECJPAKE_KKPP >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_ECJPAKE_KKPP	 ) & 0xFF);

	ret = ttls_ecjpake_write_round_one(&ssl->handshake->ecjpake_ctx,
					p + 2, end - p - 2, &kkpp_len,
					ssl->conf->f_rng, ssl->conf->p_rng);
	if (ret != 0)
	{
		TTLS_SSL_DEBUG_RET(1 , "ttls_ecjpake_write_round_one", ret);
		return;
	}

	*p++ = (unsigned char)((kkpp_len >> 8) & 0xFF);
	*p++ = (unsigned char)((kkpp_len	 ) & 0xFF);

	*olen = kkpp_len + 4;
}
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

static void ssl_write_alpn_ext(ttls_ssl_context *ssl,
				unsigned char *buf, size_t *olen)
{
	if (ssl->alpn_chosen == NULL)
	{
		*olen = 0;
		return;
	}

	TTLS_SSL_DEBUG_MSG(3, ("server hello, adding alpn extension"));

	/*
	 * 0 . 1	ext identifier
	 * 2 . 3	ext length
	 * 4 . 5	protocol list length
	 * 6 . 6	protocol name length
	 * 7 . 7+n  protocol name
	 */
	buf[0] = (unsigned char)((TTLS_TLS_EXT_ALPN >> 8) & 0xFF);
	buf[1] = (unsigned char)((TTLS_TLS_EXT_ALPN	 ) & 0xFF);

	*olen = 7 + strlen(ssl->alpn_chosen);

	buf[2] = (unsigned char)(((*olen - 4) >> 8) & 0xFF);
	buf[3] = (unsigned char)(((*olen - 4)	 ) & 0xFF);

	buf[4] = (unsigned char)(((*olen - 6) >> 8) & 0xFF);
	buf[5] = (unsigned char)(((*olen - 6)	 ) & 0xFF);

	buf[6] = (unsigned char)(((*olen - 7)	 ) & 0xFF);

	memcpy(buf + 7, ssl->alpn_chosen, *olen - 7);
}

#if defined(TTLS_SSL_DTLS_HELLO_VERIFY)
static int ssl_write_hello_verify_request(ttls_ssl_context *ssl)
{
	int ret;
	unsigned char *p = ssl->out_msg + 4;
	unsigned char *cookie_len_byte;

	TTLS_SSL_DEBUG_MSG(2, ("=> write hello verify request"));

	/*
	 * struct {
	 *   ProtocolVersion server_version;
	 *   opaque cookie<0..2^8-1>;
	 * } HelloVerifyRequest;
	 */

	/* The RFC is not clear on this point, but sending the actual negotiated
	 * version looks like the most interoperable thing to do. */
	ttls_ssl_write_version(ssl->major_ver, ssl->minor_ver,
					   ssl->conf->transport, p);
	TTLS_SSL_DEBUG_BUF(3, "server version", p, 2);
	p += 2;

	/* If we get here, f_cookie_check is not null */
	if (ssl->conf->f_cookie_write == NULL)
	{
		TTLS_SSL_DEBUG_MSG(1, ("inconsistent cookie callbacks"));
		return(TTLS_ERR_SSL_INTERNAL_ERROR);
	}

	/* Skip length byte until we know the length */
	cookie_len_byte = p++;

	if ((ret = ssl->conf->f_cookie_write(ssl->conf->p_cookie,
					 &p, ssl->out_buf + TTLS_SSL_BUFFER_LEN,
					 ssl->cli_id, ssl->cli_id_len)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "f_cookie_write", ret);
		return ret;
	}

	*cookie_len_byte = (unsigned char)(p - (cookie_len_byte + 1));

	TTLS_SSL_DEBUG_BUF(3, "cookie sent", cookie_len_byte + 1, *cookie_len_byte);

	ssl->out_msglen  = p - ssl->out_msg;
	ssl->out_msgtype = TTLS_SSL_MSG_HANDSHAKE;
	ssl->out_msg[0]  = TTLS_SSL_HS_HELLO_VERIFY_REQUEST;

	ssl->state = TTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT;

	if ((ret = ttls_ssl_write_record(ssl)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_write_record", ret);
		return ret;
	}

	TTLS_SSL_DEBUG_MSG(2, ("<= write hello verify request"));

	return 0;
}
#endif /* TTLS_SSL_DTLS_HELLO_VERIFY */

static int ssl_write_server_hello(ttls_ssl_context *ssl)
{
	time_t t;
	int ret;
	size_t olen, ext_len = 0, n;
	unsigned char *buf, *p;

	TTLS_SSL_DEBUG_MSG(2, ("=> write server hello"));

#if defined(TTLS_SSL_DTLS_HELLO_VERIFY)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM &&
		ssl->handshake->verify_cookie_len != 0)
	{
		TTLS_SSL_DEBUG_MSG(2, ("client hello was not authenticated"));
		TTLS_SSL_DEBUG_MSG(2, ("<= write server hello"));

		return(ssl_write_hello_verify_request(ssl));
	}
#endif /* TTLS_SSL_DTLS_HELLO_VERIFY */

	if (ssl->conf->f_rng == NULL)
	{
		TTLS_SSL_DEBUG_MSG(1, ("no RNG provided"));
		return(TTLS_ERR_SSL_NO_RNG);
	}

	/*
	 *	 0  .   0   handshake type
	 *	 1  .   3   handshake length
	 *	 4  .   5   protocol version
	 *	 6  .   9   UNIX time()
	 *	10  .  37   random bytes
	 */
	buf = ssl->out_msg;
	p = buf + 4;

	ttls_ssl_write_version(ssl->major_ver, ssl->minor_ver,
					   ssl->conf->transport, p);
	p += 2;

	TTLS_SSL_DEBUG_MSG(3, ("server hello, chosen version: [%d:%d]",
						buf[4], buf[5]));

	t = ttls_time(NULL);
	*p++ = (unsigned char)(t >> 24);
	*p++ = (unsigned char)(t >> 16);
	*p++ = (unsigned char)(t >>  8);
	*p++ = (unsigned char)(t	  );

	TTLS_SSL_DEBUG_MSG(3, ("server hello, current time: %lu", t));

	if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, p, 28)) != 0)
		return ret;

	p += 28;

	memcpy(ssl->handshake->randbytes + 32, buf + 6, 32);

	TTLS_SSL_DEBUG_BUF(3, "server hello, random bytes", buf + 6, 32);

	/*
	 * Resume is 0  by default, see ssl_handshake_init().
	 * It may be already set to 1 by ssl_parse_session_ticket_ext().
	 * If not, try looking up session ID in our cache.
	 */
	if (ssl->handshake->resume == 0 &&
		ssl->session_negotiate->id_len != 0 &&
		ssl->conf->f_get_cache != NULL &&
		ssl->conf->f_get_cache(ssl->conf->p_cache, ssl->session_negotiate) == 0)
	{
		TTLS_SSL_DEBUG_MSG(3, ("session successfully restored from cache"));
		ssl->handshake->resume = 1;
	}

	if (ssl->handshake->resume == 0)
	{
		/*
		 * New session, create a new session id,
		 * unless we're about to issue a session ticket
		 */
		ssl->state++;

		ssl->session_negotiate->start = ttls_time(NULL);

#if defined(TTLS_SSL_SESSION_TICKETS)
		if (ssl->handshake->new_session_ticket != 0)
		{
			ssl->session_negotiate->id_len = n = 0;
			memset(ssl->session_negotiate->id, 0, 32);
		}
		else
#endif /* TTLS_SSL_SESSION_TICKETS */
		{
			ssl->session_negotiate->id_len = n = 32;
			if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, ssl->session_negotiate->id,
									n)) != 0)
				return ret;
		}
	}
	else
	{
		/*
		 * Resuming a session
		 */
		n = ssl->session_negotiate->id_len;
		ssl->state = TTLS_SSL_SERVER_CHANGE_CIPHER_SPEC;

		if ((ret = ttls_ssl_derive_keys(ssl)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_derive_keys", ret);
			return ret;
		}
	}

	/*
	 *	38  .  38	 session id length
	 *	39  . 38+n	session id
	 *   39+n . 40+n	chosen ciphersuite
	 *   41+n . 41+n	chosen compression alg.
	 *   42+n . 43+n	extensions length
	 *   44+n . 43+n+m  extensions
	 */
	*p++ = (unsigned char) ssl->session_negotiate->id_len;
	memcpy(p, ssl->session_negotiate->id, ssl->session_negotiate->id_len);
	p += ssl->session_negotiate->id_len;

	TTLS_SSL_DEBUG_MSG(3, ("server hello, session id len.: %d", n));
	TTLS_SSL_DEBUG_BUF(3,   "server hello, session id", buf + 39, n);
	TTLS_SSL_DEBUG_MSG(3, ("%s session has been resumed",
				   ssl->handshake->resume ? "a" : "no"));

	*p++ = (unsigned char)(ssl->session_negotiate->ciphersuite >> 8);
	*p++ = (unsigned char)(ssl->session_negotiate->ciphersuite	 );
	*p++ = (unsigned char)(ssl->session_negotiate->compression	 );

	TTLS_SSL_DEBUG_MSG(3, ("server hello, chosen ciphersuite: %s",
		   ttls_ssl_get_ciphersuite_name(ssl->session_negotiate->ciphersuite)));
	TTLS_SSL_DEBUG_MSG(3, ("server hello, compress alg.: 0x%02X",
				   ssl->session_negotiate->compression));

	/* Do not write the extensions if the protocol is SSLv3 */
#if defined(TTLS_SSL_PROTO_SSL3)
	if ((ssl->major_ver != 3) || (ssl->minor_ver != 0))
	{
#endif

	/*
	 *  First write extensions, then the total length
	 */
	ssl_write_renegotiation_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

#if defined(TTLS_SSL_MAX_FRAGMENT_LENGTH)
	ssl_write_max_fragment_length_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_SSL_TRUNCATED_HMAC)
	ssl_write_truncated_hmac_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_SSL_ENCRYPT_THEN_MAC)
	ssl_write_encrypt_then_mac_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_SSL_EXTENDED_MASTER_SECRET)
	ssl_write_extended_ms_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_SSL_SESSION_TICKETS)
	ssl_write_session_ticket_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	ssl_write_supported_point_formats_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	ssl_write_ecjpake_kkpp_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

	ssl_write_alpn_ext(ssl, p + 2 + ext_len, &olen);
	ext_len += olen;

	TTLS_SSL_DEBUG_MSG(3, ("server hello, total extension length: %d", ext_len));

	if (ext_len > 0)
	{
		*p++ = (unsigned char)((ext_len >> 8) & 0xFF);
		*p++ = (unsigned char)((ext_len	 ) & 0xFF);
		p += ext_len;
	}

#if defined(TTLS_SSL_PROTO_SSL3)
	}
#endif

	ssl->out_msglen  = p - buf;
	ssl->out_msgtype = TTLS_SSL_MSG_HANDSHAKE;
	ssl->out_msg[0]  = TTLS_SSL_HS_SERVER_HELLO;

	ret = ttls_ssl_write_record(ssl);

	TTLS_SSL_DEBUG_MSG(2, ("<= write server hello"));

	return ret;
}

#if !defined(TTLS_KEY_EXCHANGE_RSA_ENABLED)	   && \
	!defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)   && \
	!defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)  && \
	!defined(TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) && \
	!defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)&& \
	!defined(TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_write_certificate_request(ttls_ssl_context *ssl)
{
	const ttls_ssl_ciphersuite_t *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;

	TTLS_SSL_DEBUG_MSG(2, ("=> write certificate request"));

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		TTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate request"));
		ssl->state++;
		return 0;
	}

	TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
	return(TTLS_ERR_SSL_INTERNAL_ERROR);
}
#else
static int ssl_write_certificate_request(ttls_ssl_context *ssl)
{
	int ret = TTLS_ERR_SSL_FEATURE_UNAVAILABLE;
	const ttls_ssl_ciphersuite_t *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;
	size_t dn_size, total_dn_size; /* excluding length bytes */
	size_t ct_len, sa_len; /* including length bytes */
	unsigned char *buf, *p;
	const unsigned char * const end = ssl->out_msg + TTLS_SSL_MAX_CONTENT_LEN;
	const ttls_x509_crt *crt;
	int authmode;

	TTLS_SSL_DEBUG_MSG(2, ("=> write certificate request"));

	ssl->state++;

	if (ssl->handshake->sni_authmode != TTLS_SSL_VERIFY_UNSET)
		authmode = ssl->handshake->sni_authmode;
	else
		authmode = ssl->conf->authmode;

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE ||
		authmode == TTLS_SSL_VERIFY_NONE)
	{
		TTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate request"));
		return 0;
	}

	/*
	 *	 0  .   0   handshake type
	 *	 1  .   3   handshake length
	 *	 4  .   4   cert type count
	 *	 5  .. m-1  cert types
	 *	 m  .. m+1  sig alg length (TLS 1.2 only)
	 *	m+1 .. n-1  SignatureAndHashAlgorithms (TLS 1.2 only)
	 *	 n  .. n+1  length of all DNs
	 *	n+2 .. n+3  length of DN 1
	 *	n+4 .. ...  Distinguished Name #1
	 *	... .. ...  length of DN 2, etc.
	 */
	buf = ssl->out_msg;
	p = buf + 4;

	/*
	 * Supported certificate types
	 *
	 *	 ClientCertificateType certificate_types<1..2^8-1>;
	 *	 enum { (255) } ClientCertificateType;
	 */
	ct_len = 0;

	p[1 + ct_len++] = TTLS_SSL_CERT_TYPE_RSA_SIGN;
#if defined(TTLS_ECDSA_C)
	p[1 + ct_len++] = TTLS_SSL_CERT_TYPE_ECDSA_SIGN;
#endif

	p[0] = (unsigned char) ct_len++;
	p += ct_len;

	sa_len = 0;
#if defined(TTLS_SSL_PROTO_TLS1_2)
	/*
	 * Add signature_algorithms for verify (TLS 1.2)
	 *
	 *	 SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>;
	 *
	 *	 struct {
	 *		   HashAlgorithm hash;
	 *		   SignatureAlgorithm signature;
	 *	 } SignatureAndHashAlgorithm;
	 *
	 *	 enum { (255) } HashAlgorithm;
	 *	 enum { (255) } SignatureAlgorithm;
	 */
	if (ssl->minor_ver == TTLS_SSL_MINOR_VERSION_3)
	{
		const int *cur;

		/*
		 * Supported signature algorithms
		 */
		for (cur = ssl->conf->sig_hashes; *cur != TTLS_MD_NONE; cur++)
		{
			unsigned char hash = ttls_ssl_hash_from_md_alg(*cur);

			if (TTLS_SSL_HASH_NONE == hash || ttls_ssl_set_calc_verify_md(ssl, hash))
				continue;

			p[2 + sa_len++] = hash;
			p[2 + sa_len++] = TTLS_SSL_SIG_RSA;
#if defined(TTLS_ECDSA_C)
			p[2 + sa_len++] = hash;
			p[2 + sa_len++] = TTLS_SSL_SIG_ECDSA;
#endif
		}

		p[0] = (unsigned char)(sa_len >> 8);
		p[1] = (unsigned char)(sa_len	 );
		sa_len += 2;
		p += sa_len;
	}
#endif /* TTLS_SSL_PROTO_TLS1_2 */

	/*
	 * DistinguishedName certificate_authorities<0..2^16-1>;
	 * opaque DistinguishedName<1..2^16-1>;
	 */
	p += 2;

	total_dn_size = 0;

	if (ssl->conf->cert_req_ca_list ==  TTLS_SSL_CERT_REQ_CA_LIST_ENABLED)
	{
		if (ssl->handshake->sni_ca_chain != NULL)
			crt = ssl->handshake->sni_ca_chain;
		else
			crt = ssl->conf->ca_chain;

		while (crt != NULL && crt->version != 0)
		{
			dn_size = crt->subject_raw.len;

			if (end < p ||
				(size_t)(end - p) < dn_size ||
				(size_t)(end - p) < 2 + dn_size)
			{
				TTLS_SSL_DEBUG_MSG(1, ("skipping CAs: buffer too short"));
				break;
			}

			*p++ = (unsigned char)(dn_size >> 8);
			*p++ = (unsigned char)(dn_size	 );
			memcpy(p, crt->subject_raw.p, dn_size);
			p += dn_size;

			TTLS_SSL_DEBUG_BUF(3, "requested DN", p - dn_size, dn_size);

			total_dn_size += 2 + dn_size;
			crt = crt->next;
		}
	}

	ssl->out_msglen  = p - buf;
	ssl->out_msgtype = TTLS_SSL_MSG_HANDSHAKE;
	ssl->out_msg[0]  = TTLS_SSL_HS_CERTIFICATE_REQUEST;
	ssl->out_msg[4 + ct_len + sa_len] = (unsigned char)(total_dn_size  >> 8);
	ssl->out_msg[5 + ct_len + sa_len] = (unsigned char)(total_dn_size	  );

	ret = ttls_ssl_write_record(ssl);

	TTLS_SSL_DEBUG_MSG(2, ("<= write certificate request"));

	return ret;
}
#endif /* !TTLS_KEY_EXCHANGE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
static int ssl_get_ecdh_params_from_cert(ttls_ssl_context *ssl)
{
	int ret;

	if (! ttls_pk_can_do(ttls_ssl_own_key(ssl), TTLS_PK_ECKEY))
	{
		TTLS_SSL_DEBUG_MSG(1, ("server key not ECDH capable"));
		return(TTLS_ERR_SSL_PK_TYPE_MISMATCH);
	}

	if ((ret = ttls_ecdh_get_params(&ssl->handshake->ecdh_ctx,
					 ttls_pk_ec(*ttls_ssl_own_key(ssl)),
					 TTLS_ECDH_OURS)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, ("ttls_ecdh_get_params"), ret);
		return ret;
	}

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) ||
		  TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED */

static int ssl_write_server_key_exchange(ttls_ssl_context *ssl)
{
	int ret;
	size_t n = 0;
	const ttls_ssl_ciphersuite_t *ciphersuite_info
		= ssl->transform_negotiate->ciphersuite_info;

#if defined(TTLS_KEY_EXCHANGE__SOME_PFS__ENABLED)
	unsigned char *p = ssl->out_msg + 4;
	size_t len;
#if defined(TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED)
	unsigned char *dig_signed = p;
	size_t dig_signed_len = 0;
#endif /* TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED */
#endif /* TTLS_KEY_EXCHANGE__SOME_PFS__ENABLED */

	TTLS_SSL_DEBUG_MSG(2, ("=> write server key exchange"));

	/*
	 *
	 * Part 1: Extract static ECDH parameters and abort
	 *		 if ServerKeyExchange not needed.
	 *
	 */

	/* For suites involving ECDH, extract DH parameters
	 * from certificate at this point. */
#if defined(TTLS_KEY_EXCHANGE__SOME__ECDH_ENABLED)
	if (ttls_ssl_ciphersuite_uses_ecdh(ciphersuite_info))
	{
		ssl_get_ecdh_params_from_cert(ssl);
	}
#endif /* TTLS_KEY_EXCHANGE__SOME__ECDH_ENABLED */

	/* Key exchanges not involving ephemeral keys don't use
	 * ServerKeyExchange, so end here. */
#if defined(TTLS_KEY_EXCHANGE__SOME_NON_PFS__ENABLED)
	if (ttls_ssl_ciphersuite_no_pfs(ciphersuite_info))
	{
		TTLS_SSL_DEBUG_MSG(2, ("<= skip write server key exchange"));
		ssl->state++;
		return 0;
	}
#endif /* TTLS_KEY_EXCHANGE__NON_PFS__ENABLED */

	/*
	 *
	 * Part 2: Provide key exchange parameters for chosen ciphersuite.
	 *
	 */

	/*
	 * - ECJPAKE key exchanges
	 */
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		const unsigned char *end = ssl->out_msg + TTLS_SSL_MAX_CONTENT_LEN;

		ret = ttls_ecjpake_write_round_two(&ssl->handshake->ecjpake_ctx,
				p, end - p, &len, ssl->conf->f_rng, ssl->conf->p_rng);
		if (ret != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecjpake_write_round_two", ret);
			return ret;
		}

		p += len;
		n += len;
	}
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

	/*
	 * For (EC)DHE key exchanges with PSK, parameters are prefixed by support
	 * identity hint (RFC 4279, Sec. 3). Until someone needs this feature,
	 * we use empty support identity hints here.
	 **/
#if defined(TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)   || \
	defined(TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK)
	{
		*(p++) = 0x00;
		*(p++) = 0x00;

		n += 2;
	}
#endif /* TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */

	/*
	 * - DHE key exchanges
	 */
#if defined(TTLS_KEY_EXCHANGE__SOME__DHE_ENABLED)
	if (ttls_ssl_ciphersuite_uses_dhe(ciphersuite_info))
	{
		if (ssl->conf->dhm_P.p == NULL || ssl->conf->dhm_G.p == NULL)
		{
			TTLS_SSL_DEBUG_MSG(1, ("no DH parameters set"));
			return(TTLS_ERR_SSL_BAD_INPUT_DATA);
		}

		/*
		 * Ephemeral DH parameters:
		 *
		 * struct {
		 *	 opaque dh_p<1..2^16-1>;
		 *	 opaque dh_g<1..2^16-1>;
		 *	 opaque dh_Ys<1..2^16-1>;
		 * } ServerDHParams;
		 */
		if ((ret = ttls_dhm_set_group(&ssl->handshake->dhm_ctx,
						   &ssl->conf->dhm_P,
						   &ssl->conf->dhm_G)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_dhm_set_group", ret);
			return ret;
		}

		if ((ret = ttls_dhm_make_params(&ssl->handshake->dhm_ctx,
						(int) ttls_mpi_size(&ssl->handshake->dhm_ctx.P),
						p, &len, ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_dhm_make_params", ret);
			return ret;
		}

#if defined(TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED)		
		dig_signed = p;
		dig_signed_len = len;
#endif

		p += len;
		n += len;

		TTLS_SSL_DEBUG_MPI(3, "DHM: X ", &ssl->handshake->dhm_ctx.X );
		TTLS_SSL_DEBUG_MPI(3, "DHM: P ", &ssl->handshake->dhm_ctx.P );
		TTLS_SSL_DEBUG_MPI(3, "DHM: G ", &ssl->handshake->dhm_ctx.G );
		TTLS_SSL_DEBUG_MPI(3, "DHM: GX", &ssl->handshake->dhm_ctx.GX);
	}
#endif /* TTLS_KEY_EXCHANGE__SOME__DHE_ENABLED */

	/*
	 * - ECDHE key exchanges
	 */
#if defined(TTLS_KEY_EXCHANGE__SOME__ECDHE_ENABLED)
	if (ttls_ssl_ciphersuite_uses_ecdhe(ciphersuite_info))
	{
		/*
		 * Ephemeral ECDH parameters:
		 *
		 * struct {
		 *	 ECParameters curve_params;
		 *	 ECPoint	  public;
		 * } ServerECDHParams;
		 */
		const ttls_ecp_curve_info **curve = NULL;
		const ttls_ecp_group_id *gid;

		/* Match our preference list against the offered curves */
		for (gid = ssl->conf->curve_list; *gid != TTLS_ECP_DP_NONE; gid++)
			for (curve = ssl->handshake->curves; *curve != NULL; curve++)
				if ((*curve)->grp_id == *gid)
					goto curve_matching_done;

curve_matching_done:
		if (curve == NULL || *curve == NULL)
		{
			TTLS_SSL_DEBUG_MSG(1, ("no matching curve for ECDHE"));
			return(TTLS_ERR_SSL_NO_CIPHER_CHOSEN);
		}

		TTLS_SSL_DEBUG_MSG(2, ("ECDHE curve: %s", (*curve)->name));

		if ((ret = ttls_ecp_group_load(&ssl->handshake->ecdh_ctx.grp,
						   (*curve)->grp_id)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecp_group_load", ret);
			return ret;
		}

		if ((ret = ttls_ecdh_make_params(&ssl->handshake->ecdh_ctx, &len,
						  p, TTLS_SSL_MAX_CONTENT_LEN - n,
						  ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecdh_make_params", ret);
			return ret;
		}

#if defined(TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED)
		dig_signed	 = p;
		dig_signed_len = len;
#endif

		p += len;
		n += len;

		TTLS_SSL_DEBUG_ECP(3, "ECDH: Q ", &ssl->handshake->ecdh_ctx.Q);
	}
#endif /* TTLS_KEY_EXCHANGE__SOME__ECDHE_ENABLED */

	/*
	 *
	 * Part 3: For key exchanges involving the server signing the
	 *		 exchange parameters, compute and add the signature here.
	 *
	 */
#if defined(TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED)
	if (ttls_ssl_ciphersuite_uses_server_signature(ciphersuite_info))
	{
		size_t signature_len = 0;
		unsigned int hashlen = 0;
		unsigned char hash[64];

		/*
		 * 3.1: Choose hash algorithm:
		 * A: For TLS 1.2, obey signature-hash-algorithm extension 
		 *	to choose appropriate hash.
		 * B: For SSL3, TLS1.0, TLS1.1 and ECDHE_ECDSA, use SHA1
		 *	(RFC 4492, Sec. 5.4)
		 * C: Otherwise, use MD5 + SHA1 (RFC 4346, Sec. 7.4.3)
		 */

		ttls_md_type_t md_alg;

#if defined(TTLS_SSL_PROTO_TLS1_2)
		ttls_pk_type_t sig_alg =
			ttls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info);
		if (ssl->minor_ver == TTLS_SSL_MINOR_VERSION_3)
		{
			/* A: For TLS 1.2, obey signature-hash-algorithm extension
			 *	(RFC 5246, Sec. 7.4.1.4.1). */
			if (sig_alg == TTLS_PK_NONE ||
				(md_alg = ttls_ssl_sig_hash_set_find(&ssl->handshake->hash_algs,
								  sig_alg)) == TTLS_MD_NONE)
			{
				TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
				/* (... because we choose a cipher suite 
				 *	  only if there is a matching hash.) */
				return(TTLS_ERR_SSL_INTERNAL_ERROR);
			}
		}
		else
#endif /* TTLS_SSL_PROTO_TLS1_2 */
#if defined(TTLS_SSL_PROTO_SSL3) || defined(TTLS_SSL_PROTO_TLS1) || \
	defined(TTLS_SSL_PROTO_TLS1_1)
		if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_ECDSA)
		{
			/* B: Default hash SHA1 */
			md_alg = TTLS_MD_SHA1;
		}
		else
#endif /* TTLS_SSL_PROTO_SSL3 || TTLS_SSL_PROTO_TLS1 || \
		  TTLS_SSL_PROTO_TLS1_1 */
		{
			/* C: MD5 + SHA1 */
			md_alg = TTLS_MD_NONE;
		}

		TTLS_SSL_DEBUG_MSG(3, ("pick hash algorithm %d for signing", md_alg));

		/*
		 * 3.2: Compute the hash to be signed
		 */
#if defined(TTLS_SSL_PROTO_SSL3) || defined(TTLS_SSL_PROTO_TLS1) || \
	defined(TTLS_SSL_PROTO_TLS1_1)
		if (md_alg == TTLS_MD_NONE)
		{
			hashlen = 36;
			ret = ttls_ssl_get_key_exchange_md_ssl_tls(ssl, hash,
								   dig_signed,
								   dig_signed_len);
			if (ret != 0)
				return ret;
		}
		else
#endif /* TTLS_SSL_PROTO_SSL3 || TTLS_SSL_PROTO_TLS1 || \
		  TTLS_SSL_PROTO_TLS1_1 */
#if defined(TTLS_SSL_PROTO_TLS1) || defined(TTLS_SSL_PROTO_TLS1_1) || \
	defined(TTLS_SSL_PROTO_TLS1_2)
		if (md_alg != TTLS_MD_NONE)
		{
			/* Info from md_alg will be used instead */
			hashlen = 0;
			ret = ttls_ssl_get_key_exchange_md_tls1_2(ssl, hash,
								  dig_signed,
								  dig_signed_len,
								  md_alg);
			if (ret != 0)
				return ret;
		}
		else
#endif /* TTLS_SSL_PROTO_TLS1 || TTLS_SSL_PROTO_TLS1_1 || \
		  TTLS_SSL_PROTO_TLS1_2 */
		{
			TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
			return(TTLS_ERR_SSL_INTERNAL_ERROR);
		}

		TTLS_SSL_DEBUG_BUF(3, "parameters hash", hash, hashlen != 0 ? hashlen :
			(unsigned int) (ttls_md_get_size(ttls_md_info_from_type(md_alg))));

		/*
		 * 3.3: Compute and add the signature
		 */
		if (ttls_ssl_own_key(ssl) == NULL)
		{
			TTLS_SSL_DEBUG_MSG(1, ("got no private key"));
			return(TTLS_ERR_SSL_PRIVATE_KEY_REQUIRED);
		}

#if defined(TTLS_SSL_PROTO_TLS1_2)
		if (ssl->minor_ver == TTLS_SSL_MINOR_VERSION_3)
		{
			/*
			 * For TLS 1.2, we need to specify signature and hash algorithm
			 * explicitly through a prefix to the signature.
			 *
			 * struct {
			 *	HashAlgorithm hash;
			 *	SignatureAlgorithm signature;
			 * } SignatureAndHashAlgorithm;
			 *
			 * struct {
			 *	SignatureAndHashAlgorithm algorithm;
			 *	opaque signature<0..2^16-1>;
			 * } DigitallySigned;
			 *
			 */

			*(p++) = ttls_ssl_hash_from_md_alg(md_alg);
			*(p++) = ttls_ssl_sig_from_pk_alg(sig_alg);

			n += 2;
		}
#endif /* TTLS_SSL_PROTO_TLS1_2 */

		if ((ret = ttls_pk_sign(ttls_ssl_own_key(ssl), md_alg, hash, hashlen,
						p + 2 , &signature_len, ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_pk_sign", ret);
			return ret;
		}

		*(p++) = (unsigned char)(signature_len >> 8);
		*(p++) = (unsigned char)(signature_len	 );
		n += 2;

		TTLS_SSL_DEBUG_BUF(3, "my signature", p, signature_len);

		n += signature_len;
	}
#endif /* TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED */

	/* Done with actual work; add header and send. */

	ssl->out_msglen  = 4 + n;
	ssl->out_msgtype = TTLS_SSL_MSG_HANDSHAKE;
	ssl->out_msg[0]  = TTLS_SSL_HS_SERVER_KEY_EXCHANGE;

	ssl->state++;

	if ((ret = ttls_ssl_write_record(ssl)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_write_record", ret);
		return ret;
	}

	TTLS_SSL_DEBUG_MSG(2, ("<= write server key exchange"));

	return 0;
}

static int ssl_write_server_hello_done(ttls_ssl_context *ssl)
{
	int ret;

	TTLS_SSL_DEBUG_MSG(2, ("=> write server hello done"));

	ssl->out_msglen  = 4;
	ssl->out_msgtype = TTLS_SSL_MSG_HANDSHAKE;
	ssl->out_msg[0]  = TTLS_SSL_HS_SERVER_HELLO_DONE;

	ssl->state++;

#if defined(TTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
		ttls_ssl_send_flight_completed(ssl);
#endif

	if ((ret = ttls_ssl_write_record(ssl)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_write_record", ret);
		return ret;
	}

	TTLS_SSL_DEBUG_MSG(2, ("<= write server hello done"));

	return 0;
}

#if defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
static int ssl_parse_client_dh_public(ttls_ssl_context *ssl, unsigned char **p,
					   const unsigned char *end)
{
	int ret = TTLS_ERR_SSL_FEATURE_UNAVAILABLE;
	size_t n;

	/*
	 * Receive G^Y mod P, premaster = (G^Y)^X mod P
	 */
	if (*p + 2 > end)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
	}

	n = ((*p)[0] << 8) | (*p)[1];
	*p += 2;

	if (*p + n > end)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
	}

	if ((ret = ttls_dhm_read_public(&ssl->handshake->dhm_ctx, *p, n)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_dhm_read_public", ret);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP);
	}

	*p += n;

	TTLS_SSL_DEBUG_MPI(3, "DHM: GY", &ssl->handshake->dhm_ctx.GY);

	return ret;
}
#endif /* TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_RSA_ENABLED) ||  \
	defined(TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
static int ssl_parse_encrypted_pms(ttls_ssl_context *ssl,
				const unsigned char *p,
				const unsigned char *end,
				size_t pms_offset)
{
	int ret;
	size_t len = ttls_pk_get_len(ttls_ssl_own_key(ssl));
	unsigned char *pms = ssl->handshake->premaster + pms_offset;
	unsigned char ver[2];
	unsigned char fake_pms[48], peer_pms[48];
	unsigned char mask;
	size_t i, peer_pmslen;
	unsigned int diff;

	if (! ttls_pk_can_do(ttls_ssl_own_key(ssl), TTLS_PK_RSA))
	{
		TTLS_SSL_DEBUG_MSG(1, ("got no RSA private key"));
		return(TTLS_ERR_SSL_PRIVATE_KEY_REQUIRED);
	}

	/*
	 * Decrypt the premaster using own private RSA key
	 */
#if defined(TTLS_SSL_PROTO_TLS1) || defined(TTLS_SSL_PROTO_TLS1_1) || \
	defined(TTLS_SSL_PROTO_TLS1_2)
	if (ssl->minor_ver != TTLS_SSL_MINOR_VERSION_0)
	{
		if (*p++ != ((len >> 8) & 0xFF) ||
			*p++ != ((len	 ) & 0xFF))
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
		}
	}
#endif

	if (p + len != end)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
	}

	ttls_ssl_write_version(ssl->handshake->max_major_ver,
					   ssl->handshake->max_minor_ver,
					   ssl->conf->transport, ver);

	/*
	 * Protection against Bleichenbacher's attack: invalid PKCS#1 v1.5 padding
	 * must not cause the connection to end immediately; instead, send a
	 * bad_record_mac later in the handshake.
	 * Also, avoid data-dependant branches here to protect against
	 * timing-based variants.
	 */
	ret = ssl->conf->f_rng(ssl->conf->p_rng, fake_pms, sizeof(fake_pms));
	if (ret != 0)
		return ret;

	ret = ttls_pk_decrypt(ttls_ssl_own_key(ssl), p, len,
					  peer_pms, &peer_pmslen,
					  sizeof(peer_pms),
					  ssl->conf->f_rng, ssl->conf->p_rng);

	diff  = (unsigned int) ret;
	diff |= peer_pmslen ^ 48;
	diff |= peer_pms[0] ^ ver[0];
	diff |= peer_pms[1] ^ ver[1];

#if defined(TTLS_SSL_DEBUG_ALL)
	if (diff != 0)
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
#endif

	if (sizeof(ssl->handshake->premaster) < pms_offset ||
		sizeof(ssl->handshake->premaster) - pms_offset < 48)
	{
		TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_SSL_INTERNAL_ERROR);
	}
	ssl->handshake->pmslen = 48;

	/* mask = diff ? 0xff : 0x00 using bit operations to avoid branches */
	/* MSVC has a warning about unary minus on unsigned, but this is
	 * well-defined and precisely what we want to do here */
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4146)
#endif
	mask = - ((diff | - diff) >> (sizeof(unsigned int) * 8 - 1));
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

	for (i = 0; i < ssl->handshake->pmslen; i++)
		pms[i] = (mask & fake_pms[i]) | ((~mask) & peer_pms[i]);

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */

#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
static int ssl_parse_client_psk_identity(ttls_ssl_context *ssl, unsigned char **p,
					const unsigned char *end)
{
	int ret = 0;
	size_t n;

	if (ssl->conf->f_psk == NULL &&
		(ssl->conf->psk == NULL || ssl->conf->psk_identity == NULL ||
		  ssl->conf->psk_identity_len == 0 || ssl->conf->psk_len == 0))
	{
		TTLS_SSL_DEBUG_MSG(1, ("got no pre-shared key"));
		return(TTLS_ERR_SSL_PRIVATE_KEY_REQUIRED);
	}

	/*
	 * Receive client pre-shared key identity name
	 */
	if (end - *p < 2)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
	}

	n = ((*p)[0] << 8) | (*p)[1];
	*p += 2;

	if (n < 1 || n > 65535 || n > (size_t) (end - *p))
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
	}

	if (ssl->conf->f_psk != NULL)
	{
		if (ssl->conf->f_psk(ssl->conf->p_psk, ssl, *p, n) != 0)
			ret = TTLS_ERR_SSL_UNKNOWN_IDENTITY;
	}
	else
	{
		/* Identity is not a big secret since clients send it in the clear,
		 * but treat it carefully anyway, just in case */
		if (n != ssl->conf->psk_identity_len ||
			ttls_ssl_safer_memcmp(ssl->conf->psk_identity, *p, n) != 0)
		{
			ret = TTLS_ERR_SSL_UNKNOWN_IDENTITY;
		}
	}

	if (ret == TTLS_ERR_SSL_UNKNOWN_IDENTITY)
	{
		TTLS_SSL_DEBUG_BUF(3, "Unknown PSK identity", *p, n);
		ttls_ssl_send_alert_message(ssl, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY);
		return(TTLS_ERR_SSL_UNKNOWN_IDENTITY);
	}

	*p += n;

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

static int ssl_parse_client_key_exchange(ttls_ssl_context *ssl)
{
	int ret;
	const ttls_ssl_ciphersuite_t *ciphersuite_info;
	unsigned char *p, *end;

	ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

	TTLS_SSL_DEBUG_MSG(2, ("=> parse client key exchange"));

	if ((ret = ttls_ssl_read_record(ssl)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_read_record", ret);
		return ret;
	}

	p = ssl->in_msg + ttls_ssl_hs_hdr_len(ssl);
	end = ssl->in_msg + ssl->in_hslen;

	if (ssl->in_msgtype != TTLS_SSL_MSG_HANDSHAKE)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
	}

	if (ssl->in_msg[0] != TTLS_SSL_HS_CLIENT_KEY_EXCHANGE)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
	}

#if defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_RSA)
	{
		if ((ret = ssl_parse_client_dh_public(ssl, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_dh_public"), ret);
			return ret;
		}

		if (p != end)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange"));
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
		}

		if ((ret = ttls_dhm_calc_secret(&ssl->handshake->dhm_ctx,
						  ssl->handshake->premaster,
						  TTLS_PREMASTER_SIZE,
						 &ssl->handshake->pmslen,
						  ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_dhm_calc_secret", ret);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS);
		}

		TTLS_SSL_DEBUG_MPI(3, "DHM: K ", &ssl->handshake->dhm_ctx.K );
	}
	else
#endif /* TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) ||		 \
	defined(TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) ||	 \
	defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) ||	 \
	defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_RSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_ECDSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDH_RSA ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDH_ECDSA)
	{
		if ((ret = ttls_ecdh_read_public(&ssl->handshake->ecdh_ctx,
									  p, end - p)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecdh_read_public", ret);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP);
		}

		TTLS_SSL_DEBUG_ECP(3, "ECDH: Qp ", &ssl->handshake->ecdh_ctx.Qp);

		if ((ret = ttls_ecdh_calc_secret(&ssl->handshake->ecdh_ctx,
						  &ssl->handshake->pmslen,
						   ssl->handshake->premaster,
						   TTLS_MPI_MAX_SIZE,
						   ssl->conf->f_rng, ssl->conf->p_rng)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecdh_calc_secret", ret);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS);
		}

		TTLS_SSL_DEBUG_MPI(3, "ECDH: z  ", &ssl->handshake->ecdh_ctx.z);
	}
	else
#endif /* TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK)
	{
		if ((ret = ssl_parse_client_psk_identity(ssl, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), ret);
			return ret;
		}

		if (p != end)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange"));
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
		}

		if ((ret = ttls_ssl_psk_derive_premaster(ssl,
						ciphersuite_info->key_exchange)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_psk_derive_premaster", ret);
			return ret;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK)
	{
		if ((ret = ssl_parse_client_psk_identity(ssl, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), ret);
			return ret;
		}

		if ((ret = ssl_parse_encrypted_pms(ssl, p, end, 2)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_encrypted_pms"), ret);
			return ret;
		}

		if ((ret = ttls_ssl_psk_derive_premaster(ssl,
						ciphersuite_info->key_exchange)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_psk_derive_premaster", ret);
			return ret;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK)
	{
		if ((ret = ssl_parse_client_psk_identity(ssl, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), ret);
			return ret;
		}
		if ((ret = ssl_parse_client_dh_public(ssl, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_dh_public"), ret);
			return ret;
		}

		if (p != end)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange"));
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
		}

		if ((ret = ttls_ssl_psk_derive_premaster(ssl,
						ciphersuite_info->key_exchange)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_psk_derive_premaster", ret);
			return ret;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK)
	{
		if ((ret = ssl_parse_client_psk_identity(ssl, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), ret);
			return ret;
		}

		if ((ret = ttls_ecdh_read_public(&ssl->handshake->ecdh_ctx,
									   p, end - p)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecdh_read_public", ret);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP);
		}

		TTLS_SSL_DEBUG_ECP(3, "ECDH: Qp ", &ssl->handshake->ecdh_ctx.Qp);

		if ((ret = ttls_ssl_psk_derive_premaster(ssl,
						ciphersuite_info->key_exchange)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_psk_derive_premaster", ret);
			return ret;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_RSA_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA)
	{
		if ((ret = ssl_parse_encrypted_pms(ssl, p, end, 0)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_parse_encrypted_pms_secret"), ret);
			return ret;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_RSA_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		ret = ttls_ecjpake_read_round_two(&ssl->handshake->ecjpake_ctx,
							  p, end - p);
		if (ret != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecjpake_read_round_two", ret);
			return(TTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE);
		}

		ret = ttls_ecjpake_derive_secret(&ssl->handshake->ecjpake_ctx,
				ssl->handshake->premaster, 32, &ssl->handshake->pmslen,
				ssl->conf->f_rng, ssl->conf->p_rng);
		if (ret != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecjpake_derive_secret", ret);
			return ret;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
	{
		TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_SSL_INTERNAL_ERROR);
	}

	if ((ret = ttls_ssl_derive_keys(ssl)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_derive_keys", ret);
		return ret;
	}

	ssl->state++;

	TTLS_SSL_DEBUG_MSG(2, ("<= parse client key exchange"));

	return 0;
}

#if !defined(TTLS_KEY_EXCHANGE_RSA_ENABLED)	   && \
	!defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)   && \
	!defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)  && \
	!defined(TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) && \
	!defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)&& \
	!defined(TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_parse_certificate_verify(ttls_ssl_context *ssl)
{
	const ttls_ssl_ciphersuite_t *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;

	TTLS_SSL_DEBUG_MSG(2, ("=> parse certificate verify"));

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		TTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate verify"));
		ssl->state++;
		return 0;
	}

	TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
	return(TTLS_ERR_SSL_INTERNAL_ERROR);
}
#else
static int ssl_parse_certificate_verify(ttls_ssl_context *ssl)
{
	int ret = TTLS_ERR_SSL_FEATURE_UNAVAILABLE;
	size_t i, sig_len;
	unsigned char hash[48];
	unsigned char *hash_start = hash;
	size_t hashlen;
#if defined(TTLS_SSL_PROTO_TLS1_2)
	ttls_pk_type_t pk_alg;
#endif
	ttls_md_type_t md_alg;
	const ttls_ssl_ciphersuite_t *ciphersuite_info =
		ssl->transform_negotiate->ciphersuite_info;

	TTLS_SSL_DEBUG_MSG(2, ("=> parse certificate verify"));

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE ||
		ssl->session_negotiate->peer_cert == NULL)
	{
		TTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate verify"));
		ssl->state++;
		return 0;
	}

	/* Read the message without adding it to the checksum */
	do {

		if ((ret = ttls_ssl_read_record_layer(ssl)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ttls_ssl_read_record_layer"), ret);
			return ret;
		}

		ret = ttls_ssl_handle_message_type(ssl);

	} while (TTLS_ERR_SSL_NON_FATAL == ret);

	if (0 != ret)
	{
		TTLS_SSL_DEBUG_RET(1, ("ttls_ssl_handle_message_type"), ret);
		return ret;
	}

	ssl->state++;

	/* Process the message contents */
	if (ssl->in_msgtype != TTLS_SSL_MSG_HANDSHAKE ||
		ssl->in_msg[0] != TTLS_SSL_HS_CERTIFICATE_VERIFY)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
		return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	i = ttls_ssl_hs_hdr_len(ssl);

	/*
	 *  struct {
	 *	 SignatureAndHashAlgorithm algorithm; -- TLS 1.2 only
	 *	 opaque signature<0..2^16-1>;
	 *  } DigitallySigned;
	 */
#if defined(TTLS_SSL_PROTO_SSL3) || defined(TTLS_SSL_PROTO_TLS1) || \
	defined(TTLS_SSL_PROTO_TLS1_1)
	if (ssl->minor_ver != TTLS_SSL_MINOR_VERSION_3)
	{
		md_alg = TTLS_MD_NONE;
		hashlen = 36;

		/* For ECDSA, use SHA-1, not MD-5 + SHA-1 */
		if (ttls_pk_can_do(&ssl->session_negotiate->peer_cert->pk,
						TTLS_PK_ECDSA))
		{
			hash_start += 16;
			hashlen -= 16;
			md_alg = TTLS_MD_SHA1;
		}
	}
	else
#endif /* TTLS_SSL_PROTO_SSL3 || TTLS_SSL_PROTO_TLS1 ||
		  TTLS_SSL_PROTO_TLS1_1 */
#if defined(TTLS_SSL_PROTO_TLS1_2)
	if (ssl->minor_ver == TTLS_SSL_MINOR_VERSION_3)
	{
		if (i + 2 > ssl->in_hslen)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
			return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
		}

		/*
		 * Hash
		 */
		md_alg = ttls_ssl_md_alg_from_hash(ssl->in_msg[i]);

		if (md_alg == TTLS_MD_NONE || ttls_ssl_set_calc_verify_md(ssl, ssl->in_msg[i]))
		{
			TTLS_SSL_DEBUG_MSG(1, ("peer not adhering to requested sig_alg"
								" for verify message"));
			return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
		}

#if !defined(TTLS_MD_SHA1)
		if (TTLS_MD_SHA1 == md_alg)
			hash_start += 16;
#endif

		/* Info from md_alg will be used instead */
		hashlen = 0;

		i++;

		/*
		 * Signature
		 */
		if ((pk_alg = ttls_ssl_pk_alg_from_sig(ssl->in_msg[i]))
						== TTLS_PK_NONE)
		{
			TTLS_SSL_DEBUG_MSG(1, ("peer not adhering to requested sig_alg"
								" for verify message"));
			return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
		}

		/*
		 * Check the certificate's key type matches the signature alg
		 */
		if (! ttls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, pk_alg))
		{
			TTLS_SSL_DEBUG_MSG(1, ("sig_alg doesn't match cert key"));
			return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
		}

		i++;
	}
	else
#endif /* TTLS_SSL_PROTO_TLS1_2 */
	{
		TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_SSL_INTERNAL_ERROR);
	}

	if (i + 2 > ssl->in_hslen)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
		return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	sig_len = (ssl->in_msg[i] << 8) | ssl->in_msg[i+1];
	i += 2;

	if (i + sig_len != ssl->in_hslen)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
		return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	/* Calculate hash and verify signature */
	ssl->handshake->calc_verify(ssl, hash);

	if ((ret = ttls_pk_verify(&ssl->session_negotiate->peer_cert->pk,
				   md_alg, hash_start, hashlen,
				   ssl->in_msg + i, sig_len)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_pk_verify", ret);
		return ret;
	}

	ttls_ssl_update_handshake_status(ssl);

	TTLS_SSL_DEBUG_MSG(2, ("<= parse certificate verify"));

	return ret;
}
#endif /* !TTLS_KEY_EXCHANGE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

#if defined(TTLS_SSL_SESSION_TICKETS)
static int ssl_write_new_session_ticket(ttls_ssl_context *ssl)
{
	int ret;
	size_t tlen;
	uint32_t lifetime;

	TTLS_SSL_DEBUG_MSG(2, ("=> write new session ticket"));

	ssl->out_msgtype = TTLS_SSL_MSG_HANDSHAKE;
	ssl->out_msg[0]  = TTLS_SSL_HS_NEW_SESSION_TICKET;

	/*
	 * struct {
	 *	 uint32 ticket_lifetime_hint;
	 *	 opaque ticket<0..2^16-1>;
	 * } NewSessionTicket;
	 *
	 * 4  .  7   ticket_lifetime_hint (0 = unspecified)
	 * 8  .  9   ticket_len (n)
	 * 10 .  9+n ticket content
	 */

	if ((ret = ssl->conf->f_ticket_write(ssl->conf->p_ticket,
					ssl->session_negotiate,
					ssl->out_msg + 10,
					ssl->out_msg + TTLS_SSL_MAX_CONTENT_LEN,
					&tlen, &lifetime)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_ticket_write", ret);
		tlen = 0;
	}

	ssl->out_msg[4] = (lifetime >> 24) & 0xFF;
	ssl->out_msg[5] = (lifetime >> 16) & 0xFF;
	ssl->out_msg[6] = (lifetime >>  8) & 0xFF;
	ssl->out_msg[7] = (lifetime	  ) & 0xFF;

	ssl->out_msg[8] = (unsigned char)((tlen >> 8) & 0xFF);
	ssl->out_msg[9] = (unsigned char)((tlen	 ) & 0xFF);

	ssl->out_msglen = 10 + tlen;

	/*
	 * Morally equivalent to updating ssl->state, but NewSessionTicket and
	 * ChangeCipherSpec share the same state.
	 */
	ssl->handshake->new_session_ticket = 0;

	if ((ret = ttls_ssl_write_record(ssl)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_write_record", ret);
		return ret;
	}

	TTLS_SSL_DEBUG_MSG(2, ("<= write new session ticket"));

	return 0;
}
#endif /* TTLS_SSL_SESSION_TICKETS */

/*
 * SSL handshake -- server side -- single step
 */
int ttls_ssl_handshake_server_step(ttls_ssl_context *ssl)
{
	int ret = 0;

	if (ssl->state == TTLS_SSL_HANDSHAKE_OVER || ssl->handshake == NULL)
		return(TTLS_ERR_SSL_BAD_INPUT_DATA);

	TTLS_SSL_DEBUG_MSG(2, ("server state: %d", ssl->state));

	if ((ret = ttls_ssl_flush_output(ssl)) != 0)
		return ret;

#if defined(TTLS_SSL_PROTO_DTLS)
	if (ssl->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM &&
		ssl->handshake->retransmit_state == TTLS_SSL_RETRANS_SENDING)
	{
		if ((ret = ttls_ssl_resend(ssl)) != 0)
			return ret;
	}
#endif

	switch(ssl->state)
	{
		case TTLS_SSL_HELLO_REQUEST:
			ssl->state = TTLS_SSL_CLIENT_HELLO;
			break;

		/*
		 *  <==   ClientHello
		 */
		case TTLS_SSL_CLIENT_HELLO:
			ret = ssl_parse_client_hello(ssl);
			break;

#if defined(TTLS_SSL_PROTO_DTLS)
		case TTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT:
			return(TTLS_ERR_SSL_HELLO_VERIFY_REQUIRED);
#endif

		/*
		 *  ==>   ServerHello
		 *		Certificate
		 *	  (ServerKeyExchange )
		 *	  (CertificateRequest)
		 *		ServerHelloDone
		 */
		case TTLS_SSL_SERVER_HELLO:
			ret = ssl_write_server_hello(ssl);
			break;

		case TTLS_SSL_SERVER_CERTIFICATE:
			ret = ttls_ssl_write_certificate(ssl);
			break;

		case TTLS_SSL_SERVER_KEY_EXCHANGE:
			ret = ssl_write_server_key_exchange(ssl);
			break;

		case TTLS_SSL_CERTIFICATE_REQUEST:
			ret = ssl_write_certificate_request(ssl);
			break;

		case TTLS_SSL_SERVER_HELLO_DONE:
			ret = ssl_write_server_hello_done(ssl);
			break;

		/*
		 *  <== (Certificate/Alert )
		 *		ClientKeyExchange
		 *	  (CertificateVerify )
		 *		ChangeCipherSpec
		 *		Finished
		 */
		case TTLS_SSL_CLIENT_CERTIFICATE:
			ret = ttls_ssl_parse_certificate(ssl);
			break;

		case TTLS_SSL_CLIENT_KEY_EXCHANGE:
			ret = ssl_parse_client_key_exchange(ssl);
			break;

		case TTLS_SSL_CERTIFICATE_VERIFY:
			ret = ssl_parse_certificate_verify(ssl);
			break;

		case TTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:
			ret = ttls_ssl_parse_change_cipher_spec(ssl);
			break;

		case TTLS_SSL_CLIENT_FINISHED:
			ret = ttls_ssl_parse_finished(ssl);
			break;

		/*
		 *  ==> (NewSessionTicket)
		 *		ChangeCipherSpec
		 *		Finished
		 */
		case TTLS_SSL_SERVER_CHANGE_CIPHER_SPEC:
#if defined(TTLS_SSL_SESSION_TICKETS)
			if (ssl->handshake->new_session_ticket != 0)
				ret = ssl_write_new_session_ticket(ssl);
			else
#endif
				ret = ttls_ssl_write_change_cipher_spec(ssl);
			break;

		case TTLS_SSL_SERVER_FINISHED:
			ret = ttls_ssl_write_finished(ssl);
			break;

		case TTLS_SSL_FLUSH_BUFFERS:
			TTLS_SSL_DEBUG_MSG(2, ("handshake: done"));
			ssl->state = TTLS_SSL_HANDSHAKE_WRAPUP;
			break;

		case TTLS_SSL_HANDSHAKE_WRAPUP:
			ttls_ssl_handshake_wrapup(ssl);
			break;

		default:
			TTLS_SSL_DEBUG_MSG(1, ("invalid state %d", ssl->state));
			return(TTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	return ret;
}
