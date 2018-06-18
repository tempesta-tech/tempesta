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
#include "ecp.h"
#include "ssl_internal.h"
#include "ttls.h"

#if defined(TTLS_SSL_SESSION_TICKETS)
/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}
#endif

#if defined(TTLS_SSL_DTLS_HELLO_VERIFY)
int ttls_ssl_set_client_transport_id(ttls_ssl_context *tls,
					 const unsigned char *info,
					 size_t ilen)
{
	if (tls->conf->endpoint != TTLS_SSL_IS_SERVER)
		return(TTLS_ERR_SSL_BAD_INPUT_DATA);

	ttls_free(tls->cli_id);

	if ((tls->cli_id = ttls_calloc(1, ilen)) == NULL)
		return(TTLS_ERR_SSL_ALLOC_FAILED);

	memcpy(tls->cli_id, info, ilen);
	tls->cli_id_len = ilen;

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

static int ssl_parse_servername_ext(ttls_ssl_context *tls,
				 const unsigned char *buf,
				 size_t len)
{
	int r;
	size_t servername_list_size, hostname_len;
	const unsigned char *p;

	TTLS_SSL_DEBUG_MSG(3, ("parse ServerName extension"));

	servername_list_size = ((buf[0] << 8) | (buf[1]));
	if (servername_list_size + 2 != len)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
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
			ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}

		if (p[0] == TTLS_TLS_EXT_SERVERNAME_HOSTNAME)
		{
			r = tls->conf->f_sni(tls->conf->p_sni,
						tls, p + 3, hostname_len);
			if (r != 0)
			{
				TTLS_SSL_DEBUG_RET(1, "ssl_sni_wrapper", r);
				ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
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
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	return 0;
}

static int ssl_parse_renegotiation_info(ttls_ssl_context *tls,
					 const unsigned char *buf,
					 size_t len)
{
	if (len != 1 || buf[0] != 0x0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("non-zero length renegotiation info"));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	tls->secure_renegotiation = TTLS_SSL_SECURE_RENEGOTIATION;

	return 0;
}

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

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
static int ssl_parse_signature_algorithms_ext(ttls_ssl_context *tls,
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
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
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

		if (ttls_ssl_check_sig_hash(tls, md_cur) == 0)
		{
			ttls_ssl_sig_hash_set_add(&tls->handshake->hash_algs, sig_cur, md_cur);
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
#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static int ssl_parse_supported_elliptic_curves(ttls_ssl_context *tls,
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
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/* Should never happen unless client duplicates the extension */
	if (tls->handshake->curves != NULL)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
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
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
		return(TTLS_ERR_SSL_ALLOC_FAILED);
	}

	tls->handshake->curves = curves;

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

static int ssl_parse_supported_point_formats(ttls_ssl_context *tls,
					  const unsigned char *buf,
					  size_t len)
{
	size_t list_size;
	const unsigned char *p;

	list_size = buf[0];
	if (list_size + 1 != len)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
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
			tls->handshake->ecdh_ctx.point_format = p[0];
#endif
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
			tls->handshake->ecjpake_ctx.point_format = p[0];
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
static int ssl_parse_ecjpake_kkpp(ttls_ssl_context *tls,
			   const unsigned char *buf,
			   size_t len)
{
	int r;

	if (ttls_ecjpake_check(&tls->handshake->ecjpake_ctx) != 0)
	{
		TTLS_SSL_DEBUG_MSG(3, ("skip ecjpake kkpp extension"));
		return 0;
	}

	if ((r = ttls_ecjpake_read_round_one(&tls->handshake->ecjpake_ctx,
						buf, len)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ecjpake_read_round_one", r);
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
		return r;
	}

	/* Only mark the extension as OK when we're sure it is */
	tls->handshake->cli_exts |= TTLS_TLS_EXT_ECJPAKE_KKPP_OK;

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_SSL_MAX_FRAGMENT_LENGTH)
static int ssl_parse_max_fragment_length_ext(ttls_ssl_context *tls,
					  const unsigned char *buf,
					  size_t len)
{
	if (len != 1 || buf[0] >= TTLS_SSL_MAX_FRAG_LEN_INVALID)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	tls->session_negotiate->mfl_code = buf[0];

	return 0;
}
#endif /* TTLS_SSL_MAX_FRAGMENT_LENGTH */

static int ssl_parse_encrypt_then_mac_ext(ttls_ssl_context *tls,
					  const unsigned char *buf,
					  size_t len)
{
	if (len != 0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	if (tls->conf->encrypt_then_mac)
		tls->session_negotiate->encrypt_then_mac = 1;

	return 0;
}

#if defined(TTLS_SSL_EXTENDED_MASTER_SECRET)
static int ssl_parse_extended_ms_ext(ttls_ssl_context *tls,
				  const unsigned char *buf,
				  size_t len)
{
	if (len != 0)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	((void) buf);

	if (tls->conf->extended_ms == TTLS_SSL_EXTENDED_MS_ENABLED &&
		tls->minor_ver != TTLS_SSL_MINOR_VERSION_0)
	{
		tls->handshake->extended_ms = TTLS_SSL_EXTENDED_MS_ENABLED;
	}

	return 0;
}
#endif /* TTLS_SSL_EXTENDED_MASTER_SECRET */

#if defined(TTLS_SSL_SESSION_TICKETS)
static int ssl_parse_session_ticket_ext(ttls_ssl_context *tls,
					 unsigned char *buf,
					 size_t len)
{
	int r;
	TtlsSess session;

	ttls_ssl_session_init(&session);

	if (tls->conf->f_ticket_parse == NULL ||
		tls->conf->f_ticket_write == NULL)
	{
		return 0;
	}

	/* Remember the client asked us to send a new ticket */
	tls->handshake->new_session_ticket = 1;

	TTLS_SSL_DEBUG_MSG(3, ("ticket length: %d", len));

	if (len == 0)
		return 0;

	/*
	 * Failures are ok: just ignore the ticket and proceed.
	 */
	if ((r = tls->conf->f_ticket_parse(tls->conf->p_ticket, &session,
					   buf, len)) != 0)
	{
		ttls_ssl_session_free(&session);

		if (r == TTLS_ERR_SSL_INVALID_MAC)
			TTLS_SSL_DEBUG_MSG(3, ("ticket is not authentic"));
		else if (r == TTLS_ERR_SSL_SESSION_TICKET_EXPIRED)
			TTLS_SSL_DEBUG_MSG(3, ("ticket is expired"));
		else
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_ticket_parse", r);

		return 0;
	}

	/*
	 * Keep the session ID sent by the client, since we MUST send it back to
	 * inform them we're accepting the ticket  (RFC 5077 section 3.4)
	 */
	session.id_len = tls->session_negotiate->id_len;
	memcpy(&session.id, tls->session_negotiate->id, session.id_len);

	ttls_ssl_session_free(tls->session_negotiate);
	memcpy(tls->session_negotiate, &session, sizeof(TtlsSess));

	/* Zeroize instead of free as we copied the content */
	ttls_zeroize(&session, sizeof(TtlsSess));

	TTLS_SSL_DEBUG_MSG(3, ("session successfully restored from ticket"));

	tls->handshake->resume = 1;

	/* Don't send a new ticket after all, this one is OK */
	tls->handshake->new_session_ticket = 0;

	return 0;
}
#endif /* TTLS_SSL_SESSION_TICKETS */

static int ssl_parse_alpn_ext(ttls_ssl_context *tls,
			   const unsigned char *buf, size_t len)
{
	size_t list_len, cur_len, ours_len;
	const unsigned char *theirs, *start, *end;
	const char **ours;

	/* If ALPN not configured, just ignore the extension */
	if (tls->conf->alpn_list == NULL)
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
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
					TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	list_len = (buf[0] << 8) | buf[1];
	if (list_len != len - 2)
	{
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
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
			ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}

		/* Empty strings MUST NOT be included */
		if (cur_len == 0)
		{
			ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}
	}

	/*
	 * Use our order of preference
	 */
	for (ours = tls->conf->alpn_list; *ours != NULL; ours++)
	{
		ours_len = strlen(*ours);
		for (theirs = start; theirs != end; theirs += cur_len)
		{
			cur_len = *theirs++;

			if (cur_len == ours_len &&
				memcmp(theirs, *ours, cur_len) == 0)
			{
				tls->alpn_chosen = *ours;
				return 0;
			}
		}
	}

	/* If we get there, no match was found */
	ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
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
static int ssl_pick_cert(ttls_ssl_context *tls,
			  const ttls_ssl_ciphersuite_t * ciphersuite_info)
{
	ttls_ssl_key_cert *cur, *list, *fallback = NULL;
	ttls_pk_type_t pk_alg =
		ttls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info);
	uint32_t flags;

	if (tls->handshake->sni_key_cert != NULL)
		list = tls->handshake->sni_key_cert;
	else
		list = tls->conf->key_cert;

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
			ssl_check_key_curve(cur->key, tls->handshake->curves) != 0)
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
		if (tls->minor_ver < TTLS_SSL_MINOR_VERSION_3 &&
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

	/* Do not update tls->handshake->key_cert unless there is a match */
	if (cur != NULL)
	{
		tls->handshake->key_cert = cur;
		TTLS_SSL_DEBUG_CRT(3, "selected certificate chain, certificate",
						  tls->handshake->key_cert->cert);
		return 0;
	}

	return(-1);
}

/*
 * Check if a given ciphersuite is suitable for use with our config/keys/etc
 * Sets ciphersuite_info only if the suite matches.
 */
static int ssl_ciphersuite_match(ttls_ssl_context *tls, int suite_id,
				  const ttls_ssl_ciphersuite_t **ciphersuite_info)
{
	const ttls_ssl_ciphersuite_t *suite_info;

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)	
	ttls_pk_type_t sig_type;
#endif

	suite_info = ttls_ssl_ciphersuite_from_id(suite_id);
	if (suite_info == NULL)
	{
		TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_SSL_INTERNAL_ERROR);
	}

	TTLS_SSL_DEBUG_MSG(3, ("trying ciphersuite: %s", suite_info->name));

	if (suite_info->min_minor_ver > tls->minor_ver ||
		suite_info->max_minor_ver < tls->minor_ver)
	{
		TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: version"));
		return 0;
	}

#if defined(TTLS_SSL_PROTO_DTLS)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM &&
		(suite_info->flags & TTLS_CIPHERSUITE_NODTLS))
		return 0;
#endif

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	if (suite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE &&
		(tls->handshake->cli_exts & TTLS_TLS_EXT_ECJPAKE_KKPP_OK) == 0)
	{
		TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: ecjpake "
					"not configured or ext missing"));
		return 0;
	}
#endif


#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C)
	if (ttls_ssl_ciphersuite_uses_ec(suite_info) &&
		(tls->handshake->curves == NULL ||
		  tls->handshake->curves[0] == NULL))
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
		tls->conf->f_psk == NULL &&
		(tls->conf->psk == NULL || tls->conf->psk_identity == NULL ||
		  tls->conf->psk_identity_len == 0 || tls->conf->psk_len == 0))
	{
		TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: no pre-shared key"));
		return 0;
	}
#endif

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
	/* If the ciphersuite requires signing, check whether
	 * a suitable hash algorithm is present. */
	if (tls->minor_ver == TTLS_SSL_MINOR_VERSION_3)
	{
		sig_type = ttls_ssl_get_ciphersuite_sig_alg(suite_info);
		if (sig_type != TTLS_PK_NONE &&
			ttls_ssl_sig_hash_set_find(&tls->handshake->hash_algs, sig_type) == TTLS_MD_NONE)
		{
			TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: no suitable hash algorithm "
						"for signature algorithm %d", sig_type));
			return 0;
		}
	}

#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

	/*
	 * Final check: if ciphersuite requires us to have a
	 * certificate/key of a particular type:
	 * - select the appropriate certificate if we have one, or
	 * - try the next ciphersuite if we don't
	 * This must be done last since we modify the key_cert list.
	 */
	if (ssl_pick_cert(tls, suite_info) != 0)
	{
		TTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: "
					"no suitable certificate"));
		return 0;
	}

	*ciphersuite_info = suite_info;
	return 0;
}

/* This function doesn't alert on errors that happen early during
   ClientHello parsing because they might indicate that the client is
   not talking SSL/TLS at all and would not understand our alert. */
static int ssl_parse_client_hello(ttls_ssl_context *tls)
{
	int r, got_common_suite;
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
#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
	int sig_hash_alg_ext_present = 0;
#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

	TTLS_SSL_DEBUG_MSG(2, ("=> parse client hello"));

#if defined(TTLS_SSL_DTLS_ANTI_REPLAY)
read_record_header:
#endif
	/*
	 * Read the input ourselves manually in order to support SSLv2
	 * ClientHello, which doesn't use the same record layer format.
	 */
	// TODO AK: just use ingress buffer as in ttls_read_record_layer().
	if ((r = ttls_fetch_input(tls, 5)) != 0) {
		/* No alert on a read error. */
		TTLS_SSL_DEBUG_RET(1, "ttls_fetch_input", r);
		return r;
	}

	buf = tls->in_hdr;

	TTLS_SSL_DEBUG_BUF(4, "record header", buf, ttls_hdr_len(tls));

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

	if (buf[0] != TTLS_MSG_HANDSHAKE)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	TTLS_SSL_DEBUG_MSG(3, ("client hello v3, message len.: %d",
				   (tls->in_len[0] << 8) | tls->in_len[1]));

	TTLS_SSL_DEBUG_MSG(3, ("client hello v3, protocol version: [%d:%d]",
				   buf[1], buf[2]));

	ttls_ssl_read_version(&major, &minor, tls->conf->transport, buf + 1);

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
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM) {
		/* Epoch should be 0 for initial handshakes */
		if (tls->in_ctr[0] != 0 || tls->in_ctr[1] != 0)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}

		memcpy(tls->out_ctr + 2, tls->in_ctr + 2, 6);

#if defined(TTLS_SSL_DTLS_ANTI_REPLAY)
		if (ttls_ssl_dtls_replay_check(tls) != 0)
		{
			TTLS_SSL_DEBUG_MSG(1, ("replayed record, discarding"));
			tls->next_record_offset = 0;
			tls->in_left = 0;
			goto read_record_header;
		}

		/* No MAC to check yet, so we can update right now */
		ttls_ssl_dtls_replay_update(tls);
#endif
	}
#endif /* TTLS_SSL_PROTO_DTLS */

	msg_len = (tls->in_len[0] << 8) | tls->in_len[1];

	if (msg_len > TTLS_SSL_MAX_CONTENT_LEN)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	// TODO AK: just use ingress buffer as in ttls_read_record_layer().
	if ((r = ttls_fetch_input(tls,
				   ttls_hdr_len(tls) + msg_len)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_fetch_input", r);
		return r;
	}

	/* Done reading this record, get ready for the next one */
#if defined(TTLS_SSL_PROTO_DTLS)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
		tls->next_record_offset = msg_len + ttls_hdr_len(tls);
	else
#endif
		tls->in_left = 0;

	buf = tls->in_msg;

	TTLS_SSL_DEBUG_BUF(4, "record contents", buf, msg_len);

	tls->handshake->update_checksum(tls, buf, msg_len);

	/*
	 * Handshake layer:
	 *	 0  .   0   handshake type
	 *	 1  .   3   handshake length
	 *	 4  .   5   DTLS only: message seqence number
	 *	 6  .   8   DTLS only: fragment offset
	 *	 9  .  11   DTLS only: fragment length
	 */
	if (msg_len < ttls_ssl_hs_hdr_len(tls))
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
		msg_len != ttls_ssl_hs_hdr_len(tls) + ((buf[2] << 8) | buf[3]))
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

#if defined(TTLS_SSL_PROTO_DTLS)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
	{
		/*
		 * Copy the client's handshake message_seq on initial handshakes,
		 * check sequence number on renego.
		 */
		unsigned int cli_msg_seq = (tls->in_msg[4] << 8) | tls->in_msg[5];
		tls->handshake->out_msg_seq = cli_msg_seq;
		tls->handshake->in_msg_seq  = cli_msg_seq + 1;

		/*
		 * For now we don't support fragmentation, so make sure
		 * fragment_offset == 0 and fragment_length == length
		 */
		if (tls->in_msg[6] != 0 || tls->in_msg[7] != 0 || tls->in_msg[8] != 0 ||
			memcmp(tls->in_msg + 1, tls->in_msg + 9, 3) != 0)
		{
			TTLS_SSL_DEBUG_MSG(1, ("ClientHello fragmentation not supported"));
			return(TTLS_ERR_SSL_FEATURE_UNAVAILABLE);
		}
	}
#endif /* TTLS_SSL_PROTO_DTLS */

	buf += ttls_ssl_hs_hdr_len(tls);
	msg_len -= ttls_ssl_hs_hdr_len(tls);

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

	ttls_ssl_read_version(&tls->major_ver, &tls->minor_ver,
					  tls->conf->transport, buf);

	tls->handshake->max_major_ver = tls->major_ver;
	tls->handshake->max_minor_ver = tls->minor_ver;

	if (tls->major_ver < tls->conf->min_major_ver ||
		tls->minor_ver < tls->conf->min_minor_ver)
	{
		TTLS_SSL_DEBUG_MSG(1, ("client only supports tls smaller than minimum"
					" [%d:%d] < [%d:%d]",
					tls->major_ver, tls->minor_ver,
					tls->conf->min_major_ver, tls->conf->min_minor_ver));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						 TTLS_SSL_ALERT_MSG_PROTOCOL_VERSION);
		return(TTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION);
	}

	if (tls->major_ver > tls->conf->max_major_ver)
	{
		tls->major_ver = tls->conf->max_major_ver;
		tls->minor_ver = tls->conf->max_minor_ver;
	}
	else if (tls->minor_ver > tls->conf->max_minor_ver)
		tls->minor_ver = tls->conf->max_minor_ver;

	/*
	 * Save client random (inc. Unix time)
	 */
	TTLS_SSL_DEBUG_BUF(3, "client hello, random bytes", buf + 2, 32);

	memcpy(tls->handshake->randbytes, buf + 2, 32);

	/*
	 * Check the session ID length and save session ID
	 */
	sess_len = buf[34];

	if (sess_len > sizeof(tls->session_negotiate->id) ||
		sess_len + 34 + 2 > msg_len) /* 2 for cipherlist length field */
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	TTLS_SSL_DEBUG_BUF(3, "client hello, session id", buf + 35, sess_len);

	tls->session_negotiate->id_len = sess_len;
	memset(tls->session_negotiate->id, 0,
			sizeof(tls->session_negotiate->id));
	memcpy(tls->session_negotiate->id, buf + 35,
			tls->session_negotiate->id_len);

	/*
	 * Check the cookie length and content
	 */
#if defined(TTLS_SSL_PROTO_DTLS)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
	{
		cookie_offset = 35 + sess_len;
		cookie_len = buf[cookie_offset];

		if (cookie_offset + 1 + cookie_len + 2 > msg_len)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
			ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_PROTOCOL_VERSION);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}

		TTLS_SSL_DEBUG_BUF(3, "client hello, cookie",
					   buf + cookie_offset + 1, cookie_len);

#if defined(TTLS_SSL_DTLS_HELLO_VERIFY)
		if (tls->conf->f_cookie_check != NULL) {
			if (tls->conf->f_cookie_check(tls->conf->p_cookie,
							 buf + cookie_offset + 1, cookie_len,
							 tls->cli_id, tls->cli_id_len) != 0)
			{
				TTLS_SSL_DEBUG_MSG(2, ("cookie verification failed"));
				tls->handshake->verify_cookie_len = 1;
			}
			else
			{
				TTLS_SSL_DEBUG_MSG(2, ("cookie verification passed"));
				tls->handshake->verify_cookie_len = 0;
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
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
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
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_DECODE_ERROR);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	TTLS_SSL_DEBUG_BUF(3, "client hello, compression",
					  buf + comp_offset + 1, comp_len);

	tls->session_negotiate->compression = TTLS_SSL_COMPRESS_NULL;

	/* See comments in ssl_write_client_hello() */
#if defined(TTLS_SSL_PROTO_DTLS)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
		tls->session_negotiate->compression = TTLS_SSL_COMPRESS_NULL;
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
			ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}

		ext_len = (buf[ext_offset + 0] << 8)
				| (buf[ext_offset + 1]	 );

		if ((ext_len > 0 && ext_len < 4) ||
			msg_len != ext_offset + 2 + ext_len)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
			ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
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
			ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}
		switch(ext_id)
		{
		case TTLS_TLS_EXT_SERVERNAME:
			TTLS_SSL_DEBUG_MSG(3, ("found ServerName extension"));
			if (tls->conf->f_sni == NULL)
				break;

			r = ssl_parse_servername_ext(tls, ext + 4, ext_size);
			if (r != 0)
				return r;
			break;

		case TTLS_TLS_EXT_RENEGOTIATION_INFO:
			TTLS_SSL_DEBUG_MSG(3, ("found renegotiation extension"));
			r = ssl_parse_renegotiation_info(tls, ext + 4, ext_size);
			if (r != 0)
				return r;
			break;

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
		case TTLS_TLS_EXT_SIG_ALG:
			TTLS_SSL_DEBUG_MSG(3, ("found signature_algorithms extension"));

			r = ssl_parse_signature_algorithms_ext(tls, ext + 4, ext_size);
			if (r != 0)
				return r;

			sig_hash_alg_ext_present = 1;
			break;
#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
		case TTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES:
			TTLS_SSL_DEBUG_MSG(3, ("found supported elliptic curves extension"));

			r = ssl_parse_supported_elliptic_curves(tls, ext + 4, ext_size);
			if (r != 0)
				return r;
			break;

		case TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS:
			TTLS_SSL_DEBUG_MSG(3, ("found supported point formats extension"));
			tls->handshake->cli_exts |= TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT;

			r = ssl_parse_supported_point_formats(tls, ext + 4, ext_size);
			if (r != 0)
				return r;
			break;
#endif /* TTLS_ECDH_C || TTLS_ECDSA_C ||
	  TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
		case TTLS_TLS_EXT_ECJPAKE_KKPP:
			TTLS_SSL_DEBUG_MSG(3, ("found ecjpake kkpp extension"));

			r = ssl_parse_ecjpake_kkpp(tls, ext + 4, ext_size);
			if (r != 0)
				return r;
			break;
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(TTLS_SSL_MAX_FRAGMENT_LENGTH)
		case TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
			TTLS_SSL_DEBUG_MSG(3, ("found max fragment length extension"));

			r = ssl_parse_max_fragment_length_ext(tls, ext + 4, ext_size);
			if (r != 0)
				return r;
			break;
#endif /* TTLS_SSL_MAX_FRAGMENT_LENGTH */

		case TTLS_TLS_EXT_ENCRYPT_THEN_MAC:
			TTLS_SSL_DEBUG_MSG(3, ("found encrypt then mac extension"));

			r = ssl_parse_encrypt_then_mac_ext(tls, ext + 4, ext_size);
			if (r != 0)
				return r;
			break;

#if defined(TTLS_SSL_EXTENDED_MASTER_SECRET)
		case TTLS_TLS_EXT_EXTENDED_MASTER_SECRET:
			TTLS_SSL_DEBUG_MSG(3, ("found extended master secret extension"));

			r = ssl_parse_extended_ms_ext(tls, ext + 4, ext_size);
			if (r != 0)
				return r;
			break;
#endif /* TTLS_SSL_EXTENDED_MASTER_SECRET */

#if defined(TTLS_SSL_SESSION_TICKETS)
		case TTLS_TLS_EXT_SESSION_TICKET:
			TTLS_SSL_DEBUG_MSG(3, ("found session ticket extension"));

			r = ssl_parse_session_ticket_ext(tls, ext + 4, ext_size);
			if (r != 0)
				return r;
			break;
#endif /* TTLS_SSL_SESSION_TICKETS */

		case TTLS_TLS_EXT_ALPN:
			TTLS_SSL_DEBUG_MSG(3, ("found alpn extension"));

			r = ssl_parse_alpn_ext(tls, ext + 4, ext_size);
			if (r != 0)
				return r;
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
			ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
							TTLS_SSL_ALERT_MSG_DECODE_ERROR);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
		}
	}

#if defined(TTLS_SSL_FALLBACK_SCSV)
	for (i = 0, p = buf + ciph_offset + 2; i < ciph_len; i += 2, p += 2)
	{
		if (p[0] == (unsigned char)((TTLS_SSL_FALLBACK_SCSV_VALUE >> 8) & 0xff) &&
			p[1] == (unsigned char)((TTLS_SSL_FALLBACK_SCSV_VALUE	 ) & 0xff))
		{
			TTLS_SSL_DEBUG_MSG(2, ("received FALLBACK_SCSV"));

			if (tls->minor_ver < tls->conf->max_minor_ver)
			{
				TTLS_SSL_DEBUG_MSG(1, ("inapropriate fallback"));

				ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
								TTLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK);

				return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
			}

			break;
		}
	}
#endif /* TTLS_SSL_FALLBACK_SCSV */

#if defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

	/*
	 * Try to fall back to default hash SHA1 if the client
	 * hasn't provided any preferred signature-hash combinations.
	 */
	if (sig_hash_alg_ext_present == 0)
	{
		ttls_md_type_t md_default = TTLS_MD_SHA1;

		if (ttls_ssl_check_sig_hash(tls, md_default) != 0)
			md_default = TTLS_MD_NONE;

		ttls_ssl_sig_hash_set_const_hash(&tls->handshake->hash_algs, md_default);
	}

#endif /* TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

	/*
	 * Check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	 */
	for (i = 0, p = buf + ciph_offset + 2; i < ciph_len; i += 2, p += 2)
	{
		if (p[0] == 0 && p[1] == TTLS_SSL_EMPTY_RENEGOTIATION_INFO)
		{
			TTLS_SSL_DEBUG_MSG(3, ("received TLS_EMPTY_RENEGOTIATION_INFO "));
			tls->secure_renegotiation = TTLS_SSL_SECURE_RENEGOTIATION;
			break;
		}
	}

	/*
	 * Renegotiation security checks
	 */
	if (tls->secure_renegotiation != TTLS_SSL_SECURE_RENEGOTIATION &&
		tls->conf->allow_legacy_renegotiation == TTLS_SSL_LEGACY_BREAK_HANDSHAKE)
	{
		TTLS_SSL_DEBUG_MSG(1, ("legacy renegotiation, breaking off handshake"));
		handshake_failure = 1;
	}

	if (handshake_failure == 1)
	{
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_HELLO);
	}

	/*
	 * Search for a matching ciphersuite
	 * (At the end because we need information from the EC-based extensions
	 * and certificate from the SNI callback triggered by the SNI extension.)
	 */
	got_common_suite = 0;
	ciphersuites = tls->conf->ciphersuite_list[tls->minor_ver];
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

			if ((r = ssl_ciphersuite_match(tls, ciphersuites[i],
							   &ciphersuite_info)) != 0)
				return r;

			if (ciphersuite_info != NULL)
				goto have_ciphersuite;
		}

	if (got_common_suite)
	{
		TTLS_SSL_DEBUG_MSG(1, ("got ciphersuites in common, "
					"but none of them usable"));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_SSL_NO_USABLE_CIPHERSUITE);
	}
	else
	{
		TTLS_SSL_DEBUG_MSG(1, ("got no ciphersuites in common"));
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return(TTLS_ERR_SSL_NO_CIPHER_CHOSEN);
	}

have_ciphersuite:
	TTLS_SSL_DEBUG_MSG(2, ("selected ciphersuite: %s", ciphersuite_info->name));

	tls->session_negotiate->ciphersuite = ciphersuites[i];
	tls->transform_negotiate->ciphersuite_info = ciphersuite_info;

	tls->state++;

#if defined(TTLS_SSL_PROTO_DTLS)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
		ttls_ssl_recv_flight_completed(tls);
#endif

	/* Debugging-only output for testsuite */
#if defined(DEBUG) && (DEBUG == 3) && \
	defined(TTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
	if (tls->minor_ver == TTLS_SSL_MINOR_VERSION_3)
	{
		ttls_pk_type_t sig_alg = ttls_ssl_get_ciphersuite_sig_alg(ciphersuite_info);
		if (sig_alg != TTLS_PK_NONE)
		{
			ttls_md_type_t md_alg = ttls_ssl_sig_hash_set_find(&tls->handshake->hash_algs,
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

static void ssl_write_encrypt_then_mac_ext(ttls_ssl_context *tls,
					unsigned char *buf,
					size_t *olen)
{
	unsigned char *p = buf;
	const ttls_ssl_ciphersuite_t *suite = NULL;
	const ttls_cipher_info_t *cipher = NULL;

	/*
	 * RFC 7366: "If a server receives an encrypt-then-MAC request extension
	 * from a client and then selects a stream or Authenticated Encryption
	 * with Associated Data (AEAD) ciphersuite, it MUST NOT send an
	 * encrypt-then-MAC response extension back to the client."
	 */
	if ((suite = ttls_ssl_ciphersuite_from_id(
			tls->session_negotiate->ciphersuite)) == NULL ||
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

#if defined(TTLS_SSL_EXTENDED_MASTER_SECRET)
static void ssl_write_extended_ms_ext(ttls_ssl_context *tls,
				   unsigned char *buf,
				   size_t *olen)
{
	unsigned char *p = buf;

	if (tls->handshake->extended_ms == TTLS_SSL_EXTENDED_MS_DISABLED ||
		tls->minor_ver == TTLS_SSL_MINOR_VERSION_0)
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
static void ssl_write_session_ticket_ext(ttls_ssl_context *tls,
					  unsigned char *buf,
					  size_t *olen)
{
	unsigned char *p = buf;

	if (tls->handshake->new_session_ticket == 0)
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

static void ssl_write_renegotiation_ext(ttls_ssl_context *tls,
					 unsigned char *buf,
					 size_t *olen)
{
	unsigned char *p = buf;

	if (tls->secure_renegotiation != TTLS_SSL_SECURE_RENEGOTIATION)
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
static void ssl_write_max_fragment_length_ext(ttls_ssl_context *tls,
					   unsigned char *buf,
					   size_t *olen)
{
	unsigned char *p = buf;

	if (tls->session_negotiate->mfl_code == TTLS_SSL_MAX_FRAG_LEN_NONE)
	{
		*olen = 0;
		return;
	}

	TTLS_SSL_DEBUG_MSG(3, ("server hello, max_fragment_length extension"));

	*p++ = (unsigned char)((TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH >> 8) & 0xFF);
	*p++ = (unsigned char)((TTLS_TLS_EXT_MAX_FRAGMENT_LENGTH	 ) & 0xFF);

	*p++ = 0x00;
	*p++ = 1;

	*p++ = tls->session_negotiate->mfl_code;

	*olen = 5;
}
#endif /* TTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static void ssl_write_supported_point_formats_ext(ttls_ssl_context *tls,
						   unsigned char *buf,
						   size_t *olen)
{
	unsigned char *p = buf;
	((void) tls);

	if ((tls->handshake->cli_exts &
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
static void ssl_write_ecjpake_kkpp_ext(ttls_ssl_context *tls,
					unsigned char *buf,
					size_t *olen)
{
	int r;
	unsigned char *p = buf;
	const unsigned char *end = tls->out_msg + TTLS_SSL_MAX_CONTENT_LEN;
	size_t kkpp_len;

	*olen = 0;

	/* Skip costly computation if not needed */
	if (tls->transform_negotiate->ciphersuite_info->key_exchange !=
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

	r = ttls_ecjpake_write_round_one(&tls->handshake->ecjpake_ctx,
					p + 2, end - p - 2, &kkpp_len,
					tls->conf->f_rng, tls->conf->p_rng);
	if (r != 0)
	{
		TTLS_SSL_DEBUG_RET(1 , "ttls_ecjpake_write_round_one", r);
		return;
	}

	*p++ = (unsigned char)((kkpp_len >> 8) & 0xFF);
	*p++ = (unsigned char)((kkpp_len	 ) & 0xFF);

	*olen = kkpp_len + 4;
}
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

static void ssl_write_alpn_ext(ttls_ssl_context *tls,
				unsigned char *buf, size_t *olen)
{
	if (tls->alpn_chosen == NULL)
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

	*olen = 7 + strlen(tls->alpn_chosen);

	buf[2] = (unsigned char)(((*olen - 4) >> 8) & 0xFF);
	buf[3] = (unsigned char)(((*olen - 4)	 ) & 0xFF);

	buf[4] = (unsigned char)(((*olen - 6) >> 8) & 0xFF);
	buf[5] = (unsigned char)(((*olen - 6)	 ) & 0xFF);

	buf[6] = (unsigned char)(((*olen - 7)	 ) & 0xFF);

	memcpy(buf + 7, tls->alpn_chosen, *olen - 7);
}

#if defined(TTLS_SSL_DTLS_HELLO_VERIFY)
static int ssl_write_hello_verify_request(ttls_ssl_context *tls)
{
	int r;
	unsigned char *p = tls->out_msg + 4;
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
	ttls_ssl_write_version(tls->major_ver, tls->minor_ver,
					   tls->conf->transport, p);
	TTLS_SSL_DEBUG_BUF(3, "server version", p, 2);
	p += 2;

	/* If we get here, f_cookie_check is not null */
	if (tls->conf->f_cookie_write == NULL)
	{
		TTLS_SSL_DEBUG_MSG(1, ("inconsistent cookie callbacks"));
		return(TTLS_ERR_SSL_INTERNAL_ERROR);
	}

	/* Skip length byte until we know the length */
	cookie_len_byte = p++;

	if ((r = tls->conf->f_cookie_write(tls->conf->p_cookie,
					 &p, tls->out_buf + TTLS_BUF_LEN,
					 tls->cli_id, tls->cli_id_len)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "f_cookie_write", r);
		return r;
	}

	*cookie_len_byte = (unsigned char)(p - (cookie_len_byte + 1));

	TTLS_SSL_DEBUG_BUF(3, "cookie sent", cookie_len_byte + 1, *cookie_len_byte);

	tls->out_msglen  = p - tls->out_msg;
	tls->out_msgtype = TTLS_MSG_HANDSHAKE;
	tls->out_msg[0]  = TTLS_SSL_HS_HELLO_VERIFY_REQUEST;

	tls->state = TTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT;

	if ((r = ttls_ssl_write_record(tls)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_write_record", r);
		return r;
	}

	TTLS_SSL_DEBUG_MSG(2, ("<= write hello verify request"));

	return 0;
}
#endif /* TTLS_SSL_DTLS_HELLO_VERIFY */

static int ssl_write_server_hello(ttls_ssl_context *tls)
{
	time_t t;
	int r;
	size_t olen, ext_len = 0, n;
	unsigned char *buf, *p;

	TTLS_SSL_DEBUG_MSG(2, ("=> write server hello"));

#if defined(TTLS_SSL_DTLS_HELLO_VERIFY)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM &&
		tls->handshake->verify_cookie_len != 0)
	{
		TTLS_SSL_DEBUG_MSG(2, ("client hello was not authenticated"));
		TTLS_SSL_DEBUG_MSG(2, ("<= write server hello"));

		return(ssl_write_hello_verify_request(tls));
	}
#endif /* TTLS_SSL_DTLS_HELLO_VERIFY */

	if (tls->conf->f_rng == NULL)
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
	buf = tls->out_msg;
	p = buf + 4;

	ttls_ssl_write_version(tls->major_ver, tls->minor_ver,
					   tls->conf->transport, p);
	p += 2;

	TTLS_SSL_DEBUG_MSG(3, ("server hello, chosen version: [%d:%d]",
						buf[4], buf[5]));

	t = ttls_time(NULL);
	*p++ = (unsigned char)(t >> 24);
	*p++ = (unsigned char)(t >> 16);
	*p++ = (unsigned char)(t >>  8);
	*p++ = (unsigned char)(t	  );

	TTLS_SSL_DEBUG_MSG(3, ("server hello, current time: %lu", t));

	if ((r = tls->conf->f_rng(tls->conf->p_rng, p, 28)) != 0)
		return r;

	p += 28;

	memcpy(tls->handshake->randbytes + 32, buf + 6, 32);

	TTLS_SSL_DEBUG_BUF(3, "server hello, random bytes", buf + 6, 32);

	/*
	 * Resume is 0  by default, see ssl_handshake_init().
	 * It may be already set to 1 by ssl_parse_session_ticket_ext().
	 * If not, try looking up session ID in our cache.
	 */
	if (tls->handshake->resume == 0 &&
		tls->session_negotiate->id_len != 0 &&
		tls->conf->f_get_cache != NULL &&
		tls->conf->f_get_cache(tls->conf->p_cache, tls->session_negotiate) == 0)
	{
		TTLS_SSL_DEBUG_MSG(3, ("session successfully restored from cache"));
		tls->handshake->resume = 1;
	}

	if (tls->handshake->resume == 0)
	{
		/*
		 * New session, create a new session id,
		 * unless we're about to issue a session ticket
		 */
		tls->state++;

		tls->session_negotiate->start = ttls_time(NULL);

#if defined(TTLS_SSL_SESSION_TICKETS)
		if (tls->handshake->new_session_ticket != 0)
		{
			tls->session_negotiate->id_len = n = 0;
			memset(tls->session_negotiate->id, 0, 32);
		}
		else
#endif /* TTLS_SSL_SESSION_TICKETS */
		{
			tls->session_negotiate->id_len = n = 32;
			if ((r = tls->conf->f_rng(tls->conf->p_rng, tls->session_negotiate->id,
									n)) != 0)
				return r;
		}
	}
	else
	{
		/*
		 * Resuming a session
		 */
		n = tls->session_negotiate->id_len;
		tls->state = TTLS_SSL_SERVER_CHANGE_CIPHER_SPEC;

		if ((r = ttls_ssl_derive_keys(tls)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_derive_keys", r);
			return r;
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
	*p++ = (unsigned char) tls->session_negotiate->id_len;
	memcpy(p, tls->session_negotiate->id, tls->session_negotiate->id_len);
	p += tls->session_negotiate->id_len;

	TTLS_SSL_DEBUG_MSG(3, ("server hello, session id len.: %d", n));
	TTLS_SSL_DEBUG_BUF(3,   "server hello, session id", buf + 39, n);
	TTLS_SSL_DEBUG_MSG(3, ("%s session has been resumed",
				   tls->handshake->resume ? "a" : "no"));

	*p++ = (unsigned char)(tls->session_negotiate->ciphersuite >> 8);
	*p++ = (unsigned char)(tls->session_negotiate->ciphersuite	 );
	*p++ = (unsigned char)(tls->session_negotiate->compression	 );

	TTLS_SSL_DEBUG_MSG(3, ("server hello, chosen ciphersuite: %s",
		   ttls_ssl_get_ciphersuite_name(tls->session_negotiate->ciphersuite)));
	TTLS_SSL_DEBUG_MSG(3, ("server hello, compress alg.: 0x%02X",
				   tls->session_negotiate->compression));

	/*
	 *  First write extensions, then the total length
	 */
	ssl_write_renegotiation_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;

#if defined(TTLS_SSL_MAX_FRAGMENT_LENGTH)
	ssl_write_max_fragment_length_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

	ssl_write_encrypt_then_mac_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;

#if defined(TTLS_SSL_EXTENDED_MASTER_SECRET)
	ssl_write_extended_ms_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_SSL_SESSION_TICKETS)
	ssl_write_session_ticket_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_ECDH_C) || defined(TTLS_ECDSA_C) || \
	defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	ssl_write_supported_point_formats_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	ssl_write_ecjpake_kkpp_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;
#endif

	ssl_write_alpn_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;

	TTLS_SSL_DEBUG_MSG(3, ("server hello, total extension length: %d", ext_len));

	if (ext_len > 0)
	{
		*p++ = (unsigned char)((ext_len >> 8) & 0xFF);
		*p++ = (unsigned char)((ext_len	 ) & 0xFF);
		p += ext_len;
	}

	tls->out_msglen  = p - buf;
	tls->out_msgtype = TTLS_MSG_HANDSHAKE;
	tls->out_msg[0]  = TTLS_SSL_HS_SERVER_HELLO;

	r = ttls_ssl_write_record(tls);

	TTLS_SSL_DEBUG_MSG(2, ("<= write server hello"));

	return r;
}

#if !defined(TTLS_KEY_EXCHANGE_RSA_ENABLED)	   && \
	!defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)   && \
	!defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)  && \
	!defined(TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) && \
	!defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)&& \
	!defined(TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_write_certificate_request(ttls_ssl_context *tls)
{
	const ttls_ssl_ciphersuite_t *ciphersuite_info =
		tls->transform_negotiate->ciphersuite_info;

	TTLS_SSL_DEBUG_MSG(2, ("=> write certificate request"));

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		TTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate request"));
		tls->state++;
		return 0;
	}

	TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
	return(TTLS_ERR_SSL_INTERNAL_ERROR);
}
#else
static int ssl_write_certificate_request(ttls_ssl_context *tls)
{
	int r = TTLS_ERR_SSL_FEATURE_UNAVAILABLE;
	const ttls_ssl_ciphersuite_t *ciphersuite_info =
		tls->transform_negotiate->ciphersuite_info;
	size_t dn_size, total_dn_size; /* excluding length bytes */
	size_t ct_len, sa_len; /* including length bytes */
	unsigned char *buf, *p;
	const unsigned char * const end = tls->out_msg + TTLS_SSL_MAX_CONTENT_LEN;
	const ttls_x509_crt *crt;
	int authmode;

	TTLS_SSL_DEBUG_MSG(2, ("=> write certificate request"));

	tls->state++;

	if (tls->handshake->sni_authmode != TTLS_SSL_VERIFY_UNSET)
		authmode = tls->handshake->sni_authmode;
	else
		authmode = tls->conf->authmode;

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
	buf = tls->out_msg;
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
	if (tls->minor_ver == TTLS_SSL_MINOR_VERSION_3)
	{
		const int *cur;

		/*
		 * Supported signature algorithms
		 */
		for (cur = tls->conf->sig_hashes; *cur != TTLS_MD_NONE; cur++)
		{
			unsigned char hash = ttls_ssl_hash_from_md_alg(*cur);

			if (TTLS_SSL_HASH_NONE == hash || ttls_ssl_set_calc_verify_md(tls, hash))
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

	/*
	 * DistinguishedName certificate_authorities<0..2^16-1>;
	 * opaque DistinguishedName<1..2^16-1>;
	 */
	p += 2;

	total_dn_size = 0;

	if (tls->conf->cert_req_ca_list ==  TTLS_SSL_CERT_REQ_CA_LIST_ENABLED)
	{
		if (tls->handshake->sni_ca_chain != NULL)
			crt = tls->handshake->sni_ca_chain;
		else
			crt = tls->conf->ca_chain;

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

	tls->out_msglen  = p - buf;
	tls->out_msgtype = TTLS_MSG_HANDSHAKE;
	tls->out_msg[0]  = TTLS_SSL_HS_CERTIFICATE_REQUEST;
	tls->out_msg[4 + ct_len + sa_len] = (unsigned char)(total_dn_size  >> 8);
	tls->out_msg[5 + ct_len + sa_len] = (unsigned char)(total_dn_size	  );

	r = ttls_ssl_write_record(tls);

	TTLS_SSL_DEBUG_MSG(2, ("<= write certificate request"));

	return r;
}
#endif /* !TTLS_KEY_EXCHANGE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED &&
		  !TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
static int ssl_get_ecdh_params_from_cert(ttls_ssl_context *tls)
{
	int r;

	if (! ttls_pk_can_do(ttls_ssl_own_key(tls), TTLS_PK_ECKEY))
	{
		TTLS_SSL_DEBUG_MSG(1, ("server key not ECDH capable"));
		return(TTLS_ERR_SSL_PK_TYPE_MISMATCH);
	}

	if ((r = ttls_ecdh_get_params(&tls->handshake->ecdh_ctx,
					 ttls_pk_ec(*ttls_ssl_own_key(tls)),
					 TTLS_ECDH_OURS)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, ("ttls_ecdh_get_params"), r);
		return r;
	}

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) ||
		  TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED */

static int ssl_write_server_key_exchange(ttls_ssl_context *tls)
{
	int r;
	size_t n = 0;
	const ttls_ssl_ciphersuite_t *ciphersuite_info
		= tls->transform_negotiate->ciphersuite_info;

#if defined(TTLS_KEY_EXCHANGE__SOME_PFS__ENABLED)
	unsigned char *p = tls->out_msg + 4;
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
		ssl_get_ecdh_params_from_cert(tls);
	}
#endif /* TTLS_KEY_EXCHANGE__SOME__ECDH_ENABLED */

	/* Key exchanges not involving ephemeral keys don't use
	 * ServerKeyExchange, so end here. */
#if defined(TTLS_KEY_EXCHANGE__SOME_NON_PFS__ENABLED)
	if (ttls_ssl_ciphersuite_no_pfs(ciphersuite_info))
	{
		TTLS_SSL_DEBUG_MSG(2, ("<= skip write server key exchange"));
		tls->state++;
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
		const unsigned char *end = tls->out_msg + TTLS_SSL_MAX_CONTENT_LEN;

		r = ttls_ecjpake_write_round_two(&tls->handshake->ecjpake_ctx,
				p, end - p, &len, tls->conf->f_rng, tls->conf->p_rng);
		if (r != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecjpake_write_round_two", r);
			return r;
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
		if (tls->conf->dhm_P.p == NULL || tls->conf->dhm_G.p == NULL)
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
		if ((r = ttls_dhm_set_group(&tls->handshake->dhm_ctx,
						   &tls->conf->dhm_P,
						   &tls->conf->dhm_G)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_dhm_set_group", r);
			return r;
		}

		if ((r = ttls_dhm_make_params(&tls->handshake->dhm_ctx,
						(int) ttls_mpi_size(&tls->handshake->dhm_ctx.P),
						p, &len, tls->conf->f_rng, tls->conf->p_rng)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_dhm_make_params", r);
			return r;
		}

#if defined(TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED)		
		dig_signed = p;
		dig_signed_len = len;
#endif

		p += len;
		n += len;

		TTLS_SSL_DEBUG_MPI(3, "DHM: X ", &tls->handshake->dhm_ctx.X );
		TTLS_SSL_DEBUG_MPI(3, "DHM: P ", &tls->handshake->dhm_ctx.P );
		TTLS_SSL_DEBUG_MPI(3, "DHM: G ", &tls->handshake->dhm_ctx.G );
		TTLS_SSL_DEBUG_MPI(3, "DHM: GX", &tls->handshake->dhm_ctx.GX);
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
		for (gid = tls->conf->curve_list; *gid != TTLS_ECP_DP_NONE; gid++)
			for (curve = tls->handshake->curves; *curve != NULL; curve++)
				if ((*curve)->grp_id == *gid)
					goto curve_matching_done;

curve_matching_done:
		if (curve == NULL || *curve == NULL)
		{
			TTLS_SSL_DEBUG_MSG(1, ("no matching curve for ECDHE"));
			return(TTLS_ERR_SSL_NO_CIPHER_CHOSEN);
		}

		TTLS_SSL_DEBUG_MSG(2, ("ECDHE curve: %s", (*curve)->name));

		if ((r = ttls_ecp_group_load(&tls->handshake->ecdh_ctx.grp,
						   (*curve)->grp_id)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecp_group_load", r);
			return r;
		}

		if ((r = ttls_ecdh_make_params(&tls->handshake->ecdh_ctx, &len,
						  p, TTLS_SSL_MAX_CONTENT_LEN - n,
						  tls->conf->f_rng, tls->conf->p_rng)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecdh_make_params", r);
			return r;
		}

#if defined(TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED)
		dig_signed	 = p;
		dig_signed_len = len;
#endif

		p += len;
		n += len;

		TTLS_SSL_DEBUG_ECP(3, "ECDH: Q ", &tls->handshake->ecdh_ctx.Q);
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

		ttls_pk_type_t sig_alg =
			ttls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info);
		if (tls->minor_ver == TTLS_SSL_MINOR_VERSION_3)
		{
			/* A: For TLS 1.2, obey signature-hash-algorithm extension
			 *	(RFC 5246, Sec. 7.4.1.4.1). */
			if (sig_alg == TTLS_PK_NONE ||
				(md_alg = ttls_ssl_sig_hash_set_find(&tls->handshake->hash_algs,
								  sig_alg)) == TTLS_MD_NONE)
			{
				TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
				/* (... because we choose a cipher suite 
				 *	  only if there is a matching hash.) */
				return(TTLS_ERR_SSL_INTERNAL_ERROR);
			}
		}
		else
		{
			/* C: MD5 + SHA1 */
			md_alg = TTLS_MD_NONE;
		}

		TTLS_SSL_DEBUG_MSG(3, ("pick hash algorithm %d for signing", md_alg));

		/*
		 * 3.2: Compute the hash to be signed
		 */
		if (md_alg != TTLS_MD_NONE)
		{
			/* Info from md_alg will be used instead */
			hashlen = 0;
			r = ttls_ssl_get_key_exchange_md_tls1_2(tls, hash,
								  dig_signed,
								  dig_signed_len,
								  md_alg);
			if (r != 0)
				return r;
		}
		else
		{
			TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
			return(TTLS_ERR_SSL_INTERNAL_ERROR);
		}

		TTLS_SSL_DEBUG_BUF(3, "parameters hash", hash, hashlen != 0 ? hashlen :
			(unsigned int) (ttls_md_get_size(ttls_md_info_from_type(md_alg))));

		/*
		 * 3.3: Compute and add the signature
		 */
		if (ttls_ssl_own_key(tls) == NULL)
		{
			TTLS_SSL_DEBUG_MSG(1, ("got no private key"));
			return(TTLS_ERR_SSL_PRIVATE_KEY_REQUIRED);
		}

		if (tls->minor_ver == TTLS_SSL_MINOR_VERSION_3)
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

		if ((r = ttls_pk_sign(ttls_ssl_own_key(tls), md_alg, hash, hashlen,
						p + 2 , &signature_len, tls->conf->f_rng, tls->conf->p_rng)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_pk_sign", r);
			return r;
		}

		*(p++) = (unsigned char)(signature_len >> 8);
		*(p++) = (unsigned char)(signature_len	 );
		n += 2;

		TTLS_SSL_DEBUG_BUF(3, "my signature", p, signature_len);

		n += signature_len;
	}
#endif /* TTLS_KEY_EXCHANGE__WITH_SERVER_SIGNATURE__ENABLED */

	/* Done with actual work; add header and send. */

	tls->out_msglen  = 4 + n;
	tls->out_msgtype = TTLS_MSG_HANDSHAKE;
	tls->out_msg[0]  = TTLS_SSL_HS_SERVER_KEY_EXCHANGE;

	tls->state++;

	if ((r = ttls_ssl_write_record(tls)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_write_record", r);
		return r;
	}

	TTLS_SSL_DEBUG_MSG(2, ("<= write server key exchange"));

	return 0;
}

static int ssl_write_server_hello_done(ttls_ssl_context *tls)
{
	int r;

	TTLS_SSL_DEBUG_MSG(2, ("=> write server hello done"));

	tls->out_msglen  = 4;
	tls->out_msgtype = TTLS_MSG_HANDSHAKE;
	tls->out_msg[0]  = TTLS_SSL_HS_SERVER_HELLO_DONE;

	tls->state++;

#if defined(TTLS_SSL_PROTO_DTLS)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM)
		ttls_ssl_send_flight_completed(tls);
#endif

	if ((r = ttls_ssl_write_record(tls)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_write_record", r);
		return r;
	}

	TTLS_SSL_DEBUG_MSG(2, ("<= write server hello done"));

	return 0;
}

#if defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
	defined(TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
static int ssl_parse_client_dh_public(ttls_ssl_context *tls, unsigned char **p,
					   const unsigned char *end)
{
	int r = TTLS_ERR_SSL_FEATURE_UNAVAILABLE;
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

	if ((r = ttls_dhm_read_public(&tls->handshake->dhm_ctx, *p, n)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_dhm_read_public", r);
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP);
	}

	*p += n;

	TTLS_SSL_DEBUG_MPI(3, "DHM: GY", &tls->handshake->dhm_ctx.GY);

	return r;
}
#endif /* TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */

#if defined(TTLS_KEY_EXCHANGE_RSA_ENABLED) ||  \
	defined(TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
static int ssl_parse_encrypted_pms(ttls_ssl_context *tls,
				const unsigned char *p,
				const unsigned char *end,
				size_t pms_offset)
{
	int r;
	size_t len = ttls_pk_get_len(ttls_ssl_own_key(tls));
	unsigned char *pms = tls->handshake->premaster + pms_offset;
	unsigned char ver[2];
	unsigned char fake_pms[48], peer_pms[48];
	unsigned char mask;
	size_t i, peer_pmslen;
	unsigned int diff;

	if (! ttls_pk_can_do(ttls_ssl_own_key(tls), TTLS_PK_RSA))
	{
		TTLS_SSL_DEBUG_MSG(1, ("got no RSA private key"));
		return(TTLS_ERR_SSL_PRIVATE_KEY_REQUIRED);
	}

	/*
	 * Decrypt the premaster using own private RSA key
	 */
	if (tls->minor_ver != TTLS_SSL_MINOR_VERSION_0)
	{
		if (*p++ != ((len >> 8) & 0xFF) ||
			*p++ != ((len	 ) & 0xFF))
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
		}
	}

	if (p + len != end)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
	}

	ttls_ssl_write_version(tls->handshake->max_major_ver,
					   tls->handshake->max_minor_ver,
					   tls->conf->transport, ver);

	/*
	 * Protection against Bleichenbacher's attack: invalid PKCS#1 v1.5 padding
	 * must not cause the connection to end immediately; instead, send a
	 * bad_record_mac later in the handshake.
	 * Also, avoid data-dependant branches here to protect against
	 * timing-based variants.
	 */
	r = tls->conf->f_rng(tls->conf->p_rng, fake_pms, sizeof(fake_pms));
	if (r != 0)
		return r;

	r = ttls_pk_decrypt(ttls_ssl_own_key(tls), p, len,
					  peer_pms, &peer_pmslen,
					  sizeof(peer_pms),
					  tls->conf->f_rng, tls->conf->p_rng);

	diff  = (unsigned int) r;
	diff |= peer_pmslen ^ 48;
	diff |= peer_pms[0] ^ ver[0];
	diff |= peer_pms[1] ^ ver[1];

#if defined(TTLS_SSL_DEBUG_ALL)
	if (diff != 0)
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
#endif

	if (sizeof(tls->handshake->premaster) < pms_offset ||
		sizeof(tls->handshake->premaster) - pms_offset < 48)
	{
		TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_SSL_INTERNAL_ERROR);
	}
	tls->handshake->pmslen = 48;

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

	for (i = 0; i < tls->handshake->pmslen; i++)
		pms[i] = (mask & fake_pms[i]) | ((~mask) & peer_pms[i]);

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */

#if defined(TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
static int ssl_parse_client_psk_identity(ttls_ssl_context *tls, unsigned char **p,
					const unsigned char *end)
{
	int r = 0;
	size_t n;

	if (tls->conf->f_psk == NULL &&
		(tls->conf->psk == NULL || tls->conf->psk_identity == NULL ||
		  tls->conf->psk_identity_len == 0 || tls->conf->psk_len == 0))
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

	if (tls->conf->f_psk != NULL)
	{
		if (tls->conf->f_psk(tls->conf->p_psk, tls, *p, n) != 0)
			r = TTLS_ERR_SSL_UNKNOWN_IDENTITY;
	}
	else
	{
		/* Identity is not a big secret since clients send it in the clear,
		 * but treat it carefully anyway, just in case */
		if (n != tls->conf->psk_identity_len ||
			crypto_memneq(tls->conf->psk_identity, *p, n) != 0)
		{
			r = TTLS_ERR_SSL_UNKNOWN_IDENTITY;
		}
	}

	if (r == TTLS_ERR_SSL_UNKNOWN_IDENTITY)
	{
		TTLS_SSL_DEBUG_BUF(3, "Unknown PSK identity", *p, n);
		ttls_ssl_send_alert_message(tls, TTLS_SSL_ALERT_LEVEL_FATAL,
						TTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY);
		return(TTLS_ERR_SSL_UNKNOWN_IDENTITY);
	}

	*p += n;

	return 0;
}
#endif /* TTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

static int ssl_parse_client_key_exchange(ttls_ssl_context *tls)
{
	int r;
	const ttls_ssl_ciphersuite_t *ciphersuite_info;
	unsigned char *p, *end;

	ciphersuite_info = tls->transform_negotiate->ciphersuite_info;

	TTLS_SSL_DEBUG_MSG(2, ("=> parse client key exchange"));

	if ((r = ttls_read_record(tls)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_read_record", r);
		return r;
	}

	p = tls->in_msg + ttls_ssl_hs_hdr_len(tls);
	end = tls->in_msg + tls->in_hslen;

	if (tls->in_msgtype != TTLS_MSG_HANDSHAKE)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
	}

	if (tls->in_msg[0] != TTLS_SSL_HS_CLIENT_KEY_EXCHANGE)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
		return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
	}

#if defined(TTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_RSA)
	{
		if ((r = ssl_parse_client_dh_public(tls, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_dh_public"), r);
			return r;
		}

		if (p != end)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange"));
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
		}

		if ((r = ttls_dhm_calc_secret(&tls->handshake->dhm_ctx,
						  tls->handshake->premaster,
						  TTLS_PREMASTER_SIZE,
						 &tls->handshake->pmslen,
						  tls->conf->f_rng, tls->conf->p_rng)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_dhm_calc_secret", r);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS);
		}

		TTLS_SSL_DEBUG_MPI(3, "DHM: K ", &tls->handshake->dhm_ctx.K );
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
		if ((r = ttls_ecdh_read_public(&tls->handshake->ecdh_ctx,
									  p, end - p)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecdh_read_public", r);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP);
		}

		TTLS_SSL_DEBUG_ECP(3, "ECDH: Qp ", &tls->handshake->ecdh_ctx.Qp);

		if ((r = ttls_ecdh_calc_secret(&tls->handshake->ecdh_ctx,
						  &tls->handshake->pmslen,
						   tls->handshake->premaster,
						   TTLS_MPI_MAX_SIZE,
						   tls->conf->f_rng, tls->conf->p_rng)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecdh_calc_secret", r);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS);
		}

		TTLS_SSL_DEBUG_MPI(3, "ECDH: z  ", &tls->handshake->ecdh_ctx.z);
	}
	else
#endif /* TTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED ||
		  TTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK)
	{
		if ((r = ssl_parse_client_psk_identity(tls, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), r);
			return r;
		}

		if (p != end)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange"));
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
		}

		if ((r = ttls_ssl_psk_derive_premaster(tls,
						ciphersuite_info->key_exchange)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_psk_derive_premaster", r);
			return r;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK)
	{
		if ((r = ssl_parse_client_psk_identity(tls, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), r);
			return r;
		}

		if ((r = ssl_parse_encrypted_pms(tls, p, end, 2)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_encrypted_pms"), r);
			return r;
		}

		if ((r = ttls_ssl_psk_derive_premaster(tls,
						ciphersuite_info->key_exchange)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_psk_derive_premaster", r);
			return r;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK)
	{
		if ((r = ssl_parse_client_psk_identity(tls, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), r);
			return r;
		}
		if ((r = ssl_parse_client_dh_public(tls, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_dh_public"), r);
			return r;
		}

		if (p != end)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad client key exchange"));
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE);
		}

		if ((r = ttls_ssl_psk_derive_premaster(tls,
						ciphersuite_info->key_exchange)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_psk_derive_premaster", r);
			return r;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK)
	{
		if ((r = ssl_parse_client_psk_identity(tls, &p, end)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), r);
			return r;
		}

		if ((r = ttls_ecdh_read_public(&tls->handshake->ecdh_ctx,
									   p, end - p)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecdh_read_public", r);
			return(TTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP);
		}

		TTLS_SSL_DEBUG_ECP(3, "ECDH: Qp ", &tls->handshake->ecdh_ctx.Qp);

		if ((r = ttls_ssl_psk_derive_premaster(tls,
						ciphersuite_info->key_exchange)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ssl_psk_derive_premaster", r);
			return r;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_RSA_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA)
	{
		if ((r = ssl_parse_encrypted_pms(tls, p, end, 0)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ssl_parse_parse_encrypted_pms_secret"), r);
			return r;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_RSA_ENABLED */
#if defined(TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE)
	{
		r = ttls_ecjpake_read_round_two(&tls->handshake->ecjpake_ctx,
							  p, end - p);
		if (r != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecjpake_read_round_two", r);
			return(TTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE);
		}

		r = ttls_ecjpake_derive_secret(&tls->handshake->ecjpake_ctx,
				tls->handshake->premaster, 32, &tls->handshake->pmslen,
				tls->conf->f_rng, tls->conf->p_rng);
		if (r != 0)
		{
			TTLS_SSL_DEBUG_RET(1, "ttls_ecjpake_derive_secret", r);
			return r;
		}
	}
	else
#endif /* TTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
	{
		TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_SSL_INTERNAL_ERROR);
	}

	if ((r = ttls_ssl_derive_keys(tls)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_derive_keys", r);
		return r;
	}

	tls->state++;

	TTLS_SSL_DEBUG_MSG(2, ("<= parse client key exchange"));

	return 0;
}

static int ssl_parse_certificate_verify(ttls_ssl_context *tls)
{
	int r = TTLS_ERR_SSL_FEATURE_UNAVAILABLE;
	size_t i, sig_len;
	unsigned char hash[48];
	unsigned char *hash_start = hash;
	size_t hashlen;
	ttls_pk_type_t pk_alg;
	ttls_md_type_t md_alg;
	const ttls_ssl_ciphersuite_t *ciphersuite_info =
		tls->transform_negotiate->ciphersuite_info;

	TTLS_SSL_DEBUG_MSG(2, ("=> parse certificate verify"));

	if (ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK ||
		ciphersuite_info->key_exchange == TTLS_KEY_EXCHANGE_ECJPAKE ||
		tls->session_negotiate->peer_cert == NULL)
	{
		TTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate verify"));
		tls->state++;
		return 0;
	}

	/* Read the message without adding it to the checksum */
	do {
		// TODO AK: the function arguments
		if ((r = ttls_read_record_layer(tls, buf, len, read)) != 0)
		{
			TTLS_SSL_DEBUG_RET(1, ("ttls_read_record_layer"), r);
			return r;
		}

		r = ttls_handle_message_type(tls);

	} while (TTLS_ERR_SSL_NON_FATAL == r);

	if (0 != r)
	{
		TTLS_SSL_DEBUG_RET(1, ("ttls_handle_message_type"), r);
		return r;
	}

	tls->state++;

	/* Process the message contents */
	if (tls->in_msgtype != TTLS_MSG_HANDSHAKE ||
		tls->in_msg[0] != TTLS_SSL_HS_CERTIFICATE_VERIFY)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
		return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	i = ttls_ssl_hs_hdr_len(tls);

	/*
	 *  struct {
	 *	 SignatureAndHashAlgorithm algorithm; -- TLS 1.2 only
	 *	 opaque signature<0..2^16-1>;
	 *  } DigitallySigned;
	 */
	if (tls->minor_ver == TTLS_SSL_MINOR_VERSION_3)
	{
		if (i + 2 > tls->in_hslen)
		{
			TTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
			return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
		}

		/*
		 * Hash
		 */
		md_alg = ttls_ssl_md_alg_from_hash(tls->in_msg[i]);

		if (md_alg == TTLS_MD_NONE || ttls_ssl_set_calc_verify_md(tls, tls->in_msg[i]))
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
		if ((pk_alg = ttls_ssl_pk_alg_from_sig(tls->in_msg[i]))
						== TTLS_PK_NONE)
		{
			TTLS_SSL_DEBUG_MSG(1, ("peer not adhering to requested sig_alg"
								" for verify message"));
			return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
		}

		/*
		 * Check the certificate's key type matches the signature alg
		 */
		if (! ttls_pk_can_do(&tls->session_negotiate->peer_cert->pk, pk_alg))
		{
			TTLS_SSL_DEBUG_MSG(1, ("sig_alg doesn't match cert key"));
			return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
		}

		i++;
	}
	else
	{
		TTLS_SSL_DEBUG_MSG(1, ("should never happen"));
		return(TTLS_ERR_SSL_INTERNAL_ERROR);
	}

	if (i + 2 > tls->in_hslen)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
		return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	sig_len = (tls->in_msg[i] << 8) | tls->in_msg[i+1];
	i += 2;

	if (i + sig_len != tls->in_hslen)
	{
		TTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
		return(TTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
	}

	/* Calculate hash and verify signature */
	tls->handshake->calc_verify(tls, hash);

	if ((r = ttls_pk_verify(&tls->session_negotiate->peer_cert->pk,
				   md_alg, hash_start, hashlen,
				   tls->in_msg + i, sig_len)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_pk_verify", r);
		return r;
	}

	ttls_ssl_update_handshake_status(tls);

	TTLS_SSL_DEBUG_MSG(2, ("<= parse certificate verify"));

	return r;
}

#if defined(TTLS_SSL_SESSION_TICKETS)
static int ssl_write_new_session_ticket(ttls_ssl_context *tls)
{
	int r;
	size_t tlen;
	uint32_t lifetime;

	TTLS_SSL_DEBUG_MSG(2, ("=> write new session ticket"));

	tls->out_msgtype = TTLS_MSG_HANDSHAKE;
	tls->out_msg[0]  = TTLS_SSL_HS_NEW_SESSION_TICKET;

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

	if ((r = tls->conf->f_ticket_write(tls->conf->p_ticket,
					tls->session_negotiate,
					tls->out_msg + 10,
					tls->out_msg + TTLS_SSL_MAX_CONTENT_LEN,
					&tlen, &lifetime)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_ticket_write", r);
		tlen = 0;
	}

	tls->out_msg[4] = (lifetime >> 24) & 0xFF;
	tls->out_msg[5] = (lifetime >> 16) & 0xFF;
	tls->out_msg[6] = (lifetime >>  8) & 0xFF;
	tls->out_msg[7] = (lifetime	  ) & 0xFF;

	tls->out_msg[8] = (unsigned char)((tlen >> 8) & 0xFF);
	tls->out_msg[9] = (unsigned char)((tlen	 ) & 0xFF);

	tls->out_msglen = 10 + tlen;

	/*
	 * Morally equivalent to updating tls->state, but NewSessionTicket and
	 * ChangeCipherSpec share the same state.
	 */
	tls->handshake->new_session_ticket = 0;

	if ((r = ttls_ssl_write_record(tls)) != 0)
	{
		TTLS_SSL_DEBUG_RET(1, "ttls_ssl_write_record", r);
		return r;
	}

	TTLS_SSL_DEBUG_MSG(2, ("<= write new session ticket"));

	return 0;
}
#endif /* TTLS_SSL_SESSION_TICKETS */

/*
 * SSL handshake -- server side -- single step
 */
int ttls_ssl_handshake_server_step(ttls_ssl_context *tls)
{
	int r = 0;

	if (tls->state == TTLS_SSL_HANDSHAKE_OVER || tls->handshake == NULL)
		return(TTLS_ERR_SSL_BAD_INPUT_DATA);

	TTLS_SSL_DEBUG_MSG(2, ("server state: %d", tls->state));

	if ((r = ttls_ssl_flush_output(tls)) != 0)
		return r;

#if defined(TTLS_SSL_PROTO_DTLS)
	if (tls->conf->transport == TTLS_SSL_TRANSPORT_DATAGRAM &&
		tls->handshake->retransmit_state == TTLS_SSL_RETRANS_SENDING)
	{
		if ((r = ttls_ssl_resend(tls)) != 0)
			return r;
	}
#endif

	switch(tls->state)
	{
		case TTLS_SSL_HELLO_REQUEST:
			tls->state = TTLS_SSL_CLIENT_HELLO;
			break;

		/*
		 *  <==   ClientHello
		 */
		case TTLS_SSL_CLIENT_HELLO:
			r = ssl_parse_client_hello(tls);
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
			r = ssl_write_server_hello(tls);
			break;

		case TTLS_SSL_SERVER_CERTIFICATE:
			r = ttls_ssl_write_certificate(tls);
			break;

		case TTLS_SSL_SERVER_KEY_EXCHANGE:
			r = ssl_write_server_key_exchange(tls);
			break;

		case TTLS_SSL_CERTIFICATE_REQUEST:
			r = ssl_write_certificate_request(tls);
			break;

		case TTLS_SSL_SERVER_HELLO_DONE:
			r = ssl_write_server_hello_done(tls);
			break;

		/*
		 *  <== (Certificate/Alert )
		 *		ClientKeyExchange
		 *	  (CertificateVerify )
		 *		ChangeCipherSpec
		 *		Finished
		 */
		case TTLS_SSL_CLIENT_CERTIFICATE:
			r = ttls_ssl_parse_certificate(tls);
			break;

		case TTLS_SSL_CLIENT_KEY_EXCHANGE:
			r = ssl_parse_client_key_exchange(tls);
			break;

		case TTLS_SSL_CERTIFICATE_VERIFY:
			r = ssl_parse_certificate_verify(tls);
			break;

		case TTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:
			r = ttls_ssl_parse_change_cipher_spec(tls);
			break;

		case TTLS_SSL_CLIENT_FINISHED:
			r = ttls_ssl_parse_finished(tls);
			break;

		/*
		 *  ==> (NewSessionTicket)
		 *		ChangeCipherSpec
		 *		Finished
		 */
		case TTLS_SSL_SERVER_CHANGE_CIPHER_SPEC:
#if defined(TTLS_SSL_SESSION_TICKETS)
			if (tls->handshake->new_session_ticket != 0)
				r = ssl_write_new_session_ticket(tls);
			else
#endif
				r = ttls_ssl_write_change_cipher_spec(tls);
			break;

		case TTLS_SSL_SERVER_FINISHED:
			r = ttls_ssl_write_finished(tls);
			break;

		case TTLS_SSL_FLUSH_BUFFERS:
			TTLS_SSL_DEBUG_MSG(2, ("handshake: done"));
			tls->state = TTLS_SSL_HANDSHAKE_WRAPUP;
			break;

		case TTLS_SSL_HANDSHAKE_WRAPUP:
			ttls_ssl_handshake_wrapup(tls);
			break;

		default:
			TTLS_SSL_DEBUG_MSG(1, ("invalid state %d", tls->state));
			return(TTLS_ERR_SSL_BAD_INPUT_DATA);
	}

	return r;
}
