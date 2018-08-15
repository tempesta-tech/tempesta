/*
 *		Tempesta TLS
 *
 * TLS server-side finite state machine.
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
#include "lib/str.h"
#include "config.h"
#include "debug.h"
#include "ecp.h"
#include "ssl_internal.h"
#include "ttls.h"

static int
ttls_check_scsv_fallback(TlsCtx *tls, unsigned short cipher_suite)
{
	if (cipher_suite == TTLS_FALLBACK_SCSV_VALUE) {
		T_DBG("received FALLBACK_SCSV\n");
		if (tls->minor < tls->conf->max_minor_ver) {
			T_DBG("inapropriate fallback\n");
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_INAPROPRIATE_FALLBACK);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}
	}
	return 0;
}

static int
ttls_parse_servername_ext(TlsCtx *tls, const unsigned char *buf, size_t len)
{
	int r;
	size_t servername_list_size, hostname_len;
	const unsigned char *p;

	servername_list_size = ((buf[0] << 8) | (buf[1]));
	if (servername_list_size + 2 != len) {
		T_DBG("ClientHello: bad SNI list size\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}

	p = buf + 2;
	while (servername_list_size > 0) {
		hostname_len = ((p[1] << 8) | p[2]);
		if (hostname_len + 3 > servername_list_size) {
			T_DBG("ClientHello: bad hostname size\n");
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}

		if (tls->conf->f_sni
		    && p[0] == TTLS_TLS_EXT_SERVERNAME_HOSTNAME)
		{
			r = tls->conf->f_sni(tls->conf->p_sni, tls, p + 3,
					     hostname_len);
			if (!r)
				return 0;
			T_DBG("ClientHello: SNI error\n");
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_UNRECOGNIZED_NAME);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}

		servername_list_size -= hostname_len + 3;
		p += hostname_len + 3;
	}

	if (servername_list_size) {
		T_DBG("ClientHello: bad SNI extension\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}

	return 0;
}

/**
 * Status of the implementation of signature-algorithms extension:
 *
 * Currently, we are only considering the signature-algorithm extension
 * to pick a ciphersuite which allows us to send the ServerKeyExchange
 * message with a signature-hash combination that the user allows.
 *
 * We do *not* check whether all certificates in our certificate
 * chain are signed with an allowed signature-hash pair.
 * This needs to be done at a later stage.
 */
static int
ttls_parse_signature_algorithms_ext(TlsCtx *tls, const unsigned char *buf,
				    size_t len)
{
	size_t sig_alg_list_size;
	const unsigned char *p, *end = buf + len;
	ttls_md_type_t md_cur;
	ttls_pk_type_t sig_cur;

	sig_alg_list_size = (buf[0] << 8) | buf[1];
	if (sig_alg_list_size + 2 != len || sig_alg_list_size % 2) {
		T_DBG("ClientHello: bad signature algorithm extension\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}

	/*
	 * Currently we only guarantee signing the ServerKeyExchange message
	 * according to the constraints specified in this extension (see above),
	 * so it suffices to remember only one suitable hash for each possible
	 * signature algorithm.
	 *
	 * This will change when we also consider certificate signatures,
	 * in which case we will need to remember the whole signature-hash
	 * pair list from the extension.
	 */
	for (p = buf + 2; p < end; p += 2) {
		/* Silently ignore unknown signature or hash algorithms. */
		if ((sig_cur = ttls_pk_alg_from_sig(p[1])) == TTLS_PK_NONE) {
			T_DBG("ClientHello: signature_algorithm ext:"
			      " unknown sig alg encoding %d\n", p[1]);
			continue;
		}

		/* Check if we support the hash the user proposes */
		md_cur = ttls_md_alg_from_hash(p[0]);
		if (md_cur == TTLS_MD_NONE) {
			T_DBG("ClientHello: signature_algorithm ext:"
			      " unknown hash alg encoding %d\n", p[0]);
			continue;
		}

		if (!ttls_check_sig_hash(tls, md_cur)) {
			ttls_sig_hash_set_add(&tls->hs->hash_algs, sig_cur,
					      md_cur);
			T_DBG("ClientHello: signature_algorithm ext:"
			      " match sig %d and hash %d",
			      sig_cur, md_cur);
		} else {
			T_DBG("ClientHello: signature_algorithm ext: "
			      "hash alg %d not supported", md_cur);
		}
	}

	return 0;
}

static int
ttls_parse_supported_elliptic_curves(TlsCtx *tls, const unsigned char *buf,
				     size_t len)
{
	size_t i, c, list_size;
	const unsigned char *p;
	const ttls_ecp_curve_info *ci;

	list_size = (buf[0] << 8) | buf[1];
	if (list_size + 2 != len || list_size % 2) {
		T_DBG("ClientHello: bad elliptic curves extension\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}

	if (tls->hs->curves_ext) {
		T_DBG("ClientHello: duplicate elliptic curves extension\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}
	tls->hs->curves_ext = 1;

	/*
	 * Limit the peer in making us allocate too much memory,
	 * and leave room for a final 0.
	 */
	if (list_size / 2 + 1 > TTLS_ECP_DP_MAX)
		list_size = TTLS_ECP_DP_MAX - 1;

	for (c = i = 0, p = buf + 2; i < list_size; ++i) {
		ci = ttls_ecp_curve_info_from_tls_id((p[0] << 8) | p[1]);
		if (ci) {
			T_DBG3("set curve %s\n", ci->name);
			tls->hs->curves[c++] = ci;
		}
		p += 2;
	}

	return 0;
}

static int
ttls_parse_supported_point_formats(TlsCtx *tls, const unsigned char *buf,
				   size_t len)
{
	size_t list_size = buf[0];
	const unsigned char *p = buf + 1;

	tls->hs->cli_exts = 1;

	if (list_size + 1 != len) {
		T_DBG("ClientHello: bad supported point formats extension\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}

	while (list_size > 0) {
		if (p[0] == TTLS_ECP_PF_UNCOMPRESSED
		    || p[0] == TTLS_ECP_PF_COMPRESSED)
		{
			tls->hs->ecdh_ctx.point_format = p[0];
			T_DBG("ClientHello: point format selected: %d\n", p[0]);
			return 0;
		}
		list_size--;
		p++;
	}

	return 0;
}

static int
ttls_parse_encrypt_then_mac_ext(TlsCtx *tls, const unsigned char *buf,
				size_t len)
{
	if (len) {
		T_DBG("ClientHello: bad EtM extension\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}
	if (tls->conf->encrypt_then_mac)
		tls->encrypt_then_mac = 1;

	return 0;
}

static int
ttls_parse_extended_ms_ext(TlsCtx *tls, const unsigned char *buf, size_t len)
{
	if (len) {
		T_DBG("ClientHello: bad extended master secret extension\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}

	/* Support RFC 7627 (Extended Master Secret) by default. */
	tls->hs->extended_ms = 1;

	return 0;
}

static int
ttls_parse_session_ticket_ext(TlsCtx *tls, unsigned char *buf, size_t len)
{
	int r;
	TlsSess session;

	if (!tls->conf->f_ticket_parse || !tls->conf->f_ticket_write)
		return 0;

	/* Remember the client asked us to send a new ticket */
	tls->hs->new_session_ticket = 1;

	T_DBG("ClientHello: ticket length: %lu\n", len);

	if (!len)
		return 0;

	/* Failures are ok: just ignore the ticket and proceed. */
	bzero_fast(&session, sizeof(session));
	r = tls->conf->f_ticket_parse(tls->conf->p_ticket, &session, buf, len);
	if (r) {
		bzero_fast(&session, sizeof(session));
		if (r == TTLS_ERR_INVALID_MAC)
			T_DBG("ClientHello: ticket is not authentic\n");
		else if (r == TTLS_ERR_SESSION_TICKET_EXPIRED)
			T_DBG("ClientHello: ticket is expired");
		else
			T_DBG("ClientHello: cannot parse ticket, %d\n", r);
		return 0;
	}

	/*
	 * Keep the session ID sent by the client, since we MUST send it back to
	 * inform them we're accepting the ticket  (RFC 5077 section 3.4)
	 */
	session.id_len = tls->sess.id_len;
	memcpy(&session.id, tls->sess.id, session.id_len);
	memcpy(&tls->sess, &session, sizeof(TlsSess));

	/* Zeroize instead of free as we copied the content */
	bzero_fast(&session, sizeof(TlsSess));

	T_DBG("ClientHello: session successfully restored from ticket\n");

	tls->hs->resume = 1;
	/* Don't send a new ticket after all, this one is OK */
	tls->hs->new_session_ticket = 0;

	return 0;
}

static int
ttls_parse_alpn_ext(TlsCtx *tls, const unsigned char *buf, size_t len)
{
	size_t list_len, cur_len, ours_len;
	const unsigned char *theirs, *start, *end;
	const char **ours;

	/* If ALPN not configured, just ignore the extension */
	/* TODO #309 #834 confugure on Tempesta side: "h2, http/1.1" */
	if (!tls->conf->alpn_list)
		return 0;

	/*
	 * opaque ProtocolName<1..2^8-1>;
	 *
	 * struct {
	 *	 ProtocolName protocol_name_list<2..2^16-1>
	 * } ProtocolNameList;
	 */

	/* Min length is 2 (list_len) + 1 (name_len) + 1 (name) */
	if (len < 4) {
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}

	list_len = (buf[0] << 8) | buf[1];
	if (list_len != len - 2) {
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_DECODE_ERROR);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}

	/* Validate peer's list (lengths). */
	start = buf + 2;
	end = buf + len;
	for (theirs = start; theirs != end; theirs += cur_len) {
		cur_len = *theirs++;

		/* Current identifier must fit in list */
		if (cur_len > (size_t)(end - theirs)) {
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}

		/* Empty strings MUST NOT be included */
		if (!cur_len) {
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_ILLEGAL_PARAMETER);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}
	}

	/* Use our order of preference. */
	for (ours = tls->conf->alpn_list; *ours; ours++) {
		/* TODO store the string length to avoid strlen(). */
		ours_len = strlen(*ours);
		WARN_ON_ONCE(ours_len > 32);
		for (theirs = start; theirs != end; theirs += cur_len) {
			cur_len = *theirs++;
			if (cur_len == ours_len
			    && !memcmp_fast(theirs, *ours, cur_len))
			{
				tls->alpn_chosen = *ours;
				return 0;
			}
		}
	}

	/* If we get there, no match was found */
	ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
			TTLS_ALERT_MSG_NO_APPLICATION_PROTOCOL);
	return TTLS_ERR_BAD_HS_CLIENT_HELLO;
}

/**
 * @return 0 if the given key uses one of the acceptable curves, -1 otherwise.
 */
static int
ttls_check_key_curve(ttls_pk_context *pk, const ttls_ecp_curve_info **curves)
{
	const ttls_ecp_curve_info **crv = curves;
	ttls_ecp_group_id grp_id = ttls_pk_ec(*pk)->grp.id;

	while (*crv) {
		if ((*crv)->grp_id == grp_id)
			return 0;
		crv++;
	}

	return -1;
}

/**
 * Try picking a certificate for this ciphersuite,
 * @return 0 on success and -1 on failure.
 */
static int
ttls_pick_cert(TlsCtx *tls, const ttls_ciphersuite_t *ci)
{
	ttls_key_cert *cur, *list;
	ttls_pk_type_t pk_alg = ttls_get_ciphersuite_sig_pk_alg(ci);
	uint32_t flags;

	if (tls->hs->sni_key_cert)
		list = tls->hs->sni_key_cert;
	else
		list = tls->conf->key_cert;

	if (pk_alg == TTLS_PK_NONE)
		return 0;

	T_DBG("ciphersuite requires certificate\n");

	if (!list) {
		T_DBG("server has no certificate\n");
		return -1;
	}

	for (cur = list; cur != NULL; cur = cur->next) {
		if (!ttls_pk_can_do(cur->key, pk_alg)) {
			T_DBG("certificate mismatch for alg %d\n", pk_alg);
			continue;
		}

		/*
		 * This avoids sending the client a cert it'll reject based on
		 * keyUsage or other extensions.
		 *
		 * It also allows the user to provision different certificates
		 * for different uses based on keyUsage, eg if they want to
		 * avoid signing and decrypting with the same RSA key.
		 */
		if (ttls_check_cert_usage(cur->cert, ci, TTLS_IS_SERVER,
					  &flags))
		{
			T_DBG("certificate mismatch: (extended) key usage"
			      " extension\n");
			continue;
		}

		if (pk_alg == TTLS_PK_ECDSA
		    && ttls_check_key_curve(cur->key, tls->hs->curves))
		{
			T_DBG("certificate mismatch: elliptic curve\n");
			continue;
		}

		/* If we get there, we got a winner */
		break;
	}

	/* Do not update tls->hs->key_cert unless there is a match */
	if (cur) {
		tls->hs->key_cert = cur;
		return 0;
	}

	return -1;
}

/**
 * Check if a given ciphersuite is suitable for use with our config/keys/etc
 * Sets @ci only if the suite matches.
 */
static int
ttls_ciphersuite_match(TlsCtx *tls, int suite_id, const ttls_ciphersuite_t **ci)
{
	const ttls_ciphersuite_t *suite_info;
	ttls_pk_type_t sig_type;

	suite_info = ttls_ciphersuite_from_id(suite_id);
	if (!suite_info) {
		T_WARN("ClientHello: cannot match a ciphersuite\n");
		return TTLS_ERR_INTERNAL_ERROR;
	}

	T_DBG("trying ciphersuite: %s\n", suite_info->name);

	if (suite_info->min_minor_ver > tls->minor
	    || suite_info->max_minor_ver < tls->minor)
	{
		T_DBG("ciphersuite mismatch: version (%d-%d to %d)\n",
		      suite_info->min_minor_ver, suite_info->max_minor_ver,
		      tls->minor);
		return 0;
	}
	if (ttls_ciphersuite_uses_ec(suite_info) && !tls->hs->curves[0]) {
		T_DBG("ciphersuite mismatch: no common elliptic curve\n");
		return 0;
	}
	/*
	 * If the ciphersuite requires signing, check whether
	 * a suitable hash algorithm is present.
	 */
	sig_type = ttls_get_ciphersuite_sig_alg(suite_info);
	if (sig_type != TTLS_PK_NONE
	    && ttls_sig_hash_set_find(&tls->hs->hash_algs, sig_type)
	        == TTLS_MD_NONE)
	{
		T_DBG("ciphersuite mismatch: no suitable hash algorithm"
		      " for signature algorithm %d", sig_type);
		return 0;
	}
	/*
	 * Final check: if ciphersuite requires us to have a
	 * certificate/key of a particular type:
	 * - select the appropriate certificate if we have one, or
	 * - try the next ciphersuite if we don't
	 * This must be done last since we modify the key_cert list.
	 */
	if (ttls_pick_cert(tls, suite_info)) {
		T_DBG("ciphersuite mismatch: no suitable certificate\n");
		return 0;
	}

	*ci = suite_info;

	return 0;
}

static int
ttls_choose_ciphersuite(TlsCtx *tls, const unsigned char *csp)
{
	unsigned short ciph_len = ntohs(*(short *)csp);
	int r, i, got_common_suite = 0;
	const int *ciphersuites = tls->conf->ciphersuite_list[tls->minor];
	const ttls_ciphersuite_t *ci = NULL;
	const unsigned char *cs;

	for (i = 0; ciphersuites[i] != 0; i++)
		for (cs = csp + 2; cs < csp + ciph_len; cs += 2) {
			if (ntohs(*(short *)cs) != ciphersuites[i])
				continue;
			got_common_suite = 1;
			r = ttls_ciphersuite_match(tls, ciphersuites[i], &ci);
			if (r)
				return r;
			if (ci)
				goto have_ciphersuite;
		}

	if (got_common_suite) {
		T_DBG("got ciphersuites in common, but none of them usable\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return TTLS_ERR_NO_USABLE_CIPHERSUITE;
	} else {
		T_DBG("got no ciphersuites in common\n");
		ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
				TTLS_ALERT_MSG_HANDSHAKE_FAILURE);
		return TTLS_ERR_NO_CIPHER_CHOSEN;
	}

have_ciphersuite:
	T_DBG("selected ciphersuite: %s\n", ci->name);

	tls->sess.ciphersuite = ciphersuites[i];
	tls->xfrm.ciphersuite_info = ci;

	/* Debugging-only output for testsuite */
#if defined(DEBUG) && (DEBUG == 3)
	{
		ttls_md_type_t md_alg;
		ttls_pk_type_t sig_alg = ttls_get_ciphersuite_sig_alg(ci);
		if (sig_alg != TTLS_PK_NONE) {
			md_alg = ttls_sig_hash_set_find(&tls->hs->hash_algs,
				sig_alg);
			T_DBG("client hello v3, signature_algorithm ext: %d",
			      ttls_hash_from_md_alg(md_alg));
		} else {
			T_DBG("no hash algorithm for signature algorithm %d"
			      " - should not happen", sig_alg);
		}
	}
#endif
	return 0;
}

/**
 * This function doesn't alert on errors that happen early during
 * ClientHello parsing because they might indicate that the client is
 * not talking SSL/TLS at all and would not understand our alert.
 *
 * We use legacy no renegotiation option: allow connections to be established
 * even if the peer does not support secure renegotiation, but does not allow
 * renegotiation to take place if not secure.
 */
static int
ttls_parse_client_hello(TlsCtx *tls, unsigned char *buf, size_t len,
			unsigned int *read)
{
	int r = T_POSTPONE, n;
	unsigned char *p = buf;
	TlsIOCtx *io = &tls->io_in;
	T_FSM_INIT(tls->state, "TLS ClientHello");

	if (io->hstype != TTLS_HS_CLIENT_HELLO) {
		T_DBG("bad type in client hello message\n");
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}
	/*
	 * Minimal length (with everything empty and extensions
	 * ommitted) is 2 + 32 + 1 + 2 + 1 = 38 bytes. Check that first,
	 * so that we can read at least up to session id length without
	 * worrying.
	 */
	if (io->hslen < 38) {
		T_DBG("too short client handshake message: %u\n", io->hslen);
		return TTLS_ERR_BAD_HS_CLIENT_HELLO;
	}


	T_FSM_START(ttls_substate(tls)) {

	/*
	 * ClientHello layer:
	 *	 0  .   1   protocol version
	 *	 2  .  33   random bytes (starting with 4 bytes of Unix time)
	 *	34  .  35   session id length (1 byte)
	 *	35  . 34+x  session id
	 *     35+x . 35+x  DTLS only: cookie length (1 byte)
	 *     36+x .  ..   DTLS only: cookie
	 *	..  .  ..   ciphersuite list length (2 bytes)
	 *	..  .  ..   ciphersuite list
	 *	..  .  ..   compression alg. list length (1 byte)
	 *	..  .  ..   compression alg. list
	 *	..  .  ..   extensions length (2 bytes, optional)
	 *	..  .  ..   extensions (optional)
	 */
	T_FSM_STATE(TTLS_CH_HS_VER) {
		BUG_ON(io->rlen >= 2);
		if (unlikely(io->rlen)) {
			tls->hs->tmp[1] = *p;
			p++;
			ttls_read_version(tls, tls->hs->tmp);
		}
		else if (unlikely(buf + len - p == 1)) {
			tls->hs->tmp[0] = *p;
			io->rlen = 1;
			p++;
			T_FSM_EXIT();
		} else {
			ttls_read_version(tls, p);
			p += 2;
		}
		io->hslen -= 2;
		if (tls->major != TTLS_MAJOR_VERSION_3
		    || tls->minor != TTLS_MINOR_VERSION_3)
		{
			T_DBG("ClientHello: bad version %u:%u\n",
			      tls->major, tls->minor);
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_PROTOCOL_VERSION);
			return TTLS_ERR_BAD_HS_PROTOCOL_VERSION;
		}
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_RND);
	}

	T_FSM_STATE(TTLS_CH_HS_RND) {
		BUG_ON(io->rlen >= 32);
		n = min_t(int, 32 - io->rlen, buf + len - p);
		/* Save client random (inc. Unix time). */
		memcpy_fast(tls->hs->randbytes + io->rlen, p, n);
		io->rlen += n;
		p += n;
		io->hslen -= 32;
		if (unlikely(io->rlen < 32))
			T_FSM_EXIT();
		T_DBG3_BUF("ClientHello: random bytes ",
			   tls->hs->randbytes, 32);
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_SLEN);
	}

	/* Check the session ID length and save session ID. */
	T_FSM_STATE(TTLS_CH_HS_SLEN) {
		n = *p;
		/* 2 for cipherlist length field. */
		if (n > sizeof(tls->sess.id) || n + 34 + 2 > io->hslen) {
			T_DBG("ClientHello: bad session length %d\n", n);
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}
		tls->sess.id_len = n;
		T_DBG3("ClientHello: Session ID length %u\n", n);
		io->hslen--;
		++p;
		if (n)
			TTLS_HS_FSM_MOVE(TTLS_CH_HS_SESS);
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_CSLEN);
	}

	T_FSM_STATE(TTLS_CH_HS_SESS) {
		BUG_ON(io->rlen >= tls->sess.id_len);
		n = min_t(int, tls->sess.id_len - io->rlen, buf + len - p);
		/* The session ID is zeroed on TlsCtx initialization. */
		memcmp_fast(tls->sess.id + io->rlen, p, n);
		io->rlen += n;
		p += n;
		io->hslen -= n;
		if (unlikely(io->rlen < tls->sess.id_len))
			T_FSM_EXIT();
		T_DBG3_BUF("ClientHello: session id ",
			   tls->sess.id, tls->sess.id_len);
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_CSLEN);
	}

	/* Read cipher suites length. */
	T_FSM_STATE(TTLS_CH_HS_CSLEN) {
		BUG_ON(io->rlen >= 2);
		if (unlikely(io->rlen)) {
			tls->hs->tmp[TTLS_HS_TMP_STORE_SZ + 1] = *p;
			p++;
		}
		else if (unlikely(buf + len - p == 1)) {
			tls->hs->tmp[TTLS_HS_TMP_STORE_SZ] = *p;
			io->rlen = 1;
			p++;
			T_FSM_EXIT();
		}
		else {
			memcpy_fast(&tls->hs->tmp[TTLS_HS_TMP_STORE_SZ], p, 2);
			p += 2;
		}
		n = ntohs(*(short *)&tls->hs->tmp[TTLS_HS_TMP_STORE_SZ]);
		T_DBG3("ClientHello: cipher suites length %u\n", n);
		/* Initialize number of currently read ciphersuites. */
		*(unsigned short *)tls->hs->tmp = 0;
		io->hslen -= 2;
		/* 1 for comp. alg. len */
		if (n < 2 || n + 1 > io->hslen || (n & 1)) {
			T_DBG("ClientHello: bad cipher suite length %d\n", n);
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_CS);
	}

	/* Read a cipher suite. */
	T_FSM_STATE(TTLS_CH_HS_CS) {
		unsigned short cs, *csn = (unsigned short *)tls->hs->tmp;
		const unsigned int off = TTLS_HS_TMP_STORE_SZ + 2;
		/* Get number of ciphersuite bytes from the client. */
		n = ntohs(*(short *)&tls->hs->tmp[TTLS_HS_TMP_STORE_SZ]);
		BUG_ON(io->rlen >= 2);
		/*
		 * Skip the last low-priority cipher suites which we can not
		 * store.
		 */
		if (2 + *csn + 2 > TTLS_HS_CS_MAX_SZ) {
			/* Write number of stored cipher suite bytes. */
			*(short *)&tls->hs->tmp[TTLS_HS_TMP_STORE_SZ] = htons(*csn);
			io->hslen -= n - *csn;
			TTLS_HS_FSM_MOVE(TTLS_CH_HS_COMPN);
		}
		/* Read current cipher suite, just after the counter. */
		if (unlikely(io->rlen)) {
			tls->hs->tmp[off + *csn + 1] = *p;
			p++;
		}
		else if (unlikely(buf + len - p == 1)) {
			tls->hs->tmp[off + *csn] = *p;
			io->rlen = 1;
			p++;
			T_FSM_EXIT();
		}
		else {
			memcpy_fast(&tls->hs->tmp[off + *csn], p, 2);
			p += 2;
		}
		cs = ntohs(*(short *)&tls->hs->tmp[off + *csn]);
		T_DBG3("ClientHello: cipher suite #%u: %#x\n",
		       *csn / 2, cs);
		if (ttls_check_scsv_fallback(tls, cs))
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		io->hslen -= 2;
		*csn += 2;
		if (*csn == n)
			TTLS_HS_FSM_MOVE(TTLS_CH_HS_COMPN);
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_CS);
	}

	/* Check the compression algorithms length. */
	T_FSM_STATE(TTLS_CH_HS_COMPN) {
		n = *p;
		if (n < 1 || n > 16 || n + 1 > io->hslen) {
			T_DBG("ClientHello: bad compression number %d\n", n);
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}
		/*
		 * Use 2 bytes to read out compression stuff: 1st for
		 * compression algorithms to read and 2nd for a flag
		 * that we've faced NULL-compression.
		 */
		tls->hs->tmp[0] = n;
		tls->hs->tmp[1] = 0;
		T_DBG3("ClientHello: compression algorithms length %u\n", n);
		io->hslen--;
		++p;
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_COMP);
	}

	T_FSM_STATE(TTLS_CH_HS_COMP) {
		if (*p == TTLS_COMPRESS_NULL) {
			T_DBG3("saw NULL compression\n");
			tls->hs->tmp[1] = 1;
		}
		io->hslen--;
		++p;
		if (!--tls->hs->tmp[0]) {
			if (!tls->hs->tmp[1]) {
				T_DBG("ClientHello: no NULL compression\n");
				ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
						TTLS_ALERT_MSG_DECODE_ERROR);
				return TTLS_ERR_BAD_HS_CLIENT_HELLO;
			}
			TTLS_HS_FSM_MOVE(TTLS_CH_HS_EXTLEN);
		}
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_COMP);
	}

	/* Read extensins length. */
	T_FSM_STATE(TTLS_CH_HS_EXTLEN) {
		/* Use the first 2 bytes for toal number of extensions. */
		BUG_ON(io->rlen >= 2);
		if (unlikely(io->rlen)) {
			tls->hs->tmp[1] = *p;
			p++;
		}
		else if (unlikely(buf + len - p == 1)) {
			tls->hs->tmp[0] = *p;
			io->rlen = 1;
			p++;
			T_FSM_EXIT();
		}
		else {
			memcpy_fast(tls->hs->tmp, p, 2);
			p += 2;
		}
		n = ntohs(*(short *)tls->hs->tmp);
		io->hslen -= 2;
		if (io->hslen != n || (n > 0 && n < 4)) {
			T_DBG("ClientHello: bad extensions length %d"
			      " (msg len=%u)\n", n, io->hslen);
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}
		if (!n) {
			r = T_OK;
			T_FSM_EXIT();
		}
		/* Swap bytes to reuse them as a pointer to short later. */
		*(short *)tls->hs->tmp = (short)n;
		T_DBG3("ClientHello: extensions length %u\n", n);
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_EXT);
	}

	/* Read extension type. */
	T_FSM_STATE(TTLS_CH_HS_EXT) {
		/* Use the second 2 bytes for current extension type. */
		BUG_ON(io->rlen >= 2);
		if (unlikely(io->rlen)) {
			tls->hs->tmp[3] = *p;
			p++;
		}
		else if (unlikely(buf + len - p == 1)) {
			tls->hs->tmp[2] = *p;
			io->rlen = 1;
			p++;
			T_FSM_EXIT();
		}
		else {
			memcpy_fast(&tls->hs->tmp[2], p, 2);
			p += 2;
		}
		/* Swap bytes to reuse them as a pointer to short later. */
		*(short *)&tls->hs->tmp[2] = ntohs(*(short *)&tls->hs->tmp[2]);
		T_DBG3("ClientHello: read extension %#x...\n",
		       *(short *)&tls->hs->tmp[2]);
		io->hslen -= 2;
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_EXS);
	}

	/* Read an extension size. */
	T_FSM_STATE(TTLS_CH_HS_EXS) {
		/* Use the third 2 bytes for current extension size. */
		unsigned short lim, ciph_len = 2, ext_len = *(short *)tls->hs->tmp;
		ciph_len += ntohs(*(short *)&tls->hs->tmp[TTLS_HS_TMP_STORE_SZ]);
		lim = TTLS_HS_RBUF_SZ - TTLS_HS_TMP_STORE_SZ - ciph_len;
		BUG_ON(io->rlen >= 2);
		WARN_ON_ONCE(lim < TTLS_HS_EXT_RES_SZ);
		if (unlikely(io->rlen)) {
			tls->hs->tmp[5] = *p;
			p++;
		}
		else if (unlikely(buf + len - p == 1)) {
			tls->hs->tmp[4] = *p;
			io->rlen = 1;
			p++;
			T_FSM_EXIT();
		}
		else {
			memcpy_fast(&tls->hs->tmp[4], p, 2);
			p += 2;
		}
		io->hslen -= 2;
		n = ntohs(*(short *)&tls->hs->tmp[4]);
		if (n + 4 > ext_len || n > lim) {
			T_DBG("ClientHello: bad extension size %d"
			      " (ext_len=%u)\n", n, ext_len);
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}
		/* Swap bytes to reuse them as a pointer to short later. */
		*(short *)&tls->hs->tmp[4] = (short)n;
		TTLS_HS_FSM_MOVE(TTLS_CH_HS_EX);
	}

	/* Parse an extension. */
	T_FSM_STATE(TTLS_CH_HS_EX) {
		unsigned char *tmp;
		unsigned short *ext_len = (short *)tls->hs->tmp;
		unsigned short ext_id = *(short *)&tls->hs->tmp[2];
		unsigned short ext_sz = *(short *)&tls->hs->tmp[4];
		/*
		 * Copy the extension to the temporary buffer for further
		 * parsing. We have to copy the data since the extension parsers
		 * call external functions and callbacks with contigous buffers.
		 * It's too time consumptive to rework the whole API to work w/
		 * chunked data and it's doubtful how much perfromance we get if
		 * we avoid the copies - the extensions are small after all.
		 */
		unsigned short off, ciph_len = 2;
		ciph_len += ntohs(*(short *)&tls->hs->tmp[TTLS_HS_TMP_STORE_SZ]);
		off = TTLS_HS_TMP_STORE_SZ + ciph_len;
		BUG_ON(io->rlen > ext_sz);
		n = min_t(int, ext_sz - io->rlen, buf + len - p);
		/* Save client random (inc. Unix time). */
		memcpy_fast(&tls->hs->tmp[off + io->rlen], p, n);
		io->rlen += n;
		p += n;
		if (unlikely(io->rlen < ext_sz))
			T_FSM_EXIT();
		T_DBG3("ClientHello: read %u bytes for ext %u\n",
		       io->rlen, ext_id);

		tmp = &tls->hs->tmp[off];
		switch (ext_id) {
		case TTLS_TLS_EXT_SERVERNAME:
			T_DBG("found ServerName extension\n");
			if (ttls_parse_servername_ext(tls, tmp, ext_sz))
				return TTLS_ERR_BAD_HS_CLIENT_HELLO;
			break;
		case TTLS_TLS_EXT_SIG_ALG:
			T_DBG("found signature_algorithms extension\n");
			if (ttls_parse_signature_algorithms_ext(tls, tmp,
								ext_sz))
				return TTLS_ERR_BAD_HS_CLIENT_HELLO;
			break;
		case TTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES:
			T_DBG("found supported elliptic curves extension\n");
			if (ttls_parse_supported_elliptic_curves(tls, tmp,
								 ext_sz))
				return TTLS_ERR_BAD_HS_CLIENT_HELLO;
			break;
		case TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS:
			T_DBG("found supported point formats extension\n");
			if (ttls_parse_supported_point_formats(tls, tmp,
							       ext_sz))
				return TTLS_ERR_BAD_HS_CLIENT_HELLO;
			break;
		case TTLS_TLS_EXT_ENCRYPT_THEN_MAC:
			T_DBG("found encrypt then mac extension\n");
			if (ttls_parse_encrypt_then_mac_ext(tls, tmp, ext_sz))
				return TTLS_ERR_BAD_HS_CLIENT_HELLO;
			break;
		case TTLS_TLS_EXT_EXTENDED_MASTER_SECRET:
			T_DBG("found extended master secret extension\n");
			if (ttls_parse_extended_ms_ext(tls, tmp, ext_sz))
				return TTLS_ERR_BAD_HS_CLIENT_HELLO;
			break;
		case TTLS_TLS_EXT_SESSION_TICKET:
			T_DBG("found session ticket extension\n");
			if (ttls_parse_session_ticket_ext(tls, tmp, ext_sz))
				return TTLS_ERR_BAD_HS_CLIENT_HELLO;
			break;
		case TTLS_TLS_EXT_ALPN:
			T_DBG("found alpn extension\n");
			if (ttls_parse_alpn_ext(tls, tmp, ext_sz))
				return TTLS_ERR_BAD_HS_CLIENT_HELLO;
			break;
		default:
			T_DBG("unknown extension found: %d (ignoring)\n",
			      ext_id);
		}
		*ext_len -= 4 + ext_sz;
		if (*ext_len > 0 && *ext_len < 4) {
			T_DBG("ClientHello: bad extensions list\n");
			ttls_send_alert(tls, TTLS_ALERT_LEVEL_FATAL,
					TTLS_ALERT_MSG_DECODE_ERROR);
			return TTLS_ERR_BAD_HS_CLIENT_HELLO;
		}
		if (*ext_len)
			TTLS_HS_FSM_MOVE(TTLS_CH_HS_EXT);
		r = T_OK;
		T_FSM_EXIT();
	}

	}
	TTLS_HS_FSM_FINISH();
	/*
	 * Return from the function if we need more data (r == T_POSTPONE -
	 * we'll reenter the function for further processing) or a failure
	 * (all other codes except T_OK).
	 */
	if (r != T_OK)
		return r;
	/* The message data is parsed, do final checks and setups. */

	ttls_set_default_sig_hash(tls);

	/*
	 * Search for a matching ciphersuite. At the end because we need
	 * information from the EC-based extensions and certificate from the SNI
	 * callback triggered by the SNI extension. The server uses its own
	 * preferences over the preference of the client.
	 */
	return ttls_choose_ciphersuite(tls,
				       &tls->hs->tmp[TTLS_HS_TMP_STORE_SZ]);
}

static void
ttls_write_extended_ms_ext(TlsCtx *tls, unsigned char *p, size_t *olen)
{
	if (!tls->hs->extended_ms) {
		*olen = 0;
		return;
	}

	T_DBG("ServerHello: adding extended master secret extension\n");

	*(unsigned short *)p = htons(TTLS_TLS_EXT_EXTENDED_MASTER_SECRET);
	p += 2;
	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
}

static void
ttls_write_session_ticket_ext(TlsCtx *tls, unsigned char *p, size_t *olen)
{
	if (!tls->hs->new_session_ticket) {
		*olen = 0;
		return;
	}

	T_DBG("ServerHello: adding session ticket extension\n");

	*(unsigned short *)p = htons(TTLS_TLS_EXT_SESSION_TICKET);
	p += 2;
	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
}

static void
ttls_write_supported_point_formats_ext(TlsCtx *tls, unsigned char *p,
				       size_t *olen)
{
	if (!tls->hs->cli_exts) {
		*olen = 0;
		return;
	}

	T_DBG("ServerHello: supported_point_formats extension\n");

	*(unsigned short *)p = htons(TTLS_TLS_EXT_SUPPORTED_POINT_FORMATS);
	p += 2;
	*p++ = 0x00;
	*p++ = 2;
	*p++ = 1;
	*p++ = TTLS_ECP_PF_UNCOMPRESSED;

	*olen = 6;
}

static void
ttls_write_alpn_ext(TlsCtx *tls, unsigned char *p, size_t *olen)
{
	if (!tls->alpn_chosen) {
		*olen = 0;
		return;
	}

	T_DBG("ServerHello: adding alpn extension\n");

	/*
	 * 0 . 1	ext identifier
	 * 2 . 3	ext length
	 * 4 . 5	protocol list length
	 * 6 . 6	protocol name length
	 * 7 . 7+n	protocol name
	 */
	*(unsigned short *)p = htons(TTLS_TLS_EXT_ALPN);

	*olen = 7 + strlen(tls->alpn_chosen);

	p[2] = (unsigned char)(((*olen - 4) >> 8) & 0xFF);
	p[3] = (unsigned char)((*olen - 4) & 0xFF);
	p[4] = (unsigned char)(((*olen - 6) >> 8) & 0xFF);
	p[5] = (unsigned char)((*olen - 6) & 0xFF);
	p[6] = (unsigned char)((*olen - 7) & 0xFF);

	memcpy_fast(p + 7, tls->alpn_chosen, *olen - 7);
}

static int
ttls_write_server_hello(TlsCtx *tls, struct sg_table *sgt,
			unsigned char **in_buf)
{
	int r;
	size_t olen, ext_len = 0, n;
	unsigned char *p, *buf = *in_buf;
	TlsIOCtx *io = &tls->io_out;

	/*
	 *	 0  .   0   handshake type
	 *	 1  .   3   handshake length
	 *	 4  .   5   protocol version
	 *	 6  .   9   UNIX time()
	 *	10  .  37   random bytes
	 */
	p = buf + 4;
	ttls_write_version(tls, p);
	p += 2;
	T_DBG("server hello, chosen version %d:%d, buf=%pK\n",
	      buf[4], buf[5], buf);

	*(unsigned int *)p = htonl(get_seconds());
	p += 4;
	get_random_bytes_arch(p, 28);
	p += 28;
	memcpy(tls->hs->randbytes + 32, buf + 6, 32);
	T_DBG3_BUF("server hello, random bytes ", buf + 6, 32);
	/*
	 * Resume is 0  by default.
	 * It may be already set to 1 by ttls_parse_session_ticket_ext().
	 * If not, try looking up session ID in our cache.
	 */
	if (!tls->hs->resume && tls->sess.id_len && tls->conf->f_get_cache
	    && !tls->conf->f_get_cache(tls->conf->p_cache, &tls->sess))
	{
		T_DBG("session successfully restored from cache\n");
		tls->hs->resume = 1;
	}
	if (!tls->hs->resume) {
		/*
		 * New session, create a new session id,
		 * unless we're about to issue a session ticket
		 */
		tls->state = TTLS_SERVER_CERTIFICATE;

		tls->sess.start = get_seconds();

		if (tls->hs->new_session_ticket) {
			tls->sess.id_len = n = 0;
			bzero_fast(tls->sess.id, 32);
		} else {
			tls->sess.id_len = n = 32;
			get_random_bytes_arch(tls->sess.id, 32);
		}
	} else {
		/* Resuming a session. */
		n = tls->sess.id_len;
		WARN_ON_ONCE(n > 32);
		tls->state = TTLS_SERVER_CHANGE_CIPHER_SPEC;

		if ((r = ttls_derive_keys(tls))) {
			T_DBG("ServerHello: cannot derive keys, %d\n", r);
			return r;
		}
	}

	/*
	 *  38  .  38		session id length
	 *  39  . 38+n		session id
	 * 39+n . 40+n		chosen ciphersuite
	 * 41+n . 41+n		chosen compression alg.
	 * 42+n . 43+n		extensions length
	 * 44+n . 43+n+m	extensions
	 */
	*p++ = (unsigned char)tls->sess.id_len;
	memcpy_fast(p, tls->sess.id, tls->sess.id_len);
	p += tls->sess.id_len;

	T_DBG("ServerHello: session id len %lu\n", n);
	T_DBG3_BUF("ServerHello: session id ", buf + 39, n);
	T_DBG("ServerHello: %s session has been resumed\n",
	      tls->hs->resume ? "a" : "no");

	*(unsigned short *)p = htons(tls->sess.ciphersuite);
	p += 2;
	*p++ = 0; /* no compression */
	T_DBG("ServerHello: chosen ciphersuite: %s\n",
	      ttls_get_ciphersuite_name(tls->sess.ciphersuite));

	/*
	 * First write extensions, then the total length.
	 *
	 * RFC 7366: "If a server receives an encrypt-then-MAC request extension
	 * from a client and then selects a stream or Authenticated Encryption
	 * with Associated Data (AEAD) ciphersuite, it MUST NOT send an
	 * encrypt-then-MAC response extension back to the client."
	 * We don't support other siphersuites, so we don't send EtM extension.
	 *
	 * We also don't support renegotiations, so also don't send the
	 * extension.
	 */
	ttls_write_extended_ms_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;
	ttls_write_session_ticket_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;
	ttls_write_supported_point_formats_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;
	ttls_write_alpn_ext(tls, p + 2 + ext_len, &olen);
	ext_len += olen;
	T_DBG("ServerHello: total extension length: %lu\n", ext_len);
	if (ext_len > 0) {
		*(unsigned short *)p = htons(ext_len);
		p += 2 + ext_len;
	}

	io->hslen = 0;
	io->msglen = p - buf;
	io->msgtype = TTLS_MSG_HANDSHAKE;
	io->hstype = TTLS_HS_SERVER_HELLO;
	ttls_write_hshdr(TTLS_HS_SERVER_HELLO, buf, p - buf);
	T_DBG3_BUF("ServerHello: write message ", buf, p - buf);

	*in_buf = p;
	sg_set_page(&sgt->sgl[sgt->nents++], virt_to_page(buf), p - buf,
		    (unsigned long)buf & ~PAGE_MASK);
	get_page(virt_to_page(buf));
	/*
	 * ServerHello is the first record,
	 * so use io->hdr for the record header.
	 */
	__ttls_add_record(tls, sgt, sgt->nents - 1, NULL);

	return 0;
}

static int
ttls_get_ecdh_params_from_cert(TlsCtx *tls)
{
	int r;

	if (!ttls_pk_can_do(ttls_own_key(tls), TTLS_PK_ECKEY)) {
		T_DBG("server key not ECDH capable\n");
		return TTLS_ERR_PK_TYPE_MISMATCH;
	}
	if ((r = ttls_ecdh_get_params(&tls->hs->ecdh_ctx,
				      ttls_pk_ec(*ttls_own_key(tls)),
				      TTLS_ECDH_OURS)))
	{
		T_DBG("cannot get ECDH params from a certificate, %d\n", r);
	}

	return r;
}

static int
ttls_write_server_key_exchange(TlsCtx *tls, struct sg_table *sgt,
			       unsigned char **in_buf)
{
	int r;
	size_t len, n = 0, dig_signed_len = 0;
	const ttls_ciphersuite_t *ci = tls->xfrm.ciphersuite_info;
	TlsIOCtx *io = &tls->io_out;
	unsigned char *dig_signed, *p, *hdr = *in_buf;

	/*
	 * Part 1: Extract static ECDH parameters and abort if
	 * ServerKeyExchange isn't needed.
	 */
	/*
	 * For suites involving ECDH, extract DH parameters from certificate at
	 * this point.
	 */
	if (ttls_ciphersuite_uses_ecdh(ci))
		ttls_get_ecdh_params_from_cert(tls);
	/*
	 * Key exchanges not involving ephemeral keys don't use
	 * ServerKeyExchange, so end here.
	 */
	if (ttls_ciphersuite_no_pfs(ci)) {
		T_DBG("the key exchanges isn't involving ephimeral keys\n");
		return 0;
	}

	/*
	 * Part 2: Provide key exchange parameters for chosen ciphersuite.
	 */
	 /*
	  * TODO estimate size of the message more accurately on configuration
	  * time.
	  */

	p = hdr + TTLS_HDR_LEN + TTLS_HS_HDR_LEN;
	dig_signed = p;

	/* DHE key exchanges. */
	if (ttls_ciphersuite_uses_dhe(ci)) {
		int x_sz;

		if (!tls->conf->dhm_P.p || !tls->conf->dhm_G.p) {
			T_DBG("no DH parameters set\n");
			r = TTLS_ERR_BAD_INPUT_DATA;
			goto err;
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
		r = ttls_dhm_set_group(&tls->hs->dhm_ctx, &tls->conf->dhm_P,
				       &tls->conf->dhm_G);
		if (r) {
			T_DBG("cannot set DHM group, %d\n", r);
			goto err;
		}

		x_sz = (int)ttls_mpi_size(&tls->hs->dhm_ctx.P);
		WARN_ON_ONCE(x_sz > PAGE_SIZE);
		r = ttls_dhm_make_params(&tls->hs->dhm_ctx, x_sz, p, &len);
		if (r) {
			TTLS_DEBUG_RET(1, "ttls_dhm_make_params", r);
			goto err;
		}
		WARN_ON_ONCE(len > 500);
		dig_signed = p;
		dig_signed_len = len;
		p += len;
		n += len;

		TTLS_DEBUG_MPI(3, "DHM: X ", &tls->hs->dhm_ctx.X );
		TTLS_DEBUG_MPI(3, "DHM: P ", &tls->hs->dhm_ctx.P );
		TTLS_DEBUG_MPI(3, "DHM: G ", &tls->hs->dhm_ctx.G );
		TTLS_DEBUG_MPI(3, "DHM: GX", &tls->hs->dhm_ctx.GX);
	}
	/* ECDHE key exchanges. */
	else if (ttls_ciphersuite_uses_ecdhe(ci)) {
		/*
		 * Ephemeral ECDH parameters:
		 *
		 * struct {
		 *	 ECParameters curve_params;
		 *	 ECPoint	  public;
		 * } ServerECDHParams;
		 */
		const ttls_ecp_curve_info **curve = NULL;
		const ttls_ecp_group_id *gid = tls->conf->curve_list;

		/* Match our preference list against the offered curves */
		for ( ; *gid != TTLS_ECP_DP_NONE; gid++)
			for (curve = tls->hs->curves; *curve; curve++)
				if ((*curve)->grp_id == *gid)
					goto curve_matching_done;
curve_matching_done:
		if (!curve || !*curve) {
			T_DBG("no matching curve for ECDHE key exchange\n");
			r = TTLS_ERR_NO_CIPHER_CHOSEN;
			goto err;
		}
		T_DBG("ECDHE curve: %s\n", (*curve)->name);

		r = ttls_ecp_group_load(&tls->hs->ecdh_ctx.grp,
		(*curve)->grp_id);
		if (r) {
			T_DBG("cannot load ECP group, %d\n", r);
			goto err;
		}

		r = ttls_ecdh_make_params(&tls->hs->ecdh_ctx, &len, p,
					  TTLS_MAX_CONTENT_LEN);
		if (r) {
			T_DBG("cannot make ECDH params, %d\n", r);
			goto err;
		}
		WARN_ON_ONCE(len > 500);
		dig_signed = p;
		dig_signed_len = len;
		p += len;
		n += len;

		TTLS_DEBUG_ECP(3, "ECDH: Q ", &tls->hs->ecdh_ctx.Q);
	}

	/*
	 * Part 3: For key exchanges involving the server signing the
	 * exchange parameters, compute and add the signature here.
	 */
	if (ttls_ciphersuite_uses_server_signature(ci)) {
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
		ttls_pk_type_t sig_alg = ttls_get_ciphersuite_sig_pk_alg(ci);
		ttls_md_type_t md_alg;
		md_alg = ttls_sig_hash_set_find(&tls->hs->hash_algs, sig_alg);
		/*
		 * A: For TLS 1.2, obey signature-hash-algorithm extension
		 * (RFC 5246, Sec. 7.4.1.4.1).
		 */
		WARN_ON_ONCE(sig_alg == TTLS_PK_NONE || md_alg == TTLS_MD_NONE);
		T_DBG("pick hash algorithm %d for signing\n", md_alg);
		/*
		 * 3.2: Compute the hash to be signed
		 */
		if (md_alg != TTLS_MD_NONE) {
			/* Info from md_alg will be used instead */
			hashlen = 0;
			r = ttls_get_key_exchange_md_tls1_2(tls, hash,
							    dig_signed,
							    dig_signed_len,
							    md_alg);
			if (r)
				goto err;
		} else {
			r = TTLS_ERR_INTERNAL_ERROR;
			goto err;
		}
		T_DBG3_BUF("parameters hash ", hash,
			   hashlen
			   ? : ttls_md_get_size(ttls_md_info_from_type(md_alg)));

		/* 3.3: Compute and add the signature */
		if (!ttls_own_key(tls)) {
			T_DBG("got no private key\n");
			r = TTLS_ERR_PRIVATE_KEY_REQUIRED;
			goto err;
		}
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
		*(p++) = ttls_hash_from_md_alg(md_alg);
		*(p++) = ttls_sig_from_pk_alg(sig_alg);
		n += 2;

		r = ttls_pk_sign(ttls_own_key(tls), md_alg, hash, hashlen,
				 p + 2, &signature_len);
		if (r) {
			T_DBG("cannot sign the digest, %d\n", r);
			goto err;
		}
		*(p++) = (unsigned char)(signature_len >> 8);
		*(p++) = (unsigned char)(signature_len);
		n += 2;

		T_DBG3_BUF("my signature ", p, signature_len);
		n += signature_len;
		WARN_ON_ONCE(signature_len > 500);
	}

	/* Done with actual work; add handshake header and add the record. */
	WARN_ON_ONCE(n > 1015);
	io->msglen = TTLS_HS_HDR_LEN + n;
	ttls_write_hshdr(TTLS_HS_SERVER_KEY_EXCHANGE, hdr + TTLS_HDR_LEN,
			 TTLS_HS_HDR_LEN + n);

	*in_buf = hdr + TTLS_HDR_LEN + TTLS_HS_HDR_LEN + n;
	sg_set_page(&sgt->sgl[sgt->nents++], virt_to_page(hdr),
		    TTLS_HDR_LEN + TTLS_HS_HDR_LEN + n,
		    (unsigned long)hdr & ~PAGE_MASK);
	get_page(virt_to_page(hdr));
	__ttls_add_record(tls, sgt, sgt->nents - 1, hdr);

	return 0;
err:
	put_page(virt_to_page(hdr));
	return r;
}

static int
ttls_write_certificate_request(TlsCtx *tls, struct sg_table *sgt,
			       unsigned char **in_buf)
{
	TlsIOCtx *io = &tls->io_out;
	size_t dn_size, total_dn_size; /* excluding length bytes */
	size_t ct_len, sa_len; /* including length bytes */
	size_t hdr_len = TTLS_HDR_LEN + 4;
	unsigned char *buf = *in_buf, *p, *end;
	const int *cur;
	const ttls_x509_crt *crt;
	int authmode;

	if (tls->hs->sni_authmode != TTLS_VERIFY_UNSET)
		authmode = tls->hs->sni_authmode;
	else
		authmode = tls->conf->authmode;

	/*
	 * TODO estimate size of the message more accurately on configuration
	 * time.
	 *
	 * At least this message, but probably some more, can be assembled on
	 * configuration time and just serialized to the TCP/IP stack.
	 * #391 addresses skb templates (as the Sandstorm), so it should be used
	 * as well.
	 */
	if (tls->conf->cert_req_ca_list) {
		T_WARN("List of acceptable CAs isn't supported"
		       " (reference issue #830)\n");
		return -EINVAL;
	}
	end = buf + 128;

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
	p = buf + hdr_len;

	/*
	 * Supported certificate types
	 *
	 *	 ClientCertificateType certificate_types<1..2^8-1>;
	 *	 enum { (255) } ClientCertificateType;
	 */
	ct_len = 0;
	p[1 + ct_len++] = TTLS_CERT_TYPE_RSA_SIGN;
	p[1 + ct_len++] = TTLS_CERT_TYPE_ECDSA_SIGN;
	p[0] = (unsigned char)ct_len++;
	p += ct_len;

	sa_len = 0;
	/*
	 * Add signature_algorithms for verify (TLS 1.2)
	 *
	 *  SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>;
	 *
	 *  struct {
	 *	HashAlgorithm hash;
	 *	SignatureAlgorithm signature;
	 *  } SignatureAndHashAlgorithm;
	 *
	 *  enum { (255) } HashAlgorithm;
	 *  enum { (255) } SignatureAlgorithm;
	 */
	/* Supported signature algorithms. */
	for (cur = tls->conf->sig_hashes; *cur != TTLS_MD_NONE; cur++) {
		unsigned char hash = ttls_hash_from_md_alg(*cur);

		if (TTLS_HASH_NONE == hash
		    || ttls_set_calc_verify_md(tls, hash))
			continue;

		p[2 + sa_len++] = hash;
		p[2 + sa_len++] = TTLS_SIG_RSA;
		p[2 + sa_len++] = hash;
		p[2 + sa_len++] = TTLS_SIG_ECDSA;
	}

	p[0] = (unsigned char)(sa_len >> 8);
	p[1] = (unsigned char)sa_len;
	sa_len += 2;
	p += sa_len;

	/*
	 * DistinguishedName certificate_authorities<0..2^16-1>;
	 * opaque DistinguishedName<1..2^16-1>;
	 */
	p += 2;
	total_dn_size = 0;

	if (tls->conf->cert_req_ca_list) {
		if (tls->hs->sni_ca_chain)
			crt = tls->hs->sni_ca_chain;
		else
			crt = tls->conf->ca_chain;

		while (crt && crt->version) {
			dn_size = crt->subject_raw.len;

			if (end < p || (size_t)(end - p) < dn_size
			    || (size_t)(end - p) < 2 + dn_size)
			{
				T_DBG("skipping CAs: buffer too short\n");
				break;
			}

			*p++ = (unsigned char)(dn_size >> 8);
			*p++ = (unsigned char)dn_size;
			memcpy_fast(p, crt->subject_raw.p, dn_size);
			p += dn_size;

			T_DBG3_BUF("requested DN ", p - dn_size, dn_size);

			total_dn_size += 2 + dn_size;
			crt = crt->next;
		}
	}

	BUG_ON(!tls->conf->cert_req_ca_list && p - buf > 128);
	io->msglen = p - buf - TTLS_HDR_LEN;
	buf[hdr_len + ct_len + sa_len] = (unsigned char)(total_dn_size >> 8);
	buf[hdr_len + 1 + ct_len + sa_len] = (unsigned char)total_dn_size;
	ttls_write_hshdr(TTLS_HS_CERTIFICATE_REQUEST, buf + TTLS_HDR_LEN,
			 io->msglen);

	*in_buf = p;
	sg_set_page(&sgt->sgl[sgt->nents++], virt_to_page(buf), p - buf,
		    (unsigned long)buf & ~PAGE_MASK);
	get_page(virt_to_page(buf));
	__ttls_add_record(tls, sgt, sgt->nents - 1, buf);

	return 0;
}

static int
ttls_write_server_hello_done(TlsCtx *tls, struct sg_table *sgt,
			     unsigned char **in_buf)
{
	TlsIOCtx *io = &tls->io_out;
	unsigned char *p = *in_buf;

	T_DBG("sending ServerHelloDone\n");

	io->msglen = TTLS_HS_HDR_LEN;
	ttls_write_hshdr(TTLS_HS_SERVER_HELLO_DONE, p + TTLS_HDR_LEN,
			 TTLS_HS_HDR_LEN);

	*in_buf += TTLS_HDR_LEN + TTLS_HS_HDR_LEN;
	sg_set_page(&sgt->sgl[sgt->nents++], virt_to_page(p), *in_buf - p,
		    (unsigned long)p & ~PAGE_MASK);
	get_page(virt_to_page(p));

	__ttls_add_record(tls, sgt, sgt->nents - 1, p);

	return 0;
}

static int
ttls_parse_client_dh_public(TlsCtx *tls, unsigned char **p,
			    const unsigned char *end)
{
	int r = TTLS_ERR_FEATURE_UNAVAILABLE;
	size_t n;

	/* Receive G^Y mod P, premaster = (G^Y)^X mod P. */
	if (*p + 2 > end) {
		T_DBG("bad client dh key exchange message\n");
		return TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE;
	}

	n = ((*p)[0] << 8) | (*p)[1];
	*p += 2;

	if (*p + n > end) {
		T_DBG("bad client key exchange message\n");
		return TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE;
	}

	if ((r = ttls_dhm_read_public(&tls->hs->dhm_ctx, *p, n))) {
		T_DBG("cannot read dhm public, %d\n", r);
		return TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_RP;
	}

	*p += n;

	TTLS_DEBUG_MPI(3, "DHM: GY", &tls->hs->dhm_ctx.GY);

	return r;
}

static int
ttls_parse_encrypted_pms(TlsCtx *tls, const unsigned char *p,
			 const unsigned char *end)
{
	unsigned char mask;
	int r;
	unsigned int diff;
	size_t len = ttls_pk_get_len(ttls_own_key(tls));
	size_t i, peer_pmslen;
	unsigned char *pms = tls->hs->premaster;
	unsigned char ver[2], fake_pms[48], peer_pms[48];

	BUILD_BUG_ON(sizeof(tls->hs->premaster) < 0
		     || sizeof(tls->hs->premaster) < 48);
	if (!ttls_pk_can_do(ttls_own_key(tls), TTLS_PK_RSA)) {
		T_DBG("got no RSA private key\n");
		return TTLS_ERR_PRIVATE_KEY_REQUIRED;
	}

	/* Decrypt the premaster using own private RSA key. */
	if (*p++ != ((len >> 8) & 0xFF) || *p++ != (len & 0xFF)
	    || p + len != end)
	{
		T_DBG("bad client key exchange message\n");
		return TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE;
	}

	ver[0] = TTLS_MAX_MAJOR_VERSION;
	ver[1] = tls->conf->max_minor_ver;

	/*
	 * Protection against Bleichenbacher's attack: invalid PKCS#1 v1.5
	 * padding must not cause the connection to end immediately; instead,
	 * send a bad_record_mac later in the handshake.
	 * Also, avoid data-dependant branches here to protect against
	 * timing-based variants.
	 */
	get_random_bytes_arch(fake_pms, sizeof(fake_pms));

	r = ttls_pk_decrypt(ttls_own_key(tls), p, len, peer_pms, &peer_pmslen,
			    sizeof(peer_pms));

	diff  = (unsigned int) r;
	diff |= peer_pmslen ^ 48;
	diff |= peer_pms[0] ^ ver[0];
	diff |= peer_pms[1] ^ ver[1];
	T_DBG("client key exchange message diff=%x\n", diff);

	tls->hs->pmslen = 48;
	/* mask = diff ? 0xff : 0x00 using bit operations to avoid branches */
	mask = - ((diff | - diff) >> (sizeof(unsigned int) * 8 - 1));
	for (i = 0; i < tls->hs->pmslen; i++)
		pms[i] = (mask & fake_pms[i]) | ((~mask) & peer_pms[i]);

	return 0;
}

static int
ttls_parse_client_key_exchange(TlsCtx *tls, unsigned char *buf, size_t len,
			       unsigned int *read)
{
	int r;
	const ttls_ciphersuite_t *ci = tls->xfrm.ciphersuite_info;
	unsigned char *p, *end;
	TlsIOCtx *io = &tls->io_in;

	BUG_ON(io->msgtype != TTLS_MSG_HANDSHAKE);
	if (io->hstype != TTLS_HS_CLIENT_KEY_EXCHANGE) {
		T_DBG("bad client key exchange message type, %u\n", io->hstype);
		return TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE;
	}

	/*
	 * TODO avoid copies even for chunked data. This requires deep
	 * MPI modifications, so leave the warning for now.
	 */
	if (io->rlen + len < io->hslen) {
		T_WARN("chunked key - fall back to copy (total length"
		       " %u, shunk length %lu, max copy %lu)\n",
		       io->hslen, len, TTLS_HS_RBUF_SZ);
		if (io->hslen > TTLS_HS_RBUF_SZ)
			return TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE;
		memcpy_fast(&tls->hs->tmp[io->rlen], buf, len);
		*read += len;
		io->rlen += len;
		return T_POSTPONE;
	}
	else if (io->rlen) {
		len = io->hslen - io->rlen;
		memcpy_fast(&tls->hs->tmp[io->rlen], buf, len);
		*read += len;
		io->rlen += len;
		p = tls->hs->tmp;
		end = p + io->hslen;
	}
	else {
		p = buf;
		end = p + io->hslen;
		*read += end - p;
	}

	if (ci->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_ECDSA
	    || ci->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_RSA
	    || ci->key_exchange == TTLS_KEY_EXCHANGE_ECDH_RSA
	    || ci->key_exchange == TTLS_KEY_EXCHANGE_ECDH_ECDSA)
	{
		r = ttls_ecdh_read_public(&tls->hs->ecdh_ctx, p, end - p);
		if (r) {
			T_DBG("cannot read ecdh public, %d\n", r);
			return TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_RP;
		}
		TTLS_DEBUG_ECP(3, "ECDH: Qp ", &tls->hs->ecdh_ctx.Qp);

		r = ttls_ecdh_calc_secret(&tls->hs->ecdh_ctx, &tls->hs->pmslen,
					  tls->hs->premaster,
					  TTLS_MPI_MAX_SIZE);
		if (r) {
			T_DBG("cannot calculate ecdh secret, %d\n", r);
			return TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_CS;
		}
		TTLS_DEBUG_MPI(3, "ECDH: z  ", &tls->hs->ecdh_ctx.z);
	}
	else if (ci->key_exchange == TTLS_KEY_EXCHANGE_DHE_RSA) {
		if ((r = ttls_parse_client_dh_public(tls, &p, end))) {
			T_DBG("cannot read dh public, %d\n", r);
			return r;
		}
		if (p != end) {
			T_DBG("bad client key exchange - to short dh public\n");
			return TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE;
		}

		r = ttls_dhm_calc_secret(&tls->hs->dhm_ctx, tls->hs->premaster,
					 TTLS_PREMASTER_SIZE, &tls->hs->pmslen);
		if (r) {
			T_DBG("cannot calculate dhm secret, %d\n", r);
			return TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_CS;
		}
		TTLS_DEBUG_MPI(3, "DHM: K ", &tls->hs->dhm_ctx.K );
	}
	else if (ci->key_exchange == TTLS_KEY_EXCHANGE_RSA) {
		if ((r = ttls_parse_encrypted_pms(tls, p, end))) {
			T_DBG("cannot parse pms, %d\n", r);
			return r;
		}
	}
	else {
		T_WARN("bad key exchange %d\n", ci->key_exchange);
		return TTLS_ERR_INTERNAL_ERROR;
	}

	if ((r = ttls_derive_keys(tls)))
		T_DBG("KeyExchange: cannot derive keys, %d\n", r);

	return r;
}

static int
ttls_parse_certificate_verify(TlsCtx *tls, unsigned char *buf, size_t len,
			      unsigned int *read)
{
	int r = TTLS_ERR_FEATURE_UNAVAILABLE;
	size_t i = 0, sig_len, hashlen;
	unsigned char hash[48], *hash_start = hash;
	ttls_pk_type_t pk_alg;
	ttls_md_type_t md_alg;
	TlsIOCtx *io = &tls->io_in;

	BUG_ON(io->msgtype != TTLS_MSG_HANDSHAKE);
	if (io->hstype != TTLS_HS_CERTIFICATE_VERIFY) {
		T_DBG("bad certificate verify message\n");
		return TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY;
	}

	/*
	 * Process the message contents.
	 * TODO #830: This function is actually never called before, so just
	 * ignore chunked data for now.
	 */
	if (io->hslen > len) {
		T_WARN("certificate verify with chunked data\n");
		return TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY;
	}

	/*
	 *  struct {
	 *	 SignatureAndHashAlgorithm algorithm; -- TLS 1.2 only
	 *	 opaque signature<0..2^16-1>;
	 *  } DigitallySigned;
	 */
	if (i + 2 > io->hslen) {
		T_DBG("bad certificate verify message\n");
		return TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY;
	}

	/* Hash.*/
	md_alg = ttls_md_alg_from_hash(buf[i]);
	if (md_alg == TTLS_MD_NONE || ttls_set_calc_verify_md(tls, buf[i])) {
		T_DBG("peer not adhering to requested sig_alg for verify"
		      " message\n");
		return TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY;
	}
	if (TTLS_MD_SHA1 == md_alg)
		hash_start += 16;
	/* Info from md_alg will be used instead */
	hashlen = 0;
	i++;

	/* Signature. */
	if ((pk_alg = ttls_pk_alg_from_sig(buf[i])) == TTLS_PK_NONE) {
		T_DBG("peer not adhering to requested sig_alg for verify"
		      " message\n");
		return TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY;
	}
	/* Check the certificate's key type matches the signature alg. */
	if (!ttls_pk_can_do(&tls->sess.peer_cert->pk, pk_alg)) {
		T_DBG("sig_alg doesn't match cert key\n");
		return TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY;
	}
	i++;

	if (i + 2 > io->hslen) {
		T_DBG("bad certificate verify message\n");
		return TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY;
	}

	sig_len = (buf[i] << 8) | buf[i + 1];
	i += 2;

	if (i + sig_len != io->hslen) {
		T_DBG("bad certificate verify message\n");
		return TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY;
	}

	/* Calculate hash and verify signature */
	tls->hs->calc_verify(tls, hash);

	r = ttls_pk_verify(&tls->sess.peer_cert->pk, md_alg,
			   hash_start, hashlen, buf + i, sig_len);
	if (r)
		T_DBG("cannot verify pk, %d\n", r);

	*read += i + sig_len;

	return r;
}

static int
ttls_write_new_session_ticket(TlsCtx *tls, struct sg_table *sgt,
			      unsigned char **in_buf)
{
	int r;
	size_t tlen;
	uint32_t lifetime;
	unsigned char *p = *in_buf;
	TlsIOCtx *io = &tls->io_out;

	/*
	 * TODO estimate size of the message more accurately on configuration
	 * time.
	 */

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
	r = tls->conf->f_ticket_write(tls->conf->p_ticket, &tls->sess, p + 10,
				      p + TTLS_MAX_CONTENT_LEN, &tlen,
				      &lifetime);
	if (r) {
		T_DBG("cannot write session ticket, %d\n", r);
		tlen = 0;
	}
	WARN_ON_ONCE(tlen > 502);

	p[4] = (lifetime >> 24) & 0xFF;
	p[5] = (lifetime >> 16) & 0xFF;
	p[6] = (lifetime >>  8) & 0xFF;
	p[7] = lifetime & 0xFF;
	p[8] = (unsigned char)((tlen >> 8) & 0xFF);
	p[9] = (unsigned char)(tlen & 0xFF);

	io->hslen = 0;
	io->msglen = 10 + tlen + TTLS_HS_HDR_LEN;
	io->msgtype = TTLS_MSG_HANDSHAKE;
	io->hstype = TTLS_HS_NEW_SESSION_TICKET;
	ttls_write_hshdr(TTLS_HS_NEW_SESSION_TICKET, p, 10 + tlen);

	/*
	 * Morally equivalent to updating tls->state, but NewSessionTicket and
	 * ChangeCipherSpec share the same state.
	 */
	tls->hs->new_session_ticket = 0;

	*in_buf = p + 10 + tlen;
	sg_set_buf(&sgt->sgl[sgt->nents++], p, 10 + tlen);
	get_page(virt_to_page(p));
	__ttls_add_record(tls, sgt, sgt->nents - 1, NULL);

	return 0;
}

#define CHECK_STATE(n)							\
do {									\
	WARN_ON_ONCE(p - begin > n);					\
	if (sgt.nents >= MAX_SKB_FRAGS) {				\
		T_WARN("too many frags on ServerHello\n");		\
		r = -ENOMEM;						\
		T_FSM_EXIT();						\
	}								\
	begin = p;							\
} while (0)

/**
 * Write all the handshake messages on ServerHello state at once.
 */
static int
ttls_handshake_server_hello(TlsCtx *tls)
{
	int r = 0;
	unsigned char *p, *begin;
	struct scatterlist sg[MAX_SKB_FRAGS] = {};
	struct sg_table sgt = { .sgl = sg };
	struct page *pg;
	T_FSM_INIT(tls->state, "TLS Server Handshake (ServerHello)");

	begin = p = pg_skb_alloc(2048, GFP_ATOMIC, NUMA_NO_NODE);
	if (!p)
		return -ENOMEM;
	pg = virt_to_page(p);

	T_FSM_START(ttls_state(tls)) {
	T_FSM_STATE(TTLS_SERVER_HELLO) {
		if ((r = ttls_write_server_hello(tls, &sgt, &p)))
			T_FSM_EXIT();
		CHECK_STATE(128);
		T_FSM_NEXT();
	}
	T_FSM_STATE(TTLS_SERVER_CERTIFICATE) {
		if ((r = ttls_write_certificate(tls, &sgt, &p)))
			T_FSM_EXIT();
		CHECK_STATE(128);
		T_FSM_JMP(TTLS_SERVER_KEY_EXCHANGE);
	}
	T_FSM_STATE(TTLS_SERVER_KEY_EXCHANGE) {
		if ((r = ttls_write_server_key_exchange(tls, &sgt, &p)))
			T_FSM_EXIT();
		CHECK_STATE(1024);
		/*
		 * RFC 5246 Certificate Request is optional, so don't requiest
		 * a certificate for now since we're unable to properly verify
		 * it certificate until #830.
		 */
		T_FSM_JMP(TTLS_SERVER_HELLO_DONE);
	}
	T_FSM_STATE(TTLS_CERTIFICATE_REQUEST) {
		if ((r = ttls_write_certificate_request(tls, &sgt, &p)))
			T_FSM_EXIT();
		CHECK_STATE(128);
		T_FSM_JMP(TTLS_SERVER_HELLO_DONE);
	}
	T_FSM_STATE(TTLS_SERVER_HELLO_DONE) {
		const ttls_ciphersuite_t *ci = tls->xfrm.ciphersuite_info;

		if ((r = ttls_write_server_hello_done(tls, &sgt, &p)))
			return r;
		CHECK_STATE(9);
		if (ci->key_exchange == TTLS_KEY_EXCHANGE_PSK
		    || ci->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK
		    || ci->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK
		    || ci->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK
		    || (tls->hs->sni_authmode == TTLS_VERIFY_UNSET
			&& tls->conf->authmode == TTLS_VERIFY_NONE)
		    || tls->hs->sni_authmode == TTLS_VERIFY_NONE)
		{
			/* Default and the only option at least before #830. */
			tls->sess.verify_result = TTLS_X509_BADCERT_SKIP_VERIFY;
			tls->state = TTLS_CLIENT_KEY_EXCHANGE;
		} else {
			tls->state = TTLS_CLIENT_CERTIFICATE;
		}
		/* All the writers getted their frags, so put our reference. */
		put_page(pg);
		sg_mark_end(&sgt.sgl[sgt.nents - 1]);
		/* Exit, enter the FSM on more data from the client. */
		return __ttls_send_record(tls, &sgt);
	}
	}
	T_FSM_FINISH(r, tls->state);

	/* If we exit here, then something went wrong. */
	BUG_ON(!r);
	while (--sgt.nents > (unsigned int)-1)
		put_page(sg_page(&sg[sgt.nents]));
	put_page(pg);

	return r;
}

/**
 * Write all the handshake messages starting from TTLS_SERVER_CHANGE_CIPHER_SPEC
 * state at once.
 */
static int
ttls_handshake_finished(TlsCtx *tls)
{
	int r;
	unsigned char *p, *begin;
	struct page *pg;
	struct scatterlist sg[MAX_SKB_FRAGS] = {};
	struct sg_table sgt = { .sgl = sg };
	T_FSM_INIT(tls->state, "TLS Server Handshake (Finish)");

	begin = p = pg_skb_alloc(1024, GFP_ATOMIC, NUMA_NO_NODE);
	if (!p)
		return -ENOMEM;
	pg = virt_to_page(p);

	T_FSM_START(ttls_state(tls)) {
	T_FSM_STATE(TTLS_SERVER_CHANGE_CIPHER_SPEC) {
		if (tls->hs->new_session_ticket) {
			r = ttls_write_new_session_ticket(tls, &sgt, &p);
			CHECK_STATE(512);
		} else {
			r = ttls_write_change_cipher_spec(tls, &sgt, &p);
			tls->state = TTLS_SERVER_FINISHED;
		}
		if (r)
			T_FSM_EXIT();
		T_FSM_NEXT();
	}
	T_FSM_STATE(TTLS_SERVER_FINISHED) {
		if ((r = ttls_write_finished(tls, &sgt, &p)))
			return r;
		CHECK_STATE(21);
		/*
		 * In case of session resuming, invert the client and server
		 * ChangeCipherSpec messages order.
		 */
		tls->state = tls->hs->resume
			     ? TTLS_CLIENT_CHANGE_CIPHER_SPEC
			     : TTLS_HANDSHAKE_WRAPUP;
		sg_mark_end(&sgt.sgl[sgt.nents - 1]);
		return __ttls_send_record(tls, &sgt);
	}
	}
	T_FSM_FINISH(r, tls->state);

	/* If we exit here, then something went wring. */
	BUG_ON(!r);
	while (--sgt.nents > (unsigned int)-1)
		put_page(sg_page(&sg[sgt.nents]));
	put_page(pg);

	return r;
}

/**
 * TLS handshake -- server side -- single step.
 */
int
ttls_handshake_server_step(TlsCtx *tls, unsigned char *buf, size_t len,
			   unsigned int *read)
{
	int r = 0;
	T_FSM_INIT(tls->state, "TLS Server Handshake");

	T_DBG("server state: %x\n", tls->state);
	BUG_ON(tls->conf->endpoint != TTLS_IS_SERVER);
	BUG_ON(tls->state == TTLS_HANDSHAKE_OVER || !tls->hs);

	T_FSM_START(ttls_state(tls)) {

	/*
	 * The following states work on one shot when a ClientHello
	 * received.
	 *
	 *  <==   ClientHello
	 */
	T_FSM_STATE(TTLS_CLIENT_HELLO) {
		if ((r = ttls_parse_client_hello(tls, buf, len, read)))
			return r;
		tls->state = TTLS_SERVER_HELLO;
		/* fall through */
	}
	/*
	 *  ==>   ServerHello
	 *	  Certificate
	 *	  (ServerKeyExchange )
	 *	  (CertificateRequest)
	 *	  ServerHelloDone
	 */
	T_FSM_STATE(TTLS_SERVER_HELLO) {
		return ttls_handshake_server_hello(tls);
	}
	T_FSM_STATE(TTLS_SERVER_CERTIFICATE)
	T_FSM_STATE(TTLS_SERVER_KEY_EXCHANGE)
	T_FSM_STATE(TTLS_CERTIFICATE_REQUEST)
	T_FSM_STATE(TTLS_SERVER_HELLO_DONE) {
		BUG(); /* must be handled in ttls_handshake_server_hello() */
	}

	/*
	 *  <==   (Certificate/Alert )
	 *	  ClientKeyExchange
	 *	  (CertificateVerify )
	 *	  ChangeCipherSpec
	 *	  Finished
	 */
	T_FSM_STATE(TTLS_CLIENT_CERTIFICATE) {
		if ((r = ttls_parse_certificate(tls, buf, len, read)))
			return r;
		tls->state = TTLS_CLIENT_KEY_EXCHANGE;
		return T_OK;
	}
	T_FSM_STATE(TTLS_CLIENT_KEY_EXCHANGE) {
		const ttls_ciphersuite_t *ci = tls->xfrm.ciphersuite_info;

		if ((r = ttls_parse_client_key_exchange(tls, buf, len, read)))
			return r;
		if (!tls->sess.peer_cert
		    || ci->key_exchange == TTLS_KEY_EXCHANGE_PSK
		    || ci->key_exchange == TTLS_KEY_EXCHANGE_RSA_PSK
		    || ci->key_exchange == TTLS_KEY_EXCHANGE_ECDHE_PSK
		    || ci->key_exchange == TTLS_KEY_EXCHANGE_DHE_PSK)
		{
			T_DBG("skip parse certificate verify\n");
			tls->state = TTLS_CLIENT_CHANGE_CIPHER_SPEC;
		} else {
			tls->state = TTLS_CERTIFICATE_VERIFY;
		}
		return T_OK;
	}
	T_FSM_STATE(TTLS_CERTIFICATE_VERIFY) {
		if ((r = ttls_parse_certificate_verify(tls, buf, len, read)))
			return r;
		tls->state = TTLS_CLIENT_CHANGE_CIPHER_SPEC;
		return T_OK;
	}
	T_FSM_STATE(TTLS_CLIENT_CHANGE_CIPHER_SPEC) {
		if ((r = ttls_parse_change_cipher_spec(tls, buf, len, read)))
			return r;
		tls->state = TTLS_CLIENT_FINISHED;
		return T_OK;
	}
	T_FSM_STATE(TTLS_CLIENT_FINISHED) {
		if ((r = ttls_parse_finished(tls, buf, len, read)))
			return r;
		tls->state = tls->hs->resume
			     ? TTLS_HANDSHAKE_WRAPUP
			     : TTLS_SERVER_CHANGE_CIPHER_SPEC;
		T_FSM_NEXT();
	}

	/*
	 *  ==>   (NewSessionTicket)
	 *	  ChangeCipherSpec
	 *	  Finished
	 */
	T_FSM_STATE(TTLS_SERVER_CHANGE_CIPHER_SPEC) {
		if ((r = ttls_handshake_finished(tls)))
			return r;
		T_FSM_NEXT();
	}
	T_FSM_STATE(TTLS_SERVER_FINISHED) {
		BUG(); /* must be handled in ttls_handshake_finished() */
	}

	T_FSM_STATE(TTLS_HANDSHAKE_WRAPUP) {
		ttls_handshake_wrapup(tls);
		tls->state = TTLS_HANDSHAKE_OVER;
	}
	T_FSM_STATE(TTLS_HANDSHAKE_OVER) {
		WARN_ON_ONCE(r);
		T_FSM_EXIT();
	}

	}
	T_FSM_FINISH(r, tls->state);

	return r;
}
