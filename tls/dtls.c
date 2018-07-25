/*
 *		Tempesta TLS
 *
 * DTLS specific routines.
 *
 * TODO DTLS isn't ported to Synchronous sockets and completely broken now,
 * we don't need it for now and don't compile it. However, it seems required
 * for QUIC, at least handshakes part since the kernel is going to implement
 * the rest.
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
#if defined(TTLS_PROTO_DTLS)

/*
 * Double the retransmit timeout value, within the allowed range,
 * returning -1 if the maximum value has already been reached.
 */
static int ssl_double_retransmit_timeout(ttls_context *tls)
{
	uint32_t new_timeout;

	if (tls->handshake->retransmit_timeout >= tls->conf->hs_timeout_max)
		return(-1);

	new_timeout = 2 * tls->handshake->retransmit_timeout;

	/* Avoid arithmetic overflow and range overflow */
	if (new_timeout < tls->handshake->retransmit_timeout ||
		new_timeout > tls->conf->hs_timeout_max)
	{
		new_timeout = tls->conf->hs_timeout_max;
	}

	tls->handshake->retransmit_timeout = new_timeout;
	TTLS_DEBUG_MSG(3, ("update timeout value to %d millisecs",
				tls->handshake->retransmit_timeout));

	return 0;
}

static void ssl_reset_retransmit_timeout(ttls_context *tls)
{
	tls->handshake->retransmit_timeout = tls->conf->hs_timeout_min;
	TTLS_DEBUG_MSG(3, ("update timeout value to %d millisecs",
				tls->handshake->retransmit_timeout));
}

/*
 * ------------------------------------------------------------------------
 * Functions to handle the DTLS retransmission state machine
 * ------------------------------------------------------------------------
 */
/*
 * Append current handshake message to current outgoing flight
 */
static int ssl_flight_append(ttls_context *tls)
{
	ttls_flight_item *msg;

	/* Allocate space for current message */
	if ((msg = ttls_calloc(1, sizeof( ttls_flight_item))) == NULL)
	{
		TTLS_DEBUG_MSG(1, ("alloc %d bytes failed",
			sizeof(ttls_flight_item)));
		return(TTLS_ERR_ALLOC_FAILED);
	}

	if ((msg->p = ttls_calloc(1, tls->out_msglen)) == NULL)
	{
		TTLS_DEBUG_MSG(1, ("alloc %d bytes failed", tls->out_msglen));
		ttls_free(msg);
		return(TTLS_ERR_ALLOC_FAILED);
	}

	/* Copy current handshake message with headers */
	memcpy(msg->p, tls->out_msg, tls->out_msglen);
	msg->len = tls->out_msglen;
	msg->type = tls->out_msgtype;
	msg->next = NULL;

	/* Append to the current flight */
	if (tls->handshake->flight == NULL)
		tls->handshake->flight = msg;
	else
	{
		ttls_flight_item *cur = tls->handshake->flight;
		while (cur->next != NULL)
			cur = cur->next;
		cur->next = msg;
	}

	return 0;
}

/*
 * Free the current flight of handshake messages
 */
static void ssl_flight_free(ttls_flight_item *flight)
{
	ttls_flight_item *cur = flight;
	ttls_flight_item *next;

	while (cur != NULL)
	{
		next = cur->next;

		ttls_free(cur->p);
		ttls_free(cur);

		cur = next;
	}
}

#if defined(TTLS_DTLS_ANTI_REPLAY)
static void ssl_dtls_replay_reset(ttls_context *tls);
#endif

/*
 * Swap transform_out and out_ctr with the alternative ones
 */
static void ssl_swap_epochs(ttls_context *tls)
{
	ttls_transform *tmp_transform;
	unsigned char tmp_out_ctr[8];

	if (tls->transform_out == tls->handshake->alt_transform_out)
	{
		TTLS_DEBUG_MSG(3, ("skip swap epochs"));
		return;
	}

	TTLS_DEBUG_MSG(3, ("swap epochs"));

	/* Swap transforms */
	tmp_transform	 = tls->transform_out;
	tls->transform_out = tls->handshake->alt_transform_out;
	tls->handshake->alt_transform_out = tmp_transform;

	/* Swap epoch + sequence_number */
	memcpy(tmp_out_ctr, tls->out_ctr, 8);
	memcpy(tls->out_ctr, tls->handshake->alt_out_ctr, 8);
	memcpy(tls->handshake->alt_out_ctr, tmp_out_ctr, 8);

	/* Adjust to the newly activated transform */
	if (tls->transform_out != NULL &&
		tls->minor_ver >= TTLS_MINOR_VERSION_2)
	{
		tls->out_msg = tls->out_iv + tls->transform_out->ivlen -
					 tls->transform_out->fixed_ivlen;
	}
	else
		tls->out_msg = tls->out_iv;
}

/*
 * Retransmit the current flight of messages.
 *
 * Need to remember the current message in case flush_output returns
 * WANT_WRITE, causing us to exit this function and come back later.
 * This function must be called until state is no longer SENDING.
 */
int ttls_resend(ttls_context *tls)
{
	TTLS_DEBUG_MSG(2, ("=> ttls_resend"));

	if (tls->handshake->retransmit_state != TTLS_RETRANS_SENDING)
	{
		TTLS_DEBUG_MSG(2, ("initialise resending"));

		tls->handshake->cur_msg = tls->handshake->flight;
		ssl_swap_epochs(tls);

		tls->handshake->retransmit_state = TTLS_RETRANS_SENDING;
	}

	while (tls->handshake->cur_msg != NULL)
	{
		int r;
		ttls_flight_item *cur = tls->handshake->cur_msg;

		/* Swap epochs before sending Finished: we can't do it after
		 * sending ChangeCipherSpec, in case write returns WANT_READ.
		 * Must be done before copying, may change out_msg pointer */
		if (cur->type == TTLS_MSG_HANDSHAKE &&
			cur->p[0] == TTLS_HS_FINISHED)
		{
			ssl_swap_epochs(tls);
		}

		memcpy(tls->out_msg, cur->p, cur->len);
		tls->out_msglen = cur->len;
		tls->out_msgtype = cur->type;

		tls->handshake->cur_msg = cur->next;

		TTLS_DEBUG_BUF(3, "resent handshake message header", tls->out_msg, 12);

		if ((r = ttls_write_record(tls)) != 0)
		{
			TTLS_DEBUG_RET(1, "ttls_write_record", r);
			return r;
		}
	}

	if (tls->state == TTLS_HANDSHAKE_OVER)
		tls->handshake->retransmit_state = TTLS_RETRANS_FINISHED;
	else
	{
		tls->handshake->retransmit_state = TTLS_RETRANS_WAITING;
		ssl_set_timer(tls, tls->handshake->retransmit_timeout);
	}

	TTLS_DEBUG_MSG(2, ("<= ttls_resend"));

	return 0;
}

/*
 * To be called when the last message of an incoming flight is received.
 */
void ttls_recv_flight_completed(ttls_context *tls)
{
	/* We won't need to resend that one any more */
	ssl_flight_free(tls->handshake->flight);
	tls->handshake->flight = NULL;
	tls->handshake->cur_msg = NULL;

	/* The next incoming flight will start with this msg_seq */
	tls->handshake->in_flight_start_seq = tls->handshake->in_msg_seq;

	/* Cancel timer */
	ssl_set_timer(tls, 0);

	if (tls->in_msgtype == TTLS_MSG_HANDSHAKE &&
		tls->in_msg[0] == TTLS_HS_FINISHED)
	{
		tls->handshake->retransmit_state = TTLS_RETRANS_FINISHED;
	}
	else
		tls->handshake->retransmit_state = TTLS_RETRANS_PREPARING;
}

/*
 * To be called when the last message of an outgoing flight is send.
 */
void ttls_send_flight_completed(ttls_context *tls)
{
	ssl_reset_retransmit_timeout(tls);
	ssl_set_timer(tls, tls->handshake->retransmit_timeout);

	if (tls->in_msgtype == TTLS_MSG_HANDSHAKE &&
		tls->in_msg[0] == TTLS_HS_FINISHED)
	{
		tls->handshake->retransmit_state = TTLS_RETRANS_FINISHED;
	}
	else
		tls->handshake->retransmit_state = TTLS_RETRANS_WAITING;
}

/*
 * Mark bits in bitmask (used for DTLS HS reassembly)
 */
static void ssl_bitmask_set(unsigned char *mask, size_t offset, size_t len)
{
	unsigned int start_bits, end_bits;

	start_bits = 8 - (offset % 8);
	if (start_bits != 8)
	{
		size_t first_byte_idx = offset / 8;

		/* Special case */
		if (len <= start_bits)
		{
			for (; len != 0; len--)
				mask[first_byte_idx] |= 1 << (start_bits - len);

			/* Avoid potential issues with offset or len becoming invalid */
			return;
		}

		offset += start_bits; /* Now offset % 8 == 0 */
		len -= start_bits;

		for (; start_bits != 0; start_bits--)
			mask[first_byte_idx] |= 1 << (start_bits - 1);
	}

	end_bits = len % 8;
	if (end_bits != 0)
	{
		size_t last_byte_idx = (offset + len) / 8;

		len -= end_bits; /* Now len % 8 == 0 */

		for (; end_bits != 0; end_bits--)
			mask[last_byte_idx] |= 1 << (8 - end_bits);
	}

	memset(mask + offset / 8, 0xFF, len / 8);
}

/*
 * Check that bitmask is full
 */
static int ssl_bitmask_check(unsigned char *mask, size_t len)
{
	size_t i;

	for (i = 0; i < len / 8; i++)
		if (mask[i] != 0xFF)
			return(-1);

	for (i = 0; i < len % 8; i++)
		if ((mask[len / 8] & (1 << (7 - i))) == 0)
			return(-1);

	return 0;
}

/*
 * Reassemble fragmented DTLS handshake messages.
 *
 * Use a temporary buffer for reassembly, divided in two parts:
 * - the first holds the reassembled message (including handshake header),
 * - the second holds a bitmask indicating which parts of the message
 * (excluding headers) have been received so far.
 */
static int ssl_reassemble_dtls_handshake(ttls_context *tls)
{
	unsigned char *msg, *bitmask;
	size_t frag_len, frag_off;
	size_t msg_len = tls->in_hslen - 12; /* Without headers */

	if (tls->handshake == NULL)
	{
		TTLS_DEBUG_MSG(1, ("not supported outside handshake (for now)"));
		return(TTLS_ERR_FEATURE_UNAVAILABLE);
	}

	/*
	 * For first fragment, check size and allocate buffer
	 */
	if (tls->handshake->hs_msg == NULL)
	{
		size_t alloc_len;

		TTLS_DEBUG_MSG(2, ("initialize reassembly, total length = %d",
							msg_len));

		if (tls->in_hslen > TTLS_MAX_CONTENT_LEN)
		{
			TTLS_DEBUG_MSG(1, ("handshake message too large"));
			return(TTLS_ERR_FEATURE_UNAVAILABLE);
		}

		/* The bitmask needs one bit per byte of message excluding header */
		alloc_len = 12 + msg_len + msg_len / 8 + (msg_len % 8 != 0);

		tls->handshake->hs_msg = ttls_calloc(1, alloc_len);
		if (tls->handshake->hs_msg == NULL)
		{
			TTLS_DEBUG_MSG(1, ("alloc failed (%d bytes)", alloc_len));
			return(TTLS_ERR_ALLOC_FAILED);
		}

		/* Prepare final header: copy msg_type, length and message_seq,
		 * then add standardised fragment_offset and fragment_length */
		memcpy(tls->handshake->hs_msg, tls->in_msg, 6);
		memset(tls->handshake->hs_msg + 6, 0, 3);
		memcpy(tls->handshake->hs_msg + 9,
				tls->handshake->hs_msg + 1, 3);
	}
	else
	{
		/* Make sure msg_type and length are consistent */
		if (memcmp(tls->handshake->hs_msg, tls->in_msg, 4) != 0)
		{
			TTLS_DEBUG_MSG(1, ("fragment header mismatch"));
			return(TTLS_ERR_INVALID_RECORD);
		}
	}

	msg = tls->handshake->hs_msg + 12;
	bitmask = msg + msg_len;

	/*
	 * Check and copy current fragment
	 */
	frag_off = (tls->in_msg[6] << 16) |
			 (tls->in_msg[7] << 8 ) |
				 tls->in_msg[8];
	frag_len = (tls->in_msg[9] << 16) |
			 (tls->in_msg[10] << 8 ) |
				 tls->in_msg[11];

	if (frag_off + frag_len > msg_len)
	{
		TTLS_DEBUG_MSG(1, ("invalid fragment offset/len: %d + %d > %d",
						 frag_off, frag_len, msg_len));
		return(TTLS_ERR_INVALID_RECORD);
	}

	if (frag_len + 12 > tls->in_msglen)
	{
		TTLS_DEBUG_MSG(1, ("invalid fragment length: %d + 12 > %d",
						 frag_len, tls->in_msglen));
		return(TTLS_ERR_INVALID_RECORD);
	}

	TTLS_DEBUG_MSG(2, ("adding fragment, offset = %d, length = %d",
						frag_off, frag_len));

	memcpy(msg + frag_off, tls->in_msg + 12, frag_len);
	ssl_bitmask_set(bitmask, frag_off, frag_len);

	/*
	 * Do we have the complete message by now?
	 * If yes, finalize it, else ask to read the next record.
	 */
	if (ssl_bitmask_check(bitmask, msg_len) != 0)
	{
		TTLS_DEBUG_MSG(2, ("message is not complete yet"));
		return(TTLS_ERR_WANT_READ);
	}

	TTLS_DEBUG_MSG(2, ("handshake message completed"));

	if (frag_len + 12 < tls->in_msglen)
	{
		/*
		 * We'got more handshake messages in the same record.
		 * This case is not handled now because no know implementation does
		 * that and it's hard to test, so we prefer to fail cleanly for now.
		 */
		TTLS_DEBUG_MSG(1, ("last fragment not alone in its record"));
		return(TTLS_ERR_FEATURE_UNAVAILABLE);
	}

	if (tls->in_left > tls->next_record_offset)
	{
		/*
		 * We've got more data in the buffer after the current record,
		 * that we don't want to overwrite. Move it before writing the
		 * reassembled message, and adjust in_left and next_record_offset.
		 */
		unsigned char *cur_remain = tls->in_hdr + tls->next_record_offset;
		unsigned char *new_remain = tls->in_msg + tls->in_hslen;
		size_t remain_len = tls->in_left - tls->next_record_offset;

		/* First compute and check new lengths */
		tls->next_record_offset = new_remain - tls->in_hdr;
		tls->in_left = tls->next_record_offset + remain_len;

		if (tls->in_left > TTLS_BUF_LEN -
						 (size_t)(tls->in_hdr - tls->in_buf))
		{
			TTLS_DEBUG_MSG(1, ("reassembled message too large for buffer"));
			return(TTLS_ERR_BUFFER_TOO_SMALL);
		}

		memmove(new_remain, cur_remain, remain_len);
	}

	memcpy(tls->in_msg, tls->handshake->hs_msg, tls->in_hslen);

	ttls_free(tls->handshake->hs_msg);
	tls->handshake->hs_msg = NULL;

	TTLS_DEBUG_BUF(3, "reassembled handshake message",
				 tls->in_msg, tls->in_hslen);

	return 0;
}

/*
 * DTLS anti-replay: RFC 6347 4.1.2.6
 *
 * in_window is a field of bits numbered from 0 (lsb) to 63 (msb).
 * Bit n is set iff record number in_window_top - n has been seen.
 *
 * Usually, in_window_top is the last record number seen and the lsb of
 * in_window is set. The only exception is the initial state (record number 0
 * not seen yet).
 */
#if defined(TTLS_DTLS_ANTI_REPLAY)
static void ssl_dtls_replay_reset(ttls_context *tls)
{
	tls->in_window_top = 0;
	tls->in_window = 0;
}

static inline uint64_t ssl_load_six_bytes(unsigned char *buf)
{
	return(((uint64_t) buf[0] << 40) |
			((uint64_t) buf[1] << 32) |
			((uint64_t) buf[2] << 24) |
			((uint64_t) buf[3] << 16) |
			((uint64_t) buf[4] << 8) |
			((uint64_t) buf[5]	 ));
}

/*
 * Return 0 if sequence number is acceptable, -1 otherwise
 */
int ttls_dtls_replay_check(ttls_context *tls)
{
	uint64_t rec_seqnum = ssl_load_six_bytes(tls->in_ctr + 2);
	uint64_t bit;

	if (tls->conf->anti_replay == TTLS_ANTI_REPLAY_DISABLED)
		return 0;

	if (rec_seqnum > tls->in_window_top)
		return 0;

	bit = tls->in_window_top - rec_seqnum;

	if (bit >= 64)
		return(-1);

	if ((tls->in_window & ((uint64_t) 1 << bit)) != 0)
		return(-1);

	return 0;
}

/*
 * Update replay window on new validated record
 */
void ttls_dtls_replay_update(ttls_context *tls)
{
	uint64_t rec_seqnum = ssl_load_six_bytes(tls->in_ctr + 2);

	if (tls->conf->anti_replay == TTLS_ANTI_REPLAY_DISABLED)
		return;

	if (rec_seqnum > tls->in_window_top)
	{
		/* Update window_top and the contents of the window */
		uint64_t shift = rec_seqnum - tls->in_window_top;

		if (shift >= 64)
			tls->in_window = 1;
		else
		{
			tls->in_window <<= shift;
			tls->in_window |= 1;
		}

		tls->in_window_top = rec_seqnum;
	}
	else
	{
		/* Mark that number as seen in the current window */
		uint64_t bit = tls->in_window_top - rec_seqnum;

		if (bit < 64) /* Always true, but be extra sure */
			tls->in_window |= (uint64_t) 1 << bit;
	}
}
#endif /* TTLS_DTLS_ANTI_REPLAY */

#if defined(TTLS_DTLS_CLIENT_PORT_REUSE)
/* Forward declaration */
static int ssl_session_reset_int(ttls_context *tls, int partial);

/*
 * Without any SSL context, check if a datagram looks like a ClientHello with
 * a valid cookie, and if it doesn't, generate a HelloVerifyRequest message.
 * Both input and output include full DTLS headers.
 *
 * - if cookie is valid, return 0
 * - if ClientHello looks superficially valid but cookie is not,
 *   fill obuf and set olen, then
 *   return TTLS_ERR_HELLO_VERIFY_REQUIRED
 * - otherwise return a specific error code
 */
static int ssl_check_dtls_clihlo_cookie(
			 ttls_cookie_write_t *f_cookie_write,
			 ttls_cookie_check_t *f_cookie_check,
			 void *p_cookie,
			 const unsigned char *cli_id, size_t cli_id_len,
			 const unsigned char *in, size_t in_len,
			 unsigned char *obuf, size_t buf_len, size_t *olen)
{
	size_t sid_len, cookie_len;
	unsigned char *p;

	if (f_cookie_write == NULL || f_cookie_check == NULL)
		return(TTLS_ERR_BAD_INPUT_DATA);

	/*
	 * Structure of ClientHello with record and handshake headers,
	 * and expected values. We don't need to check a lot, more checks will be
	 * done when actually parsing the ClientHello - skipping those checks
	 * avoids code duplication and does not make cookie forging any easier.
	 *
	 * 0-0 ContentType type;		copied, must be handshake
	 * 1-2 ProtocolVersion version;		copied
	 * 3-4 uint16 epoch;			copied, must be 0
	 * 5-10 uint48 sequence_number;		copied
	 * 11-12 uint16 length;			(ignored)
	 *
	 * 13-13 HandshakeType msg_type;	(ignored)
	 * 14-16 uint24 length;			(ignored)
	 * 17-18 uint16 message_seq;		copied
	 * 19-21 uint24 fragment_offset;	copied, must be 0
	 * 22-24 uint24 fragment_length;	(ignored)
	 *
	 * 25-26 ProtocolVersion client_version; (ignored)
	 * 27-58 Random random;			(ignored)
	 * 59-xx SessionID session_id;		1 byte len + sid_len content
	 * 60+ opaque cookie<0..2^8-1>;		1 byte len + content
	 *	 ...
	 *
	 * Minimum length is 61 bytes.
	 */
	if (in_len < 61 ||
		in[0] != TTLS_MSG_HANDSHAKE ||
		in[3] != 0 || in[4] != 0 ||
		in[19] != 0 || in[20] != 0 || in[21] != 0)
	{
		return(TTLS_ERR_BAD_HS_CLIENT_HELLO);
	}

	sid_len = in[59];
	if (sid_len > in_len - 61)
		return(TTLS_ERR_BAD_HS_CLIENT_HELLO);

	cookie_len = in[60 + sid_len];
	if (cookie_len > in_len - 60)
		return(TTLS_ERR_BAD_HS_CLIENT_HELLO);

	if (f_cookie_check(p_cookie, in + sid_len + 61, cookie_len,
					cli_id, cli_id_len) == 0)
	{
		/* Valid cookie */
		return 0;
	}

	/*
	 * If we get here, we've got an invalid cookie, let's prepare HVR.
	 *
	 * 0-0 ContentType type;		copied
	 * 1-2 ProtocolVersion version;		copied
	 * 3-4 uint16 epoch;			copied
	 * 5-10 uint48 sequence_number;		copied
	 * 11-12 uint16 length;			olen - 13
	 *
	 * 13-13 HandshakeType msg_type;	hello_verify_request
	 * 14-16 uint24 length;			olen - 25
	 * 17-18 uint16 message_seq;		copied
	 * 19-21 uint24 fragment_offset;	copied
	 * 22-24 uint24 fragment_length;	olen - 25
	 *
	 * 25-26 ProtocolVersion server_version; 0xfe 0xff
	 * 27-27 opaque cookie<0..2^8-1>;	cookie_len = olen - 27, cookie
	 *
	 * Minimum length is 28.
	 */
	if (buf_len < 28)
		return(TTLS_ERR_BUFFER_TOO_SMALL);

	/* Copy most fields and adapt others */
	memcpy(obuf, in, 25);
	obuf[13] = TTLS_HS_HELLO_VERIFY_REQUEST;
	obuf[25] = 0xfe;
	obuf[26] = 0xff;

	/* Generate and write actual cookie */
	p = obuf + 28;
	if (f_cookie_write(p_cookie,
			&p, obuf + buf_len, cli_id, cli_id_len) != 0)
	{
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	*olen = p - obuf;

	/* Go back and fill length fields */
	obuf[27] = (unsigned char)(*olen - 28);

	obuf[14] = obuf[22] = (unsigned char)((*olen - 25) >> 16);
	obuf[15] = obuf[23] = (unsigned char)((*olen - 25) >> 8);
	obuf[16] = obuf[24] = (unsigned char)((*olen - 25)	 );

	obuf[11] = (unsigned char)((*olen - 13) >> 8);
	obuf[12] = (unsigned char)((*olen - 13)	 );

	return(TTLS_ERR_HELLO_VERIFY_REQUIRED);
}

/*
 * Handle possible client reconnect with the same UDP quadruplet
 * (RFC 6347 Section 4.2.8).
 *
 * Called by ssl_parse_record_header() in case we receive an epoch 0 record
 * that looks like a ClientHello.
 *
 * - if the input looks like a ClientHello without cookies,
 * send back HelloVerifyRequest, then
 * return TTLS_ERR_HELLO_VERIFY_REQUIRED
 * - if the input looks like a ClientHello with a valid cookie,
 * reset the session of the current context, and
 * return TTLS_ERR_CLIENT_RECONNECT
 * - if anything goes wrong, return a specific error code
 *
 * ttls_read_record() will ignore the record if anything else than
 * TTLS_ERR_CLIENT_RECONNECT or 0 is returned, although this function
 * cannot not return 0.
 */
static int ssl_handle_possible_reconnect(ttls_context *tls)
{
	int r;
	size_t len;

	r = ssl_check_dtls_clihlo_cookie(
			tls->conf->f_cookie_write,
			tls->conf->f_cookie_check,
			tls->conf->p_cookie,
			tls->cli_id, tls->cli_id_len,
			tls->in_buf, tls->in_left,
			tls->out_buf, TTLS_MAX_CONTENT_LEN, &len);

	TTLS_DEBUG_RET(2, "ssl_check_dtls_clihlo_cookie", r);

	if (r == TTLS_ERR_HELLO_VERIFY_REQUIRED)
	{
		/* Don't check write errors as we can't do anything here.
		 * If the error is permanent we'll catch it later,
		 * if it's not, then hopefully it'll work next time. */
		(void) tls->f_send(tls->p_bio, tls->out_buf, len);

		return(TTLS_ERR_HELLO_VERIFY_REQUIRED);
	}

	if (r == 0)
	{
		/* Got a valid cookie, partially reset context */
		if ((r = ssl_session_reset_int(tls, 1)) != 0)
		{
			TTLS_DEBUG_RET(1, "reset", r);
			return r;
		}

		return(TTLS_ERR_CLIENT_RECONNECT);
	}

	return r;
}
#endif /* TTLS_DTLS_CLIENT_PORT_REUSE */

#if defined(TTLS_DTLS_HELLO_VERIFY)
/* Dummy cookie callbacks for defaults */
static int ssl_cookie_write_dummy(void *ctx,
		unsigned char **p, unsigned char *end,
		const unsigned char *cli_id, size_t cli_id_len)
{
	return TTLS_ERR_FEATURE_UNAVAILABLE;
}

static int ssl_cookie_check_dummy(void *ctx,
		const unsigned char *cookie, size_t cookie_len,
		const unsigned char *cli_id, size_t cli_id_len)
{
	return TTLS_ERR_FEATURE_UNAVAILABLE;
}
#endif /* TTLS_DTLS_HELLO_VERIFY */

#if defined(TTLS_DTLS_ANTI_REPLAY)
void ttls_conf_dtls_anti_replay(ttls_config *conf, char mode)
{
	conf->anti_replay = mode;
}
#endif

#if defined(TTLS_DTLS_BADMAC_LIMIT)
void ttls_conf_dtls_badmac_limit(ttls_config *conf, unsigned limit)
{
	conf->badmac_limit = limit;
}
#endif

#if defined(TTLS_PROTO_DTLS)
void ttls_conf_handshake_timeout(ttls_config *conf, uint32_t min, uint32_t max)
{
	conf->hs_timeout_min = min;
	conf->hs_timeout_max = max;
}
#endif

#if defined(TTLS_DTLS_HELLO_VERIFY)
int ttls_set_client_transport_id(ttls_context *tls,
					 const unsigned char *info,
					 size_t ilen)
{
	if (tls->conf->endpoint != TTLS_IS_SERVER)
		return(TTLS_ERR_BAD_INPUT_DATA);

	ttls_free(tls->cli_id);

	if ((tls->cli_id = ttls_calloc(1, ilen)) == NULL)
		return(TTLS_ERR_ALLOC_FAILED);

	memcpy(tls->cli_id, info, ilen);
	tls->cli_id_len = ilen;

	return 0;
}

void ttls_conf_dtls_cookies(ttls_config *conf,
				   ttls_cookie_write_t *f_cookie_write,
				   ttls_cookie_check_t *f_cookie_check,
				   void *p_cookie)
{
	conf->f_cookie_write = f_cookie_write;
	conf->f_cookie_check = f_cookie_check;
	conf->p_cookie	   = p_cookie;
}

static int ssl_write_hello_verify_request(ttls_context *tls)
{
	int r;
	unsigned char *p = tls->out_msg + 4;
	unsigned char *cookie_len_byte;

	TTLS_DEBUG_MSG(2, ("=> write hello verify request"));

	/*
	 * struct {
	 *   ProtocolVersion server_version;
	 *   opaque cookie<0..2^8-1>;
	 * } HelloVerifyRequest;
	 */

	/* The RFC is not clear on this point, but sending the actual negotiated
	 * version looks like the most interoperable thing to do. */
	ttls_write_version(tls->major_ver, tls->minor_ver,
					   tls->conf->transport, p);
	TTLS_DEBUG_BUF(3, "server version", p, 2);
	p += 2;

	/* If we get here, f_cookie_check is not null */
	if (tls->conf->f_cookie_write == NULL)
	{
		TTLS_DEBUG_MSG(1, ("inconsistent cookie callbacks"));
		return(TTLS_ERR_INTERNAL_ERROR);
	}

	/* Skip length byte until we know the length */
	cookie_len_byte = p++;

	if ((r = tls->conf->f_cookie_write(tls->conf->p_cookie,
					 &p, tls->out_buf + TTLS_BUF_LEN,
					 tls->cli_id, tls->cli_id_len)) != 0)
	{
		TTLS_DEBUG_RET(1, "f_cookie_write", r);
		return r;
	}

	*cookie_len_byte = (unsigned char)(p - (cookie_len_byte + 1));

	TTLS_DEBUG_BUF(3, "cookie sent", cookie_len_byte + 1, *cookie_len_byte);

	tls->out_msglen  = p - tls->out_msg;
	tls->out_msgtype = TTLS_MSG_HANDSHAKE;
	tls->out_msg[0]  = TTLS_HS_HELLO_VERIFY_REQUEST;

	tls->state = TTLS_SERVER_HELLO_VERIFY_REQUEST_SENT;

	if ((r = ttls_write_record(tls)) != 0)
	{
		TTLS_DEBUG_RET(1, "ttls_write_record", r);
		return r;
	}

	TTLS_DEBUG_MSG(2, ("<= write hello verify request"));

	return 0;
}
#endif /* TTLS_DTLS_HELLO_VERIFY */

#endif /* TTLS_PROTO_DTLS */
