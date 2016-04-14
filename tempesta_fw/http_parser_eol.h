/**
 *		Tempesta FW
 *
 * Copyright (C) 2016 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

__FSM_STATE(RGen_EoL) {
	parser->_tmp.eol = 0;
	/* Pass through */
}
__FSM_STATE(RGen__EoL) {
	if (likely(IS_CR_OR_LF(c))) {
		/*
		 * We use special register to track line endings. New
		 * characters are appended to the beginning while old
		 * characters are shifted left. The lower 4 bits used to
		 * track CR/LF characters.
		 */
		parser->_tmp.eol = (parser->_tmp.eol << 4) | (c & 0xf);
		TFW_DBG3("parser: eol %08lx\n", parser->_tmp.eol);

		/*
		 * We have a number of valid CR/LF mixtures. Any other
		 * mixtures must be blocked:
		 *
		 *   LF          -> next header / empty-line (incomplete)
		 *   CR LF       -> next header / empty-line (incomplete)
		 *   CR          -> (incomplete)
		 *   LF CR       -> empty-line (incomplete)
		 *   LF LF       -> empty-line
		 *   LF CR LF    -> empty-line
		 *   CR LF CR    -> empty-line (incomplete)
		 *   CR LF LF    -> empty-line
		 *   CR LF CR LF -> empty-line
		 */
		switch (parser->_tmp.eol) {
		case 0xa:
		case 0xda:
			/* Skip headers that were not opened */
			if (msg->parser.hdr.ptr) {
				tfw_str_set_eolen(&parser->hdr, 1 + !!(parser->_tmp.eol == 0xda));
				if (tfw_http_msg_hdr_close(msg, parser->_hdr_tag))
					return TFW_BLOCK;
			}
			/* Fall through */
		case 0xd:
		case 0xad:
		case 0xaa:
		case 0xada:
		case 0xdad:
		case 0xdaa:
		case 0xdada:
			goto GoodLookingEOL;
		}

		return TFW_BLOCK;

	GoodLookingEOL:

		/*
		 * Set empty-line mark only if LFxx or CRLFxx was
		 * catched and crlf wasn't completed yet by
		 * @__field_finish function.
		 */
		if ((parser->_tmp.eol & 0xf0) == 0xa0) {
			if (!(msg->crlf.flags & TFW_STR_COMPLETE)) {
				tfw_http_msg_set_data(msg, &msg->crlf, p);
			}
		}

		/*
		 * Check for the empty-line (EOL + EOL) mixture here as
		 * it can be handled immediately.
		 */
		switch (parser->_tmp.eol) {
		case 0xaa: case 0xada: case 0xdaa: case 0xdada:
			parser->_tmp.eol = 0;
			if (!(msg->crlf.flags & TFW_STR_COMPLETE)) {
				__field_finish(msg, &msg->crlf, data, p + 1);
				TFW_HTTP_INIT_BODY_PARSING(msg, RGen_Body);
			} else if (msg->body.flags & TFW_STR_COMPLETE) {
				r = TFW_PASS;
				FSM_EXIT();
			} else {
				return TFW_BLOCK;
			}
		}

		/*
		 * Can't make desicion right now as the EOL-sequence
		 * is incomplete. So, let's try to do it on the next
		 * pass.
		 */

		__FSM_MOVE(RGen__EoL);
	}

	TFW_DBG3("parser: eol %08lx +%02x(%c)\n", parser->_tmp.eol, c, isprint(c) ? c : '.');

	/*
	 * Non EOL character was received after some CR/LF
	 * characters. This usually happens after the end of line, but
	 * the tracked sequence may be incomplete. So, we need to
	 * check for allowed line endings (LF or CRLF).
	 */
	if (!(parser->_tmp.eol == 0xa || parser->_tmp.eol == 0xda))
		return TFW_BLOCK;

	parser->_tmp.eol = 0;

	/*
	 * According to RFC 7230, HTTP-headers may appear in two
	 * cases. The first one is parsing header section (3.2) and
	 * the second one is parsing chunked-body trailer-part (4.1).
	 */
	if (!(msg->crlf.flags & TFW_STR_COMPLETE) ||
	     (msg->body.flags & TFW_STR_COMPLETE))
		__FSM_JMP(RGen_Hdr);

	/*
	 * The next chunk of chunked-body payload (RFC 7320, 4.1.2)
	 * needs to be handled.
	 */
	__FSM_JMP(RGen_Body);
}
