/**
 *		Tempesta FW
 *
 * HTTP/2 Huffman encoders and decoders.
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef HPACK_HUFFMAN_H
#define HPACK_HUFFMAN_H

#include "common.h"
#include "errors.h"
#include "buffers.h"

ufast huffman_decode(const char *__restrict source,
		     char *__restrict dst, uwide n);

ufast huffman_decode_fragments(HTTP2Input * __restrict source,
			       HTTP2Output * __restrict out, uwide n);

uwide huffman_encode(const char *__restrict source,
		     char *__restrict dst, uwide n);

uchar *huffman_encode_fragments(HTTP2Output * __restrict out,
				uchar * __restrict dst,
				ufast * __restrict k_new,
				const TfwStr * __restrict source,
				ufast * __restrict rc);

uchar *huffman_encode_plain(HTTP2Output * __restrict out,
			    uchar * __restrict dst,
			    ufast * __restrict k_new,
			    uchar * __restrict src,
			    uwide n, ufast * __restrict rc);

uwide huffman_encode_length(const char *__restrict source, uwide n);

/* Same as http2_huffman_encode_check, but stops calculating */
/* length if encoding longer than source:		     */

uwide huffman_check(const char *__restrict source, uwide n);
uwide huffman_check_fragments(const TfwStr * __restrict source, uwide n);

#endif
