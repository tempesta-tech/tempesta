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

#ifndef HUFFMAN_H
#define HUFFMAN_H

#include "common.h"
#include "buffers.h"

enum {
   HTTP2Error_Huffman_InvalidCode = 0x1000, /* 4096 */
   HTTP2Error_Huffman_UnexpectedEOS,	    /* 4097 */
   HTTP2Error_Huffman_CodeTooShort,	    /* 4098 */
   HTTP2Error_Huffman_CodeTooLong	    /* 4099 */
};

fast
http2_huffman_decode (const char * __restrict source,
			    char * __restrict dst,
			    uwide	      n);

fast
http2_huffman_decode_fragments (HTTP2Buffer * const __restrict source,
				char	    *	    __restrict dst,
				uwide			       n);

uwide
http2_huffman_encode (const char * __restrict source,
			    char * __restrict dst,
			    uwide	      n);

#endif
