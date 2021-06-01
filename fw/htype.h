/**
 *		Tempesta FW
 *
 * HTTP types: this file defines character types for HTTP like ctype.h
 *
 * Copyright (C) 2016 Tempesta Technologies, Inc.
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
#ifndef __HTYPE_H__
#define __HTYPE_H__

/**
 * ASCII codes to accept HTTP token (RFC 7230 3.2.6).
 */
static const unsigned char token_a[] ____cacheline_aligned = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

extern const unsigned char __tfw_lct[256];

/**
 * Check whether a character is CR or LF.
 */
#define IS_CRLF(c)	 ((c) == '\r' || (c) == '\n')
/**
 * Check whether a character is a whitespace (RWS/OWS/BWS according to RFC7230).
 */
#define IS_WS(c)	((c) == ' ' || (c) == '\t')
/**
 * RFC 7230 3.2 allows OWS after header field, so the macro is used to identify
 * possible end of header field.
 */
#define IS_CRLFWS(c)	(IS_WS(c) || IS_CRLF(c))
/**
 * RFC 7230 3.2.6 token as
 *
 * 	ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
 * 	!#$%&'*+-.^_`|~0123456789
 */
#define IS_TOKEN(c)	(token_a[c])

/**
 * Much faster implementation than standard tolower().
 * Also it's safer than ((c) | 0x20) which for example can convert '\r' to '-'.
 * Unsigned char must be used as @c.
 */
#define TFW_LC(c)	__tfw_lct[c]

#endif /* __HTYPE_H__ */
