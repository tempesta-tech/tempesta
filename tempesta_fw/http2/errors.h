/**
 *		Tempesta FW
 *
 * Conversion between little and big endian numbers.
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

#ifndef HTTP2_ERRORS_H
#define HTTP2_ERRORS_H

enum {
	Err_HTTP2_NoError = 0,		       /* 0    */
	Err_HTTP2_ProtocolError      = 0x1,    /* 1    */
	Err_HTTP2_InternalError      = 0x2,    /* 2    */
	Err_HTTP2_FlowControlError   = 0x3,    /* 3    */
	Err_HTTP2_SettingsTimeout    = 0x4,    /* 4    */
	Err_HTTP2_StreamClosed	     = 0x5,    /* 5    */
	Err_HTTP2_FrameSizeError     = 0x6,    /* 6    */
	Err_HTTP2_RefusedStream      = 0x7,    /* 7    */
	Err_HTTP2_Cancel	     = 0x8,    /* 8    */
	Err_HTTP2_CompressionError   = 0x9,    /* 9    */
	Err_HTTP2_ConnectError	     = 0xA,    /* 10   */
	Err_HTTP2_EnhanceYourCalm    = 0xB,    /* 11   */
	Err_HTTP2_InadequateSecurity = 0xC,    /* 12   */
	Err_HTTP2_HTTP11Required     = 0xD,    /* 13   */
	Err_HTTP2_Custom,		       /* 14   */
	Err_HTTP2_OutOfMemory	     = 0x400,  /* 1024 */
	Err_HTTP2_IntegerOverflow,	       /* 1025 */
	Err_Huffman_InvalidCode      = 0x1000, /* 4096 */
	Err_Huffman_UnexpectedEOS,	       /* 4097 */
	Err_Huffman_CodeTooShort,	       /* 4098 */
	Err_Huffman_CodeTooLong,	       /* 4099 */
	Err_HPack_UnknownIndex, 	       /* 4100 */
	Err_HPack_InvalidIndex, 	       /* 4101 */
	Err_HPack_InvalidNameLength,	       /* 4102 */
	Err_HPack_InvalidTableSize	       /* 4103 */
};

#endif
