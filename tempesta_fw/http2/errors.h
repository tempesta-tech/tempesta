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
 *
 * Copyright (C) Julius Goryavsky. Original code of this module
 * is granted by the author for unrestricted use in the Tempesta FW
 * and for distribution under GNU General Public License without
 * any restrictions.
 */

#ifndef HTTP2_ERRORS_H
#define HTTP2_ERRORS_H

/* NB! All protocol-related errors moved to */
/*     "official" API header file ("http2.h"). */

enum {
   HTTP2Error_Huffman_InvalidCode = 0x1000, /* 4096 */
   HTTP2Error_Huffman_UnexpectedEOS,	    /* 4097 */
   HTTP2Error_Huffman_CodeTooShort,	    /* 4098 */
   HTTP2Error_Huffman_CodeTooLong,	    /* 4099 */
   HTTP2Error_HPack_Unknown_Index,	    /* 4100 */
   HTTP2Error_HPack_Invalid_Index,	    /* 4101 */
   HTTP2Error_HPack_Invalid_Name_Length,    /* 4102 */
   HTTP2Error_Out_Of_Memory = 0x2000,	    /* 8192 */
   HTTP2Error_Integer_Overflow		    /* 8193 */
};

#endif
