/**
 *		Tempesta FW
 *
 * HPACK compression standard (RFC-7541).
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

#ifndef HPACK_H
#define HPACK_H

#include "common.h"
#include "../pool.h"
#include "../str.h"
#include "../http.h"
#include "errors.h"
#include "buffers.h"

/* HIndex declared here to prevent the circular */
/* dependency from the "hindex.h" header file: */

typedef struct HTTP2Index HTTP2Index;

typedef struct HTTP2Field {
	struct HTTP2Field *next;
	TfwStr name;
	TfwStr value;
} HTTP2Field;

enum {
	HPack_State_Ready = 0,
	HPack_State_Index,
	HPack_State_Name,
	HPack_State_Name_Length,
	HPack_State_Name_Text,
	HPack_State_Value,
	HPack_State_Value_Length,
	HPack_State_Value_Text,
	HPack_State_Window
};

#define HPack_State_Mask 15

#define HPack_Flags_Add 	  0x010	/* Field must be added to dynamic table. */
#define HPack_Flags_No_Value	  0x020	/* Index without literal value. */
#define HPack_Flags_Transit	  0x040	/* Transit header field. */
#define HPack_Flags_Huffman_Name  0x080	/* Huffman encoding used for field name. */
#define HPack_Flags_Huffman_Value 0x100	/* Huffman encoding used for field value. */

/* state:      Current state.			      */
/* shift:      Current shift, used when integer       */
/*	       decoding interrupted due to absence    */
/*	       of the next fragment.		      */
/* saved:      Current integer value (see above).     */
/* field:      Last header field name and value,      */
/*	       used when decoding proccess interruped */
/*	       due to absence of the next fragment.   */
/* pool:       Memory pool.			      */
/* dynamic:    Dynamic table for headers compression. */
/* max_window: Maximum allowed dynamic table size.    */
/* window:     Current dynamic table size (in bytes). */

typedef struct {
	ufast state;
	ufast shift;
	uwide saved;
	 HTTP2Field * field;
	 TfwPool * pool;
	 HTTP2Index * dynamic;
	ufast max_window;
	ufast window;
} HPack;

HTTP2Field *hpack_decode(HPack * __restrict hp,
			 HTTP2Input * __restrict source,
			 uwide n,
			 HTTP2Output * __restrict buffer,
			 ufast * __restrict rc);

void hpack_free_list(HTTP2Output * __restrict hp, HTTP2Field * __restrict fp);

ufast hpack_encode(HPack * __restrict hp,
		   const TfwHttpHdrTbl * __restrict source,
		   HTTP2Output * __restrict buffer);

ufast hpack_set_max_window(HPack * __restrict hp, ufast max_window);

ufast hpack_set_window(HPack * __restrict hp, ufast window);

HPack *hpack_new(ufast max_window, TfwPool * __restrict pool);

void hpack_free(HPack * __restrict hp);

#endif
