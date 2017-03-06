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
	struct HTTP2Field * next;
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

#define HPack_Flags_Add 	  0x010 /* Field must be added to dynamic table. */
#define HPack_Flags_No_Value	  0x020 /* Index without literal value. */
#define HPack_Flags_Transit	  0x040 /* Transit header field. */
#define HPack_Flags_Huffman_Name  0x080 /* Huffman encoding used for field name. */
#define HPack_Flags_Huffman_Value 0x100 /* Huffman encoding used for field value. */

typedef struct {
	ufast	  state;   /* Current state. */
	ufast	  shift;   /* Current shift, used when integer */
			   /* decoding interrupted due to absence */
			   /* of the next fragment. */
	ufast	  saved;   /* Current integer value (see above). */
	HTTP2Field
		* field;   /* Last header field name and value, */
			   /* used when decoding proccess interruped */
			   /* due to absence of the next fragment. */
	TfwPool * pool;    /* Memory pool. */
	HTTP2Index
		* dynamic; /* Dynamic headers table. */
} HPack;

HTTP2Field *
hpack_decode (HPack	  * __restrict hp,
	      HTTP2Input  * __restrict source,
	      uwide		       n,
	      HTTP2Output * __restrict buffer,
	      ufast	  * __restrict rc);

void
hpack_free_chain (HPack      * __restrict hp,
		  HTTP2Field * __restrict fp);

ufast
hpack_encode (HPack		  * __restrict hp,
	      const TfwHttpHdrTbl * __restrict source,
	      HTTP2Output	  * __restrict buffer);

HPack *
hpack_new (ufast		window,
	   TfwPool * __restrict pool);

void
hpack_free (HPack * __restrict hp);

#endif
