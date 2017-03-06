/**
 *		Tempesta FW
 *
 * HPACK (RFC-7541) decoder and encoder.
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

#include "common.h"
#include "../pool.h"
#include "../str.h"
#include "../http.h"
#include "errors.h"
#include "buffers.h"
#include "huffman.h"
#include "hindex.h"
#include "hpack_helpers.h"
#include "hpack.h"

#define HPACK_COPY_STRING(value)				\
do {								\
	n -= length;						\
	src = buffer_copy(					\
		source, &m, src, m, length, &field->value, pool \
	);							\
	if (Opt_Unlikely(src == NULL)) {			\
		goto Out_Of_Memory;				\
	}							\
} while (0)

HTTP2Field *
hpack_decode (HPack	  * __restrict hp,
	      HTTP2Input  * __restrict source,
	      uwide		       n,
	      HTTP2Output * __restrict buffer,
	      ufast	  * __restrict rc)
{
	TfwPool * __restrict pool = buffer->pool;
	HTTP2Field * __restrict field = hp->field;
	HTTP2Field * fp = NULL;
     /* Initialized only to prevent compiler warnings: */
	HTTP2Field * bp = NULL;
	* rc = 0;
	if (n) {
		uwide m;
		const uchar * __restrict src = buffer_get(source, &m);
		ufast state = hp->state;
		do {
		     /* Initialized only to prevent compiler warnings: */
			ufast index  = 0;
			ufast length = 0;
			switch (state & HPack_State_Mask) {
			case HPack_State_Index:
				GET_CONTINUE(index);
				if ((state & HPack_Flags_No_Value) == 0) {
					if (n) {
						goto Get_Value;
					}
					else {
						state &= ~HPack_State_Mask;
						state |=  HPack_State_Value;
						goto Incomplete;
					}
				}
				else {
					goto Duplicate;
				}
				break;
			case HPack_State_Window:
				GET_CONTINUE(index);
Set_Window:			state = HPack_State_Ready;
				hpack_set_window(hp->dynamic, index);
				break;
			case HPack_State_Name_Length:
				GET_CONTINUE(length);
				if (n >= length) {
					goto Get_Name_Text;
				}
				else {
					state &= ~HPack_State_Mask;
					state |=  HPack_State_Name_Text;
					goto Incomplete;
				}
			case HPack_State_Value_Length:
				GET_CONTINUE(length);
				if (n >= length) {
					goto Get_Value_Text;
				}
				else {
					state &= ~HPack_State_Mask;
					state |=  HPack_State_Value_Text;
					goto Incomplete;
				}
			default:
		     /* case HPack_State_Ready: */
			{
				uchar c;
				field = tfw_pool_alloc(pool, sizeof(HTTP2Field));
				if (Opt_Unlikely(field == NULL)) {
					goto Out_Of_Memory;
				}
				memset(field, 0, sizeof(HTTP2Field));
				if (Opt_Unlikely(m == 0)) {
					src = buffer_next(source, &m);
				}
				c = * src++;
				n--;
				m--;
				if (c & 0x80) {
					state = HPack_State_Index | HPack_Flags_No_Value;
					index = c & 0x7F;
					if (index == 0x7F) {
						GET_FLEXIBLE(index);
					}
					else if (Opt_Unlikely(index == 0)) {
						* rc = HTTP2Error_HPack_Invalid_Index;
						goto Bug;
					}
					goto Duplicate;
				}
				else if (c & 0x40) {
					state = HPack_State_Index | HPack_Flags_Add;
					index = c & 0x3F;
					if (index == 0x3F) {
Index:						GET_FLEXIBLE(index);
						state = HPack_State_Value;
						goto Get_Value;
					}
				}
				else if (c & 0x20) {
					index = c & 0x1F;
					if (index == 0x1F) {
						state = HPack_State_Window;
						GET_FLEXIBLE(index);
					}
					goto Set_Window;
				}
				else {
					state = HPack_State_Index;
					if (c & 0x10) {
						state = HPack_State_Index | HPack_Flags_Transit;
					}
					index = c & 15;
					if (index == 15) {
						goto Index;
					}
				}
				if (n) {
					if (index) {
						goto Get_Value;
					}
				}
				else {
					state &= ~HPack_State_Mask;
					state |= index ? HPack_State_Value :
							 HPack_State_Name;
					goto Incomplete;
				}
			}
			case HPack_State_Name:
			{
				uchar c;
				if (Opt_Unlikely(m == 0)) {
					src = buffer_next(source, &m);
				}
				c = * src++;
				n--;
				m--;
				length = c & 0x7F;
				if (Opt_Likely(c & 0x80)) {
					state |= HPack_Flags_Huffman_Name;
				}
				if (Opt_Unlikely(length == 0x7F)) {
					state &= ~HPack_State_Mask;
					state |=  HPack_State_Name_Length;
					GET_FLEXIBLE(length);
				}
				else if (Opt_Unlikely(length == 0)) {
					* rc = HTTP2Error_HPack_Invalid_Name_Length;
					goto Bug;
				}
				if (n >= length) {
					goto Get_Name_Text;
				}
				else {
					state &= ~HPack_State_Mask;
					state |=  HPack_State_Name_Text;
					goto Incomplete;
				}
			}
			case HPack_State_Name_Text:
			{
				if (Opt_Unlikely(n < length)) {
					break;
				}
Get_Name_Text:
				if (state & HPack_Flags_Huffman_Name) {
					ufast hrc;
					buffer_close(source, m);
					hrc = http2_huffman_decode_fragments(source, buffer, length);
					if (Opt_Unlikely(hrc)) {
						* rc = hrc;
						goto Bug;
					}
					field->name = buffer->str;
					n -= length;
					if (Opt_Likely(n)) {
						src = buffer_get(source, &m);
					}
				}
				else {
					HPACK_COPY_STRING(name);
				}
				if (Opt_Unlikely(n == 0)) {
					state &= ~HPack_State_Mask;
					state |=  HPack_State_Value;
				}
			}
			case HPack_State_Value:
			{
				uchar c;
Get_Value:
				if (Opt_Unlikely(m == 0)) {
					src = buffer_next(source, &m);
				}
				c = * src++;
				n--;
				m--;
				length = c & 0x7F;
				if (Opt_Likely(c & 0x80)) {
					state |= HPack_Flags_Huffman_Value;
				}
				if (Opt_Unlikely(length == 0x7F)) {
					state &= ~HPack_State_Mask;
					state |=  HPack_State_Value_Length;
					GET_FLEXIBLE(length);
				}
				if (n >= length) {
					goto Get_Value_Text;
				}
				else {
					state &= ~HPack_State_Mask;
					state |=  HPack_State_Value_Text;
					goto Incomplete;
				}
			}
			case HPack_State_Value_Text:
			{
				ufast hrc;
				if (Opt_Unlikely(n < length)) {
					break;
				}
Get_Value_Text:
				if (length) {
					if (state & HPack_Flags_Huffman_Value) {
						buffer_close(source, m);
						hrc = http2_huffman_decode_fragments(source, buffer, length);
						if (Opt_Unlikely(hrc)) {
							* rc = hrc;
							goto Bug;
						}
						field->value = buffer->str;
						n -= length;
						if (Opt_Likely(n)) {
							src = buffer_get(source, &m);
						}
					}
					else {
						HPACK_COPY_STRING(value);
					}
				}
				if (index) {
Duplicate:				hrc = hpack_add_index(hp->dynamic, field, index, state);
				}
				else {
					hrc = hpack_add(hp->dynamic, field, state);
				}
				if (hrc) {
					if (fp) {
						bp->next = field;
					}
					else {
						fp = field;
					}
					bp = field;
					field = NULL;
					state = HPack_State_Ready;
				}
				else {
					* rc = hrc;
					goto Bug;
				}
			}
			}
		} while (n);
Incomplete:	hp->state = state;
		hp->field = field;
		buffer_close(source, m);
	}
	return fp;
Overflow:
	* rc = HTTP2Error_Integer_Overflow;
Bug:
	if (field) {
		hp->field = NULL;
		buffer_free_tfwstr(pool, &field->name);
		buffer_free_tfwstr(pool, &field->value);
	}
	if (fp) {
		hpack_free_chain(hp, fp);
	}
	return NULL;
Out_Of_Memory:
	* rc = HTTP2Error_Out_Of_Memory;
	goto Bug;
}

HPack *
hpack_new (ufast		window,
	   TfwPool * __restrict pool)
{
	HPack * __restrict hp =
		tfw_pool_alloc(pool, sizeof(HPack));
	if (hp) {
		hp->state = HPack_State_Ready;
		hp->shift = 0;
		hp->saved = 0;
		hp->field = NULL;
		hp->pool = pool;
		hp->dynamic = hpack_new_index(window, pool);
	}
	return hp;
}

void
hpack_free (HPack * __restrict hp)
{
	HTTP2Field * __restrict field = hp->field;
	TfwPool * __restrict pool = hp->pool;
	if (field) {
		buffer_free_tfwstr(pool, &field->name);
		buffer_free_tfwstr(pool, &field->value);
	}
	hpack_free_index(hp->dynamic);
	tfw_pool_free(pool, hp, sizeof(HPack));
}
