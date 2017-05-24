/**
 *		Tempesta FW
 *
 * HPACK (RFC-7541) decoder.
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

#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
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

#define Debug_HPack 1

#if Debug_HPack
#define DPRINTF(...) printf("HPack: " __VA_ARGS__)
#define DPUTS(...) puts("HPack: " __VA_ARGS__)
#else
#define DPRINTF(...)
#define DPUTS(...)
#endif

#define HPACK_COPY_STRING(value)    \
do {				    \
	n -= length;		    \
	src = buffer_copy(	    \
		source, &m, src, m, \
		length, buffer, rc  \
	);			    \
	if (unlikely(* rc)) {	    \
		goto Bug;	    \
	}			    \
	field->value = buffer->str; \
} while (0)

HTTP2Field *
hpack_decode(HPack * __restrict hp,
	     HTTP2Input * __restrict source,
	     uintptr_t n,
	     HTTP2Output * __restrict buffer, unsigned int *__restrict rc)
{
	TfwPool *const __restrict pool = buffer->pool;
	HTTP2Field *__restrict field = hp->field;
	HTTP2Field *fp = NULL;

	/* Initialized only to prevent compiler warnings: */
	HTTP2Field *bp = NULL;

	*rc = 0;
	if (n) {
		uintptr_t m;
		const uchar *__restrict src = buffer_get(source, &m);
		unsigned int state = hp->state;

		do {
			uintptr_t index = hp->index;

			/* Initialized only to prevent compiler warnings: */
			uintptr_t length = 0;

			switch (state & HPack_State_Mask) {
			case HPack_State_Index:
				GET_CONTINUE(index);
				DPRINTF("Index finally decoded: %" PRIuPTR "\n",
					index);
				hp->index = index;
				if ((state & HPack_Flags_No_Value) == 0) {
					if (n) {
						goto Get_Value;
					} else {
						state &= ~HPack_State_Mask;
						state |= HPack_State_Value;
						goto Incomplete;
					}
				} else {
					goto Duplicate;
				}
				break;
			case HPack_State_Window:
				GET_CONTINUE(index);
				DPRINTF("Window finally decoded: %" PRIuPTR
					"\n", index);
 Set_Window:
				DPRINTF("Window size: %" PRIuPTR "\n", index);
				if (index <= hp->max_window) {
					DPUTS("Set window size...");
					hp->window = index;
					hpack_set_length(hp->dynamic, index);
					state = HPack_State_Ready;
				} else {
					*rc = Err_HPack_InvalidTableSize;
					goto Bug;
				}
				break;
			case HPack_State_Name_Length:
				GET_CONTINUE(length);
				DPRINTF("Name length finally decoded: %" PRIuPTR
					"\n", length);
				field->name.len = length;
				if (n >= length) {
					goto Get_Name_Text;
				} else {
					state &= ~HPack_State_Mask;
					state |= HPack_State_Name_Text;
					goto Incomplete;
				}
			case HPack_State_Value_Length:
				GET_CONTINUE(length);
				DPRINTF("Value length finally decoded: %"
					PRIuPTR "\n", length);
				field->value.len = length;
				if (n >= length) {
					goto Get_Value_Text;
				} else {
					state &= ~HPack_State_Mask;
					state |= HPack_State_Value_Text;
					goto Incomplete;
				}
			default:
				/* case HPack_State_Ready: */
				{
					uchar c;

					field =
					    tfw_pool_alloc(pool,
							   sizeof(HTTP2Field));
					if (unlikely(field == NULL)) {
						goto Out_Of_Memory;
					}
					memset(field, 0, sizeof(HTTP2Field));
					if (unlikely(m == 0)) {
						src = buffer_next(source, &m);
					}
					c = *src++;
					n--;
					m--;
					if (c & 0x80) {
						DPUTS("Reference by index...");
						state =
						    HPack_State_Index |
						    HPack_Flags_No_Value;
						index = c & 0x7F;
						if (index == 0x7F) {
							GET_FLEXIBLE(index);
						} else if (unlikely(index == 0)) {
							*rc =
							    Err_HPack_InvalidIndex;
							goto Bug;
						}
						DPRINTF("Decoded index: %"
							PRIuPTR "\n", index);
						goto Duplicate;
					} else if (c & 0x40) {
						DPUTS
						    ("Reference with addition...");
						state =
						    HPack_State_Index |
						    HPack_Flags_Add;
						index = c & 0x3F;
						if (index == 0x3F) {
 Index:
							GET_FLEXIBLE(index);
							DPRINTF
							    ("Decoded index: %"
							     PRIuPTR "\n",
							     index);
							hp->index = index;
							state =
							    HPack_State_Value;
							goto Get_Value;
						}
					} else if (c & 0x20) {
						DPUTS("New window size...");
						index = c & 0x1F;
						if (index == 0x1F) {
							state =
							    HPack_State_Window;
							GET_FLEXIBLE(index);
						}
						DPRINTF("Decoded window: %"
							PRIuPTR "\n", index);
						goto Set_Window;
					} else {
						DPUTS
						    ("Reference with value...");
						state = HPack_State_Index;
						if (c & 0x10) {
							DPUTS
							    ("Transit header...");
							state =
							    HPack_State_Index |
							    HPack_Flags_Transit;
						}
						index = c & 15;
						if (index == 15) {
							goto Index;
						}
					}
					hp->index = index;
					if (index) {
						DPRINTF("Decoded index: %"
							PRIuPTR "\n", index);
					}
					if (n) {
						if (index) {
							goto Get_Value;
						}
					} else {
						state &= ~HPack_State_Mask;
						state |=
						    index ? HPack_State_Value :
						    HPack_State_Name;
						goto Incomplete;
					}
				}
			case HPack_State_Name:
				{
					uchar c;

					DPUTS("Decode header name length...");
					if (unlikely(m == 0)) {
						src = buffer_next(source, &m);
					}
					c = *src++;
					n--;
					m--;
					length = c & 0x7F;
					if (c & 0x80) {
						DPUTS
						    ("Huffman encoding used...");
						state |=
						    HPack_Flags_Huffman_Name;
					}
					if (unlikely(length == 0x7F)) {
						state &= ~HPack_State_Mask;
						state |=
						    HPack_State_Name_Length;
						GET_FLEXIBLE(length);
					} else if (unlikely(length == 0)) {
						*rc =
						    Err_HPack_InvalidNameLength;
						goto Bug;
					}
					DPRINTF("Name length: %" PRIuPTR "\n",
						length);
					field->name.len = length;
					if (n >= length) {
						goto Get_Name_Text;
					} else {
						state &= ~HPack_State_Mask;
						state |= HPack_State_Name_Text;
						goto Incomplete;
					}
				}
			case HPack_State_Name_Text:
				{
					length = field->name.len;
					if (unlikely(n < length)) {
						DPUTS("Not enough data...");
						break;
					}
 Get_Name_Text:
					DPUTS("Decode header name...");
					if (state & HPack_Flags_Huffman_Name) {
						DPRINTF("Decode %" PRIuPTR
							" bytes of Huffman data...\n",
							length);
						unsigned int hrc;

						buffer_close(source, m);
						hrc =
						    huffman_decode_fragments
						    (source, buffer, length);
						if (unlikely(hrc)) {
							*rc = hrc;
							goto Bug;
						}
						field->name = buffer->str;
						n -= length;
						if (likely(n)) {
							src =
							    buffer_get(source,
								       &m);
						}
					} else {
						DPRINTF("Copy %" PRIuPTR
							" bytes of plain text...\n",
							length);
						HPACK_COPY_STRING(name);
					}
#if Debug_HPack
					printf("Decoded name: \"");
					buffer_str_print(&field->name);
					printf("\"\n");
#endif
					if (unlikely(n == 0)) {
						state &= ~HPack_State_Mask;
						state |= HPack_State_Value;
					}
				}
			case HPack_State_Value:
				{
					uchar c;

 Get_Value:
					DPUTS("Decode header value length...");
					if (unlikely(m == 0)) {
						src = buffer_next(source, &m);
					}
					c = *src++;
					n--;
					m--;
					length = c & 0x7F;
					if (c & 0x80) {
						DPRINTF("Name length: %" PRIuPTR
							"\n", length);
						state |=
						    HPack_Flags_Huffman_Value;
					}
					if (unlikely(length == 0x7F)) {
						state &= ~HPack_State_Mask;
						state |=
						    HPack_State_Value_Length;
						GET_FLEXIBLE(length);
					}
					DPRINTF("Value length: %" PRIuPTR "\n",
						length);
					field->value.len = length;
					if (n >= length) {
						goto Get_Value_Text;
					} else {
						state &= ~HPack_State_Mask;
						state |= HPack_State_Value_Text;
						goto Incomplete;
					}
				}
			case HPack_State_Value_Text:
				{
					uchar *dst;
					unsigned int hrc;

					length = field->value.len;
					if (unlikely(n < length)) {
						DPUTS("Not enough data...");
						break;
					}
 Get_Value_Text:
					DPUTS("Decode header value...");
					if (length) {
						if ((state & HPack_Flags_Pseudo)
						    == 0) {
							/* Add ":" between name and value: */
							dst =
							    buffer_small(buffer,
									 2, 1);
							dst[0] = ':';
							dst[1] = ' ';
						}
						if (state &
						    HPack_Flags_Huffman_Value) {
							DPRINTF("Decode %"
								PRIuPTR
								" bytes of Huffman data...\n",
								length);
							buffer_close(source, m);
							hrc =
							    huffman_decode_fragments
							    (source, buffer,
							     length);
							if (unlikely(hrc)) {
								*rc = hrc;
								goto Bug;
							}
							field->value =
							    buffer->str;
							n -= length;
							if (likely(n)) {
								src =
								    buffer_get
								    (source,
								     &m);
							}
						} else {
							DPRINTF("Copy %" PRIuPTR
								" bytes of plain text...\n",
								length);
							HPACK_COPY_STRING
							    (value);
						}
#if Debug_HPack
						printf("Decoded value: \"");
						buffer_str_print(&field->value);
						printf("\"\n");
#endif
					}
#if Debug_HPack
					else {
						DPUTS("Zero-length value");
					}
#endif
					if (index) {
 Duplicate:
						DPRINTF
						    ("Add header by dictionary index: %"
						     PRIuPTR "\n", index);
#if Fast_Capacity > 32
						if ((index >> 32) == 0) {
							hrc =
							    hpack_add_index(hp->
									    dynamic,
									    field,
									    index,
									    state,
									    buffer);
						} else {
							hrc =
							    Err_HTTP2_IntegerOveflow;
						}
#else
						hrc =
						    hpack_add_index(hp->dynamic,
								    field,
								    index,
								    state,
								    buffer);
#endif
					} else {
						DPUTS
						    ("Add header with name and value...");
						hrc =
						    hpack_add(hp->dynamic,
							      field, state,
							      buffer);
					}
					if ((state & HPack_Flags_Pseudo) == 0) {
						/* Add CR/LF after decoded field: */
						dst =
						    buffer_small(buffer, 2, 1);
						dst[0] = '\r';
						dst[1] = '\n';
					}
					if (hrc == 0) {
						DPUTS("New header added...");
						if (fp) {
							bp->next = field;
						} else {
							fp = field;
						}
						bp = field;
						field = NULL;
						state = HPack_State_Ready;
					} else {
						DPRINTF
						    ("New header was NOT ADDED, rc = %u\n",
						     hrc);
						*rc = hrc;
						goto Bug;
					}
				}
			}
		} while (n);
 Incomplete:
		hp->state = state;
		hp->field = field;
		buffer_close(source, m);
	}
	return fp;
 Overflow:
	*rc = Err_HTTP2_IntegerOverflow;
 Bug:
	if (field) {
		hp->field = NULL;
		buffer_str_free(pool, &field->name);
		buffer_str_free(pool, &field->value);
	}
	if (fp) {
		hpack_free_list(buffer, fp);
	}
	return NULL;
 Out_Of_Memory:
	*rc = Err_HTTP2_OutOfMemory;
	goto Bug;
}

static HTTP2Field *
hpack_list_reverse(HTTP2Field * const list)
{
	HTTP2Field *p = list;
	HTTP2Field *q = p->next;

	if (q) {
		p->next = NULL;
		do {
			HTTP2Field *n;

			n = q->next;
			q->next = p;
			if (n == NULL) {
				return q;
			}
			p = n->next;
			n->next = q;
			if (p == NULL) {
				return n;
			}
			q = p->next;
			p->next = n;
		} while (q);
	}
	return p;
}

void
hpack_free_list(HTTP2Output * __restrict buffer, HTTP2Field * __restrict p)
{
	TfwPool *__restrict pool = buffer->pool;

	if (p) {
		/* Reverse list to incease probability of successful */
		/* coalescence of the free memory blocks in the pool: */
		p = hpack_list_reverse(p);
		do {
			HTTP2Field *n = p->next;

			buffer_str_free(pool, &p->value);
			buffer_str_free(pool, &p->name);
			tfw_pool_free(pool, p, sizeof(HTTP2Field));
			p = n;
		} while (p);
	}
}

unsigned int
hpack_set_max_window(HPack * __restrict hp, unsigned int max_window)
{
#if Fast_Capacity > 32
	if (unlikely(max_window > (uint32_t) - 1)) {
		return Err_HPack_InvalidTableSize;
	}
#endif
	if (max_window == 0) {
		max_window = (uint32_t) - 1;
	}
	hp->max_window = max_window;
	if (unlikely(hp->window > max_window)) {
		hp->window = max_window;
		hpack_set_length(hp->dynamic, max_window);
	}
	return 0;
}

unsigned int
hpack_set_window(HPack * __restrict hp, unsigned int window)
{
	if (window <= hp->max_window) {
		hp->window = window;
		hpack_set_length(hp->dynamic, window);
		return 0;
	} else {
		return Err_HPack_InvalidTableSize;
	}
}

HPack *
hpack_new(unsigned int max_window, unsigned char is_encoder,
	  TfwPool * __restrict pool)
{
	HTTP2Index *__restrict dynamic;

#if Fast_Capacity > 32
	if (unlikely(max_window > (uint32_t) - 1)) {
		return NULL;
	}
#endif
	if (max_window == 0) {
		max_window = (uint32_t) - 1;
	}
	dynamic = hpack_new_index(max_window, is_encoder, pool);
	if (dynamic) {
		HPack *const __restrict hp =
		    tfw_pool_alloc(pool, sizeof(HPack));
		if (hp) {
			hp->state = HPack_State_Ready;
			hp->shift = 0;
			hp->saved = 0;
			hp->max_window = max_window;
			hp->window = max_window;
			hp->field = NULL;
			hp->pool = pool;
			hp->dynamic = dynamic;
		} else {
			hpack_free_index(dynamic);
		}
		return hp;
	}
	return NULL;
}

void
hpack_free(HPack * __restrict hp)
{
	HTTP2Field *const __restrict field = hp->field;
	TfwPool *const __restrict pool = hp->pool;

	if (field) {
		buffer_str_free(pool, &field->name);
		buffer_str_free(pool, &field->value);
	}
	hpack_free_index(hp->dynamic);
	tfw_pool_free(pool, hp, sizeof(HPack));
}

void
hpack_init(TfwPool * __restrict pool)
{
	hpack_index_init(pool);
}

void
hpack_shutdown(void)
{
	hpack_index_shutdown();
}
