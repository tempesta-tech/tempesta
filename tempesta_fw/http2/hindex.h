/**
 *		Tempesta FW
 *
 * Indexing of the HPACK static and dynamic tables
 * for headers compression.
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

#ifndef HPACK_INDEX_H
#define HPACK_INDEX_H

#include "common.h"
#include "../pool.h"
#include "../str.h"
#include "subs.h"
#include "hash.h"
#include "errors.h"
#include "hpack.h"

/* HPack string (used for the various buffers): */

enum {
	HPack_Arena_Static = 0, /* String resides in the static memory.     */
	HPack_Arena_Dynamic,	/* String allocated from the classic heap.  */
	HPack_Arena_User	/* String allocated from the user-conrolled */
				/* memory (in form of the TfwStr).	    */
};

/* ptr:   Pointer to the static memory block (plain, may be directly  */
/*	  copied via memcpy), or pointer to the dynamically allocated */
/*	  memory block (allocated from the classic heap, data may be  */
/*	  directly copyied via memcpy), or pointer to the TfwStr      */
/*	  descriptor (when the data resides in the user-contolled     */
/*	  memory and must be manipulated taking into account TfwStr   */
/*	  structure).						      */
/* len:   Total length of the string.				      */
/* arena: Allocator that is used for this memory block. 	      */
/* count: Reference counter.					      */

typedef struct {
	void *ptr;
	uwide len;
	uint8 arena;
	uint32 count;
} HPackStr;

/* Ring buffer (dictionary) entry: */

typedef struct {
	HPackStr *name;
	HPackStr *value;
} HPackEntry;

/* HPack index structure: */

/* n:	       Current length of the dynamic table	*/
/*	       (in entries).				*/
/* current:    Circular buffer pointer to recent entry. */
/* length:     Real number of allocated entries.	*/
/* size:       Current pseudo-length of the dynamic	*/
/*	       headers table (in bytes).		*/
/* window:     Maximum pseudo-length of the dynamic	*/
/*	       table (in bytes). This value used as	*/
/*	       threshold to flushing old entries.	*/
/* entries:    Dynamic table entries.			*/
/* sub:        Sub-allocator for HPackStr descriptors.	*/
/* is_encoder: Non-zero if HPack index used by encoder. */
/* hash:       Hash table texts of names and values.	*/
/* pairs:      Hash table with {name, value} tuples.	*/
/* names:      Hash table with name pointers.		*/
/* pool:       Memory pool, which used for dynamic	*/
/*	       table.					*/

struct HTTP2Index {
	ufast n;
	ufast current;
	ufast length;
	ufast size;
	ufast window;
	HPackEntry *entries;
	Sub *sub;
	byte is_encoder;
	Hash *hash;
	Hash *pairs;
	Hash *names;
	TfwPool *pool;
};

ufast hpack_add(HTTP2Index * __restrict ip,
		HTTP2Field * __restrict fp,
		ufast flags, HTTP2Output * __restrict out);

ufast hpack_add_index(HTTP2Index * __restrict ip,
		      HTTP2Field * __restrict fp,
		      ufast index, ufast flags, HTTP2Output * __restrict out);

HPackStr *hpack_find_string(HTTP2Index * __restrict ip,
			    HPackStr * __restrict name);

ufast hpack_find_entry(HTTP2Index * __restrict ip,
		       HPackStr * __restrict name,
		       HPackStr * __restrict value, ufast * __restrict flags);

void hpack_set_length(HTTP2Index * __restrict ip, ufast window);

HTTP2Index *hpack_new_index(ufast window, byte is_encoder,
			    TfwPool * __restrict pool);

void hpack_free_index(HTTP2Index * __restrict ip);

void hpack_index_init(TfwPool * __restrict pool);

void hpack_index_shutdown(void);

void hpack_str_print(const HPackStr * __restrict str);

#endif
