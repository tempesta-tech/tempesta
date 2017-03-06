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
#include "errors.h"
#include "hpack.h"

typedef struct {
	TfwStr name;
	TfwStr value;
} HPackEntry;

struct HTTP2Index {
	ufast	  window;  /* Maximal pseudo-length of the dynamic */
			   /* table (in bytes). This value used as */
			   /* threshold to flushing old entries. */
	ufast	  size;    /* Current pseudo-length of the dynamic */
			   /* table (in bytes). */
	ufast	  n;	   /* Current length of the dynamic table */
			   /* (in entries). */
	ufast	  current; /* Circular buffer pointer to recent entry. */
	ufast	  length;  /* Real number of allocated entries. */
	HPackEntry
		* entries; /* Dynamic tabl entries. */
	TfwPool * pool;    /* Memory pool, which used for dynamic */
			   /* headers table. */
};

ufast
hpack_add (HTTP2Index * __restrict ip,
	   HTTP2Field * __restrict fp,
	   ufast		   flags);

ufast
hpack_add_index (HTTP2Index * __restrict ip,
		 HTTP2Field * __restrict fp,
		 ufast			 index,
		 ufast			 flags);

void
hpack_set_window (HTTP2Index * __restrict ip,
		  ufast 		  window);

HTTP2Index *
hpack_new_index (ufast		      window,
		 TfwPool * __restrict pool);

void
hpack_free_index (HTTP2Index * __restrict ip);

#endif
