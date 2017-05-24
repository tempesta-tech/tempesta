/**
 *		Tempesta FW
 *
 * Hash tables: simple hash table with collision chains.
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

#ifndef HASH_H
#define HASH_H

#include "common.h"
#include "../pool.h"

typedef struct Hash Hash;

typedef unsigned int
 Hash_Equal(const void *const x, const void *const y);

typedef uintptr_t Hash_Function(const void *const Name);

typedef void

Hash_Iterator_Function(const void *const Key,
		       void *const Value, void *const User);

typedef unsigned int

Hash_Iterator_Function2(const void *const Key,
			void *const Value, void *const User);

typedef unsigned int
 Hash_Filter_Function(void *const Key, void *const Value, void *const User);

/* Hash table control functions: */

Hash *Hash_New(const char *__restrict const Name,
	       const int Initial_Size,
	       const int Minimal_Size,
	       const int Quant,
	       Hash_Function * const Function,
	       Hash_Equal * const Equal_Function,
	       TfwPool * __restrict const hp);
void
 Hash_Free(Hash * __restrict const ht);
void

Hash_Free2(Hash * __restrict const ht,
	   Hash_Iterator_Function * const Function, void *const User);
void
 Hash_Clear(Hash * __restrict const ht);
void

Hash_Clear2(Hash * __restrict const ht,
	    Hash_Iterator_Function * const Function, void *const User);
uintptr_t Hash_Count(const Hash * __restrict const ht);

/* Hash table manipulation functions: */

unsigned int

Hash_SoftAdd(Hash * __restrict const ht,
	     const void *__restrict const Key,
	     const void *__restrict const Value);
void *Hash_FindAdd(Hash * __restrict const ht,
		   const void *__restrict const Key,
		   const void *__restrict const Value);
void *Hash_Replace(Hash * __restrict const ht,
		   const void *__restrict const Key,
		   const void *__restrict const Value);
void *Hash_Change(const Hash * __restrict const ht,
		  const void *__restrict const Key,
		  const void *__restrict const Value);
void *Hash_SoftDelete(Hash * __restrict const ht,
		      const void *__restrict const Key);
void *Hash_Find(const Hash * __restrict const ht,
		const void *__restrict const Key);
void

Hash_Iterator(const Hash * __restrict const ht,
	      Hash_Iterator_Function * const Function, void *const User);
unsigned int

Hash_Iterator2(const Hash * __restrict const ht,
	       Hash_Iterator_Function2 * const Function, void *const User);
void

Hash_Filter(Hash * __restrict const ht,
	    Hash_Filter_Function * const Function, void *const User);

#define Hash_Delete Hash_SoftDelete
#define Hash_Add Hash_SoftAdd

uintptr_t Byte_Hash_Chain(const void *__restrict const x,
			  const uintptr_t Length, const unsigned int Shift);

#endif
