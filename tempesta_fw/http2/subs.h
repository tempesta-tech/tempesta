/**
 *		Tempesta FW
 *
 * Sub-allocator: simple pool of equal-sized elements.
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

#ifndef SUBS_H
#define SUBS_H

#include <inttypes.h>

#include "../pool.h"

/*
 * Remove aliasing effects from the pointer, because ANSI-compliant
 * compiler should assume that any  pointer to a union, which containing
 * "char", potentially overlap with any other pointers in the program:
 */
typedef union {
	char  c;
	void *p;
} AntiAliasType;

#define AntiAliasLink(x) ((AntiAliasType *) (x))->p

typedef struct Sub Sub;

typedef void *Sub_Allocate_Function(Sub * const Object);
typedef void
 Sub_Free_Function(Sub * const Object, void *const Block);
typedef void
 Sub_Free_Chain_Function(Sub * const Object, void *const p, void *const q);

typedef struct {
	void *p;
} SList;

#define Synch_New(x, y) x.p = y

struct Sub {
/* Next field must be first field in the structure: */
	SList Next;
	uint32_t Block;
	uint32_t Length;
	TfwPool *heap;
	SList Chunk;
	uint32_t Initial;
	uint32_t Quant;
	const char *Name;
	uint32_t True_Length;
	uint32_t Allocated;
	unsigned char Data[1];
};

#define Sub_New(Name, Length, Initial, Quant, Heap) \
	Sub_New_Internal(Name, Length, Initial, Quant, Heap)

Sub *Sub_New_Internal(const char *const Name,
		      const int Length,
		      const int Initial, const int Quant, TfwPool * const hp);
void *Sub_Allocate2(Sub * const Object);
void Sub_Delete(Sub * const Object);
void Sub_Clear(Sub * const Object);
void *Sub_Allocate_List(Sub * const Object, const int Count, void *const Last);
void Sub_Free_List(Sub * const Object, void *const First_Element);
unsigned int Sub_Query_Length(const Sub * const Object);

static __inline__ void *
Sub_Allocate(Sub * const Object)
{
	void **const Block = Object->Next.p;

	if (Block) {
		Object->Next.p = (void * *)*Block;
		return Block;
	} else {
		return Sub_Allocate2(Object);
	}
}

static __inline__ void
Sub_Free(Sub * const Object, void *const Block)
{
	AntiAliasLink(Block) = Object->Next.p;
	Object->Next.p = (void * *)Block;
}

static __inline__ void
Sub_Free_Chain(Sub * const Object, void *const p, void *const q)
{
	AntiAliasLink(q) = Object->Next.p;
	Object->Next.p = (void * *)p;
}

#endif
