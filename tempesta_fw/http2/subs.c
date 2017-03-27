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

#include "common.h"
#include "subs.h"

#ifndef offsetof
#define offsetof(x, y) ((uwide) &((x *) 0)->y))
#endif

#define Bit_UMul32(x, y) (uint32) ((x) * (y))

#define Sub_Shift(n) \
   Shift = (offsetof(Sub, Data) + (Word_Size - 1)) & \
				 ~(Word_Size - 1); \
   if ((n & (2 * Word_Size - 1)) == 0) { \
      Shift = (offsetof(Sub, Data) + (2 * Word_Size - 1)) & \
				    ~(2 * Word_Size - 1); \
   }

static void Sub_Chunk(Sub * const Object, void *const x, ufast n,
		      const ufast Length);

static void *Sub_Allocate_Tail(Sub * const Object, ufast n, void * *q);

Sub *
Sub_New_Internal(const char *const Name, const fast Length,
		 const fast Initial, const fast Quant, TfwPool * const hp)
{
	if (Length >= 1) {
		const ufast n = (Length + (Word_Size - 1)) & ~(Word_Size - 1);

		if ((Quant | Initial) >= 0) {
			ufast Allocated;
			Sub *Object;

			if (Initial) {
				ufast Shift;

				Sub_Shift(Length);
				Allocated = Shift + Bit_UMul32(n, Initial);
				Object = tfw_pool_alloc(hp, Allocated);
				if (unlikely(Object == NULL)) {
					return NULL;
				}
				Object->Allocated = Allocated;
				Sub_Chunk(Object, (byte *) Object + Shift,
					  Initial, n);
			} else {
				Allocated = offsetof(Sub, Data);
				Object =
				    tfw_pool_alloc(hp, offsetof(Sub, Data));
				if (unlikely(Object == NULL)) {
					return NULL;
				}
				Object->Next.p = NULL;
			}
			Object->Block = 0;
			Object->Length = n;
			Object->heap = hp;
			Object->Chunk.p = NULL;
			Object->Initial = Initial;
			Object->Quant = Quant;
			Object->Name = Name;
			Object->True_Length = Length;
			Object->Allocated = Allocated;
			if (Quant) {
				Object->Block = Bit_UMul32(n, Quant);
			}
			return Object;
		}
	}
	return NULL;
}

static void
Sub_Chunk(Sub * const Object, void *const x, ufast n, const ufast Length)
{
	void **p = x;
	void **q;

	Object->Next.p = x;
	while (--n) {
		q = (void * *)((byte *) p + Length);
		*p = q;
		if (--n) {
			p = (void * *)((byte *) q + Length);
			*q = p;
		} else {
			*q = NULL;
			return;
		}
	}
	*p = NULL;
}

ufast
Sub_Query_Length(const Sub * const Object)
{
	return Object->Length;
}

void *
Sub_Allocate2(Sub * const Object)
{
	const ufast b = Object->Block;
	TfwPool *const hp = Object->heap;

	if (b) {
		ufast n;
		byte *const Chunk = tfw_pool_alloc(hp, b + sizeof(void *));
		void **const Tail = (void * *)(Chunk + b);

		if (unlikely(Chunk == NULL)) {
			return NULL;
		}
		n = Object->Quant;
		*Tail = Object->Chunk.p;
		Object->Chunk.p = Tail;
		if (--n) {
			const ufast m = Object->Length;

			Sub_Chunk(Object, Chunk + m, n, m);
		}
		return Chunk;
	} else {
		return NULL;
	}
}

void
Sub_Free_List(Sub * const Object, void *const First_Element)
{
	void **p = First_Element;
	void **q;

	do {
		q = p;
		p = *p;
	} while (p);
	*q = Object->Next.p;
	Object->Next.p = First_Element;
}

void *
Sub_Allocate_List(Sub * const Object, const fast Count, void *const Last)
{
	if (Count >= 1) {
		void **p;
		void **q;
		void **Next = Object->Next.p;

		if (Count != 1) {
			ufast n = Count;

			if (Next) {
				p = Next;
				do {
					q = Next;
					Next = *Next;
					if (--n == 0) {
						goto L1;
					}
				} while (Next);
				q = Sub_Allocate_Tail(Object, n, q);
			} else {
				q = Sub_Allocate_Tail(Object, n, (void *)&p);
			}
		} else {
			if (Next) {
				q = Next;
				p = Next;
				Next = *Next;
 L1:				Object->Next.p = Next;
			} else {
				q = Sub_Allocate2(Object);
				p = q;
			}
		}
		*q = NULL;
		if (Last) {
			*(void * *)Last = q;
		}
		return p;
	} else {
		return NULL;
	}
}

static void *
Sub_Allocate_Tail(Sub * const Object, ufast n, void * *q)
{
	const ufast b = Object->Block;
	TfwPool *const hp = Object->heap;

	if (b) {
		ufast k, l;
		void **Next;
		byte *cp;
		byte *cf;

		cp = tfw_pool_alloc(hp, b + sizeof(void *));
		cf = cp + b;
		k = Object->Quant;
		l = Object->Length;
		while (k < n) {
			ufast m;

			Next = (void * *)cp;
			n = n - k;
			m = k;
			do {
				*q = Next;
				q = Next;
				Next = (void * *)((byte *) Next + l);
			} while (--m);
			cp = tfw_pool_alloc(hp, b + sizeof(void *));
			*Next = (void * *)(cp + b);
		}
		*(void * *)(cp + b) = Object->Chunk.p;
		Object->Chunk.p = (void *)cf;
		Next = (void * *)cp;
		k = k - n;
		do {
			*q = Next;
			q = Next;
			Next = (void * *)((byte *) Next + l);
		} while (--n);
		*q = NULL;
		if (k) {
			Sub_Chunk(Object, Next, k, l);
		} else {
			Object->Next.p = NULL;
		}
		return q;
	} else {
		return NULL;
	}
}

void
Sub_Delete(Sub * const Object)
{
	TfwPool *const hp = Object->heap;
	void **p = Object->Chunk.p;

	if (p) {
		const ufast b = Object->Block;

		do {
			byte *const q = (byte *) p - b;

			p = *p;
			tfw_pool_free(hp, q, b + sizeof(void *));
		} while (p);
	}
	tfw_pool_free(hp, Object, Object->Allocated);
}

void
Sub_Clear(Sub * const Object)
{
	void **p;
	const ufast Initial = Object->Initial;

	Object->Next.p = NULL;
	if (Initial) {
		ufast Shift;
		const ufast n = Object->Length;

		Sub_Shift(Object->True_Length);
		Sub_Chunk(Object, (byte *) Object + Shift, Initial, n);
	}
	p = Object->Chunk.p;
	if (p) {
		TfwPool *const hp = Object->heap;
		const ufast b = Object->Block;

		Object->Chunk.p = NULL;
		do {
			byte *const q = (byte *) p - b;

			p = *p;
			tfw_pool_free(hp, q, b + sizeof(void *));
		} while (p);
	}
}
