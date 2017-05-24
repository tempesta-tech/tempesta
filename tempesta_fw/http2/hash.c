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

#include <stdint.h>
#include <string.h>
#include "common.h"
#include "../pool.h"
#include "bits.h"
#include "subs.h"
#include "rotate.h"
#include "hash.h"

typedef struct Hash_Entry {
	struct Hash_Entry *Next;
	const void *Name;
	void *Value;
} Hash_Entry;

/* Mask:	  Current hash function mask. */
/* Count:	  Number of elements in hash table. */
/* Index:	  Hash table index. */
/* Function:	  Hash function. */
/* Equal:	  Equivalence function. */
/* Pool:	  Pool for hash table elements. */
/* Threshold:	  Index growth threshold. */
/* Minimal:	  Index compactification threshold. */
/* Initial_Size:  Initial table length. */
/* Minimal_Size:  Minimal index length. */
/* Initial_Bound: Initial index threshold. */
/* Quant:	  Extension quant. */
/* heap:	  Heap used by hash table structures. */
/* Name:	  Hash table name. */
/* Index_Size:	  Amount of memory allocated for index. */

struct Hash {
	uintptr_t Mask;
	uintptr_t Count;
	Hash_Entry **Index;
	Hash_Function *Function;
	Hash_Equal *Equal;
	Sub *Pool;
	uintptr_t Threshold;
	uintptr_t Minimal;
	uint32_t Initial_Size;
	uint32_t Minimal_Size;
	uint32_t Initial_Bound;
	uint32_t Quant;
	TfwPool *heap;
	const char *Name;
	uintptr_t Index_Size;
};

static Hash_Entry **Hash_Reindex(Hash * __restrict const ht,
				 Hash_Entry * *__restrict const x,
				 const uintptr_t m, uintptr_t n);
static void Hash_Expand(Hash * __restrict const ht, uintptr_t m);
static void Hash_Compact(Hash * __restrict const ht, const uintptr_t n);
static void Hash_Compress(Hash * __restrict const ht, const uintptr_t c);

/* ------------------------------------------- */
/* Some helper routines:		       */
/* ------------------------------------------- */

local_function uintptr_t
HF(const uintptr_t k)
{
#ifdef __GNUC__
	return Bit_CRC(k, k);
#else
	return k * 2654435769U ^ k;
#endif
}

Hash *
Hash_New(const char *__restrict const Name,
	 const int Initial_Size,
	 const int Minimal_Size,
	 const int Quant,
	 Hash_Function * const Function,
	 Hash_Equal * const Equal_Function, TfwPool * __restrict const hp)
{
	if ((Initial_Size | Quant) >= 0 && Minimal_Size >= -1) {
		uintptr_t Index_Size;
		uintptr_t Size;
		uintptr_t Threshold;
		uintptr_t Minimal = Minimal_Size;
		Hash *__restrict ht;
		Hash_Entry **__restrict Index;

		if (Initial_Size) {
			Size = Bit_UpPowerOfTwo((Initial_Size + 7) & ~7);
			Threshold = Size;
			if (Size > 32) {
				Threshold = Size - Size / 4;
			}
			if (Minimal == 0) {
				Minimal = Size;
			}
		} else {
			Size = 32;
			Threshold = 32;
		}
		ht = tfw_pool_alloc(hp, sizeof(Hash));
		Index_Size = Size * sizeof(Hash_Entry *);
		Index = tfw_pool_alloc(hp, Index_Size);
		memset(Index, 0, Size * sizeof(Hash_Entry *));
		ht->Mask = Size - 1;
		ht->Count = 0;
		ht->Index = Index;
		ht->Pool = Sub_New(Name, sizeof(Hash_Entry), Size, Quant, hp);
		ht->Function = Function;
		ht->Equal = Equal_Function;
		Threshold++;
		ht->Threshold = Threshold;
		ht->Minimal = 0;
		ht->Initial_Size = Size;
		ht->Minimal_Size = Minimal;
		ht->Initial_Bound = Threshold;
		ht->Quant = Quant;
		ht->heap = hp;
		ht->Name = Name;
		ht->Index_Size = Index_Size;
		return ht;
	} else {
		return NULL;
	}
}

void
Hash_Free(Hash * __restrict const ht)
{
	TfwPool *__restrict const hp = ht->heap;

	Sub_Delete(ht->Pool);
	tfw_pool_free(hp, ht->Index, ht->Index_Size);
	tfw_pool_free(hp, ht, sizeof(Hash));
}

void
Hash_Free2(Hash * __restrict const ht,
	   Hash_Iterator_Function * const Function, void *const User)
{
	Hash_Iterator(ht, Function, User);
	Hash_Free(ht);
}

void
Hash_Clear(Hash * __restrict const ht)
{
	const uintptr_t Current = ht->Mask + 1;
	uintptr_t m = ht->Initial_Size;
	Hash_Entry **__restrict Index;

	if (m < Current) {
		TfwPool *__restrict const hp = ht->heap;

		ht->Mask = m - 1;
		tfw_pool_free(hp, ht->Index, ht->Index_Size);
		Index = tfw_pool_alloc(hp, m * sizeof(Hash_Entry *));
		ht->Index_Size = m * sizeof(Hash_Entry *);
		ht->Index = Index;
		ht->Threshold = ht->Initial_Bound;
 L0:		ht->Count = 0;
		memset(Index, 0, m * sizeof(Hash_Entry *));
	} else if (ht->Count) {
		Index = ht->Index;
		m = Current;
		goto L0;
	}
	ht->Minimal = 0;
	Sub_Clear(ht->Pool);
}

void
Hash_Clear2(Hash * __restrict const ht,
	    Hash_Iterator_Function * const Function, void *const User)
{
	Hash_Iterator(ht, Function, User);
	Hash_Clear(ht);
}

uintptr_t
Hash_Count(const Hash * __restrict const ht)
{
	return ht->Count;
}

unsigned int
Hash_SoftAdd(Hash * __restrict const ht,
	     const void *__restrict const Name,
	     const void *__restrict const Value)
{
	Hash_Entry *__restrict h;
	Hash_Entry **__restrict Previous;
	const uintptr_t Code = HF(ht->Function(Name));

	Previous = &ht->Index[Code & ht->Mask];
	h = *Previous;
	while (h) {
		if (ht->Equal(Name, h->Name)) {
			return 0;
		}
		Previous = &h->Next;
		h = h->Next;
	}
	h = Sub_Allocate(ht->Pool);
	*Previous = h;
	h->Next = NULL;
	h->Name = Name;
	h->Value = (void *)Value;
	if (++ht->Count == ht->Threshold) {
		Hash_Expand(ht, ht->Mask);
	}
	return 1;
}

void *
Hash_FindAdd(Hash * __restrict const ht,
	     const void *__restrict const Name,
	     const void *__restrict const Value)
{
	Hash_Entry *__restrict h;
	Hash_Entry **__restrict Previous;
	const uintptr_t Code = HF(ht->Function(Name));

	Previous = &ht->Index[Code & ht->Mask];
	h = *Previous;
	while (h) {
		if (ht->Equal(Name, h->Name)) {
			return h->Value;
		}
		Previous = &h->Next;
		h = h->Next;
	}
	h = Sub_Allocate(ht->Pool);
	*Previous = h;
	h->Next = NULL;
	h->Name = Name;
	h->Value = (void *)Value;
	if (++ht->Count == ht->Threshold) {
		Hash_Expand(ht, ht->Mask);
	}
	return NULL;
}

void *
Hash_Replace(Hash * __restrict const ht,
	     const void *__restrict const Name,
	     const void *__restrict const Value)
{
	Hash_Entry *__restrict h;
	Hash_Entry **__restrict Previous;
	const uintptr_t Code = HF(ht->Function(Name));

	Previous = &ht->Index[Code & ht->Mask];
	h = *Previous;
	while (h) {
		if (ht->Equal(Name, h->Name)) {
			void *__restrict Old = h->Value;

			h->Value = (void *)Value;
			return Old;
		}
		Previous = &h->Next;
		h = h->Next;
	}
	h = Sub_Allocate(ht->Pool);
	*Previous = h;
	h->Next = NULL;
	h->Name = Name;
	h->Value = (void *)Value;
	if (++ht->Count == ht->Threshold) {
		Hash_Expand(ht, ht->Mask);
	}
	return NULL;
}

void *
Hash_SoftDelete(Hash * __restrict const ht, const void *__restrict const Name)
{
	Hash_Entry *__restrict h;
	Hash_Entry **__restrict Previous;
	const uintptr_t Code = HF(ht->Function(Name));

	Previous = &ht->Index[Code & ht->Mask];
	h = *Previous;
	while (h) {
		if (ht->Equal(Name, h->Name)) {
			void *__restrict Value;

			*Previous = h->Next;
			Value = h->Value;
			Sub_Free(ht->Pool, h);
			if (--ht->Count >= ht->Minimal) {
				return Value;
			} else {
				Hash_Compact(ht, ht->Mask);
				return Value;
			}
		}
		Previous = &h->Next;
		h = h->Next;
	}
	return NULL;
}

static Hash_Entry **
Hash_Reindex(Hash * __restrict const ht,
	     Hash_Entry * *__restrict const x, const uintptr_t m, uintptr_t n)
{
	Hash_Entry **__restrict y;
	Hash_Entry **__restrict z;
	Hash_Function *const f = ht->Function;

	ht->Mask = m;
	ht->Threshold = m - m / 4 + 1;
	y = ht->Index;
	ht->Index = x;
	z = y;
	if (ht->Count) {
		do {
			Hash_Entry *__restrict h = *y++;

			while (h) {
				uintptr_t c;
				Hash_Entry *__restrict p;
				Hash_Entry *__restrict q;

				c = HF(f(h->Name)) & m;
				p = x[c];
				x[c] = h;
				q = h->Next;
				h->Next = p;
				if (q == NULL)
					break;
				c = HF(f(q->Name)) & m;
				p = x[c];
				x[c] = q;
				h = q->Next;
				q->Next = p;
			}
		} while (--n);
	}
	return z;
}

static void
Hash_Expand(Hash * __restrict const ht, uintptr_t m)
{
	TfwPool *__restrict hp;
	Hash_Entry **__restrict x;
	Hash_Entry **__restrict y;
	uintptr_t Index_Size;
	uintptr_t l;
	uintptr_t t;
	uintptr_t n = m + 1;

	m += n;
	l = m + 1;
	t = l / 3;
	if (t < ht->Minimal_Size) {
		t = 0;
	}
	ht->Minimal = t;
	hp = ht->heap;
	Index_Size = l * sizeof(Hash_Entry *);
	x = tfw_pool_alloc(hp, Index_Size);
	memset(x, 0, Index_Size);
	y = Hash_Reindex(ht, x, m, n);
	tfw_pool_free(hp, y, ht->Index_Size);
	ht->Index_Size = Index_Size;
}

static void
Hash_Compact(Hash * __restrict const ht, const uintptr_t n)
{
	uintptr_t m, l, t;
	uintptr_t Index_Size;
	TfwPool *__restrict hp;
	Hash_Entry **__restrict x;
	Hash_Entry **__restrict y;

	m = n / 2;
	t = 0;
	l = m + 1;
	if (m != 7) {
		t = l / 3;
		if (t < ht->Minimal_Size) {
			t = 0;
		}
	}
	ht->Minimal = t;
	hp = ht->heap;
	Index_Size = l * sizeof(Hash_Entry *);
	x = tfw_pool_alloc(hp, Index_Size);
	memset(x, 0, Index_Size);
	y = Hash_Reindex(ht, x, m, n + 1);
	tfw_pool_free(hp, y, ht->Index_Size);
	ht->Index_Size = Index_Size;
}

static void
Hash_Compress(Hash * __restrict const ht, const uintptr_t c)
{
	uintptr_t Index_Size;
	uintptr_t m, t;
	TfwPool *__restrict hp;
	Hash_Entry **__restrict x;
	Hash_Entry **__restrict y;

	m = 8;
	t = 0;
	if (c > 8) {
		m = Bit_UpPowerOfTwo(c);
		t = m / 3;
		if (t < ht->Minimal_Size) {
			t = 0;
		}
	}
	ht->Minimal = t;
	hp = ht->heap;
	Index_Size = m * sizeof(Hash_Entry *);
	x = tfw_pool_alloc(hp, Index_Size);
	memset(x, 0, Index_Size);
	y = Hash_Reindex(ht, x, m - 1, ht->Mask + 1);
	tfw_pool_free(hp, y, ht->Index_Size);
	ht->Index_Size = Index_Size;
}

void *
Hash_Find(const Hash * __restrict const ht, const void *__restrict const Name)
{
	const Hash_Entry *__restrict h =
	    ht->Index[HF(ht->Function(Name)) & ht->Mask];
	if (h) {
		Hash_Equal *const Equal = ht->Equal;

		do {
			if (Equal(Name, h->Name)) {
				return h->Value;
			}
			h = h->Next;
		} while (h);
	}
	return NULL;
}

void *
Hash_Change(const Hash * __restrict const ht,
	    const void *__restrict const Name,
	    const void *__restrict const Value)
{
	Hash_Entry *__restrict h = ht->Index[HF(ht->Function(Name)) & ht->Mask];
	Hash_Equal *const Equal = ht->Equal;

	while (h) {
		if (Equal(Name, h->Name)) {
			void *__restrict Old = h->Value;

			h->Value = (void *)Value;
			return Old;
		}
		h = h->Next;
	}
	return NULL;
}

void
Hash_Iterator(const Hash * __restrict const ht,
	      Hash_Iterator_Function * const Function, void *const User)
{
	uintptr_t c = ht->Count;

	if (c) {
		Hash_Entry *__restrict const *__restrict x = ht->Index;

		do {
			Hash_Entry *__restrict p;

			do {
				p = *x++;
			} while (p == NULL);
			do {
				Function(p->Name, p->Value, User);
				p = p->Next;
				c--;
			} while (p);
		} while (c);
	}
}

unsigned int
Hash_Iterator2(const Hash * __restrict const ht,
	       Hash_Iterator_Function2 * const Function, void *const User)
{
	uintptr_t c = ht->Count;

	if (c) {
		Hash_Entry *__restrict const *__restrict x = ht->Index;

		do {
			Hash_Entry *__restrict p;

			do {
				p = *x++;
			} while (p == NULL);
			do {
				unsigned int rc =
				    Function(p->Name, p->Value, User);
				if (unlikely(rc)) {
					return rc;
				}
				p = p->Next;
				c--;
			} while (p);
		} while (c);
	}
	return 0;
}

void
Hash_Filter(Hash * __restrict const ht,
	    Hash_Filter_Function * const Function, void *const User)
{
	uintptr_t c = ht->Count;

	if (c) {
		Hash_Entry **__restrict x = ht->Index;
		uintptr_t n = ht->Mask + 1;
		uintptr_t l;

		do {
			Hash_Entry *__restrict p = *x;

			if (p) {
				Hash_Entry **__restrict b = x;

				do {
					if (Function
					    ((void *)p->Name, p->Value,
					     User) == 0) {
						b = &p->Next;
						p = p->Next;
					} else {
						Hash_Entry *__restrict const r =
						    p;
						p = p->Next;
						Sub_Free(ht->Pool, r);
						*b = p;
						if (--c == 0) {
							goto E0;
						}
					}
				} while (p);
			}
			x = x + 1;
		} while (--n);
 E0:
		l = ht->Count;
		if (c != l) {
			ht->Count = c;
			if (c < ht->Minimal) {
				Hash_Compress(ht, c);
			}
		}
	}
}

uintptr_t
Byte_Hash_Chain(const void *__restrict const x, const uintptr_t Length,
		const unsigned int Shift)
{
	const unsigned char *__restrict t = x;
	uintptr_t m;
	uintptr_t n = Length;
	uintptr_t h = 0;
	unsigned int l = (uintptr_t) t & (sizeof(uintptr_t) - 1);

	if (l) {
		l = sizeof(uintptr_t) - l;
		if (n >= l) {
			n = n - l;
#ifdef Platform_Big
			if (l & 1) {
				h = *t++;
			}
#ifdef Platform_32bit
			if (l >= 2) {
#else
			if (l & 2) {
#endif
				h = Bit_Shift(h, 16, *(uint16_t *) t);
				t = t + 2;
			}
#ifdef Platform_64bit
			if (l >= 4) {
				h = Bit_Shift(h, 32, *(uint32_t *) t);
				t = t + 4;
			}
#endif
#else
#ifdef Platform_32bit
			if (l & 1) {
				h = *t++ << 24;
			}
			if (l >= 2) {
#if defined(Compiler_Rotate) && ! defined(_MSC_VER)
				h = Rotate_Left(h | *(uint16_t *) t, 16);
#else
				h = Bit_Shift(*(uint16_t *) t, 16, h >> 16);
#endif
				t = t + 2;
			}
#else
			if (l & 1) {
				h = (uintptr_t) * t++ << 56;
			}
			if (l & 2) {
#if defined(Compiler_Rotate64)
				h = Rotate_Left(h | *(uint16_t *) t, 48);
#else
				h = Bit_Shift((uintptr_t) * (uint16_t *) t, 48,
					      h >> 16);
#endif
				t = t + 2;
			}
			if (l >= 4) {
#if defined(Compiler_Rotate64)
				h = Rotate_Left(h | *(uint32_t *) t, 32);
#else
				h = Bit_Shift((uintptr_t) * (uint32_t *) t, 32,
					      h >> 32);
#endif
				t = t + 4;
			}
#endif
#endif
		} else {
#ifdef Platform_32bit
#ifdef Platform_Little
			h = *t++;
			if (n == 2) {
				h = Bit_Join8(*t, h);
			}
#else
			h = *t++ << 24;
			if (n == 2) {
				h = Bit_Shift(*t, 16, h);
			}
#endif
#else
#ifdef Platform_Little
			unsigned int s = (l & 1) << 3;

			if (s) {
				h = *t;
				if (--n == 0) {
					goto L0;
				}
				t = t + 1;
			}
			if (n >= 2) {
				h = Bit_Shift((uintptr_t) * (uint16_t *) t, s,
					      h);
				n = n - 2;
				if (n == 0) {
					goto L0;
				}
				t = t + 2;
				s = s + 16;
				if (n >= 2) {
					h = Bit_Shift((uintptr_t) *
						      (uint16_t *) t, s, h);
					if (n == 2) {
						goto L0;
					}
					t = t + 2;
					s = s + 16;
				}
			}
			h = Bit_Shift((uintptr_t) * t, s, h);
#else
			unsigned int s = 64;

			if (l & 1) {
				h = (uintptr_t) * t << 56;
				if (--n == 0) {
					goto L0;
				}
				t = t + 1;
				s = 56;
			}
			if (n >= 2) {
				s = s - 16;
				h = Bit_Shift((uintptr_t) * (uint16_t *) t, s,
					      h);
				n = n - 2;
				if (n == 0) {
					goto L0;
				}
				t = t + 2;
				if (n >= 2) {
					s = s - 16;
					h = Bit_Shift((uintptr_t) *
						      (uint16_t *) t, s, h);
					if (n == 2) {
						goto L0;
					}
					t = t + 2;
				}
			}
			h = Bit_Shift((uintptr_t) * t, s - 8, h);
#endif
 L0:
#endif
#ifdef Platform_Little
			return Rotate_Left(h, (Shift & (Word_Size - 1)) * 8);
#else
			return Rotate_Right(h, (Shift & (Word_Size - 1)) * 8);
#endif
		}
	}
	l = (l + Shift) & (Word_Size - 1);
	m = n / sizeof(uintptr_t);
	if (m) {
		do {
			h = h ^ *(uintptr_t *) t;
			t = t + sizeof(uintptr_t);
		} while (--m);
	}
	if (n & (sizeof(uintptr_t) - 1)) {
		unsigned int s;

#ifdef Platform_Little
#ifdef Platform_64bit
		s = (n & 4) << 3;
		if (s) {
			h = h ^ *(uint32_t *) t;
			t = t + 4;
		}
		if (n & 2) {
			h = h ^ ((uintptr_t) * (uint16_t *) t << s);
			t = t + 2;
			s = s + 16;
		}
		if (n & 1) {
			h = h ^ ((uintptr_t) * t << s);
		}
#else
		s = n & 2;
		if (s) {
			h = h ^ *(uint16_t *) t;
			t = t + 2;
		}
		if (n & 1) {
			h = h ^ (*t << (s << 3));
		}
#endif
#else
#ifdef Platform_64bit
		s = 64;
		if (n & 4) {
			h = h ^ ((uintptr_t) * (uint32_t *) t << 32);
			t = t + 4;
			s = 32;
		}
		if (n & 2) {
			s = s - 16;
			h = h ^ ((uintptr_t) * (uint16_t *) t << s);
			t = t + 2;
		}
		if (n & 1) {
			h = h ^ ((uintptr_t) * t << (s - 8));
		}
#else
		s = 24;
		if (n & 2) {
			h = h ^ (*(uint16_t *) t << 16);
			t = t + 2;
			s = 8;
		}
		if (n & 1) {
			h = h ^ (*t << s);
		}
#endif
#endif
	}
#ifdef Platform_Little
	return Rotate_Left(h, l * 8);
#else
	return Rotate_Right(h, l * 8);
#endif
}
