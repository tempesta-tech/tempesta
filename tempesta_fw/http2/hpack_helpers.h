/**
 *		Tempesta FW
 *
 * Common macro definitions used by HPACK decoder modules.
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

#ifndef HPACK_HELPERS_H
#define HPACK_HELPERS_H

#include <inttypes.h>
#include <stdlib.h>
#include <arpa/inet.h>

/*
 * Macros to use LEA on the x86, barrel shifter and other
 * hardware-specific instructions istead of "|" if suitable:
 */
#define Bit_Add(x, y) ((x) | (y))
#define Bit_Join1(x, y) (((x) << 1) + (y))
#define Bit_Join2(x, y) (((x) << 2) + (y))
#define Bit_Join3(x, y) (((x) << 3) + (y))
#define Bit_Join4(x, y) (((x) << 4) | (y))
#define Bit_Join8(x, y) (((x) << 8) | (y))
#define Bit_Shift(x, y, z) (((x) << (y)) | (z))
#define Bit_Join Bit_Shift

#define Big16 htons
#define Big32 htonl

#ifdef __GNUC__

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)

#define Big64(x) (uint64_t) __builtin_bswap64(x)

#else

#define Big64(x) \
	(__extension__ ({ \
		register uint64_t __r = x; \
		__asm__( \
			"bswapq %0" : "=r" (__r) : "0" (__r) \
		); \
		__r; \
	}))

#endif

#else

static __inline__ uint64_t
Big64 (const uint64_t x)
{
	uint64_t y;
	y = Bit_Join8(x & 0x00FF00FF00FF00FF, (x >> 8) & 0x00FF00FF00FF00FF);
	y = Bit_Shift(y & 0x0000FFFF0000FFFF, 16, (y >> 16) & 0x0000FFFF0000FFFF);
	return return (y << 32) | (y >> (64 - 32));
}

#endif

#define BigWide Big64

#define GET_INT32_FLAT(x) \
	x = Big32(* (uint32_t_t *) src)

#define GET_INT16_FLAT(x) \
	x = Big16(* (uint16_t_t *) src)

#define GET_INT32(x)					       \
do {							       \
	n -= 4; 					       \
	if (likely(m >= 4)) {				       \
		GET_INT32_FLAT(x);			       \
		src += 4;				       \
		m -= 4; 				       \
	}						       \
	else {						       \
		unsigned int __n;			       \
		if (m == 0) {				       \
			src = buffer_next(source, &m);	       \
		}					       \
		x = * src++;				       \
		m--;					       \
		__n = 3;				       \
		do {					       \
			if (unlikely(m == 0)) { 	       \
				src = buffer_next(source, &m); \
			}				       \
			x = Bit_Join8(x, * src++);	       \
			m--;				       \
		} while (--__n);			       \
	}						       \
} while (0)

#define GET_INT16(x)					       \
do {							       \
	n -= 2; 					       \
	if (likely(m >= 2)) {				       \
		GET_INT16_FLAT(x);			       \
		src += 2;				       \
		m -= 2; 				       \
	}						       \
	else {						       \
		if (m == 0) {				       \
			src = buffer_next(source, &m);	       \
		}					       \
		x = * src++;				       \
		m--;					       \
		if (m == 0) {				       \
			src = buffer_next(source, &m);	       \
		}					       \
		x = Bit_Join8(x, * src++);		       \
		m--;					       \
	}						       \
} while (0)

#define PUT_INT32_FLAT(x)	\
do {				\
	* (uint32_t_t *) dst = x; \
	dst += 4;		\
} while (0)

#define PUT_INT24_FLAT(x)		   \
do {					   \
	* (uint16_t_t *) dst = (x) >> 8;     \
	* (dst + 2) = (unsigned char) (x); \
	dst += 3;			   \
} while (0)

#define PUT_INT16_FLAT(x)	\
do {				\
	* (uint16_t_t *) dst = x; \
	dst += 2;		\
} while (0)

#define HPACK_LIMIT (64 / 7) * 7
#define HPACK_LAST ((1 << (64 % 7)) - 1)

/* Flexible integer decoding as specified */
/* in the HPACK RFC-7541: */

#define GET_FLEXIBLE(x) 				       \
do {							       \
	unsigned int __m = 0;				       \
	unsigned int __c;				       \
	do {						       \
		if (unlikely(m == 0)) { 		       \
			if (n) {			       \
				src = buffer_next(source, &m); \
			}				       \
			else {				       \
				hp->shift = __m;	       \
				hp->saved = x;		       \
				goto Incomplete;	       \
			}				       \
		}					       \
		__c = * src++;				       \
		n--;					       \
		m--;					       \
		if (__m <  HPACK_LIMIT ||		       \
		   (__m == HPACK_LIMIT &&		       \
		    __c <= HPACK_LAST)) 		       \
		{					       \
			x += (__c & 127) << __m;	       \
			__m += 7;			       \
		}					       \
		else if (__c) { 			       \
			goto Overflow;			       \
		}					       \
	} while (__c > 127);				       \
} while (0)

/* Continue decoding after interruption due */
/* to absence of the next fragment: */

#define GET_CONTINUE(x) 				       \
do {							       \
	unsigned int __m = hp->shift;			       \
	unsigned int __c = * src++;			       \
	x = hp->saved;					       \
	n--;						       \
	m--;						       \
	if (__m <  HPACK_LIMIT ||			       \
	   (__m == HPACK_LIMIT &&			       \
	    __c <= HPACK_LAST)) 			       \
	{						       \
		x += (__c & 127) << __m;		       \
		__m += 7;				       \
	}						       \
	else if (__c) { 				       \
		goto Overflow;				       \
	}						       \
	while (__c > 127) {				       \
		if (unlikely(m == 0)) { 		       \
			if (n) {			       \
				src = buffer_next(source, &m); \
			}				       \
			else {				       \
				hp->shift = __m;	       \
				hp->saved = x;		       \
				goto Incomplete;	       \
			}				       \
		}					       \
		__c = * src++;				       \
		n--;					       \
		m--;					       \
		if (__m <  HPACK_LIMIT ||		       \
		   (__m == HPACK_LIMIT &&		       \
		    __c <= HPACK_LAST)) 		       \
		{					       \
			x = Bit_Join(__c & 127, __m, x);       \
			__m += 7;			       \
		}					       \
		else if (__c) { 			       \
			goto Overflow;			       \
		}					       \
	}						       \
} while (0)

#endif
