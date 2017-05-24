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

#include "common.h"
#include "netconv.h"

#ifdef Platform_Alignment

#define GET_INT32_FLAT(x)		\
	x = Bit_Join(src[0], 24,	\
	    Bit_Join(src[1], 16,	\
	    Bit_Join8(src[2], src[3])))

#define GET_INT16_FLAT(x) \
	x = Bit_Join8(src[0], src[1])

#else

#define GET_INT32_FLAT(x) \
	x = Big32(* (uint32_t_t *) src)

#define GET_INT16_FLAT(x) \
	x = Big16(* (uint16_t_t *) src)

#endif

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

#ifdef Platform_Alignment

#define PUT_INT32_FLAT(x)		      \
do {					      \
	dst[0] = (x) >> 24;		      \
	dst[1] = (unsigned char) ((x) >> 16); \
	dst[2] = (unsigned char) ((x) >> 8);  \
	dst[3] = (unsigned char)  (x);	      \
	dst += 4;			      \
} while (0)

#define PUT_INT24_FLAT(x)		     \
do {					     \
	dst[0] = (x) >> 16;		     \
	dst[1] = (unsigned char) ((x) >> 8); \
	dst[2] = (unsigned char)  (x);	     \
	dst += 3;			     \
} while (0)

#define PUT_INT16_FLAT(x)	      \
do {				      \
	dst[0] = (x) >> 8;	      \
	dst[2] = (unsigned char) (x); \
	dst += 2;		      \
} while (0)

#else

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

#endif

#define HPACK_LIMIT (Bit_Capacity / 7) * 7
#define HPACK_LAST ((1 << (Bit_Capacity % 7)) - 1)

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
