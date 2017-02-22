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

#if Platform_Alignment

#define GET_INT32(p, n, x)					\
	do {							\
		if (n < 4) {					\
			goto Bug;				\
		}						\
		x = Bit_Join(p[3], 24,				\
		    Bit_Join(p[2], 16, Bit_Join8(p[1], p[0]))); \
		p += 4; 					\
		n -= 4; 					\
	} while (0)

#define GET_INT16(p, n, x)					\
	do {							\
		if (n < 2) {					\
			goto Bug;				\
		}						\
		x = Bit_Join8(p[1], p[0]);			\
		p += 2; 					\
		n -= 2; 					\
	} while (0)

#else

#define GET_INT32(p, n, x)					\
	do {							\
		if (n < 4) {					\
			goto Bug;				\
		}						\
		x = Little32(* (uint32 *) p);			\
		p += 4; 					\
		n -= 4; 					\
	} while (0)

#define GET_INT16(p, n, x)					\
	do {							\
		if (n < 2) {					\
			goto Bug;				\
		}						\
		x = Little16(* (uint16 *) p);			\
		p += 2; 					\
		n -= 2; 					\
	} while (0)

#endif

#define GET_FLEXIBLE(p, n, x)					\
	do {							\
		x = 0;						\
		do {						\
			if (n == 0) {				\
				goto Bug;			\
			}					\
			c = * p++;				\
			n--;					\
			if ((x & ~((uint32) -1 >> 7)) == 0) {	\
				x = Bit_Join(x, 7, c & 127);	\
			}					\
			else {					\
			     goto Bug;				\
			}					\
		} while (c > 127);				\
	} while (0)

#endif
