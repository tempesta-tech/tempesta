/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_LIB_H__
#define __TFW_LIB_H__

#include "pool.h"

/* Str is compound from many chunks, use indirect table for the chunks. */
#define TFW_STR_COMPOUND	0x01
/* Str constists from compound strings. */
#define TFW_STR_COMPOUND2	0x02

typedef struct {
	unsigned int	flags;
	unsigned int	len; /* length of a string or array of strings */
	void		*ptr; /* pointer to string or array of strings */
} TfwStr;

#define TFW_STR_CHUNK(s, c)	(((s)->flags & TFW_STR_COMPOUND)	\
				 ? (c >= (s)->len			\
				    ? NULL				\
				    : (TfwStr *)(s)->ptr + c)		\
				 : s)
#define TFW_STR_CURR(s)		(((s)->flags & TFW_STR_COMPOUND)	\
				 ? (TfwStr *)(s)->ptr + (s)->len - 1	\
				 : s)

#define TFW_STR_INIT(s)		memset(s, 0, sizeof(TfwStr))
#define TFW_STR_COPY(dst, src)	memcpy(dst, src, sizeof(TfwStr))

TfwStr *tfw_str_add_compound(TfwPool *pool, TfwStr *str);

int tfw_inet_ntop(void *addr, char *buf);

#endif /* __TFW_LIB_H__ */
