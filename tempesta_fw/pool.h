/**
 *		Tempesta FW
 *
 * Memory pool.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#ifndef __TFW_POOL_H__
#define __TFW_POOL_H__

#include <linux/cache.h>
#include "log.h"

#define TFW_POOL_ZERO	0x1

/**
 * Memory pool chunk descriptor.
 *
 * @next	- pointer to next memory chunk;
 * @order	- order of number of pages in the chunk;
 * @off		- current chunk offset;
 */
typedef struct tfw_pool_chunk_t {
	struct tfw_pool_chunk_t	*next;
	unsigned int		order;
	unsigned int		off;
} TfwPoolChunk;

/**
 * Memory pool descriptor.
 *
 * @curr	- current chunk to allocate memory from;
 * @order,@off	- cached members of @curr;
 */
typedef struct {
	TfwPoolChunk	*curr;
	unsigned int	order;
	unsigned int	off;
} TfwPool;

#define tfw_pool_new(struct_name, mask)					\
({									\
 	struct_name *s = NULL;						\
	TfwPool *p = __tfw_pool_new(sizeof(struct_name));		\
	if (likely(p)) {						\
 		s = tfw_pool_alloc(p, sizeof(struct_name));		\
 		BUG_ON(!s);						\
		if (mask & TFW_POOL_ZERO)				\
			memset(s, 0, sizeof(struct_name));		\
 		s->pool = p;						\
 	} else {							\
		T_ERR("Can't alloc new " #struct_name);			\
 	}								\
 	s;								\
 })

TfwPool *__tfw_pool_new(size_t n);
void *tfw_pool_alloc(TfwPool *p, size_t n);
void *tfw_pool_realloc(TfwPool *p, void *ptr, size_t old_n, size_t new_n);
void tfw_pool_free(TfwPool *p, void *ptr, size_t n);
void tfw_pool_destroy(TfwPool *p);

#endif /* __TFW_POOL_H__ */
