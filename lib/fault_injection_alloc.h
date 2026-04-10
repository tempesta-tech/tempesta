/**
 *		Tempesta FW
 *
 * Copyright (C) 2025 Tempesta Technologies, Inc.
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
#ifndef __TFW_ALLOC_H__
#define __TFW_ALLOC_H__

#include <linux/slab.h>

#ifndef CONFIG_FAULT_INJECTION

#define tfw_kmalloc(size, flags)		kmalloc(size, flags)
#define tfw_kzalloc(size, flags)		kzalloc(size, flags)
#define	tfw_kcalloc(n, size, flags)		kcalloc(n, size, flags)
#define tfw_kmalloc_node(size, flags, node)	kmalloc_node(size, flags, node)
#define tfw_kvmalloc_node(size, flags, node)	\
	kvmalloc_node(size, flags, node)
#define tfw__alloc_percpu(size, align)		__alloc_percpu(size, align)
#define tfw_alloc_percpu(t)			alloc_percpu(t)
#define tfw_alloc_percpu_gfp(t, gfp)		alloc_percpu_gfp(t, gfp)
#define tfw__get_free_pages(gfp_mask, order)	\
	__get_free_pages(gfp_mask, order)
#define tfw_percpu_ref_init(ref, release, flags, gfp)	\
	percpu_ref_init(ref, release, flags, gfp)

#else

void *tfw_kmalloc(size_t size, gfp_t flags);
void *tfw_kzalloc(size_t size, gfp_t flags);
void *tfw_kcalloc(size_t n, size_t size, gfp_t flags);
void *tfw_kmalloc_node(size_t size, gfp_t flags, int node);
void *tfw_kvmalloc_node(size_t size, gfp_t flags, int node);
void *tfw__alloc_percpu(size_t size, size_t align);
void *tfw__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp);
int __must_check tfw_percpu_ref_init(struct percpu_ref *ref,
				     percpu_ref_func_t *release,
				     unsigned int flags,
				     gfp_t gfp);
unsigned long tfw__get_free_pages(gfp_t gfp_mask, unsigned int order);
#define tfw_alloc_percpu(t)					\
	(typeof(t) __percpu *) tfw__alloc_percpu(sizeof(t), __alignof__(t))
#define tfw_alloc_percpu_gfp(t, gfp)				\
	(typeof(t) __percpu *) tfw__alloc_percpu_gfp(sizeof(t),	\
						     __alignof__(t), gfp)

#endif

#endif /* __TFW_ALLOC_H__ */
