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
#include <linux/error-injection.h>

#include "fault_injection_alloc.h"

#ifdef CONFIG_FAULT_INJECTION

void *
tfw_kmalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags);
}
ALLOW_ERROR_INJECTION(tfw_kmalloc, NULL);
EXPORT_SYMBOL(tfw_kmalloc);

void *
tfw_kzalloc(size_t size, gfp_t flags)
{
	return kzalloc(size, flags);
}
ALLOW_ERROR_INJECTION(tfw_kzalloc, NULL);
EXPORT_SYMBOL(tfw_kzalloc);

void *
tfw_kcalloc(size_t n, size_t size, gfp_t flags)
{
	return kcalloc(n, size, flags);
}
ALLOW_ERROR_INJECTION(tfw_kcalloc, NULL);
EXPORT_SYMBOL(tfw_kcalloc);

void *
tfw_kmalloc_node(size_t size, gfp_t flags, int node)
{
	return kmalloc_node(size, flags, node);
}
ALLOW_ERROR_INJECTION(tfw_kmalloc_node, NULL);
EXPORT_SYMBOL(tfw_kmalloc_node);

void *
tfw_kvmalloc_node(size_t size, gfp_t flags, int node)
{
	return kvmalloc_node(size, flags, node);
}
ALLOW_ERROR_INJECTION(tfw_kvmalloc_node, NULL);
EXPORT_SYMBOL(tfw_kvmalloc_node);

void *
tfw__alloc_percpu(size_t size, size_t align)
{
	return __alloc_percpu(size, align);
}
ALLOW_ERROR_INJECTION(tfw__alloc_percpu, NULL);
EXPORT_SYMBOL(tfw__alloc_percpu);

#endif
