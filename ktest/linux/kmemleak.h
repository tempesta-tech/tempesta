/**
 *	Tempesta kernel emulation unit testing framework.
 *
 * Copyright (C) 2025 Tempesta Technologies, Inc.
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
#ifndef __KMEMLEAK_H__
#define __KMEMLEAK_H__

static inline void
kmemleak_alloc(const void *ptr, size_t size, int min_count, gfp_t gfp)
{
}

static inline void
kmemleak_free(const void *ptr)
{
}

#endif /* __KMEMLEAK_H__ */
