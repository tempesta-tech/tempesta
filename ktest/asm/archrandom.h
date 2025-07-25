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
#ifndef __ARCHRANDOM_H__
#define __ARCHRANDOM_H__

static inline size_t
arch_get_random_longs(unsigned long *v, size_t max_longs)
{
	return max_longs && __builtin_ia32_rdrand64_step((unsigned long long *)v);
}

#endif /* __ARCHRANDOM_H__ */
