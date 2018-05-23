/**
 *		Tempesta kernel libarary
 *
 * Copyright (C) 2018 Tempesta Technologies, INC.
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
#include <linux/string.h>

void
memcpy_fast(void *to, const void *from, size_t len)
{
	memcpy(to, from, len);
}

int
memcmp_fast(const void *a, const void *b, size_t len)
{
	return memcmp(a, b, len);
}

void
bzero_fast(void *s, size_t len)
{
	memset(s, 0, len);
}
