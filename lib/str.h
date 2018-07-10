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
#ifndef __LIB_STR_H__
#define __LIB_STR_H__

#include <linux/types.h>

void memcpy_fast(void *to, const void *from, size_t len);
/*
 * This memcmp() version return 0 on equal strings and non-zero otherwise -
 * keep this in mind, e.g. it can not be used for binary search as the standard
 * one.
 */
int memcmp_fast(const void *a, const void *b, size_t len);
void bzero_fast(void *s, size_t len);

#endif /* __LIB_STR_H__ */
