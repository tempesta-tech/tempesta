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
#include <linux/module.h>
#include <linux/string.h>

MODULE_AUTHOR("Tempesta Technologies, INC");
MODULE_VERSION("0.1.1");
MODULE_LICENSE("GPL");

/* Assembly wrappers to make linker happy. */
extern void __memcpy_fast(void *to, const void *from, size_t len);
extern int __memcmp_fast(const void *a, const void *b, size_t len);
extern void __bzero_fast(void *s, size_t len);

void
memcpy_fast(void *to, const void *from, size_t len)
{
#ifdef AVX2
	__memcpy_fast(to, from, len);
#else
	memcpy(to, from, len);
#endif
}
EXPORT_SYMBOL(memcpy_fast);

int
memcmp_fast(const void *a, const void *b, size_t len)
{
#ifdef AVX2
	return __memcmp_fast(a, b, len);
#else
	return memcmp(a, b, len);
#endif
}
EXPORT_SYMBOL(memcmp_fast);

void
bzero_fast(void *s, size_t len)
{
#ifdef AVX2
	__bzero_fast(s, len);
#else
	memset(s, 0, len);
#endif
}
EXPORT_SYMBOL(bzero_fast);

static int __init
tempesta_lib_init(void)
{
	return 0;
}

static void __exit
tempesta_lib_exit(void)
{
}

module_init(tempesta_lib_init);
module_exit(tempesta_lib_exit);
