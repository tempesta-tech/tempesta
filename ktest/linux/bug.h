/**
 *	Tempesta kernel emulation unit testing framework.
 *
 * Copyright (C) 2019-2020 Tempesta Technologies, Inc.
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
#ifndef __BUG_H__
#define __BUG_H__

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#define BUG_ON(c)	assert(unlikely(!(c)))
#define BUILD_BUG_ON(c)	assert(unlikely(!(c)))
#define BUG()		abort()

/*
 * Make all the warning is the tests fatal: there is no point for backward
 * recovery in tests and early crashes with backtraces make debugging more
 * productive.
 */

#define __WARN()							\
do {									\
	fprintf(stderr, "Warning at %s:%d\n", __FILE__, __LINE__);	\
	abort();							\
} while (0)

#define WARN(condition, format...) ({					\
	int __ret_warn_on = !!(condition);				\
	if (__ret_warn_on) {						\
		fprintf(stderr, format);				\
		abort();						\
	}								\
	__ret_warn_on;							\
})

#define WARN_ONCE(condition, format...) ({				\
	int __ret_warn_on = !!(condition);				\
	if (__ret_warn_on) {						\
		fprintf(stderr, format);				\
		abort();						\
	}								\
	__ret_warn_on;							\
})

#define WARN_ON_ONCE(condition) ({					\
	int __ret_warn_on = !!(condition);				\
	if (__ret_warn_on) {						\
		fprintf(stderr, "Warning at %s:%d\n", __FILE__, __LINE__);\
		abort();						\
	}								\
	__ret_warn_on;							\
})

#endif /* __BUG_H__ */
