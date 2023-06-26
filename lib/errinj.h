/**
 *              Tempesta FW
 *
 * Error injection library.
 *
 * Copyright (C) 2023 Tempesta Technologies, Inc.
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
#ifndef __LIB_ERRINJ_H__
#define __LIB_ERRINJ_H__

#include <linux/types.h>

enum errinj_type {
	/** boolean */
	ERRINJ_BOOL,
	/** int64_t */
	ERRINJ_LONG,
};

/**
 * Error injection structure.
 * 
 * @name 	- name, used to get/set errinj from userspace tests.
 * @type 	- Ttpe, e.g. ERRINJ_BOOL, ERRINJ_LONG.
 * @bparam	- bool value for errinj with type ERRINJ_BOOL.
 * @lparam	- long value for errinj with type ERRINJ_LONG.
 */
struct errinj {
	const char *name;
	enum errinj_type type;
	union {
		/** bool parameter */
		bool bparam;
		/** integer parameter */
		long lparam;
	};
};

#define FIRST_MEMBER(s, ...) s

/**
 * List of error injections.
 */
#define ERRINJ_LIST(_)						\
	_(ERRINJ_SELF_TEST, ERRINJ_BOOL, {.bparam = false})	\

enum errinj_id {
	ERRINJ_LIST(FIRST_MEMBER),
	errinj_id_MAX
};
extern struct errinj errinjs[];

/**
 * Split string with errinj in format "name=val"
 */
int
errinj_split_name_val(char *input, char **name, char **val);

/**
 * Returns the error injection by name
 * @param name of error injection
 */
struct errinj *
errinj_by_name(const char *name);

void
errinj_to_str(const struct errinj *inj, char *buf, size_t buf_size);

int
str_to_errinj(struct errinj *inj, const char *buf);

#ifndef DBG_ERRINJ
#  define errinj_get(ID, TYPE) ((struct errinj *) NULL)
#  define ERROR_INJECT(ID, CODE)
#  define ERROR_INJECT_COUNTDOWN(ID, CODE)
#else
#  define errinj_get(ID, TYPE)						\
	({								\
		BUG_ON(!(ID >= 0 && ID < errinj_id_MAX));		\
		BUG_ON(errinjs[ID].type != TYPE);			\
		&errinjs[ID];						\
	})
#  define ERROR_INJECT(ID, CODE)					\
	do {								\
		if (errinj_get(ID, ERRINJ_BOOL)->bparam)		\
			CODE;						\
	} while (0)
#  define ERROR_INJECT_COUNTDOWN(ID, CODE)				\
	do {								\
		if (errinj(ID, ERRINJ_INT)->iparam-- == 0) {		\
			CODE;						\
		}							\
	} while (0)
#endif

#endif /* __LIB_ERRINJ_H__ */
