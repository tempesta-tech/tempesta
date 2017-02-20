/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#ifndef __TFW_HTTP_MATCH_H__
#define __TFW_HTTP_MATCH_H__

#include <linux/list.h>

#include "addr.h"
#include "pool.h"
#include "http.h"

typedef enum {
	TFW_HTTP_MATCH_F_NA = 0,
	TFW_HTTP_MATCH_F_WILDCARD,
	TFW_HTTP_MATCH_F_HDR_CONN,
	TFW_HTTP_MATCH_F_HDR_HOST,
	TFW_HTTP_MATCH_F_HDR_RAW,
	TFW_HTTP_MATCH_F_HOST,
	TFW_HTTP_MATCH_F_METHOD,
	TFW_HTTP_MATCH_F_URI,
	_TFW_HTTP_MATCH_F_COUNT
} tfw_http_match_fld_t;

typedef enum {
	TFW_HTTP_MATCH_O_NA = 0,
	TFW_HTTP_MATCH_O_WILDCARD,
	TFW_HTTP_MATCH_O_EQ,
	TFW_HTTP_MATCH_O_PREFIX,
	TFW_HTTP_MATCH_O_SUFFIX,
	_TFW_HTTP_MATCH_O_COUNT
} tfw_http_match_op_t;

typedef tfw_http_match_op_t	tfw_match_t;

typedef enum {
	TFW_HTTP_MATCH_A_NA = 0,
	TFW_HTTP_MATCH_A_WILDCARD,
	TFW_HTTP_MATCH_A_ADDR,
	TFW_HTTP_MATCH_A_METHOD,
	TFW_HTTP_MATCH_A_NUM,
	TFW_HTTP_MATCH_A_STR,
	_TFW_HTTP_MATCH_A_COUNT
} tfw_http_match_arg_t;

typedef struct {
	tfw_http_match_arg_t type;
	short len; /* Actual amount of memory allocated for the union below. */
	union {
		tfw_http_meth_t method;
		TfwAddr addr;
		char str[0];
	};
} TfwHttpMatchArg;

typedef struct {
	struct list_head	list;
	tfw_http_match_fld_t	field; /* Field of a HTTP message to compare. */
	tfw_http_match_op_t 	op;    /* Comparison operator. */
	TfwHttpMatchArg 	arg;   /* A value to be compared with the field.
					  note: the @arg has variable length. */
} TfwHttpMatchRule;

#define TFW_HTTP_MATCH_MAX_ARG_LEN (1<<16)

/**
 * Size of a rule (taking into account the variable-length @rule.arg.
 */
#define TFW_HTTP_MATCH_RULE_SIZE(arg_len) \
	(offsetof(TfwHttpMatchRule, arg.str) + arg_len)

/**
 * Size of a container of the TfwHttpMatchRule.
 *
 * @arg_len is variable size of the @arg member.
 *          Because of this, the rule must be the last member in the container.
 */
#define TFW_HTTP_MATCH_CONT_SIZE(container_struct_name, arg_len)  \
	(sizeof(container_struct_name) - sizeof(TfwHttpMatchRule) \
	 + TFW_HTTP_MATCH_RULE_SIZE(arg_len))

/**
 * List of rules for matching.
 */
typedef struct {
	struct list_head list;
	TfwPool *pool;
} TfwHttpMatchList;


TfwHttpMatchList *tfw_http_match_list_alloc(void);
void tfw_http_match_list_free(TfwHttpMatchList *);

/**
 * Match a HTTP request agains a list of rules.
 * Return a matching rule.
 */
TfwHttpMatchRule *tfw_http_match_req(const TfwHttpReq *, const TfwHttpMatchList *);

/**
 * Allocate a new rule in a given list.
 */
TfwHttpMatchRule *tfw_http_match_rule_new(TfwHttpMatchList *, size_t arg_len);

/**
 * Match a HTTP request against a list of rules, but return a container
 * structure instead of TfwHttpMatchRule.
 */
#define tfw_http_match_req_entry(req, mlst, container, member) 		\
({ 									\
	container *_c = NULL;						\
	TfwHttpMatchRule *_r = tfw_http_match_req((req), (mlst)); 	\
	if (_r)								\
		_c = container_of(_r, container, member);		\
	_c;								\
})

/**
 * Allocate a container (with embedded rule) within a rule list.
 */
#define tfw_http_match_entry_new(mlst, container, member, arg_len) 	\
({ 									\
	size_t _s = TFW_HTTP_MATCH_CONT_SIZE(container, arg_len);	\
	container *_c = tfw_pool_alloc((mlst)->pool, _s);		\
	if (!_c) {							\
		TFW_ERR("Can't allocate memory from pool\n");		\
	} else { 							\
		memset(_c, 0, _s);					\
		INIT_LIST_HEAD(&_c->member.list);			\
		list_add_tail(&_c->member.list, &(mlst)->list);		\
	}								\
	_c;								\
})

void tfw_http_match_rule_init(TfwHttpMatchRule *rule, tfw_http_match_fld_t field,
	tfw_http_match_op_t op, tfw_http_match_arg_t type, const char *arg);

#endif /* __TFW_HTTP_MATCH_H__ */
