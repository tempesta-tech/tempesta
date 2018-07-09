/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#include "http.h"
#include "http_tbl.h"

typedef enum {
	TFW_HTTP_MATCH_F_NA = 0,
	TFW_HTTP_MATCH_F_WILDCARD,
	TFW_HTTP_MATCH_F_HDR,
	TFW_HTTP_MATCH_F_HOST,
	TFW_HTTP_MATCH_F_METHOD,
	TFW_HTTP_MATCH_F_URI,
	TFW_HTTP_MATCH_F_MARK,
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

typedef enum {
	TFW_HTTP_MATCH_ACT_NA = 0,
	TFW_HTTP_MATCH_ACT_CHAIN,
	TFW_HTTP_MATCH_ACT_VHOST,
	TFW_HTTP_MATCH_ACT_MARK,
	TFW_HTTP_MATCH_ACT_BLOCK,
	_TFW_HTTP_MATCH_ACT_COUNT
} tfw_http_rule_act_t;

typedef struct {
	tfw_http_match_arg_t type;
	short len; /* Actual amount of memory allocated for the union below. */
	union {
		tfw_http_meth_t method;
		unsigned int num;
		TfwAddr addr;
		char str[0];
	};
} TfwHttpMatchArg;

typedef struct {
	tfw_http_rule_act_t type;
	union {
		TfwHttpChain *chain;
		TfwVhost *vhost;
		unsigned int mark;
	};
} TfwHttpAction;

typedef struct {
	struct list_head	list;
	tfw_http_match_fld_t	field; /* Field of a HTTP message to compare. */
	tfw_http_match_op_t 	op;    /* Comparison operator. */
	TfwHttpAction		act;   /* Rule action. */
	unsigned int		hid;   /* Header ID. */
	unsigned int		inv;   /* Comparison inversion (inequality) flag.*/
	TfwHttpMatchArg 	arg;   /* A value to be compared with the field.
					  note: the @arg has variable length. */
} TfwHttpMatchRule;

#define TFW_HTTP_MATCH_MAX_ARG_LEN (1<<16)

/**
 * Size of a rule (taking into account the variable-length @rule.arg.
 */
#define TFW_HTTP_MATCH_RULE_SIZE(arg_len) \
	(offsetof(TfwHttpMatchRule, arg.str) + arg_len)

TfwHttpChain *tfw_http_chain_add(const char *name, TfwHttpTable *table);
void tfw_http_table_free(TfwHttpTable *table);

/**
 * Match a HTTP request agains a list of rules in chain.
 * Return a matching rule.
 */
TfwHttpMatchRule *tfw_http_match_req(const TfwHttpReq *req,
				     struct list_head *mlst);

/**
 * Allocate a new rule in a given chain.
 */
TfwHttpMatchRule *tfw_http_rule_new(TfwHttpChain *chain,
				    tfw_http_match_arg_t type,
				    size_t arg_len);

int tfw_http_rule_arg_init(TfwHttpMatchRule *rule, const char *arg,
			   size_t arg_len);
const char *tfw_http_arg_adjust(const char *arg, size_t len, const char *h_name,
				size_t *size_out, tfw_http_match_op_t *op_out);
int tfw_http_verify_hdr_field(tfw_http_match_fld_t field, const char **h_name,
			      unsigned int *hid_out);

#define tfw_http_chain_rules_for_each(chain, func)			\
({									\
	int r = 0;							\
	TfwHttpMatchRule *rule;					 	\
	if (chain) {							\
		list_for_each_entry(rule, &(chain)->match_list, list)	\
			r |= func(rule);				\
		list_for_each_entry(rule, &(chain)->mark_list, list)	\
			r |= func(rule);				\
	}								\
	r;								\
})

#endif /* __TFW_HTTP_MATCH_H__ */
