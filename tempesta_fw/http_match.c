/**
 *		Tempesta FW
 *
 * HTTP table logic.
 *
 * The matching process is driven by a "chain" of rules that look like this:
 *         @field       = (!=)    @arg     ->   @action [ = @action_val ]
 * { TFW_HTTP_MATCH_F_HOST,   "*example.com",  TFW_HTTP_MATCH_ACT_CHAIN },
 * { TFW_HTTP_MATCH_F_URI,    "/foo/bar*",     TFW_HTTP_MATCH_ACT_VHOST },
 * { TFW_HTTP_MATCH_F_URI,    "/",             TFW_HTTP_MATCH_ACT_MARK  },
 *
 * The table is represented by a list of linked chains, that contain rules
 * of TfwHttpMatchRule type that has the fields described above:
 *  - @field is a field of a parsed HTTP request: method/uri/host/header/etc.
 *  - @op determines a comparison operator and depends on wildcard existance
 *    in @arg : "arg" => eq / "arg*" => prefix / "*arg" => suffix.
 *  - @act is a rule action with appropriate type (examples specified above).
 *  - @arg is the second argument in rule, its type is determined dynamically
 *    depending on the @field (may be number/string/addr/etc).
 *
 * So the tfw_sched_http_table_scan() threads a HTTP request sequentally across
 * all rules in all chains in the table and stops on a first matching rule (the
 * rule is returned).
 *
 * Internally, each @field is dispatched to a corresponding match_* function.
 * For example:
 *  TFW_HTTP_MATCH_F_METHOD => match_method
 *  TFW_HTTP_MATCH_F_URI    => match_uri
 *  etc...
 * Each such match_*() function takes TfwHttpReq and TfwHttpMatchRule and
 * returns true if the given request matches to the given rule.
 * Such approach allows to keep the code structured and eases adding new
 * @field types.
 * Currently that is implemented with a multi-dimensional array of pointers
 * (the match_fn_tbl). However the code is critical for performance, so perhaps
 * this may be optimized to a kind of jump table.
 *
 * TODO:
 *   - Compare normalized URIs.
 *   - Handle LWS* between header and value for raw headers.
 *   - Case-sensitive matching for headers when required by RFC.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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
#include <linux/ctype.h>
#include "http_match.h"
#include "http_msg.h"
#include "cfg.h"

/**
 * Look up a header in the @req->h_tbl by given @id,
 * and compare @str with the header's value (skipping name and LWS).
 *
 * For example:
 *   hdr_val_eq(req, TFW_HTTP_HDR_HOST, "natsys-lab", 10, TFW_STR_EQ_PREFIX);
 * will match the following headers:
 *   "Host: natsys-lab"
 *   "Host: natsys-lab.com"
 *   "Host  :  natsys-lab.com"
 */
static bool
hdr_val_eq(const TfwHttpReq *req, tfw_http_hdr_t id, tfw_http_match_op_t op,
	   const char *str, int str_len, tfw_str_eq_flags_t flags)
{
	TfwStr *hdr;
	TfwStr hdr_val;

	BUG_ON(id < 0 || id >= TFW_HTTP_HDR_NUM);

	hdr = &req->h_tbl->tbl[id];
	if (TFW_STR_EMPTY(hdr))
		return false;

	tfw_http_msg_clnthdr_val(hdr, id, &hdr_val);

	if (op == TFW_HTTP_MATCH_O_SUFFIX)
		return tfw_str_eq_cstr_off(&hdr_val, hdr_val.len - str_len,
					   str, str_len, flags);

	return tfw_str_eq_cstr(&hdr_val, str, str_len, flags);
}

/**
 * Map an operator to that flags passed to tfw_str_eq_*() functions.
 */
static tfw_str_eq_flags_t
map_op_to_str_eq_flags(tfw_http_match_op_t op)
{
	static const tfw_str_eq_flags_t flags_tbl[] = {
		[ 0 ... _TFW_HTTP_MATCH_O_COUNT ] = -1,
		[TFW_HTTP_MATCH_O_EQ]		= TFW_STR_EQ_DEFAULT,
		[TFW_HTTP_MATCH_O_PREFIX]	= TFW_STR_EQ_PREFIX,
		[TFW_HTTP_MATCH_O_SUFFIX]	= TFW_STR_EQ_DEFAULT,
	};
	BUG_ON(flags_tbl[op] < 0);
	return flags_tbl[op];
}

static bool
match_method(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	if (rule->op == TFW_HTTP_MATCH_O_EQ)
		return req->method == rule->arg.method;

	/* Only EQ operator is supported. */
	BUG();
	return 0;
}

static bool
match_uri(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	const TfwStr *uri_path = &req->uri_path;
	const TfwHttpMatchArg *arg = &rule->arg;
	tfw_str_eq_flags_t flags = map_op_to_str_eq_flags(rule->op);

	/* RFC 7230:
	 *  2.7.3: the comparison is case-insensitive.
	 *
	 * TODO:
	 *  2.7.3: compare normalized URIs.
	 */
	flags |= TFW_STR_EQ_CASEI;

	if (rule->op == TFW_HTTP_MATCH_O_SUFFIX)
		return tfw_str_eq_cstr_off(uri_path, uri_path->len - arg->len,
					   arg->str, arg->len, flags);

	return tfw_str_eq_cstr(uri_path, arg->str, arg->len, flags);
}

static bool
match_host(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	const TfwStr *host = &req->host;
	const TfwHttpMatchArg *arg = &rule->arg;
	tfw_str_eq_flags_t flags = map_op_to_str_eq_flags(rule->op);

	/*
	 * RFC 7230:
	 *  5.4: Host header must be ignored when URI is absolute.
	 *  5.4, 2.7.3: the comparison is case-insensitive.
	 *
	 * TODO:
	 *  5.4, 2.7.3: Port 80 is equal to a non-given/empty port (done by
	 *  normalizing the host).
	 */

	flags |= TFW_STR_EQ_CASEI;

	if (host->len == 0)
		return hdr_val_eq(req, TFW_HTTP_HDR_HOST,
				  rule->op, arg->str, arg->len, flags);

	if (rule->op == TFW_HTTP_MATCH_O_SUFFIX)
		return tfw_str_eq_cstr_off(host, host->len - arg->len,
					   arg->str, arg->len, flags);

	return tfw_str_eq_cstr(host, arg->str, arg->len, flags);
}

static bool
match_hdr(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	static const tfw_http_hdr_t id_tbl[] = {
		[0 ... _TFW_HTTP_MATCH_F_COUNT] = -1,
		[TFW_HTTP_MATCH_F_HDR_CONN]	= TFW_HTTP_HDR_CONNECTION,
		[TFW_HTTP_MATCH_F_HDR_HOST]	= TFW_HTTP_HDR_HOST,
		[TFW_HTTP_MATCH_F_HDR_REFERER]	= TFW_HTTP_HDR_REFERER,
	};

	const TfwHttpMatchArg *arg = &rule->arg;
	tfw_str_eq_flags_t flags = map_op_to_str_eq_flags(rule->op);
	tfw_http_hdr_t id = id_tbl[rule->field];
	BUG_ON(id < 0);

	/* There is no general rule, but most headers are case-insensitive.
	 * TODO: case-sensitive matching for headers when required by RFC. */
	flags |= TFW_STR_EQ_CASEI;

	return hdr_val_eq(req, id, rule->op, arg->str, arg->len, flags);
}

#define _MOVE_TO_COND(p, end, cond)			\
	while ((p) < (end) && !(cond))			\
		(p)++;

/* It would be hard to apply some header-specific rules here, so ignore
 * case for all headers according to the robustness principle.
 */
static bool
match_hdr_raw(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	int i;
	tfw_str_eq_flags_t flags = map_op_to_str_eq_flags(rule->op);

	for (i = 0; i < req->h_tbl->off; ++i) {
		const TfwStr *hdr, *dup, *end, *chunk;
		const char *c, *cend, *p, *pend;
		char prev;
		short cnum;

		hdr = &req->h_tbl->tbl[i];
		if (TFW_STR_EMPTY(hdr)) {
			continue;
		}

		TFW_STR_FOR_EACH_DUP(dup, hdr, end) {
			/* Initialize  the state - get the first chunk. */
			p = rule->arg.str;
			pend = rule->arg.str + rule->arg.len;
			cnum = 0;
			chunk = TFW_STR_CHUNK(dup, 0);
			if (!chunk) {
				return p == NULL;
			}
			c = chunk->ptr;
			cend = chunk->ptr + chunk->len;

#define _TRY_NEXT_CHUNK(ok_code, err_code)		\
	if (unlikely(c == cend))	{		\
		++cnum;					\
		chunk = TFW_STR_CHUNK(dup, cnum); 	\
		if (chunk) {				\
			c = chunk->ptr;			\
			cend = chunk->ptr + chunk->len; \
			ok_code;			\
		} else {				\
			err_code;			\
		}					\
	}

			prev = *p;
state_common:
			while (p != pend && c != cend) {
				/* The rule convert to lower case on the step of
				 * handling the configuration.
				 */
				if (*p != tolower(*c)) {
					/* If the same position of the header
					 * field and rule have a different
					 * number of whitespace characters,
					 * consider their as equivalent and
					 * skip whitespace characters after ':'.
					 */
					if (isspace(prev) || prev == ':') {
						if (isspace(*c)) {
							c++;
							goto state_hdr_sp;
						}

						if (isspace(*p)) {
							prev = *p++;
							goto state_rule_sp;
						}
					}

					return false;
				}

				prev = *p++;
				c++;
			}

			if (p == pend && flags & TFW_STR_EQ_PREFIX) {
				return true;
			}

			_TRY_NEXT_CHUNK(goto state_common, {
				/* If header field and rule finished, then
				 * header field and rule are equivalent.
				 */
				if (p == pend) {
					return true;
				}

				/* If only rule doesn't finished, may be it have
				 * trailing spaces.
				 */
				if (isspace(*p)) {
					p++;
					goto state_rule_sp;
				}
			});

			/* If only header field doesn't finished, may be it have
			 * trailing spaces.
			 */
			if (isspace(*c)) {
				c++;
				goto state_hdr_sp;
			}

			return false;

state_rule_sp:
			_MOVE_TO_COND(p, pend, !isspace(*p));
			goto state_common;

state_hdr_sp:
			_MOVE_TO_COND(c, cend, !isspace(*c));
			goto state_common;
		}
	}

	return false;
}

static bool
match_wildcard(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	if ((rule->op == TFW_HTTP_MATCH_O_WILDCARD)
	    && (rule->arg.type == TFW_HTTP_MATCH_A_WILDCARD))
		return true;
	return false;
}

static bool
match_mark(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	BUG_ON(rule->op != TFW_HTTP_MATCH_O_EQ);
	return req->msg.skb_head->mark == rule->arg.num;
}


typedef bool (*match_fn)(const TfwHttpReq *, const TfwHttpMatchRule *);

static const match_fn match_fn_tbl[_TFW_HTTP_MATCH_F_COUNT] = {
	[TFW_HTTP_MATCH_F_WILDCARD]	= match_wildcard,
	[TFW_HTTP_MATCH_F_HDR_CONN]	= match_hdr,
	[TFW_HTTP_MATCH_F_HDR_HOST]	= match_hdr,
	[TFW_HTTP_MATCH_F_HDR_REFERER]	= match_hdr,
	[TFW_HTTP_MATCH_F_HDR_RAW]	= match_hdr_raw,
	[TFW_HTTP_MATCH_F_HOST]		= match_host,
	[TFW_HTTP_MATCH_F_METHOD]	= match_method,
	[TFW_HTTP_MATCH_F_URI]		= match_uri,
	[TFW_HTTP_MATCH_F_MARK]		= match_mark,
};

/**
 * Dispatch rule to a corresponding match_*() function, invert result 
 * if rule contains the inequality condition and evaluate rule if it
 * has appropriate action type. 
 */
static bool
do_eval(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	match_fn match_fn;
	tfw_http_match_fld_t field;
	bool matched;

	TFW_DBG2("rule: %p, field: %#x, op: %#x, arg:%d:%d'%.*s'\n",
		 rule, rule->field, rule->op, rule->arg.type, rule->arg.len,
		 rule->arg.len, rule->arg.str);

	BUG_ON(!req || !rule);
	BUG_ON(rule->field <= 0 || rule->field >= _TFW_HTTP_MATCH_F_COUNT);
	BUG_ON(rule->op <= 0 || rule->op >= _TFW_HTTP_MATCH_O_COUNT);
	BUG_ON(rule->act.type <= 0 || rule->act.type >= _TFW_HTTP_MATCH_ACT_COUNT);
	BUG_ON(rule->arg.type <= 0 || rule->arg.type >= _TFW_HTTP_MATCH_A_COUNT);
	BUG_ON(rule->arg.len < 0 || rule->arg.len >= TFW_HTTP_MATCH_MAX_ARG_LEN);

	field = rule->field;
	match_fn = match_fn_tbl[field];
	BUG_ON(!match_fn);

	matched = match_fn(req, rule);
	if (rule->inv)
		matched = !matched;
	if (!matched)
		return false;
	/*
	 * Evaluate mark action. Set mark only for head skb here; propagating
	 * to others skb will take place later - in SS level.
	 */
	if (rule->act.type == TFW_HTTP_MATCH_ACT_MARK) {
		req->msg.skb_head->mark = rule->act.mark;
		return false;
	}
	return true;
}

/**
 * Match a HTTP request against all rules in @mlst.
 * Return a first matching rule.
 */
TfwHttpMatchRule *
tfw_http_match_req(const TfwHttpReq *req, struct list_head *mlst)
{
	TfwHttpMatchRule *rule;

	TFW_DBG2("Matching request: %p, list: %p\n", req, mlst);

	list_for_each_entry(rule, mlst, list) {
		if (do_eval(req, rule))
			return rule;
	}

	return NULL;
}
EXPORT_SYMBOL(tfw_http_match_req);

/**
 * Allocate an empty HTTP chain.
 */
TfwHttpChain *
tfw_http_chain_add(const char *name, TfwHttpTable *table)
{
	TfwHttpChain *chain;
	int name_sz = name ? (strlen(name) + 1) : 0;
	int size = sizeof(TfwHttpChain) + name_sz;

	if (!(chain = tfw_pool_alloc(table->pool, size))) {
		TFW_ERR("Can't allocate memory for HTTP chain\n");
		return NULL;
	}

	memset(chain, 0, size);
	INIT_LIST_HEAD(&chain->list);
	INIT_LIST_HEAD(&chain->mark_list);
	INIT_LIST_HEAD(&chain->match_list);
	chain->pool = table->pool;

	if (name) {
		chain->name = (char *)(chain + 1);
		memcpy((void *)chain->name, (void *)name, name_sz);
	}

	list_add(&chain->list, &table->head);

	return chain;
}
EXPORT_SYMBOL(tfw_http_chain_add);

/**
 * Free http table (together with all elements allocated from its pool).
 */
void
tfw_http_table_free(TfwHttpTable *table)
{
	if (table)
		tfw_pool_destroy(table->pool);
}
EXPORT_SYMBOL(tfw_http_table_free);

/**
 * Allocate a rule from the pool of current http table
 * and add it to @chain list.
 */
TfwHttpMatchRule *
tfw_http_rule_new(TfwHttpChain *chain, tfw_http_match_arg_t type,
			size_t arg_size)
{
	TfwHttpMatchRule *rule;
	struct list_head *head;
	size_t size = (type == TFW_HTTP_MATCH_A_STR)
		    ? TFW_HTTP_MATCH_RULE_SIZE(arg_size)
		    : sizeof(TfwHttpMatchRule);

	BUG_ON(!chain || !chain->pool);
	if (!(rule = tfw_pool_alloc(chain->pool, size))) {
		TFW_ERR_NL("Can't allocate a rule for http chain: %p\n",
			   chain->name);
		return NULL;
	}

	head = (type == TFW_HTTP_MATCH_A_NUM)
	     ? &chain->mark_list
	     : &chain->match_list;
	memset(rule, 0, size);
	INIT_LIST_HEAD(&rule->list);
	list_add_tail(&rule->list, head);

	return rule;
}
EXPORT_SYMBOL(tfw_http_rule_new);

int
tfw_http_rule_init(TfwHttpMatchRule *rule, tfw_http_match_fld_t field,
		   tfw_http_match_op_t op, tfw_http_match_arg_t type,
		   const char *arg, size_t arg_len)
{
	rule->field = field;
	rule->op = op;
	rule->arg.type = type;

	if (type == TFW_HTTP_MATCH_A_WILDCARD)
		return 0;

	if (type == TFW_HTTP_MATCH_A_NUM) {
		if (tfw_cfg_parse_uint(arg, &rule->arg.num)) {
			TFW_ERR_NL("sched_http: invalid 'mark'"
				   " codition: '%s'\n", arg);
			return -EINVAL;
		}
		return 0;
	}

	rule->arg.len = arg_len;
	memcpy(rule->arg.str, arg, arg_len);
	if (field == TFW_HTTP_MATCH_F_HDR_RAW) {
		char *p = rule->arg.str;
		while ((*p = tolower(*p)))
			p++;
	}

	return 0;
}
EXPORT_SYMBOL(tfw_http_rule_init);

bool
tfw_http_arg_adjust(const char **arg_out, size_t *size_out,
		    tfw_http_match_op_t *op_out)
{
	size_t len;
	const char *arg = *arg_out;

	BUG_ON(!arg);
	len = strlen(arg);
	*op_out = TFW_HTTP_MATCH_O_EQ;
	*size_out = len + 1;

	if (arg[len - 1] == '*') {
		if (len == 1) {
			*op_out = TFW_HTTP_MATCH_O_WILDCARD;
			return false;
		}
		*op_out = TFW_HTTP_MATCH_O_PREFIX;
		--(*size_out);
	}
	if (arg[0] == '*') {
		*op_out = TFW_HTTP_MATCH_O_SUFFIX;
		*arg_out = &arg[1];
		--(*size_out);
	}

	return true;
}
EXPORT_SYMBOL(tfw_http_arg_adjust);
