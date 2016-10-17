/**
 *		Tempesta FW
 *
 * HTTP matching logic.
 *
 * The matching process is driven by a "table" of rules that may look like this:
 *         @field                  @op                      @arg
 * { TFW_HTTP_MATCH_F_HOST,  TFW_HTTP_MATCH_O_EQ,       "example.com" },
 * { TFW_HTTP_MATCH_F_URI,   TFW_HTTP_MATCH_O_PREFIX,   "/foo/bar"    },
 * { TFW_HTTP_MATCH_F_URI,   TFW_HTTP_MATCH_O_PREFIX,   "/"           },
 *
 * The table is represented by a linked list TfwHttpMatchList that contains
 * of TfwHttpMatchRule that has the field described above:
 *  - @field is a field of a parsed HTTP request: method/uri/host/header/etc.
 *  - @op determines a comparison operator: eq/prefix/substring/regex/etc.
 *  - @arg is the second argument of the binary @op, its type is determined
 *    dynamically depending on the @field (may be number/string/addr/etc).
 *
 * So the tfw_http_match_req() threads a HTTP request sequentally across all
 * rules in the table and stops on a first matching rule (the rule is returned).
 * The rule may be wrapped by a container structure and thus custom data may
 * be attached to rules.
 *
 * Internally, each pair of @field and @op is dispatched to a corresponding
 * match_* function.
 * For example:
 *  TFW_HTTP_MATCH_F_METHOD + TFW_HTTP_MATCH_O_EQ  => match_method_eq
 *  TFW_HTTP_MATCH_F_METHOD + TFW_HTTP_MATCH_O_IN  => match_method_in
 * However, different pairs may be dispatched to the same function:
 *  TFW_HTTP_MATCH_F_URI + TFW_HTTP_MATCH_O_EQ     => match_uri
 *  TFW_HTTP_MATCH_F_URI + TFW_HTTP_MATCH_O_PREFIX => match_uri
 *  etc...
 * Each such match_*() function takes TfwHttpReq and TfwHttpMatchRule and
 * returns true if the given request matches to the given rule.
 * Such approach allows to keep the code structured and eases adding new
 * @field/@op combinations.
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
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
		[TFW_HTTP_MATCH_O_EQ]     = TFW_STR_EQ_DEFAULT,
		[TFW_HTTP_MATCH_O_PREFIX] = TFW_STR_EQ_PREFIX,
		[TFW_HTTP_MATCH_O_SUFFIX] = TFW_STR_EQ_DEFAULT,
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
		[TFW_HTTP_MATCH_F_HDR_CONN] = TFW_HTTP_HDR_CONNECTION,
		[TFW_HTTP_MATCH_F_HDR_HOST] = TFW_HTTP_HDR_HOST,
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
	    && (rule->arg.type == TFW_HTTP_MATCH_A_WILDCARD)
	    && (rule->arg.len == 1) && (rule->arg.str[0] == '*'))
		return true;
	return false;
}


typedef bool (*match_fn)(const TfwHttpReq *, const TfwHttpMatchRule *);

static const match_fn
__read_mostly match_fn_tbl[_TFW_HTTP_MATCH_F_COUNT] = {
	[TFW_HTTP_MATCH_F_WILDCARD]	= match_wildcard,
	[TFW_HTTP_MATCH_F_HDR_CONN]	= match_hdr,
	[TFW_HTTP_MATCH_F_HDR_HOST]	= match_hdr,
	[TFW_HTTP_MATCH_F_HDR_RAW]	= match_hdr_raw,
	[TFW_HTTP_MATCH_F_HOST]		= match_host,
	[TFW_HTTP_MATCH_F_METHOD]	= match_method,
	[TFW_HTTP_MATCH_F_URI]		= match_uri,
};

/**
 * Dispatch rule to a corresponding match_*() function.
 */
static bool
do_match(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	match_fn match_fn;
	tfw_http_match_fld_t field;

	TFW_DBG2("rule: %p, field: %#x, op: %#x, arg:%d:%d'%.*s'\n",
		 rule, rule->field, rule->op, rule->arg.type, rule->arg.len,
		 rule->arg.len, rule->arg.str);

	BUG_ON(!req || !rule);
	BUG_ON(rule->field < 0 || rule->field >= _TFW_HTTP_MATCH_F_COUNT);
	BUG_ON(rule->op < 0 || rule->op >= _TFW_HTTP_MATCH_O_COUNT);
	BUG_ON(rule->arg.type < 0 || rule->arg.type >= _TFW_HTTP_MATCH_A_COUNT);
	BUG_ON(rule->arg.len <= 0 || rule->arg.len >= TFW_HTTP_MATCH_MAX_ARG_LEN);

	field = rule->field;
	match_fn = match_fn_tbl[field];
	BUG_ON(!match_fn);

	return match_fn(req, rule);
}

/**
 * Match a HTTP request against all rules in @mlst.
 * Return a first matching rule.
 */
TfwHttpMatchRule *
tfw_http_match_req(const TfwHttpReq *req, const TfwHttpMatchList *mlst)
{
	TfwHttpMatchRule *rule;

	TFW_DBG2("Matching request: %p, list: %p\n", req, mlst);

	list_for_each_entry(rule, &mlst->list, list) {
		if (do_match(req, rule))
			return rule;
	}

	return NULL;
}
EXPORT_SYMBOL(tfw_http_match_req);

/**
 * Allocate a rule from the pool of @mlst and add it to the list.
 */
TfwHttpMatchRule *
tfw_http_match_rule_new(TfwHttpMatchList *mlst, size_t arg_len)
{
	TfwHttpMatchRule *rule;
	size_t size = TFW_HTTP_MATCH_RULE_SIZE(arg_len);

	BUG_ON(!mlst || !mlst->pool);

	rule = tfw_pool_alloc(mlst->pool, size);
	if (!rule) {
		TFW_ERR("Can't allocate a rule for match list: %p\n", mlst);
		return NULL;
	}

	memset(rule, 0, size);
	rule->arg.len = arg_len;
	INIT_LIST_HEAD(&rule->list);
	list_add_tail(&rule->list, &mlst->list);

	return rule;
}
EXPORT_SYMBOL(tfw_http_match_rule_new);

/**
 * Allocate an empty list of rules.
 */
TfwHttpMatchList *
tfw_http_match_list_alloc(void)
{
	TfwHttpMatchList *mlst;

	mlst = tfw_pool_new(TfwHttpMatchList, 0);
	if (!mlst) {
		TFW_ERR("Can't create a memory pool\n");
		return NULL;
	}

	INIT_LIST_HEAD(&mlst->list);

	return mlst;
}
EXPORT_SYMBOL(tfw_http_match_list_alloc);

/**
 * Free a list of rules (together with all elements allocated from its pool).
 */
void
tfw_http_match_list_free(TfwHttpMatchList *mlst)
{
	if (mlst)
		tfw_pool_destroy(mlst->pool);
}
EXPORT_SYMBOL(tfw_http_match_list_free);

void
tfw_http_match_rule_init(TfwHttpMatchRule *rule, tfw_http_match_fld_t field,
			 tfw_http_match_op_t op, tfw_http_match_arg_t type,
			 const char *arg)
{
	rule->field = field;
	rule->op = op;
	rule->arg.type = type;
	rule->arg.len = strlen(arg);
	memcpy(rule->arg.str, arg, rule->arg.len + 1);

	if (field == TFW_HTTP_MATCH_F_HDR_RAW) {
		char *p = rule->arg.str;
		while ((*p = tolower(*p)))
			p++;
	}
}
EXPORT_SYMBOL(tfw_http_match_rule_init);
