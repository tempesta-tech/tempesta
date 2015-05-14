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
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#include <linux/cache.h>
#include "http_match.h"
#include "http.h"

/*
 * Use -DTFW_HTTP_MATCH_DBG_LVL=N to increase verbosity just for this unit.
 *
 * At the level 1 you get a log message for every processed HTTP message,
 * and at level 2 a message for each rule against which the request is matched.
 */
#ifndef TFW_HTTP_MATCH_DBG_LVL
#define TFW_HTTP_MATCH_DBG_LVL 0
#endif

#if (TFW_HTTP_MATCH_DBG_LVL >= 1)
#undef TFW_DBG
#define TFW_DBG(...) __TFW_DBG1(__VA_ARGS__)
#endif

#if (TFW_HTTP_MATCH_DBG_LVL >= 2)
#undef TFW_DBG2
#define TFW_DBG2(...) __TFW_DBG2(__VA_ARGS__)
#endif

/**
 * Look up a header in the @req->h_tbl by given @id,
 * and compare @val with the header's value (skipping name and LWS).
 *
 * For example:
 *   hdr_val_eq(req, TFW_HTTP_HDR_HOST, "natsys-lab", 10, TFW_STR_EQ_PREFIX);
 * will match the following headers:
 *   "Host: natsys-lab"
 *   "Host: natsys-lab.com"
 *   "Host  :  natsys-lab.com"
 */
static bool
hdr_val_eq(const TfwHttpReq *req, tfw_http_hdr_t id, const char *val,
           int val_len, tfw_str_eq_flags_t f)
{
#define _HDR(name) { name, sizeof(name) - 1 }
	static const struct {
		const char *name;
		int name_len;
	} hdr_name_tbl[TFW_HTTP_HDR_NUM] = {
		[TFW_HTTP_HDR_CONNECTION]      = _HDR("Connection"),
		[TFW_HTTP_HDR_HOST]            = _HDR("Host"),
		[TFW_HTTP_HDR_X_FORWARDED_FOR] = _HDR("X-Forwarded-For"),
	};
#undef _HDR

	TfwStr *hdr;
	const char *hdr_name;
	int hdr_name_len;

	BUG_ON(id < 0 || id >= TFW_HTTP_HDR_NUM);

	hdr = &req->h_tbl->tbl[id].field;
	if (!hdr->len)
		return false;

	hdr_name = hdr_name_tbl[id].name;
	hdr_name_len = hdr_name_tbl[id].name_len;
	BUG_ON(!hdr_name);
	BUG_ON(!hdr_name_len);

	return tfw_str_eq_kv(hdr, hdr_name, hdr_name_len, ':', val, val_len, f);
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
	tfw_str_eq_flags_t flags = map_op_to_str_eq_flags(rule->op);

	/* RFC 7230:
	 *  2.7.3: the comparison is case-insensitive.
	 *
	 * TODO:
	 *  2.7.3: compare normalized URIs.
	 */
	flags |= TFW_STR_EQ_CASEI;

	return tfw_str_eq_cstr(&req->uri_path, rule->arg.str, rule->arg.len, flags);
}

static bool
match_host(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
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

	if (req->host.len) {
		return tfw_str_eq_cstr(&req->host, rule->arg.str,
		                       rule->arg.len, flags);
	}

	return hdr_val_eq(req, TFW_HTTP_HDR_HOST, rule->arg.str,
	                  rule->arg.len, flags);
}

static bool
match_hdr(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	static const tfw_http_hdr_t id_tbl[] = {
		[0 ... _TFW_HTTP_MATCH_F_COUNT] = -1,
		[TFW_HTTP_MATCH_F_HDR_CONN] = TFW_HTTP_HDR_CONNECTION,
		[TFW_HTTP_MATCH_F_HDR_HOST] = TFW_HTTP_HDR_HOST,
	};

	tfw_str_eq_flags_t flags = map_op_to_str_eq_flags(rule->op);
	tfw_http_hdr_t id = id_tbl[rule->field];
	BUG_ON(id < 0);

	/* There is no general rule, but most headers are case-insensitive.
	 * TODO: case-sensitive matching for headers when required by RFC. */
	flags |= TFW_STR_EQ_CASEI;

	return hdr_val_eq(req, id, rule->arg.str, rule->arg.len, flags);
}

static bool
match_hdr_raw(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	TfwStr *hdr;
	int i;
	tfw_str_eq_flags_t flags = map_op_to_str_eq_flags(rule->op);

	/* It would be hard to apply some header-specific rules here, so ignore
	 * case for all headers according to the robustness principle. */
	flags |= TFW_STR_EQ_CASEI;

	for (i = 0; i < req->h_tbl->size; ++i) {
		hdr = &req->h_tbl->tbl[i].field;
		if (!hdr->len)
			continue;

		/* TODO: handle LWS* between header and value for raw headers.
		 * (currently "X-Hdr:foo" is not equal to "X-Hdr: foo").
		 */
		if (tfw_str_eq_cstr(hdr, rule->arg.str, rule->arg.len, flags))
			return true;
	}

	return false;
}


typedef bool (*match_fn)(const TfwHttpReq *, const TfwHttpMatchRule *);

static const match_fn
__read_mostly match_fn_tbl[_TFW_HTTP_MATCH_F_COUNT] = {
	[TFW_HTTP_MATCH_F_HDR_CONN]	= match_hdr,
	[TFW_HTTP_MATCH_F_HDR_HOST]	= match_hdr,
	[TFW_HTTP_MATCH_F_HDR_RAW]	= match_hdr_raw,
	[TFW_HTTP_MATCH_F_HOST]		= match_host,
	[TFW_HTTP_MATCH_F_METHOD]	= match_method,
	[TFW_HTTP_MATCH_F_URI]		= match_uri,
};

static const tfw_http_match_arg_t
__read_mostly arg_type_tbl[_TFW_HTTP_MATCH_F_COUNT] = {
	[TFW_HTTP_MATCH_F_HDR_CONN]	= TFW_HTTP_MATCH_A_STR,
	[TFW_HTTP_MATCH_F_HDR_HOST]	= TFW_HTTP_MATCH_A_STR,
	[TFW_HTTP_MATCH_F_HDR_RAW]	= TFW_HTTP_MATCH_A_STR,
	[TFW_HTTP_MATCH_F_HOST]		= TFW_HTTP_MATCH_A_STR,
	[TFW_HTTP_MATCH_F_METHOD]	= TFW_HTTP_MATCH_A_METHOD,
	[TFW_HTTP_MATCH_F_URI]		= TFW_HTTP_MATCH_A_STR,
};

/**
 * Dispatch rule to a corresponding match_*() function.
 */
static bool
do_match(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	match_fn match_fn;
	tfw_http_match_fld_t field;
	tfw_http_match_arg_t arg_type;

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
	arg_type = arg_type_tbl[field];
	BUG_ON(!match_fn);
	BUG_ON(!arg_type);
	BUG_ON(arg_type != rule->arg.type);

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

	TFW_DBG("Matching request: %p, list: %p\n", req, mlst);

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
		tfw_pool_free(mlst->pool);
}
EXPORT_SYMBOL(tfw_http_match_list_free);

/**
 * call_rcu() callback for freeing the TfwHttpMatchList.
 */
void
tfw_http_match_list_rcu_free(struct rcu_head *r)
{
	TfwHttpMatchList *l = container_of(r, TfwHttpMatchList, rcu);
	tfw_pool_free(l->pool);
}
EXPORT_SYMBOL(tfw_http_match_list_rcu_free);
