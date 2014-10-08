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
 *  TFW_HTTP_MATCH_F_HOST + TFW_HTTP_MATCH_O_EQ    => match_host_eq
 *  TFW_HTTP_MATCH_F_URI + TFW_HTTP_MATCH_O_EQ     => match_uri_eq
 *  TFW_HTTP_MATCH_F_URI + TFW_HTTP_MATCH_O_PREFIX => match_uri_prefix
 *  etc...
 * Each such match_*() function takes TfwHttpReq and @arg as arguments and
 * returns true if the given request matches to the given @arg.
 * Such approach allows to keep the code structured and eases adding new
 * @field/@op combinations.
 * Currently that is implemented with a multi-dimensional array of pointers
 * (the match_fn_tbl). However the code is critical for performance, so perhaps
 * this may be optimized to a kind of jump table.
 *
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

#include "http_match.h"

static bool
match_method_eq(const TfwHttpReq *req, const TfwMatchArg *arg)
{
	return (req->method == arg->method);
}

static bool
match_uri_eq(const TfwHttpReq *req, const TfwMatchArg *arg)
{
	/* TODO: compare URI according to RFC 2616 3.2.3:
	 * - A client SHOULD use a case-sensitive octet-by-octet
	 *   comparison with exceptions:
	 *     * Comparisons of host names MUST be case-insensitive;
	 *     * Comparisons of scheme names MUST be case-insensitive;
	 * - Characters other than those in the "reserved" and "unsafe"
	 *   sets (see RFC 2396) are equivalent to their ""%" HEX HEX" encoding.
	 */
	return tfw_str_eq_cstr_ci(&req->uri, arg->str, arg->len);
}

static bool
match_uri_prefix(const TfwHttpReq *req, const TfwMatchArg *arg)
{
	return tfw_str_startswith_cstr_ci(&req->uri, arg->str, arg->len);
}

static bool
match_host_eq(const TfwHttpReq *req, const TfwMatchArg *arg)
{
	/* TODO: compare host according to RFC2616 (sections 5.2 and 3.2.3):
	 * - If Virtual Hosts are used, then the host is determined by either
	 *   URI or Host header (the header is used if URI is not absolute).
	 * - Empty port and default port (80) are equal when comparing URIs.
	 */
	return tfw_str_eq_cstr_ci(&req->host, arg->str, arg->len);
}

static bool
match_headers(const TfwHttpReq *req, const TfwMatchArg *arg,
              bool (*cmp_fn)(const TfwStr *, const char *cstr, int cstr_len))
{
	int i;
	TfwHttpHdrTbl *tbl = req->h_tbl;
	TfwStr *hdr;

	for (i = 0; i < tbl->size; ++i) {
		hdr = &tbl->tbl[i].field;
		if (cmp_fn(hdr, arg->str, arg->len))
			return true;
	}

	return false;
}

static bool
match_headers_eq(const TfwHttpReq *req, const TfwMatchArg *arg)
{
	return match_headers(req, arg, tfw_str_eq_cstr_ci);
}

static bool
match_headers_prefix(const TfwHttpReq *req, const TfwMatchArg *arg)
{
	return match_headers(req, arg, tfw_str_startswith_cstr_ci);
}

typedef bool (*tfw_match_fn_t)(const TfwHttpReq *req, const TfwMatchArg *arg);

static tfw_match_fn_t
match_fn_tbl[_TFW_HTTP_MATCH_F_COUNT][_TFW_HTTP_MATCH_O_COUNT] = {
	[TFW_HTTP_MATCH_F_METHOD] = {
		[TFW_HTTP_MATCH_O_EQ]     = match_method_eq,
	},
	[TFW_HTTP_MATCH_F_URI] = {
		[TFW_HTTP_MATCH_O_EQ]     = match_uri_eq,
		[TFW_HTTP_MATCH_O_PREFIX] = match_uri_prefix,
	},
	[TFW_HTTP_MATCH_F_HOST] = {
		[TFW_HTTP_MATCH_O_EQ]     = match_host_eq,
	},
	[TFW_HTTP_MATCH_F_HEADERS] = {
		[TFW_HTTP_MATCH_O_EQ]     = match_headers_eq,
		[TFW_HTTP_MATCH_O_PREFIX] = match_headers_prefix,
	},
};

static bool
do_match(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	tfw_match_fn_t fn;

	BUG_ON(!req || !rule);
	BUG_ON(rule->field >= ARRAY_SIZE(match_fn_tbl));
	BUG_ON(rule->op >= ARRAY_SIZE(match_fn_tbl[0]));

	TFW_DBG("rule: %p, field: %#x, op: %#x\n", rule, rule->field, rule->op);

	fn = match_fn_tbl[rule->field][rule->op];
	if (!fn) {
		TFW_WARN("No matching function defined for subj=%d op=%d\n",
		         rule->field, rule->op);
		return false;
	}

	return fn(req, &rule->arg);
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
		if (do_match(req, rule)) {
			return rule;
		}
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
