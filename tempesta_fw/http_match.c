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
 *   - Handle "Percent-encoding" during URI comparison.
 *   - Default port 80 in Host header and absoluteURI.
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

#include "http_match.h"
#include "http.h"

typedef bool (*match_fn)(const TfwHttpReq *, const TfwHttpMatchRule *);
typedef typeof(&tfw_str_eq_cstr) eq_str_fn;
typedef typeof(&tfw_str_eq_kv) eq_hdr_fn;

/**
 * Look up a header in the @req->h_tbl by given @id,
 * and compare @val with the header's value (skipping name and LWS).
 *
 * For example:
 *   hdr_cmp(req, TFW_HTTP_HDR_HOST, "natsys-lab", 14, tfw_str_subjoins_kv);
 * will match the following headers:
 *   "Host: natsys-lab"
 *   "Host: natsys-lab.com"
 *   "Host  :  natsys-lab.com"
 */
static bool
hdr_cmp(const TfwHttpReq *req, tfw_http_hdr_t id, const char *val,
        int val_len, eq_hdr_fn fn)
{
	TfwStr *hdr;
	const char *name;
	int name_len;

	hdr = &req->h_tbl->tbl[id].field;
	if (!hdr->len)
		return false;

	name = tfw_http_hdr_name(id);
	name_len = tfw_http_hdr_name_len(id);

	return fn(hdr, name, name_len, ':', val, val_len);
}

static bool
match_method_in(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	return (req->method & rule->arg.method);
}

static bool
match_method_eq(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	return (req->method == rule->arg.method);
}

static bool
match_uri(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	/* The comparison is case-sensitive according to RFC 2616 (3.2.3).
	 * The RFC says a client SHOULD use a case-sensitive octet-by-octet
	 * comparison" except for 'host' and 'scheme'. Since we don't store
	 * them in the @uri field, the whole field is case-sensitive.
	 *
	 * TODO: Handle URI encoding.
	 */
	static const eq_str_fn op_tbl[] = {
		[TFW_HTTP_MATCH_O_EQ] = tfw_str_eq_cstr,
		[TFW_HTTP_MATCH_O_PREFIX] = tfw_str_subjoins_cstr,
	};
	eq_str_fn fn = op_tbl[rule->op];
	BUG_ON(!fn);

	return fn(&req->uri, rule->arg.str, rule->arg.len);
}

static bool
match_host(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	/* According to RFC 2616 (5.2), when Virtual Hosts are on, then
	 * both URI and Host header are used (URI overrides Host).
	 * Also the comparison is case-insensitive.
	 *
	 * TODO: Empty and 80 ports are equal.
	 */
	static const eq_str_fn op_tbl_uri[] = {
		[TFW_HTTP_MATCH_O_EQ] = tfw_str_eq_cstr_ci,
		[TFW_HTTP_MATCH_O_PREFIX] = tfw_str_subjoins_cstr_ci
	};
	static const eq_hdr_fn op_tbl_hdr[] = {
		[TFW_HTTP_MATCH_O_EQ] = tfw_str_eq_kv_ci,
		[TFW_HTTP_MATCH_O_PREFIX] = tfw_str_subjoins_kv_ci
	};

	if (req->host.len) {
		eq_str_fn fn = op_tbl_uri[rule->op];
		BUG_ON(!fn);

		return fn(&req->host, rule->arg.str, rule->arg.len);
	} else {
		eq_hdr_fn fn = op_tbl_hdr[rule->op];
		BUG_ON(!fn);

		return hdr_cmp(req, TFW_HTTP_HDR_HOST, rule->arg.str,
		               rule->arg.len, fn);
	}
}

static bool
match_hdr(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	/* There is no general constraint on case-sensitivity of header values,
	 * each header defines its own rules. However, we always ignore case
	 * here because that apply to the most of the headers.
	 *
	 * TODO: case-sensitive matching for headers when required by RFC.
	 */
	static const eq_hdr_fn op_tbl[] = {
		[TFW_HTTP_MATCH_O_EQ] = tfw_str_eq_kv_ci,
		[TFW_HTTP_MATCH_O_PREFIX] = tfw_str_subjoins_kv_ci
	};
	static const tfw_http_hdr_t id_tbl[] = {
		[0 ... _TFW_HTTP_MATCH_F_COUNT] = -1,
		[TFW_HTTP_MATCH_F_HDR_CONN] = TFW_HTTP_HDR_CONNECTION,
		[TFW_HTTP_MATCH_F_HDR_HOST] = TFW_HTTP_HDR_HOST,
	};
	eq_hdr_fn fn = op_tbl[rule->op];
	tfw_http_hdr_t id = id_tbl[rule->field];

	BUG_ON(id < 0 || !fn);

	return hdr_cmp(req, id, rule->arg.str, rule->arg.len, fn);
}

static bool
match_hdr_raw(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	/* Raw headers are not tokenized, (e.g. "Host:foo" != "Host: foo).
	 *
	 * TODO: handle LWS* between header and value for raw headers.
	 */
	static const eq_str_fn op_tbl[] = {
		[TFW_HTTP_MATCH_O_EQ] = tfw_str_eq_cstr_ci,
		[TFW_HTTP_MATCH_O_PREFIX] = tfw_str_eq_cstr_ci
	};
	eq_str_fn fn;
	TfwStr *hdr;
	int i;

	fn = op_tbl[rule->op];
	BUG_ON(!fn);

	for (i = 0; i < req->h_tbl->size; ++i) {
		hdr = &req->h_tbl->tbl[i].field;
		if (!hdr->len)
			continue;
		if (fn(hdr, rule->arg.str, rule->arg.len))
			return true;
	}

	return false;
}

static const match_fn
match_fn_tbl[_TFW_HTTP_MATCH_F_COUNT][_TFW_HTTP_MATCH_O_COUNT] = {
	[TFW_HTTP_MATCH_F_METHOD] = {
		[TFW_HTTP_MATCH_O_EQ]     = match_method_eq,
		[TFW_HTTP_MATCH_O_IN]     = match_method_in,
	},
	[TFW_HTTP_MATCH_F_URI] = {
		[TFW_HTTP_MATCH_O_EQ]     = match_uri,
		[TFW_HTTP_MATCH_O_PREFIX] = match_uri,
	},
	[TFW_HTTP_MATCH_F_HOST] = {
		[TFW_HTTP_MATCH_O_EQ]     = match_host,
		[TFW_HTTP_MATCH_O_PREFIX] = match_host,
	},
	[TFW_HTTP_MATCH_F_HDR_CONN] = {
		[TFW_HTTP_MATCH_O_EQ]     = match_hdr,
		[TFW_HTTP_MATCH_O_PREFIX] = match_hdr,
	},
	[TFW_HTTP_MATCH_F_HDR_HOST] = {
		[TFW_HTTP_MATCH_O_EQ]     = match_hdr,
		[TFW_HTTP_MATCH_O_PREFIX] = match_hdr,
	},
	[TFW_HTTP_MATCH_F_HDR_RAW] = {
		[TFW_HTTP_MATCH_O_EQ]     = match_hdr_raw,
		[TFW_HTTP_MATCH_O_PREFIX] = match_hdr_raw,
	},
};

static bool
do_match(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	match_fn fn;

	BUG_ON(!req || !rule);
	BUG_ON(rule->field >= ARRAY_SIZE(match_fn_tbl));
	BUG_ON(rule->op >= ARRAY_SIZE(match_fn_tbl[0]));

	TFW_DBG("rule: %p, field: %#x, op: %#x\n", rule, rule->field, rule->op);

	fn = match_fn_tbl[rule->field][rule->op];
	BUG_ON(!fn);

	return fn(req, rule);
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
