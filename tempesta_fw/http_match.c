/**
 *		Tempesta FW
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

#define TFW_MATCH_TBL_RULES_START 32
#define TFW_MATCH_RULE_ARG_LEN_MAX 512

#define TFW_MATCH_TBL_SIZE(rules_max) \
	(sizeof(TfwMatchTbl) + ((rules_max) * FIELD_SIZEOF(TfwMatchTbl, rules[0])))


TfwMatchTbl *
tfw_match_tbl_alloc(void)
{
	size_t rules_max, tbl_size, pool_size;
	TfwMatchTbl *tbl;
	TfwPool *pool;

	rules_max = TFW_MATCH_TBL_RULES_START;
	tbl_size = TFW_MATCH_TBL_SIZE(rules_max);
	pool_size = tbl_size +  rules_max * sizeof(TfwMatchRule);

	pool = __tfw_pool_new(pool_size);
	if (!pool) {
		TFW_ERR("Can't create a memory pool\n");
		return NULL;
	}

	tbl = tfw_pool_alloc(pool, tbl_size);
	if (!tbl) {
		TFW_ERR("Can't allocate memory from pool\n");
		tfw_pool_free(pool);
		return NULL;
	}

	memset(tbl, 0, tbl_size);
	tbl->pool = pool;
	tbl->rules_max = rules_max;

	return tbl;
}
EXPORT_SYMBOL(tfw_match_tbl_alloc);

void
tfw_match_tbl_free(TfwMatchTbl *tbl)
{
	BUG_ON(!tbl || !tbl->pool);

	tfw_pool_free(tbl->pool);
}
EXPORT_SYMBOL(tfw_match_tbl_free);

static TfwMatchTbl *
tbl_grow_if_full(TfwMatchTbl *tbl)
{
	size_t old_size, new_size, new_rules_max;

	if (likely(tbl->rules_n < tbl->rules_max))
		return tbl;

	new_rules_max = tbl->rules_max * 2;
	new_size = TFW_MATCH_TBL_SIZE(new_rules_max);
	old_size = TFW_MATCH_TBL_SIZE(tbl->rules_max);

	TFW_DBG("Re-allocating matching table: %p, "
		"old size: %zu, new size: %zu\n", tbl, old_size, new_size);

	tbl = tfw_pool_realloc(tbl->pool, tbl, old_size, new_size);
	if (!tbl) {
		TFW_ERR("Can't re-allocate matching table\n");
		return NULL;
	}

	return tbl;
}

int
tfw_match_tbl_rise(TfwMatchTbl **tbl, TfwMatchRule **rule, int rule_arg_len)
{
	size_t rule_size;
	TfwMatchRule *r;
	TfwMatchTbl *t;

	BUG_ON(!tbl || !*tbl || !rule);
	BUG_ON(rule_arg_len < 0 || rule_arg_len > TFW_MATCH_RULE_ARG_LEN_MAX);

	t = tbl_grow_if_full(*tbl);
	if (!t)
		return -ENOMEM;
	*tbl = t;

	rule_size = sizeof(TfwMatchRule) + rule_arg_len;
	r = tfw_pool_alloc(t->pool, rule_size);
	if (!r) {
		TFW_ERR("Can't allocate rule for table: %p\n", t);
		return -ENOMEM;
	}

	memset(r, 0, rule_size);
	t->rules[t->rules_n] = r;
	++t->rules_n;
	*rule = r;

	return 0;
}
EXPORT_SYMBOL(tfw_match_tbl_rise);

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
	return tfw_str_eq_cstr_ci(&req->uri, arg->str.data, arg->str.len);
}

static bool
match_uri_prefix(const TfwHttpReq *req, const TfwMatchArg *arg)
{
	return tfw_str_startswith_cstr_ci(&req->uri, arg->str.data, arg->str.len);
}

static bool
match_host_eq(const TfwHttpReq *req, const TfwMatchArg *arg)
{
	/* TODO: compare host according to RFC2616 (sections 5.2 and 3.2.3):
	 * - If Virtual Hosts are used, then the host is determined by either
	 *   URI or Host header (the header is used if URI is not absolute).
	 * - Empty port and default port (80) are equal when comparing URIs.
	 */
	return tfw_str_eq_cstr_ci(&req->host, arg->str.data, arg->str.len);
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
		if (cmp_fn(hdr, arg->str.data, arg->str.len))
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
match_fn_tbl[_TFW_MATCH_SUBJ_COUNT][_TFW_MATCH_OP_COUNT] = {
	[TFW_MATCH_SUBJ_URI] = {
		[TFW_MATCH_OP_EQ]	= match_uri_eq,
		[TFW_MATCH_OP_PREFIX] 	= match_uri_prefix,
	},
	[TFW_MATCH_SUBJ_HOST] = {
		[TFW_MATCH_OP_EQ] 	= match_host_eq,
	},
	[TFW_MATCH_SUBJ_HEADERS] = {
		[TFW_MATCH_OP_EQ] 	= match_headers_eq,
		[TFW_MATCH_OP_PREFIX] 	= match_headers_prefix,
	},
};

static bool
do_match(const TfwHttpReq *req, const TfwMatchRule *rule)
{
	tfw_match_fn_t fn;

	BUG_ON(!req || !rule);
	BUG_ON(rule->subj >= ARRAY_SIZE(match_fn_tbl));
	BUG_ON(rule->op >= ARRAY_SIZE(match_fn_tbl[0]));

	fn = match_fn_tbl[rule->subj][rule->op];
	if (!fn) {
		TFW_WARN("No matching function defined for subj=%d op=%d\n",
		         rule->subj, rule->op);
		return false;
	}

	return fn(req, &rule->arg);
}

const TfwMatchRule *
tfw_match_http_req(const TfwHttpReq *req, const TfwMatchTbl *tbl)
{
	int i;

	BUG_ON(!req || !tbl);

	for (i = 0; i < tbl->rules_n; ++i) {
		if (do_match(req, tbl->rules[i]))
			return tbl->rules[i];
	}

	return NULL;
}
