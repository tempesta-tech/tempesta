/**
 *		Tempesta FW
 *
 * HTTP table logic.
 *
 * The matching process is driven by a "chain" of rules that look like this:
 *  @field  [ @hdr_name ]  == (!=)    @arg     ->   @action [ = @action_val ]
 * { TFW_HTTP_MATCH_F_HOST,   "*example.com",  TFW_HTTP_MATCH_ACT_CHAIN },
 * { TFW_HTTP_MATCH_F_URI,    "/foo/bar*",     TFW_HTTP_MATCH_ACT_VHOST },
 * { TFW_HTTP_MATCH_F_URI,    "/",             TFW_HTTP_MATCH_ACT_MARK  },
 *
 * The table is represented by a list of linked chains, that contain rules
 * of TfwHttpMatchRule type that has the fields described above:
 *  - @field is the first argument in rule - the field of a parsed HTTP request:
 *    method/uri/host/header/etc; @hdr_name is used only in cases when
 *    @field == 'hdr', to specify the name of desired header.
 *  - @arg is the second argument in rule, its type is determined dynamically
 *    depending on the @field (may be number/string/addr/etc); comparison
 *    operator for @field and @arg depends on "==" ("!=") sign and on wildcard
 *    existence in @arg:
 *    "==": "arg" => eq / "arg*" => eq_prefix / "*arg" => eq_suffix.
 *    "!=": "arg" => non_eq / "arg*" => non_eq_prefix / "*arg" => non_eq_suffix.
 *  - @act is a rule action with appropriate type (examples specified above);
 *    possible types are: reference to virtual host (defined before), reference
 *    to other HTTP chain (defined before and not the same), "mark" action for
 *    setting netfilter marks into all skbs for all matched requests, "block"
 *    action for blocking all matched requests.
 *  - @action_val is possible value for specified action; only "mark" action is
 *    allowed to have value (unsigned integer type).
 *
 * So the tfw_http_tbl_scan() threads a HTTP request sequentially across
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
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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

/**
 * Look up a header in the @req->h_tbl by given @id,
 * and compare @rule->arg with the header's value (skipping name and LWS).
 *
 * For example:
 *   hdr_val_eq(req,
 *		{
 *			.arg.str="natsys-lab",
 *			.arg.len=10,
 *			.op=TFW_STR_EQ_PREFIX
 *		},
 *		TFW_HTTP_HDR_HOST);
 * will match the following headers:
 *   "Host: natsys-lab"
 *   "Host: natsys-lab.com"
 *   "Host  :  natsys-lab.com"
 */
static bool
hdr_val_eq(const TfwHttpReq *req, const TfwHttpMatchRule *rule,
	   tfw_http_hdr_t id)
{
	TfwStr *hdr;
	TfwStr hdr_val;
	tfw_str_eq_flags_t flags;
	tfw_http_match_op_t op =  rule->op;
	const char *str = rule->arg.str;
	int str_len = rule->arg.len;

	BUG_ON(id < 0 || id >= TFW_HTTP_HDR_NUM);

	hdr = &req->h_tbl->tbl[id];
	if (TFW_STR_EMPTY(hdr))
		return false;

	if (op == TFW_HTTP_MATCH_O_WILDCARD)
		return true;

	tfw_http_msg_clnthdr_val(hdr, id, &hdr_val);

	flags = map_op_to_str_eq_flags(rule->op);
	/*
	 * There is no general rule, but most headers are case-insensitive.
	 * TODO: case-sensitive matching for headers when required by RFC.
	 */
	flags |= TFW_STR_EQ_CASEI;

	if (op == TFW_HTTP_MATCH_O_SUFFIX)
		return tfw_str_eq_cstr_off(&hdr_val, hdr_val.len - str_len,
					   str, str_len, flags);

	return tfw_str_eq_cstr(&hdr_val, str, str_len, flags);
}

static bool
match_method(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	/* Only WILDCARD and EQ operators are supported. */
	if (rule->op == TFW_HTTP_MATCH_O_WILDCARD)
		return true;

	BUG_ON(rule->op != TFW_HTTP_MATCH_O_EQ);
	return req->method == rule->arg.method;
}

static bool
match_uri(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	tfw_str_eq_flags_t flags;
	const TfwStr *uri_path = &req->uri_path;
	const TfwHttpMatchArg *arg = &rule->arg;

	if (rule->op == TFW_HTTP_MATCH_O_WILDCARD)
		return true;

	flags = map_op_to_str_eq_flags(rule->op);
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
	tfw_str_eq_flags_t flags;
	const TfwHttpMatchArg *arg;
	const TfwStr *host = &req->host;

	if (host->len == 0)
		return hdr_val_eq(req, rule, TFW_HTTP_HDR_HOST);

	if (rule->op == TFW_HTTP_MATCH_O_WILDCARD)
		return true;

	flags = map_op_to_str_eq_flags(rule->op);
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
	arg = &rule->arg;
	if (rule->op == TFW_HTTP_MATCH_O_SUFFIX)
		return tfw_str_eq_cstr_off(host, host->len - arg->len,
					   arg->str, arg->len, flags);

	return tfw_str_eq_cstr(host, arg->str, arg->len, flags);
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

	for (i = TFW_HTTP_HDR_RAW; i < req->h_tbl->off; ++i) {
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
			c = chunk->data;
			cend = chunk->data + chunk->len;

#define _TRY_NEXT_CHUNK(ok_code, err_code)		\
	if (unlikely(c == cend))	{		\
		++cnum;					\
		chunk = TFW_STR_CHUNK(dup, cnum); 	\
		if (chunk) {				\
			c = chunk->data;		\
			cend = chunk->data + chunk->len;\
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

					break;
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
			if (p == pend && isspace(*c)) {
				c++;
				goto state_hdr_sp;
			}

			continue;

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
match_hdr(const TfwHttpReq *req, const TfwHttpMatchRule *rule)
{
	tfw_http_hdr_t id = rule->hid;

	BUG_ON(id < 0);
	if (id == TFW_HTTP_HDR_RAW)
		return match_hdr_raw(req, rule);

	return hdr_val_eq(req, rule, id);
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
	unsigned int mark = req->msg.skb_head->mark;

	if (!mark)
		return false;

	if (rule->op == TFW_HTTP_MATCH_O_WILDCARD)
		return true;

	BUG_ON(rule->op != TFW_HTTP_MATCH_O_EQ);
	return mark == rule->arg.num;
}

typedef bool (*match_fn)(const TfwHttpReq *, const TfwHttpMatchRule *);

static const match_fn match_fn_tbl[_TFW_HTTP_MATCH_F_COUNT] = {
	[TFW_HTTP_MATCH_F_WILDCARD]	= match_wildcard,
	[TFW_HTTP_MATCH_F_HDR]		= match_hdr,
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

	TFW_DBG2("rule: %p, field: %#x, op: %#x, arg:%d:%d'%.*s'\n",
		 rule, rule->field, rule->op, rule->arg.type, rule->arg.len,
		 rule->arg.len, rule->arg.str);

	BUG_ON(!req || !rule);
	BUG_ON(rule->field <= 0 || rule->field >= _TFW_HTTP_MATCH_F_COUNT);
	BUG_ON(rule->op <= 0 || rule->op >= _TFW_HTTP_MATCH_O_COUNT);
	BUG_ON(rule->act.type <= 0 ||
	       rule->act.type >= _TFW_HTTP_MATCH_ACT_COUNT);
	BUG_ON(rule->arg.type <= 0 ||
	       rule->arg.type >= _TFW_HTTP_MATCH_A_COUNT);
	BUG_ON(rule->arg.len < 0 ||
	       rule->arg.len >= TFW_HTTP_MATCH_MAX_ARG_LEN);

	field = rule->field;
	match_fn = match_fn_tbl[field];
	BUG_ON(!match_fn);

	if (!(match_fn(req, rule) ^ rule->inv))
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

static tfw_http_match_arg_t
tfw_http_tbl_arg_type(tfw_http_match_fld_t field)
{
	static const tfw_http_match_arg_t arg_types[_TFW_HTTP_MATCH_F_COUNT] = {
		[TFW_HTTP_MATCH_F_WILDCARD]	= TFW_HTTP_MATCH_A_WILDCARD,
		[TFW_HTTP_MATCH_F_HDR]		= TFW_HTTP_MATCH_A_STR,
		[TFW_HTTP_MATCH_F_HOST]		= TFW_HTTP_MATCH_A_STR,
		[TFW_HTTP_MATCH_F_METHOD]	= TFW_HTTP_MATCH_A_METHOD,
		[TFW_HTTP_MATCH_F_URI]		= TFW_HTTP_MATCH_A_STR,
		[TFW_HTTP_MATCH_F_MARK]		= TFW_HTTP_MATCH_A_NUM,
	};

	BUG_ON(field <= 0 || field >= _TFW_HTTP_MATCH_F_COUNT);

	return arg_types[field];
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
tfw_http_rule_arg_init(TfwHttpMatchRule *rule, const char *arg, size_t arg_len)
{
	if (rule->arg.type == TFW_HTTP_MATCH_A_WILDCARD ||
	    rule->op == TFW_HTTP_MATCH_O_WILDCARD)
		return 0;

	if (rule->arg.type == TFW_HTTP_MATCH_A_NUM) {
		if (tfw_cfg_parse_uint(arg, &rule->arg.num) || !rule->arg.num) {
			TFW_ERR_NL("http_match: invalid 'mark' condition:"
				   " '%s'\n", arg);
			return -EINVAL;
		}
		rule->op = TFW_HTTP_MATCH_O_EQ;
		return 0;
	}

	if (rule->arg.type == TFW_HTTP_MATCH_A_METHOD) {
		if (tfw_http_tbl_method(arg, &rule->arg.method)) {
			TFW_ERR_NL("http_tbl: invalid 'method' condition:"
				   " '%s'\n", arg);
			return -EINVAL;
		}
		rule->op = TFW_HTTP_MATCH_O_EQ;
		return 0;
	}

	rule->arg.len = arg_len;
	memcpy(rule->arg.str, arg, arg_len);
	if (rule->field == TFW_HTTP_MATCH_F_HDR
	    && rule->hid == TFW_HTTP_HDR_RAW)
	{
		char *p = rule->arg.str;
		while ((*p = tolower(*p)))
			p++;
	}

	return 0;
}
EXPORT_SYMBOL(tfw_http_rule_arg_init);

const char *
tfw_http_arg_adjust(const char *arg, tfw_http_match_fld_t field,
		    const char *raw_hdr_name, size_t *size_out,
		    tfw_http_match_arg_t *type_out,
		    tfw_http_match_op_t *op_out)
{
	int i;
	bool escaped;
	char *arg_out, *pos;
	size_t name_len = 0, full_name_len = 0, len = strlen(arg);
	bool wc_arg = (arg[0] == '*' && len == 1);

	*type_out = tfw_http_tbl_arg_type(field);

	/*
	 * If this is simple wildcard argument and this is not raw
	 * header case, this is wildcard type case and we do not
	 * need any argument for matching.
	 */
	if (wc_arg && !raw_hdr_name)
		return NULL;

	if (raw_hdr_name) {
		name_len = strlen(raw_hdr_name);
		full_name_len = name_len + SLEN(S_DLM);
	}

	if (!(arg_out = kzalloc(full_name_len + len + 1, GFP_KERNEL))) {
		TFW_ERR_NL("http_match: unable to allocate rule"
			   " argument.\n");
		return ERR_PTR(-ENOMEM);
	}

	if (raw_hdr_name) {
		memcpy(arg_out, raw_hdr_name, name_len);
		memcpy(arg_out + name_len, S_DLM, SLEN(S_DLM));
	}

	*op_out = TFW_HTTP_MATCH_O_EQ;

	/*
	 * In cases of simple wildcard argument for raw header or
	 * argument ended with wildcard, the prefix matching pattern
	 * should be applied.
	 */
	if (wc_arg || (len > 1 && arg[len - 1] == '*' && arg[len - 2] != '\\'))
		*op_out = TFW_HTTP_MATCH_O_PREFIX;

	/*
	 * For argument started with wildcard, the suffix matching
	 * pattern should be applied.
	 */
	if (!wc_arg && arg[0] == '*') {
		if (*op_out == TFW_HTTP_MATCH_O_PREFIX)
			TFW_WARN_NL("http_match: unable to match"
				    " double-wildcard patterns '%s', so"
				    " prefix pattern will be applied\n", arg);

		else if (raw_hdr_name)
			TFW_WARN_NL("http_match: unable to match suffix"
				    " pattern '%s' in case of raw header"
				    " specification: '%s', so wildcard pattern"
				    " will not be applied\n", arg, raw_hdr_name);

		else
			*op_out = TFW_HTTP_MATCH_O_SUFFIX;
	}

	len = full_name_len;
	escaped = false;
	pos = arg_out + full_name_len;
	for (i = 0; arg[i]; ++i) {
		if (arg[i] == '*' && !escaped && (i == 0 || !arg[i + 1]))
			continue;
		if (arg[i] != '\\' || escaped) {
			escaped = false;
			*pos = arg[i];
			++len;
			++pos;
		}
		else if (arg[i] == '\\') {
			escaped = true;
		}
	}
	*size_out = len + 1;

	return arg_out;
}
EXPORT_SYMBOL(tfw_http_arg_adjust);

int
tfw_http_verify_hdr_field(tfw_http_match_fld_t field, const char **hdr_name,
			  unsigned int *hid_out)
{
	const char *h_name = *hdr_name;

	if (field != TFW_HTTP_MATCH_F_HDR && h_name) {
		TFW_ERR_NL("http_tbl: unnecessary extra field is specified:"
			   " '%s'\n", h_name);
		return -EINVAL;
	} else if (field == TFW_HTTP_MATCH_F_HDR && !h_name) {
		TFW_ERR_NL("http_tbl: header name missed\n");
		return -EINVAL;
	} else if (h_name) {
		size_t h_len = strlen(h_name);
		const TfwStr tmp_hdr = {
			.chunks = (TfwStr []){
				{ .data = (void *)h_name,	.len = h_len },
				{ .data = S_DLM,		.len = SLEN(S_DLM) }
			},
			.len = h_len + SLEN(S_DLM),
			.eolen = 0,
			.nchunks = 2
		};

		*hid_out = tfw_http_msg_req_spec_hid(&tmp_hdr);

		if (*hid_out != TFW_HTTP_HDR_RAW)
			*hdr_name = NULL;
	}

	return 0;
}
EXPORT_SYMBOL(tfw_http_verify_hdr_field);
