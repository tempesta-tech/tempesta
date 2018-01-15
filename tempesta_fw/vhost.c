/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2017 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "tempesta_fw.h"
#include "http.h"
#include "http_match.h"
#include "http_msg.h"
#include "vhost.h"
#include "str.h"

/* Mappings for match operators. */
static const TfwCfgEnum tfw_match_enum[] = {
	{ "*",		TFW_HTTP_MATCH_O_WILDCARD },
	{ "eq",		TFW_HTTP_MATCH_O_EQ },
	{ "prefix",	TFW_HTTP_MATCH_O_PREFIX },
	{ "suffix",	TFW_HTTP_MATCH_O_SUFFIX },
	{ 0 }
};

/* Mappings for HTTP request methods. */
static const TfwCfgEnum tfw_method_enum[] = {
	{ "*",		UINT_MAX },
	{ "COPY",	1 << TFW_HTTP_METH_COPY },
	{ "DELETE",	1 << TFW_HTTP_METH_DELETE },
	{ "GET",	1 << TFW_HTTP_METH_GET },
	{ "HEAD",	1 << TFW_HTTP_METH_HEAD },
	{ "LOCK",	1 << TFW_HTTP_METH_LOCK },
	{ "MKCOL",	1 << TFW_HTTP_METH_MKCOL },
	{ "MOVE",	1 << TFW_HTTP_METH_MOVE },
	{ "OPTIONS",	1 << TFW_HTTP_METH_OPTIONS },
	{ "PATCH",	1 << TFW_HTTP_METH_PATCH },
	{ "POST",	1 << TFW_HTTP_METH_POST },
	{ "PROPFIND",	1 << TFW_HTTP_METH_PROPFIND },
	{ "PROPPATCH",	1 << TFW_HTTP_METH_PROPPATCH },
	{ "PUT",	1 << TFW_HTTP_METH_PUT },
	{ "TRACE",	1 << TFW_HTTP_METH_TRACE },
	{ "UNLOCK",	1 << TFW_HTTP_METH_UNLOCK, },
	{ "PURGE",	1 << TFW_HTTP_METH_PURGE },
	{ "unknown",	1 << _TFW_HTTP_METH_UNKNOWN },
	{ 0 }
};

/*
 * All cache policy directives are put into a fixed size array.
 * The directives are deduplicated when put into the array.
 * Individual directives are linked to from lists of cache policy
 * directives for specific location sections.
 */
#define TFW_CAPOLICY_ARRAY_SZ	(64)

static TfwCaPolicy	tfw_capolicy[TFW_CAPOLICY_ARRAY_SZ];
static size_t		tfw_capolicy_sz = 0;	/* Current size. */

/*
 * Each non-idempotent request definition directive is put into
 * a separately allocated memory area. The pointers to the memory
 * are put into a fixed size array of pointers within a location
 * definition.
 */
#define TFW_NIPDEF_ARRAY_SZ	(64)

#define TFW_USRHDRS_ARRAY_SZ	(64)

/*
 * All 'location' directives are put into a fixed size array.
 * Duplicate directives are not allowed.
 */
#define TFW_LOCATION_ARRAY_SZ	(64)

static TfwLocation	tfw_location[TFW_LOCATION_ARRAY_SZ];
static size_t		tfw_location_sz = 0;	/* Current size. */

/*
 * Default location is a wildcard location. It matches any URI.
 * It may (or may not) contain a set of cache matching directives,
 * and/or a set of non-idempotent request definitions.
 */
static TfwCaPolicy	*tfw_capolicy_dflt[TFW_CAPOLICY_ARRAY_SZ];
static TfwNipDef	*tfw_nipdef_dflt[TFW_NIPDEF_ARRAY_SZ];
static TfwHdrModsDesc	tfw_hmods_req_dflt[TFW_USRHDRS_ARRAY_SZ];
static TfwHdrModsDesc	tfw_hmods_resp_dflt[TFW_USRHDRS_ARRAY_SZ];

static TfwLocation tfw_location_dflt = {
	.op = TFW_HTTP_MATCH_O_WILDCARD,
	.arg = "*",
	.len = 1,
	.capo = tfw_capolicy_dflt,
	.capo_sz = 0,
	.nipdef = tfw_nipdef_dflt,
	.nipdef_sz = 0,
	.mod_hdrs = { {0, tfw_hmods_req_dflt}, {0, tfw_hmods_resp_dflt}}
};

/* Pool for 'hdr_add' directive (TfwLocation->usr_hdrs) */
static TfwPool *tfw_usr_hdrs_pool;

/*
 * IP addresses that make the ACL for cache purge operations are put
 * into a fixed size array. The IP addresses are kept in form of an
 * IPv6 address and the prefix size. sockaddr_in6.sin6_scope_id is
 * used to store the prefix size.
 */
#define TFW_CAPUACL_ARRAY_SZ	(32)

static TfwAddr		tfw_capuacl[TFW_CAPUACL_ARRAY_SZ];

/*
 * Default vhost is a wildcard vhost. It matches any URI.
 * It may (or may not) contain a set of various directives.
 *
 * Note that @loc_dflt in the default vhost serves as global
 * default caching policy.
 */
static const char s_hdr_via_dflt[] =
	"tempesta_fw" " (" TFW_NAME " " TFW_VERSION ")";

static TfwVhost		tfw_vhost_dflt = {
	.hdr_via	= s_hdr_via_dflt,
	.hdr_via_len	= sizeof(s_hdr_via_dflt) - 1,
	.loc		= tfw_location,
	.loc_dflt	= &tfw_location_dflt,
	.loc_dflt_sz	= 1,
	.capuacl	= tfw_capuacl,
};

/*
 * Match the IP address @addr against the addresses in the ACL list.
 * The addresses are compared according to the prefix length stored
 * with each address in the ACL list.
 * True is returned if the match is found.
 * False is returned otherwise.
 */
bool
tfw_capuacl_match(TfwVhost *vhost, TfwAddr *addr)
{
	size_t i;
	struct in6_addr *inaddr = &addr->v6.sin6_addr;

	for (i = 0; i < vhost->capuacl_sz; ++i) {
		TfwAddr *acl_addr = &vhost->capuacl[i];
		if (ipv6_prefix_equal(inaddr, &acl_addr->v6.sin6_addr,
					      acl_addr->in6_prefix))
			return true;
	}
	return false;
}

/*
 * Matching functions for match operators. A TfwStr{} is compared
 * with a plain C string according to a specified match operator.
 * The functions are generic.
 */
static bool
__tfw_match_wildcard(tfw_match_t op, const char *cstr, size_t len, TfwStr *arg)
{
	return ((op == TFW_HTTP_MATCH_O_WILDCARD)
		&& (len == 1) && (*cstr == '*'));
}

static bool
__tfw_match_suffix(tfw_match_t op, const char *cstr, size_t len, TfwStr *arg)
{
	tfw_str_eq_flags_t flags = TFW_STR_EQ_DEFAULT | TFW_STR_EQ_CASEI;
	return tfw_str_eq_cstr_off(arg, arg->len - len, cstr, len, flags);
}

static bool
__tfw_match_eq(tfw_match_t op, const char *cstr, size_t len, TfwStr *arg)
{
	tfw_str_eq_flags_t flags = TFW_STR_EQ_DEFAULT | TFW_STR_EQ_CASEI;
	return tfw_str_eq_cstr(arg, cstr, len, flags);
}

static bool
__tfw_match_prefix(tfw_match_t op, const char *cstr, size_t len, TfwStr *arg)
{
	tfw_str_eq_flags_t flags = TFW_STR_EQ_PREFIX | TFW_STR_EQ_CASEI;
	return tfw_str_eq_cstr(arg, cstr, len, flags);
}

typedef bool (*__tfw_match_fn)(tfw_match_t, const char *, size_t, TfwStr *);

static const __tfw_match_fn __tfw_match_fn_tbl[] = {
	[0 ... _TFW_HTTP_MATCH_O_COUNT] = NULL,
	[TFW_HTTP_MATCH_O_WILDCARD]	= __tfw_match_wildcard,
	[TFW_HTTP_MATCH_O_EQ]		= __tfw_match_eq,
	[TFW_HTTP_MATCH_O_PREFIX]	= __tfw_match_prefix,
	[TFW_HTTP_MATCH_O_SUFFIX]	= __tfw_match_suffix,
};

/*
 * Find a matching non-idempotent request directive. Strings
 * are compared according to the match operator in the directive.
 * A pointer to the matching TfwNipDef structure is returned if
 * the match is found. NULL is returned if there's no match.
 */
static inline bool
__tfw_nipdef_match_fn(TfwNipDef *nipdef, TfwStr *arg)
{
	__tfw_match_fn match_fn = __tfw_match_fn_tbl[nipdef->op];
	BUG_ON(!match_fn);

	return match_fn(nipdef->op, nipdef->arg, nipdef->len, arg);
}

TfwNipDef *
tfw_nipdef_match(TfwLocation *loc, unsigned char method, TfwStr *arg)
{
	size_t i;

	BUG_ON(!loc);
	BUG_ON(!arg);

	for (i = 0; i < loc->nipdef_sz; ++i) {
		TfwNipDef *nipdef = loc->nipdef[i];
		if ((nipdef->method & (1 << method))
		    && __tfw_nipdef_match_fn(nipdef, arg))
			return nipdef;
	}
	return NULL;
}

/*
 * Find a matching cache policy directive. Strings are compared
 * according to the match operator in the directive. A pointer
 * to the matching TfwCaPolicy structure is returned if the
 * match is found. Null is returned if there's no match.
 */
static inline bool
__tfw_capolicy_match_fn(TfwCaPolicy *capo, TfwStr *arg)
{
	__tfw_match_fn match_fn = __tfw_match_fn_tbl[capo->op];
	BUG_ON(!match_fn);

	return match_fn(capo->op, capo->arg, capo->len, arg);
}

TfwCaPolicy *
tfw_capolicy_match(TfwLocation *loc, TfwStr *arg)
{
	size_t i;

	BUG_ON(!loc);
	BUG_ON(!arg);

	for (i = 0; i < loc->capo_sz; ++i) {
		TfwCaPolicy *capo = loc->capo[i];
		if (__tfw_capolicy_match_fn(capo, arg))
			return capo;
	}
	return NULL;
}

/*
 * Find a matching location directive within specified vhost.
 * A pointer to the matching TfwLocation structure is returned
 * if the match is found. NULL is returned if there's no match.
 */
static inline bool
__tfw_location_match(TfwLocation *loc, TfwStr *arg)
{
	__tfw_match_fn match_fn = __tfw_match_fn_tbl[loc->op];
	BUG_ON(!match_fn);

	return match_fn(loc->op, loc->arg, loc->len, arg);
}

TfwLocation *
tfw_location_match(TfwVhost *vhost, TfwStr *arg)
{
	size_t i;

	BUG_ON(!vhost);
	BUG_ON(!arg);

	for (i = 0; i < vhost->loc_sz; ++i) {
		TfwLocation *loc = &vhost->loc[i];
		if (__tfw_location_match(loc, arg))
			return loc;
	}
	return NULL;
}

/*
 * Find a matching vhost directive. Strings are compared according
 * to the match operator in the directive. A pointer to the matching
 * TfwVhost structure is returned if the match is found. A pointer
 * to the default vhost structure is returned if there's no match.
 * Thus the returned value is always a valid address.
 */
TfwVhost *
tfw_vhost_get_default(void)
{
	return &tfw_vhost_dflt;
}

TfwVhost *
tfw_vhost_match(TfwStr *arg)
{
	BUG_ON(!arg);

	/* For now there's just the default vhost. */
	return &tfw_vhost_dflt;
}

/**
 * Find a headers modification description according to target message type
 * and current location.
 *
 * @req		- http request to deturmine location;
 * @msg_type	- Target message type (TFW_HTTP_MSG_REQ or TFW_HTTP_MSG_RESP).
 */
TfwHdrMods*
tfw_vhost_get_hdr_mods(TfwMsg *msg, int msg_type)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwLocation *loc = req->location;

	/* TODO #862: req->location must be the full set of options. */
	if (!loc || !loc->mod_hdrs[msg_type].sz)
		loc = req->vhost->loc_dflt;
	if (!loc || !loc->mod_hdrs[msg_type].sz)
		loc = (tfw_vhost_get_default())->loc_dflt;
	BUG_ON(!loc);

	return &loc->mod_hdrs[msg_type];
}

/*
 * Configuration processing.
 */

/*
 * Pointer to the current location structure.
 * The pointer is shared among multiple functions below.
 */
static TfwLocation *tfwcfg_this_location;

/*
 * Find a non-idempotent request definition entry within specified location.
 * Entries are processed in the order they are defined in the configuration.
 * That means the matching entry must be the last entry in the array, and it
 * must have the same match @op and the same @arg.
 */
static TfwNipDef *
tfw_nipdef_lookup(TfwLocation *loc, int op, const char *arg, size_t len)
{
	TfwNipDef *nipdef;

	if (!loc->nipdef_sz)
		return NULL;

	nipdef = loc->nipdef[loc->nipdef_sz - 1];
	if ((nipdef->op == op) && (nipdef->len == len)
	    && !strcasecmp(nipdef->arg, arg))
		return nipdef;

	return NULL;
}

static TfwNipDef *
tfw_nipdef_lookup_dup(TfwLocation *loc, int method,
		      int op, const char *arg, size_t len)
{
	size_t i;
	TfwNipDef *nipdef;

	if (!loc->nipdef_sz)
		return NULL;

	/* Check all entries but the last one. */
	for (i = 0; i < loc->nipdef_sz - 1; ++i) {
		nipdef = loc->nipdef[i];
		if ((nipdef->op == op) && (nipdef->len == len)
		    && !strcasecmp(nipdef->arg, arg))
			return nipdef;
	}
	/* Check the last entry. */
	nipdef = loc->nipdef[i];
	if ((nipdef->method & method) && (nipdef->op == op)
	    && (nipdef->len == len) && !strcasecmp(nipdef->arg, arg))
		return nipdef;

	return NULL;
}

/*
 * Create and initialize a new non-idempotent request definition entry,
 * and add it to the given location structure. The entry is added as
 * a pointer to the memory allocated to hold the definition.
 */
static TfwNipDef *
tfw_nipdef_addnew(TfwLocation *loc, int method,
		  int op, const char *arg, size_t len)
{
	char *data;
	TfwNipDef *nipdef;

	if (loc->nipdef_sz == TFW_NIPDEF_ARRAY_SZ)
		return NULL;

	if ((data = kmalloc(sizeof(TfwNipDef) + len + 1, GFP_KERNEL)) == NULL)
		return NULL;

	nipdef = (TfwNipDef *)data;
	nipdef->method = method;
	nipdef->op = op;
	nipdef->arg = data + sizeof(TfwNipDef);
	nipdef->len = len;
	memcpy((void *)nipdef->arg, (void *)arg, len + 1);

	loc->nipdef[loc->nipdef_sz++] = nipdef;

	return nipdef;
}

static int
tfw_cfgop_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t len;
	int ret, method, op;
	const char *in_method, *in_op, *arg;
	TfwLocation *loc = tfwcfg_this_location;
	TfwNipDef *nipdef;

	BUILD_BUG_ON(sizeof(tfw_method_enum[0].value) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);
	BUG_ON(!tfwcfg_this_location);

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 3) {
		TFW_ERR_NL("%s: Invalid number of arguments.\n", cs->name);
		return -EINVAL;
	}

	/* The method: one of GET, PUT, POST, etc. in form of a bitmask. */
	in_method = ce->vals[0];
	ret = tfw_cfg_map_enum(tfw_method_enum, in_method, &method);
	if (ret) {
		TFW_ERR_NL("Unsupported HTTP method: '%s %s'\n",
			   cs->name, in_method);
		return -EINVAL;
	}

	/* The match operator. */
	in_op = ce->vals[1];
	ret = tfw_cfg_map_enum(tfw_match_enum, in_op, &op);
	if (ret) {
		TFW_ERR("Unsupported match OP: '%s %s'\n", cs->name, in_op);
		return -EINVAL;
	}

	/* The match string. */
	arg = ce->vals[2];
	len = strlen(arg);

	/*
	 * Issue a warning if there's an entry with the same argument
	 * (URI path) that is not the last entry.
	 */
	if (tfw_nipdef_lookup_dup(loc, method, op, arg, len))
		TFW_WARN_NL("%s: Duplicate entry in location '%s': "
			    "'%s %s %s %s'\n", cs->name,
			    loc == &tfw_location_dflt ? "default" : loc->arg,
			    cs->name, in_method, in_op, arg);

	/*
	 * Do not add a "duplicate" entry within a location. If the
	 * preceding entry has the same @op and @arg, then just add
	 * the new method to the entry.
	 */
	nipdef = tfw_nipdef_lookup(loc, op, arg, len);
	if (nipdef) {
		nipdef->method |= method;
	} else {
		nipdef = tfw_nipdef_addnew(loc, method, op, arg, len);
		if (nipdef == NULL)
			return -ENOMEM;
	}

	return 0;
}

static int
tfw_cfgop_in_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_nonidempotent(cs, ce);
}

static int
tfw_cfgop_out_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (!tfwcfg_this_location)
		tfwcfg_this_location = &tfw_location_dflt;
	return tfw_cfgop_nonidempotent(cs, ce);
}

static int
tfw_cfgop_mod_hdr_add(TfwHdrMods *h_mods, const char *name, const char *value,
		      bool append)
{
	TfwStr *hdr;
	TfwHdrModsDesc *desc = &h_mods->hdrs[h_mods->sz];

	if (h_mods->sz == TFW_USRHDRS_ARRAY_SZ) {
		TFW_WARN_NL("Too lot of custom headers, %d supported.\n",
			    TFW_USRHDRS_ARRAY_SZ);
		return -EINVAL;
	}
	if (!(hdr = tfw_http_msg_make_hdr(tfw_usr_hdrs_pool, name, value))) {
		TFW_WARN_NL("Can't create header.\n");
		return -ENOMEM;
	}
	desc->hdr = hdr;
	desc->append = append;
	desc->hid = tfw_http_msg_is_spec_hdr(hdr);
	++h_mods->sz;

	return 0;
}

/**
 * Parse '[req|resp]_hdr_[add|set] directives. @append is set to true for 'add'.
 * @msg_type is responsible for req or resp.
 * Both directives has two parameters: header name and it's value. Value
 * is optional for 'set' directive.
 */
static int
tfw_cfgop_mod_hdr(TfwCfgSpec *cs, TfwCfgEntry *ce, int msg_type, bool append)
{
	TfwLocation *loc = tfwcfg_this_location;
	const char *name;
	const char *value = NULL;

	BUG_ON(!tfwcfg_this_location);

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	switch (ce->val_n)
	{
	case 2:
		break;
	case 1:
		if (!append)
			break;
		/* Fall through */
	default:
		TFW_ERR_NL("%s: Invalid number of values.\n", cs->name);
		return -EINVAL;
	}

	name = ce->vals[0];
	if (ce->val_n == 2)
		value = ce->vals[1];

	return tfw_cfgop_mod_hdr_add(&loc->mod_hdrs[msg_type], name, value,
				     append);
}

static int
tfw_cfgop_in_req_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce, TFW_HTTP_MSG_REQ, true);
}

static int
tfw_cfgop_in_req_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce, TFW_HTTP_MSG_REQ, false);
}

static int
tfw_cfgop_out_req_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (!tfwcfg_this_location)
		tfwcfg_this_location = &tfw_location_dflt;
	return tfw_cfgop_in_req_hdr_add(cs, ce);
}

static int
tfw_cfgop_out_req_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (!tfwcfg_this_location)
		tfwcfg_this_location = &tfw_location_dflt;
	return tfw_cfgop_in_req_hdr_set(cs, ce);
}

static int
tfw_cfgop_in_resp_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce, TFW_HTTP_MSG_RESP, true);
}

static int
tfw_cfgop_in_resp_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce, TFW_HTTP_MSG_RESP, false);
}

static int
tfw_cfgop_out_resp_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (!tfwcfg_this_location)
		tfwcfg_this_location = &tfw_location_dflt;
	return tfw_cfgop_in_resp_hdr_add(cs, ce);
}

static int
tfw_cfgop_out_resp_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (!tfwcfg_this_location)
		tfwcfg_this_location = &tfw_location_dflt;
	return tfw_cfgop_in_resp_hdr_set(cs, ce);
}

/*
 * Find a cache policy directive entry. The entry is looked up
 * in the array that holds all cache policy directives from all
 * location sections.
 */
static TfwCaPolicy *
tfw_capolicy_lookup(int cmd, int op, const char *arg, size_t len)
{
	size_t i;

	for (i = 0; i < tfw_capolicy_sz; ++i) {
		TfwCaPolicy *capo = &tfw_capolicy[i];
		if ((capo->cmd == cmd) && (capo->op == op) && (capo->len == len)
		    && !strncasecmp(capo->arg, arg, len))
			return capo;
	}

	return NULL;
}

/*
 * Create and initialize a new cache policy entry. The entry is placed
 * in the array for all cache policy entries from all location sections.
 */
static TfwCaPolicy *
tfw_capolicy_new(int cmd, int op, const char *arg, size_t len)
{
	char *argmem;
	TfwCaPolicy *capo;

	if (tfw_capolicy_sz == TFW_CAPOLICY_ARRAY_SZ)
		return NULL;

	if ((argmem = kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return NULL;

	capo = &tfw_capolicy[tfw_capolicy_sz++];
	capo->cmd = cmd;
	capo->op = op;
	capo->arg = argmem;
	capo->len = len;
	memcpy((void *)capo->arg, (void *)arg, len + 1);

	return capo;
}

/*
 * Add a new cache policy entry to the given location structure.
 * The entry is added as a pointer into the array for all cache
 * policy entries.
 */
static TfwCaPolicy *
tfw_capolicy_add(TfwLocation *loc, TfwCaPolicy *capo)
{
	if (loc->capo_sz == TFW_CAPOLICY_ARRAY_SZ)
		return NULL;
	loc->capo[loc->capo_sz++] = capo;
	return capo;
}

/*
 * Process a cache policy directive. The directive is added to the
 * current location structure. Duplicate directives are ignored but
 * a warning is produced in that case. if a directive lists several
 * strings to match, then an identical directive is added for each
 * string that is listed.
 */
static int
tfw_cfgop_capolicy(TfwCfgSpec *cs, TfwCfgEntry *ce, int cmd)
{
	int ret;
	size_t i, len;
	tfw_match_t op;
	const char *in_op, *arg;

	BUG_ON(!tfwcfg_this_location);
	BUG_ON((cmd != TFW_D_CACHE_BYPASS) && (cmd != TFW_D_CACHE_FULFILL));

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n < 2) {
		TFW_ERR_NL("%s: Invalid number of arguments: %d\n",
			   cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	in_op = ce->vals[0];	/* Match operator. */

	/* Convert the match operator string to the enum value. */
	ret = tfw_cfg_map_enum(tfw_match_enum, in_op, &op);
	if (ret) {
		TFW_ERR_NL("Unknown match OP: '%s %s'\n", cs->name, in_op);
		return -EINVAL;
	}

	/* Add each match string in the directive to the array.*/
	for (i = 1; i < ce->val_n; ++i) {
		TfwCaPolicy *capo;

		arg = ce->vals[i];
		len = strlen(arg);

		/* Get the cache policy entry. */
		capo = tfw_capolicy_lookup(cmd, op, arg, len);
		if (capo) {
			TFW_WARN_NL("%s: Duplicate entry: '%s %s %s'\n",
				    cs->name, cs->name, in_op, arg);
			continue;
		}
		capo = tfw_capolicy_new(cmd, op, arg, len);
		if (!capo)
			return -ENOMEM;
		/* Link the cache policy entry with the location entry. */
		if (!tfw_capolicy_add(tfwcfg_this_location, capo))
			return -ENOENT;
	}

	return 0;
}

/*
 * The configuration parser has recognized the cache policy directive
 * already, so there's no need to spend cycles and convert it again
 * from the string to the enum value. The functions below are for
 * each directive inside the location section, and for each directive
 * outside of any location section.
 */
static int
tfw_cfgop_in_cache_fulfill(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_capolicy(cs, ce, TFW_D_CACHE_FULFILL);
}

static int
tfw_cfgop_in_cache_bypass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_capolicy(cs, ce, TFW_D_CACHE_BYPASS);
}

static int
tfw_cfgop_out_cache_fulfill(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (!tfwcfg_this_location)
		tfwcfg_this_location = &tfw_location_dflt;
	return tfw_cfgop_capolicy(cs, ce, TFW_D_CACHE_FULFILL);
}

static int
tfw_cfgop_out_cache_bypass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (!tfwcfg_this_location)
		tfwcfg_this_location = &tfw_location_dflt;
	return tfw_cfgop_capolicy(cs, ce, TFW_D_CACHE_BYPASS);
}

/*
 * Find a location directive entry. The entry is looked up
 * in the array that holds all location directives.
 */
static TfwLocation *
tfw_location_lookup(tfw_match_t op, const char *arg, size_t len)
{
	size_t i;

	for (i = 0; i < tfw_location_sz; ++i) {
		TfwLocation *loc = &tfw_location[i];
		if ((loc->op == op) && (loc->len == len)
		    && !strncasecmp(loc->arg, arg, len))
			return loc;
	}

	return NULL;
}

/*
 * Create and initialize a new entry for a location directive.
 * The entry is placed in the array that holds all location directives.
 */
static TfwLocation *
tfw_location_new(tfw_match_t op, const char *arg, size_t len)
{
	TfwLocation *loc;
	char *argmem, *data;
	size_t size = sizeof(TfwCaPolicy *) * TFW_CAPOLICY_ARRAY_SZ
		    + sizeof(TfwNipDef *) * TFW_NIPDEF_ARRAY_SZ
		    + sizeof(TfwHdrModsDesc) * TFW_USRHDRS_ARRAY_SZ * 2;

	if (tfw_location_sz == TFW_LOCATION_ARRAY_SZ)
		return NULL;

	if ((argmem = kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return NULL;
	if ((data = kmalloc(size, GFP_KERNEL)) == NULL) {
		kfree(argmem);
		return NULL;
	}

	loc = &tfw_location[tfw_location_sz++];
	loc->op = op;
	loc->arg = argmem;
	loc->len = len;
	loc->capo = (TfwCaPolicy **)data;
	loc->capo_sz = 0;
	loc->nipdef = (TfwNipDef **)(loc->capo + TFW_CAPOLICY_ARRAY_SZ);
	loc->nipdef_sz = 0;
	loc->mod_hdrs[TFW_HTTP_MSG_REQ].hdrs =
			(TfwHdrModsDesc *)(loc->nipdef + TFW_NIPDEF_ARRAY_SZ);
	loc->mod_hdrs[TFW_HTTP_MSG_RESP].hdrs =
			loc->mod_hdrs[TFW_HTTP_MSG_REQ].hdrs + TFW_USRHDRS_ARRAY_SZ;
	memcpy((void *)loc->arg, (void *)arg, len + 1);

	return loc;
}

/*
 * Process the location directive that opens a section for cache
 * policy directives in the configuration.
 */
static int
tfw_cfgop_location_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int ret;
	size_t len;
	tfw_match_t op;
	const char *in_op, *arg;

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 2) {
		TFW_ERR_NL("%s: Invalid number of arguments: %d\n",
			   cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	/* Get the values of the 'location' directive. */
	in_op = ce->vals[0];	/* Match operator. */
	arg = ce->vals[1];	/* String for the match operator. */
	len = strlen(arg);

	/* Convert the match operator string to the enum value. */
	ret = tfw_cfg_map_enum(tfw_match_enum, in_op, &op);
	if (ret) {
		TFW_ERR_NL("%s: Unknown match OP: '%s %s %s'\n",
			   cs->name, cs->name, in_op, arg);
		return -EINVAL;
	}

	/* Make sure the location is not a duplicate. */
	if (tfw_location_lookup(op, arg, len)) {
		TFW_ERR_NL("%s: Duplicate entry: '%s %s %s'\n",
			   cs->name, cs->name, in_op, arg);
		return -EINVAL;
	}

	/* Add new location and set it to be the current one. */
	tfwcfg_this_location = tfw_location_new(op, arg, len);
	if (tfwcfg_this_location == NULL) {
		TFW_ERR_NL("%s: Unable to add new location: '%s %s %s'\n",
			   cs->name, cs->name, in_op, arg);
		return -EINVAL;
	}

	return 0;
}

/*
 * Close the section for a location directive.
 */
static int
tfw_cfgop_location_finish(TfwCfgSpec *cs)
{
	BUG_ON(!tfwcfg_this_location);
	tfwcfg_this_location = NULL;
	return 0;
}

/*
 * Free only the memory that has been allocated while processing
 * configuration directives. Make sure the memory is not freed twice.
 */
static void
tfw_cfgop_cleanup_locache(TfwCfgSpec *cs)
{
	size_t i, k;

	for (i = 0; i < tfw_location_sz; ++i) {
		TfwLocation *loc = &tfw_location[i];
		if (loc->arg) {
			kfree(loc->arg);
			loc->arg = NULL;
		}
		for (k = 0; k < loc->nipdef_sz; ++k) {
			if (loc->nipdef[k])
				kfree(loc->nipdef[k]);
		}
		/* Free loc->capo, loc->nipdef and loc->mod_hdrs. */
		if (loc->capo) {
			kfree(loc->capo);
			loc->capo = NULL;
		}
	}
	for (i = 0; i < tfw_capolicy_sz; ++i) {
		TfwCaPolicy *capo = &tfw_capolicy[i];
		if (capo->arg) {
			kfree(capo->arg);
			capo->arg = NULL;
		}
	}
	for (i = 0; i < tfw_location_dflt.nipdef_sz; ++i) {
		if (tfw_location_dflt.nipdef[i])
			kfree(tfw_location_dflt.nipdef[i]);
	}
	tfw_capolicy_sz = 0;
	tfw_location_sz = 0;
	tfw_location_dflt.capo_sz = 0;
	tfw_location_dflt.nipdef_sz = 0;
}

/*
 *  Match the ip address against the ACL list.
 */
static bool
tfw_capuacl_lookup(TfwVhost *vhost, TfwAddr *addr)
{
	size_t i;
	struct in6_addr *inaddr = &addr->v6.sin6_addr;

	for (i = 0; i < vhost->capuacl_sz; ++i) {
		struct in6_addr *acl_inaddr = &vhost->capuacl[i].v6.sin6_addr;
		if (ipv6_prefix_equal(inaddr, acl_inaddr, addr->in6_prefix))
			return true;
	}
	return false;
}

/*
 * Process the cache_purge_acl directive.
 */
static int
tfw_cfgop_cache_purge_acl(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t i;
	const char *val;
	TfwVhost *vhost = &tfw_vhost_dflt;

	if (ce->attr_n) {
		TFW_ERR("%s: Arguments may not have the \'=\' sign\n",
			cs->name);
		return -EINVAL;
	}

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		TfwAddr addr = { 0 };

		if (tfw_addr_pton_cidr(val, &addr)) {
			TFW_ERR_NL("%s: Invalid ACL entry: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
		/* Make sure the address is not a duplicate. */
		if (tfw_capuacl_lookup(vhost, &addr)) {
			TFW_ERR_NL("%s: Duplicate IP address or prefix: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
		/* Add new ACL entry. */
		if (vhost->capuacl_sz == TFW_CAPUACL_ARRAY_SZ) {
			TFW_ERR_NL("%s: Unable to add new ACL: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
		vhost->capuacl[vhost->capuacl_sz++] = addr;
	}
	vhost->cache_purge_acl = 1;

	return 0;
}

/*
 * Process the cache_purge directive.
 */
static int
tfw_cfgop_cache_purge(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t i;
	const char *val;
	TfwVhost *vhost = &tfw_vhost_dflt;

	if (ce->attr_n) {
		TFW_ERR("%s: Arguments may not have the \'=\' sign\n",
			cs->name);
		return -EINVAL;
	}
	if (!ce->val_n) {
		/* Default value for the cache_purge directive. */
		vhost->cache_purge_mode = TFW_D_CACHE_PURGE_INVALIDATE;
		goto done;
	}
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (!strcasecmp(val, "invalidate")) {
			vhost->cache_purge_mode = TFW_D_CACHE_PURGE_INVALIDATE;
		} else {
			TFW_ERR_NL("%s: unsupported argument: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
	}
done:
	vhost->cache_purge = 1;

	return 0;
}

static void
tfw_cfgop_cleanup_cache_purge(TfwCfgSpec *cs)
{
	TfwVhost *vhost = &tfw_vhost_dflt;

	vhost->cache_purge =
	vhost->cache_purge_mode =
	vhost->cache_purge_acl = 0;
}

/*
 * Process hdr_via directive.
 * Default value is preset statically.
 */
static int
tfw_cfgop_hdr_via(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t len;
	TfwVhost *vhost = &tfw_vhost_dflt;

	if (ce->attr_n) {
		TFW_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 1) {
		TFW_ERR_NL("%s: Invalid number of arguments: %d\n",
			   cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	/*
	 * If a value is specified in the configuration file, then
	 * the default value is not used, even if the processing of
	 * the specified value results in an error.
	 */
	len = strlen(ce->vals[0]);
	if ((vhost->hdr_via = kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memcpy((void *)vhost->hdr_via, (void *)ce->vals[0], len + 1);
	vhost->hdr_via_len = len;

	return 0;
}

static void
tfw_cfgop_cleanup_hdrvia(TfwCfgSpec *cs)
{
	TfwVhost *vhost = &tfw_vhost_dflt;

	if (vhost->hdr_via && (vhost->hdr_via != s_hdr_via_dflt))
		kfree(vhost->hdr_via);
	vhost->hdr_via = s_hdr_via_dflt;
}

static int
tfw_vhost_cfgend(void)
{
	BUILD_BUG_ON(sizeof(tfw_nipdef_dflt[0]->method) * 8 - 1
		     < _TFW_HTTP_METH_COUNT);
	BUILD_BUG_ON(sizeof(tfw_capolicy_dflt[0]->op) * 8 - 1
		     < _TFW_HTTP_MATCH_O_COUNT);
	BUILD_BUG_ON(sizeof(tfw_location_dflt.op) * 8 - 1
		     < _TFW_HTTP_MATCH_O_COUNT);

	if (tfw_runstate_is_reconfig())
		return 0;

	if (tfw_vhost_dflt.cache_purge && !tfw_vhost_dflt.cache_purge_acl)
		TFW_WARN("cache_purge directive works only in combination"
			 " with cache_purge_acl directive.\n");
	tfw_vhost_dflt.loc_sz = tfw_location_sz;

	return 0;
}

static void
tfw_vhost_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;
	tfw_vhost_dflt.loc_sz = 0;
}

static TfwCfgSpec tfw_vhost_location_specs[] = {
	{
		.name = "cache_bypass",
		.deflt = NULL,
		.handler = tfw_cfgop_in_cache_bypass,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "cache_fulfill",
		.deflt = NULL,
		.handler = tfw_cfgop_in_cache_fulfill,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "nonidempotent",
		.deflt = NULL,
		.handler = tfw_cfgop_in_nonidempotent,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "req_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_in_req_hdr_add,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "req_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_in_req_hdr_set,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "resp_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_in_resp_hdr_add,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "resp_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_in_resp_hdr_set,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{ 0 }
};

static TfwCfgSpec tfw_vhost_specs[] = {
	{
		.name = "hdr_via",
		.deflt = NULL,
		.handler = tfw_cfgop_hdr_via,
		.cleanup = tfw_cfgop_cleanup_hdrvia,
		.allow_none = true,
		.allow_repeat = false,
	},
	{
		.name = "cache_purge",
		.deflt = NULL,
		.handler = tfw_cfgop_cache_purge,
		.cleanup = tfw_cfgop_cleanup_cache_purge,
		.allow_none = true,
		.allow_repeat = false,
	},
	{
		.name = "cache_purge_acl",
		.deflt = NULL,
		.handler = tfw_cfgop_cache_purge_acl,
		.cleanup = tfw_cfgop_cleanup_cache_purge,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "cache_bypass",
		.deflt = NULL,
		.handler = tfw_cfgop_out_cache_bypass,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "cache_fulfill",
		.deflt = NULL,
		.handler = tfw_cfgop_out_cache_fulfill,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "nonidempotent",
		.deflt = NULL,
		.handler = tfw_cfgop_out_nonidempotent,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "req_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_out_req_hdr_add,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "req_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_out_req_hdr_set,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "resp_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_out_resp_hdr_add,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "resp_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_out_resp_hdr_set,
		.cleanup = tfw_cfgop_cleanup_locache,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "location",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfg_cleanup_children,
		.dest = tfw_vhost_location_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tfw_cfgop_location_begin,
			.finish_hook = tfw_cfgop_location_finish
		},
		.allow_none = true,
		.allow_repeat = true,
	},
	{ 0 },
};

TfwMod tfw_vhost_mod = {
	.name	= "vhost",
	.cfgend	= tfw_vhost_cfgend,
	.stop	= tfw_vhost_stop,
	.specs	= tfw_vhost_specs,
};

int
tfw_vhost_init(void)
{
	tfw_mod_register(&tfw_vhost_mod);
	tfw_usr_hdrs_pool = __tfw_pool_new(0);
	if (!tfw_usr_hdrs_pool)
		return -ENOMEM;

	return 0;
}

void
tfw_vhost_exit(void)
{
	tfw_mod_unregister(&tfw_vhost_mod);

	tfw_pool_destroy(tfw_usr_hdrs_pool);
	tfw_usr_hdrs_pool = NULL;
}
