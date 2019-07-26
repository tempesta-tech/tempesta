/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2019 Tempesta Technologies, Inc.
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
#include "hash.h"
#include "http.h"
#include "http_limits.h"
#include "http_match.h"
#include "http_msg.h"
#include "vhost.h"
#include "str.h"
#include "client.h"
#include "tls_conf.h"

#define TFW_VH_HBITS	10
/**
 * Control object for holding full set of virtual hosts specific for current
 * configuration/reconfiguration stage.
 *
 * @vhost_dflt	- Default virtual host with global policies (always present in
 *		  current configuration).
 * @expl_dflt	- Flag to indicate explicit configuration of default
 *		  virtual host.
 * @vh_hash	- Hash table with configured virtual hosts.
 */
typedef struct {
	TfwVhost	*vhost_dflt;
	bool		expl_dflt;
	DECLARE_HASHTABLE(vh_hash, TFW_VH_HBITS);
} TfwVhostList;

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
 * Each cache policy directive is put into a separately allocated
 * memory are within a location definition.
 * The directives are deduplicated when put into the array.
 */
#define TFW_CAPOLICY_ARRAY_SZ	(64)

/*
 * Each non-idempotent request definition directive is put into
 * a separately allocated memory area. The pointers to the memory
 * are put into a fixed size array of pointers within a location
 * definition.
 */
#define TFW_NIPDEF_ARRAY_SZ	(64)

/* Max number of headers allowed for end user to modify. */
#define TFW_USRHDRS_ARRAY_SZ	(64)

/*
 * All 'location' directives are put into a fixed size array.
 * Duplicate directives are not allowed.
 */
#define TFW_LOCATION_ARRAY_SZ	(64)

/*
 * IP addresses that make the ACL for cache purge operations are put
 * into a fixed size array. The IP addresses are kept in form of an
 * IPv6 address and the prefix size. sockaddr_in6.sin6_scope_id is
 * used to store the prefix size.
 */
#define TFW_CAPUACL_ARRAY_SZ	(32)

static TfwAddr	tfw_capuacl_dflt[TFW_CAPUACL_ARRAY_SZ];

/*
 * Default vhost is a wildcard vhost. It matches any URI.
 * It may (or may not) contain a set of various directives.
 *
 * Note that @loc_dflt in the default vhost serves as global
 * default caching policy.
 */
static const char s_hdr_via_dflt[] =
	"tempesta_fw" " (" TFW_NAME " " TFW_VERSION ")";

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
 *
 * TODO #732 use multi-pattern string matching.
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
 * Find request's location with server group linked. If there is no
 * separate location for request (or there is no server group linked
 * with such location), then get the default location of the request's
 * current vhost (must be present in any case).
 */
static inline TfwLocation *
tfw_vhost_act_location(TfwHttpReq *req)
{
	TfwLocation *loc = req->location;
	TfwVhost *vhost = req->vhost;

	BUG_ON(!vhost);
	if (loc && loc->main_sg)
		return loc;

	return vhost->loc_dflt;
}

/*
 * Search server connection in main or backup server groups in
 * locations of the request's current vhost.
 */
TfwSrvConn *
tfw_vhost_get_srv_conn(TfwMsg *msg)
{
	TfwLocation *loc;
	TfwSrvGroup *main_sg, *backup_sg;
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwSrvConn *srv_conn = NULL;

	loc = tfw_vhost_act_location(req);
	main_sg = loc->main_sg;
	backup_sg = loc->backup_sg;

	if (unlikely(!main_sg))
		return NULL;
	T_DBG2("vhost: use server group: '%s'\n", main_sg->name);

	if (likely(main_sg->sched))
		srv_conn = main_sg->sched->sched_sg_conn(msg, main_sg);

	if (unlikely(!srv_conn && backup_sg && backup_sg->sched)) {
		T_DBG("vhost: the main group is offline, use backup: '%s'\n",
		      backup_sg->name);
		srv_conn = backup_sg->sched->sched_sg_conn(msg, backup_sg);
	}

	if (unlikely(!srv_conn))
		T_DBG2("vhost: Unable to select server from group '%s'\n",
		       backup_sg ? backup_sg->name : main_sg->name);

	return srv_conn;
}

/**
 * Find a headers modification description according to target message type
 * and current location.
 *
 * @loc		- request URI location;
 * @vhost	- virtual host for the request;
 * @mod_type	- Target modification type, TFW_VHOST_HDRMOD_(REQ|RESP).
 */
TfwHdrMods*
tfw_vhost_get_hdr_mods(TfwLocation *loc, TfwVhost *vhost, int mod_type)
{
	TfwVhost *vh_dflt = vhost->vhost_dflt;

	/* TODO #862: req->location must be the full set of options. */
	if (!loc || !loc->mod_hdrs[mod_type].sz)
		loc = vhost->loc_dflt;
	if (!loc || !loc->mod_hdrs[mod_type].sz)
		loc = vh_dflt ? vh_dflt->loc_dflt : NULL;
	if (!loc)
		return NULL;

	return &loc->mod_hdrs[mod_type];
}

/*
 * Configuration processing.
 */

/*
 * Pointer to the current location structure.
 * The pointer is shared among multiple functions below.
 */
static TfwLocation		*tfwcfg_this_location;
/* Entry for configuration of separate vhost. */
static TfwVhost			*tfw_vhost_entry;
/* Pointer to all current vhosts. */
static TfwVhostList __rcu	*tfw_vhosts;
/* Pointer to all vhosts parsed during reconfiguration. */
static TfwVhostList		*tfw_vhosts_reconfig;
/* Object with global level settings (non-reconfigurable). */
static TfwGlobal		tfw_global = {
	.hdr_via	= s_hdr_via_dflt,
	.hdr_via_len	= sizeof(s_hdr_via_dflt) - 1,
	.capuacl	= tfw_capuacl_dflt,
};
/* Temporal structures to parse top level (outside vhost) Frang configuration. */
static FrangVhostCfg	tfw_frang_vhost_reconfig;
static FrangGlobCfg	tfw_frang_glob_reconfig;


/**
 * Match vhost to requested name. Called in process context during configuration
 * processing, both strings are guaranteed to be plain.
 */
static bool
tfw_vhost_name_match(TfwVhost *vh, const TfwStr *name)
{
	if (WARN_ON_ONCE(!TFW_STR_PLAIN(name)))
		return false;
	return vh->name.len == name->len
		&& !strncasecmp(vh->name.data, name->data, vh->name.len);
}

/**
 *  Match vhost to requested name. Can be called in softirq context only.
 */
static bool
tfw_vhost_name_match_fast(TfwVhost *vh, const TfwStr *name)
{
	return !tfw_stricmp(&vh->name, name);
}

static inline TfwVhost *
__tfw_vhost_lookup(TfwVhostList *vh_list, const TfwStr *name,
		   bool (*match_fn)(TfwVhost *, const TfwStr *))
{
	TfwVhost *vhost;
	unsigned long key = tfw_hash_str(name);

	hash_for_each_possible(vh_list->vh_hash, vhost, hlist, key) {
		if (match_fn(vhost, name)) {
			tfw_vhost_get(vhost);
			return vhost;
		}
	}
	return NULL;
}

/**
 * Find vhost named @name in the _currently parsed and not yet applied_
 * configuration. The operation is safe to use in process context.
 * If vhost is found, an additional reference is taken. Caller is responsible to
 * release the reference after use.
 */
TfwVhost *
tfw_vhost_lookup_reconfig(const char *name)
{
	TfwStr ns = TFW_STR_FROM_CSTR(name);
	return __tfw_vhost_lookup(tfw_vhosts_reconfig, &ns,
				  tfw_vhost_name_match);
}

/**
 * Find vhost in the _running_ configuration, matching name @name. The operation
 * involves fast avx2 operations and can be done only in softirq context.
 * If vhost is found, an additional reference is taken. Caller is responsible to
 * release the reference after use.
 */
TfwVhost *
tfw_vhost_lookup(const TfwStr *name)
{
	TfwVhost *vhost;
	TfwVhostList *vhlist;

	if (unlikely(TFW_STR_EMPTY(name)))
		return NULL;

	rcu_read_lock_bh();
	vhlist = rcu_dereference_bh(tfw_vhosts);
	BUG_ON(!vhlist);
	vhost = __tfw_vhost_lookup(vhlist, name,
				   tfw_vhost_name_match_fast);
	rcu_read_unlock_bh();

	return vhost;
}

/**
 * Get default vhost in the running configuration. Default vhost is special
 * entity that contains default policies if more precise vhost cannot be found.
 */
TfwVhost *
tfw_vhost_lookup_default(void)
{
	TfwVhost *vhost;
	TfwVhostList *vhlist;

	rcu_read_lock_bh();
	vhlist = rcu_dereference_bh(tfw_vhosts);
	BUG_ON(!vhlist);
	vhost = vhlist->vhost_dflt;
	tfw_vhost_get(vhost);
	rcu_read_unlock_bh();

	return vhost;
}

TfwGlobal *
tfw_vhost_get_global(void)
{
	return &tfw_global;
}

bool
tfw_vhost_is_default_reconfig(TfwVhost *vhost)
{
	return tfw_vhosts_reconfig->vhost_dflt == vhost;
}

/*
 * Match the IP address @addr against the addresses in the ACL list.
 * The addresses are compared according to the prefix length stored
 * with each address in the ACL list.
 * True is returned if the match is found.
 * False is returned otherwise.
 */
bool
tfw_capuacl_match(TfwAddr *addr)
{
	size_t i;
	struct in6_addr *inaddr = &addr->sin6_addr;

	for (i = 0; i < tfw_global.capuacl_sz; ++i) {
		TfwAddr *acl_addr = &tfw_global.capuacl[i];
		if (ipv6_prefix_equal(inaddr, &acl_addr->sin6_addr,
					      acl_addr->in6_prefix))
			return true;
	}
	return false;
}

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
tfw_cfgop_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc)
{
	size_t len;
	int ret, method, op;
	const char *in_method, *in_op, *arg;
	TfwNipDef *nipdef;
	TfwVhost *vh_dflt;

	BUILD_BUG_ON(sizeof(tfw_method_enum[0].value) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);

	if (ce->attr_n) {
		T_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			 cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 3) {
		T_ERR_NL("%s: Invalid number of arguments.\n", cs->name);
		return -EINVAL;
	}

	/* The method: one of GET, PUT, POST, etc. in form of a bitmask. */
	in_method = ce->vals[0];
	ret = tfw_cfg_map_enum(tfw_method_enum, in_method, &method);
	if (ret) {
		T_ERR_NL("Unsupported HTTP method: '%s %s'\n",
			 cs->name, in_method);
		return -EINVAL;
	}

	/* The match operator. */
	in_op = ce->vals[1];
	ret = tfw_cfg_map_enum(tfw_match_enum, in_op, &op);
	if (ret) {
		T_ERR_NL("Unsupported match OP: '%s %s'\n", cs->name, in_op);
		return -EINVAL;
	}

	/* The match string. */
	arg = ce->vals[2];
	len = strlen(arg);

	/*
	 * Issue a warning if there's an entry with the same argument
	 * (URI path) that is not the last entry.
	 */
	vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	if (tfw_nipdef_lookup_dup(loc, method, op, arg, len))
		T_WARN_NL("%s: Duplicate entry in location '%s': "
			  "'%s %s %s %s'\n", cs->name,
			  loc == vh_dflt->loc_dflt ? "default" : loc->arg,
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
tfw_cfgop_loc_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_nonidempotent(cs, ce, tfwcfg_this_location);
}

static int
tfw_cfgop_in_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_nonidempotent(cs, ce, tfw_vhost_entry->loc_dflt);
}

static int
tfw_cfgop_out_nonidempotent(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	return tfw_cfgop_nonidempotent(cs, ce, vh_dflt->loc_dflt);
}

static int
tfw_cfgop_mod_hdr_add(TfwLocation *loc, const char *name, const char *value,
		      int mod_type, bool append)
{
	TfwStr *hdr;
	TfwHdrMods *h_mods = &loc->mod_hdrs[mod_type];
	TfwHdrModsDesc *desc = &h_mods->hdrs[h_mods->sz];

	if (h_mods->sz == TFW_USRHDRS_ARRAY_SZ) {
		T_WARN_NL("Too lot of custom headers, %d supported.\n",
			  TFW_USRHDRS_ARRAY_SZ);
		return -EINVAL;
	}
	if (!(hdr = tfw_http_msg_make_hdr(loc->hdrs_pool, name, value))) {
		T_WARN_NL("Can't create header.\n");
		return -ENOMEM;
	}
	desc->hdr = hdr;
	desc->append = append;
	desc->hid = (mod_type == TFW_VHOST_HDRMOD_RESP)
			? tfw_http_msg_resp_spec_hid(hdr)
			: tfw_http_msg_req_spec_hid(hdr);
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
tfw_cfgop_mod_hdr(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc,
		  int mod_type, bool append)
{
	const char *name;
	const char *value = NULL;

	if (ce->attr_n) {
		T_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
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
		T_ERR_NL("%s: Invalid number of values.\n", cs->name);
		return -EINVAL;
	}

	name = ce->vals[0];
	if (ce->val_n == 2)
		value = ce->vals[1];

	return tfw_cfgop_mod_hdr_add(loc, name, value, mod_type, append);
}

static int
tfw_cfgop_loc_req_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_mod_hdr(cs, ce, tfwcfg_this_location,
				 TFW_VHOST_HDRMOD_REQ, true);
}

static int
tfw_cfgop_loc_req_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_mod_hdr(cs, ce, tfwcfg_this_location,
				 TFW_VHOST_HDRMOD_REQ, false);
}

static int
tfw_cfgop_in_req_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_mod_hdr(cs, ce, tfw_vhost_entry->loc_dflt,
				 TFW_VHOST_HDRMOD_REQ, true);
}

static int
tfw_cfgop_in_req_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_mod_hdr(cs, ce, tfw_vhost_entry->loc_dflt,
				 TFW_VHOST_HDRMOD_REQ, false);
}

static int
tfw_cfgop_out_req_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce,
				 tfw_vhosts_reconfig->vhost_dflt->loc_dflt,
				 TFW_VHOST_HDRMOD_REQ, true);
}

static int
tfw_cfgop_out_req_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce,
				 tfw_vhosts_reconfig->vhost_dflt->loc_dflt,
				 TFW_VHOST_HDRMOD_REQ, false);
}

static int
tfw_cfgop_loc_resp_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_mod_hdr(cs, ce, tfwcfg_this_location,
				 TFW_VHOST_HDRMOD_RESP, true);
}

static int
tfw_cfgop_loc_resp_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_mod_hdr(cs, ce, tfwcfg_this_location,
				 TFW_VHOST_HDRMOD_RESP, false);
}

static int
tfw_cfgop_in_resp_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_mod_hdr(cs, ce, tfw_vhost_entry->loc_dflt,
				 TFW_VHOST_HDRMOD_RESP, true);
}

static int
tfw_cfgop_in_resp_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_mod_hdr(cs, ce, tfw_vhost_entry->loc_dflt,
				 TFW_VHOST_HDRMOD_RESP, false);
}

static int
tfw_cfgop_out_resp_hdr_add(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce,
				 tfw_vhosts_reconfig->vhost_dflt->loc_dflt,
				 TFW_VHOST_HDRMOD_RESP, true);
}

static int
tfw_cfgop_out_resp_hdr_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_mod_hdr(cs, ce,
				 tfw_vhosts_reconfig->vhost_dflt->loc_dflt,
				 TFW_VHOST_HDRMOD_RESP, false);
}

/*
 * Find a cache policy directive entry.
 */
static TfwCaPolicy *
tfw_capolicy_lookup(TfwLocation *loc, int cmd, int op, const char *arg,
		    size_t len)
{
	size_t i, capo_sz = loc->capo_sz;

	for (i = 0; i < capo_sz; ++i) {
		TfwCaPolicy *capo = loc->capo[i];
		if ((capo->cmd == cmd) && (capo->op == op) && (capo->len == len)
		    && !strncasecmp(capo->arg, arg, len))
			return capo;
	}

	return NULL;
}

/*
 * Create and initialize a new cache policy entry.
 */
static TfwCaPolicy *
tfw_capolicy_new(int cmd, int op, const char *arg, size_t len)
{
	TfwCaPolicy *capo;

	if ((capo = kmalloc(sizeof(TfwCaPolicy) + len + 1, GFP_KERNEL)) == NULL)
		return NULL;

	capo->cmd = cmd;
	capo->op = op;
	capo->arg = (char *)(capo + 1);
	capo->len = len;
	memcpy((void *)capo->arg, (void *)arg, len + 1);

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
tfw_cfgop_capolicy(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc, int cmd)
{
	int ret;
	size_t i, len;
	tfw_match_t op;
	const char *in_op, *arg;

	BUG_ON((cmd != TFW_D_CACHE_BYPASS) && (cmd != TFW_D_CACHE_FULFILL));

	if (ce->attr_n) {
		T_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			 cs->name);
		return -EINVAL;
	}
	if (ce->val_n < 2) {
		T_ERR_NL("%s: Invalid number of arguments: %d\n",
			 cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	in_op = ce->vals[0];	/* Match operator. */

	/* Convert the match operator string to the enum value. */
	ret = tfw_cfg_map_enum(tfw_match_enum, in_op, &op);
	if (ret) {
		T_ERR_NL("Unknown match OP: '%s %s'\n", cs->name, in_op);
		return -EINVAL;
	}

	/* Add each match string in the directive to the array.*/
	for (i = 1; i < ce->val_n; ++i) {
		TfwCaPolicy *capo;

		arg = ce->vals[i];
		len = strlen(arg);

		if (tfw_capolicy_lookup(loc, cmd, op, arg, len)) {
			T_WARN_NL("%s: Duplicate entry: '%s %s %s'\n",
				  cs->name, cs->name, in_op, arg);
			continue;
		}
		if (loc->capo_sz == TFW_CAPOLICY_ARRAY_SZ)
			return -ENOMEM;
		if (!(capo = tfw_capolicy_new(cmd, op, arg, len)))
			return -ENOMEM;
		loc->capo[loc->capo_sz++] = capo;
	}

	return 0;
}

/*
 * The configuration parser has recognized the cache policy directive
 * already, so there's no need to spend cycles and convert it again
 * from the string to the enum value. The functions below are for
 * each directive inside the location section, for each directive
 * inside the vhost section (default location for current vhost),
 * and for each directive outside of any vhost section (global
 * default location).
 */
static int
tfw_cfgop_loc_cache_fulfill(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_capolicy(cs, ce, tfwcfg_this_location,
				  TFW_D_CACHE_FULFILL);
}

static int
tfw_cfgop_loc_cache_bypass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_capolicy(cs, ce, tfwcfg_this_location,
				  TFW_D_CACHE_BYPASS);
}

static int
tfw_cfgop_in_cache_fulfill(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_capolicy(cs, ce, tfw_vhost_entry->loc_dflt,
				  TFW_D_CACHE_FULFILL);
}

static int
tfw_cfgop_in_cache_bypass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_capolicy(cs, ce, tfw_vhost_entry->loc_dflt,
				  TFW_D_CACHE_BYPASS);
}

static int
tfw_cfgop_in_http_post_validate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_vhost_entry->loc_dflt->validate_post_req = 1;
	return 0;
}

static int
tfw_cfgop_out_cache_fulfill(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	return tfw_cfgop_capolicy(cs, ce, vh_dflt->loc_dflt,
				  TFW_D_CACHE_FULFILL);
}

static int
tfw_cfgop_out_cache_bypass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	return tfw_cfgop_capolicy(cs, ce, vh_dflt->loc_dflt,
				  TFW_D_CACHE_BYPASS);
}

static int
tfw_cfgop_out_http_post_validate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_vhosts_reconfig->vhost_dflt->loc_dflt->validate_post_req = 1;
	return 0;
}

/*
 * Find a location directive entry. The entry is looked up
 * in the array that holds all location directives.
 */
static TfwLocation *
tfw_location_lookup(TfwVhost *vhost, tfw_match_t op, const char *arg, size_t len)
{
	size_t i;

	for (i = 0; i < vhost->loc_sz; ++i) {
		TfwLocation *loc = &vhost->loc[i];
		if ((loc->op == op) && (loc->len == len)
		    && !strncasecmp(loc->arg, arg, len))
			return loc;
	}

	return NULL;
}

static int
tfw_frang_cfg_inherit(FrangVhostCfg *curr, FrangVhostCfg *from)
{
	int r = 0;

	memcpy(curr, from, sizeof(FrangVhostCfg));

	if (from->http_ct_vals) {
		size_t sz = from->http_ct_vals_sz;
		curr->http_ct_vals = kmalloc(sz, GFP_KERNEL);
		if (!curr->http_ct_vals)
			r = -ENOMEM;
		else
			memcpy(curr->http_ct_vals, from->http_ct_vals, sz);
	}
	if (!r && from->http_resp_code_block) {
		size_t sz = sizeof(FrangHttpRespCodeBlock);
		curr->http_resp_code_block = kmalloc(sz, GFP_KERNEL);
		if (!curr->http_resp_code_block) {
			r = -ENOMEM;
		}
		else {
			memcpy(curr->http_resp_code_block,
			       from->http_resp_code_block, sz);
		}
	}
	if (unlikely(r))
		T_WARN_NL("Failed to inherit Frang limits: %d.\n", r);

	return r;
}

static int
tfw_location_init(TfwLocation *loc, tfw_match_t op, const char *arg,
		  size_t len, TfwPool *pool)
{
	char *argmem, *data;
	size_t size = sizeof(FrangVhostCfg)
		    + sizeof(TfwCaPolicy *) * TFW_CAPOLICY_ARRAY_SZ
		    + sizeof(TfwNipDef *) * TFW_NIPDEF_ARRAY_SZ
		    + sizeof(TfwHdrModsDesc) * TFW_USRHDRS_ARRAY_SZ * 2;

	if ((argmem = kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	if ((data = kzalloc(size, GFP_KERNEL)) == NULL) {
		kfree(argmem);
		return -ENOMEM;
	}

	loc->op = op;
	loc->arg = argmem;
	loc->len = len;
	loc->frang_cfg = (FrangVhostCfg *)data;
	loc->capo = (TfwCaPolicy **)(loc->frang_cfg + 1);
	loc->capo_sz = 0;
	loc->nipdef = (TfwNipDef **)(loc->capo + TFW_CAPOLICY_ARRAY_SZ);
	loc->nipdef_sz = 0;
	loc->hdrs_pool = pool;
	loc->mod_hdrs[TFW_VHOST_HDRMOD_REQ].hdrs =
			(TfwHdrModsDesc *)(loc->nipdef + TFW_NIPDEF_ARRAY_SZ);
	loc->mod_hdrs[TFW_VHOST_HDRMOD_RESP].hdrs =
			loc->mod_hdrs[TFW_VHOST_HDRMOD_REQ].hdrs + TFW_USRHDRS_ARRAY_SZ;
	memcpy((void *)loc->arg, (void *)arg, len + 1);

	return 0;
}

/*
 * Create and initialize a new entry for a location directive.
 * The entry is placed in the array that holds all location directives
 * for current vhost.
 */
static inline TfwLocation *
tfw_location_new(TfwVhost *vhost, tfw_match_t op, const char *arg, size_t len)
{
	TfwLocation *loc;

	loc = &vhost->loc[vhost->loc_sz];
	if (tfw_location_init(loc, op, arg, len, vhost->hdrs_pool))
		return NULL;
	vhost->loc_sz++;

	if (tfw_frang_cfg_inherit(loc->frang_cfg, vhost->loc_dflt->frang_cfg))
		return NULL;

	return loc;
}

/*
 * Process the location directive that opens a section for cache
 * policy directives in the configuration.
 */
static int
tfw_cfgop_location_begin(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwVhost *vhost)
{
	int ret;
	size_t len;
	tfw_match_t op;
	const char *in_op, *arg;

	if (ce->attr_n) {
		T_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			   cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 2) {
		T_ERR_NL("%s: Invalid number of arguments: %d\n",
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
		T_ERR_NL("%s: Unknown match OP: '%s %s %s'\n",
			   cs->name, cs->name, in_op, arg);
		return -EINVAL;
	}

	/* Make sure the location is not a duplicate. */
	if (tfw_location_lookup(vhost, op, arg, len)) {
		T_ERR_NL("%s: Duplicate entry: '%s %s %s'\n",
			   cs->name, cs->name, in_op, arg);
		return -EINVAL;
	}


	if (vhost->loc_sz == TFW_LOCATION_ARRAY_SZ) {
		T_ERR_NL("%s: There is no empty slots in '%s' vhost to"
			   " add new location: '%s %s %s'\n", cs->name,
			   vhost->name.data, cs->name, in_op, arg);
		return -EINVAL;
	}

	/* Add new location and set it to be the current one. */
	tfwcfg_this_location = tfw_location_new(vhost, op, arg, len);
	if (!tfwcfg_this_location) {
		T_ERR_NL("%s: Unable to create new location: '%s %s %s'\n",
			   cs->name, cs->name, in_op, arg);
		return -ENOMEM;
	}

	return 0;
}

static int
tfw_cfgop_in_location_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	BUG_ON(tfwcfg_this_location);
	return tfw_cfgop_location_begin(cs, ce, tfw_vhost_entry);
}

static int
tfw_cfgop_out_location_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(tfw_vhost_entry);
	BUG_ON(tfwcfg_this_location);
	return tfw_cfgop_location_begin(cs, ce,
					tfw_vhosts_reconfig->vhost_dflt);
}

/*
 * Close the section for a location directive inside of current vhost.
 */
static int
tfw_cfgop_in_location_finish(TfwCfgSpec *cs)
{
	BUG_ON(!tfw_vhost_entry);
	BUG_ON(!tfwcfg_this_location);
	if (!tfw_vhost_is_default_reconfig(tfw_vhost_entry)
	    && !tfwcfg_this_location->main_sg)
	{
		T_ERR_NL("Directive 'proxy_pass' is not specified for"
			   " location (with arg '%s') inside not default"
			   " vhost '%s'.\n", tfwcfg_this_location->arg,
			   tfw_vhost_entry->name.data);
		return -EINVAL;
	}
	tfwcfg_this_location = NULL;
	return 0;
}

/*
 * Close the section for a global location directive.
 */
static int
tfw_cfgop_out_location_finish(TfwCfgSpec *cs)
{
	BUG_ON(tfw_vhost_entry);
	BUG_ON(!tfwcfg_this_location);
	tfwcfg_this_location = NULL;
	return 0;
}

static void
__tfw_frang_clean(FrangVhostCfg *cfg)
{
	kfree(cfg->http_ct_vals);
	kfree(cfg->http_resp_code_block);
}

static void
tfw_frang_clean(FrangVhostCfg *cfg)
{
	__tfw_frang_clean(cfg);
	memset(cfg, 0, sizeof(FrangVhostCfg));
}

static void
tfw_frang_global_clean(FrangGlobCfg *cfg)
{
	memset(cfg, 0, sizeof(FrangGlobCfg));
}

/*
 * Free 'location' memory which has been allocated while processing
 * configuration directives.
 */
static void
tfw_location_del(TfwLocation *loc)
{
	size_t i;

	if (unlikely(!loc))
		return;

	for (i = 0; i < loc->capo_sz; ++i) {
		BUG_ON(!loc->capo[i]);
		kfree(loc->capo[i]);
	}
	for (i = 0; i < loc->nipdef_sz; ++i) {
		BUG_ON(!loc->nipdef[i]);
		kfree(loc->nipdef[i]);
	}

	__tfw_frang_clean(loc->frang_cfg);
	/*
	 * Free loc->arg and loc->frang_cfg, loc->capo,
	 * loc->nipdef and loc->mod_hdrs.
	 */
	kfree(loc->arg);
	kfree(loc->frang_cfg);

	tfw_sg_put(loc->main_sg);
	tfw_sg_put(loc->backup_sg);
}

/*
 *  Match the ip address against the ACL list.
 */
static bool
tfw_capuacl_lookup(TfwAddr *addr)
{
	size_t i;
	struct in6_addr *inaddr = &addr->sin6_addr;

	for (i = 0; i < tfw_global.capuacl_sz; ++i) {
		struct in6_addr *acl_inaddr = &tfw_global.capuacl[i].sin6_addr;
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

	if (ce->attr_n) {
		T_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			cs->name);
		return -EINVAL;
	}

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		TfwAddr addr = { 0 };

		if (tfw_addr_pton_cidr(val, &addr)) {
			T_ERR_NL("%s: Invalid ACL entry: '%s'\n",
				 cs->name, val);
			return -EINVAL;
		}
		/* Make sure the address is not a duplicate. */
		if (tfw_capuacl_lookup(&addr)) {
			T_ERR_NL("%s: Duplicate IP address or prefix: '%s'\n",
				 cs->name, val);
			return -EINVAL;
		}
		/* Add new ACL entry. */
		if (tfw_global.capuacl_sz == TFW_CAPUACL_ARRAY_SZ) {
			T_ERR_NL("%s: Unable to add new ACL: '%s'\n",
				 cs->name, val);
			return -EINVAL;
		}
		tfw_global.capuacl[tfw_global.capuacl_sz++] = addr;
	}
	tfw_global.cache_purge_acl = 1;

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

	if (ce->attr_n) {
		T_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			 cs->name);
		return -EINVAL;
	}
	if (!ce->val_n) {
		/* Default value for the cache_purge directive. */
		tfw_global.cache_purge_mode = TFW_D_CACHE_PURGE_INVALIDATE;
		goto done;
	}
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (!strcasecmp(val, "invalidate")) {
			tfw_global.cache_purge_mode = TFW_D_CACHE_PURGE_INVALIDATE;
		} else {
			T_ERR_NL("%s: unsupported argument: '%s'\n",
				 cs->name, val);
			return -EINVAL;
		}
	}
done:
	tfw_global.cache_purge = 1;

	return 0;
}

/*
 * Process hdr_via directive.
 * Default value is preset statically.
 */
static int
tfw_cfgop_hdr_via(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t len;

	if (ce->attr_n) {
		T_ERR_NL("%s: Arguments may not have the \'=\' sign\n",
			 cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 1) {
		T_ERR_NL("%s: Invalid number of arguments: %d\n",
			 cs->name, (int)ce->val_n);
		return -EINVAL;
	}

	/*
	 * If a value is specified in the configuration file, then
	 * the default value is not used, even if the processing of
	 * the specified value results in an error.
	 */
	len = strlen(ce->vals[0]);
	if ((tfw_global.hdr_via = kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memcpy((void *)tfw_global.hdr_via, (void *)ce->vals[0], len + 1);
	tfw_global.hdr_via_len = len;

	return 0;
}

static int
tfw_cfgop_vhost_check_flags(TfwSrvGroup *main_sg, TfwSrvGroup *backup_sg)
{
	int r = ((main_sg->flags & TFW_SRV_STICKY_FLAGS) ^
		 (backup_sg->flags & TFW_SRV_STICKY_FLAGS));
	if (r)
		T_ERR_NL("vhost: srv_groups '%s' and '%s' must "
			 "have the same sticky sessions settings\n",
			 main_sg->name, backup_sg->name);

	return r;
}

static int
__tfw_cfgop_proxy_pass(const char *main_sg_nm, const char *backup_sg_nm,
		       TfwLocation *loc)
{
	int r;
	TfwSrvGroup *main_sg, *backup_sg = NULL;

	main_sg = tfw_sg_lookup_reconfig(main_sg_nm, strlen(main_sg_nm));
	if (!main_sg) {
		T_ERR_NL("proxy_pass: srv_group is not found: '%s'\n",
			 main_sg_nm);
		return -EINVAL;
	}
	if (backup_sg_nm) {
		backup_sg = tfw_sg_lookup_reconfig(backup_sg_nm,
						   strlen(backup_sg_nm));
		if (!backup_sg) {
			T_ERR_NL("proxy_pass: backup srv_group is not found:"
				 " '%s'\n", backup_sg_nm);
			r = -EINVAL;
			goto err;
		}

		/* Check main/backup group flags for incompatibilities. */
		if (strcasecmp(main_sg_nm, "default")
		    && strcasecmp(backup_sg_nm, "default")
		    && tfw_cfgop_vhost_check_flags(main_sg, backup_sg))
		{
			r = -EINVAL;
			goto err;
		}
	}

	loc->main_sg = main_sg;
	loc->backup_sg = backup_sg;

	return 0;
err:
	tfw_sg_put(main_sg);
	tfw_sg_put(backup_sg);

	return r;
}

static inline int
tfw_cfgop_proxy_pass(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc)
{
	int r;
	const char *in_main_sg, *in_backup_sg;

	if ((r = tfw_cfg_check_val_n(ce, 1)))
		return r;

	in_main_sg = ce->vals[0];
	in_backup_sg = tfw_cfg_get_attr(ce, "backup", NULL);

	if (!tfw_vhost_entry || tfw_vhost_is_default_reconfig(tfw_vhost_entry))
	{
		if (!strcasecmp(in_main_sg, TFW_VH_DFT_NAME)
		    && (!in_backup_sg
			|| !strcasecmp(in_backup_sg, TFW_VH_DFT_NAME)))
			return 0;
		T_ERR_NL("Default vhost must point to default server"
			 " group only, so it is not allowed to specify"
			 " any not default 'proxy_pass' directive inside of"
			 " default vhost.\n");
		return -EINVAL;
	}
	return __tfw_cfgop_proxy_pass(in_main_sg, in_backup_sg, loc);
}

static int
tfw_cfgop_loc_proxy_pass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_proxy_pass(cs, ce, tfwcfg_this_location);
}

static int
tfw_cfgop_in_proxy_pass(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_proxy_pass(cs, ce, tfw_vhost_entry->loc_dflt);
}

void
tfw_vhost_destroy(TfwVhost *vhost)
{
	int i;

	for (i = 0; i < vhost->loc_sz; ++i)
		tfw_location_del(&vhost->loc[i]);
	tfw_location_del(vhost->loc_dflt);
	tfw_vhost_put(vhost->vhost_dflt);
	tfw_pool_destroy(vhost->hdrs_pool);
	tfw_tls_cert_clean(vhost);
	kfree(vhost);
}

static TfwVhost *
tfw_vhost_create(const char *name)
{
	TfwPool *pool;
	TfwVhost *vhost;
	int name_sz = strlen(name) + 1;
	int size = sizeof(TfwVhost)
		+ name_sz
		+ sizeof(TfwLocation) * (TFW_LOCATION_ARRAY_SZ + 1)
		+ tfw_tls_vhost_priv_data_sz();

	if (!(pool = __tfw_pool_new(0)))
		return NULL;

	if (!(vhost = kzalloc(size, GFP_KERNEL))) {
		tfw_pool_destroy(pool);
		T_ERR_NL("Cannot allocate vhost entry '%s'\n", name);
		return NULL;
	}
	INIT_HLIST_NODE(&vhost->hlist);
	vhost->name.data = (char *)(vhost + 1);
	vhost->name.len = name_sz - 1;
	vhost->loc_dflt = (TfwLocation *)(vhost->name.data + name_sz);
	vhost->loc = (TfwLocation *)(vhost->loc_dflt + 1);
	vhost->frang_gconf = (FrangGlobCfg *)(vhost->loc + TFW_LOCATION_ARRAY_SZ);
	vhost->tls_cfg.priv = (vhost->frang_gconf + 1);
	memcpy(vhost->name.data, name, name_sz);
	vhost->hdrs_pool = pool;
	atomic64_set(&vhost->refcnt, 1);

	return vhost;
}

TfwVhost *
tfw_vhost_new(const char *name)
{
	TfwVhost *vhost;

	if (!(vhost = tfw_vhost_create(name)))
		return NULL;

	/* Init default location for the new vhost. */
	if (tfw_location_init(vhost->loc_dflt,
			      TFW_HTTP_MATCH_O_WILDCARD, "*", 1,
			      vhost->hdrs_pool))
	{
		T_ERR_NL("Unable to add default location for vhost '%s'.\n",
			 name);
		tfw_vhost_destroy(vhost);
		return NULL;
	}
	if (strcasecmp(name, TFW_VH_DFT_NAME)) {
		TfwVhost *dvh = tfw_vhosts_reconfig->vhost_dflt;
		if (tfw_frang_cfg_inherit(vhost->loc_dflt->frang_cfg,
					  dvh->loc_dflt->frang_cfg))
		{
			tfw_vhost_destroy(vhost);
			return NULL;
		}
	}

	return vhost;
}

static inline void
tfw_vhost_add(TfwVhost *vhost)
{
	unsigned long key = tfw_hash_str(&vhost->name);

	hash_add(tfw_vhosts_reconfig->vh_hash, &vhost->hlist, key);
	tfw_vhost_get(vhost);
	if (!tfw_vhost_is_default_reconfig(vhost)) {
		vhost->vhost_dflt = tfw_vhosts_reconfig->vhost_dflt;
		tfw_vhost_get(vhost->vhost_dflt);
	}
}

static const TfwCfgEnum frang_http_methods_enum[] = {
	{ "copy",	TFW_HTTP_METH_COPY },
	{ "delete",	TFW_HTTP_METH_DELETE },
	{ "get",	TFW_HTTP_METH_GET },
	{ "head",	TFW_HTTP_METH_HEAD },
	{ "lock",	TFW_HTTP_METH_LOCK },
	{ "mkcol",	TFW_HTTP_METH_MKCOL },
	{ "move",	TFW_HTTP_METH_MOVE },
	{ "options",	TFW_HTTP_METH_OPTIONS },
	{ "patch",	TFW_HTTP_METH_PATCH },
	{ "post",	TFW_HTTP_METH_POST },
	{ "propfind",	TFW_HTTP_METH_PROPFIND },
	{ "proppatch",	TFW_HTTP_METH_PROPPATCH },
	{ "put",	TFW_HTTP_METH_PUT },
	{ "trace",	TFW_HTTP_METH_TRACE },
	{ "unlock",	TFW_HTTP_METH_UNLOCK },
	{ "unknown",	_TFW_HTTP_METH_UNKNOWN }, /* Pass unknown methods. */
	{}
};

static int
__tfw_cfgop_frang_http_methods(TfwCfgSpec *cs, TfwCfgEntry *ce,
			     unsigned long *cfg_methods_mask)
{
	int i, method_id;
	const char *method_str;
	unsigned long methods_mask = 0;

	BUILD_BUG_ON(sizeof(*cfg_methods_mask) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, method_str) {
		int r = tfw_cfg_map_enum(frang_http_methods_enum, method_str,
					 &method_id);
		if (r) {
			T_ERR_NL("frang: invalid method: '%s'\n", method_str);
			return -EINVAL;
		}

		T_DBG3("frang: parsed method: %s => %d\n",
		       method_str, method_id);
		methods_mask |= (1UL << method_id);
	}

	T_DBG3("parsed methods_mask: %#lx\n", methods_mask);
	*cfg_methods_mask = methods_mask;
	return 0;
}

static int
__tfw_cfgop_frang_http_ct_vals(TfwCfgSpec *cs, TfwCfgEntry *ce,
			       FrangVhostCfg *conf)
{
	void *mem;
	const char *in_str;
	char *strs, *strs_pos;
	FrangCtVal *vals, *vals_pos;
	size_t i, strs_size, vals_n, vals_size;

	/* Allocate a single chunk of memory which is suitable to hold the
	 * variable-sized list of variable-sized strings.
	 *
	 * Basically that will look like:
	 *  [[FrangCtVal, FrangCtVal, FrangCtVal, NULL]str1\0\str2\0\str3\0]
	 *           +         +         +             ^      ^      ^
	 *           |         |         |             |      |      |
	 *           +---------------------------------+      |      |
	 *                     |         |                    |      |
	 *                     +------------------------------+      |
	 *                               |                           |
	 *                               +---------------------------+
	 */
	vals_n = ce->val_n;
	vals_size = sizeof(FrangCtVal) * (vals_n + 1);
	strs_size = 0;
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, in_str) {
		strs_size += strlen(in_str) + 1;
	}
	mem = kzalloc(vals_size + strs_size, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;
	vals = mem;
	strs = mem + vals_size;

	/* Copy tokens to the new vals/strs list. */
	/* TODO: validate tokens, they should look like: "text/plain". */
	vals_pos = vals;
	strs_pos = strs;
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, in_str) {
		size_t len = strlen(in_str) + 1;

		memcpy(strs_pos, in_str, len);
		vals_pos->str = strs_pos;
		vals_pos->len = (len - 1);

		T_DBG3("parsed Content-Type value: '%s'\n", in_str);

		vals_pos++;
		strs_pos += len;
	}
	BUG_ON(vals_pos != (vals + vals_n));
	BUG_ON(strs_pos != (strs + strs_size));

	conf->http_ct_vals = vals;
	conf->http_ct_vals_sz = vals_size + strs_size;
	return 0;
}

static int
frang_parse_ushort(const char *s, unsigned short *out)
{
	int n;
	if (tfw_cfg_parse_int(s, &n)) {
		T_ERR_NL("frang: http_resp_code_block: "
			 "\"%s\" isn't a valid value\n", s);
		return -EINVAL;
	}
	if (tfw_cfg_check_range(n, 1, USHRT_MAX))
		return -EINVAL;
	*out = n;
	return 0;
}

/**
 * Save response code block configuration
 */
static int
__tfw_cfgop_frang_rsp_code_block(TfwCfgSpec *cs, TfwCfgEntry *ce,
				 FrangVhostCfg *conf)
{
	FrangHttpRespCodeBlock *cb;
	static const char *error_msg_begin = "frang: http_resp_code_block:";
	int n, i;

	if (ce->attr_n) {
		T_ERR_NL("%s arguments may not have the \'=\' sign\n",
			 error_msg_begin);
		return -EINVAL;
	}

	if (ce->val_n < 3) {
		T_ERR_NL("%s too few arguments\n", error_msg_begin);
		return -EINVAL;
	}

	cb = kzalloc(sizeof(FrangHttpRespCodeBlock), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;
	conf->http_resp_code_block = cb;

	i = ce->val_n - 2;
	while (--i >= 0) {
		if (tfw_cfg_parse_int(ce->vals[i], &n)
		    || !tfw_http_resp_code_range(n)) {
			T_ERR_NL("%s invalid HTTP code \"%s\"",
				 error_msg_begin, ce->vals[i]);
			return -EINVAL;
		}
		/* Atomic restriction isn't needed here */
		__set_bit(HTTP_CODE_BIT_NUM(n), cb->codes);
	}

	if (frang_parse_ushort(ce->vals[ce->val_n - 2], &cb->limit)
	    || frang_parse_ushort(ce->vals[ce->val_n - 1], &cb->tf))
		return -EINVAL;

	/*
	 * We need the maximum time frame used by all the limiting logic
	 * to keep limit accounting data during this time if the connection is
	 * closed
	 */
	tfw_client_set_expires_time(cb->tf);
	/* Update time frame value to reduce calculations in hot-path. */
	cb->tf = (cb->tf * HZ) / FRANG_FREQ;

	return 0;
}

static int
tfw_cfgop_frang_glob_in_vhost(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	T_ERR_NL("Directive '%s' from 'frang_limits' group can be used "
		 "only as top-level directive (outside of any 'vhost' "
		 "directive).\n",
		 cs->name);
	return -EINVAL;
}

static int
tfw_cfgop_frang_glob_set_bool(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	/*
	 * 'frang_limits' section may appear multiple times to modify defaults
	 * values for future 'frang_limits' directives.
	 */
	if (ce->dflt_value && *(bool *)(cs->dest))
		return 0;
	return tfw_cfg_set_bool(cs, ce);
}

static int
tfw_cfgop_frang_glob_set_int(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (ce->dflt_value && *(unsigned int *)(cs->dest))
		return 0;
	return tfw_cfg_set_int(cs, ce);
}

static int
tfw_cfgop_frang_hdr_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int secs;
	int r;

	if (ce->dflt_value && tfw_frang_glob_reconfig.clnt_hdr_timeout)
		return 0;
	cs->dest = &secs;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	if (!r)
		tfw_frang_glob_reconfig.clnt_hdr_timeout = (unsigned long) HZ
				* secs;

	return r;
}

static int
tfw_cfgop_frang_body_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int secs;
	int r;

	if (ce->dflt_value && tfw_frang_glob_reconfig.clnt_body_timeout)
		return 0;
	cs->dest = &secs;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	if (!r)
		tfw_frang_glob_reconfig.clnt_body_timeout = (unsigned long) HZ
				* secs;

	return r;
}

static FrangVhostCfg *
tfw_cfgop_frang_get_cfg(void)
{
	if (tfwcfg_this_location)
		return tfwcfg_this_location->frang_cfg;
	if (tfw_vhost_entry)
		return tfw_vhost_entry->loc_dflt->frang_cfg;
	return &tfw_frang_vhost_reconfig;
}

static int
tfw_cfgop_frang_uri_len(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value && cfg->http_uri_len)
		return 0;
	cs->dest = &cfg->http_uri_len;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_field_len(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value && cfg->http_field_len)
		return 0;
	cs->dest = &cfg->http_field_len;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_body_len(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value && cfg->http_body_len)
		return 0;
	cs->dest = &cfg->http_body_len;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_hdr_cnt(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value && cfg->http_hdr_cnt)
		return 0;
	cs->dest = &cfg->http_hdr_cnt;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_host_required(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value && cfg->http_host_required)
		return 0;
	cs->dest = &cfg->http_host_required;
	r = tfw_cfg_set_bool(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_ct_required(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value && cfg->http_ct_required)
		return 0;
	cs->dest = &cfg->http_ct_required;
	r = tfw_cfg_set_bool(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_trailer_split(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value && cfg->http_trailer_split)
		return 0;
	cs->dest = &cfg->http_trailer_split;
	r = tfw_cfg_set_bool(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_http_methods(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value && cfg->http_methods_mask)
		return 0;
	return __tfw_cfgop_frang_http_methods(cs, ce, &cfg->http_methods_mask);
}

static int
tfw_cfgop_frang_http_ct_vals(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (cfg->http_ct_vals) {
		if (ce->dflt_value)
			return 0;
		kfree(cfg->http_ct_vals);
		cfg->http_ct_vals = NULL;
		cfg->http_ct_vals_sz = 0;
	}
	return __tfw_cfgop_frang_http_ct_vals(cs, ce, cfg);
}

static int
tfw_cfgop_frang_rsp_code_block(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (cfg->http_resp_code_block) {
		if (ce->dflt_value)
			return 0;
		kfree(cfg->http_resp_code_block);
		cfg->http_resp_code_block = NULL;
	}
	return __tfw_cfgop_frang_rsp_code_block(cs, ce, cfg);
}

static int
tfw_cfgop_http_post_validate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfwcfg_this_location->validate_post_req = 1;
	return 0;
}

/*
 * Frang objects are cleaned when their location is destroyed. This dummy
 * function is required to save time during reconfiguration by skipping
 * traversing over the list of child directives cleanup functions.
 */
static void
tfw_cfgop_frang_cleanup(TfwCfgSpec *cs)
{
	return;
}

static int
tfw_cfgop_out_tls_certificate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_vhosts_reconfig->expl_dflt) {
		T_ERR_NL("%s: global level certificates are to be configured "
			 "outside of explicit '%s' vhost.\n",
			 cs->name, TFW_VH_DFT_NAME);
		return -EINVAL;
	}
	return tfw_tls_set_cert(tfw_vhosts_reconfig->vhost_dflt, cs, ce);
}

static int
tfw_cfgop_in_tls_certificate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_tls_set_cert(tfw_vhost_entry, cs, ce);
}

static int
tfw_cfgop_out_tls_certificate_key(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_vhosts_reconfig->expl_dflt) {
		T_ERR_NL("%s: global level certificates are to be configured "
			 "outside of explicit '%s' vhost.\n",
			 cs->name, TFW_VH_DFT_NAME);
		return -EINVAL;
	}
	return tfw_tls_set_cert_key(tfw_vhosts_reconfig->vhost_dflt, cs, ce);
}

static int
tfw_cfgop_in_tls_certificate_key(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_tls_set_cert_key(tfw_vhost_entry, cs, ce);
}

static int
tfw_cfgop_tls_any_sni(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	bool val;
	int r;

	cs->dest = &val;
	r = tfw_cfg_set_bool(cs, ce);
	cs->dest = NULL;
	if (r)
		return r;

	tfw_tls_match_any_sni_to_dflt(val);

	return 0;
}

static int
tfw_cfgop_in_tls_any_sni(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (!tfw_vhost_is_default_reconfig(tfw_vhost_entry)) {
		if (ce->dflt_value)
			return 0;
		T_ERR_NL("%s: directive can be applied only to '%s' vhost.\n",
			 cs->name, TFW_VH_DFT_NAME);
		return -EINVAL;
	}

	return tfw_cfgop_tls_any_sni(cs, ce);
}

static int
tfw_cfgop_out_tls_any_sni(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_vhosts_reconfig->expl_dflt && ce->dflt_value)
		return 0;
	if (tfw_vhosts_reconfig->expl_dflt) {
		if (ce->dflt_value) {
			return 0;
		}
		else {
			T_ERR_NL("%s: directive defined outside explicit '%s'"
				 "vhost definition\n",
				 cs->name, TFW_VH_DFT_NAME);
			return -EINVAL;
		}
	}

	return tfw_cfgop_tls_any_sni(cs, ce);
}

static int
tfw_vhost_cfgstart(void)
{
	TfwVhost *vh_dflt;

	BUG_ON(tfw_vhosts_reconfig);
	tfw_vhosts_reconfig = kmalloc(sizeof(TfwVhostList), GFP_KERNEL);
	if (!tfw_vhosts_reconfig) {
		T_ERR_NL("Unable to allocate vhosts' list.\n");
		return -ENOMEM;
	}

	tfw_vhosts_reconfig->expl_dflt = false;
	hash_init(tfw_vhosts_reconfig->vh_hash);
	if(!(vh_dflt = tfw_vhost_new(TFW_VH_DFT_NAME))) {
		T_ERR_NL("Unable to create default vhost.\n");
		return -ENOMEM;
	}

	tfw_vhosts_reconfig->vhost_dflt = vh_dflt;
	tfw_frang_clean(&tfw_frang_vhost_reconfig);
	tfw_frang_global_clean(&tfw_frang_glob_reconfig);

	return 0;
}

static int
tfw_vhost_cfgend(void)
{
	TfwSrvGroup *sg_def;
	TfwVhost *vh_dflt;
	int r;

	*tfw_vhosts_reconfig->vhost_dflt->frang_gconf = tfw_frang_glob_reconfig;
	/*
	 * Add default vhost into list if it hadn't been added yet explicitly
	 * to keep default location policies.
	 */
	if (tfw_vhosts_reconfig->expl_dflt)
		return 0;
	/*
	 * Implicit default vhost is still useful even if it's never used to
	 * forward the traffic. It stores fallback location providing
	 * default policies and options that can be used before incoming
	 * request is parsed and assigned to any location.
	 */
	vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	if (tfw_frang_cfg_inherit(vh_dflt->loc_dflt->frang_cfg,
				  &tfw_frang_vhost_reconfig))
		return -ENOMEM;
	sg_def = tfw_sg_lookup_reconfig(TFW_VH_DFT_NAME, SLEN("default"));
	vh_dflt->loc_dflt->main_sg = sg_def;
	tfw_vhost_add(vh_dflt);
	if ((r = tfw_tls_cert_cfg_finish(vh_dflt)))
		return r;

	if (tfw_global.cache_purge && !tfw_global.cache_purge_acl)
		T_WARN_NL("Directives mismatching: 'cache_purge' directive "
			  "requires 'cache_purge_acl', but it wasn't "
			  "provided. 'cache_purge' directive is ignored.\n");
	return 0;
}

static int
tfw_cfgop_vhost_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vhost;
	int i;

	BUG_ON(tfw_vhost_entry);

	if (tfw_cfg_check_val_n(ce, 1))
		return -EINVAL;
	if (ce->attr_n) {
		T_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}
	hash_for_each(tfw_vhosts_reconfig->vh_hash, i, vhost, hlist) {
		if (!strcasecmp(vhost->name.data, ce->vals[0])) {
			T_ERR_NL("Duplicate vhost entry: '%s'\n",
				 ce->vals[0]);
			return -EINVAL;
		}
	}
	if (!strcasecmp(ce->vals[0], TFW_VH_DFT_NAME)) {
		tfw_vhosts_reconfig->expl_dflt = true;
		tfw_vhost_entry = tfw_vhosts_reconfig->vhost_dflt;
		if (__tfw_cfgop_proxy_pass(TFW_VH_DFT_NAME, NULL,
					   tfw_vhost_entry->loc_dflt))
			return -EINVAL;
		if (tfw_frang_cfg_inherit(tfw_vhost_entry->loc_dflt->frang_cfg,
					  &tfw_frang_vhost_reconfig))
			return -ENOMEM;
	} else {
		if (!(tfw_vhost_entry = tfw_vhost_new(ce->vals[0]))) {
			T_ERR_NL("Unable to create new vhost entry: '%s'\n",
				 ce->vals[0]);
			return -ENOMEM;
		}
	}
	tfw_vhost_add(tfw_vhost_entry);
	if (!tfw_vhost_is_default_reconfig(tfw_vhost_entry))
		tfw_vhost_put(tfw_vhost_entry);

	return 0;
}

static int
tfw_cfgop_vhost_finish(TfwCfgSpec *cs)
{
	int r;

	BUG_ON(!tfw_vhost_entry);
	if (!tfw_vhost_entry->loc_dflt->main_sg) {
		BUG_ON(tfw_vhost_is_default_reconfig(tfw_vhost_entry));
		T_ERR_NL("Directive 'proxy_pass' is not specified"
			 " for not default vhost '%s'.\n",
			 tfw_vhost_entry->name.data);
		return -EINVAL;
	}
	if ((r = tfw_tls_cert_cfg_finish(tfw_vhost_entry)))
		return r;
	tfw_vhost_entry = NULL;
	return 0;
}

static void
tfw_cfgop_vhosts_list_free(TfwVhostList *vhosts)
{
	TfwVhost *vhost;
	struct hlist_node *tmp;
	int i;

	if (!vhosts)
		return;

	hash_for_each_safe((vhosts->vh_hash), i, tmp, vhost, hlist) {
		hash_del(&vhost->hlist);
		set_bit(TFW_VHOST_B_REMOVED, &vhost->flags);
		tfw_vhost_put(vhost);
		tfw_srv_loop_sched_rcu();
	}
	set_bit(TFW_VHOST_B_REMOVED, &vhosts->vhost_dflt->flags);
	tfw_vhost_put(vhosts->vhost_dflt);
	kfree(vhosts);
}

static int
tfw_vhost_start(void)
{
	TfwVhostList *vh_list;

	rcu_read_lock();
	vh_list = rcu_dereference(tfw_vhosts);
	rcu_read_unlock();
	rcu_assign_pointer(tfw_vhosts, tfw_vhosts_reconfig);
	synchronize_rcu();

	tfw_cfgop_vhosts_list_free(vh_list);
	tfw_vhosts_reconfig = NULL;

	return 0;
}

static void
__tfw_cfgop_vhosts_cleanup(void)
{
	tfw_cfgop_vhosts_list_free(tfw_vhosts_reconfig);
	tfw_vhosts_reconfig = NULL;

	if (!tfw_runstate_is_reconfig()) {
		tfw_cfgop_vhosts_list_free(tfw_vhosts);
		tfw_vhosts = NULL;
	}
}

static void
tfw_cfgop_vhosts_cleanup(TfwCfgSpec *cs)
{
	__tfw_cfgop_vhosts_cleanup();
}

static void
tfw_vhost_cfgclean(void)
{
	__tfw_cfgop_vhosts_cleanup();

	if (tfw_runstate_is_reconfig())
		return;

	tfw_global.capuacl_sz =
	tfw_global.cache_purge =
	tfw_global.cache_purge_mode =
	tfw_global.cache_purge_acl = 0;

	if (tfw_global.hdr_via && (tfw_global.hdr_via != s_hdr_via_dflt))
		kfree(tfw_global.hdr_via);
	tfw_global.hdr_via = s_hdr_via_dflt;
}

/*
 * Not all Frang specs can be applied to nested locations and can be applied
 * only as high-level options. It's possible to provide their own sets for
 * global and inner (location) options. But warning "line 32: the frang limit
 * can be assigned only at global level" is much more user friendly than generic
 * "line 32: unknown command".
 */
static TfwCfgSpec tfw_global_frang_specs[] = {
	/* Options that can be enabled|disabled only globally. */
	{
		.name = "ip_block",
		.deflt = "off",
		.handler = tfw_cfgop_frang_glob_set_bool,
		.dest = &tfw_frang_glob_reconfig.ip_block,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "request_rate",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.req_rate,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "request_burst",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.req_burst,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "connection_rate",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.conn_rate,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "connection_burst",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.conn_burst,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "concurrent_connections",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.conn_max,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "client_header_timeout",
		.deflt = "0",
		.handler = tfw_cfgop_frang_hdr_timeout,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "client_body_timeout",
		.deflt = "0",
		.handler = tfw_cfgop_frang_body_timeout,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "http_header_chunk_cnt",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.http_hchunk_cnt,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "http_body_chunk_cnt",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.http_bchunk_cnt,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	/* Option can be redefined per vhost|location. */
	{
		.name = "http_uri_len",
		.deflt = "0",
		.handler = tfw_cfgop_frang_uri_len,
		.allow_reconfig = true,
	},
	{
		.name = "http_field_len",
		.deflt = "0",
		.handler = tfw_cfgop_frang_field_len,
		.allow_reconfig = true,
	},
	{
		.name = "http_body_len",
		.deflt = "1073741824", /* 1 Gb. */
		.handler = tfw_cfgop_frang_body_len,
		.allow_reconfig = true,
	},
	{
		.name = "http_header_cnt",
		.deflt = "0",
		.handler = tfw_cfgop_frang_hdr_cnt,
		.allow_reconfig = true,
	},
	{
		.name = "http_host_required",
		.deflt = "true",
		.handler = tfw_cfgop_frang_host_required,
		.allow_reconfig = true,
	},
	{
		.name = "http_ct_required",
		.deflt = "false",
		.handler = tfw_cfgop_frang_ct_required,
		.allow_reconfig = true,
	},
	{
		.name = "http_trailer_split_allowed",
		.deflt = "false",
		.handler = tfw_cfgop_frang_trailer_split,
		.allow_reconfig = true,
	},
	{
		.name = "http_methods",
		.deflt = "",
		.handler = tfw_cfgop_frang_http_methods,
		.allow_reconfig = true,
	},
	{
		.name = "http_ct_vals",
		.deflt = NULL,
		.handler = tfw_cfgop_frang_http_ct_vals,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{
		.name = "http_resp_code_block",
		.deflt = NULL,
		.handler = tfw_cfgop_frang_rsp_code_block,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{ 0 }
};

static TfwCfgSpec tfw_vhost_frang_specs[] = {
	/* Options that can be enabled|disabled only globally. */
	{
		.name = "ip_block",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "request_rate",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "request_burst",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "connection_rate",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "connection_burst",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "concurrent_connections",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "client_header_timeout",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "client_body_timeout",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "http_header_chunk_cnt",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "http_body_chunk_cnt",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	/* Option can be redefined per vhost|location. */
	{
		.name = "http_uri_len",
		.deflt = "0",
		.handler = tfw_cfgop_frang_uri_len,
		.allow_reconfig = true,
	},
	{
		.name = "http_field_len",
		.deflt = "0",
		.handler = tfw_cfgop_frang_field_len,
		.allow_reconfig = true,
	},
	{
		.name = "http_body_len",
		.deflt = "1073741824", /* 1 Gb. */
		.handler = tfw_cfgop_frang_body_len,
		.allow_reconfig = true,
	},
	{
		.name = "http_header_cnt",
		.deflt = "0",
		.handler = tfw_cfgop_frang_hdr_cnt,
		.allow_reconfig = true,
	},
	{
		.name = "http_host_required",
		.deflt = "true",
		.handler = tfw_cfgop_frang_host_required,
		.allow_reconfig = true,
	},
	{
		.name = "http_ct_required",
		.deflt = "false",
		.handler = tfw_cfgop_frang_ct_required,
		.allow_reconfig = true,
	},
	{
		.name = "http_trailer_split_allowed",
		.deflt = "false",
		.handler = tfw_cfgop_frang_trailer_split,
		.allow_reconfig = true,
	},
	{
		.name = "http_methods",
		.deflt = "",
		.handler = tfw_cfgop_frang_http_methods,
		.allow_reconfig = true,
	},
	{
		.name = "http_ct_vals",
		.deflt = NULL,
		.handler = tfw_cfgop_frang_http_ct_vals,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{
		.name = "http_resp_code_block",
		.deflt = NULL,
		.handler = tfw_cfgop_frang_rsp_code_block,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{ 0 }
};

static TfwCfgSpec tfw_vhost_location_specs[] = {
	{
		.name = "cache_bypass",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_cache_bypass,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_fulfill",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_cache_fulfill,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "nonidempotent",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_nonidempotent,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_req_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_req_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_resp_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_resp_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "http_post_validate",
		.handler = tfw_cfgop_http_post_validate,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "http_resp_code_block",
		.handler = tfw_cfgop_frang_rsp_code_block,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "proxy_pass",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_proxy_pass,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "frang_limits",
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfgop_frang_cleanup,
		.dest = tfw_vhost_frang_specs,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{ 0 }
};

static TfwCfgSpec tfw_vhost_internal_specs[] = {
	{
		.name = "cache_bypass",
		.deflt = NULL,
		.handler = tfw_cfgop_in_cache_bypass,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_fulfill",
		.deflt = NULL,
		.handler = tfw_cfgop_in_cache_fulfill,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "http_post_validate",
		.deflt = NULL,
		.handler = tfw_cfgop_in_http_post_validate,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "nonidempotent",
		.deflt = NULL,
		.handler = tfw_cfgop_in_nonidempotent,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_in_req_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_in_req_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_in_resp_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_in_resp_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "proxy_pass",
		.deflt = NULL,
		.handler = tfw_cfgop_in_proxy_pass,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "tls_certificate",
		.deflt = NULL,
		.handler = tfw_cfgop_in_tls_certificate,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "tls_certificate_key",
		.deflt = NULL,
		.handler = tfw_cfgop_in_tls_certificate_key,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "tls_match_any_server_name",
		.deflt = "false",
		.handler = tfw_cfgop_in_tls_any_sni,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "location",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfg_cleanup_children,
		.dest = tfw_vhost_location_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tfw_cfgop_in_location_begin,
			.finish_hook = tfw_cfgop_in_location_finish
		},
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "frang_limits",
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfgop_frang_cleanup,
		.dest = tfw_vhost_frang_specs,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{ 0 }
};

static TfwCfgSpec tfw_vhost_specs[] = {
	{
		.name = "hdr_via",
		.deflt = NULL,
		.handler = tfw_cfgop_hdr_via,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = false,
	},
	{
		.name = "cache_purge",
		.deflt = NULL,
		.handler = tfw_cfgop_cache_purge,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = false,
	},
	{
		.name = "cache_purge_acl",
		.deflt = NULL,
		.handler = tfw_cfgop_cache_purge_acl,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = false,
	},
	{
		.name = "cache_bypass",
		.deflt = NULL,
		.handler = tfw_cfgop_out_cache_bypass,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_fulfill",
		.deflt = NULL,
		.handler = tfw_cfgop_out_cache_fulfill,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "http_post_validate",
		.deflt = NULL,
		.handler = tfw_cfgop_out_http_post_validate,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "nonidempotent",
		.deflt = NULL,
		.handler = tfw_cfgop_out_nonidempotent,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_out_req_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "req_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_out_req_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_add",
		.deflt = NULL,
		.handler = tfw_cfgop_out_resp_hdr_add,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "resp_hdr_set",
		.deflt = NULL,
		.handler = tfw_cfgop_out_resp_hdr_set,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "tls_certificate",
		.deflt = NULL,
		.handler = tfw_cfgop_out_tls_certificate,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "tls_certificate_key",
		.deflt = NULL,
		.handler = tfw_cfgop_out_tls_certificate_key,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "tls_match_any_server_name",
		.deflt = "false",
		.handler = tfw_cfgop_out_tls_any_sni,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "location",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfg_cleanup_children,
		.dest = tfw_vhost_location_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tfw_cfgop_out_location_begin,
			.finish_hook = tfw_cfgop_out_location_finish
		},
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "vhost",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfgop_vhosts_cleanup,
		.dest = tfw_vhost_internal_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tfw_cfgop_vhost_begin,
			.finish_hook = tfw_cfgop_vhost_finish
		},
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "frang_limits",
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfgop_frang_cleanup,
		.dest = tfw_global_frang_specs,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{ 0 }
};

TfwMod tfw_vhost_mod = {
	.name		= "vhost",
	.cfgstart	= tfw_vhost_cfgstart,
	.cfgend		= tfw_vhost_cfgend,
	.start		= tfw_vhost_start,
	.specs		= tfw_vhost_specs,
	.cfgclean	= tfw_vhost_cfgclean,
};

int
tfw_vhost_init(void)
{
	tfw_mod_register(&tfw_vhost_mod);
	return 0;
}

void
tfw_vhost_exit(void)
{
	tfw_mod_unregister(&tfw_vhost_mod);
}
