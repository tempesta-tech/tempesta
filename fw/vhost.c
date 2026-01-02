/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2024 Tempesta Technologies, Inc.
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
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/sort.h>

#undef DEBUG
#if DBG_VHOST > 0
#define DEBUG DBG_VHOST
#endif

#include "tempesta_fw.h"
#include "cache.h"
#include "hash.h"
#include "http.h"
#include "http_limits.h"
#include "http_match.h"
#include "http_msg.h"
#include "http_sess_conf.h"
#include "vhost.h"
#include "str.h"
#include "http_limits.h"
#include "http_sess.h"
#include "client.h"
#include "tls_conf.h"
#include "lib/log.h"
#include "lib/fault_injection_alloc.h"

/*
 * The hash table entry for mapping @sni to @vhost for SAN certificates handling.
 */
typedef struct {
	struct hlist_node	hlist;
	TfwVhost		*vhost;
	size_t			sni_len;
	char			sni[0];
} TfwSVHMap;

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
 * @sni_vh_map	- Hash table mapping SNI to virtual hosts.
 */
typedef struct {
	TfwVhost	*vhost_dflt;
	bool		expl_dflt;
	DECLARE_HASHTABLE(vh_hash, TFW_VH_HBITS);
	DECLARE_HASHTABLE(sni_vh_map, TFW_VH_HBITS);
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

#define TFW_CAPOLICY_HDR_DEL_LIMIT	(16)

/*
 * Each non-idempotent request definition directive is put into
 * a separately allocated memory area. The pointers to the memory
 * are put into a fixed size array of pointers within a location
 * definition.
 */
#define TFW_NIPDEF_ARRAY_SZ	(64)

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

#if DBG_VHOST > 0
static void tfw_cfgop_vhosts_print(TfwVhostList *vhosts);
#endif

/*
 * Default vhost is a wildcard vhost. It matches any URI.
 * It may (or may not) contain a set of various directives.
 *
 * Note that @loc_dflt in the default vhost serves as global
 * default caching policy.
 */
static const char s_hdr_via_dflt[] =
	"tempesta_fw" " (" TFW_NAME " " TFW_VERSION ")";

static TfwCfgSpec tfw_global_frang_specs[];

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
TfwHdrMods *
tfw_vhost_get_hdr_mods(TfwLocation *loc, TfwVhost *vhost, int mod_type)
{
	TfwVhost *vh_dflt = vhost->vhost_dflt;

	/* TODO #862: req->location must be the full set of options. */
	if (!loc || !loc->mod_hdrs[mod_type].sz)
		loc = vhost->loc_dflt;
	if (!loc || !loc->mod_hdrs[mod_type].sz)
		loc = vh_dflt ? vh_dflt->loc_dflt : NULL;
	if (!loc || !loc->mod_hdrs[mod_type].sz)
		return NULL;

	return &loc->mod_hdrs[mod_type];
}

TfwCaTokenArray
tfw_vhost_get_capo_hdr_del(TfwLocation *loc, TfwVhost *vhost)
{
	TfwVhost *vh_dflt = vhost->vhost_dflt;

	/* TODO #862: req->location must be the full set of options. */
	if (!loc || !loc->capo_hdr_del)
		loc = vhost->loc_dflt;
	if (!loc || !loc->capo_hdr_del)
		loc = vh_dflt ? vh_dflt->loc_dflt : NULL;
	if (!loc || !loc->capo_hdr_del)
		return (TfwCaTokenArray){0, NULL};

	return (TfwCaTokenArray){loc->capo_hdr_del_sz, loc->capo_hdr_del};
}

unsigned int
tfw_vhost_get_cc_ignore(TfwLocation *loc, TfwVhost *vhost)
{
	TfwVhost *vh_dflt = vhost->vhost_dflt;

	/* TODO #862: req->location must be the full set of options. */
	if (!loc || !loc->cc_ignore)
		loc = vhost->loc_dflt;
	if (!loc || !loc->cc_ignore)
		loc = vh_dflt ? vh_dflt->loc_dflt : NULL;
	if (!loc || !loc->cc_ignore)
		return 0;

	return loc->cc_ignore;
}

/**
 * Find a cache use stale setting according to the current location.
 *
 * @loc		- request URI location;
 * @vhost	- virtual host for the request;
 */
TfwCacheUseStale *
tfw_vhost_get_cache_use_stale(TfwLocation *loc, TfwVhost *vhost)
{
	TfwVhost *vh_dflt = vhost->vhost_dflt;

	/* TODO #862: req->location must be the full set of options. */
	if (!loc || !loc->cache_use_stale)
		loc = vhost->loc_dflt;
	if (!loc || !loc->cache_use_stale)
		loc = vh_dflt ? vh_dflt->loc_dflt : NULL;
	if (!loc || !loc->cache_use_stale)
		return NULL;

	return loc->cache_use_stale;
}

/*
 * ------------------------------------------------------------------------
 *	Configuration processing.
 * ------------------------------------------------------------------------
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
tfw_vhost_name_match(const BasicStr *vh, const BasicStr *name)
{
	return vh->len == name->len
		&& !strncasecmp(vh->data, name->data, vh->len);
}

static inline TfwVhost *
__tfw_vhost_lookup(TfwVhostList *vh_list, const BasicStr *name,
		   bool (*match_fn)(const BasicStr *, const BasicStr *))
{
	TfwVhost *vhost;
	unsigned long key = basic_hash_str(name);

	hash_for_each_possible(vh_list->vh_hash, vhost, hlist, key) {
		if (match_fn(&vhost->name, name)) {
			tfw_vhost_get(vhost);
			return vhost;
		}
	}
	return NULL;
}

/**
 * Find vhost named @name in the _currently parsed and not yet applied_
 * configuration. The operation is safe to use in process context.
 * If vhost is found, an additional reference is taken. Caller is responsible
 * to release the reference after use.
 */
TfwVhost *
tfw_vhost_lookup_reconfig(const char *name)
{
	const BasicStr ns = {.data = (char *)name, .len = strlen(name)};

	return __tfw_vhost_lookup(tfw_vhosts_reconfig, &ns,
				  tfw_vhost_name_match);
}

/**
 * Lookup vhost by an SNI wildcard. It is a caller responsibility to
 * release the vhost reference after use.
 */
TfwVhost *
tfw_vhost_lookup_sni(const BasicStr *name)
{
	TfwSVHMap *svhm;
	TfwVhostList *vhlist;
	unsigned long key = basic_hash_str(name);

	rcu_read_lock_bh();
	vhlist = rcu_dereference_bh(tfw_vhosts);
	BUG_ON(!vhlist);

	hash_for_each_possible(vhlist->sni_vh_map, svhm, hlist, key) {
		if (svhm->sni_len != name->len
		    || tfw_cstricmp(name->data, svhm->sni, svhm->sni_len))
			continue;
		tfw_vhost_get(svhm->vhost);
		rcu_read_unlock_bh();
		return svhm->vhost;
	}
	rcu_read_unlock_bh();

	return NULL;
}

/**
 * Get default vhost in the running configuration. Default vhost is special
 * entity that contains default policies if more precise vhost cannot be found.
 * It is a caller responsibility to release the vhost reference after use.
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

	data = tfw_kmalloc(sizeof(TfwNipDef) + len + 1, GFP_KERNEL);
	if (unlikely(!data))
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

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);
	TFW_CFG_CHECK_VAL_N(==, 3, cs, ce);

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

	if (unlikely(h_mods->sz == TFW_USRHDRS_ARRAY_SZ)) {
		T_WARN_NL("Too lot of custom headers, %d supported.\n",
			  TFW_USRHDRS_ARRAY_SZ);
		return -EINVAL;
	}

	if (!(hdr = tfw_http_msg_make_hdr(loc->hdrs_pool, name, value))) {
		T_WARN_NL("Can't create header.\n");
		return -ENOMEM;
	}

	desc->hid = (mod_type == TFW_VHOST_HDRMOD_RESP)
			? tfw_http_msg_resp_spec_hid(TFW_STR_CHUNK(hdr, 0))
			: tfw_http_msg_req_spec_hid(TFW_STR_CHUNK(hdr, 0));

	if (desc->hid < TFW_HTTP_HDR_RAW) {
		if (h_mods->spec_hdrs[desc->hid]) {
			T_WARN_NL("Duplicated header modification.\n");
			return -EINVAL;
		}
		h_mods->spec_hdrs[desc->hid] = desc;
		++h_mods->spec_num;
	}

	hdr->hpack_idx = tfw_hpack_find_hdr_idx(TFW_STR_CHUNK(hdr, 0));
	desc->hdr = hdr;
	desc->append = append;
	++h_mods->sz;
	if (!append)
		set_bit(hdr->hpack_idx, h_mods->s_tbl);

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

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	switch (ce->val_n)
	{
	case 2:
		break;
	case 1:
		if (!append)
			break;
		fallthrough;
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

static int
tfw_mod_hdr_cmp(const void *l, const void *r)
{
	TfwHdrModsDesc *desc_l = (TfwHdrModsDesc *)l;
	TfwHdrModsDesc *desc_r = (TfwHdrModsDesc *)r;

	return (int)desc_l->hid - (int)desc_r->hid;
}

static void
tfw_mod_hdr_sort(TfwLocation *loc)
{
	unsigned short type;

	for (type = 0; type < TFW_VHOST_HDRMOD_NUM; type++) {
		TfwHdrMods *h_mods = &loc->mod_hdrs[type];

		sort(h_mods->hdrs, h_mods->sz, sizeof(h_mods->hdrs[0]),
		     tfw_mod_hdr_cmp, NULL);
	}
}

static void
__set_bit_range(int start, int end, unsigned long *codes)
{
	int i;

	for (i = HTTP_CODE_BIT_NUM(start); i < HTTP_CODE_BIT_NUM(end); i++)
		__set_bit(i, codes);
}

static int
tfw_cfgop_cache_use_stale(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc)
{
	TfwCacheUseStale *cfg;
	size_t i;
	int n = 0;
	bool mask5x = false, mask4x = false, any4x = false, any5x = false;

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);
	TFW_CFG_CHECK_VAL_N(>=, 1, cs, ce);

	/* 
	 * TODO: Revise and remove after #2123.
	 */
	if (tfw_vhost_is_default_reconfig(tfw_vhost_entry)) {
		T_ERR_NL("%s: directive can not be applied to default vhost.\n",
			 cs->name);
		return -EINVAL;
	}

	cfg = tfw_kzalloc(sizeof(TfwCacheUseStale), GFP_KERNEL);

	if (!cfg)
		return -ENOMEM;

	loc->cache_use_stale = cfg;

	for (i = 0; i < ce->val_n; i++) {
		if (!strcasecmp(ce->vals[i], "4*")) {
			if (any4x) {
				T_ERR_NL("Attempt to override by mask 4* the value specified by code.\n");
				return -EINVAL;
			}
			else if (mask4x) {
				T_ERR_NL("Duplicated mask 4*.\n");
				return -EINVAL;
			}
			mask4x = true;
			__set_bit_range(400, 499, cfg->codes);
		}
		else if (!strcasecmp(ce->vals[i], "5*")) {
			if (any5x) {
				T_ERR_NL("Attempt to override by mask 5* the value specified by code.\n");
				return -EINVAL;
			}
			else if (mask5x) {
				T_ERR_NL("Duplicated mask 5*.\n");
				return -EINVAL;
			}
			mask5x = true;
			__set_bit_range(500, 599, cfg->codes);
		}
		else {
			if (tfw_cfg_parse_int(ce->vals[i], &n)
			    || !tfw_http_resp_code_range(n))
			{
				T_ERR_NL("%s Unsupported argument \"%s\"",
					 cs->name, ce->vals[i]);
				return -EINVAL;
			}

			/* Allows status-codes only above 399. */
			if (n < 400) {
				T_ERR_NL("Please specify status code above than 399.");
				return -EINVAL;
			}

			if (n >= 400 && n <= 499)
				any4x = true;
			else if (n >= 500 && n <= 599)
				any5x = true;

			if ((any4x && mask4x) || (any5x && mask5x)) {
				T_ERR_NL("Attempt to set the value %d already set by mask.\n",
					 n);
				return -EINVAL;
			}

			if (test_bit(HTTP_CODE_BIT_NUM(n), cfg->codes)) {
				T_ERR_NL("Duplicated value %d.\n", n);
				return -EINVAL;
			}

			__set_bit(HTTP_CODE_BIT_NUM(n), cfg->codes);
		}
	}

	return 0;
}

static int
tfw_cfgop_loc_cache_use_stale(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_cache_use_stale(cs, ce, tfwcfg_this_location);
}

static int
tfw_cfgop_in_cache_use_stale(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_cache_use_stale(cs, ce, tfw_vhost_entry->loc_dflt);
}

static int
tfw_cfgop_out_cache_use_stale(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	return tfw_cfgop_cache_use_stale(cs, ce, vh_dflt->loc_dflt);
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

	capo = tfw_kmalloc(sizeof(TfwCaPolicy) + len + 1,
			   GFP_KERNEL);
	if (unlikely(!capo))
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

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);
	TFW_CFG_CHECK_VAL_N(>=, 2, cs, ce);

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
 * cache_resp_hdr_del option to always remove specific headers from
 * cached responses.
 */
static int
tfw_cfgop_capo_hdr_del(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc)
{
	size_t i;
	size_t total_size;
	TfwCaToken *new_tokens;

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);
	TFW_CFG_CHECK_VAL_N(>=, 1, cs, ce);
	if (ce->val_n > TFW_CAPOLICY_HDR_DEL_LIMIT) {
		T_ERR_NL("%s: Too many headers\n",
			 cs->name);
		return -EINVAL;
	}

	/*
	 * Precalculate the total strings size and allocate into
	 * single memory block
	 */
	total_size = 0;
	for (i = 0; i < ce->val_n; ++i) {
		const char *arg = ce->vals[i];
		size_t len = strlen(arg);
		/* Need a trailing colon for header matching, and '\0'. */
		int item_size = sizeof(TfwCaToken) + len + 1 + 1;
		total_size += item_size;
	}
	new_tokens = NULL;

	if (total_size != 0) {
		size_t actual_bytes = 0;
		TfwCaToken *token;
		new_tokens = tfw_kzalloc(total_size, GFP_KERNEL);
		if (!new_tokens)
			return -ENOMEM;
		token = new_tokens;
		for (i = 0; i < ce->val_n; ++i) {
			const char *arg = ce->vals[i];
			size_t len = strlen(arg);
			char *str = token->str;
			token->len = len + 2;
			memcpy(str, (void *)arg, len);
			str[len] = ':';
			str[len + 1] = '\0';

			actual_bytes += sizeof(TfwCaToken) + len + 2;
			token = (TfwCaToken *)(actual_bytes + (char *)new_tokens);
		}
		BUG_ON(actual_bytes != total_size);
	}
	BUG_ON(ce->val_n && !new_tokens);
	loc->capo_hdr_del = new_tokens;
	loc->capo_hdr_del_sz = ce->val_n;

	return 0;
}

/*
 * cache_control_ignore allows us to selectively ignore some undesired
 * Cache-Control directives sent to us in a response from upstream server.
 */
static int
tfw_cfgop_cc_ignore(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwLocation *loc)
{
#define STR_AND_LEN(s)  sizeof(s)-1, s
const struct {
	unsigned int flag;
	unsigned int dir_sz;
	char *dir;
} dir_map[] = {
	/* CC directives common to requests and responses. */
	{ TFW_HTTP_CC_NO_CACHE, STR_AND_LEN("no-cache") },
	{ TFW_HTTP_CC_NO_STORE, STR_AND_LEN("no-store") },
	{ TFW_HTTP_CC_NO_TRANSFORM, STR_AND_LEN("no-transform") },
	{ TFW_HTTP_CC_MAX_AGE, STR_AND_LEN("max-age") },
	/* Response-only CC directives. */
	{ TFW_HTTP_CC_MUST_REVAL, STR_AND_LEN("must-revalidate") },
	{ TFW_HTTP_CC_PROXY_REVAL, STR_AND_LEN("proxy-revalidate") },
	{ TFW_HTTP_CC_PUBLIC, STR_AND_LEN("public") },
	{ TFW_HTTP_CC_PRIVATE, STR_AND_LEN("private") },
	{ TFW_HTTP_CC_S_MAXAGE, STR_AND_LEN("s-maxage") },
};
#undef 	STR_AND_LEN

	size_t i, len;
	const char *arg;

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);
	TFW_CFG_CHECK_VAL_N(>=, 1, cs, ce);

	for (i = 0; i < ce->val_n; ++i) {
		int map_idx;
		arg = ce->vals[i];
		len = strlen(arg);
		for (map_idx = 0; map_idx < ARRAY_SIZE(dir_map); map_idx++) {
			if (strncasecmp(arg, dir_map[map_idx].dir,
					 dir_map[map_idx].dir_sz) == 0)
			{
				loc->cc_ignore |= dir_map[map_idx].flag;
				break;
			}
		}
	}

	return 0;
}

static int
tfw_cfgop_loc_cache_resp_hdr_del(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_capo_hdr_del(cs, ce, tfwcfg_this_location);
}

static int
tfw_cfgop_loc_cache_control_ignore(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfwcfg_this_location);
	return tfw_cfgop_cc_ignore(cs, ce, tfwcfg_this_location);
}

static int
tfw_cfgop_in_cache_resp_hdr_del(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_capo_hdr_del(cs, ce, tfw_vhost_entry->loc_dflt);
}

static int
tfw_cfgop_in_cache_control_ignore(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_cfgop_cc_ignore(cs, ce, tfw_vhost_entry->loc_dflt);
}

static int
tfw_cfgop_out_cache_resp_hdr_del(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	return tfw_cfgop_capo_hdr_del(cs, ce, vh_dflt->loc_dflt);
}

static int
tfw_cfgop_out_cache_control_ignore(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	return tfw_cfgop_cc_ignore(cs, ce, vh_dflt->loc_dflt);
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
tfw_frang_cfg_inherit(FrangVhostCfg *curr, const FrangVhostCfg *from)
{
	int r = 0;

	memcpy(curr, from, sizeof(FrangVhostCfg));

	if (from->http_ct_vals) {
		size_t sz = from->http_ct_vals->alloc_sz;
		FrangCtVal *val;
		long delta;

		curr->http_ct_vals = tfw_kzalloc(sz, GFP_KERNEL);
		if (!curr->http_ct_vals) {
			r = -ENOMEM;
		}
		else {
			delta = (void *)from->http_ct_vals -
				(void *)curr->http_ct_vals;
			memcpy(curr->http_ct_vals, from->http_ct_vals, sz);
			curr->http_ct_vals->vals = (void *)curr->http_ct_vals
					+ sizeof(FrangCtVals);
			curr->http_ct_vals->data -= delta;
			/* Restore data pointers. */
			for (val = curr->http_ct_vals->vals; val->str; ++ val)
				val->str -= delta;
		}
	}
	if (!r && from->http_resp_code_block) {
		size_t sz = sizeof(FrangHttpRespCodeBlock);
		curr->http_resp_code_block = tfw_kzalloc(sz, GFP_KERNEL);
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
		    + sizeof(TfwHdrModsDesc) * TFW_USRHDRS_ARRAY_SZ * 2
		    + sizeof(TfwHdrModsDesc *) * TFW_HTTP_HDR_RAW * 2;

	memset(loc, 0, sizeof(TfwLocation));
	if ((argmem = tfw_kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	if ((data = tfw_kzalloc(size, GFP_KERNEL)) == NULL) {
		kfree(argmem);
		return -ENOMEM;
	}

	loc->op = op;
	loc->arg = argmem;
	loc->len = len;
	loc->frang_cfg = (FrangVhostCfg *)data;
	/* next array starts right after the previous one */
	loc->capo = (TfwCaPolicy **)(loc->frang_cfg + 1);
	loc->capo_sz = 0;
	loc->capo_hdr_del = NULL;
	loc->capo_hdr_del_sz = 0;
	loc->cc_ignore = 0;
	loc->nipdef = (TfwNipDef **)(loc->capo + TFW_CAPOLICY_ARRAY_SZ);
	loc->nipdef_sz = 0;
	loc->hdrs_pool = pool;
	loc->mod_hdrs[TFW_VHOST_HDRMOD_REQ].hdrs =
		(TfwHdrModsDesc *)(loc->nipdef + TFW_NIPDEF_ARRAY_SZ);

	loc->mod_hdrs[TFW_VHOST_HDRMOD_REQ].spec_hdrs =
		(TfwHdrModsDesc **)(loc->mod_hdrs[TFW_VHOST_HDRMOD_REQ].hdrs
				    + TFW_USRHDRS_ARRAY_SZ);

	loc->mod_hdrs[TFW_VHOST_HDRMOD_RESP].hdrs =
		(TfwHdrModsDesc *)(loc->mod_hdrs[TFW_VHOST_HDRMOD_REQ].spec_hdrs
				   + TFW_HTTP_HDR_RAW);

	loc->mod_hdrs[TFW_VHOST_HDRMOD_RESP].spec_hdrs =
		(TfwHdrModsDesc **)(loc->mod_hdrs[TFW_VHOST_HDRMOD_RESP].hdrs
				    + TFW_USRHDRS_ARRAY_SZ);

	memcpy((void *)loc->arg, (void *)arg, len + 1);

	return 0;
}

/*
 * Create and initialize a new entry for a location directive.
 * The entry is placed in the array that holds all location directives
 * for current vhost.
 */
static inline TfwLocation *
tfw_location_new(TfwVhost *vhost, tfw_match_t op, const char *arg,
		 size_t len, bool is_global)
{
	TfwLocation *loc;

	loc = &vhost->loc[vhost->loc_sz];
	if (tfw_location_init(loc, op, arg, len, vhost->hdrs_pool))
		return NULL;
	vhost->loc_sz++;

	if (!is_global) {
		/* Explicit vhost */
		if (tfw_frang_cfg_inherit(loc->frang_cfg,
					  vhost->loc_dflt->frang_cfg))
			return NULL;
		return loc;
	}

	/* Implicit default vhost */
	if (tfw_frang_cfg_inherit(loc->frang_cfg,
				  &tfw_frang_vhost_reconfig))
		return NULL;
	return loc;
}

/*
 * Process the location directive that opens a section for cache
 * policy directives in the configuration.
 */
static int
tfw_cfgop_location_begin(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwVhost *vhost,
			 bool is_global)
{
	int ret;
	size_t len;
	tfw_match_t op;
	const char *in_op, *arg;

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);
	TFW_CFG_CHECK_VAL_N(==, 2, cs, ce);

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
	tfwcfg_this_location = tfw_location_new(vhost, op, arg, len, is_global);
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
	return tfw_cfgop_location_begin(cs, ce, tfw_vhost_entry, false);
}

static int
tfw_cfgop_out_location_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(tfw_vhost_entry);
	BUG_ON(tfwcfg_this_location);
	return tfw_cfgop_location_begin(cs, ce,
					tfw_vhosts_reconfig->vhost_dflt,
					true);
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
	tfw_mod_hdr_sort(tfwcfg_this_location);
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

	/*
	 * Free loc->arg and loc->frang_cfg, loc->capo,
	 * loc->nipdef, loc->cache_use_stale and loc->capo_hdr_del.
	 */
	for (i = 0; i < loc->capo_sz; ++i) {
		BUG_ON(!loc->capo[i]);
		kfree(loc->capo[i]);
	}

	kfree(loc->capo_hdr_del);
	for (i = 0; i < loc->nipdef_sz; ++i) {
		BUG_ON(!loc->nipdef[i]);
		kfree(loc->nipdef[i]);
	}

	if (loc->frang_cfg)
		__tfw_frang_clean(loc->frang_cfg);

	kfree(loc->arg);
	kfree(loc->frang_cfg);
	kfree(loc->cache_use_stale);

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

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

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

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	if (!ce->val_n) {
		/* Default value for the cache_purge directive. */
		tfw_global.cache_purge_mode = TFW_D_CACHE_PURGE_INVALIDATE;
		goto done;
	}
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (!strcasecmp(val, "invalidate")) {
			tfw_global.cache_purge_mode = TFW_D_CACHE_PURGE_INVALIDATE;
		}
		else if (!strcasecmp(val, "immediate")) {
			tfw_global.cache_purge_mode = TFW_D_CACHE_PURGE_IMMEDIATE;
		}
		else {
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

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);
	TFW_CFG_CHECK_VAL_N(==, 1, cs, ce);

	/*
	 * If a value is specified in the configuration file, then
	 * the default value is not used, even if the processing of
	 * the specified value results in an error.
	 */
	len = strlen(ce->vals[0]);
	if ((tfw_global.hdr_via = tfw_kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memcpy((void *)tfw_global.hdr_via, (void *)ce->vals[0], len + 1);
	tfw_global.hdr_via_len = len;

	return 0;
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

		if (main_sg == backup_sg) {
			T_ERR_NL("proxy_pass: the same group is used as primary"
				 " and backup\n");
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
	const char *in_main_sg, *in_backup_sg;

	TFW_CFG_CHECK_VAL_N(==, 1, cs, ce);

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

static int
tfw_cfgop_in_sticky_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_http_sess_cfgop_begin(tfw_vhost_entry, cs, ce);
}

static int
tfw_cfgop_out_sticky_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(tfw_vhost_entry);

	return tfw_http_sess_cfgop_begin(NULL, cs, ce);
}

static int
tfw_cfgop_in_sticky_finish(TfwCfgSpec *cs)
{
	BUG_ON(!tfw_vhost_entry);
	return tfw_http_sess_cfgop_finish(tfw_vhost_entry, cs);
}

static int
tfw_cfgop_out_sticky_finish(TfwCfgSpec *cs)
{
	BUG_ON(tfw_vhost_entry);
	return tfw_http_sess_cfgop_finish(NULL, cs);
}

void
tfw_vhost_destroy(TfwVhost *vhost)
{
	int i;

	for (i = 0; i < vhost->loc_sz; ++i)
		tfw_location_del(&vhost->loc[i]);
	tfw_location_del(vhost->loc_dflt);
	tfw_http_sess_cookie_clean(vhost);
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
	int name_strlen = strlen(name);
	int name_mem_sz = ALIGN(name_strlen + 1, sizeof(void *));
	int size = sizeof(TfwVhost)
		+ name_mem_sz
		+ sizeof(TfwLocation) * (TFW_LOCATION_ARRAY_SZ + 1)
		+ sizeof(TfwStickyCookie) + sizeof(FrangGlobCfg)
		+ tfw_tls_vhost_priv_data_sz();

	if (!(pool = __tfw_pool_new(0)))
		return NULL;

	if (!(vhost = tfw_kzalloc(size, GFP_KERNEL))) {
		tfw_pool_destroy(pool);
		T_ERR_NL("Cannot allocate vhost entry '%s'\n", name);
		return NULL;
	}
	INIT_HLIST_NODE(&vhost->hlist);
	vhost->name.data = (char *)(vhost + 1);
	vhost->name.len = name_strlen;
	vhost->loc_dflt = (TfwLocation *)(vhost->name.data + name_mem_sz);
	vhost->loc = (TfwLocation *)(vhost->loc_dflt + 1);
	vhost->frang_gconf = (FrangGlobCfg *)(vhost->loc + TFW_LOCATION_ARRAY_SZ);
	vhost->cookie = (TfwStickyCookie *)(vhost->frang_gconf + 1);
	vhost->tls_cfg.priv = (vhost->cookie + 1);

	/* Must be sure all data fits, to prevent silent data corruption. */
	BUG_ON((char *)vhost->tls_cfg.priv + tfw_tls_vhost_priv_data_sz() !=
	       (char *)vhost + size);

	memcpy(vhost->name.data, name, name_strlen + 1);
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

	if (tfw_location_init(vhost->loc_dflt,
			      TFW_HTTP_MATCH_O_WILDCARD, "*", 1,
			      vhost->hdrs_pool))
	{
		T_ERR_NL("Unable to add default location for vhost '%s'.\n",
			 name);
		tfw_vhost_destroy(vhost);
		return NULL;
	}
	if (tfw_frang_cfg_inherit(vhost->loc_dflt->frang_cfg,
				  &tfw_frang_vhost_reconfig))
	{
		tfw_vhost_destroy(vhost);
		return NULL;
	}
	return vhost;
}

static inline void
tfw_vhost_add(TfwVhost *vhost)
{
	unsigned long key = basic_hash_str(&vhost->name);

	hash_add(tfw_vhosts_reconfig->vh_hash, &vhost->hlist, key);
	tfw_vhost_get(vhost);
	if (!tfw_vhost_is_default_reconfig(vhost)) {
		vhost->vhost_dflt = tfw_vhosts_reconfig->vhost_dflt;
		tfw_vhost_get(vhost->vhost_dflt);
	}
}

/**
 * Called on (re-)configuration time in process context.
 */
void
tfw_vhost_add_sni_map(const BasicStr *cn, TfwVhost *vhost)
{
	unsigned long key = basic_hash_str(cn);
	TfwSVHMap *svhm;
	int n = sizeof(*svhm) + cn->len;

	if (!(svhm = tfw_kmalloc(n, GFP_KERNEL))) {
		T_WARN("Cannot allocate mapping for SAN/CN %.*s -> %.*s\n",
		       (int)cn->len, cn->data,
		       (int)vhost->name.len, vhost->name.data);
		return;
	}

	svhm->vhost = vhost;
	INIT_HLIST_NODE(&svhm->hlist);
	svhm->sni_len = cn->len;
	memcpy(svhm->sni, cn->data, cn->len);

	hash_add(tfw_vhosts_reconfig->sni_vh_map, &svhm->hlist, key);
	tfw_vhost_get(vhost);
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
	{ "purge",	TFW_HTTP_METH_PURGE },
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

	TFW_CFG_CHECK_VAL_N(>, 0, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

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
	char *strs_pos;
	FrangCtVals *vals;
	FrangCtVal *vals_pos;
	size_t i, strs_size, vals_n, vals_size, alloc_sz;

	/* Allocate a single chunk of memory which is suitable to hold the
	 * variable-sized list of variable-sized strings. See FrangCtVals
	 * definition for details.
	 */
	vals_n = ce->val_n;
	vals_size = sizeof(FrangCtVal) * (vals_n + 1);
	strs_size = 0;
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, in_str) {
		strs_size += strlen(in_str) + 1;
	}
	alloc_sz = vals_size + strs_size + sizeof(FrangCtVals);
	mem = tfw_kzalloc(alloc_sz, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;
	vals = mem;
	vals->alloc_sz = alloc_sz;
	vals->vals = mem + sizeof(FrangCtVals);
	vals->data = mem + sizeof(FrangCtVals) + vals_size;

	/* Copy tokens to the new vals/strs list. */
	/* TODO: validate tokens, they should look like: "text/plain". */
	vals_pos = vals->vals;
	strs_pos = vals->data;
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, in_str) {
		size_t len = strlen(in_str) + 1;

		memcpy(strs_pos, in_str, len);
		vals_pos->str = strs_pos;
		vals_pos->len = (len - 1);

		T_DBG3("parsed Content-Type value: '%s'\n", in_str);

		vals_pos++;
		strs_pos += len;
	}
	BUG_ON(vals_pos != (vals->vals + vals_n));
	BUG_ON(strs_pos != (vals->data + strs_size));

	conf->http_ct_vals = vals;
	return 0;
}

static int
frang_parse_ushort(const char *s, unsigned short *out, const char *spec_name)
{
	int n;
	if (tfw_cfg_parse_int(s, &n)) {
		T_ERR_NL("frang: %s: "
			 "\"%s\" isn't a valid value\n", spec_name, s);
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
	int n, i;

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);
	if (ce->val_n < 3) {
		T_ERR_NL("frang: %s: too few arguments\n", cs->name);
		return -EINVAL;
	}

	cb = tfw_kzalloc(sizeof(FrangHttpRespCodeBlock), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;
	conf->http_resp_code_block = cb;

	i = ce->val_n - 2;
	while (--i >= 0) {
		if (tfw_cfg_parse_int(ce->vals[i], &n)
		    || !tfw_http_resp_code_range(n)) {
			T_ERR_NL("%s invalid HTTP code \"%s\"", cs->name,
				 ce->vals[i]);
			return -EINVAL;
		}
		/* Atomic restriction isn't needed here */
		__set_bit(HTTP_CODE_BIT_NUM(n), cb->codes);
	}

	if (frang_parse_ushort(ce->vals[ce->val_n - 2], &cb->limit, cs->name)
	    || frang_parse_ushort(ce->vals[ce->val_n - 1], &cb->tf, cs->name))
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

/**
 * Here we check whether the handler has already been called or not.
 * If it was, that means value already set and we must not
 * override it with default value.
 *
 * 'frang_limits' section may appear multiple times in config file
 * and the first time before it.
 * Each time, when frang_limits section apears in the config,
 * handlers will be called for all directives and if we skip checking
 * that they are already set, frang directives will be overriden with
 * default values.
 */
static inline bool
tfw_cfgop_is_dflt_val_already_set(TfwCfgSpec *cs)
{
        return cs->__called_cfg;
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
	if (ce->dflt_value && tfw_cfgop_is_dflt_val_already_set(cs))
		return 0;
	return tfw_cfg_set_bool(cs, ce);
}

static int
tfw_cfgop_frang_glob_set_int(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (ce->dflt_value && tfw_cfgop_is_dflt_val_already_set(cs))
		return 0;
	return tfw_cfg_set_int(cs, ce);
}

static int
tfw_cfgop_frang_glob_set_long(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (ce->dflt_value && tfw_cfgop_is_dflt_val_already_set(cs))
		return 0;
	return tfw_cfg_set_long(cs, ce);
}

static int
tfw_cfgop_frang_glob_http_methods(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	long int *dest_long = cs->dest;

	if (ce->dflt_value && tfw_cfgop_is_dflt_val_already_set(cs))
		return 0;
	return __tfw_cfgop_frang_http_methods(cs, ce, dest_long);
}

static int
tfw_cfgop_frang_hdr_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int secs;
	int r;

	if (ce->dflt_value && tfw_cfgop_is_dflt_val_already_set(cs))
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

	if (ce->dflt_value && tfw_cfgop_is_dflt_val_already_set(cs))
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
	/*
	 * There is unnecessary to check the value here because
	 * the default value was already set in tfw_frang_cfg_inherit().
	 */
	if (ce->dflt_value)
		return 0;
	cs->dest = &cfg->http_uri_len;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_body_len(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value)
		return 0;
	cs->dest = &cfg->http_body_len;
	r = tfw_cfg_set_long(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_strict_host_checking(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value)
		return 0;
	cs->dest = &cfg->http_strict_host_checking;
	r = tfw_cfg_set_bool(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_ct_required(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value)
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

	if (ce->dflt_value)
		return 0;
	cs->dest = &cfg->http_trailer_split;
	r = tfw_cfg_set_bool(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_method_override(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value)
		return 0;
	cs->dest = &cfg->http_method_override;
	r = tfw_cfg_set_bool(cs, ce);
	cs->dest = NULL;
	return r;
}

static int
tfw_cfgop_frang_http_methods(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (ce->dflt_value)
		return 0;
	return __tfw_cfgop_frang_http_methods(cs, ce, &cfg->http_methods_mask);
}

static int
tfw_cfgop_frang_http_ct_vals(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (cfg->http_ct_vals) {
		/*
		 * Here is no need to check
		 * tfw_cfgop_is_dflt_val_already_set()
		 * on the global frang, because if it is not NULL,
		 * it is already set.
		 */
		if (ce->dflt_value)
			return 0;
		kfree(cfg->http_ct_vals);
		cfg->http_ct_vals = NULL;
	}
	return __tfw_cfgop_frang_http_ct_vals(cs, ce, cfg);
}

static int
tfw_cfgop_frang_rsp_code_block(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	FrangVhostCfg *cfg = tfw_cfgop_frang_get_cfg();

	if (cfg->http_resp_code_block) {
		/*
		 * Here is no need to check
		 * tfw_cfgop_is_dflt_val_already_set()
		 * on the global frang, because if it is not NULL,
		 * it is already set.
		 */
		if (ce->dflt_value)
			return 0;
		kfree(cfg->http_resp_code_block);
		cfg->http_resp_code_block = NULL;
	}
	return __tfw_cfgop_frang_rsp_code_block(cs, ce, cfg);
}

static int
__tfw_cfgop_frang_rates(TfwCfgSpec *cs, TfwCfgEntry *ce, unsigned int *rate,
			unsigned short *tf)
{
	if (ce->dflt_value && tfw_cfgop_is_dflt_val_already_set(cs))
		return 0;

	TFW_CFG_CHECK_VAL_N(>=, 1, cs, ce);
	TFW_CFG_CHECK_VAL_N(<=, 2, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	if (tfw_cfg_parse_uint(ce->vals[0], rate)) {
		T_ERR_NL("%s: \"%s\" isn't a valid value\n", cs->name,
			 ce->vals[0]);
		return -EINVAL;
	}

	*tf = 1;
	if (ce->val_n == 2 && frang_parse_ushort(ce->vals[1], tf, cs->name))
		return -EINVAL;

	/*
	 * How many ticks in signle timeframe. Update the
	 * value to reduce calculations in hot-path.
	 */
	*tf = (*tf * HZ) / FRANG_FREQ;

	return 0;
}

static int
tfw_cfgop_frang_conn_rate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	FrangGlobCfg *cfg = &tfw_frang_glob_reconfig;

	return __tfw_cfgop_frang_rates(cs, ce, &cfg->conn_rate,
				       &cfg->conn_rate_tf);
}

static int
tfw_cfgop_frang_req_rate(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	FrangGlobCfg *cfg = &tfw_frang_glob_reconfig;

	return __tfw_cfgop_frang_rates(cs, ce, &cfg->req_rate,
				       &cfg->req_rate_tf);
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
tfw_cfgop_out_tls_tickets(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_vhosts_reconfig->expl_dflt) {
		if (ce->dflt_value)
			return 0;
		T_ERR_NL("%s: global tls_tickets are to be configured "
			 "outside of explicit '%s' vhost.\n",
			 cs->name, TFW_VH_DFT_NAME);
		return -EINVAL;
	}
	return tfw_tls_set_tickets(tfw_vhosts_reconfig->vhost_dflt, cs, ce);
}

static int
tfw_cfgop_in_tls_tickets(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_tls_set_tickets(tfw_vhost_entry, cs, ce);
}

static int
tfw_cfgop_tls_any_sni(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	bool val;
	int r;

	if (ce->dflt_value) {
		val = tfw_tls_get_allow_any_sni_reconfig();
	}
	else {
		cs->dest = &val;
		r = tfw_cfg_set_bool(cs, ce);
		cs->dest = NULL;
		if (r)
			return r;
	}
	tfw_tls_set_allow_any_sni(val);

	return 0;
}

static int
tfw_cfgop_in_tls_any_sni(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_vhosts_reconfig->expl_dflt) {
		if (ce->dflt_value)
			return 0;
		T_ERR_NL("%s: global tls_match_ani_server_name are to be "
			 "configured outside of explicit '%s' vhost.\n",
			 cs->name, TFW_VH_DFT_NAME);
		return -EINVAL;
	}

	return tfw_cfgop_tls_any_sni(cs, ce);
}

static int
tfw_cfgop_out_tls_any_sni(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
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
	tfw_vhosts_reconfig = tfw_kmalloc(sizeof(TfwVhostList), GFP_KERNEL);
	if (!tfw_vhosts_reconfig) {
		T_ERR_NL("Unable to allocate vhosts' list.\n");
		return -ENOMEM;
	}

	tfw_vhosts_reconfig->expl_dflt = false;
	hash_init(tfw_vhosts_reconfig->vh_hash);
	hash_init(tfw_vhosts_reconfig->sni_vh_map);
	tfw_frang_clean(&tfw_frang_vhost_reconfig);
	tfw_frang_global_clean(&tfw_frang_glob_reconfig);
	tfw_spec_init_frang_default(tfw_global_frang_specs);

	if(!(vh_dflt = tfw_vhost_new(TFW_VH_DFT_NAME))) {
		T_ERR_NL("Unable to create default vhost.\n");
		return -ENOMEM;
	}

	tfw_vhosts_reconfig->vhost_dflt = vh_dflt;

	tfw_vhost_entry = NULL;
	tfwcfg_this_location = NULL;

	tfw_http_sess_cfgstart();

	return 0;
}

static int
tfw_vhost_cfgend(void)
{
	TfwSrvGroup *sg_def;
	TfwVhost *vh_dflt;
	int r = 0;

	*tfw_vhosts_reconfig->vhost_dflt->frang_gconf = tfw_frang_glob_reconfig;
	/*
	 * Add default vhost into list if it hadn't been added yet explicitly
	 * to keep default location policies.
	 */
	if (tfw_vhosts_reconfig->expl_dflt)
		goto check_vhost;
	/*
	 * Implicit default vhost is still useful even if it's never used to
	 * forward the traffic. It stores fallback location providing
	 * default policies and options that can be used before incoming
	 * request is parsed and assigned to any location.
	 */
	vh_dflt = tfw_vhosts_reconfig->vhost_dflt;
	r = tfw_frang_cfg_inherit(vh_dflt->loc_dflt->frang_cfg,
				  &tfw_frang_vhost_reconfig);
	if (r)
		goto err;
	sg_def = tfw_sg_lookup_reconfig(TFW_VH_DFT_NAME, SLEN(TFW_VH_DFT_NAME));
	vh_dflt->loc_dflt->main_sg = sg_def;
	tfw_vhost_add(vh_dflt);
	if ((r = tfw_tls_cert_cfg_finish(vh_dflt)))
		goto err;
	if ((r = tfw_http_sess_cfg_finish(vh_dflt)))
		goto err;

check_vhost:
	if (tfw_global.cache_purge
	    && !tfw_cache_is_enabled_or_not_configured())
	{
		T_ERR_NL("Directives mismatching: 'cache_purge' directive "
			  "requires 'cache' be not none\n");
		r = -EINVAL;
		goto err;
	}

	if (tfw_global.cache_purge && !tfw_global.cache_purge_acl) {
		T_ERR_NL("Directives mismatching: 'cache_purge' directive "
			  "requires 'cache_purge_acl', but it wasn't "
			  "provided.\n");
		r = -EINVAL;
	} else if (tfw_global.cache_purge_acl && !tfw_global.cache_purge) {
		T_ERR_NL("Directives mismatching: 'cache_purge_acl' directive "
			  "requires 'cache_purge', but it wasn't "
			  "provided.\n");
		r = -EINVAL;
	}

err:
	tfw_frang_clean(&tfw_frang_vhost_reconfig);

#if DBG_VHOST > 0
	tfw_cfgop_vhosts_print(tfw_vhosts_reconfig);
#endif
	tfw_http_sess_cfgend();
	return r;
}

static int
tfw_cfgop_vhost_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwVhost *vhost;
	int i;

	BUG_ON(tfw_vhost_entry);

	TFW_CFG_CHECK_VAL_N(==, 1, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

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
	int r, i;

	BUG_ON(!tfw_vhost_entry);
	if (!tfw_vhost_entry->loc_dflt->main_sg) {
		BUG_ON(tfw_vhost_is_default_reconfig(tfw_vhost_entry));
		T_ERR_NL("Directive 'proxy_pass' is not specified"
			 " for not default vhost '%s'.\n",
			 tfw_vhost_entry->name.data);
		return -EINVAL;
	}

	for (i = 0; i < tfw_vhost_entry->loc_sz; i++)
		tfw_mod_hdr_sort(tfw_vhost_entry->loc + i);

	tfw_mod_hdr_sort(tfw_vhost_entry->loc_dflt);

	if ((r = tfw_tls_cert_cfg_finish(tfw_vhost_entry)))
		return r;
	if ((r = tfw_http_sess_cfg_finish(tfw_vhost_entry)))
		return r;
	tfw_vhost_entry = NULL;
	return 0;
}

static void
tfw_cfgop_vhosts_list_free(TfwVhostList *vhosts)
{
	TfwVhost *vhost;
	TfwSVHMap *svhm;
	struct hlist_node *tmp;
	int i;
	if (!vhosts)
		return;

	hash_for_each_safe(vhosts->vh_hash, i, tmp, vhost, hlist) {
		hash_del(&vhost->hlist);
		set_bit(TFW_VHOST_B_REMOVED, &vhost->flags);
		tfw_vhost_put(vhost);
		tfw_srv_loop_sched_rcu();
	}

	hash_for_each_safe(vhosts->sni_vh_map, i, tmp, svhm, hlist) {
		hash_del(&svhm->hlist);
		tfw_vhost_put(svhm->vhost);
		kfree(svhm);
		tfw_srv_loop_sched_rcu();
	}

	if (vhosts->vhost_dflt) {
		set_bit(TFW_VHOST_B_REMOVED, &vhosts->vhost_dflt->flags);
		tfw_vhost_put(vhosts->vhost_dflt);
	}

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

#if DBG_VHOST > 0
static void
tfw_print_frang_stripped(const char *tab, const FrangVhostCfg *frang)
{
	int i;

	if (!frang)
		return;

	T_LOG_NL("%s   http_methods_mask %lu;\n",
		 tab, frang->http_methods_mask);
	T_LOG_NL("%s   http_body_len %lu;\n",
		 tab, frang->http_body_len);
	T_LOG_NL("%s   http_uri_len %i;\n", tab,
		 frang->http_uri_len);
	if (!frang->http_ct_vals) {
		T_LOG_NL("%s   http_ct_vals=NULL;\n", tab);
	}
	else {
		T_LOG_NL("%s   http_ct_vals=%s;\n", tab,
			 frang->http_ct_vals->data);
	}

	if (!frang->http_resp_code_block) {
		T_LOG_NL("%s   FrangHttpRespCodeBlock: Empty;\n", tab);
	}
	else {
		T_LOG_NL("%s   FrangHttpRespCodeBlock:\n", tab);
		for (i = 0; i < 512; ++i) {
			if (test_bit(HTTP_CODE_BIT_NUM(i),
				     frang->http_resp_code_block->codes))
				T_LOG_NL("%s   %i\n", tab, i);
		}
	}

	T_LOG_NL("%s   http_ct_required %s;\n", tab,
		 frang->http_ct_required ? "true" : "false");
	T_LOG_NL("%s   http_strict_host_checking %s;\n", tab,
		 frang->http_strict_host_checking ? "true" : "false");
	T_LOG_NL("%s   http_trailer_split_allowed %s;\n", tab,
		 frang->http_trailer_split ? "true" : "false");
	T_LOG_NL("%s   http_method_override_allowed %s;\n", tab,
		 frang->http_method_override ? "true" : "false");

}

static void
tfw_print_frang(const char *tab, const FrangVhostCfg *frang)
{
	if (!frang)
		return;

	T_LOG_NL("%sfrang_limits {\n", tab);
	tfw_print_frang_stripped(tab, frang);
	T_LOG_NL("%s}\n", tab);
}

static void
tfw_cfgop_location_print(TfwLocation *loc)
{
        int i;
         TfwHdrMods *h_mods = &loc->mod_hdrs[TFW_VHOST_HDRMOD_RESP];

        if (!loc->arg)
                return;

        T_LOG_NL("   location  %s {", loc->arg);
        tfw_print_frang("      ", loc->frang_cfg);

        for (i = 0; i < loc->capo_sz; ++i) {
                TfwCaPolicy *capo = loc->capo[i];

                switch (capo->cmd) {
                case TFW_D_CACHE_BYPASS:
                        T_LOG_NL("      cache_bypass %s\n",
                                 capo->arg);
                        break;
                case TFW_D_CACHE_FULFILL:
                        T_LOG_NL("      cache_fulfill %s\n",
                                 capo->arg);
                        break;
                case TFW_D_CACHE_RESP_HDR_DEL:
                        T_LOG_NL("      cache_resp_hdr_del %s\n",
                                 capo->arg);
                        break;
                case TFW_D_CACHE_CONTROL_IGNORE:
                        T_LOG_NL("      cache_control_ignore %s\n",
                                 capo->arg);
                        break;
                }

        }

        for (i = 0; i < loc->nipdef_sz; ++i) {
                TfwNipDef *nipdef= loc->nipdef[i];
                T_LOG_NL("      %s\n", nipdef->arg);
        }

        if (h_mods) {
                for (i = 0; i < h_mods->sz; ++i) {
                        TfwHdrModsDesc *d = &h_mods->hdrs[i];
                        T_LOG_NL("      %s  %i  %i\n", d->hdr->data,
                                d->hdr->nchunks, (int)d->hdr->len);
                }
        }
        T_LOG_NL("   }");
}

static void
tfw_cfgop_frang_global_print(void)
{
	T_LOG_NL("frang_limits {\n");
	T_LOG_NL("   client_header_timeout %lu;\n",
		 tfw_frang_glob_reconfig.clnt_hdr_timeout);
	T_LOG_NL("   client_body_timeout %lu;\n",
		 tfw_frang_glob_reconfig.clnt_body_timeout);
	T_LOG_NL("   request_rate %u;\n", tfw_frang_glob_reconfig.req_rate);
	T_LOG_NL("   request_burst %u;\n", tfw_frang_glob_reconfig.req_burst);
	T_LOG_NL("   tcp_connection_rate %u;\n",
	         tfw_frang_glob_reconfig.conn_rate);
	T_LOG_NL("   tcp_connection_burst %u;\n",
		 tfw_frang_glob_reconfig.conn_burst);
	T_LOG_NL("   concurrent_tcp_connections %u;\n",
	         tfw_frang_glob_reconfig.conn_max);
	T_LOG_NL("   tls_connection_rate %u;\n",
		 tfw_frang_glob_reconfig.tls_new_conn_rate);
	T_LOG_NL("   tls_connection_burst %u;\n",
		 tfw_frang_glob_reconfig.tls_new_conn_burst);
	T_LOG_NL("   tls_incomplete_connection_rate %u;\n",
		 tfw_frang_glob_reconfig.tls_incomplete_conn_rate);
	T_LOG_NL("   http_header_chunk_cnt %u;\n",
		 tfw_frang_glob_reconfig.http_hchunk_cnt);
	T_LOG_NL("   http_body_chunk_cnt %u;\n",
		 tfw_frang_glob_reconfig.http_bchunk_cnt);
	T_LOG_NL("   http_hdr_len %u;\n",
		 tfw_frang_glob_reconfig.http_hdr_len);
	T_LOG_NL("   http_header_cnt %u;\n",
		 tfw_frang_glob_reconfig.http_hdr_cnt);
	T_LOG_NL("   ip_block %s;\n\n",
		 tfw_frang_glob_reconfig.ip_block ? "true" : "false");
	tfw_print_frang_stripped("", &tfw_frang_vhost_reconfig);
	T_LOG_NL("}\n");
}

static void
tfw_cfgop_vhosts_print(TfwVhostList *vhosts)
{
	TfwVhost *vhost;
	char str[128];
	int i, j;
	int len;

	T_LOG_NL("Actual configuration.\n");
	if (!vhosts)
		return;

	memset(str, 0, sizeof(str));
	tfw_cfgop_frang_global_print();

	T_LOG_NL("tls_match_any_server_name=%s\n",
		 tfw_tls_get_allow_any_sni_reconfig() ? "true" : "false");
	hash_for_each(vhosts->vh_hash, i, vhost, hlist) {
                len = vhost->name.len < 128 ? vhost->name.len : 127;
                memcpy(str, vhost->name.data, len);
                str[len] = 0;
                T_LOG_NL("vhost %s {", str);
                tfw_cfgop_location_print(vhost->loc_dflt);
                for (j = 0; j < vhost->loc_sz; ++j)
                      tfw_cfgop_location_print(&vhost->loc[j]);

                T_LOG_NL("}");
        }
}
#endif
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
		.handler = tfw_cfgop_frang_req_rate,
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
		.name = "tcp_connection_rate",
		.deflt = "0",
		.handler = tfw_cfgop_frang_conn_rate,
		.allow_reconfig = true,
	},
	{
		.name = "tcp_connection_burst",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.conn_burst,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "concurrent_tcp_connections",
		.deflt = "1000",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.conn_max,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "tls_connection_rate",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.tls_new_conn_rate,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "tls_connection_burst",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.tls_new_conn_burst,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "tls_incomplete_connection_rate",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.tls_incomplete_conn_rate,
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
	{
		.name = "http_hdr_len",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.http_hdr_len,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	{
		.name = "http_header_cnt",
		.deflt = "50",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_glob_reconfig.http_hdr_cnt,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_reconfig = true,
	},
	/* Option can be redefined per vhost|location.
	 *
	 * All handler are changed to tfw_cfgop_frang_glob_...
	 * because here we need to know whether the values
	 * have already been set or not.
	 */
	{
		.name = "http_uri_len",
		.deflt = "0",
		.handler = tfw_cfgop_frang_glob_set_int,
		.dest = &tfw_frang_vhost_reconfig.http_uri_len,
		.allow_reconfig = true,
	},
	{
		.name = "http_body_len",
		.deflt = "1073741824", /* 1 Gb. */
		.handler = tfw_cfgop_frang_glob_set_long,
		.dest = &tfw_frang_vhost_reconfig.http_body_len,
		.allow_reconfig = true,
	},
	{
		.name = "http_strict_host_checking",
		.deflt = "true",
		.handler = tfw_cfgop_frang_glob_set_bool,
		.dest = &tfw_frang_vhost_reconfig.http_strict_host_checking,
		.allow_reconfig = true,
	},
	{
		.name = "http_ct_required",
		.deflt = "false",
		.handler = tfw_cfgop_frang_glob_set_bool,
		.dest = &tfw_frang_vhost_reconfig.http_ct_required,
		.allow_reconfig = true,
	},
	{
		.name = "http_trailer_split_allowed",
		.deflt = "false",
		.handler = tfw_cfgop_frang_glob_set_bool,
		.dest = &tfw_frang_vhost_reconfig.http_trailer_split,
		.allow_reconfig = true,
	},
	{
		.name = "http_method_override_allowed",
		.deflt = "false",
		.handler = tfw_cfgop_frang_glob_set_bool,
		.dest = &tfw_frang_vhost_reconfig.http_method_override,
		.allow_reconfig = true,
	},
	/*http_methods should contain at least one method by default.*/
	{
		.name = "http_methods",
		.deflt = "get post head",
		.handler = tfw_cfgop_frang_glob_http_methods,
		.dest = &tfw_frang_vhost_reconfig.http_methods_mask,
		.allow_reconfig = true,
	},
	{
		.name = "http_ct_vals",
		.deflt = NULL,
		.handler = tfw_cfgop_frang_http_ct_vals,
		.dest = &tfw_frang_vhost_reconfig.http_ct_vals,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{
		.name = "http_resp_code_block",
		.deflt = NULL,
		.handler = tfw_cfgop_frang_rsp_code_block,
		.dest = &tfw_frang_vhost_reconfig.http_resp_code_block,
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
		.name = "tcp_connection_rate",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "tcp_connection_burst",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "concurrent_tcp_connections",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "tls_connection_rate",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "tls_connection_burst",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "tls_incomplete_connection_rate",
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
	{
		.name = "http_hdr_len",
		.handler = tfw_cfgop_frang_glob_in_vhost,
		.allow_reconfig = true,
		.allow_none = true,
	},
	{
		.name = "http_header_cnt",
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
		.name = "http_body_len",
		.deflt = "1073741824", /* 1 Gb. */
		.handler = tfw_cfgop_frang_body_len,
		.allow_reconfig = true,
	},
	{
		.name = "http_strict_host_checking",
		.deflt = "true",
		.handler = tfw_cfgop_frang_strict_host_checking,
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
		.name = "http_method_override_allowed",
		.deflt = "false",
		.handler = tfw_cfgop_frang_method_override,
		.allow_reconfig = true,
	},
	/*http_methods should contain at least one method by default.*/
	{
		.name = "http_methods",
		.deflt = "get post head",
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
		.name = "cache_resp_hdr_del",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_cache_resp_hdr_del,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_control_ignore",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_cache_control_ignore,
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
		.allow_none = false,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "cache_use_stale",
		.deflt = NULL,
		.handler = tfw_cfgop_loc_cache_use_stale,
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
		.name = "cache_resp_hdr_del",
		.deflt = NULL,
		.handler = tfw_cfgop_in_cache_resp_hdr_del,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_control_ignore",
		.deflt = NULL,
		.handler = tfw_cfgop_in_cache_control_ignore,
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
		.name = "tls_tickets",
		.deflt = "",
		.handler = tfw_cfgop_in_tls_tickets,
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
		.name = "sticky",
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_http_sess_cfgop_cleanup,
		.dest = tfw_http_sess_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tfw_cfgop_in_sticky_begin,
			.finish_hook = tfw_cfgop_in_sticky_finish
		},
		.allow_reconfig = true,
		.allow_none = true,
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
		.allow_none = false,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_use_stale",
		.deflt = NULL,
		.handler = tfw_cfgop_in_cache_use_stale,
		.allow_none = true,
		.allow_repeat = false,
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
		.name = "cache_resp_hdr_del",
		.deflt = NULL,
		.handler = tfw_cfgop_out_cache_resp_hdr_del,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_control_ignore",
		.deflt = NULL,
		.handler = tfw_cfgop_out_cache_control_ignore,
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
		.name = "tls_tickets",
		.deflt = "",
		.handler = tfw_cfgop_out_tls_tickets,
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
		.name = "sticky",
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_http_sess_cfgop_cleanup,
		.dest = tfw_http_sess_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tfw_cfgop_out_sticky_begin,
			.finish_hook = tfw_cfgop_out_sticky_finish
		},
		.allow_reconfig = true,
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
		.allow_none = false,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "cache_use_stale",
		.deflt = NULL,
		.handler = tfw_cfgop_out_cache_use_stale,
		.allow_none = true,
		.allow_repeat = false,
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
