/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2026 Tempesta Technologies, Inc.
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
#ifndef __TFW_VHOST_H__
#define __TFW_VHOST_H__

#include "str.h"
#include "addr.h"
#include "msg.h"
#include "server.h"
#include "tls.h"

/* Size of special headers bitmap. */
#define TFW_MOD_SPEC_HDR_NUM 32

/**
 * Non-Idempotent Request definition.
 *
 * @method	- One bit for each value defined in tfw_http_meth_t.
 * @op		- Match operator: eq, prefix, suffix, etc.
 * @len		- Length of the string in @arg.
 * @arg		- String for the match operator.
 */
typedef struct {
	int		method;
	short		op;
	size_t		len;
	const char	*arg;
} TfwNipDef;

/* Cache policy configuration directives. */
typedef enum {
	TFW_D_CACHE_BYPASS,
	TFW_D_CACHE_FULFILL,
	TFW_D_CACHE_RESP_HDR_DEL,
	TFW_D_CACHE_CONTROL_IGNORE
} tfw_capo_t;

/**
 * Cache Policy.
 *
 * @cmd	- One of defined in tfw_capo_t.
 * @op	- Match operator: eq, prefix, suffix, etc.
 * @len	- Length of the string in @arg.
 * @arg	- String for the match operator.
 */
typedef struct {
	short		cmd;
	short		op;
	size_t		len;
	const char	*arg;
} TfwCaPolicy;

/**
 * Just a simple string.
 *
 * @len	- Length of the string in @str (with null-terminator).
 * @str	- First character of the string.
 */
typedef struct {
	size_t		len;
	DECLARE_FLEX_ARRAY(char, str);
} TfwCaToken;

/* tfw_vhost_get_capo_hdr_del result */
typedef struct {
	unsigned int	sz;
	TfwCaToken	*tokens;
} TfwCaTokenArray;

/**
 * Headers modification description.
 *
 * @hdr		- Header string, see @tfw_http_msg_make_hdr();
 * @hid		- Header index in the header table;
 * @append	- if set the value is added to the end of the response
 *		  otherwise the original header is overwritten with given one.
 */
struct tfw_hdr_mods_desc_t {
	TfwStr		*hdr;
	unsigned int	hid;
	bool		append;
};

/*
 * Layout of headers list in tfw_hdr_mods_t::hdrs. It allows to iterate over
 * "Non-indexed raw headers *hdr_set". See @tfw_http_hdr_skip().
 *
 *     .----------------------------------------.
 *     | Special headers *hdr_set               |
 *     :----------------------------------------:
 *     | Hpack indexed raw headers *hdr_set     |
 *     :----------------------------------------:
 *     | Non-indexed raw headers *hdr_set       |
 *     :----------------------------------------:
 *     | All headers *hdr_add                   |
 *     '----------------------------------------'
 *
 */

/**
 *
 * Headers modification before forwarding HTTP message.
 *
 * @sz		- Total number of headers to modify;
 * @set_num	- Number of headers to modify using req/resp_hdr_set directive;
 * @scan_off	- Offset in @hdrs to start finding header to modify by name
 * 		  comparision;
 * @host_off	- Offset of the Host header in @hdrs.
 * @hdrs	- Headers to modify;
 * @spec_hdrs	- Bitmap of special headers;
 * @s_tbl	- Bitmap of headers from static table. Static table index
 * 		  equals to bit number of the bitmap. The size of the bitmap is
 * 		  HPACK_STATIC_ENTRIES plus one entry, because static table
 * 		  indexed from one, zero bit always set to zero;
 */
struct tfw_hdr_mods_t {
	unsigned int	sz:8;
	unsigned int	set_num:8;
	unsigned int	scan_off:8;
	unsigned int	host_off:8;
	TfwHdrModsDesc	*hdrs;
	DECLARE_BITMAP	(spec_hdrs, TFW_MOD_SPEC_HDR_NUM);
	DECLARE_BITMAP	(s_tbl, HPACK_STATIC_ENTRIES + 1);
};

enum {
	TFW_VHOST_HDRMOD_REQ,
	TFW_VHOST_HDRMOD_RESP,

	TFW_VHOST_HDRMOD_NUM
};

/**
 * cache_use_stale code block setting
 *
 * @codes	- Response codes for which use of stale cached response is
 * 		- permitted;
 * @on_error	- Whether or not stale cached response to be used when request
 * 		  unable to be forwarded to backend.(e.g no alive servers);
 * @on_timeout	- Whether or not stale cached response to be used when request
 * 		  is timedout during forwarding to backend;
 */
typedef struct {
	DECLARE_BITMAP(codes, 512);
	bool		on_error;
	bool		on_timeout;
} TfwCacheUseStale;

/**
 * Group of policies by specific location.
 *
 * @op		- Match operator: eq, prefix, suffix, etc.
 * @arg		- Null-terminated string for the match operator.
 * @len		- Length of the string in @arg. Not include null character.
 * @capo_sz	- Size of @capo array.
 * @nipdef_sz	- Size of @nipdef array.
 * @capo	- Array of pointers to Cache Policy definitions.
 * @capo_hdr_del - Flat array of cache_resp_hdr_del header names.
 * @capo_hdr_del_sz - Number of headers in the @capo_hdr_del.
 * @cc_ignore   - Mask for flags corresponding to cache_control_ignore headers.
 * @nipdef	- Array of pointers to Non-Idempotent Request definitions.
 * @frang_cfg	- Pointer to location-specific Frang settings structure.
 * @main_sg	- Main server group to which requests must be proxied.
 * @backup_sg	- Backup server group.
 * @hdrs_pool	- Pointer to parent vhost's pool (for mod. headers allocation).
 * @mod_hdrs	- Modification of request/response headers before forwarding.
 */
typedef struct {
	short			op;
	const char		*arg;
	size_t			len;
	size_t			capo_sz;
	size_t			nipdef_sz;
	TfwCaPolicy		**capo;
	TfwCaToken		*capo_hdr_del;
	unsigned int		capo_hdr_del_sz;
	unsigned int		cc_ignore;
	TfwNipDef		**nipdef;
	FrangVhostCfg		*frang_cfg;
	TfwSrvGroup		*main_sg;
	TfwSrvGroup		*backup_sg;
	TfwPool			*hdrs_pool;
	TfwCacheUseStale	*cache_use_stale;
	TfwHdrMods		mod_hdrs[TFW_VHOST_HDRMOD_NUM];
	unsigned int		validate_post_req:1;
} TfwLocation;

/* Cache purge configuration modes. */
enum {
	TFW_D_CACHE_PURGE_INVALIDATE,
	TFW_D_CACHE_PURGE_IMMEDIATE
};

enum {
	/* Vhost was removed during reconfiguration. */
	TFW_VHOST_B_REMOVED = 0,
	/* Sticky sessions are enabled for vhost. */
	TFW_VHOST_B_STICKY_SESS,
	/*
	 * Re-pin existing sticky session to a new server if the old one was
	 * removed.
	 */
	TFW_VHOST_B_STICKY_SESS_FAILOVER,
};

/* Max number of headers allowed for end user to modify. */
#define TFW_USRHDRS_ARRAY_SZ	64

/**
 * Virtual host defined by directives and policies.
 *
 * @list	- Entry in list of all configured virtual hosts.
 * @name	- Name of virtual host. Contains zero terminator in the end,
 *		  which is not counted by 'len' member.
 * @loc		- Array of groups of policies by specific location.
 * @loc_dflt	- Default policy.
 * @vhost_dflt	- Pointer to default virtual host with global policies.
 * @hdrs_pool	- Modification headers allocation pool for vhost's policies.
 * @frang_gconf	- Global frang configuration. Applicable only for 'default'
 *		  vhost and NULL for others. Provides frang configuration
 *		  options used before request is parsed and assigned to any
 *		  vhost.
 * @cookie	- Sticky cookie configuration.
 * @refcnt	- Number of users of the virtual host object.
 * @loc_sz	- Count of elements in @loc array.
 * @flags	- flags.
 * @tls_cfg	- TLS per-vhost configuration data used in data processing.
 */
struct  tfw_vhost_t {
	struct hlist_node	hlist;
	BasicStr		name;
	TfwLocation		*loc;
	TfwLocation		*loc_dflt;
	TfwVhost		*vhost_dflt;
	TfwPool			*hdrs_pool;
	FrangGlobCfg		*frang_gconf;
	TfwStickyCookie		*cookie;
	atomic64_t		refcnt;
	size_t			loc_sz;
	unsigned long		flags;
	TlsPeerCfg		tls_cfg;
};

/* Default vhost is simply a full wildcard, matching any name. */
#define TFW_VH_DFT_NAME		"default"

/**
 * Global settings (exist only on top level and are not reconfigurable).
 *
 * @hdr_via		- 'Via' header value for HTTP messages.
 * @capuacl		- Array of addresses permitted for purge configuration.
 * @hdr_via_len		- Length of 'Via' header value.
 * @capuacl_sz		- Count of elements in @capuacl array.
 * @cache_purge		- Enable/disable cache purge configuration.
 * @cache_purge_mode	- Cache purge configuration mode.
 * @cache_purge_acl	- Enable/disable ACL for cache purge configuration.
 */
typedef struct {
	const char		*hdr_via;
	TfwAddr			*capuacl;
	size_t			hdr_via_len;
	size_t			capuacl_sz;
	u8			cache_purge:1;
	u8			cache_purge_mode:2;
	u8			cache_purge_acl:1;
} TfwGlobal;

int tfw_vhost_init(void);
void tfw_vhost_exit(void);

void tfw_vhost_destroy(TfwVhost *vhost);

static inline void
tfw_vhost_get(TfwVhost *vhost)
{
	atomic64_inc(&vhost->refcnt);
}

static inline void
tfw_vhost_put(TfwVhost *vhost)
{
	s64 refcnt;

	if (unlikely(!vhost))
		return;

	refcnt = atomic64_dec_return(&vhost->refcnt);
	BUG_ON(refcnt < 0);

	if (likely(refcnt))
		return;
	tfw_vhost_destroy(vhost);
}

static inline TfwVhost*
tfw_vhost_from_tls_conf(const TlsPeerCfg *cfg)
{
	return container_of(cfg, TfwVhost, tls_cfg);
}

static inline bool
tfw_vhost_is_default(TfwVhost *vhost)
{
	return !vhost->vhost_dflt;
}

TfwNipDef *tfw_nipdef_match(TfwLocation *loc, unsigned char meth, TfwStr *arg);
bool tfw_capuacl_match(TfwAddr *addr);
TfwCaPolicy *tfw_capolicy_match(TfwLocation *loc, TfwStr *arg);
TfwLocation *tfw_location_match(TfwVhost *vhost, TfwStr *arg);

TfwVhost *tfw_vhost_new(const char *name);
void tfw_vhost_add_sni_map(const BasicStr *cn, TfwVhost *vhost);

TfwVhost *tfw_vhost_lookup_reconfig(const char *name);
TfwVhost *tfw_vhost_lookup_sni(const BasicStr *name);
TfwVhost *tfw_vhost_lookup_default(void);

bool tfw_vhost_is_default_reconfig(TfwVhost *vhost);
TfwSrvConn *tfw_vhost_get_srv_conn(TfwMsg *msg);
TfwGlobal *tfw_vhost_get_global(void);
TfwHdrMods *tfw_vhost_get_hdr_mods(TfwLocation *loc, TfwVhost *vhost,
				   int mod_type);
TfwCaTokenArray tfw_vhost_get_capo_hdr_del(TfwLocation *loc,
					   TfwVhost *vhost);
unsigned int tfw_vhost_get_cc_ignore(TfwLocation *loc,
				     TfwVhost *vhost);
TfwCacheUseStale *tfw_vhost_get_cache_use_stale(TfwLocation *loc,
						TfwVhost *vhost);

#endif /* __TFW_VHOST_H__ */
