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
#ifndef __TFW_VHOST_H__
#define __TFW_VHOST_H__

#include "str.h"
#include "addr.h"
#include "msg.h"
#include "server.h"
#include "tls.h"

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
 * Headers modification description.
 *
 * @hdr		- Header string, see @tfw_http_msg_hdr_xfrm_str();
 * @add_hdrs	- Headers to modify;
 */
typedef struct {
	TfwStr		*hdr;
	unsigned int	hid;
	bool		append;
} TfwHdrModsDesc;

/**
 * Headers modification before forwarding HTTP message.
 *
 * @sz		- Number of headers to modify;
 * @hdrs	- Headers to modify;
 */
typedef struct {
	size_t		sz;
	TfwHdrModsDesc	*hdrs;
} TfwHdrMods;

enum {
	TFW_VHOST_HDRMOD_REQ,
	TFW_VHOST_HDRMOD_RESP,

	TFW_VHOST_HDRMOD_NUM
};

/**
 * Group of policies by specific location.
 *
 * @op		- Match operator: eq, prefix, suffix, etc.
 * @arg		- String for the match operator.
 * @len		- Length of the string in @arg.
 * @capo_sz	- Size of @capo array.
 * @nipdef_sz	- Size of @nipdef array.
 * @capo	- Array of pointers to Cache Policy definitions.
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
	TfwNipDef		**nipdef;
	FrangVhostCfg		*frang_cfg;
	TfwSrvGroup		*main_sg;
	TfwSrvGroup		*backup_sg;
	TfwPool			*hdrs_pool;
	TfwHdrMods		mod_hdrs[TFW_VHOST_HDRMOD_NUM];
	unsigned int		validate_post_req:1;
} TfwLocation;

/* Cache purge configuration modes. */
enum {
	TFW_D_CACHE_PURGE_INVALIDATE,
};

enum {
	/* Vhost was removed during reconfiguration. */
	TFW_VHOST_B_REMOVED = 0,
};

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
 * @refcnt	- Number of users of the virtual host object.
 * @loc_sz	- Count of elements in @loc array.
 * @flags	- flags.
 * @tls_cfg	- TLS per-vhost configuration data used in data processing.
 */
struct  tfw_vhost_t {
	struct hlist_node	hlist;
	TfwStr			name;
	TfwLocation		*loc;
	TfwLocation		*loc_dflt;
	TfwVhost		*vhost_dflt;
	TfwPool			*hdrs_pool;
	FrangGlobCfg		*frang_gconf;
	atomic64_t		refcnt;
	size_t			loc_sz;
	unsigned long		flags;
	TlsPeerCfg		tls_cfg;
};

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

void tfw_vhost_destroy(TfwVhost *vhost);

static inline void
tfw_vhost_get(TfwVhost *vhost)
{
	atomic64_inc(&vhost->refcnt);
}

static inline void
tfw_vhost_put(TfwVhost *vhost)
{
	if (unlikely(!vhost))
		return;
	if (likely(atomic64_dec_return(&vhost->refcnt)))
		return;
	tfw_vhost_destroy(vhost);
}

TfwNipDef *tfw_nipdef_match(TfwLocation *loc, unsigned char meth, TfwStr *arg);
bool tfw_capuacl_match(TfwAddr *addr);
TfwCaPolicy *tfw_capolicy_match(TfwLocation *loc, TfwStr *arg);
TfwLocation *tfw_location_match(TfwVhost *vhost, TfwStr *arg);
TfwVhost *tfw_vhost_lookup_reconfig(const char *name);
TfwVhost *tfw_vhost_lookup(const TfwStr *name);
TfwVhost *tfw_vhost_lookup_default(void);
bool tfw_vhost_is_default_reconfig(TfwVhost *vhost);
TfwSrvConn *tfw_vhost_get_srv_conn(TfwMsg *msg);
TfwVhost *tfw_vhost_new(const char *name);
TfwGlobal *tfw_vhost_get_global(void);
TfwHdrMods *tfw_vhost_get_hdr_mods(TfwLocation *loc, TfwVhost *vhost,
				   int mod_type);

static inline TfwVhost*
tfw_vhost_from_tls_conf(const TlsPeerCfg *cfg)
{
	return  container_of(cfg, TfwVhost, tls_cfg);
}

#endif /* __TFW_VHOST_H__ */
