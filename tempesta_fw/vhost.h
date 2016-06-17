/**
 *		Tempesta FW
 *
 * Copyright (C) 2016 Tempesta Technologies, Inc.
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

/* Cache policy configuration directives. */
typedef enum {
	TFW_D_CACHE_BYPASS,
	TFW_D_CACHE_FULFILL,
} tfw_capo_t;

/*
 * Cache Policy.
 *
 * @cmd	- One of defined in tfw_capo_t.
 * @op	- Match operator: eq, prefix, suffix, etc.
 * @len	- Length of the sting in @arg.
 * @arg	- String for the match operator.
 */
typedef struct {
	short		cmd;
	short		op;
	unsigned int	len;
	const char	*arg;
} TfwCaPolicy;

/*
 * Group of policies by specific location.
 *
 * @op		- Match operator: eq, prefix, suffix, etc.
 * @arg		- String for the match operator.
 * @len		- Length of the sting in @arg.
 * @capo_sz	- Size of @capo array.
 * @capo	- Array of pointers to Cache Policy definitions.
 */
typedef struct {
	short		op;
	const char	*arg;
	unsigned int	len;
	unsigned int	capo_sz;
	TfwCaPolicy	**capo;
} TfwLocation;

/* Cache purge configuration modes. */
enum {
	TFW_D_CACHE_PURGE_INVALIDATE,
	TFW_D_CACHE_PURGE_DELETE,
};

/*
 * Virtual host defined by directives and policies.
 * @loc		- Array of groups of policies by specific location.
 * @loc_dflt	- Group of default policies.
 * @loc_sz	- Size of @loc array.
 * @loc_dflt_sz	- Size of @loc_dflt.
 */
typedef struct {
	TfwLocation	*loc;
	TfwLocation	*loc_dflt;
	TfwAddr		*capuacl;
	const char	*hdr_via;
	unsigned int	loc_sz;
	unsigned int	loc_dflt_sz;
	unsigned int	capuacl_sz;
	unsigned int	hdr_via_len;
	u8		cache_purge:1;
	u8		cache_purge_mode:2;
	u8		cache_purge_acl:1;
} TfwVhost;

bool tfw_capuacl_match(TfwVhost *vhost, TfwAddr *addr);
TfwCaPolicy *tfw_capolicy_match(TfwLocation *loc, TfwStr *arg);
TfwLocation *tfw_location_match(TfwVhost *vhost, TfwStr *arg);
TfwVhost *tfw_vhost_match(TfwStr *arg);
TfwVhost *tfw_vhost_get_default(void);

#endif /* __TFW_VHOST_H__ */
