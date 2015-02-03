/**
 *		Tempesta FW
 *
 * Tempesta HTTP scheduler (load-balancing module).
 *
 * The goal of this module is to implement a load balancing scheme based on
 * HTTP message contents, that is, to provide user a way to route HTTP requests
 * to different back-end servers depending on HTTP request fields: Host, URI,
 * headers, etc.
 *
 * For example, you have a hardware setup that consists of:
 *   - a web application server for a site, say "site1.example.com";
 *   - another web application for another domain, say "site2.example2.com";
 *   - a bunch of storage servers, they can't generate dynamic contents, but
 *     good at handling large amounts of static files: images, videos, etc.
 * ...and you want to use Tempesta FW to route requests between them, so this
 * scheduler module allows you to reach that.
 *
 * We utilize rule-based HTTP matching logic from http_match.c here.
 * User defines a list of pattern-matching rules in a configuration file, and we
 * match every request against all rules, and the first matching rule determines
 * a back-end server to which the request is sent.
 *
 * The configuration section for the example above looks like:
 *   sched_http {
 *       backend_group webapp_site1 {
 *           backend 10.0.17.1:8081;
 *       }
 *       backend_group webapp_site2 {
 *           backend 10.0.17.2:8082;
 *       }
 *       backend_group storage_servers {
 *           backend 10.0.18.1;
 *           backend 10.0.18.2;
 *           backend 10.0.18.3;
 *       }
 *       rule storage_servers uri prefix "static.example.com";
 *       rule webapp_site1 host eq "site1.example.com";
 *       rule webapp_site2 host eq "site2.example.com";
 *   }
 *
 * In this module, we parse such configuration and build a TfwHttpMatchList
 * from these rules. Then, we compare every incoming HTTP request against all
 * rules in the list. If we find a matching one, we pick a corresponding backend
 * server. If there is no matching rule, then we return error (and the request
 * is eventually dropped, although that should be done by filtering logic).
 *
 * Rules are processed in the order they are specified in the configuration
 * file. If there is a very generic rule in the top of the list, like this:
 *     match foo uri prefix "/";
 * Then it always will be chosen, and other rules will never be reached.
 *
 * The code below contains three main entities:
 *   - The TfwHttpMatchList and helper functions for building the list.
 *     Things are complicated by the fact that servers may go down and up in
 *     runtime. Configuration may also be changed in runtime. So we have to
 *     store a list of rules and a list of servers and re-build the
 *     TfwHttpMatchList when either one changes.
 *   - TfwScheduler implementation: add_srv()/del_srv()/get_srv() methods.
 *   - Configuration parsing code.
 *
 * TODO:
 *   - Extended string matching operators: "suffix", "regex", "substring".
 *   - Extract the global list of back-end servers to main Tempesta FW code.
 *     Similar implementations of the list are done in every scheduler module,
 *     and also there is one in the sock_backend.c. We need to eliminate all
 *     this boilerplate code, and store one list of back-end servers somewhere.
 *   - Extract backend_group to the top-level of the configuration file.
 *     Currently you have to specify each "backend" twice:
 *     one for the "global" backend, and another inside "backend_group".
 *     That is ugly. "backend_group" should be handled together with "backend"
 *     and parsed into the global list of back-end servers (see above).
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies.
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

#include <linux/ctype.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/sysctl.h>

#include "cfg.h"
#include "http_match.h"
#include "rrptrset.h"
#include "sched.h"
#include "server.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta HTTP scheduler");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");

#define BANNER "tfw_sched_http: "
#define ERR(...) TFW_ERR(BANNER __VA_ARGS__)
#define LOG(...) TFW_LOG(BANNER __VA_ARGS__)
#define DBG(...) TFW_DBG(BANNER __VA_ARGS__)

#define TFW_BE_GROUP_MAX_ADDRS 16  /* max TfwAddr per TfwBeGroupAddrSet */

typedef struct {
	size_t n;
	TfwAddr addrs[TFW_BE_GROUP_MAX_ADDRS];
} TfwBeGroupAddrSet;

typedef struct {
	struct list_head list;
	const char   *name;
	TfwBeGroupAddrSet addrs;
} TfwSchedHttpCfgBeGroup;

typedef struct {
	TfwSchedHttpCfgBeGroup *be_group;
	TfwHttpMatchRule rule;
} TfwSchedHttpCfgRule;

typedef struct {
	TfwRrPtrSet *servers;  /* Pointers to TfwServer objects. */
	TfwHttpMatchRule rule;
} TfwSchedHttpMatchEntry;

/**
 * The list of TfwSchedHttpMatchEntry
 *
 * The list is a composition of:
 *   - parsed configuration ("backend_group" and "rule" entries);
 *   - a list of available servers (to which Tempesta FW is connected);
 * Each of the two components may change in runtime: servers go up and down,
 * and rules may be adjusted (or at least we aim to support that in future).
 *
 * That implies synchronization between these changes and tfw_sched_srv_get().
 * This is performance critical, so we don't use locks here.
 * Instead, we store these components (parsed configuration + list of servers),
 * and when either one changes, we re-build the whole @match_list from them and
 * replace it via RCU, so readers don't need locking.
 *
 * A single RCU updater (writer) may avoid locking as well, but concurrent
 * updaters must be synchronized with the match_list_update_lock.
 */
static TfwHttpMatchList __rcu *match_list;
DEFINE_SPINLOCK(match_list_update_lock);

/* Parsed configuration. */
static struct list_head parsed_be_groups;  /* TfwSchedHttpCfgBeGroup */
static TfwHttpMatchList *parsed_rules;
DEFINE_SPINLOCK(parsed_rules_lock);

/**
 * The list of available servers (TfwServer objects added for scheduling).
 * Allocated once upon initialization. Any access require locking.
 */
static TfwRrPtrSet *added_servers;
DEFINE_SPINLOCK(added_servers_lock);

/*
 * --------------------------------------------------------------------------
 * Functions for building match_list.
 * --------------------------------------------------------------------------
 */

static TfwRrPtrSet *
alloc_srv_set(TfwPool *pool, size_t max_srv_n)
{
	size_t size = tfw_ptrset_size(max_srv_n);
	TfwRrPtrSet *ptrset = tfw_pool_alloc(pool, size);
	if (!ptrset) {
		ERR("Can't allocate memory from pool: %p\n", pool);
		return NULL;
	}
	tfw_ptrset_init(ptrset, max_srv_n);

	return ptrset;
}

/**
 * Resolve TfwAddr to TfwServer (using added_servers).
 */
static TfwServer *
resolve_addr(const TfwAddr *addr)
{
	int i, ret;
	TfwAddr curr_addr;
	TfwServer *curr_srv;
	TfwServer *out_srv = NULL;

	spin_lock_bh(&added_servers_lock);

	tfw_ptrset_for_each(curr_srv, i, added_servers) {
		ret = tfw_server_get_addr(curr_srv, &curr_addr);
		if (ret) {
			LOG("Can't get address of the server: %p\n", curr_srv);
		}
		else if (tfw_addr_eq(addr, &curr_addr)) {
			out_srv = curr_srv;
			break;
		}
	}

	spin_unlock_bh(&added_servers_lock);

	return out_srv;
}

/**
 * Resolve a set of TfwAddr pointers into a set of TfwServer pointers
 * using the added_servers (the list of available back-end servers).
 *
 * Only available servers are added to the output @servers set, and unresolved
 * addresses are skipped, so the output set may be smaller than the input set.
 */
static int
resolve_addrs(TfwRrPtrSet *servers, const TfwBeGroupAddrSet *addrs)
{
	int i, ret;
	const TfwAddr *addr;
	TfwServer *srv;

	for (i = 0; i < addrs->n; ++i) {
		addr = &addrs->addrs[i];
		srv = resolve_addr(addr);
		if (srv) {
			ret = tfw_ptrset_add(servers, srv);
			if (ret) {
				ERR("Can't add resolved server: %p\n", srv);
				return -1;
			}
		}
	}

	return 0;
}

/**
 * Build a single TfwSchedHttpMatchEntry from @src rule, resolve IP addresses
 * into TfwServer objects, and add the entry to the @dst_mlst.
 */
static int
build_match_entry(TfwHttpMatchList *dst_mlst, const TfwSchedHttpCfgRule *src)
{
	TfwSchedHttpMatchEntry *dst;
	size_t arg_len;

	/* Allocate a new entry in @dst_mlst. */
	arg_len = src->rule.arg.len;
	dst = tfw_http_match_entry_new(dst_mlst, TfwSchedHttpMatchEntry, rule,
				       arg_len);
	if (!dst) {
		ERR("Can't create new match entry\n");
		return -1;
	}

	/* Copy all fields except @list. At this point the @dst is already a
	 * member of @dst_mlst, so we can't touch @dst->rule.list here. */
	dst->rule.field = src->rule.field;
	dst->rule.op = src->rule.op;
	dst->rule.arg.type = src->rule.arg.type;
	dst->rule.arg.len = arg_len;
	memcpy(&dst->rule.arg, &src->rule.arg, arg_len);

	/* Resolve IP addresses (from "backend_group") to TfwServer objects. */
	dst->servers = alloc_srv_set(dst_mlst->pool, src->be_group->addrs.n);
	if (!dst->servers)
		return -1;

	return resolve_addrs(dst->servers, &src->be_group->addrs);
}

/**
 * Build a new TfwHttpMatchList from saved_rules and added_servers.
 */
static TfwHttpMatchList *
build_match_list(void)
{
	int ret;
	TfwHttpMatchList *new_match_list = NULL;
	TfwSchedHttpCfgRule *src_rule;

	new_match_list = tfw_http_match_list_alloc();
	if (!new_match_list) {
		ERR("Can't allocate new match list\n");
		return NULL;
	}

	spin_lock_bh(&parsed_rules_lock);
	list_for_each_entry(src_rule, &parsed_rules->list, rule.list)
	{
		ret = build_match_entry(new_match_list, src_rule);
		if (ret) {
			spin_unlock_bh(&parsed_rules_lock);
			ERR("Can't build match entry\n");
			tfw_http_match_list_free(new_match_list);
			return NULL;
		}
	}
	spin_unlock_bh(&parsed_rules_lock);

	return new_match_list;
}

/**
 * Build a new match_list and update it via RCU.
 */
static int
rebuild_match_list(void)
{
	TfwHttpMatchList *old_match_list, *new_match_list;

	DBG("Rebuilding match_list\n");

	if (!parsed_rules) {
		DBG("No rules loaded to the scheduler yet\n");
		return 0;
	}

	new_match_list = build_match_list();
	if (!new_match_list) {
		ERR("Can't build new match_list\n");
		return -1;
	}

	spin_lock_bh(&match_list_update_lock);
	old_match_list = match_list;
	rcu_assign_pointer(match_list, new_match_list);
	spin_unlock_bh(&match_list_update_lock);

	if (old_match_list)
		call_rcu(&old_match_list->rcu, tfw_http_match_list_rcu_free);

	return 0;
}

/*
 * --------------------------------------------------------------------------
 * Scheduler API methods.
 * --------------------------------------------------------------------------
 */

static TfwServer *
tfw_sched_http_get_srv(TfwMsg *msg)
{
	TfwHttpMatchList *mlst;
	TfwSchedHttpMatchEntry *entry;
	TfwServer *srv = NULL;

	rcu_read_lock();
	mlst = rcu_dereference(match_list);
	if (unlikely(!mlst)) {
		ERR("No rules loaded to the scheduler\n");
	} else {
		entry = tfw_http_match_req_entry((TfwHttpReq * )msg, mlst,
						 TfwSchedHttpMatchEntry, rule);
		if (likely(entry))
			srv = tfw_ptrset_get_rr(entry->servers);
	}
	rcu_read_unlock();

	if (unlikely(!srv))
		ERR("A matching server is not found\n");

	return srv;
}


static int
tfw_sched_http_add_srv(TfwServer *srv)
{
	int ret = 0;

	DBG("Adding server: %p\n", srv);

	spin_lock_bh(&added_servers_lock);
	ret = tfw_ptrset_add(added_servers, srv);
	spin_unlock_bh(&added_servers_lock);

	if (ret)
		ERR("Can't add the server to the scheduler: %p\n", srv);
	else
		rebuild_match_list();

	return ret;
}

static int
tfw_sched_http_del_srv(TfwServer *srv)
{
	int ret = 0;

	DBG("Deleting server: %p\n", srv);

	spin_lock_bh(&added_servers_lock);
	ret = tfw_ptrset_del(added_servers, srv);
	spin_unlock_bh(&added_servers_lock);

	if (ret)
		ERR("Can't delete the server from the scheduler: %p\n", srv);
	else
		rebuild_match_list();

	return ret;
}

static TfwScheduler tfw_sched_http_mod_sched = {
	.name = "http",
	.get_srv = tfw_sched_http_get_srv,
	.add_srv = tfw_sched_http_add_srv,
	.del_srv = tfw_sched_http_del_srv
};

/*
 * --------------------------------------------------------------------------
 * Configuration parsing routines.
 * --------------------------------------------------------------------------
 *
 *   sched_http {
 *        backend_group {
 *            backend ...;
 *            backend ...;
 *            ...
 *        }
 *        backend_group {
 *            ...
 *        }
 *
 *        rule ...;
 *        rule ...;
 *        rule ...;
 *        ...
 *   }
 *
 */

static int
parse_sched_http_section(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	/* Allocate memory for nested backend_group/rule entries. */
	BUG_ON(parsed_rules);
	parsed_rules = tfw_http_match_list_alloc();
	if (!parsed_rules)
		return -ENOMEM;

	return tfw_cfg_handle_children(cs, e);
}

static void
free_parsed_rules(TfwCfgSpec *cs)
{
	tfw_http_match_list_free(parsed_rules);
	parsed_rules = NULL;
	INIT_LIST_HEAD(&parsed_be_groups);
}

static int
parse_backend_group(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	TfwSchedHttpCfgBeGroup *new_group;
	const char *in_name;
	char *new_name;
	size_t len;

	/* We just consume parsed_rules->pool for backend_group entries as well.
	 * Dirty but simple; everything is freed in tfw_sched_http_cfg_free() */
	new_group = tfw_pool_alloc(parsed_rules->pool, sizeof(*new_group));
	if (!new_group)
		return -ENOMEM;
	list_add(&new_group->list, &parsed_be_groups);

	in_name = e->vals[0];
	len = strlen(in_name) + 1;
	new_name = tfw_pool_alloc(parsed_rules->pool, len);
	if (!new_name)
		return -ENOMEM;
	memcpy(new_name, in_name, len);
	new_group->name = new_name;

	return tfw_cfg_handle_children(cs, e);
}

static int
parse_backend(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	TfwSchedHttpCfgBeGroup *current_be_group;
	TfwBeGroupAddrSet *addrs;
	TfwAddr *parsed_addr;
	int r;

	r = tfw_cfg_check_single_val(e);
	if (r)
		return r;

	/* Put parsed_addr to the current backend_group which is the latest
	 * element added to the parsed_be_groups. */
	current_be_group = list_entry(parsed_be_groups.prev,
				      TfwSchedHttpCfgBeGroup, list);
	addrs = &current_be_group->addrs;

	if (addrs->n == ARRAY_SIZE(addrs->addrs)) {
		ERR("maximum number of addresses per backend_group reached\n");
		return -ENOBUFS;
	}

	parsed_addr = &addrs->addrs[addrs->n++];
	r = tfw_addr_pton(e->vals[0], parsed_addr);
	if (r)
		ERR("Can't parse IP address\n");
	return r;
}

TfwCfgEnum cfg_field_enum_mappings[] = {
	{ "uri",      TFW_HTTP_MATCH_F_URI },
	{ "host",     TFW_HTTP_MATCH_F_HOST },
	{ "hdr_host", TFW_HTTP_MATCH_F_HDR_HOST },
	{ "hdr_conn", TFW_HTTP_MATCH_F_HDR_CONN },
	{ "hdr_raw",  TFW_HTTP_MATCH_F_HDR_RAW },
	{}
};

TfwCfgEnum cfg_op_enum_mappings[] = {
	{ "eq",     TFW_HTTP_MATCH_O_EQ },
	{ "prefix", TFW_HTTP_MATCH_O_PREFIX },
	/* TODO: suffix, substr, regex, case sensitive/insensitive versions. */
	{}
};

static TfwSchedHttpCfgBeGroup*
resolve_backend_group(const char *name)
{
	TfwSchedHttpCfgBeGroup *current_group;

	list_for_each_entry(current_group, &parsed_be_groups, list) {
		if (!strcasecmp(name, current_group->name))
			return current_group;
	}

	return NULL;
}

static int
parse_rule(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	const char *in_be_group, *in_field, *in_op, *in_arg;
	TfwSchedHttpCfgBeGroup *be_group;
	tfw_http_match_fld_t    field;
	tfw_http_match_op_t     op;
	TfwSchedHttpCfgRule     *rule;
	size_t arg_len;
	int r;

	in_be_group = e->vals[0];
	in_field = e->vals[1];
	in_op = e->vals[2];
	in_arg = e->vals[3];

	be_group = resolve_backend_group(in_be_group);
	if (!be_group) {
		ERR("backend_group is not found: '%s'\n", in_be_group);
		return -EINVAL;
	}

	r = tfw_cfg_map_enum(cfg_field_enum_mappings, in_field, &field);
	if (r) {
		ERR("invalid HTTP request field: '%s'\n", in_field);
		return -EINVAL;
	}

	r = tfw_cfg_map_enum(cfg_op_enum_mappings, in_op, &op);
	if (r) {
		ERR("invalid matching operator: '%s'\n", in_op);
		return -EINVAL;
	}

	arg_len = strlen(in_arg) + 1;
	rule = tfw_http_match_entry_new(parsed_rules, TfwSchedHttpCfgRule,
					rule, arg_len);
	if (!rule) {
		ERR("can't allocate memory for parsed rule\n");
		return -ENOMEM;
	}

	rule->be_group = be_group;
	rule->rule.field = field;
	rule->rule.op = op;
	rule->rule.arg.len = arg_len;
	memcpy(rule->rule.arg.str, in_arg, arg_len);
	return 0;
}


static TfwCfgSpec cfg_backend_group_specs[] = {
	{
		.name    = "backend",
		.handler = parse_backend,
		.allow_repeat = true,
	},
	{}
};

static TfwCfgSpec cfg_sched_http_section_specs[] = {
	{
		.name    = "backend_group",
		.handler = parse_backend_group,
		.dest    = cfg_backend_group_specs,
		.allow_repeat = true,
	},
	{
		.name    = "rule",
		.handler = parse_rule,
		.allow_repeat = true,
	},
	{}
};

static TfwCfgSpec cfg_toplevel_specs[] = {
	{
		.name    = "sched_http",
		.handler = parse_sched_http_section,
		.dest    = cfg_sched_http_section_specs,
		.cleanup = free_parsed_rules
	},
	{}
};

static TfwCfgMod tfw_sched_http_cfg_mod = {
	.name    = "sched_http",
	.specs   = cfg_toplevel_specs,
};

/*
 * --------------------------------------------------------------------------
 * init/exit routines.
 * --------------------------------------------------------------------------
 */

int
tfw_sched_http_init(void)
{
	int ret;
	size_t size = tfw_ptrset_size(TFW_SCHED_MAX_SERVERS);
	added_servers = kmalloc(size, GFP_KERNEL);
	if (!added_servers) {
		ERR("can't allocate memory\n");
		ret = -ENOMEM;
		goto err_alloc;
	}

	ret = tfw_cfg_mod_register(&tfw_sched_http_cfg_mod);
	if (ret) {
		ERR("Can't register configuration module\n");
		goto err_cfg_register;
	}

	ret = tfw_sched_register(&tfw_sched_http_mod_sched);
	if (ret) {
		ERR("Can't register scheduler module\n");
		goto err_sched_register;
	}

	return 0;

err_sched_register:
	tfw_cfg_mod_unregister(&tfw_sched_http_cfg_mod);
err_cfg_register:
	kfree(added_servers);
err_alloc:
	return ret;
}

void
tfw_sched_http_exit(void)
{
	tfw_sched_unregister();
	tfw_cfg_mod_unregister(&tfw_sched_http_cfg_mod);
	kfree(added_servers);
}

module_init(tfw_sched_http_init);
module_exit(tfw_sched_http_exit);
