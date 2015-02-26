/**
 *		Tempesta FW
 *
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

#include <linux/percpu.h>
#include <linux/smp.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "http_match.h"
#include "lb_mod.h"
#include "log.h"
#include "tempesta.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta HTTP load balancer");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");

#define TFW_LB_GROUP_MAX 	32
#define TFW_LB_SRV_CONN_MAX	32

typedef enum {
	TFW_LB_SCHED_RR,
	TFW_LB_SCHED_HASH,
} tfw_lb_sched_t;

/* XXX-comments are only for the review, they will be removed afterwards. */

typedef struct {
	struct list_head list;		/* entry in TfwLbGroup->srvs */
	TfwAddr		 addr;
	int		 socks_n;
	struct socket	 *socks[];	/* parallel connections to the server */
} TfwLbSrv;

#define TFW_LB_SRV_SIZE(socks_n) \
	(sizeof(TfwLbSrv) * ((socks_n) + 1) * sizeof(struct sock *))

/**
 * XXX: the structure should correspond to one "backend_group" configuration
 * entry and contain all nested "backend" servers.
 */
typedef struct {
	struct list_head list;		/* entry in tfw_lb_groups */
	struct list_head srvs; 		/* contains TfwLbSrv objects */
	const char	 *name;
	tfw_lb_sched_t	 sched;
	int		 rr_idx;	/* index in tfw_lb_group_rr_ctrs */
	int		 sks_n;
	struct sock 	 **sks;		/* array of 'struct sock *' */
	u32	 	*sk_hashes;	/* array of hashes for @sks */
} TfwLbGroup;

/**
 * Calculate size of a TfwLbGroup structure.
 * Note that the size doesn't include TfwLbGoup->name and TfwLbGroup->sk_hashes.
 */
#define TFW_LB_GROUP_SIZE(sks_n) \
	(sizeof(TfwLbGroup) * ((sks_n) + 1) * sizeof(struct sk *))

/**
 * XXX: the structure is adopted from tfw_sched_http. It allows to route HTTP
 * requests to a certain group of backend servers depending on HTTP request
 * fields: URI, Host, headers, etc.
 */
typedef struct {
	TfwLbGroup *group;
	TfwHttpMatchRule rule;
} TfwLbRule;

/**
 * The list of all groups of backend servers (consists of TfwLbGroup objects).
 */
static LIST_HEAD(tfw_lb_groups);

/**
 * The list of rules that allow to choose a particular group for sending a
 * HTTP request depending on its fields: URI, Host, headers. etc.
 */
static TfwHttpMatchList *tfw_lb_rules;

/**
 * The group which is chosen when none of tfw_lb_rules is applied.
 */
static TfwLbGroup *tfw_lb_default_group;

/**
 * The array of round-robin counters for tfw_lb_groups.
 * Each TfLbGroup has a corresponding slot allocated in this array.
 * The slot may be accessed via TFW_LB_GROUP_RR_CTR(TfwLbGroup->rr_idx).
 *
 * XXX: non-shared round-robin counters allow to avoid atomic instructions
 * and prevent cache line bouncing.
 */
static DEFINE_PER_CPU(u8[TFW_LB_GROUP_MAX], tfw_lb_group_rr_ctrs);

#define TFW_LB_GROUP_RR_CTR(group) \
	(__get_cpu_var(tfw_lb_group_rr_ctrs)[(group)->rr_idx])

/**
 * The number entries in the tfw_lb_groups list.
 * Helps to protect tfw_lb_group_rr_ctrs from overflow.
 */
static int tfw_lb_groups_n;

/*
 * ------------------------------------------------------------------------
 *	tfw_lb_http_send_msg() and its scheduling helpers
 * ------------------------------------------------------------------------
 *
 * This is the actual load balancing implementation.
 * The code decides how to distribute HTTP requests across backend servers.
 */

static struct sock *
tfw_lb_sched_rr_failover(TfwLbGroup *group)
{
	int sks_n, ctr, ctr_end;
	struct sock *sk, **sks;

	sks = group->sks;
	sks_n = group->sks_n;
	ctr = TFW_LB_GROUP_RR_CTR(group);
	ctr_end = ctr + sks_n;

	while (likely(++ctr < ctr_end)) {
		sk = sks[ctr % sks_n];
		if (likely(sk->sk_state == TCP_ESTABLISHED)) {
			TFW_LB_GROUP_RR_CTR(group) = ctr;
			return sk;
		}
	}

	TFW_ERR("can't find any online backend server\n");
	return NULL;
}

/**
 * XXX: the whole tfw_sched_rr is collapsed into this single function.
 */
static struct sock *
tfw_lb_sched_rr(TfwLbGroup *group)
{
	struct sock *sk;

	sk = group->sks[++TFW_LB_GROUP_RR_CTR(group) % group->sks_n];
	if (likely(sk->sk_state == TCP_ESTABLISHED))
		return sk;

	return tfw_lb_sched_rr_failover(group);
}

/**
 * XXX: the whole tfw_sched_hash is collapsed into this single function.
 * Rendezvous hashing is included as a failovering strategy.
 *
 * XXX: the linear search is slow but it is required for failover switching.
 * Perhaps we should do binary search first, and then fall back to linear if
 * the chosen socket is dead.
 *
 * XXX: schedulers will be separated into modules later. Now the code is here
 * because it determines how to build everything else around it.
 */
static struct sock *
tfw_lb_sched_hash(TfwLbGroup *group, TfwHttpReq *req)
{
	struct sock **sk_pos, *sk, *best_sk;
	u32 *hash_pos, hash, best_hash, req_hash;

	best_sk = NULL;
	best_hash = 0;
	req_hash = tfw_http_req_key_calc(req);

	sk_pos = group->sks;
	hash_pos = group->sk_hashes;
	do {
		sk = *sk_pos;
		hash = *hash_pos;

		if ((req_hash ^ hash) > (req_hash ^ best_hash) &&
		    likely(sk->sk_state == TCP_ESTABLISHED)) {
			best_sk = sk;
			best_hash = hash;
		}
	} while (*(++sk_pos) && *(++hash_pos));

	return best_sk;
}

static struct sock *
tfw_lb_sched(TfwLbGroup *group, TfwHttpReq *req)
{
	/* Should be done via a function pointer, but KISS for now. */
	return (group->sched == TFW_LB_SCHED_RR)
	       ? tfw_lb_sched_rr(group)
	       : tfw_lb_sched_hash(group, req);
}

static TfwLbGroup *
tfw_lb_select_group(TfwHttpReq *req)
{
	TfwLbRule *rule;

	if (!tfw_lb_rules)
		return tfw_lb_default_group;

	rule = tfw_http_match_req_entry(req, tfw_lb_rules, TfwLbRule, rule);
	return rule ? rule->group : tfw_lb_default_group;
}

/**
 * XXX: all useful logic from tfw_sched_http is merged into this function.
 * The rest of tfw_sched_http is configuration parsing and boilerplate code.
 */
static int
tfw_lb_http_send_msg(TfwMsg *msg)
{
	struct sock *sk;
	TfwLbGroup *group;
	TfwHttpReq *req = container_of(msg, TfwHttpReq, msg);

	group = tfw_lb_select_group(req);
	if (unlikely(!group)) {
		TFW_ERR("can't select a backend_group\n");
		return -ENOENT;
	}

	sk = tfw_lb_sched(group, req);
	if (unlikely(!sk)) {
		TFW_ERR("can't obtain a connection to the backend_group: %s\n",
			group->name);
		return -ENOENT;
	}

	TFW_DBG("send to backend_group: %s\n", group->name);
	ss_send(sk, &msg->skb_list);
	return 0;
}

/*
 * ------------------------------------------------------------------------
 *	TfwLbGroup/TfwLbSrv management helpers
 * ------------------------------------------------------------------------
 */

/**
 * Resolve @name into a group that was added via tfw_lb_group_add().
 */
static TfwLbGroup *
tfw_lb_group_find(const char *name)
{
	TfwLbGroup *group;

	list_for_each_entry(group, &tfw_lb_groups, list) {
		if (!strcasecmp(name, group->name))
			return group;
	}

	return NULL;
}

/**
 * Allocate a TfwLbGroup object and put it in the global list of all groups.
 */
static TfwLbGroup *
tfw_lb_group_add(const char *name, tfw_lb_sched_t sched)
{
	void *mem;
	TfwLbGroup *group;
	size_t group_size, name_size;

	TFW_DBG("add group: %s\n", name);

	/* Validate invariants. */
	if (tfw_lb_group_find(name)) {
		TFW_ERR("duplicate group: %s\n", name);
		return NULL;
	}
	if (tfw_lb_groups_n >= TFW_LB_GROUP_MAX) {
		TFW_ERR("maximum number of groups reached: %d\n",
			TFW_LB_GROUP_MAX);
		return NULL;
	}

	/* Allocate memory for group + group->name in one chunk. */
	group_size = sizeof(*group);
	name_size = strlen(name) + 1;
	mem = kzalloc(group_size + name_size, GFP_KERNEL);
	if (!mem)
		return NULL;
	group = mem;
	group->name = mem + group_size;

	/* Initialize fields. */
	INIT_LIST_HEAD(&group->list);
	INIT_LIST_HEAD(&group->srvs);
	memcpy((char *)group->name, name, name_size);
	group->sched = sched;
	group->rr_idx = tfw_lb_groups_n;

	/* Add to the list of all groups. */
	list_add(&group->list, &tfw_lb_groups);
	++tfw_lb_groups_n;

	return group;
}

/**
 * Allocate a TfwLbSrv object and add it to the @group.
 */
static int
tfw_lb_group_add_srv(TfwLbGroup *group, TfwAddr *addr, int socks_n)
{
	TfwLbSrv *srv;

	TFW_DBG_ADDR("add server", addr);
	TFW_DBG("add server to group: %s\n", group->name);

	list_for_each_entry(srv, &group->srvs, list) {
		if (tfw_addr_eq(addr, &srv->addr)) {
			TFW_ERR_ADDR("duplicate address", addr);
			return -EEXIST;
		}
	}

	srv = kzalloc(TFW_LB_SRV_SIZE(socks_n), GFP_KERNEL);
	if (!srv)
		return -ENOMEM;

	srv->addr = *addr;
	srv->socks_n = socks_n;
	INIT_LIST_HEAD(&srv->list);
	list_add(&srv->list, &group->srvs);

	return 0;
}

/**
 * Delete all TfwLbGroup and nested TfwLbSrv objects.
 */
static void
tfw_lb_group_del_all(void)
{
	TfwLbSrv *srv, *tmp_srv;
	TfwLbGroup *group, *tmp_group;

	list_for_each_entry_safe(group, tmp_group, &tfw_lb_groups, list) {
		TFW_DBG("delete group: %s\n", group->name);
		BUG_ON(group->sks_n || group->sks);

		list_for_each_entry_safe(srv, tmp_srv, &group->srvs, list) {
			TFW_DBG_ADDR("delete server", &srv->addr);
			BUG_ON(srv->socks[0]);
			kfree(srv);
		}

		--tfw_lb_groups_n;
		kfree(group);
	}

	BUG_ON(tfw_lb_groups_n);
	INIT_LIST_HEAD(&tfw_lb_groups);
}


/*
 * ------------------------------------------------------------------------
 *	Configuration handling
 * ------------------------------------------------------------------------
 */

/* Default values for attributes. */
#define TFW_LB_CFG_DEF_SCHED	"rr"	/* backend_group sched=DEF_VAL */
#define TFW_LB_CFG_DEF_CONNS_N	"4"	/* backend conns_n=DEF_VAL */

/* backend_group sched=ENUM { ... } */
static const TfwCfgEnum tfw_lb_cfg_sched_enum[] = {
	{ "rr",		TFW_LB_SCHED_RR },
	{ "hash",	TFW_LB_SCHED_HASH },
	{}
};

/* match group ENUM eq "pattern"; */
static const TfwCfgEnum tfw_lb_cfg_field_enum[] = {
	{ "uri",      TFW_HTTP_MATCH_F_URI },
	{ "host",     TFW_HTTP_MATCH_F_HOST },
	{ "hdr_host", TFW_HTTP_MATCH_F_HDR_HOST },
	{ "hdr_conn", TFW_HTTP_MATCH_F_HDR_CONN },
	{ "hdr_raw",  TFW_HTTP_MATCH_F_HDR_RAW },
	{}
};

/* match group uri ENUM "pattern"; */
static const TfwCfgEnum tfw_lb_cfg_op_enum[] = {
	{ "eq",     TFW_HTTP_MATCH_O_EQ },
	{ "prefix", TFW_HTTP_MATCH_O_PREFIX },
	/* TODO: suffix, substr, regex, case sensitive/insensitive versions. */
	{}
};

/**
 * The "backend_group" which is currently being parsed.
 * All "backend" entries are added to this group.
 */
static TfwLbGroup *tfw_lb_cfg_curr_be_group;

/**
 * Handle "backend" within a "backend_group", e.g.:
 *   backend_group foo {
 *       backend 10.0.0.1;
 *       backend 10.0.0.2;
 *       backend 10.0.0.3 conn_n=1;
 *   }
 *
 * Every backend is simply added to the tfw_lb_cfg_curr_be_group.
 */
static int
tfw_lb_cfg_handle_backend(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwAddr addr;
	int r, conns_n;
	const char *in_addr, *in_conns_n;

	BUG_ON(!tfw_lb_cfg_curr_be_group);

	r  = tfw_cfg_check_val_n(ce, 1);
	if (r)
		return -EINVAL;

	in_addr = ce->vals[0];
	in_conns_n = tfw_cfg_get_attr(ce, "conns_n", TFW_LB_CFG_DEF_CONNS_N);

	r =  tfw_addr_pton(in_addr, &addr)
	  || tfw_cfg_parse_int(in_conns_n, &conns_n)
	  || tfw_cfg_check_range(conns_n, 1, TFW_LB_SRV_CONN_MAX)
	  || tfw_lb_group_add_srv(tfw_lb_cfg_curr_be_group, &addr, conns_n)
	   ? -EINVAL:0;

	return r;
}

/**
 * Handle a top-level "backend" entry that doesn't belong to any group.
 *
 * All such top-level entries are simply added to the "default" group.
 * So this configuration example:
 *    backend 10.0.0.1;
 *    backend 10.0.0.2;
 *    backend_group local {
 *        backend 127.0.0.1:8000;
 *    }
 * Is implicitly transformed to this:
 *    backend_group default {
 *        backend 10.0.0.1;
 *        backend 10.0.0.2;
 *    }
 *    backend_group local {
 *        backend 127.0.0.1:8000;
 *    }
 */
static int
tfw_lb_cfg_handle_backend_outside_group(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_lb_cfg_curr_be_group = tfw_lb_group_find("default");

	/* The "default" group is created implicitly. */
	if (!tfw_lb_cfg_curr_be_group) {
		tfw_lb_sched_t sched;
		int r = tfw_cfg_map_enum(tfw_lb_cfg_sched_enum,
					 TFW_LB_CFG_DEF_SCHED, &sched);
		BUG_ON(r);

		tfw_lb_cfg_curr_be_group = tfw_lb_group_add("default", sched);
		BUG_ON(!tfw_lb_cfg_curr_be_group);
	}

	return tfw_lb_cfg_handle_backend(cs, ce);
}

/**
 * Handle defaults for the "backend" spec.
 *
 * The separate function is only needed to check that there are no "backend"s
 * already defined (either top-level or within a "backend_group").
 * If there is at least one, we don't need to use defaults.
 */
static int
tfw_lb_cfg_handle_backend_default(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_lb_groups_n) {
		TFW_DBG("at least one backend is defined, ignore defaults\n");
		return 0;
	}

	TFW_DBG("no backends defined, use the default backend\n");
	return tfw_lb_cfg_handle_backend_outside_group(cs, ce);
}

/**
 * The callback is invoked on entering a "backend_group", e.g:
 *
 *   backend_group foo sched=hash {  <--- The position at the moment of call.
 *       backend ...;
 *       backend ...;
 *       ...
 *   }
 *
 * Basically it parses the group name and the "sched" attribute, allocates
 * the TfwLbGroup object and sets the context for parsing nested "backend"s.
 */
static int
fw_lb_cfg_begin_backend_group(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	TfwLbGroup *group;
	tfw_lb_sched_t sched;
	const char *name, *sched_str;

	r = tfw_cfg_check_val_n(ce, 1);
	if (r)
		return r;

	name = ce->vals[0];
	TFW_DBG("begin backend_group: %s\n", name);

	/* Parse the sched=keyword attribute. */
	sched_str = tfw_cfg_get_attr(ce, "sched", TFW_LB_CFG_DEF_SCHED);
	r = tfw_cfg_map_enum(tfw_lb_cfg_sched_enum, sched_str, &sched);
	if (r) {
		TFW_ERR("invalid 'sched' attribute value: '%s'\n", sched_str);
		return r;
	}

	/* Allocate/add the TfwLbGroup object. */
	group = tfw_lb_group_add(name, sched);
	if (!group) {
		TFW_ERR("can't add backend_group: %s\n", name);
		return -EINVAL;
	}

	/* Set the current group. All nested "backend"s are added to it. */
	tfw_lb_cfg_curr_be_group = group;
	return 0;
}

/**
 * The callback is invoked upon exit from a "backend_group" when all nested
 * "backend"s are parsed, e.g.:
 *
 *   backend_group foo sched=hash {
 *       backend ...;
 *       backend ...;
 *       ...
 *   }  <--- The position at the moment of call.
 *
 * TODO: Allocate TfwLbGroup->sks and TfwLbGroup->sk_hashes here.
 *       These arrays depend on the number of servers, so they may be allocated
 *       only when the backend_group is finished.
 */
static int
tfw_lb_cfg_finish_backend_group(TfwCfgSpec *cs)
{
	BUG_ON(!tfw_lb_cfg_curr_be_group);
	BUG_ON(list_empty(&tfw_lb_cfg_curr_be_group->srvs));
	TFW_DBG("finish backend_group: %s\n", tfw_lb_cfg_curr_be_group->name);
	tfw_lb_cfg_curr_be_group = NULL;
	return 0;
}

/**
 * Clean the state that is changed during parsing "backend" and "backend_group".
 */
static void
tfw_lb_cfg_clean_backend_groups(TfwCfgSpec *cs)
{
	tfw_lb_group_del_all();
	tfw_lb_cfg_curr_be_group = NULL;
}

/**
 * Handle the "backend_lb_rules" section.
 * Allocate the tfw_lb_rules list. All nested rules are added to the list.
 */
static int
tfw_lb_cfg_begin_rules(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(tfw_lb_rules);

	TFW_DBG("begin backend_lb_rules\n");
	BUG_ON(tfw_lb_rules);

	tfw_lb_rules = tfw_http_match_list_alloc();
	if (!tfw_lb_rules)
		return -ENOMEM;

	return 0;
}

static int
tfw_lb_cfg_finish_rules(TfwCfgSpec *cs)
{
	TFW_DBG("finish backend_lb_rules\n");
	BUG_ON(!tfw_lb_rules);
	return 0;
}

/**
 * Handle a "match" entry within "backend_lb_rules" section, e.g.:
 *   backend_lb_rules {
 *       match group1 uri prefix "/foo";
 *       match group2 host eq "example.com";
 *   }
 *
 * This callback is invoked for every such "match" entry.
 * It resolves name of the group, parses the rule and adds the entry to the
 * tfw_lb_rules list.
 *
 * Syntax:
 *            +---------------------- a reference to "backend_group";
 *            |     +---------------- HTTP request field
 *            |     |     +---------- operator (eq, prefix, substr, etc)
 *            |     |     |       +-- argument for the operator (any string)
 *            V     V     V       V
 *    match group3 uri  prefix "/foo/bar/baz.html";
 */
static int
tfw_lb_cfg_handle_match(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int r;
	size_t arg_len;
	TfwLbRule *rule;
	TfwLbGroup *group;
	tfw_http_match_op_t  op;
	tfw_http_match_fld_t field;
	const char *in_group, *in_field, *in_op, *in_arg;

	r = tfw_cfg_check_val_n(e, 4);
	if (r)
		return r;

	in_group = e->vals[0];
	in_field = e->vals[1];
	in_op = e->vals[2];
	in_arg = e->vals[3];

	group = tfw_lb_group_find(in_group);
	if (!group) {
		TFW_ERR("backend_group is not found: '%s'\n", in_group);
		return -EINVAL;
	}

	r = tfw_cfg_map_enum(tfw_lb_cfg_field_enum, in_field, &field);
	if (r) {
		TFW_ERR("invalid HTTP request field: '%s'\n", in_field);
		return -EINVAL;
	}

	r = tfw_cfg_map_enum(tfw_lb_cfg_op_enum, in_op, &op);
	if (r) {
		TFW_ERR("invalid matching operator: '%s'\n", in_op);
		return -EINVAL;
	}

	arg_len = strlen(in_arg) + 1;
	rule = tfw_http_match_entry_new(tfw_lb_rules,
					TfwLbRule, rule, arg_len);
	if (!rule) {
		TFW_ERR("can't allocate memory for parsed rule\n");
		return -ENOMEM;
	}

	TFW_DBG("parsed rule: match  '%s'=%p  '%s'=%d  '%s'=%d  '%s'\n",
		in_group, group, in_field, field, in_op, op, in_arg);

	rule->group = group;
	rule->rule.field = field;
	rule->rule.op = op;
	rule->rule.arg.len = arg_len;
	memcpy(rule->rule.arg.str, in_arg, arg_len);
	return 0;
}

/**
 * Delete all rules parsed out of the "backend_lb_rules" section.
 */
static void
tfw_lb_cfg_clean_rules(TfwCfgSpec *cs)
{
	tfw_http_match_list_free(tfw_lb_rules);
	tfw_lb_rules = NULL;
}

static TfwCfgSpec tfw_lb_cfg_backend_group_specs[] = {
	{
		"backend", NULL,
		tfw_lb_cfg_handle_backend,
		.allow_repeat = true,
		.cleanup = tfw_lb_cfg_clean_backend_groups
	},
	{}
};

static TfwCfgSpec tfw_lb_cfg_backend_lb_rules_specs[] = {
	{
		"match", NULL,
		tfw_lb_cfg_handle_match,
		.allow_repeat = true,
		.cleanup = tfw_lb_cfg_clean_rules,
	},
	{}
};

static TfwCfgSpec tfw_lb_cfg_toplevel_specs[] = {
	{
		"backend", NULL,
		tfw_lb_cfg_handle_backend_outside_group,
		.allow_none = true,
		.allow_repeat = true,
		.cleanup = tfw_lb_cfg_clean_backend_groups,
	},
	{
		"backend_default_dummy", "127.0.0.1:8080 conns_n=4",
		tfw_lb_cfg_handle_backend_default
	},
	{
		"backend_group", NULL,
		tfw_cfg_handle_children,
		tfw_lb_cfg_backend_group_specs,
		&(TfwCfgSpecChild) {
			.begin_hook = fw_lb_cfg_begin_backend_group,
			.finish_hook = tfw_lb_cfg_finish_backend_group
		},
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		"backend_lb_rules", NULL,
		tfw_cfg_handle_children,
		tfw_lb_cfg_backend_lb_rules_specs,
		&(TfwCfgSpecChild) {
			.begin_hook = tfw_lb_cfg_begin_rules,
			.finish_hook = tfw_lb_cfg_finish_rules
		},
		.allow_none = true,
		.allow_repeat = false,
	},
	{}
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

static const TfwLbMod tfw_lb_http_mod = {
	.name = "tfw_lb_http",
	.send_msg = tfw_lb_http_send_msg
};

static TfwCfgMod tfw_lb_http_cfg_mod = {
	.name = "tfw_lb_http",
	.specs = tfw_lb_cfg_toplevel_specs
};

int
tfw_lb_http_init(void)
{
	int r;

	r = tfw_lb_mod_register(&tfw_lb_http_mod);
	if (r) {
		TFW_ERR("can't register as a load balancer module\n");
		return r;
	}

	r = tfw_cfg_mod_register(&tfw_lb_http_cfg_mod);
	if (r) {
		TFW_ERR("can't register as a configuration module\n");
		tfw_lb_mod_unregister();
		return r;
	}

	return 0;
}
module_init(tfw_lb_http_init);

void
tfw_lb_http_exit(void)
{
	tfw_cfg_mod_unregister(&tfw_lb_http_cfg_mod);
	tfw_lb_mod_unregister();
}
module_exit(tfw_lb_http_exit);
