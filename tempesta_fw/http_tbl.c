/**
 *		Tempesta FW
 *
 * Tempesta HTTP tables.
 *
 * The goal of this module is to implement HTTP requests routing system based on
 * HTTP message contents, that is, to provide user a way to route HTTP requests
 * to different virtual hosts locations for additional analyzing and then - to
 * different back-end server groups depending on HTTP request fields:
 * Host, URI, headers, etc.
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
 * User defines a number for chains with lists of pattern-matching rules
 * in a configuration file, and we match every request against all rules,
 * in all linked chains of current HTTP table and the first matching rule
 * determines a virtual host to which the request is redirected.
 *
 * The configuration section for the example above looks like:
 *   srv_group webapp_site1 {
 *       server 10.0.17.1:8081;
 *   }
 *   srv_group webapp_site2 {
 *       server 10.0.17.2:8082;
 *   }
 *   srv_group storage_servers {
 *       server 10.0.18.1;
 *       server 10.0.18.2;
 *       server 10.0.18.3;
 *   }
 *   vhost storage {
 *       proxy_pass storage_servers;
 *       ...
 *   }
 *   vhost ws1 {
 *       proxy_pass webapp_site1;
 *       ...
 *   }
 *   vhost ws2 {
 *       proxy_pass webapp_site2;
 *       ...
 *   }
 *   http_chain base {
 *       ...
 *       mark != 1 -> storage;
 *   }
 *   http_chain {
 *       uri  == "static.example.com*" -> base;
 *       host == "site1.example.com"   -> ws1;
 *       host == "site2.example.com"   -> ws2;
 *   }
 *
 * There's also a default match rule that looks like this:
 *                       -> storage;
 * This rule works as last resort option, and if specified it applies designated
 * action to requests that didn't match any more specific rule. As all match
 * rules are processed in sequential order, this rule must come last to serve
 * the intended role.
 *
 * Rules are grouped in HTTP chains. One main HTTP chain (without name) must
 * be specified after all other chains in configuration file. If no main chain
 * is specified, it is created implicitly. In this case one default match rule
 * pointing to default virtual host will be created in implicit main chain if
 * default virtual host is present in configuration and if such default rule
 * (with default virtual host) have not been specified explicitly in any chain
 * in configuration.
 * Besides, user can explicitly create main HTTP chain with empty list of rules,
 * which means the complete absence of rules - all incoming requests will be
 * dropped in such configuration.
 *
 * This module handles only the "http_chain" sections. It simply selects rule for
 * an incoming HTTP request. Other entities ("server", "srv_group" and "vhost")
 * are handled in other modules.
 *
 * TODO:
 *   - Extended string matching operators: "regex", "substring".
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#include <linux/string.h>
#include <linux/ctype.h>

#include "http_tbl.h"
#include "tempesta_fw.h"
#include "cfg.h"
#include "http_match.h"
#include "server.h"

/* Active HTTP table. */
static TfwHttpTable __rcu *tfw_table;
/* Reconfig HTTP table. */
static TfwHttpTable *tfw_table_reconfig;
/* Entry for configuration particular HTTP chain of rules. */
static TfwHttpChain *tfw_chain_entry;

/*
 * Scan all rules in linked chains of current active HTTP table. Main HTTP
 * chain is processed primarily (must be first in the table list); if rule
 * of some chain points to other chain - move to that chain and scan it.
 */
static TfwVhost *
tfw_http_tbl_scan(TfwMsg *msg, TfwHttpTable *table, bool *block)
{
	TfwHttpChain *chain;
	TfwHttpMatchRule *rule;

	chain = list_first_entry_or_null(&table->head, TfwHttpChain, list);
	BUG_ON(!chain || chain->name);
	while (chain) {
		rule = tfw_http_match_req((TfwHttpReq *)msg, &chain->mark_list);
		if (!rule)
			rule = tfw_http_match_req((TfwHttpReq *)msg,
						  &chain->match_list);
		if (unlikely(!rule)) {
			TFW_DBG("http_tbl: No rule found in HTTP"
				" chain '%s'\n", chain->name);
			return NULL;
		}
		chain = (rule->act.type == TFW_HTTP_MATCH_ACT_CHAIN)
		      ? rule->act.chain
		      : NULL;
	}

	/* If rule points to virtual host, return the pointer. */
	if (rule->act.type == TFW_HTTP_MATCH_ACT_VHOST)
		return  rule->act.vhost;

	/* If rule has 'block' action, request must be blocked. */
	if (rule->act.type == TFW_HTTP_MATCH_ACT_BLOCK)
		*block = true;

	return NULL;
}

/*
 * Find vhost for an outgoing HTTP request.
 *
 * The search is based on contents of an HTTP request and
 * match http chain rules that specify which virtual host
 * or other http chain the request should be forwarded to.
 */
TfwVhost *
tfw_http_tbl_vhost(TfwMsg *msg, bool *block)
{
	TfwVhost *vhost = NULL;
	TfwHttpTable *active_table;

	rcu_read_lock_bh();

	active_table = rcu_dereference_bh(tfw_table);
	if(!active_table)
		goto done;

	BUG_ON(list_empty(&active_table->head));
	if ((vhost = tfw_http_tbl_scan(msg, active_table, block)))
		tfw_vhost_get(vhost);
done:
 	rcu_read_unlock_bh();
 	return vhost;
}

/*
 * ------------------------------------------------------------------------
 *	Configuration handling
 * ------------------------------------------------------------------------
 */

/* e.g.: match group ENUM eq "pattern"; */
static const TfwCfgEnum tfw_http_tbl_cfg_field_enum[] = {
	{ "uri",	TFW_HTTP_MATCH_F_URI },
	{ "host",	TFW_HTTP_MATCH_F_HOST },
	{ "hdr",	TFW_HTTP_MATCH_F_HDR },
	{ "mark",	TFW_HTTP_MATCH_F_MARK },
	{ "method",	TFW_HTTP_MATCH_F_METHOD },
	{ 0 }
};

static const TfwCfgEnum tfw_http_tbl_cfg_method_enum[] = {
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
	{ "unlock",	TFW_HTTP_METH_UNLOCK, },
	{ "purge",	TFW_HTTP_METH_PURGE },
	{ 0 }
};

int
tfw_http_tbl_method(const char *arg, tfw_http_meth_t *method)
{
	if (tfw_cfg_map_enum(tfw_http_tbl_cfg_method_enum, arg, method))
	{
		TFW_ERR_NL("http_tbl: invalid 'method' condition:"
			   " '%s'\n", arg);
		return -EINVAL;
	}
	return 0;
}

static TfwHttpChain *
tfw_chain_lookup(const char *name)
{
	TfwHttpChain *chain;

	list_for_each_entry(chain, &tfw_table_reconfig->head, list) {
		if (chain->name && !strcasecmp(chain->name, name))
			return chain;
	}
	return NULL;
}

static inline bool
tfw_http_rule_default_exist(struct list_head *head)
{
	TfwHttpMatchRule *rule;

	rule = !list_empty(head)
	     ? list_last_entry(head, TfwHttpMatchRule, list)
	     : NULL;

	if (rule
	    && !rule->inv
	    && rule->field == TFW_HTTP_MATCH_F_WILDCARD
	    && rule->act.type != TFW_HTTP_MATCH_ACT_MARK)
		return true;

	return false;
}

static int
tfw_http_tbl_cfgstart(void)
{
	BUG_ON(tfw_table_reconfig);

	tfw_table_reconfig = tfw_pool_new(TfwHttpTable, TFW_POOL_ZERO);
	if (!tfw_table_reconfig) {
		TFW_ERR_NL("Can't create a memory pool\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&tfw_table_reconfig->head);

	return 0;
}

/**
 * Handle the "http_chain" section. Allocate the chain inside reconfig table.
 * All nested rules are added to the chain.
 */
static int
tfw_cfgop_http_tbl_chain_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwHttpChain *chain;
	const char *name = NULL;

	BUG_ON(!tfw_table_reconfig);
	BUG_ON(tfw_chain_entry);

	TFW_DBG("http_tbl: begin http_chain\n");

	if (ce->val_n > 1) {
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR_NL("Unexpected attributes\n");
		return -EINVAL;
	}

	chain = list_first_entry_or_null(&tfw_table_reconfig->head,
					 TfwHttpChain, list);
	if (chain && !chain->name) {
		TFW_ERR_NL("Main HTTP chain must be only one and last\n");
		return -EINVAL;
	}
	if (ce->val_n) {
		name = ce->vals[0];
		list_for_each_entry(chain, &tfw_table_reconfig->head, list) {
			if (!strcasecmp(chain->name, name)) {
				TFW_ERR_NL("Duplicate http chain"
					   " entry: '%s'\n", name);
				return -EINVAL;
			}
		}
	}

	tfw_chain_entry = tfw_http_chain_add(name, tfw_table_reconfig);
	if (!tfw_chain_entry)
		return -ENOMEM;

	return 0;
}

static int
tfw_cfgop_http_tbl_chain_finish(TfwCfgSpec *cs)
{
	TFW_DBG("http_tbl: finish http_chain\n");
	BUG_ON(!tfw_chain_entry);
	tfw_chain_entry = NULL;
	return 0;
}

/**
 * Handle a rule entry within "http_chain" section, e.g.:
 *   http_chain  {
 *       uri == "*.php" -> static;
 *       mark == 2 -> waf_chain;
 *       referer != "*hacked.com" -> mark = 7;
 *       -> mark = 3;
 *   }
 *
 * This callback is invoked for every such rule. It interprets the
 * condition and action parts of the rule, and adds the entry to
 * the list of rules of current chain.
 *
 * Syntax:
 *            +------------------------ First operand of rule's condition part
 *            |                         (HTTP request field or 'mark');
 *            |   +-------------------- Condition type: equal ('==') or not
 *            |   |                     equal ('!=');
 *            |   |     +-------------- Second operand of rule's condition part
 *            |   |     |               (argument for the rule - any string);
 *            |   |     |         +---- Action part of the rule (reference to
 *            |   |     |         |     other http_chain or vhost, 'block' or
 *            |   |     |         |     'mark' action).
 *            V   V     V         V
 *           uri == "*.php" -> static
 *
 */
static int
tfw_cfgop_http_rule(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int r;
	TfwHttpMatchRule *rule;
	const char *in_field, *hdr, *action, *action_val, *in_arg, *arg = NULL;
	unsigned int invert, hid = TFW_HTTP_HDR_RAW;
	tfw_http_match_op_t op = TFW_HTTP_MATCH_O_WILDCARD;
	tfw_http_match_fld_t field = TFW_HTTP_MATCH_F_WILDCARD;
	tfw_http_match_arg_t type = TFW_HTTP_MATCH_A_WILDCARD;
	TfwCfgRule *cfg_rule = &e->rule;
	size_t len = 0, arg_size = 0;
	TfwHttpChain *chain = NULL;
	TfwVhost *vhost = NULL;

	BUG_ON(!tfw_chain_entry);
	if ((r = tfw_cfg_check_val_n(e, 0)))
		return r;
	if (e->attr_n) {
		TFW_ERR_NL("Attributes count must be zero\n");
		return -EINVAL;
	}

	invert = cfg_rule->inv;
	in_field = cfg_rule->fst;
	hdr = cfg_rule->fst_ext;
	in_arg = cfg_rule->snd;
	if (in_arg)
		len = strlen(in_arg);
	action = cfg_rule->act;
	action_val = cfg_rule->val;
	BUG_ON(!action);

	if (tfw_http_rule_default_exist(&tfw_chain_entry->match_list)) {
		TFW_ERR_NL("http_tbl: default HTTP rule must be"
			   " only one and last; chain '%s'\n",
			   tfw_chain_entry->name ? : "main" );
		return -EINVAL;
	}

	/* Interpret condition part of the rule. */
	if (in_arg) {
		BUG_ON(!in_field);
		r = tfw_cfg_map_enum(tfw_http_tbl_cfg_field_enum,
				     in_field, &field);
		if (r) {
			TFW_ERR_NL("http_tbl: invalid rule field: '%s'\n",
				   in_field);
			return r;
		}
		if ((r = tfw_http_verify_hdr_field(field, &hdr, &hid)))
			return r;

		arg = tfw_http_arg_adjust(in_arg, field, hdr, &arg_size,
					  &type, &op);
		if (IS_ERR(arg))
			return PTR_ERR(arg);
	}

	rule = tfw_http_rule_new(tfw_chain_entry, type, arg_size);
	if (!rule) {
		TFW_ERR_NL("http_tbl: can't allocate memory for rule\n");
		r = -ENOMEM;
		goto err;
	} else {
		BUG_ON(type != TFW_HTTP_MATCH_A_STR
		       && type != TFW_HTTP_MATCH_A_NUM
		       && type != TFW_HTTP_MATCH_A_METHOD
		       && type != TFW_HTTP_MATCH_A_WILDCARD);
		rule->hid = hid;
		rule->inv = invert;
		rule->field = field;
		rule->op = op;
		rule->arg.type = type;
		if ((r = tfw_http_rule_arg_init(rule, arg, arg_size - 1)))
			goto err;
		kfree(arg);
	}

	/* Interpret action part of the rule. */
	if (!strcasecmp(action, "mark")) {
		if (!action_val ||
		    tfw_cfg_parse_uint(action_val,&rule->act.mark))
		{
			TFW_ERR_NL("http_tbl: 'mark' action must have"
				   " unsigned integer value: '%s'\n",
				   action_val);
			return -EINVAL;
		}
		rule->act.type = TFW_HTTP_MATCH_ACT_MARK;
	} else if (action_val) {
		TFW_ERR_NL("http_tbl: not 'mark' actions must not have"
			   " any value: '%s'\n", action_val);
		return -EINVAL;
	} else if (!strcasecmp(action, "block")) {
		rule->act.type = TFW_HTTP_MATCH_ACT_BLOCK;
	} else if ((chain = tfw_chain_lookup(action))) {
		rule->act.type = TFW_HTTP_MATCH_ACT_CHAIN;
		rule->act.chain = chain;
	} else if ((vhost = tfw_vhost_lookup_reconfig(action))) {
		rule->act.type = TFW_HTTP_MATCH_ACT_VHOST;
		rule->act.vhost = vhost;
	} else {
		TFW_ERR_NL("http_tbl: neither http_chain nor vhost with"
			   " specified name were found: '%s'\n", action);
		return -EINVAL;
	}

	if (chain == tfw_chain_entry) {
		TFW_ERR_NL("http_tbl: cyclic reference of http_chain to"
			   " itself: '%s'\n", tfw_chain_entry->name);
		return -EINVAL;
	}

	if (vhost && !strcasecmp(vhost->name.data, TFW_VH_DFT_NAME))
		tfw_table_reconfig->chain_dflt = true;

	return 0;
err:
	kfree(arg);
	return r;
}

static int
tfw_cfgop_release_rule(TfwHttpMatchRule *rule)
{
	if (rule->act.type == TFW_HTTP_MATCH_ACT_VHOST)
		tfw_vhost_put(rule->act.vhost);
	return 0;
}

static void
tfw_cfgop_free_table(TfwHttpTable *table)
{
	TfwHttpChain *chain;

	if (!table)
		return;

	list_for_each_entry(chain, &table->head, list) {
		tfw_http_chain_rules_for_each(chain, tfw_cfgop_release_rule);
	}
	tfw_http_table_free(table);
}

static void
tfw_cfgop_replace_active_table(TfwHttpTable *new_table)
{
	TfwHttpTable *active_table = tfw_table;

	rcu_assign_pointer(tfw_table, new_table);
	synchronize_rcu_bh();

	tfw_cfgop_free_table(active_table);
}

static int
tfw_http_tbl_start(void)
{
	tfw_cfgop_replace_active_table(tfw_table_reconfig);
	tfw_table_reconfig = NULL;

	return 0;
}

static int
tfw_http_tbl_cfgend(void)
{
	int r;
	TfwVhost *vhost_dflt;
	TfwHttpChain *chain;
	TfwHttpMatchRule *rule;

	/*
	 * Add rule with 'default' virtual host into main HTTP chain if such
	 * rule have not been specified in any chain at all and if 'default'
	 * virtual host (explicit or implicit) is present in configuration
	 * and if main HTTP chain is absent. In any case - add empty main
	 * HTTP chain if it is absent.
	 */
	BUG_ON(!tfw_table_reconfig);
	chain = list_first_entry_or_null(&tfw_table_reconfig->head,
					 TfwHttpChain, list);
	if (chain && !chain->name)
		return 0;

	if (!(chain = tfw_http_chain_add(NULL, tfw_table_reconfig)))
		return -ENOMEM;

	if (tfw_table_reconfig->chain_dflt)
		return 0;

	if (!(vhost_dflt = tfw_vhost_lookup_reconfig(TFW_VH_DFT_NAME)))
		return 0;

	rule = tfw_http_rule_new(chain, TFW_HTTP_MATCH_A_WILDCARD, 0);
	if (!rule) {
		TFW_ERR_NL("http_tbl: can't allocate memory for"
			   " default rule of main HTTP chain\n");
		r = -ENOMEM;
		goto err;
	}

	rule->op = TFW_HTTP_MATCH_O_WILDCARD;
	rule->field = TFW_HTTP_MATCH_F_WILDCARD;
	rule->arg.type = TFW_HTTP_MATCH_A_WILDCARD;
	rule->act.type = TFW_HTTP_MATCH_ACT_VHOST;
	rule->act.vhost = vhost_dflt;

	return 0;
err:
	tfw_vhost_put(vhost_dflt);
	return r;
}

/**
 * Delete all rules parsed out of all "http_chain" sections for current (if
 * this is not live reconfiguration) and reconfig HTTP tables.
 */
static void
__tfw_cfgop_rules_cleanup(void)
{
	tfw_cfgop_free_table(tfw_table_reconfig);
	tfw_table_reconfig = NULL;

	if (!tfw_runstate_is_reconfig())
		tfw_cfgop_replace_active_table(NULL);
}

static void
tfw_cfgop_rules_cleanup(TfwCfgSpec *cs)
{
	tfw_chain_entry = NULL;
	__tfw_cfgop_rules_cleanup();
}

static void
tfw_http_tbl_cfgclean(void)
{
	__tfw_cfgop_rules_cleanup();
}

static TfwCfgSpec tfw_http_tbl_rules_specs[] = {
	{
		.name = TFW_CFG_RULE_NAME,
		.deflt = NULL,
		.handler = tfw_cfgop_http_rule,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{ 0 }
};

static TfwCfgSpec tfw_http_tbl_specs[] = {
	{
		.name = "http_chain",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfgop_rules_cleanup,
		.dest = tfw_http_tbl_rules_specs,
		.spec_ext = &(TfwCfgSpecChild) {
			.begin_hook = tfw_cfgop_http_tbl_chain_begin,
			.finish_hook = tfw_cfgop_http_tbl_chain_finish
		},
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{ 0 }
};

static TfwMod tfw_http_tbl_mod = {
	.name		= "http_tbl",
	.cfgstart	= tfw_http_tbl_cfgstart,
	.cfgend		= tfw_http_tbl_cfgend,
	.start		= tfw_http_tbl_start,
	.cfgclean	= tfw_http_tbl_cfgclean,
	.specs		= tfw_http_tbl_specs,
};

/*
 * --------------------------------------------------------------------------
 * init/exit routines.
 * --------------------------------------------------------------------------
 */

int
tfw_http_tbl_init(void)
{
	tfw_mod_register(&tfw_http_tbl_mod);
	return 0;
}

void
tfw_http_tbl_exit(void)
{
	BUG_ON(tfw_table_reconfig);
	tfw_mod_unregister(&tfw_http_tbl_mod);
}
