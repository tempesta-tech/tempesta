/**
 *		Tempesta FW
 *
 * Tempesta HTTP scheduler (load-balancing module).
 *
 * The goal of this module is to implement a load balancing scheme based on
 * HTTP message contents, that is, to provide user a way to route HTTP requests
 * to different back-end server groups depending on HTTP request fields:
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
 * User defines a list of pattern-matching rules in a configuration file,
 * and we match every request against all rules, and the first matching rule
 * determines a back-end server to which the request is sent.
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
 *   sched_http_rules {
 *       match storage_servers uri prefix "static.example.com";
 *       match webapp_site1 host eq "site1.example.com";
 *       match webapp_site2 host eq "site2.example.com";
 *   }
 *
 * There's also a wildcard, or default match rule that looks like this:
 *       match storage_servers * * *
 * Here all of field, op, and arg arguments of the rule are wilcard characters.
 * This rule works as last resort option, and it forwards requests that didn't
 * match any more specific rule to the designated server group. If no default
 * rule is specified, it is created implicitly to point to the group 'default'
 * if it exists. As all match rules are processed in sequential order, this
 * rule must come last to serve the intended role.
 *
 * This module handles only the "sched_http_rules" section. It simply selects
 * a "match" rule for an incoming HTTP request. Other entities ("server" and
 * "srv_group") are handled in other modules.
 *
 * TODO:
 *   - Extended string matching operators: "suffix", "regex", "substring".
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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

#include "tempesta_fw.h"
#include "cfg.h"
#include "http_match.h"
#include "server.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta HTTP scheduler");
MODULE_VERSION("0.2.1");
MODULE_LICENSE("GPL");

typedef struct {
	TfwSrvGroup *main_sg;
	TfwSrvGroup *backup_sg;
	TfwHttpMatchRule rule;
} TfwSchedHttpRule;

static TfwHttpMatchList *tfw_sched_http_rules;

/*
 * Find a connection for an outgoing HTTP request.
 *
 * The search is based on contents of an HTTP request and match rules
 * that specify which Server Group the request should be forwarded to.
 */
static TfwConnection *
tfw_sched_http_sched_grp(TfwMsg *msg)
{
	TfwSrvGroup *sg;
	TfwConnection *conn;
	TfwSchedHttpRule *rule;

	if(!tfw_sched_http_rules || list_empty(&tfw_sched_http_rules->list))
		return NULL;

	rule = tfw_http_match_req_entry((TfwHttpReq *)msg, tfw_sched_http_rules,
					TfwSchedHttpRule, rule);
	if (unlikely(!rule)) {
		TFW_DBG("sched_http: No matching rule found.\n");
		return NULL;
	}

	sg = rule->main_sg;
	BUG_ON(!sg);
	TFW_DBG2("sched_http: use server group: '%s'\n", sg->name);

	conn = sg->sched->sched_srv(msg, sg);

	if (unlikely(!conn && rule->backup_sg)) {
		sg = rule->backup_sg;
		TFW_DBG("sched_http: the main group is offline, use backup:"
			" '%s'\n", sg->name);
		conn = sg->sched->sched_srv(msg, sg);
	}

	if (unlikely(!conn))
		TFW_DBG2("sched_http: Unable to select server from group"
			 " '%s'\n", sg->name);

	return conn;
}

static TfwConnection *
tfw_sched_http_sched_srv(TfwMsg *msg, TfwSrvGroup *sg)
{
	WARN_ONCE(true, "tfw_sched_http can't select a server from a group\n");
	return NULL;
}

static TfwScheduler tfw_sched_http = {
	.name		= "http",
	.list		= LIST_HEAD_INIT(tfw_sched_http.list),
	.sched_grp	= tfw_sched_http_sched_grp,
	.sched_srv	= tfw_sched_http_sched_srv,
};


/*
 * ------------------------------------------------------------------------
 *	Configuration handling
 * ------------------------------------------------------------------------
 */

/* e.g.: match group ENUM eq "pattern"; */
static const TfwCfgEnum __read_mostly tfw_sched_http_cfg_field_enum[] = {
	{ "*",		TFW_HTTP_MATCH_F_WILDCARD },
	{ "uri",	TFW_HTTP_MATCH_F_URI },
	{ "host",	TFW_HTTP_MATCH_F_HOST },
	{ "hdr_host",	TFW_HTTP_MATCH_F_HDR_HOST },
	{ "hdr_conn",	TFW_HTTP_MATCH_F_HDR_CONN },
	{ "hdr_raw",	TFW_HTTP_MATCH_F_HDR_RAW },
	{}
};

/* e.g.: match group uri ENUM "pattern"; */
static const TfwCfgEnum __read_mostly tfw_sched_http_cfg_op_enum[] = {
	{ "*",		TFW_HTTP_MATCH_O_WILDCARD },
	{ "eq",		TFW_HTTP_MATCH_O_EQ },
	{ "prefix",	TFW_HTTP_MATCH_O_PREFIX },
	{ "suffix",	TFW_HTTP_MATCH_O_SUFFIX },
	/* TODO: substr, regex, case sensitive/insensitive versions. */
	{}
};

static const tfw_http_match_arg_t
__read_mostly tfw_sched_http_cfg_arg_tbl[_TFW_HTTP_MATCH_F_COUNT] = {
	[TFW_HTTP_MATCH_F_WILDCARD]	= TFW_HTTP_MATCH_A_WILDCARD,
	[TFW_HTTP_MATCH_F_HDR_CONN]	= TFW_HTTP_MATCH_A_STR,
	[TFW_HTTP_MATCH_F_HDR_HOST]	= TFW_HTTP_MATCH_A_STR,
	[TFW_HTTP_MATCH_F_HDR_RAW]	= TFW_HTTP_MATCH_A_STR,
	[TFW_HTTP_MATCH_F_HOST]		= TFW_HTTP_MATCH_A_STR,
	[TFW_HTTP_MATCH_F_METHOD]	= TFW_HTTP_MATCH_A_METHOD,
	[TFW_HTTP_MATCH_F_URI]		= TFW_HTTP_MATCH_A_STR,
};

/**
 * Handle the "sched_http_rules" section.
 * Allocate the tfw_sched_http_rules list. All nested rules are added to the list.
 */
static int
tfw_sched_http_cfg_begin_rules(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TFW_DBG("sched_http: begin sched_http_rules\n");

	if (!tfw_sched_http_rules)
		tfw_sched_http_rules = tfw_http_match_list_alloc();
	if (!tfw_sched_http_rules)
		return -ENOMEM;

	return 0;
}

static int
tfw_sched_http_cfg_finish_rules(TfwCfgSpec *cs)
{
	TFW_DBG("sched_http: finish sched_http_rules\n");
	BUG_ON(!tfw_sched_http_rules);
	return 0;
}

/**
 * Handle a "match" entry within "sched_http_rules" section, e.g.:
 *   sched_http_rules {
 *       match group1 uri prefix "/foo";
 *       match group2 host eq "example.com";
 *   }
 *
 * This callback is invoked for every such "match" entry.
 * It resolves name of the group, parses the rule and adds the entry to the
 * tfw_sched_http_rules list.
 *
 * Syntax:
 *            +------------------------ a reference to "srv_group";
 *            |     +------------------ HTTP request field
 *            |     |     +------------ operator (eq, prefix, substr, etc)
 *            |     |     |       +---- argument for the operator (any string)
 *            |     |     |       |
 *            V     V     V       V
 *    match group3 uri  prefix "/foo/bar/baz.html" backup=group4
 *                                                    ^
 *                                                    |
 *                 a backup "srv_group" (optional)----+
 *
 */
static int
tfw_sched_http_cfg_handle_match(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int r;
	size_t arg_size;
	TfwSchedHttpRule *rule;
	tfw_http_match_op_t op;
	tfw_http_match_fld_t field;
	tfw_http_match_arg_t type;
	TfwSrvGroup *main_sg, *backup_sg;
	const char *in_main_sg, *in_field, *in_op, *in_arg, *in_backup_sg;

	r = tfw_cfg_check_val_n(e, 4);
	if (r)
		return r;

	in_main_sg = e->vals[0];
	in_field = e->vals[1];
	in_op = e->vals[2];
	in_arg = e->vals[3];
	in_backup_sg = tfw_cfg_get_attr(e, "backup", NULL);

	main_sg = tfw_sg_lookup(in_main_sg);
	if (!main_sg) {
		TFW_ERR("sched_http: srv_group is not found: '%s'\n",
			in_main_sg);
		return -EINVAL;
	}

	if (!in_backup_sg) {
		backup_sg = NULL;
	} else {
		backup_sg = tfw_sg_lookup(in_backup_sg);
		if (!backup_sg) {
			TFW_ERR("sched_http: backup srv_group is not found:"
				" '%s'\n", in_backup_sg);
			return -EINVAL;
		}
	}

	r = tfw_cfg_map_enum(tfw_sched_http_cfg_field_enum, in_field, &field);
	if (r) {
		TFW_ERR("sched_http: invalid HTTP request field: '%s'\n",
			in_field);
		return -EINVAL;
	}

	r = tfw_cfg_map_enum(tfw_sched_http_cfg_op_enum, in_op, &op);
	if (r) {
		TFW_ERR("sched_http: invalid matching operator: '%s'\n",
			in_op);
		return -EINVAL;
	}

	arg_size = strlen(in_arg) + 1;
	type = tfw_sched_http_cfg_arg_tbl[field];

	rule = tfw_http_match_entry_new(tfw_sched_http_rules,
					TfwSchedHttpRule, rule, arg_size);
	if (!rule) {
		TFW_ERR("sched_http: can't allocate memory for parsed rule\n");
		return -ENOMEM;
	}

	TFW_DBG("sched_http: parsed rule: match"
		" '%s'=%p '%s'=%d '%s'=%d '%s'\n",
		in_main_sg, main_sg, in_field, field, in_op, op, in_arg);

	if (type == TFW_HTTP_MATCH_A_STR || type == TFW_HTTP_MATCH_A_WILDCARD) {
		tfw_http_match_rule_init(&rule->rule, field, op, type, in_arg);
	} else {
		BUG();
		// TODO: parsing not string matching rules
	}

	rule->main_sg = main_sg;
	rule->backup_sg = backup_sg;

	return 0;
}

/**
 * Delete all rules parsed out of the "sched_http_rules" section.
 */
static void
tfw_sched_http_cfg_clean_rules(TfwCfgSpec *cs)
{
	tfw_http_match_list_free(tfw_sched_http_rules);
	tfw_sched_http_rules = NULL;
}

/* Forward declaration */
static TfwCfgMod tfw_sched_http_cfg_mod;

static int
tfw_sched_http_start(void)
{
	TfwHttpMatchRule *mrule;
	TfwSrvGroup *sg_default;
	struct list_head mod_list;
	TfwCfgMod cfg_mod;
	TfwCfgSpec *cfg_spec;
	static const char __read_mostly cfg_text[] =
		"sched_http_rules {\nmatch default * * *;\n}\n";

	/*
	 * See if we need to add a default rule that forwards all
	 * requests that do not match any rule to group 'default'.
	 *
	 * If there's a default rule already then we are all set.
	 */
	if (tfw_sched_http_rules && !list_empty(&tfw_sched_http_rules->list)) {
		mrule = list_entry(tfw_sched_http_rules->list.prev,
				   TfwHttpMatchRule, list);
		if ((mrule->field == TFW_HTTP_MATCH_F_WILDCARD)
		    && (mrule->op == TFW_HTTP_MATCH_O_WILDCARD)
		    && (mrule->arg.len == 1) && (*mrule->arg.str == '*'))
			return 0;
	}
	/*
	 * No default rule specified in the configuration, but there's no
	 * group 'default' so we would have nowhere to point this rule to.
	 */
	if ((sg_default = tfw_sg_lookup("default")) == NULL)
		return 0;

	/*
	 * Add a default rule that points to group 'default'. Note that
	 * there's a restriction that 'sched_http_rules' option can only
	 * be seen once in the configuration file. As we know for sure
	 * the there's no default rule yet, we can work around that by
	 * removing the restriction in a copy of specs for the option.
	 * Using configuration processing functions, we add the default
	 * rule exactly the same way it would have been done if it were
	 * in the configuration file.
	 */
	cfg_mod = tfw_sched_http_cfg_mod;
	INIT_LIST_HEAD(&cfg_mod.list);
	INIT_LIST_HEAD(&mod_list);
	list_add(&cfg_mod.list, &mod_list);

	cfg_spec = tfw_cfg_spec_find(cfg_mod.specs, "sched_http_rules");
	cfg_spec->allow_repeat = true;

	if (tfw_cfg_parse_mods_cfg(cfg_text, &mod_list))
		return -EINVAL;

	return 0;
}

static void
tfw_sched_http_stop(void)
{
}

static TfwCfgSpec tfw_sched_http_rules_section_specs[] = {
	{
		"match", NULL,
		tfw_sched_http_cfg_handle_match,
		.allow_repeat = true,
		.cleanup = tfw_sched_http_cfg_clean_rules,
	},
	{}
};

static TfwCfgMod tfw_sched_http_cfg_mod = {
	.name  = "tfw_sched_http",
	.start = tfw_sched_http_start,
	.stop  = tfw_sched_http_stop,
	.specs = (TfwCfgSpec[]) {
		{
			"sched_http_rules", NULL,
			tfw_cfg_handle_children,
			tfw_sched_http_rules_section_specs,
			&(TfwCfgSpecChild) {
				.begin_hook = tfw_sched_http_cfg_begin_rules,
				.finish_hook = tfw_sched_http_cfg_finish_rules
			},
			.allow_none = true
		},
		{}
	}
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

	TFW_DBG("sched_http: init\n");

	ret = tfw_cfg_mod_register(&tfw_sched_http_cfg_mod);
	if (ret) {
		TFW_ERR("sched_http: can't register configuration module\n");
		return ret;
	}

	ret = tfw_sched_register(&tfw_sched_http);
	if (ret) {
		TFW_ERR("sched_http: can't register scheduler module\n");
		tfw_cfg_mod_unregister(&tfw_sched_http_cfg_mod);
		return ret;
	}

	return 0;
}

void
tfw_sched_http_exit(void)
{
	TFW_DBG("sched_http: exit\n");

	BUG_ON(tfw_sched_http_rules);
	tfw_sched_unregister(&tfw_sched_http);
	tfw_cfg_mod_unregister(&tfw_sched_http_cfg_mod);
}

module_init(tfw_sched_http_init);
module_exit(tfw_sched_http_exit);
