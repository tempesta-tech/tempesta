/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#include "http_match.h"
#include "http.h"
#include "lib.h"
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

#define MAX_SRV_PER_RULE 16
#define RULES_TEXT_BUF_SIZE 4096
#define IP_ADDR_TEXT_BUF_SIZE 32

/**
 * PtrSet is a generic set of pointers implemented by a plain array.
 *
 * In this module it is used for:
 *   - Maintaining a list of all servers added to the scheduler.
 *   - Storing TfwAddr pointers in a parsed rule.
 *   - Storing TfwServer pointers for entries in a matching table.
 *
 * @counter is used only in the third case for round-robin balancing between
 *          the servers.
 * @max is a size of the @ptrs array (and @n is a number of occupied elements).
 */
typedef struct {
	atomic_t counter;
	short n;
	short max;
	void *ptrs[0];
} PtrSet;

#define PTR_SET_SIZE(max) (sizeof(PtrSet) + ((max) * sizeof(void *)))

/**
 * The structure may be used in two forms:
 *  - A list of parsed rules with attached backend addresses.
 *  - The same list of rules, but addresses are resolved to TfwServer objects.
 */
typedef struct {
	union {
		PtrSet *servers; /* Contains TfwServer pointers. */
		PtrSet *addrs;   /* Contains TfwAddr pointers. */
	};
	TfwHttpMatchRule rule;
} MatchEntry;

/**
 * A list of matching rules which is used to schedule HTTP requests.
 *
 * The list contains pre-resolved TfwServer objects instead instead of IP
 * addresses (specified in rules). That is done for performance purposes:
 * when a corresponding rule is found, a TfwServer may be returned immediately
 * without searching a TfwServer by its IP address.
 *
 * When either rules or servers are changed a new match_list is allocated and
 * built, and this pointer is replaced via RCU.
 *
 * RCU Updaters must be synchronized with the match_list_update_lock.
 */
static TfwHttpMatchList __rcu *match_list;
DEFINE_SPINLOCK(match_list_update_lock);

/**
 * A list of parsed rules (but not yet a match_list).
 * A new list is allocated by configuration parser when rules are changed.
 * Any access must be protected with the saved_rules_lock.
 */
static TfwHttpMatchList *saved_rules;
DEFINE_SPINLOCK(saved_rules_lock);

/**
 * A set of all (online) servers added to the scheduler.
 * Allocated once upon module initialization (for fixed amount of servers).
 * Any access must be protected with the added_servers_lock.
 */
static PtrSet *added_servers;
DEFINE_SPINLOCK(added_servers_lock);

/*
 * --------------------------------------------------------------------------
 *  PtrSet related functions.
 * --------------------------------------------------------------------------
 */

static int
ptrset_find(const PtrSet *s, const void *ptr)
{
	int i;

	BUG_ON(!s || !ptr);

	for (i = 0; i < s->n; ++i) {
		if (s->ptrs[i] == ptr)
			return i;
	}

	return -1;
}

static int
ptrset_add(PtrSet *s, void *ptr)
{
	BUG_ON(!s || !ptr);

	if (ptrset_find(s, ptr) > 0) {
		ERR("Can't add ptr %p to set %p - duplicate ptr\n", ptr, s);
		return -EEXIST;
	}
	else if (s->n >= s->max) {
		ERR("Can't add ptr %p to set %p - set is full\n", ptr, s);
		return -ENOSPC;
	}

	s->ptrs[s->n] = ptr;
	++s->n;

	return 0;
}

static int
ptrset_del(PtrSet *s, void *ptr)
{
	int i;

	BUG_ON(!s || !ptr);

	i = ptrset_find(s, ptr);

	if (i < 0) {
		ERR("Can't delete ptr %p from set %p - not found\n", ptr, s);
		return -ENOENT;
	}

	s->ptrs[i] = s->ptrs[s->n - 1];
	s->ptrs[s->n] = NULL;
	--s->n;

	return 0;
}

static void *
ptrset_get_rr(PtrSet *s)
{
	unsigned int n, counter;
	void *ret;

	do {
		n = s->n;
		if (!n) {
			ERR("Can't get a pointer from the empty set: %p\n",
			       s);
			return NULL;
		}

		counter = atomic_inc_return(&s->counter);
		ret = s->ptrs[counter % n];
	} while (!ret);

	return ret;
}

/*
 * --------------------------------------------------------------------------
 * Functions for building match_list.
 * --------------------------------------------------------------------------
 */

/**
 * Allocate a set of TfwAddr or TfwServer pointers for placing it
 * into a MatchEntry.
 */
static PtrSet *
alloc_servers(TfwPool *pool)
{
	size_t size = PTR_SET_SIZE(MAX_SRV_PER_RULE);
	PtrSet *servers = tfw_pool_alloc(pool, size);
	if (!servers) {
		ERR("Can't allocate memory from pool: %p\n", pool);
		return NULL;
	}
	memset(servers, 0, size);
	servers->max = MAX_SRV_PER_RULE;

	return servers;
}

#define alloc_addrs(pool) alloc_servers(pool)

/**
 * Resolve TfwAddr to TfwServer (using a set of servers added to the scheduler).
 */
static TfwServer *
resolve_addr(const TfwAddr *addr)
{
	int i, ret;
	TfwAddr curr_addr;
	TfwServer *curr_srv;
	TfwServer *out_srv = NULL;

	spin_lock_bh(&added_servers_lock);

	for (i = 0; i < added_servers->n; ++i) {
		curr_srv = added_servers->ptrs[i];

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
 * Resolve a set of TfwAddr pointers into a set of TfwServer pointers.
 * Only online servers added to this scheduler are added to @dst_servers.
 * Unresolved addresses are skipped.
 */
static int
resolve_addresses(PtrSet *dst_servers, const PtrSet *src_addrs)
{
	int i, ret;
	TfwAddr *addr;
	TfwServer *srv;

	for (i = 0; i < src_addrs->n; ++i) {
		addr = src_addrs->ptrs[i];
		srv = resolve_addr(addr);
		if (srv) {
			ret = ptrset_add(dst_servers, srv);
			if (ret) {
				ERR("Can't add resolved server: %p\n", srv);
				return -1;
			}
		}
	}

	return 0;
}

/**
 * Allocate a new entry in @dst_mlst, copy rule from @src and with resolving
 * IP addresses to TfwServer objects.
 */
static int
build_match_entry(TfwHttpMatchList *dst_mlst, const MatchEntry *src)
{
	int ret = 0;
	MatchEntry *dst;
	size_t arg_len;

	/* Allocate a new entry in @dst_mlst. */
	arg_len = src->rule.arg.len;
	dst = tfw_http_match_entry_new(dst_mlst, MatchEntry, rule, arg_len);
	if (!dst) {
		ERR("Can't create new match entry\n");
		return -1;
	}

	/* Copy all fields except @list. At this point the @dst is already a
	 * member of @dst_mlst, so we can't touch @dst->rule.list here. */
	dst->rule.field = src->rule.field;
	dst->rule.op = src->rule.op;
	dst->rule.arg.len = arg_len;
	memcpy(dst->rule.arg.str, src->rule.arg.str, arg_len);

	/* Allocate a set of server and resolve addresses to servers. */
	dst->servers = alloc_servers(dst_mlst->pool);
	if (!dst->servers)
		return -1;
	ret = resolve_addresses(dst->servers, src->addrs);
	if (ret)
		return -1;

	return ret;
}

/**
 * Build a new MatchList from saved_rules and added_servers.
 */
static TfwHttpMatchList *
build_match_list(void)
{
	int ret;
	TfwHttpMatchList *new_match_list = NULL;
	MatchEntry *src_entry;

	new_match_list = tfw_http_match_list_alloc();
	if (!new_match_list) {
		ERR("Can't allocate new match list\n");
		return NULL;
	}

	spin_lock_bh(&saved_rules_lock);
	list_for_each_entry(src_entry, &saved_rules->list, rule.list)
	{
		ret = build_match_entry(new_match_list, src_entry);
		if (ret) {
			spin_unlock_bh(&saved_rules_lock);
			ERR("Can't build match entry\n");
			tfw_http_match_list_free(new_match_list);
			return NULL;
		}
	}
	spin_unlock_bh(&saved_rules_lock);

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

	if (!saved_rules) {
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

TfwServer *
tfw_sched_http_get_srv(TfwMsg *msg)
{
	TfwHttpMatchList *mlst;
	MatchEntry *entry;
	TfwServer *srv = NULL;

	rcu_read_lock();
	mlst = rcu_dereference(match_list);
	if (!mlst) {
		ERR("No rules loaded to the scheduler\n");
	} else {
		entry = tfw_http_match_req_entry((TfwHttpReq * )msg, mlst,
						 MatchEntry, rule);
		if (entry)
			srv = ptrset_get_rr(entry->servers);
	}
	rcu_read_unlock();

	if (!srv)
		ERR("A matching server is not found\n");

	return srv;
}


int
tfw_sched_http_add_srv(TfwServer *srv)
{
	int ret = 0;

	DBG("Adding server: %p\n", srv);

	spin_lock_bh(&added_servers_lock);
	ret = ptrset_add(added_servers, srv);
	spin_unlock_bh(&added_servers_lock);

	if (ret)
		ERR("Can't add the server to the scheduler: %p\n", srv);
	else
		rebuild_match_list();

	return ret;
}

int
tfw_sched_http_del_srv(TfwServer *srv)
{
	int ret = 0;

	DBG("Deleting server: %p\n", srv);

	spin_lock_bh(&added_servers_lock);
	ret = ptrset_del(added_servers, srv);
	spin_unlock_bh(&added_servers_lock);

	if (ret)
		ERR("Can't delete the server from the scheduler: %p\n", srv);
	else
		rebuild_match_list();

	return ret;
}

/*
 * --------------------------------------------------------------------------
 *  Sysctl configuration parser.
 * --------------------------------------------------------------------------
 *
 * This is a tiny recursive descent parser that tries to mimic this grammar:
 *  input   ::= rules
 *  rules   ::= rule rules
 *  rule    ::= field
 *            | op
 *            | arg
 *            | LBRACE
 *            | addrs
 *            | RBRACE
 *  addrs ::= addr addrs
 *  addr  ::= STR
 *  field ::= STR
 *  op    ::= STR
 *  arg   ::= STR
 *
 * The parser is a subject to change.
 * In future, it should be generalized to a Tempesta configuration framework.
 */

typedef enum {
	TOKEN_NA = 0,
	TOKEN_LBRACE,
	TOKEN_RBRACE,
	TOKEN_STR,
} token_t;

static const char *
token_str(token_t t)
{
	static const char *token_str_tbl[] = {
		[TOKEN_NA] 	= STRINGIFY(TOKEN_NA),
		[TOKEN_LBRACE] 	= STRINGIFY(TOKEN_LBRACE),
		[TOKEN_RBRACE] 	= STRINGIFY(TOKEN_RBRACE),
		[TOKEN_STR] 	= STRINGIFY(TOKEN_STR),
	};

	BUG_ON(t >= ARRAY_SIZE(token_str_tbl));
	return token_str_tbl[t];
}

typedef struct {
	token_t token;
	int len;
	const char *lexeme;
	const char *pos;
	MatchEntry *entry;
	TfwHttpMatchList *mlst;
} ParserState;

#define PARSER_ERR(s, ...) \
do { \
	ERR("Parser error: " __VA_ARGS__); \
	ERR("lexeme: %.*s  position: %.80s\n", s->len, s->lexeme, s->pos); \
} while (0)

static token_t
get_token(ParserState *s)
{
	static const token_t single_char_tokens[] = {
		[0 ... 255] = TOKEN_NA,
		['{'] = TOKEN_LBRACE,
		['}'] = TOKEN_RBRACE,
	};
	const char *p;

	s->token = TOKEN_NA;
	s->lexeme = NULL;
	s->len = 0;
	s->pos = skip_spaces(s->pos);

	if (!s->pos[0])
		goto out;
	s->lexeme = s->pos;

	s->token = single_char_tokens[(u8)s->pos[0]];
	if (s->token) {
		s->pos++;
		s->len = 1;
		goto out;
	}

	if (s->lexeme[0] == '"') {
		for (p = s->pos + 1; *p; ++p) {
			if (*p == '"' && *(p - 1) != '\\') {
				break;
			}
		}
		if (*p == '"') {
			s->lexeme++;
			s->len = (p - s->lexeme);
			s->pos = ++p;
			s->token = TOKEN_STR;
		} else {
			PARSER_ERR(s, "unterminated quote");
		}
	} else {
		for (p = s->pos + 1; *p && !isspace(*p); ++p)
			;
		s->len = (p - s->pos);
		s->pos = p;
		s->token = TOKEN_STR;
	}

out:
	return s->token;
}

static token_t
peek_token(ParserState *s)
{
	ParserState old_state = *s;
	token_t t = get_token(s);
	*s = old_state;

	return t;
}

#define EXPECT(token, s, action_if_unexpected) 		\
do { 							\
	token_t _t = peek_token(s); 			\
	if (_t != token) { 				\
		PARSER_ERR(s, "Unexpected token: %s (expected %s)\n", \
		              token_str(_t), token_str(token)); \
		action_if_unexpected;			\
	} 						\
} while (0)

#define EXPECT_EITHER(t1, t2, s, action_if_unexpected) 	\
({ 							\
	token_t _t = peek_token(s); 			\
	if (_t != t1 && _t != t2) { 			\
		PARSER_ERR(s, "Unexpected token: %s (expected: %s or %s)\n", \
		              token_str(_t) token_str(t1), token_str(t2)); \
		action_if_unexpected; 			\
	} 						\
	_t; 						\
})

#define IDX_BY_STR(array, str, maxlen)			\
({ 							\
	int _found_idx = 0; 				\
	int _i; 					\
	for (_i = 0; _i < ARRAY_SIZE(array); ++_i) { 	\
		if (!array[_i])				\
			continue;			\
		if (!strncmp(str, array[_i], maxlen)) {	\
			_found_idx = _i; 		\
			break; 				\
		} 					\
	} 						\
	_found_idx; 					\
})

static int
parse_field(ParserState *s)
{
	static const char *field_str_tbl[] = {
		[TFW_HTTP_MATCH_F_NA] 	   = STRINGIFY(TFW_HTTP_MATCH_F_NA),
		[TFW_HTTP_MATCH_F_HOST] = "host",
		[TFW_HTTP_MATCH_F_URI] = "uri",
		[TFW_HTTP_MATCH_F_HDR_RAW] = "headers",
	};
	tfw_http_match_fld_t field;

	EXPECT(TOKEN_STR, s, return -1);
	get_token(s);

	field = IDX_BY_STR(field_str_tbl, s->lexeme, s->len);
	if (!field) {
		PARSER_ERR(s, "invalid HTTP request field");
		return -1;
	}

	s->entry->rule.field = field;

	return 0;
}

static int
parse_op(ParserState *s)
{
	static const char *op_str_tbl[] = {
		[TFW_HTTP_MATCH_O_NA] = STRINGIFY(TFW_HTTP_MATCH_O_NA),
		[TFW_HTTP_MATCH_O_EQ] = "=",
		[TFW_HTTP_MATCH_O_PREFIX] = "^",
	};
	tfw_http_match_op_t op;

	EXPECT(TOKEN_STR, s, return -1);
	get_token(s);

	op = IDX_BY_STR(op_str_tbl, s->lexeme, s->len);
	if (!op) {
		PARSER_ERR(s, "invalid operator");
		return -1;
	}

	s->entry->rule.op = op;

	return 0;
}

static int
parse_arg(ParserState *s)
{
	TfwMatchArg *arg;
	size_t old_size, new_size;

	EXPECT(TOKEN_STR, s, return -1);
	get_token(s);

	old_size = TFW_HTTP_MATCH_CONT_SIZE(MatchEntry, 0);
	new_size = TFW_HTTP_MATCH_CONT_SIZE(MatchEntry, s->len + 1);
	s->entry = tfw_pool_realloc(s->mlst->pool, s->entry, old_size,
				    new_size);
	if (!s->entry) {
		PARSER_ERR(s, "can't reallocate match entry");
		return -1;
	}

	arg = &s->entry->rule.arg;
	arg->len = s->len;
	memcpy(arg->str, s->lexeme, arg->len);
	arg->str[arg->len] = '\0';

	return 0;
}

static int
parse_addr(ParserState *s)
{
	int ret = 0;
	TfwAddr *addr;
	char *pos;
	char buf[IP_ADDR_TEXT_BUF_SIZE + 1];

	EXPECT(TOKEN_STR, s, return -1);
	get_token(s);

	addr = tfw_pool_alloc(s->mlst->pool, sizeof(*addr));
	if (!addr) {
		PARSER_ERR(s, "can't allocate memory for new address");
		return -1;
	}

	memcpy(buf, s->lexeme, s->len);
	buf[s->len] = '\0';
	pos = buf;
	ret = tfw_inet_pton(&pos, addr);

	if (ret) {
		PARSER_ERR(s, "invalid address");
	} else {
		ret = ptrset_add(s->entry->addrs, addr);
		if (ret)
			PARSER_ERR(s, "can't save address");
	}

	return ret;
}

static int
parse_addrs(ParserState *s)
{
	EXPECT(TOKEN_LBRACE, s, return -1);
	get_token(s);

	while (1) {
		token_t t = peek_token(s);
		if (t == TOKEN_RBRACE) {
			get_token(s);
			return 0;
		} else {
			EXPECT(TOKEN_STR, s, return -1);
			if (parse_addr(s))
				return -1;
		}
	}

	return 0;
}

static int
parse_rule(ParserState *s)
{
	return parse_field(s) || parse_op(s) || parse_arg(s) || parse_addrs(s);
}

static int
parse_rules(ParserState *s)
{
	int ret;

	while (peek_token(s)) {
		s->entry = tfw_http_match_entry_new(s->mlst, MatchEntry, rule, 0);
		if (!s->entry) {
			PARSER_ERR(s, "can't allocate new match entry");
			return -1;
		}

		s->entry->addrs = alloc_addrs(s->mlst->pool);
		if (!s->entry->addrs) {
			PARSER_ERR(s, "can't allocate addresses list");
			return -1;
		}

		ret = parse_rule(s);
		if (ret)
			return ret;
	}

	return 0;
}

static TfwHttpMatchList *
run_parser(const char *input)
{
	int ret;
	TfwHttpMatchList *mlst;
	ParserState s = {
		.pos = input,
	};

	mlst = tfw_http_match_list_alloc();
	if (!mlst) {
		ERR("Clsan't allocate match list\n");
		return NULL;
	}
	s.mlst = mlst;

	ret = parse_rules(&s);
	if (ret) {
		tfw_http_match_list_free(mlst);
		mlst = NULL;
	}

	return mlst;
}

static int
handle_sysctl(ctl_table *ctl, int write, void __user *user_buf,
	      size_t *lenp,
	      loff_t *ppos)
{
	int len;
	int ret = 0;
	TfwHttpMatchList *old_rules, *new_rules;

	if (!write) {
		ret = proc_dostring(ctl, write, user_buf, lenp, ppos);
		if (ret)
			ERR("Can't copy data to user-space\n");
		return ret;
	}

	DBG("Copying data to kernel-space\n");
	len = min((size_t )ctl->maxlen, *lenp);
	ret = copy_from_user(ctl->data, user_buf, len);
	if (ret) {
		ERR("Can't copy data from user-space");
		return -1;
	}

	DBG("Parsing copied data\n");
	new_rules = run_parser(ctl->data);
	if (!new_rules) {
		ERR("Can't parse input data\n");
		return -EINVAL;
	}

	DBG("Replacing old rules\n");
	spin_lock_bh(&saved_rules_lock);
	old_rules = saved_rules;
	saved_rules = new_rules;
	spin_unlock_bh(&saved_rules_lock);

	tfw_http_match_list_free(old_rules);

	DBG("Applying new rules\n");
	ret = rebuild_match_list();
	if (ret)
		ERR("Can't apply new rules\n");

	return ret;
}

static struct ctl_table_header *sched_http_ctl;
static char sched_http_ctl_data[RULES_TEXT_BUF_SIZE + 1];
static ctl_table sched_http_ctl_tbl[] = {
	{
		.procname = "sched_http_rules",
		.data = sched_http_ctl_data,
		.maxlen = RULES_TEXT_BUF_SIZE,
		.mode = 0644,
		.proc_handler = handle_sysctl
	},
	{ }
};

/*
 * --------------------------------------------------------------------------
 * Init/Exit routines.
 * --------------------------------------------------------------------------
 */

static TfwScheduler tfw_sched_rr_mod = {
	.name = "http",
	.get_srv = tfw_sched_http_get_srv,
	.add_srv = tfw_sched_http_add_srv,
	.del_srv = tfw_sched_http_del_srv
};

int
tfw_sched_http_init(void)
{
	int ret;

	LOG("init\n");

	added_servers = kzalloc(PTR_SET_SIZE(TFW_SCHED_MAX_SERVERS),
				GFP_KERNEL);
	if (!added_servers) {
		LOG("Can't allocate servers list\n");
		ret = -ENOMEM;
		goto err_alloc;
	}
	added_servers->max = TFW_SCHED_MAX_SERVERS;

	sched_http_ctl = register_net_sysctl(&init_net, "net/tempesta",
					     sched_http_ctl_tbl);
	if (!sched_http_ctl) {
		ret = -1;
		LOG("Can't register the sysctl table\n");
		goto err_sysctl_register;
	}

	ret = tfw_sched_register(&tfw_sched_rr_mod);
	if (ret) {
		LOG("Can't register the scheduler module\n");
		ret = -1;
		goto err_mod_register;
	}

	return ret;

err_mod_register:
	unregister_net_sysctl_table(sched_http_ctl);
err_sysctl_register:
	kfree(added_servers);
err_alloc:
	return ret;
}

void
tfw_sched_http_exit(void)
{
	tfw_sched_unregister();
	unregister_net_sysctl_table(sched_http_ctl);
	kfree(added_servers);
}

module_init(tfw_sched_http_init);
module_exit(tfw_sched_http_exit);

