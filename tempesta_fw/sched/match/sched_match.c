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

#include <linux/rcupdate.h>

#include "sched.h"
#include "server.h"
#include "http.h"

#include "tfw_sched_match.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta request-matching scheduler");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");


/* How does the scheduler work:
 *
 * There is a global matching table that contains rules of the following format:
 *  { subject,   operator,  pattern,        servers_list }
 * For example:
 *  { SUBJ_HOST, OP_EQUAL,  "example.com", { TfwServer, TfwServer, TfwServer } }
 *  { SUBJ_URI,  OP_PREFIX, "/foo/bar",    { TfwServer } }
 *  { SUBJ_URI,  OP_PREFIX, "/",           { TfwServer, TfwServer } }
 *
 * The 'subject' determines a field of a HTTP request (uri, host, header, etc).
 * The 'operator' determines how to compare the field with the 'pattern'.
 * Each incoming HTTP request is sequentially matched against each entry in the
 * table until. If a matching entry is found, then the algorithm stops and
 * returns a server from the list.
 *
 */

typedef struct {
	u16 counter;
	u8  srv_max;
	u8  srv_n;
	TfwServer *srv[0];
} SrvList;

#define SIZE_OF_SRV_LIST(n) (sizeof(SrvList) + sizeof(TfwServer) * (n))


typedef struct {
	subj_t 	subj;
	op_t   	op;
	short 	len;
	const char *pattern;
	SrvList *servers;
} MatchTblEntry;

typedef struct {
	int count;
	MatchTblEntry *entries[RULE_MAX_COUNT];
	TfwPool *pool;
} MatchTbl;


/**
 * The table is not updated in-place.
 * Instead, each time something is modified, a new table is built and the
 * pointer is replaced via RCU.
 */
static MatchTbl *match_tbl = NULL;
static SrvList *added_servers = NULL;
static RuleTbl rule_tbl;

DEFINE_SPINLOCK(sched_match_write_lock);


static void
dbg_print_entry(const char *msg, const MatchTblEntry *e, bool print_servers)
{
	DBG("%s: subj=%d op=%d pattern='%.*s'\n",
	    msg, e->subj, e->op, e->len, e->pattern);

	if (print_servers) {
		int i;
		char buf[32];
		const SrvList *s = e->servers;

		DBG("Servers (total %d):\n", s->srv_n);

		for (i = 0; i < s->srv_n; ++i) {
			tfw_server_snprint(s->srv[i], buf, sizeof(buf));
			DBG("  #%d - %s\n", i, buf);
		}
	}
}


static int
srv_list_find(const SrvList *list, const TfwServer *srv)
{
	int i;

	BUG_ON(!list || !srv);

	for (i = 0; i < list->srv_n; ++i) {
		if (list->srv[i] == srv)
			return i;
	}

	return -1;
}

static int
srv_list_add(SrvList *list, TfwServer *srv)
{
	BUG_ON(!list || !srv);

	if (srv_list_find(list, srv) > 0) {
		ERR("The server is already present in the list\n");
		return -EEXIST;
	} else if (list->srv_n >= list->srv_max) {
		ERR("No space left in the servers list\n");
		return -ENOMEM;
	}

	list->srv[list->srv_n] = srv;
	++list->srv_n;

	return 0;
}

static int
srv_list_del(SrvList *list, TfwServer *srv)
{
	int idx;

	BUG_ON(!list || !srv);

	idx = srv_list_find(list, srv);

	if (idx < 0) {
		ERR("Server is not found in the list\n");
		return -ENOENT;
	}

	list->srv[idx] = list->srv[list->srv_n - 1];
	list->srv[list->srv_n] = NULL;
	--list->srv_n;

	return 0;
}

static TfwServer *
srv_list_get_rr(SrvList *list)
{
	unsigned int n;
	TfwServer *srv;

	BUG_ON(!list);

	do {
		n = list->srv_n;
		if (!n) {
			ERR("The servers list is empty\n");
			return NULL;
		}

		srv = list->srv[list->counter++ % n];
	} while (!srv);

	return srv;
}

static TfwServer *
srv_list_get_by_addr(const SrvList *list, const TfwAddr *addr)
{
	int i;
	int ret;
	TfwServer *curr_srv;
	TfwAddr curr_addr;

	BUG_ON(!list || !addr);

	for (i = 0; i < list->srv_n; ++i) {
		curr_srv = list->srv[i];

		ret = tfw_server_get_addr(curr_srv, &curr_addr);
		if (ret) {
			ERR("Can't obtain address of the server: %p\n", curr_srv);
			return NULL;
		}

		if (tfw_addr_eq(addr, &curr_addr)) {
			return curr_srv;
		}
	}

	return NULL;
}


/**
 * Merge a table of rules and a list of servers into a single matching table.
 *
 * The function copies elements from @rule_tbl into @tbl and resolves IP
 * addresses to TfwServer objects from the given @all_servers list.
 *
 * @rule_tbl Contains a set of rules and corresponding IP addresses.
 * @all_servers Contains a list of all known servers.
 *
 * @tbl The output table to be filled.
 *      Not allocated automatically, upon the call it must be pre-allocated
 *      using tfw_pool_new().
 *
 * Also, the function uses @tbl->pool to allocate new elements, so you are
 * responsible for freeing them, even if the function returns an error.
 */
int
fill_match_tbl(const RuleTbl *rule_tbl, const SrvList *all_servers, MatchTbl *tbl)
{
	int rule_idx, addr_idx, pattern_len;
	char *pattern;
	const Rule *rule;
	MatchTblEntry *entry;
	SrvList *servers;

	for (rule_idx = 0; rule_idx < rule_tbl->rules_n; ++rule_idx) {
		rule = &rule_tbl->rules[rule_idx];
		pattern_len = strnlen(rule->pattern, sizeof(rule->pattern));

		entry = tfw_pool_alloc(tbl->pool, sizeof(*entry));
		pattern = tfw_pool_alloc(tbl->pool, pattern_len);
		servers = tfw_pool_alloc(tbl->pool, SIZE_OF_SRV_LIST(rule->addrs_n));
		if (!entry || !pattern || !servers) {
			ERR("Can't allocate memory\n");
			return -1;
		}

		servers->srv_max = rule->addrs_n;

		for (addr_idx = 0; addr_idx < rule->addrs_n; ++addr_idx) {
			const TfwAddr *addr = &rule->addrs[addr_idx];
			TfwServer *srv = srv_list_get_by_addr(all_servers, addr);
			if (srv) {
				srv_list_add(servers, srv);
			} else {
				TFW_ERR_ADDR("No server found for addr", addr);
			}
		}

		memcpy(pattern, rule->pattern, pattern_len);
		entry->subj = rule->subj;
		entry->op = rule->op;
		entry->pattern = pattern;
		entry->len = pattern_len;
		entry->servers = servers;

		tbl->entries[tbl->count++] = entry;
	}

	return 0;
}


/**
 * The function does two things:
 * 1. Builds new MatchTbl from a set of Rules (stored in 'rule_tbl') and a set
 *    of online servers (stored in 'added_servers').
 * 2. Replace the global 'match_tbl' with a fresh one using the RCU mechanism.
 *
 * It should be called when rules or servers are changed.
 */
static int
refresh_match_tbl(void)
{
	int ret;
	MatchTbl *old_tbl, *new_tbl;

	new_tbl = tfw_pool_new(MatchTbl, TFW_POOL_ZERO);
	if (!new_tbl) {
		ERR("Can't create a new matching tabe\n");
		return -1;
	}

	spin_lock_bh(&sched_match_write_lock);
	ret = fill_match_tbl(&rule_tbl, added_servers, new_tbl);
	spin_unlock_bh(&sched_match_write_lock);

	if (ret) {
		ERR("Can't fill a new matching table\n");
		tfw_pool_free(new_tbl->pool);
		return ret;
	}

	DBG("Replacing the matching table\n");

	old_tbl = match_tbl;
	rcu_assign_pointer(match_tbl, new_tbl);
	synchronize_rcu();

	if (old_tbl) {
		DBG("Freeing old matching table\n");
		tfw_pool_free(old_tbl->pool);
	}

	return 0;
}

/**
 * Evaluate an "expression" of a form: (subject [operator] pattern).
 *
 * The function maps a given @op to a C function that compares strings,
 * passes arguments @str and @cstr to it and returns the result of comparison.
 */
static bool
apply_str_op(op_t op, const TfwStr *str, const char *cstr, int cstr_len)
{

	static const typeof(&tfw_str_eq_cstr_ci) fns[] = {
		[OP_EQUAL] = tfw_str_eq_cstr_ci,
		[OP_PREFIX] = tfw_str_startswith_cstr_ci,
	};

	BUG_ON(op >= ARRAY_SIZE(fns));
	BUG_ON(!fns[op]);

	return fns[op](str, cstr, cstr_len);
}


static bool
match_uri(const TfwHttpReq *r, const MatchTblEntry *e)
{
	return apply_str_op(e->op, &r->uri, e->pattern, e->len);
}

static bool
match_host(const TfwHttpReq *r, const MatchTblEntry *e)
{
	const TfwStr *host = &r->host;

	if (!host)
		host = &r->h_tbl->tbl[TFW_HTTP_HDR_HOST].field;

	return apply_str_op(e->op, host, e->pattern, e->len);
}

static bool
match_any_header(const TfwHttpReq *r, const MatchTblEntry *e)
{
	int i;
	TfwStr *hdr;
	TfwHttpHdrTbl *tbl = r->h_tbl;

	for (i = 0; i < tbl->size; ++i) {
		hdr = &tbl->tbl[i].field;
		if (apply_str_op(e->op, hdr, e->pattern, e->len))
			return true;

	}

	return false;
}

static bool
match(const TfwHttpReq *req, const MatchTblEntry *entry)
{
	static const typeof(&match_uri) fns[] = {
		[SUBJ_HOST] 	= match_host,
		[SUBJ_URI] 	= match_uri,
		[SUBJ_HEADER] 	= match_any_header,
	};
	subj_t subj = entry->subj;

	BUG_ON(subj >= ARRAY_SIZE(fns));
	BUG_ON(!fns[subj]);

	return fns[subj](req, entry);
}


static TfwServer *
do_matches(const TfwHttpReq *req, const MatchTbl *tbl)
{
	int i;
	MatchTblEntry *entry;
	TfwServer *srv;

	DBG("Matching request: %p against %d rules\n", req, tbl->count);

	for (i = 0; i < tbl->count; ++i) {
		entry = tbl->entries[i];

		if (match(req, entry)) {
			dbg_print_entry("Match", entry, true);

			srv = srv_list_get_rr(entry->servers);
			if (srv)
				return srv;
		} else {
			dbg_print_entry("No match", entry, false);
		}
	}

	return NULL;
}

TfwServer *
tfw_sched_match_get_srv(TfwMsg *msg)
{
	TfwServer *srv = NULL;
	MatchTbl *tbl = NULL;

	if (!added_servers->srv_n) {
		ERR("The scheduler's server list is empty\n");
		return NULL;
	}

	rcu_read_lock();
	tbl = rcu_dereference(match_tbl);
	if (!tbl) {
		ERR("The scheduler's matchig table is empty\n");
	} else {
		srv = do_matches((TfwHttpReq *)msg, tbl);
	}
	rcu_read_unlock();

	if (!srv)
		ERR("A matching server is not found\n");

	return srv;
}


int
tfw_sched_match_add_srv(TfwServer *srv)
{
	int ret = 0;

	DBG("Adding server: %p\n", srv);

	spin_lock_bh(&sched_match_write_lock);
	ret = srv_list_add(added_servers, srv);
	spin_unlock_bh(&sched_match_write_lock);

	if (ret) {
		ERR("Can't add the server to the scheduler: %p\n", srv);
		return -1;
	}

	ret = refresh_match_tbl();
	if (ret) {
		ERR("Can't re-build the matching table\n");
	}

	return ret;
}

int
tfw_sched_match_del_srv(TfwServer *srv)
{
	int ret = 0;

	DBG("Deleting server: %p\n", srv);

	spin_lock_bh(&sched_match_write_lock);
	ret = srv_list_del(added_servers, srv);
	spin_unlock_bh(&sched_match_write_lock);

	if (ret) {
		ERR("Can't delete the server from the scheduler: %p\n", srv);
		return -1;
	}

	ret = refresh_match_tbl();
	if (ret) {
		ERR("Can't refresh the matching table\n");
	}

	return ret;
}


int
apply_new_rules(const RuleTbl *tbl)
{
	int ret;

	DBG("Applying new matching rules\n");

	spin_lock_bh(&sched_match_write_lock);
	memcpy(&rule_tbl, tbl, sizeof(rule_tbl));
	spin_unlock_bh(&sched_match_write_lock);

	ret = refresh_match_tbl();
	if (ret) {
		ERR("Can't refresh the matching table\n");
	}

	return ret;
}


extern int sysctl_register(void);
extern void sysctl_unregister(void);

int
tfw_sched_match_init(void)
{
	int ret;

	static TfwScheduler tfw_sched_rr_mod = {
		.name = "match",
		.get_srv = tfw_sched_match_get_srv,
		.add_srv = tfw_sched_match_add_srv,
		.del_srv = tfw_sched_match_del_srv
	};

	LOG("init\n");

	added_servers = kzalloc(SIZE_OF_SRV_LIST(TFW_SCHED_MAX_SERVERS), GFP_KERNEL);
	if (!added_servers) {
		ERR("Can't allocate servers list\n");
		return -ENOMEM;
	}
	added_servers->srv_max = TFW_SCHED_MAX_SERVERS;


	ret = sysctl_register();
	if (ret) {
		ERR("Can't register the sysctl table\n");
		return ret;
	}

	ret = tfw_sched_register(&tfw_sched_rr_mod);
	if (ret) {
		ERR("Can't register the scheduler module\n");
	}

	return ret;
}
module_init(tfw_sched_match_init);

void
tfw_sched_match_exit(void)
{
	tfw_sched_unregister();
	sysctl_unregister();
	kfree(added_servers);
}
module_exit(tfw_sched_match_exit);


