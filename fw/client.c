/**
 *		Tempesta FW
 *
 * Clients handling.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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
#include <linux/hashtable.h>
#include <linux/slab.h>

#include "lib/hash.h"
#include "hash.h"
#include "client.h"
#include "connection.h"
#include "log.h"
#include "procfs.h"
#include "tdb.h"
#include "lib/str.h"
#include "lib/common.h"

/* Length of comparison of clients entry by User-Agent. */
#define UA_CMP_LEN	256

static struct {
	const char	*db_path;
	unsigned long	db_size;
	unsigned int	lru_size;
} client_cfg __read_mostly;

/**
 * Client tdb entry.
 *
 * @cli			- client descriptor;
 * @xff_addr		- peer IPv6 address from X-Forwarded-For;
 * @user_agent_len	- Length of @user_agent
 * @user_agent		- UA_CMP_LEN first characters of User-Agent
 */
typedef struct {
	TfwClient	cli;
	TfwAddr		xff_addr;
	unsigned long	user_agent_len;
	char		user_agent[UA_CMP_LEN];
} TfwClientEntry;

typedef struct {
	struct list_head	list;
	unsigned long		key;
} TfwClientLRU;

static struct {
	struct list_head	head;
	struct list_head	freelist;
	TfwClientLRU		*mem;
} client_lru;

static TDB *client_db;

/*
 * Called only under db->ga_lock.
 *
 * TODO #515 Rewrite when remove ga_lock.
 */
static void
tfw_client_update_lru(unsigned long key)
{
	if (list_empty(&client_lru.freelist)) {
		/* Free list is empty, get the last from LRU list. */
		TfwClientLRU *last = list_last_entry(&client_lru.head,
						     TfwClientLRU, list);

		list_del_init(&last->list);
		tdb_entry_remove(client_db, last->key, NULL, NULL, false);
		last->key = key;
		list_add(&last->list, &client_lru.head);
	} else {
		TfwClientLRU *new = list_first_entry(&client_lru.freelist,
						     TfwClientLRU, list);

		list_del_init(&new->list);
		new->key = key;
		list_add(&new->list, &client_lru.head);
	}
}

static int
tfw_client_init_lru(void)
{
	TfwClientLRU *block;
	int i, order = get_order(sizeof(TfwClientLRU) * client_cfg.lru_size);

	INIT_LIST_HEAD(&client_lru.freelist);
	INIT_LIST_HEAD(&client_lru.head);

	client_lru.mem = (TfwClientLRU *)__get_free_pages(GFP_ATOMIC, order);
	if (!client_lru.mem) {
		T_ERR("Can't allocate client LRU list.");
		return -ENOMEM;
	}

	for (i = 0, block = client_lru.mem; i < client_cfg.lru_size; i++)
		list_add(&block[i].list, &client_lru.freelist);

	return 0;
}

static void
tfw_client_free_lru(void)
{
	int order = get_order(sizeof(TfwClientLRU) * client_cfg.lru_size);

	free_pages((unsigned long)client_lru.mem, order);
}

/**
 * Called when a client socket is closed.
 */
void
tfw_client_put(TfwClient *cli)
{
	TdbFRec *rec = ((TdbFRec *)cli) - 1;

	T_DBG("put client: cli=%p\n", cli);

	tdb_rec_put(client_db, rec);
}

void
tfw_client_get(TfwClient *cli)
{
	tdb_rec_keep(((TdbFRec *)cli) - 1);
}

typedef struct {
	TfwAddr		addr;
	TfwAddr		xff_addr;
	TfwStr		user_agent;
	unsigned long	key;
	void		(*init)(void *);
} TfwClientEqCtx;

static struct in6_addr any_addr = IN6ADDR_ANY_INIT;

static bool
tfw_client_addr_eq(TdbRec *rec, void *data)
{
	TfwClientEntry *ent = (TfwClientEntry *)rec->data;
	TfwClient *cli = &ent->cli;
	TfwClientEqCtx *ctx = (TfwClientEqCtx *)data;

	if (memcmp_fast(&cli->addr.sin6_addr, &ctx->addr.sin6_addr,
			sizeof(cli->addr.sin6_addr)))
	{
		return false;
	}

#ifdef DISABLED_934
	if (memcmp_fast(&ent->xff_addr.sin6_addr, &ctx->xff_addr.sin6_addr,
			sizeof(ent->xff_addr.sin6_addr)))
	{
		return false;
	}

	if (!tfw_str_eq_cstr(&ctx->user_agent, ent->user_agent,
			     ent->user_agent_len, 0))
	{
		return false;
	}
#endif

	T_DBG("client %p was found in tdb\n", cli);

	return true;
}

static void
tfw_client_ent_init(TdbRec *rec, void *data)
{
	TfwClientEntry *ent = (TfwClientEntry *)rec->data;
	TfwClient *cli = &ent->cli;
	TfwClientEqCtx *ctx = (TfwClientEqCtx *)data;

	bzero_fast(&cli->class_prvt, sizeof(cli->class_prvt));
	if (ctx->init)
		ctx->init(cli);

	tfw_peer_init((TfwPeer *)cli, &ctx->addr);
	atomic_set(&cli->mem, 0);
	ent->xff_addr = ctx->xff_addr;
	tfw_str_to_cstr(&ctx->user_agent, ent->user_agent,
			sizeof(ent->user_agent));
	ent->user_agent_len = min(ctx->user_agent.len, sizeof(ent->user_agent));

	T_DBG("new client: cli=%p\n", cli);
	T_DBG_ADDR("client address", &cli->addr, TFW_NO_PORT);
	T_DBG2("client %p, users=%d\n", cli, 1);
}

static int
tfw_client_precreate(void *data)
{
	TfwClientEqCtx *ctx = (TfwClientEqCtx *)data;

	tfw_client_update_lru(ctx->key);

	return 0;
}

/**
 * Find a client corresponding to @addr, @xff_addr (e.g. from X-Forwarded-For)
 * and @user_agent.
 *
 * The returned TfwClient reference must be released via tfw_client_put()
 * when the @sk is closed.
 * TODO #515 employ eviction strategy for the table.
 */
TfwClient *
tfw_client_obtain(TfwAddr addr, TfwAddr *xff_addr, TfwStr *user_agent,
		  void (*init)(void *))
{
	TfwClientEntry *ent;
	TfwClient *cli;
	unsigned long key;
	TfwClientEqCtx ctx = { .init = init };
	TdbRec *rec;
	TdbGetAllocCtx tdb_ctx = { 0 };

	ctx.addr = addr;

	key = hash_calc((const char *)&addr.sin6_addr,
			sizeof(addr.sin6_addr));

#ifdef DISABLED_934
	if (xff_addr) {
		key ^= hash_calc((const char *)&xff_addr->sin6_addr,
				 sizeof(xff_addr->sin6_addr));
		ctx.xff_addr = *xff_addr;
	} else {
		ctx.xff_addr.sin6_addr = any_addr;
	}
#else
	ctx.xff_addr.sin6_addr = any_addr;
#endif

#ifdef DISABLED_934
	if (user_agent) {
		key ^= tfw_hash_str_len(user_agent, UA_CMP_LEN);
		ctx.user_agent = *user_agent;
	} else {
		TFW_STR_INIT(&ctx.user_agent);
	}
#else
	TFW_STR_INIT(&ctx.user_agent);
#endif
	ctx.key = key;

	tdb_ctx.eq_rec =  tfw_client_addr_eq;
	tdb_ctx.init_rec = tfw_client_ent_init;
	tdb_ctx.precreate_rec = tfw_client_precreate;
	tdb_ctx.len = sizeof(TfwClientEntry);
	tdb_ctx.ctx = &ctx;
	rec = tdb_rec_get_alloc(client_db, key, &tdb_ctx);
	BUG_ON(tdb_ctx.len < sizeof(TfwClientEntry));
	if (!rec) {
		T_WARN("cannot allocate TDB space for client\n");
		return NULL;
	}

	ent = (TfwClientEntry *)rec->data;
	cli = &ent->cli;
	return cli;
}
EXPORT_SYMBOL(tfw_client_obtain);
ALLOW_ERROR_INJECTION(tfw_client_obtain, NULL);

/**
 * Beware: @fn is called under client hash bucket spin lock.
 *
 * TODO #515: tfw_client_for_each() can cause a scheduler stall message in
 * kernel log. Earlier TfwClients were organised as a list and looping through
 * all the clients involved a schedule() call like all other long loops in
 * process context. So it was safe to dive into a long tfw_client_for_each()
 * loop. But after TDB become the storage for TfwClient instances, a new
 * procedure tdb_entry_walk() was introduced, that can grab the scheduler for
 * a long time while interrupts are disabled.
 */
int
tfw_client_for_each(int (*fn)(void *))
{
	if (!client_db)
		return 0;
	return tdb_entry_walk(client_db, fn);
}

static int
tfw_client_start(void)
{
	if (tfw_runstate_is_reconfig())
		return 0;
	/*
	 * The TfwClientEntry is used as direct pointer to data  inside a TDB
	 * entry. Small entries may be moved between locations as index tree
	 * grows, while big ones has constant location.
	 */
	BUILD_BUG_ON(sizeof(TfwClientEntry) <= TDB_HTRIE_MINDREC);
	client_db = tdb_open(client_cfg.db_path, client_cfg.db_size,
			     sizeof(TfwClientEntry), numa_node_id());
	if (!client_db)
		return -EINVAL;

	if (tfw_client_init_lru())
		return -EINVAL;

	return 0;
}

static void
tfw_client_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;
	if (client_db) {
		tdb_close(client_db);
		client_db = NULL;
	}

	tfw_client_free_lru();
}

static TfwCfgSpec tfw_client_specs[] = {
	{
		.name = "client_tbl_size",
		.deflt = "16M",
		.handler = tfw_cfg_set_mem,
		.dest = &client_cfg.db_size,
		.spec_ext = &(TfwCfgSpecMem) {
			.multiple_of = "4K",
			.range = { "4K", "1G" },
		}
	},
	{
		.name = "client_db",
		.deflt = "/opt/tempesta/db/client.tdb",
		.handler = tfw_cfg_set_str,
		.dest = &client_cfg.db_path,
		.spec_ext = &(TfwCfgSpecStr) {
			.len_range = { 1, PATH_MAX },
		}
	},
	{
		.name = "client_lru_size",
		.deflt = "8000",
		.handler = tfw_cfg_set_int,
		.dest = &client_cfg.lru_size,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 1, UINT_MAX },
		},
	},
	{ 0 }
};

TfwMod tfw_client_mod = {
	.name 	= "client",
	.start	= tfw_client_start,
	.stop	= tfw_client_stop,
	.specs	= tfw_client_specs,
};

int __init
tfw_client_init(void)
{
	tfw_mod_register(&tfw_client_mod);

	return 0;
}

void
tfw_client_exit(void)
{
	tfw_mod_unregister(&tfw_client_mod);
}
