/**
 *		Tempesta FW
 *
 * Clients handling.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2026 Tempesta Technologies, Inc.
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
#include "filter.h"
#include "log.h"
#include "procfs.h"
#include "tdb.h"
#include "training.h"
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

static struct {
	struct list_head	head;
	unsigned int		lru_size;
} client_lru;

static TDB *client_db;

/*
 * Called only under db->ga_lock.
 *
 * TODO #515 Rewrite when remove ga_lock.
 */
static void
tfw_client_update_lru(TfwClient *cli)
{
	if (client_lru.lru_size >= client_cfg.lru_size) {
		/*
		 * Count of clients exceeded configured lru size, remove
		 * previos added client from lru list and try to remove it
		 * from TDB.
		 */
		TfwClient *last = list_last_entry(&client_lru.head,
						  TfwClient, list);

		list_del_init(&last->list);
		tfw_client_put(last);
		list_add(&cli->list, &client_lru.head);
	} else {
		list_add(&cli->list, &client_lru.head);
		client_lru.lru_size++;
	}
}

static void
tfw_client_free(TdbRec *rec)
{
	TfwClientEntry *ent = (TfwClientEntry *)rec->data;
	TfwClient *cli = &ent->cli;

	/*
	 * Client always has extra reference counter, so
	 * it can be deleted only when client_lru.lru_size is
	 * exceeded from `tfw_client_update_lru` or when
	 * Tempesta FW shut down from `tfw_client_free_lru`
	 */
	WARN_ON(!list_empty(&cli->list));
	tfw_training_stat_destroy(&cli->req_stat);
	tfw_training_stat_destroy(&cli->cpu_stat);
	free_percpu(cli->cpu_usage);
}

static void
tfw_client_init_lru(void)
{
	INIT_LIST_HEAD(&client_lru.head);
	client_lru.lru_size = 0;
}

static void
tfw_client_free_lru(void)
{
	TfwClient *curr, *tmp;

	spin_lock_bh(&client_db->ga_lock);

	list_for_each_entry_safe(curr, tmp, &client_lru.head, list) {
		list_del_init(&curr->list);
		client_lru.lru_size--;
		tfw_client_put(curr);
	}

	spin_unlock_bh(&client_db->ga_lock);

	WARN_ON(client_lru.lru_size);
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

static int
tfw_client_ent_init(TdbRec *rec, void *data)
{
	TfwClientEntry *ent = (TfwClientEntry *)rec->data;
	TfwClient *cli = &ent->cli;
	TfwClientEqCtx *ctx = (TfwClientEqCtx *)data;
	int r;

	r = tfw_training_stat_init(&cli->req_stat);
	if (unlikely(r))
		return r;

	r = tfw_training_stat_init(&cli->cpu_stat);
	if (unlikely(r))
		return r;

	cli->cpu_usage =
		tfw_alloc_percpu_gfp(TfwCpuHistory, GFP_ATOMIC | __GFP_ZERO);
	if (unlikely(!cli->cpu_usage))
		return -ENOMEM;

	assert_spin_locked(&client_db->ga_lock);

	INIT_LIST_HEAD(&cli->list);
	tfw_client_update_lru(cli);

	bzero_fast(&cli->class_prvt, sizeof(cli->class_prvt));
	if (ctx->init)
		ctx->init(cli);

	cli->conn_max = 0;

	tfw_peer_init((TfwPeer *)cli, &ctx->addr);
	ent->xff_addr = ctx->xff_addr;
	tfw_str_to_cstr(&ctx->user_agent, ent->user_agent,
			sizeof(ent->user_agent));
	ent->user_agent_len = min(ctx->user_agent.len, sizeof(ent->user_agent));

	T_DBG("new client: cli=%p\n", cli);
	T_DBG_ADDR("client address", &cli->addr, TFW_NO_PORT);
	T_DBG2("client %p, users=%d\n", cli, 1);

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

bool
tfw_client_training_adjust_conn_num(TfwClient *cli, unsigned int conn_curr)
{
	u64 delta1, delta2;
	unsigned int old_max;
	bool new_client = false;

	if (tfw_mode_is_disabled())
		return true;

	if (tfw_mode_is_defence())
		return tfw_training_mode_defence_conn_num(conn_curr);

	/*
	 * This function same as all `*_conn_num` functions are called
	 * under ra->lock (private lock inside client), so we don't need
	 * any synchronization here.
	 */
	if (cli->conn_training_num < g_training_num) {
		cli->conn_training_num = g_training_num;
		cli->conn_max = 0;
		new_client = true;
	}

	old_max = cli->conn_max;
	if (conn_curr <= old_max)
		return true;
	cli->conn_max = conn_curr;
	delta1 = conn_curr - old_max;
	delta2 = (u64)conn_curr * conn_curr - (u64)old_max * old_max;
	tfw_training_mode_adjust_conn_num(delta1, delta2, new_client);

	return true;
}

bool
tfw_client_training_adjust_cpu_num(TfwClient *cli, u64 begin_time)
{
	static const u64 min_time_to_adjust = 1000;
	const unsigned short ticks = HZ / CPU_HISTORY_WINDOW;
	const unsigned long ts = tfw_time_quantum(ticks);
	unsigned int i = ts % CPU_HISTORY_WINDOW;
	TfwCpuHistory *cpu_usage = this_cpu_ptr(cli->cpu_usage);
	u64 now = ktime_get_ns();
	u64 total_bucket_cpu = 0;
	u64 delta_cpu = now - begin_time;
	u64 dt, usage, total = 0;

	if (cpu_usage->buckets[i].slot_ts != ts) {
		cpu_usage->buckets[i].usage = 0;
		cpu_usage->buckets[i].pending_cpu = 0;
		cpu_usage->buckets[i].slot_ts = ts;
	}

	cpu_usage->buckets[i].pending_cpu += delta_cpu;
	if (!cpu_usage->ts) {
		cpu_usage->ts = now;
		return true;
	}

	dt = now - cpu_usage->ts;
	cpu_usage->ts = now;
	if (dt < min_time_to_adjust)
		return true;

	swap(total_bucket_cpu, cpu_usage->buckets[i].pending_cpu);
	usage = (total_bucket_cpu << SCALE_SHIFT) / dt;
	cpu_usage->buckets[i].usage += usage;
	
	TFW_SUMM_IN_FRAME(ts, cpu_usage->buckets[iter].slot_ts, {
		total += cpu_usage->buckets[iter].usage;
	});

	return tfw_training_mode_update_cpu_num_stat(&cli->cpu_stat, total);
}

void
tfw_client_filter_block_ip(TfwClient *cli)
{
	TfwVhost *dflt_vh = tfw_vhost_lookup_default();

	if (WARN_ON_ONCE(!dflt_vh))
		return;

	if (dflt_vh->frang_gconf->ip_block)
		tfw_filter_block_ip(cli,
				    dflt_vh->frang_gconf->ip_block_duration);

	tfw_vhost_put(dflt_vh);
}

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

	client_db->hdr->before_free = tfw_client_free;
	tfw_client_init_lru();

	return 0;
}

static void
tfw_client_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;
	if (client_db) {
		tfw_client_free_lru();
		tdb_close(client_db);
		client_db = NULL;
	}
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
