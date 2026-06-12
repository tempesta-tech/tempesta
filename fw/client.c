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
#include "lib/fault_injection_alloc.h"
#include "training.h"
#include "lib/str.h"
#include "lib/common.h"

/* Length of comparison of clients entry by User-Agent. */
#define UA_CMP_LEN	256

static struct {
	const char		*db_path;
	unsigned long		db_size;
	unsigned int		lru_size;
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
	TfwClient		cli;
	TfwAddr			xff_addr;
	unsigned long		user_agent_len;
	char			user_agent[UA_CMP_LEN];
} TfwClientEntry;

static struct {
	struct list_head	head;
	unsigned int     	lru_size;
} client_lru = {
	.head = LIST_HEAD_INIT(client_lru.head),
	.lru_size = 0,
};

static TDB *client_db;

static atomic_t shutdown_pending = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(shutdown_wq);

static struct kmem_cache *tfw_cli_counters_cache;
static struct {
	TfwClientCounters	*objs;
	TfwClientCounters	*free_list;
	unsigned int		size;
	unsigned int		order;
} cli_counters_pool;

static int
tfw_client_counter_init(TfwClientCounter *counter, gfp_t flags)
{
	counter->counter = tfw_alloc_percpu_gfp(s64, flags | __GFP_ZERO);
	if (unlikely(!counter->counter))
		return -ENOMEM;

	spin_lock_init(&counter->lock);
	atomic64_set(&counter->max, 0);
	counter->epoch = 0;

	return 0;
}

static void
tfw_client_counter_destroy(TfwClientCounter *counter)
{
	free_percpu(counter->counter);
	counter->counter = NULL;
}

static inline bool
tfw_cli_counters_belongs_to_pool(TfwClientCounters *counters)
{
	return counters >= cli_counters_pool.objs
	       && counters < cli_counters_pool.objs + cli_counters_pool.size;
}

static inline void
tfw_cli_mem_destroy(TfwClientMem *cli_mem)
{
	free_percpu(cli_mem->mem);
	tfw_client_counter_destroy(&cli_mem->counter);
}

static void
__cli_counters_release(TfwClientCounters *counters)
{
	percpu_ref_exit(&counters->refcnt);
	tfw_cli_mem_destroy(&counters->cli_mem);
	tfw_client_counter_destroy(&counters->req_counter);
	if (!tfw_cli_counters_belongs_to_pool(counters))
		kmem_cache_free(tfw_cli_counters_cache, counters);
}

/*
 * Reset counters, reinit refcnt and put `counters` back to the pool.
 * Should be called under `ga_lock`, to protect `cli_counters_pool.free_list`.
 */
static inline void
tfw_cli_counters_pool_free(TfwClientCounters *counters)
{
	int cpu;

	assert_spin_locked(&client_db->ga_lock);

	for_each_online_cpu(cpu) {
		*per_cpu_ptr(counters->cli_mem.mem, cpu) = 0;
		*per_cpu_ptr(counters->cli_mem.counter.counter, cpu) = 0;
		*per_cpu_ptr(counters->req_counter.counter, cpu) = 0;
		*per_cpu_ptr(counters->cpu_ema_counter.counter, cpu) = 0;
	}
	percpu_ref_reinit(&counters->refcnt);
	counters->next_free = cli_counters_pool.free_list;
	cli_counters_pool.free_list = counters;
}

/*
 * Workqueue handler for asynchronous cli_mem destruction.
 *
 * This function initiates final teardown of a TfwClientCounters object:
 *  - percpu_ref_kill() marks the refcount as dead, preventing any new
 *    users from acquiring references.
 *  - percpu_ref_put() drops the caller’s reference, which may trigger
 *    final release via cli_counters_release() once all outstanding users
 *    are gone.
 */
static void
tfw_cli_counters_kill_work_fn(struct work_struct *work)
{
	TfwClientCounters *counters =
		container_of(work, TfwClientCounters, kill_work);

	percpu_ref_kill(&counters->refcnt);
	percpu_ref_put(&counters->refcnt);
}

/*
 * Get `TfwClientCounters` object from pool if present.
 * Object was already initialized during pool creation or
 * releasing to pool.
 */
static inline TfwClientCounters *
tfw_cli_counters_pool_alloc(void)
{
	TfwClientCounters *counters;

	assert_spin_locked(&client_db->ga_lock);

	if (!cli_counters_pool.free_list)
		return NULL;

	counters = cli_counters_pool.free_list;
	cli_counters_pool.free_list = counters->next_free;
	/*
	 * Should be called only after `free_list` initialization
	 * using `next_free` pointer, because `next_free` and
	 * `kill_work` members belong to the same union.
	 */
	INIT_WORK(&counters->kill_work, tfw_cli_counters_kill_work_fn);

	return counters;
}

/*
 * Final release of counters: verify refcnt/memory are zero and either
 * return to pool or free it. Signals shutdown completion if needed.
 */
static void
cli_counters_release(struct percpu_ref *ref)
{
	TfwClientCounters *counters =
		container_of(ref, TfwClientCounters, refcnt);

	spin_lock_bh(&client_db->ga_lock);

	WARN_ON_ONCE(!percpu_ref_is_zero(ref));
	WARN_ON_ONCE(tfw_client_mem(&counters->cli_mem));
	if (tfw_cli_counters_belongs_to_pool(counters))
		tfw_cli_counters_pool_free(counters);
	else
		__cli_counters_release(counters);

	spin_unlock_bh(&client_db->ga_lock);

	if (atomic_dec_and_test(&shutdown_pending))
		wake_up(&shutdown_wq);
}

static inline int
tfw_cli_mem_init(TfwClientMem *cli_mem, gfp_t flags)
{
	int r;

	r = tfw_client_counter_init(&cli_mem->counter, flags);
	if (unlikely(r))
		return r;

	cli_mem->mem = tfw_alloc_percpu_gfp(s64, flags | __GFP_ZERO);
	if (unlikely(!cli_mem->mem)) {
		r = -ENOMEM;
		goto counter_destroy;
	}

	return 0;

counter_destroy:
	tfw_client_counter_destroy(&cli_mem->counter);

	return r;
}

static inline int
tfw_cli_counters_init(TfwClientCounters *counters, gfp_t flags)
{
	TfwClientMem *cli_mem = &counters->cli_mem;
	TfwClientCounter *req_counter = &counters->req_counter;
	TfwClientCounter *cpu_ema_counter = &counters->cpu_ema_counter;
	int r;

	r = tfw_cli_mem_init(cli_mem, flags);
	if (unlikely(r))
		return r;

	r = tfw_client_counter_init(req_counter, flags);
	if (unlikely(r))
		goto cli_mem_destroy;

	r = tfw_client_counter_init(cpu_ema_counter, flags);
	if (unlikely(r))
		goto req_counter_destroy;

	r = tfw_percpu_ref_init(&counters->refcnt, cli_counters_release,
				PERCPU_REF_ALLOW_REINIT, flags);
	if (unlikely(r))
		goto cpu_ema_counter_destroy;

	return 0;

cpu_ema_counter_destroy:
	tfw_client_counter_destroy(cpu_ema_counter);
req_counter_destroy:
	tfw_client_counter_destroy(req_counter);
cli_mem_destroy:
	tfw_cli_mem_destroy(cli_mem);
	
	return r;
}

static inline void
tfw_cli_counters_pool_exit(void)
{
	TfwClientCounters *tmp, *curr = cli_counters_pool.free_list;

	while (curr) {
		tmp = curr;
		curr = tmp->next_free;
		__cli_counters_release(tmp);
	}

	free_pages((unsigned long)cli_counters_pool.objs, cli_counters_pool.order);
	bzero_fast(&cli_counters_pool, sizeof(cli_counters_pool));
}

/*
 * Initialize cli_counters pool.
 *
 * Allocates a contiguous block of TfwClientCounters objects and initializes
 * each element, then builds a free list for fast allocation.
 *
 * Steps:
 *  - Validate pool size from configuration.
 *  - Compute allocation order and clamp it to MAX_PAGE_ORDER.
 *  - Allocate zeroed pages for the entire pool.
 *  - Initialize each TfwClientCounters (per-cpu counters + refcnt + work).
 *  - Link all objects into a singly-linked free list.
 *
 * Provide fast allocations of `TfwClientCounters` later.
 */
static inline int
tfw_cli_counters_pool_init(void)
{
	TfwClientCounters *block, *tail = NULL;
	unsigned int i, order;
	int r;

	if (WARN_ON_ONCE(!client_cfg.lru_size))
		return -EINVAL;

	order = get_order(sizeof(TfwClientCounters) * client_cfg.lru_size);
	if (order > MAX_PAGE_ORDER)
		order = MAX_PAGE_ORDER;

	cli_counters_pool.order = order;
	cli_counters_pool.objs =
		(TfwClientCounters *)tfw__get_free_pages(GFP_KERNEL,
							 order);
	if (unlikely(!cli_counters_pool.objs))
		return -ENOMEM;

	/*
	 * Initialize pool in forward order and build free_list as
	 * 0 -> 1 -> ... -> N-1.
	 *
	 * This preserves the natural memory layout of the preallocated array,
	 * which is important because tfw_cli_counters_belongs_to_pool() relies
	 * on the pool being a contiguous range [objs, objs + size).
	 *
	 * Using tail insertion avoids reversing the order (which would happen
	 * with head insertion) and keeps allocation predictable and
	 * cache-friendly.
	 */
	block = cli_counters_pool.objs;
	for (i = 0; i < client_cfg.lru_size; i++) {
		r = tfw_cli_counters_init(&block[i], GFP_KERNEL);
		if (unlikely(r))
			return r;

		if (!cli_counters_pool.free_list)
			cli_counters_pool.free_list = &block[i];
		else
			tail->next_free = &block[i];

		block[i].next_free = NULL;
		tail = &block[i];
		cli_counters_pool.size++;
	}

	return 0;
}

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
	if (likely(cli->counters)) {
		atomic_inc(&shutdown_pending);
		if (!schedule_work(&cli->counters->kill_work))
			atomic_dec(&shutdown_pending);
	}
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

/*
 * Allocate cli_mem from slab cache and fully initialize it.
 * Used as a fallback when pool allocation is exhausted.
 */
static inline TfwClientCounters *
tfw_cli_counters_alloc_from_cache(void)
{
	TfwClientCounters *counters;

	counters = kmem_cache_alloc(tfw_cli_counters_cache, GFP_ATOMIC);
	if (unlikely(!counters))
		return NULL;

	if (unlikely(tfw_cli_counters_init(counters, GFP_ATOMIC)))
		goto free_cli_counters;

	INIT_WORK(&counters->kill_work, tfw_cli_counters_kill_work_fn);
	return counters;

free_cli_counters:
	kmem_cache_free(tfw_cli_counters_cache, counters);

	return NULL;
}

/*
 * Allocate cli_mem:
 *  - Try fast pool first, then fallback to slab cache.
 *  - On success, take an extra refcnt reference before returning.
 */
static inline TfwClientCounters *
tfw_cli_counters_alloc(void)
{
	TfwClientCounters *counters;

	counters = tfw_cli_counters_pool_alloc();
	if (!counters)
		counters = tfw_cli_counters_alloc_from_cache();
	if (unlikely(!counters))
		return NULL;

	percpu_ref_get(&counters->refcnt);

	return counters;
}

static int
tfw_client_ent_init(TdbRec *rec, void *data)
{
	TfwClientEntry *ent = (TfwClientEntry *)rec->data;
	TfwClient *cli = &ent->cli;
	TfwClientEqCtx *ctx = (TfwClientEqCtx *)data;

	INIT_LIST_HEAD(&cli->list);

	cli->counters = tfw_cli_counters_alloc();
	if (unlikely(!cli->counters))
		return -ENOMEM;

	assert_spin_locked(&client_db->ga_lock);

	tfw_client_update_lru(cli);

	bzero_fast(&cli->class_prvt, sizeof(cli->class_prvt));
	if (ctx->init)
		ctx->init(cli);

	cli->conn_max = 0;
	cli->conn_curr = 0;
	cli->conn_training_epoch = 0;

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
 * @cli			- client object
 * @delta		- connection delta (+1 on open, -1 on close)
 * @training_epoch 	- per-connection training epoch marker
 *
 * This function updates per-client connection statistics used by the
 * training/defence subsystem.
 *
 * Behaviour depends on current mode:
 *
 *   - TFW_MODE_DISABLED:
 *       No-op, always returns true.
 *
 *   - TFW_MODE_IS_DEFENCE:
 *       Updates current number of connections and checks it against
 *       learned z-score threshold. Returns false if the value exceeds
 *       the threshold (connection should be rejected).
 *
 *   - TFW_MODE_IS_TRAINING:
 *       Tracks per-client maximum number of concurrent connections and
 *       contributes positive deltas (growth of max) to global statistics.
 *
 * Epoch handling:
 *
 * Each connection is tagged with @training_epoch when created. When a
 * connection is closed, its contribution is ignored if it belongs to a
 * previous training epoch. This prevents mixing statistics across
 * training restarts.
 *
 * Concurrency:
 *
 * The function is called under client-private lock, so per-client fields
 * (conn_curr, conn_max, training_epoch) are updated without atomics.
 */
bool
tfw_client_training_adjust_conn_num(TfwClient *cli, int delta,
				    u16 *training_epoch)
{
	u64 delta1, delta2;
	unsigned int old_max;
	bool new_client = false;

	if (tfw_mode_is_disabled())
		return true;

	/*
	 * Ignore connection close events from previous training epochs.
	 * For new connections, assign current training epoch.
	 */
	if (delta < 0 && *training_epoch < g_training_epoch)
		return true;
	else if (!(*training_epoch) && delta > 0)
		*training_epoch = g_training_epoch;

	if (tfw_mode_is_defence()) {
		cli->conn_curr += delta;
		WARN_ON(cli->conn_curr < 0);

		if (delta < 0)
			return true;
		return tfw_training_mode_defence_conn_num(cli->conn_curr);
	}

	/*
	 * Training mode.
	 *
	 * Reset per-client stats on new training epoch.
	 * This is safe without extra synchronization as we are under
	 * client-private lock.
	 */
	if (cli->conn_training_epoch < g_training_epoch) {
		cli->conn_training_epoch = g_training_epoch;
		cli->conn_curr = 0;
		cli->conn_max = 0;
		new_client = true;
	}

	if (new_client)
		tfw_training_mode_adjust_conn_new_client();
	cli->conn_curr += delta;
	WARN_ON(cli->conn_curr < 0);

	old_max = cli->conn_max;
	if (cli->conn_curr <= old_max)
		return true;
	cli->conn_max = cli->conn_curr;
	delta1 = cli->conn_curr - old_max;
	delta2 = (u64)cli->conn_curr * cli->conn_curr -
		(u64)old_max * old_max;
	tfw_training_mode_adjust_conn_num(delta1, delta2);

	return true;
}

static inline bool
tfw_client_counter_change_epoch(TfwClientCounter *counter)
{
	bool new_client = false;

	/*
	 * We increment `g_training_epoch` each time when we start new
	 * training, when we are sure that all threads don't use `max`
	 * and `counter`. During training all threads call this function
	 * before use `counter` and `max`, so we are sure that `counter`
	 * and `max` will be zeroed on the start of the new training.
	 * We make first check to prevent unnecessary lock on the hot
	 * path on each call.
	 */
	if (counter->epoch < g_training_epoch) {
		spin_lock_bh(&counter->lock);
		if (likely(counter->epoch < g_training_epoch)) {
			int cpu;

			for_each_online_cpu(cpu)
				*(per_cpu_ptr(counter->counter, cpu)) = 0;
			atomic64_set(&counter->max, 0);
			counter->epoch = g_training_epoch;
			new_client = true;
		}
		spin_unlock_bh(&counter->lock);
	}

	return new_client;
}

static void
__tfw_client_counter_training_adjust(TfwClientCounter *counter,
				     void (*adjust_new_client)(void),
				     void (*add)(TfwClientCounter *counter,
				     		 int delta),
				     int delta)
{
	if (tfw_mode_is_training()
	    && tfw_client_counter_change_epoch(counter))
		adjust_new_client();
	add(counter, delta);
}

static void
tfw_client_counter_training_adjust(TfwClientCounter *counter,
				   void (*adjust_new_client)(void),
				   void (*add)(TfwClientCounter *counter,
				   	       int delta),
				   u16 *training_epoch, int delta)
{
	if (tfw_mode_is_disabled())
		return;

	/*
	 * Ignore event removing events from previous training epochs. If we
	 * add new request (`delta > 0`) it always belongs to the new epoch.
	 * For memory tracking there is a case when we make allocation in the
	 * new epoch for the pool or skb which was allocated in the previous
	 * epoch, we should also ignore such cases (there is only one epoch
	 * identifier for structure, which we set on it's first tracking.
	 * `training_epoch` - is a new field in the appropriate structure.
	 */
	if ((*training_epoch || delta < 0)
	    && *training_epoch < g_training_epoch)
		return;
	else if (!(*training_epoch) && delta > 0)
		*training_epoch = g_training_epoch;

	__tfw_client_counter_training_adjust(counter, adjust_new_client,
					     add, delta);
}

void
tfw_client_counter_training_adjust_req(TfwClientCounter *counter, int delta,
				       u16 *training_epoch)
{
	void (*adjust_new_client)(void) =
		tfw_training_mode_adjust_req_new_client;
	void (*add)(TfwClientCounter *counter, int delta) =
		tfw_client_counter_add;

	return tfw_client_counter_training_adjust(counter, adjust_new_client,
						  add, training_epoch, delta);
}

void
tfw_client_counter_training_adjust_mem(TfwClientCounter *counter, int delta,
				       u16 *training_epoch)
{
	void (*adjust_new_client)(void) =
		tfw_training_mode_adjust_mem_new_client;
	void (*add)(TfwClientCounter *counter, int delta) =
		tfw_client_counter_add;

	return tfw_client_counter_training_adjust(counter, adjust_new_client,
						  add, training_epoch, delta);
}

static inline bool
tfw_client_counter_change_max(TfwClientCounter *counter, long curr,
			      u64 *delta1, u64 *delta2)
{
	s64 old_max = atomic64_read(&counter->max);

	/*
	 * Can be called concurrentrly on other cpu with different
	 * curr value, so we need `atomic` syncronization here.
	 */
	do {
		if (curr <= old_max)
			return false;
	} while (!atomic64_try_cmpxchg(&counter->max, &old_max, curr));

	*delta1 = curr - old_max;
	*delta2 = (u64)curr * curr - (u64)old_max * old_max;

	return true;
}

static bool
tfw_client_counter_training_check(TfwClientCounter *counter,
				  void (*adjust_num)(u64, u64),
				  bool(*defence)(u64))
{
	u64 delta1, delta2;
	s64 curr;

	if (tfw_mode_is_disabled())
		return true;

	curr = tfw_client_counter_get(counter);
	if (tfw_mode_is_defence())
		return defence(curr);

	if (tfw_client_counter_change_max(counter, curr, &delta1, &delta2))
		adjust_num(delta1, delta2);

	return true;
}

bool
tfw_client_counter_training_check_req(TfwClientCounter *counter)
{
	void (*adjust_num)(u64, u64) =
		tfw_training_mode_adjust_req_num;
	bool (*defence)(u64) = tfw_training_mode_defence_req_num;

	return tfw_client_counter_training_check(counter, adjust_num,
						 defence);
}

bool
tfw_client_counter_training_check_mem(TfwClientCounter *counter)
{
	void (*adjust_num)(u64, u64) =
		tfw_training_mode_adjust_mem;
	bool (*defence)(u64) = tfw_training_mode_defence_mem;

	return tfw_client_counter_training_check(counter, adjust_num,
						 defence);
}	

static inline void
tfw_client_counter_add_ema(TfwClientCounter *counter, int delta)
{
	s64 *ema = this_cpu_ptr(counter->counter);
	static const unsigned int ema_alpha_shift = 4;

	*ema += ((s64)delta - *ema) >> ema_alpha_shift;
}

bool
tfw_client_counter_training_check_cpu(TfwClientCounter *counter,
				      u64 time_begin)
{
	u64 delta =  get_cycles() - time_begin;
	void (*adjust_new_client)(void) =
		tfw_training_mode_adjust_cpu_new_client;
	void (*add)(TfwClientCounter *counter, int delta) =
		tfw_client_counter_add_ema;
	void (*adjust_num)(u64, u64) =
		tfw_training_mode_adjust_cpu;
	bool (*defence)(u64) = tfw_training_mode_defence_cpu;

	if (tfw_mode_is_disabled())
		return true;

	__tfw_client_counter_training_adjust(counter, adjust_new_client,
					     add, delta);

	return tfw_client_counter_training_check(counter, adjust_num,
						 defence);
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
	int r;

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

	r = tfw_cli_counters_pool_init();
	if (unlikely(r))
		return r;

	client_db->hdr->before_free = tfw_client_free;

	return 0;
}

static void
tfw_client_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;

	if (client_db) {
		tfw_client_free_lru();
		wait_event(shutdown_wq, !atomic_read(&shutdown_pending));
		tfw_cli_counters_pool_exit();
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
	tfw_cli_counters_cache = kmem_cache_create("tfw_cli_counters_cache",
						   sizeof(TfwClientCounters),
						   0, 0, NULL);
	if (!tfw_cli_counters_cache)
		return -ENOMEM;

	tfw_mod_register(&tfw_client_mod);

	return 0;
}

void
tfw_client_exit(void)
{
	kmem_cache_destroy(tfw_cli_counters_cache);
	tfw_mod_unregister(&tfw_client_mod);
}
