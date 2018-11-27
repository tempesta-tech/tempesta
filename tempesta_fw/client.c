/**
 *		Tempesta FW
 *
 * Clients handling.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#include "client.h"
#include "connection.h"
#include "log.h"
#include "procfs.h"

#define CLI_HASH_BITS	17
#define CLI_HASH_SZ	(1 << CLI_HASH_BITS)

typedef struct {
	struct hlist_head	list;
	spinlock_t		lock;
} CliHashBucket;

/*
 * TODO probably not the best container for the task and
 * HTrie should be used instead.
 */
CliHashBucket cli_hash[CLI_HASH_SZ] = {
	[0 ... (CLI_HASH_SZ - 1)] = {
		HLIST_HEAD_INIT,
	}
};

static struct kmem_cache *cli_cache;

/* Total number of created clients. */
static atomic64_t act_cli_n = ATOMIC64_INIT(0);

/**
 * Called when a client socket is closed.
 */
void
tfw_client_put(TfwClient *cli)
{
	TFW_DBG2("put client %p, conn_users=%d\n",
		 cli, atomic_read(&cli->conn_users));

	if (!atomic_dec_and_test(&cli->conn_users))
		return;

	spin_lock(cli->hb_lock);

	if (atomic_read(&cli->conn_users)) {
		spin_unlock(cli->hb_lock);
		return;
	}
	BUG_ON(!list_empty(&cli->conn_list));

	hlist_del(&cli->hentry);

	spin_unlock(cli->hb_lock);

	TFW_DBG("free client: cli=%p\n", cli);
	kmem_cache_free(cli_cache, cli);
	atomic64_dec(&act_cli_n);
	TFW_DEC_STAT_BH(clnt.online);
}
EXPORT_SYMBOL(tfw_client_put);

/**
 * Find a client corresponding to the @sk by IP address.
 * More advanced identification is possible based on User-Agent,
 * Cookie and other HTTP headers.
 *
 * The returned TfwClient reference must be released via tfw_client_put()
 * when the @sk is closed.
 *
 * TODO #488 (#100): evict connections and/or clients and drop their accounting.
 * For now a client is freed immediately when the last of its connections is
 * closed, probably we should evict clients after some timeout to keep their
 * classifier statistic for following sessions...
 */
TfwClient *
tfw_client_obtain(struct sock *sk, void (*init)(TfwClient *))
{
	TfwClient *cli;
	CliHashBucket *hb;
	struct hlist_node *tmp;
	unsigned long key;
	TfwAddr addr;

	ss_getpeername(sk, &addr);
	key = hash_calc((const char *)&addr.sin6_addr,
			sizeof(addr.sin6_addr));

	hb = &cli_hash[hash_min(key, CLI_HASH_BITS)];

	spin_lock(&hb->lock);

	hlist_for_each_entry_safe(cli, tmp, &hb->list, hentry)
		if (ipv6_addr_equal(&addr.sin6_addr,
		                    &cli->addr.sin6_addr))
			goto found;

	if (!(cli = kmem_cache_alloc(cli_cache, GFP_ATOMIC | __GFP_ZERO))) {
		spin_unlock(&hb->lock);
		return NULL;
	}

	tfw_peer_init((TfwPeer *)cli, &addr);
	hlist_add_head(&cli->hentry, &hb->list);
	cli->hb_lock = &hb->lock;
	if (init)
		init(cli);

	atomic64_inc(&act_cli_n);
	TFW_INC_STAT_BH(clnt.online);
	TFW_DBG("new client: cli=%p\n", cli);
	TFW_DBG_ADDR("client address", &cli->addr, TFW_NO_PORT);

found:
	atomic_inc(&cli->conn_users);

	TFW_DBG2("client %p, conn_users=%d\n",
		 cli, atomic_read(&cli->conn_users));

	spin_unlock(&hb->lock);

	return cli;
}
EXPORT_SYMBOL(tfw_client_obtain);

/**
 * Beware: @fn is called under client hash bucket spin lock.
 */
int
tfw_client_for_each(int (*fn)(TfwClient *))
{
	int i, r = 0;

	for (i = 0; i < CLI_HASH_SZ && !r; ++i) {
		TfwClient *c;
		CliHashBucket *hb = &cli_hash[i];

		spin_lock(&hb->lock);

		hlist_for_each_entry(c, &hb->list, hentry) {
			r = fn(c);
			if (unlikely(r))
				break;
		}

		spin_unlock(&hb->lock);
	}

	return r;
}

/**
 * Waiting for destruction of all clients.
 */
void
tfw_cli_wait_release(void)
{
	tfw_objects_wait_release(&act_cli_n, 5, "client");
}

int __init
tfw_client_init(void)
{
	int i;

	cli_cache = kmem_cache_create("tfw_cli_cache", sizeof(TfwClient),
				      0, 0, NULL);
	if (!cli_cache)
		return -ENOMEM;

	/*
	 * Dynamically initialize hash table spinlocks to avoid lockdep leakage
	 * (see Troubleshooting in Documentation/locking/lockdep-design.txt).
	 */
	for (i = 0; i < CLI_HASH_SZ; ++i)
		spin_lock_init(&cli_hash[i].lock);

	return 0;
}

void
tfw_client_exit(void)
{
	int i;

	/*
	 * Free client records with classification modules accounting records.
	 * There are must not be users.
	 */
	for (i = 0; i < (1 << CLI_HASH_BITS); ++i) {
		TfwClient *c;
		struct hlist_node *tmp;
		CliHashBucket *hb = &cli_hash[i];

		hlist_for_each_entry_safe(c, tmp, &hb->list, hentry) {
			BUG_ON(!list_empty(&c->conn_list));
			hash_del(&c->hentry);
			kmem_cache_free(cli_cache, c);
		}
	}
	kmem_cache_destroy(cli_cache);
}
