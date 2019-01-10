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
#include "tdb.h"
#include "lib/str.h"
#include "lib/common.h"

#define CLI_HASH_BITS	17
#define CLI_HASH_SZ	(1 << CLI_HASH_BITS)

typedef struct {
	spinlock_t		lock;
} CliHashBucket;

/*
 * TODO probably not the best container for the task and
 * HTrie should be used instead.
 */
CliHashBucket cli_hash[CLI_HASH_SZ];

static struct {
	unsigned int db_size;
	const char *db_path;
	unsigned int lifetime;
} client_cfg __read_mostly;

typedef struct {
	time_t expires;
	TfwClient cli;
} TfwClientEntry;

static TDB *ip_client_db;

/* Total number of created clients. */
static atomic64_t act_cli_n = ATOMIC64_INIT(0);

/**
 * Called when a client socket is closed.
 */
void
tfw_client_put(TfwClient *cli)
{
	TfwClientEntry *ent;

	TFW_DBG2("put client %p, conn_users=%d\n",
		 cli, atomic_read(&cli->conn_users));

	if (!atomic_dec_and_test(&cli->conn_users))
		return;

	ent = (TfwClientEntry *)((void *)cli - offsetof(TfwClientEntry, cli));
	ent->expires = tfw_current_timestamp() + client_cfg.lifetime;

	TFW_DBG("free client: cli=%p\n", cli);
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
 */
TfwClient *
tfw_client_obtain(struct sock *sk, void (*init)(TfwClient *))
{
	TdbIter iter;
	TfwClientEntry *ent;
	TfwClient *cli;
	CliHashBucket *hb;
	unsigned long key;
	TfwAddr addr;
	size_t len;
	TdbRec *rec;

	ss_getpeername(sk, &addr);
	key = hash_calc((const char *)&addr.sin6_addr,
			sizeof(addr.sin6_addr));

	hb = &cli_hash[hash_min(key, CLI_HASH_BITS)];

	spin_lock(&hb->lock);

	iter = tdb_rec_get(ip_client_db, key);
	while (!TDB_ITER_BAD(iter)) {
		time_t curr_time = tfw_current_timestamp();

		ent = (TfwClientEntry *)iter.rec->data;
		cli = &ent->cli;
		if (!memcmp_fast(&cli->addr, &addr, sizeof(cli->addr))) {
			if (curr_time > ent->expires) {
				memset(&cli->class_prvt, 0, sizeof(cli->class_prvt));
				if (init)
					init(cli);
			}
			ent->expires = LONG_MAX;
			tdb_rec_put(iter.rec);
			TFW_DBG("client was found in tdb\n");
			goto found;
		}
		tdb_rec_next(ip_client_db, &iter);
	}

	if (unlikely(!ss_active())) {
		TFW_DBG("reject allocation of new client after shutdown\n");
		return NULL;
	}

	len = sizeof(*cli);
	rec = tdb_entry_alloc(ip_client_db, key, &len);
	if (!rec)
		return NULL;

	ent = (TfwClientEntry *)rec->data;
	ent->expires = LONG_MAX;
	cli = &ent->cli;

	tfw_peer_init((TfwPeer *)cli, &addr);
	if (init)
		init(cli);

	TFW_DBG("new client: cli=%p\n", cli);
	TFW_DBG_ADDR("client address", &cli->addr, TFW_NO_PORT);

found:
	if (!atomic_read(&cli->conn_users)) {
		atomic64_inc(&act_cli_n);
		TFW_INC_STAT_BH(clnt.online);
	}

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
	int r = 0;
	/*TfwClient *c;

	tdb_for_each_rec(c, ip_client_db) {
		r = fn(c);
		if (unlikely(r))
				break;
	}*/

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

static int
tfw_client_start(void)
{
	if (tfw_runstate_is_reconfig())
		return 0;

	ip_client_db = tdb_open(client_cfg.db_path, client_cfg.db_size,
				sizeof(TfwClient), numa_node_id());
	if (!ip_client_db)
		return -EINVAL;

	return 0;
}

static void
tfw_client_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;
	if (ip_client_db)
		tdb_close(ip_client_db);
}

static int
tfw_client_lifetime(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	r = tfw_cfg_set_int(cs, ce);
	/*
	 * "client_lifetime 0;" means unlimited client lifetime,
	 * set client_cfg.lifetime to maximum value.
	*/
	if (!r && !client_cfg.lifetime)
		client_cfg.lifetime = UINT_MAX;

	return r;
}

static TfwCfgSpec tfw_client_specs[] = {
	{
		.name = "client_tbl_size",
		.deflt = "16777216",
		.handler = tfw_cfg_set_int,
		.dest = &client_cfg.db_size,
		.spec_ext = &(TfwCfgSpecInt) {
			.multiple_of = PAGE_SIZE,
			.range = { PAGE_SIZE, (1 << 30) },
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
		.name = "client_lifetime",
		.deflt = "3600",
		.handler = tfw_client_lifetime,
		.dest = &client_cfg.lifetime,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
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
	int i;

	/*
	 * Dynamically initialize hash table spinlocks to avoid lockdep leakage
	 * (see Troubleshooting in Documentation/locking/lockdep-design.txt).
	 */
	for (i = 0; i < CLI_HASH_SZ; ++i)
		spin_lock_init(&cli_hash[i].lock);

	tfw_mod_register(&tfw_client_mod);

	return 0;
}

void
tfw_client_exit(void)
{
	tfw_mod_unregister(&tfw_client_mod);
}
