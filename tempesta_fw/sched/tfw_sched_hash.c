/**
 *		Tempesta FW
 *
 * Hash-based HTTP request scheduler.
 *
 * The scheduler computes hash of URI and Host header fields of a HTTP request
 * and uses the hash value to select an appropriate server.
 * The same hash value is always mapped to the same server, therefore HTTP
 * requests with the same Host/URI are always scheduled to the same server.
 *
 * Also, the scheduler utilizes the Rendezvous hashing (Highest Random Weight)
 * method that allows to stick every HTTP message to its server, preserving
 * this mapping when servers are added/deleted and go online/offline.
 *
 * The scheduler hashes not only HTTP requests, but also servers (TfwServer
 * objects), and for each incoming HTTP request it searches for a best match
 * among all server hashes. Each Host/URI hash has only one best matching
 * TfwSrver hash which is chosen, and thus any request always goes to its home
 * server unless it is offline.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
 *
 */
#include <linux/hash.h>
#include <linux/module.h>

#include "log.h"
#include "server.h"
#include "http_msg.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta hash-based scheduler");
MODULE_VERSION("0.2.0");
MODULE_LICENSE("GPL");

#define BANNER "tfw_sched_hash: "
#define ERR(...) TFW_ERR(BANNER __VA_ARGS__)
#define DBG(...) TFW_DBG(BANNER __VA_ARGS__)
#define DBG2(...) TFW_DBG2(BANNER __VA_ARGS__)

typedef struct {
	TfwConnection	*conn;
	unsigned long	hash;
} TfwConnHash;

typedef struct {
	TfwConnHash	conn_hashes[0];
} TfwConnHashList;

#define TFW_CONN_HASH_LIST_SIZE(n) \
	((n) + 1)
#define TFW_CONN_HASH_DATA_SIZE(n) \
	(sizeof(TfwConnHashList) + TFW_CONN_HASH_LIST_SIZE(n) * sizeof(TfwConnHash))

/**
 * Find an appropriate server connection for the HTTP request @msg.
 * The server is chosen based on the hash value of URI/Host fields of the @msg,
 * so multiple requests to the same resource are mapped to the same server.
 *
 * Higest Random Weight hashing method is involved: for each message we
 * calculate randomized weights as follows: (msg_hash ^ srv_conn_hash),
 * and pick a server/connection with the highest weight.
 * That sticks messages with certain Host/URI to certain server connection.
 * A server always receives requests with some URI/Host values bound to it,
 * and that holds even if some servers go offline/online.
 *
 * The drawbacks of HRW hashing are:
 *  - A weak hash function adds unfairness to the load balancing.
 *    There may be a case when a server pulls all load from all other servers.
 *    Although it is quite improbable, such condition is quite stable: it cannot
 *    be fixed by adding/removing servers and restarting the Tempesta FW.
 *  - For every HTTP request, we have to scan the list of all servers to find
 *    a matching one with the highest weight. That adds some overhead.
 */
static TfwConnection *
tfw_sched_hash_get_srv_conn(TfwMsg *msg, TfwSrvGroup *sg)
{
	TfwConnHash *curr_conn_hash;
	TfwConnHashList *conn_hash_list;
	TfwConnection *best_conn;
	unsigned long msg_hash, curr_weight, best_weight;

	conn_hash_list = sg->sched_data;
	msg_hash = tfw_http_req_key_calc((TfwHttpReq *)msg);

	/* 1. Set best = first element of the list. */
	curr_conn_hash = &conn_hash_list->conn_hashes[0];
	best_conn = curr_conn_hash->conn;
	best_weight = msg_hash ^ curr_conn_hash->hash;

	/* 2. Try to find a better one among 2nd...Nth elements of the list. */
	/* TODO: binary search. */
	while ((++curr_conn_hash)->conn) {
		curr_weight = msg_hash ^ curr_conn_hash->hash;
		if (curr_weight > best_weight) {
			best_weight = curr_weight;
			best_conn = curr_conn_hash->conn;
		}
		++curr_conn_hash;
	}

	if (likely(best_conn))
		tfw_connection_get(best_conn);

	return best_conn;
}

static void
tfw_sched_hash_alloc_data(TfwSrvGroup *sg)
{
	size_t sched_data_size = TFW_CONN_HASH_DATA_SIZE(TFW_SG_MAX_CONN);
	BUG_ON(sg->sched_data);
	sg->sched_data = kzalloc(sched_data_size, GFP_KERNEL);
	BUG_ON(!sg->sched_data);
}

static void
tfw_sched_hash_free_data(TfwSrvGroup *sg)
{
	BUG_ON(!sg->sched_data);
	kfree(sg->sched_data);
	sg->sched_data = NULL;
}

static unsigned long
__calc_conn_hash(TfwServer *srv, size_t conn_idx)
{
	unsigned long hash;
	union {
		TfwAddr addr;
		unsigned char bytes[0];
	} *a;
	size_t i, bytes_n;

	/* hash_64() works better when bits are distributed uniformly. */
	hash = REPEAT_BYTE(0xAA);

	/**
	 * Here we just cast the whole TfwAddr to an array of bytes.
	 *
	 * That only works if the following invariants are held:
	 *  - There are no gaps between structure fields.
	 *  - No structure fields (e.g. sin6_flowinfo) are changed if we
	 *    re-connect to the same server.
	 */
	a = (void *)&srv->addr;
	bytes_n = tfw_addr_sa_len(&a->addr);
	for (i = 0; i < bytes_n; ++i) {
		hash = hash_long(hash ^ a->bytes[i], BITS_PER_LONG);
	}

	/* Also mix-in the conn_idx. */
	hash = hash_long(hash ^ conn_idx, BITS_PER_LONG);

	return hash;
}

static void
tfw_sched_hash_update_data(TfwSrvGroup *sg)
{
	TfwServer *srv;
	TfwConnection *conn;
	TfwConnHash *conn_hash;
	TfwConnHashList *hash_list;
	size_t conn_idx, hash_idx;

	hash_list = sg->sched_data;
	BUG_ON(!hash_list);

	hash_idx = 0;
	list_for_each_entry(srv, &sg->srv_list, list) {
		conn_idx = 0;
		list_for_each_entry(conn, &srv->conn_list, list) {
			/*
			 * Skip not-yet-established connections. Take care
			 * of conn_idx to preserve same hash values for all
			 * connections.
			 *
			 * A connection may die by the time someone wants
			 * to use it. That has to be dealt with elsewhere.
			 * It should be assumed that scheduler's data is
			 * only semi-accurate at any point of time.
			 */
			if (!tfw_connection_live(conn)) {
				++conn_idx;
				continue;
			}

			conn_hash = &hash_list->conn_hashes[hash_idx];
			conn_hash->conn = conn;
			conn_hash->hash = __calc_conn_hash(srv, conn_idx);
			++conn_idx;
			++hash_idx;
		}
	}

	BUG_ON(hash_idx >= TFW_CONN_HASH_LIST_SIZE(TFW_SG_MAX_CONN));
	hash_list->conn_hashes[hash_idx].conn = NULL; /* terminate the list */
}

static TfwScheduler tfw_sched_hash = {
	.name		= "hash",
	.list		= LIST_HEAD_INIT(tfw_sched_hash.list),
	.add_grp	= tfw_sched_hash_alloc_data,
	.del_grp	= tfw_sched_hash_free_data,
	.update_grp	= tfw_sched_hash_update_data,
	.sched_srv	= tfw_sched_hash_get_srv_conn,
};

int
tfw_sched_hash_init(void)
{
	DBG("init\n");
	return tfw_sched_register(&tfw_sched_hash);
}
module_init(tfw_sched_hash_init);

void
tfw_sched_hash_exit(void)
{
	DBG("exit\n");
	tfw_sched_unregister(&tfw_sched_hash);
}
module_exit(tfw_sched_hash_exit);
