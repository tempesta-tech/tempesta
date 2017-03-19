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
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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
#include <linux/hash.h>
#include <linux/module.h>

#include "tempesta_fw.h"
#include "log.h"
#include "server.h"
#include "http_msg.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta hash-based scheduler");
MODULE_VERSION("0.3.0");
MODULE_LICENSE("GPL");

typedef struct {
	size_t			conn_n;
	TfwServer		*srv;
	TfwSrvConn		*conn[TFW_SRV_MAX_CONN];
	unsigned long		hash[TFW_SRV_MAX_CONN];
} TfwHashSrv;

typedef struct {
	size_t			srv_n;
	TfwHashSrv		srvs[TFW_SG_MAX_SRV];
} TfwHashSrvList;

static void
tfw_sched_hash_alloc_data(TfwSrvGroup *sg)
{
	sg->sched_data = kzalloc(sizeof(TfwHashSrvList), GFP_KERNEL);
	BUG_ON(!sg->sched_data);
}

static void
tfw_sched_hash_free_data(TfwSrvGroup *sg)
{
	kfree(sg->sched_data);
}

static unsigned long
__calc_conn_hash(TfwServer *srv, size_t conn_idx)
{
	/* hash_64() works better when bits are distributed uniformly. */
	unsigned long hash = REPEAT_BYTE(0xAA);
	size_t i, bytes_n;
	union {
		TfwAddr addr;
		unsigned char bytes[0];
	} *a;

	/*
	 * Here we just cast the whole TfwAddr to an array of bytes.
	 *
	 * That only works if the following invariants are held:
	 *  - There are no gaps between structure fields.
	 *  - No structure fields (e.g. sin6_flowinfo) are changed if we
	 *    re-connect to the same server.
	 */
	a = (void *)&srv->addr;
	bytes_n = tfw_addr_sa_len(&a->addr);
	for (i = 0; i < bytes_n; ++i)
		hash = hash_long(hash ^ a->bytes[i], BITS_PER_LONG);

	/* Also mix-in the conn_idx. */
	return hash_long(hash ^ conn_idx, BITS_PER_LONG);
}

static void
tfw_sched_hash_add_conn(TfwSrvGroup *sg, TfwServer *srv, TfwSrvConn *conn)
{
	size_t s, c;
	TfwHashSrv *srv_cl;
	TfwHashSrvList *sl = sg->sched_data;

	BUG_ON(!sl);

	for (s = 0; s < sl->srv_n; ++s)
		if (sl->srvs[s].srv == srv)
			break;
	if (s == sl->srv_n) {
		sl->srvs[s].srv = srv;
		++sl->srv_n;
		BUG_ON(sl->srv_n > TFW_SG_MAX_SRV);
		srv->sched_data = &sl->srvs[s];
	}

	srv_cl = &sl->srvs[s];

	for (c = 0; c < srv_cl->conn_n; ++c)
		if (srv_cl->conn[c] == conn) {
			TFW_WARN("sched_hash: Try to add existing connection,"
				 " srv=%zu conn=%zu\n", s, c);
			return;
		}
	srv_cl->conn[c] = conn;
	srv_cl->hash[c] = __calc_conn_hash(srv, s * TFW_SRV_MAX_CONN + c);
	++srv_cl->conn_n;
	BUG_ON(srv_cl->conn_n > TFW_SRV_MAX_CONN);
}

static inline void
__find_best_conn(TfwSrvConn **best_conn, TfwHashSrv *srv_cl,
		 unsigned long *best_weight, unsigned long msg_hash)
{
	size_t i;

	for (i = 0; i < srv_cl->conn_n; ++i) {
		unsigned long curr_weight;
		TfwSrvConn *conn = srv_cl->conn[i];

		if (unlikely(tfw_srv_conn_restricted(conn)
			     || tfw_srv_conn_queue_full(conn)
			     || !tfw_srv_conn_live(conn)))
			continue;

		curr_weight = msg_hash ^ srv_cl->hash[i];
		if (curr_weight > *best_weight) {
			*best_weight = curr_weight;
			*best_conn = conn;
		}
	}
}

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
 *    Although it is quite improbable, such condition is quite stable:
 *    it cannot be fixed by adding/removing servers and restarting Tempesta FW.
 *  - For every HTTP request, we have to scan the list of all servers to find
 *    a matching one with the highest weight. That adds some overhead.
 */
static TfwSrvConn *
tfw_sched_hash_get_sg_conn(TfwMsg *msg, TfwSrvGroup *sg)
{
	unsigned long msg_hash;
	unsigned long tries = TFW_SG_MAX_CONN;
	TfwHashSrvList *sl = sg->sched_data;

	BUG_ON(!sl);

	msg_hash = tfw_http_req_key_calc((TfwHttpReq *)msg);
	while (--tries) {
		size_t i;
		unsigned long best_weight = 0;
		TfwSrvConn *best_conn = NULL;

		for (i = 0; i < sl->srv_n; ++i) {
			TfwHashSrv *srv_cl = &sl->srvs[i];
			__find_best_conn(&best_conn, srv_cl, &best_weight,
					 msg_hash);
		}
		if (unlikely(!best_conn))
			return NULL;
		if (likely(tfw_srv_conn_get_if_live(best_conn)))
			return best_conn;
	}
	return NULL;
}

/**
 * Same as @tfw_sched_hash_get_sg_conn(), but schedule for a specific server
 * in a group.
 */
static TfwSrvConn *
tfw_sched_hash_get_srv_conn(TfwMsg *msg, TfwServer *srv)
{
	unsigned long msg_hash;
	size_t tries;
	TfwHashSrv *srv_cl = srv->sched_data;

	/*
	 * For @srv without connections srv_cl will be NULL, that normally
	 * does not happen in real life, but unit tests check that case.
	*/
	if (unlikely(!srv_cl))
		return NULL;

	msg_hash = tfw_http_req_key_calc((TfwHttpReq *)msg);
	/* Try several times even if server has just a few connections. */
	tries = srv_cl->conn_n + 1;
	while (--tries) {
		unsigned long best_weight = 0;
		TfwSrvConn *best_conn = NULL;

		__find_best_conn(&best_conn, srv_cl, &best_weight, msg_hash);
		if (unlikely(!best_conn))
			return NULL;
		if (likely(tfw_srv_conn_get_if_live(best_conn)))
			return best_conn;
	}
	return NULL;
}

static TfwScheduler tfw_sched_hash = {
	.name		= "hash",
	.list		= LIST_HEAD_INIT(tfw_sched_hash.list),
	.add_grp	= tfw_sched_hash_alloc_data,
	.del_grp	= tfw_sched_hash_free_data,
	.add_conn	= tfw_sched_hash_add_conn,
	.sched_sg_conn	= tfw_sched_hash_get_sg_conn,
	.sched_srv_conn	= tfw_sched_hash_get_srv_conn,
};

int
tfw_sched_hash_init(void)
{
	TFW_DBG("sched_hash: init\n");
	return tfw_sched_register(&tfw_sched_hash);
}
module_init(tfw_sched_hash_init);

void
tfw_sched_hash_exit(void)
{
	TFW_DBG("sched_hash: exit\n");
	tfw_sched_unregister(&tfw_sched_hash);
}
module_exit(tfw_sched_hash_exit);
