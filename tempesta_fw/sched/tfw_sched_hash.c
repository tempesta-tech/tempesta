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
MODULE_VERSION("0.4.1");
MODULE_LICENSE("GPL");

typedef struct {
	unsigned long		hash;
	TfwSrvConn		*conn;
} TfwHashConn;

typedef struct {
	size_t			conn_n;
	TfwHashConn		conns[0];
} TfwHashConnList;

typedef struct {
	TfwServer		*srv;
	TfwHashConnList		*cl;
} TfwHashSrvConnList;

/* Same as hash_64_generic, but return 64-bit value. */
static __always_inline unsigned long
__hash_64(unsigned long val)
{
	return val * GOLDEN_RATIO_64;
}

static unsigned long
__calc_srv_hash(TfwServer *srv)
{
	unsigned long hash;

	/*
	 * Here we just cast the whole TfwAddr to an array of bytes.
	 *
	 * That only works if the following invariants are held:
	 *  - There are no gaps between structure fields.
	 *  - No structure fields (e.g. sin6_flowinfo) are changed if we
	 *    re-connect to the same server.
	 */
	hash = tdb_hash_calc((char *)&srv->addr, tfw_addr_sa_len(&srv->addr));
	/*
	 * If TfwAddr represents IPv4 address @tdb_hash_calc() will always
	 * generate a 32-bit value. In the same time IPv6 servers are likely to
	 * have a 64-bit hashes. That will lead to situation when IPv6 will
	 * take all the load since message hash is most likely to be a 64-bit
	 * value.
	 *
	 * Use @__hash_64 to get 64-bit hash value.
	 */
	return __hash_64(hash);
}

/**
 * Binary search for connection with hash closest to @hash value in connection
 * list @cl. Most likely, that exact @hash value cannot be found.
 *
 * Returns index of closest element in array.
 */
static ssize_t
__bsearch(const unsigned long hash, TfwHashConnList *cl)
{
	ssize_t start = 0, end = (ssize_t)cl->conn_n - 1, mid = 0;
	unsigned long mid_hash;

	while (start < end) {
		mid = start + (end - start) / 2;

		mid_hash = cl->conns[mid].hash;
		if (hash < mid_hash)
			end = mid;
		else if (hash > mid_hash)
			start = mid + 1;
		else
			return mid; /* an unexpected outcome. */
	}
	/*
	 * Most expected outcome: exact @hash not found, @start points to the
	 * closest item.
	 */
	return start;
}

static inline int
__is_conn_suitable(TfwSrvConn *conn)
{
	return !tfw_srv_conn_restricted(conn)
		&& !tfw_srv_conn_queue_full(conn)
		&& tfw_srv_conn_get_if_live(conn);
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
static inline TfwSrvConn *
__find_best_conn(TfwMsg *msg, TfwHashConnList *cl)
{
	ssize_t l_idx, r_idx, idx;
	TfwSrvConn *conn;
	unsigned long msg_hash = tfw_http_req_key_calc((TfwHttpReq *)msg);
	unsigned long best_hash = (~0UL ^ msg_hash);

	if (unlikely(!cl->conn_n))
		return NULL;

	/*
	 * Find a connection with hash as close to @best_hash as possible.
	 * Value of (msg_hash ^ srv_conn_hash) will be biggest for that
	 * connection.
	 */
	idx = __bsearch(best_hash, cl);
	conn = cl->conns[idx].conn;
	if (likely(__is_conn_suitable(conn)))
		return conn;

	/*
	 * The best connection is dead or overfilled. Take the nearest live
	 * neighbour.
	*/
	r_idx = idx + 1;
	l_idx = idx - 1;
	while (l_idx >= 0 || r_idx < (ssize_t)cl->conn_n) {
		unsigned long l_diff = (l_idx >= 0)
				? (best_hash - cl->conns[l_idx].hash)
				: ULONG_MAX;
		unsigned long r_diff = (r_idx < (ssize_t)cl->conn_n)
				? (cl->conns[r_idx].hash - best_hash)
				: ULONG_MAX;
		ssize_t best_idx = (l_diff <= r_diff) ? l_idx : r_idx;

		conn = cl->conns[best_idx].conn;
		if (likely(__is_conn_suitable(conn)))
			return conn;

		if (l_diff <= r_diff)
			--l_idx;
		else
			++r_idx;
	};

	return NULL;
}

static TfwSrvConn *
tfw_sched_hash_get_sg_conn(TfwMsg *msg, TfwSrvGroup *sg)
{
	TfwHashConnList *cl;
	TfwSrvConn *srv_conn = NULL;

	rcu_read_lock();
	cl = rcu_dereference(sg->sched_data);

	if (likely(cl))
		srv_conn = __find_best_conn(msg, cl);

	rcu_read_unlock();
	return srv_conn;
}

/**
 * Same as @tfw_sched_hash_get_sg_conn(), but schedule for a specific server
 * in a group.
 */
static TfwSrvConn *
tfw_sched_hash_get_srv_conn(TfwMsg *msg, TfwServer *srv)
{
	TfwHashConnList *cl;
	TfwSrvConn *srv_conn = NULL;

	rcu_read_lock();
	cl = rcu_dereference(srv->sched_data);

	if (likely(cl))
		srv_conn = __find_best_conn(msg, cl);

	rcu_read_unlock();
	return srv_conn;
}

static void
tfw_sched_hash_del_grp(TfwSrvGroup *sg)
{
	TfwServer *srv;
	TfwHashConnList *cl = rcu_dereference(sg->sched_data);

	list_for_each_entry(srv, &sg->srv_list, list)
		rcu_assign_pointer(srv->sched_data, NULL);

	rcu_assign_pointer(sg->sched_data, NULL);

	synchronize_rcu();
	if (cl)
		kfree(cl);
}

static int
__add_conn(TfwHashConnList *cl, TfwSrvConn *conn, unsigned long hash)
{
	ssize_t idx;
	TfwHashConn new_hcon = {hash, conn};

	/* @cl is empty. */
	if (unlikely(!cl->conn_n)) {
		cl->conns[0] = new_hcon;
		++cl->conn_n;

		return 0;
	}

	idx = __bsearch(hash, cl);
	if (cl->conns[idx].hash == hash)
		return -EEXIST;

	/* Need to insert connection before or after found index. */
	if ((hash > cl->conns[idx].hash) && (idx != (ssize_t)cl->conn_n))
		++idx;

	if ((size_t)idx != cl->conn_n)
		memmove(&cl->conns[idx+1], &cl->conns[idx],
			sizeof(TfwHashConn) * (cl->conn_n - (size_t)idx));

	cl->conns[idx] = new_hcon;
	++cl->conn_n;

	return 0;
}

/**
 * Fill per-server sched_data according to sched_data of the entire server
 * group.
 */
static void
__fill_srv_lists(TfwHashConnList *cl, size_t srv_n, TfwHashSrvConnList *srv_cls)
{
	size_t i, j;

	for (i = 0; i < srv_n; ++i) {
		TfwServer *srv = srv_cls[i].srv;
		TfwHashConnList *scl = srv_cls[i].cl;

		for (j = 0; j < cl->conn_n; ++j) {
			TfwHashConn *hconn = &cl->conns[j];
			if ((TfwServer *)hconn->conn->peer == srv) {
				scl->conns[scl->conn_n] = *hconn;
				++scl->conn_n;
			}
		}
		rcu_assign_pointer(srv->sched_data, scl);
	}
}

static int
tfw_sched_hash_add_grp(TfwSrvGroup *sg, void *data)
{
	size_t size, conn_n = 0, offset = 0, seed, seed_inc, i = 0;
	TfwServer *srv;
	TfwHashConnList *cl;
	TfwHashSrvConnList *srv_cls;

	if (unlikely(!sg->srv_n || list_empty(&sg->srv_list)))
		return -EINVAL;

	seed = get_random_long();
	seed_inc = get_random_int();

	list_for_each_entry(srv, &sg->srv_list, list)
		conn_n += srv->conn_n;

	size = sizeof(TfwHashConnList) * (sg->srv_n + 1)
			+ sizeof(TfwHashConn) * conn_n * 2;
	if (!(cl = kzalloc(size, GFP_KERNEL)))
		return -ENOMEM;
	if (!(srv_cls = kcalloc(sg->srv_n, sizeof(TfwHashSrvConnList),
				GFP_KERNEL))) {
		kfree(cl);
		return -ENOMEM;
	}
	offset = sizeof(TfwHashConnList) + sizeof(TfwHashConn) * conn_n;

	/*
	 * The add_group() function can be called during live reconfiguration,
	 * assign srv->sched_data after the data is fully prepared and valid.
	 */
	list_for_each_entry(srv, &sg->srv_list, list) {
		TfwSrvConn *conn;
		unsigned long srv_hash = __calc_srv_hash(srv);

		srv_cls[i].srv = srv;
		srv_cls[i].cl = (void *)cl + offset;
		offset += sizeof(TfwHashConnList)
				+ sizeof(TfwHashConn) * srv->conn_n;
		++i;

		list_for_each_entry(conn, &srv->conn_list, list) {
			unsigned long hash;
			do {
				hash = __hash_64(srv_hash ^ seed);
				seed += seed_inc;
			} while (__add_conn(cl, conn, hash));
		}
	}
	/* Create per-server connection lists. */
	__fill_srv_lists(cl, sg->srv_n, srv_cls);

	rcu_assign_pointer(sg->sched_data, cl);
	kfree(srv_cls);

	return 0;
}

static TfwScheduler tfw_sched_hash = {
	.name		= "hash",
	.list		= LIST_HEAD_INIT(tfw_sched_hash.list),
	.add_grp	= tfw_sched_hash_add_grp,
	.del_grp	= tfw_sched_hash_del_grp,
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
