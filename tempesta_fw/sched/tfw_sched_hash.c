/**
 *		Tempesta FW
 *
 * Hash-based HTTP request scheduler.
 * The scheduler computes hash of URI and Host header fields of a HTTP request
 * and uses the hash value as an index in the array of servers added with
 * the tfw_sched_add_srv() function. Therefore, requests with the same URI and
 * Host are mapped to the same server (unless the list of servers is changed).
 *
 * TODO:
 *  - Replace the hash function (currnlty djb2 is used).
 *  - Refactoring: there is simpilar logic in all scheduler modules related
 *    to lists of TfwServer objects. The code should be extracted and re-used.
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
 *
 */
#include <linux/module.h>

#include "log.h"
#include "sched.h"
#include "http_msg.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta hash-based scheduler");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");


#define BANNER "tfw_sched_hash: "
#define ERR(...) TFW_ERR(BANNER __VA_ARGS__)
#define LOG(...) TFW_LOG(BANNER __VA_ARGS__)
#define DBG(...) TFW_DBG(BANNER __VA_ARGS__)

/* TODO: change this to a global setting after merging sched/http. */
#define MAX_SERVERS_N 64

/**
 * Servers added to the scheduler are stored in this statically allocated array.
 * Only writes are protected with the servers_write_lock, reads are lock-free.
 */
static TfwServer *servers[MAX_SERVERS_N];
static int servers_n;
static DEFINE_SPINLOCK(servers_write_lock);

static int
find_srv_idx(TfwServer *srv)
{
	int i;
	for (i = 0; i < servers_n; ++i) {
		if (servers[i] == srv)
			return i;
	}

	return -1;
}

static TfwServer *
tfw_sched_hash_get_srv(TfwMsg *msg)
{
	TfwServer *srv;
	int n;

	unsigned long hash = tfw_http_req_key_calc((TfwHttpReq *)msg);

	do {
		n = servers_n;
		if (!n) {
			ERR("No servers added to the scheduler\n");
			return NULL;
		}
		srv = servers[hash % n];
	} while (!srv);

	return srv;
}

static int
tfw_sched_hash_add_srv(TfwServer *srv)
{
	int ret = 0;

	spin_lock_bh(&servers_write_lock);
	if (servers_n >= MAX_SERVERS_N) {
		ERR("Can't add a server to the scheduler - the list is full\n");
		ret = -ENOMEM;
	} else if (find_srv_idx(srv) >= 0) {
		ERR("Can't add the server to the scheduler - already added\n");
		ret = -EEXIST;
	} else {
		servers[servers_n] = srv;
		++servers_n;
	}
	spin_unlock_bh(&servers_write_lock);

	return ret;
}

static int
tfw_sched_hash_del_srv(TfwServer *srv)
{
	int ret = 0;
	int i;

	spin_lock_bh(&servers_write_lock);
	i = find_srv_idx(srv);
	if (i < 0) {
		ERR("Can't delete the server from the scheduler - not found\n");
		ret = -ENOENT;
	} else {
		servers[i] = servers[servers_n - 1];
		--servers_n;
		servers[servers_n] = NULL;
	}
	spin_unlock_bh(&servers_write_lock);

	return ret;
}

int
tfw_sched_hash_init(void)
{
	static TfwScheduler tfw_sched_hash_mod = {
		.name = "hash",
		.get_srv = tfw_sched_hash_get_srv,
		.add_srv = tfw_sched_hash_add_srv,
		.del_srv = tfw_sched_hash_del_srv
	};

	LOG("init\n");

	return tfw_sched_register(&tfw_sched_hash_mod);
}
module_init(tfw_sched_hash_init);

void
tfw_sched_hash_exit(void)
{
	tfw_sched_unregister();
}
module_exit(tfw_sched_hash_exit);
