/**
 *		Tempesta FW
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
 */
#include <linux/kernel.h>
#include <linux/module.h>

#include "log.h"
#include "server.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta round-robin scheduler");
MODULE_VERSION("0.2.0");
MODULE_LICENSE("GPL");

#define BANNER "tfw_sched_rr: "
#define ERR(...) TFW_ERR(BANNER __VA_ARGS__)
#define DBG(...) TFW_DBG(BANNER __VA_ARGS__)

typedef struct {
	atomic_t	rr_counter;
	size_t		conn_n;
	TfwConnection	*conns[TFW_SRV_MAX_CONN];
} TfwConnRrList;

typedef struct {
	atomic_t	rr_counter;
	size_t		srv_n;
	TfwConnRrList	conn_lists[TFW_SG_MAX_SRV];
} TfwSrvRrList;

/**
 * On each subsequent call the function returns the next server in the group.
 *
 * Parallel connections to the same server are also rotated in the
 * round-robin manner.
 */
static TfwConnection *
tfw_sched_rr_get_srv_conn(TfwMsg *msg, TfwSrvGroup *sg)
{
	size_t idx;
	TfwConnection *conn;
	TfwSrvRrList *srv_list;
	TfwConnRrList *conn_list;

	srv_list = sg->sched_data;
	BUG_ON(!srv_list);

	/* 1. Select a server (represented by a list of connections). */
	if (unlikely(!srv_list->srv_n))
		return NULL;
	idx = atomic_inc_return(&srv_list->rr_counter) % srv_list->srv_n;
	conn_list = &srv_list->conn_lists[idx];

	/* 2. Select a connection in the same round-robin manner. */
	BUG_ON(!conn_list || !conn_list->conn_n);
	idx = atomic_inc_return(&conn_list->rr_counter) % conn_list->conn_n;
	conn = conn_list->conns[idx];

	BUG_ON(!conn);
	return conn;
}

static void
tfw_sched_rr_alloc_data(TfwSrvGroup *sg)
{
	BUG_ON(sg->sched_data);
	sg->sched_data = kzalloc(sizeof(TfwSrvRrList), GFP_KERNEL);
	BUG_ON(!sg->sched_data);
}

static void
tfw_sched_rr_free_data(TfwSrvGroup *sg)
{
	BUG_ON(!sg->sched_data);
	kfree(sg->sched_data);
	sg->sched_data = NULL;
}

static void
tfw_sched_rr_update_data(TfwSrvGroup *sg)
{
	TfwServer *srv;
	TfwConnection *conn;
	TfwSrvRrList *srv_list;
	TfwConnRrList *conn_list;
	size_t srv_idx, conn_idx;

	srv_list = sg->sched_data;
	BUG_ON(!srv_list);

	srv_idx = 0;
	list_for_each_entry(srv, &sg->srv_list, list) {
		if (list_empty(&srv->conn_list))
			continue;

		conn_idx = 0;
		conn_list = &srv_list->conn_lists[srv_idx];

		list_for_each_entry(conn, &srv->conn_list, list) {
			/*
			 * Skip not-yet-established connections.
			 *
			 * A connection may die by the time someone wants
			 * to use it. That has to be dealt with elsewhere.
			 * It should be assumed that scheduler's data is
			 * only semi-accurate at any point of time.
			 */
			spin_lock(&conn->splock);
			if (!conn->sk) {
				spin_unlock(&conn->splock);
				continue;
			}
			spin_unlock(&conn->splock);

			conn_list->conns[conn_idx] = conn;
			++conn_idx;
		}

		conn_list->conn_n = conn_idx;
		++srv_idx;
	}
	srv_list->srv_n = srv_idx;
}

static TfwScheduler tfw_sched_rr = {
	.name		= "round-robin",
	.list		= LIST_HEAD_INIT(tfw_sched_rr.list),
	.add_grp	= tfw_sched_rr_alloc_data,
	.del_grp	= tfw_sched_rr_free_data,
	.update_grp	= tfw_sched_rr_update_data,
	.sched_srv	= tfw_sched_rr_get_srv_conn,
};

int
tfw_sched_rr_init(void)
{
	DBG("init\n");
	return tfw_sched_register(&tfw_sched_rr);
}
module_init(tfw_sched_rr_init);

void
tfw_sched_rr_exit(void)
{
	DBG("exit\n");
	tfw_sched_unregister(&tfw_sched_rr);
}
module_exit(tfw_sched_rr_exit);

