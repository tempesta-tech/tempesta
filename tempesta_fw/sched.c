/**
 *		Tempesta FW
 *
 * Requst schedulers interface.
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
#include "tempesta_fw.h"
#include "log.h"
#include "server.h"
#include "http_sess.h"

/*
 * Normally, schedulers are separate modules. Schedulers register
 * and deregister themselves via register()/unregister() functions.
 * Registered schedulers are placed on the list and can be used by
 * Tempesta. The list is traversed on each HTTP message in search
 * for an outgoing connection, so the list traversal operation is
 * critical for speed. The event of a scheduler's registration or
 * deregistration is rare. The list of schedulers is traversed on
 * multiple CPUs simultaneously. These properties and the goals
 * make RCU locks a beneficial choice.
 */

static LIST_HEAD(sched_list);
static DEFINE_SPINLOCK(sched_lock);

static inline TfwSrvConn *
__get_srv_conn(TfwMsg *msg)
{
	TfwSrvConn *srv_conn;
	TfwScheduler *sched;

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &sched_list, list) {
		if (!sched->sched_grp)
			break;
		if ((srv_conn = sched->sched_grp(msg))) {
			rcu_read_unlock();
			return srv_conn;
		}
	}
	rcu_read_unlock();

	return NULL;
}

static inline TfwSrvConn *
__try_conn(TfwMsg *msg, TfwStickyConn *st_conn)
{
	TfwServer *srv;

	if (unlikely(!st_conn->srv_conn))
		return NULL;

	if (!tfw_srv_conn_restricted(st_conn->srv_conn)
	    && !tfw_srv_conn_queue_full(st_conn->srv_conn)
	    && !tfw_srv_conn_hasnip(st_conn->srv_conn)
	    && tfw_srv_conn_get_if_live(st_conn->srv_conn))
	{
		return st_conn->srv_conn;
	}

	/* Try to sched from the same server. */
	srv = (TfwServer *)st_conn->srv_conn->peer;

	return srv->sg->sched->sched_srv(msg, srv);
}

static inline TfwSrvConn *
__get_sticky_srv_conn(TfwMsg *msg, TfwHttpSess *sess)
{
	TfwStickyConn *st_conn = &sess->st_conn;
	TfwSrvConn *srv_conn;

	read_lock(&st_conn->conn_lock);

	if ((srv_conn = __try_conn(msg, st_conn))) {
		read_unlock(&st_conn->conn_lock);
		return srv_conn;
	}

	read_unlock(&st_conn->conn_lock);

	if (st_conn->srv_conn) {
		/* Failed to sched from the same server. */
		TfwServer *srv = (TfwServer *)st_conn->srv_conn->peer;
		char addr_str[TFW_ADDR_STR_BUF_SIZE] = { 0 };

		tfw_addr_ntop(&srv->addr, addr_str, sizeof(addr_str));

		if (!(srv->sg->flags & TFW_SRV_STICKY_FAILOVER)) {
			TFW_ERR("sched %s: Unable to schedule new request in "
				"session to server %s in group %s\n",
				srv->sg->sched->name, addr_str, srv->sg->name);
			return NULL;
		}
		else {
			TFW_WARN("sched %s: Unable to schedule new request in "
				 "session to server %s in group %s,"
				 " fallback to a new server\n",
				 srv->sg->sched->name, addr_str, srv->sg->name);
		}
	}

	write_lock(&st_conn->conn_lock);
	/*
	 * Connection and server may return back online while we were trying
	 * for a lock.
	 */
	if ((srv_conn = __try_conn(msg, st_conn)))
		goto done;

	if (st_conn->main_sg)
		srv_conn = tfw_sched_get_sg_srv_conn(msg, st_conn->main_sg,
						     st_conn->backup_sg);
	else
		srv_conn = __get_srv_conn(msg);

	if (srv_conn
	    && (((TfwServer *)srv_conn->peer)->sg->flags & TFW_SRV_STICKY)) {
		st_conn->srv_conn = srv_conn;
	}

done:
	write_unlock(&st_conn->conn_lock);

	return srv_conn;
}

/*
 * Find an outgoing connection for an HTTP message.
 *
 * Where an HTTP message goes in controlled by schedulers. It may
 * or may not depend on properties of HTTP message itself. In any
 * case, schedulers are polled in sequential order until a result
 * is received. Schedulers that distribute HTTP messages among
 * server groups come first in the list. The search stops when
 * these schedulers run out.
 *
 * This function is always called in SoftIRQ context.
 */
TfwSrvConn *
tfw_sched_get_srv_conn(TfwMsg *msg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwHttpSess *sess = req->sess;

	/* Sticky sessions disabled or client doesn't support cookies. */
	if (!sess)
		return __get_srv_conn(msg);

	return __get_sticky_srv_conn(msg, sess);
}

TfwSrvConn *
tfw_sched_get_sg_srv_conn(TfwMsg *msg, TfwSrvGroup *main_sg,
			  TfwSrvGroup *backup_sg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwSrvConn *srv_conn;

	BUG_ON(!main_sg);
	TFW_DBG2("sched: use server group: '%s'\n", sg->name);

	if (req->sess && (main_sg->flags & TFW_SRV_STICKY)) {
		TfwStickyConn *st_conn = &req->sess->st_conn;

		/*
		 * @st_conn->lock is already acquired for writing, if called
		 * from @__get_sticky_srv_conn().
		 */
		st_conn->main_sg = main_sg;
		st_conn->backup_sg = backup_sg;
	}

	srv_conn = main_sg->sched->sched_sg(msg, main_sg);

	if (unlikely(!srv_conn && backup_sg)) {
		TFW_DBG("sched: the main group is offline, use backup: '%s'\n",
			sg->name);
		srv_conn = backup_sg->sched->sched_sg(msg, backup_sg);
	}

	if (unlikely(!srv_conn))
		TFW_DBG2("sched: Unable to select server from group '%s'\n",
			 sg->name);

	return srv_conn;
}
EXPORT_SYMBOL(tfw_sched_get_sg_srv_conn);

/*
 * Lookup a scheduler by name.
 *
 * If @name is NULL, then the first available scheduler is returned.
 * Called only in user context, and used in configuration routines.
 */
TfwScheduler *
tfw_sched_lookup(const char *name)
{
	TfwScheduler *sched;

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &sched_list, list) {
		if (!name || !strcasecmp(name, sched->name)) {
			rcu_read_unlock();
			return sched;
		}
	}
	rcu_read_unlock();

	return NULL;
}

/*
 * Register a new scheduler.
 * Called only in user context.
 */
int
tfw_sched_register(TfwScheduler *sched)
{
	TFW_LOG("Registering new scheduler: %s\n", sched->name);
	BUG_ON(!list_empty(&sched->list));

	/* Add group scheduling schedulers at head of the list. */
	spin_lock(&sched_lock);
	if (sched->sched_grp)
		list_add_rcu(&sched->list, &sched_list);
	else
		list_add_tail_rcu(&sched->list, &sched_list);
	spin_unlock(&sched_lock);

	return 0;
}
EXPORT_SYMBOL(tfw_sched_register);

/*
 * Deregister a new scheduler.
 * Called only in user context.
 */
void
tfw_sched_unregister(TfwScheduler *sched)
{
	TFW_LOG("Un-registering scheduler: %s\n", sched->name);
	BUG_ON(list_empty(&sched->list));

	spin_lock(&sched_lock);
	list_del_rcu(&sched->list);
	spin_unlock(&sched_lock);

	/* Make sure the removed @sched is not used. */
	synchronize_rcu();
	/* Clear up scheduler for future use. */
	INIT_LIST_HEAD(&sched->list);
}
EXPORT_SYMBOL(tfw_sched_unregister);
