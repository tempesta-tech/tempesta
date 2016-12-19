/**
 *		Tempesta FW
 *
 * Requst schedulers interface.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#include "http.h"
#include "server.h"

/**
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

/**
 * Schedule connection to either to main @main_sg server group or to backup
 * @backup_sg if scheduling to main group failed.
 */
static inline TfwConnection *
sched_conn(TfwMsg *msg, TfwSrvGroup *main_sg, TfwSrvGroup *backup_sg)
{
	TfwConnection *conn;
	TfwSrvGroup *sg = main_sg;

	TFW_DBG2("sched: use server group: '%s'\n", sg->name);
	conn = sg->sched->sched_sg_conn(msg, sg);

	if (unlikely(!conn && backup_sg)) {
		sg = backup_sg;
		TFW_DBG("sched: the main group is offline, use backup:"
			" '%s'\n", sg->name);
		conn = sg->sched->sched_sg_conn(msg, sg);
	}

	if (unlikely(!conn))
		TFW_DBG2("sched: Unable to select server from group"
			 " '%s'\n", sg->name);

	return conn;
}

/**
 * Try to reuse last connection to @sg server group saved in http session.
 * Fallback to scheduling from server group for newly setting connections to
 * @sg or if sticky sessions failovering is enabled.
 *
 * @return TfwConnection *, NULL, or -1 if message cannot be scheduled and must
 * be dropped.
 */
static TfwConnection *
sched_conn_sticky(TfwMsg *msg, TfwSrvGroup *sg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwConnection *conn;

	conn = tfw_http_sess_get_conn(req, sg);
	if (conn) {
		TfwServer *srv = (TfwServer *)conn->peer;

		if (tfw_connection_get_if_nfo(conn))
			return conn;

		if ((conn = srv->sg->sched->sched_srv_conn(msg, srv)))
			return conn;

		if (!tfw_cfg_sticky_sessions_failover) {
			return (void *)(-1);
		}
		else {
			char addr_str[TFW_ADDR_STR_BUF_SIZE] = { 0 };

			tfw_addr_fmt_v6(&srv->addr.v6.sin6_addr, 0, addr_str);
			TFW_WARN("sched: Unable to reschedule request to the "
				 "same server %s, schedule from server group\n",
				 addr_str);
		}
	}

	/*
	 * Schedule message to main server group if the message is the first
	 * to that server group or last connected server offline
	 */
	conn = sg->sched->sched_sg_conn(msg, sg);
	if (unlikely(!conn))
		TFW_DBG2("sched: Unable to select server from group"
			 " '%s'\n", sg->name);
	return conn;
}

/**
 * Schedule connection to the same server used last time either from main
 * @main_sg server group or from backup @backup_sg. Called only when sticky
 * sessions are enabled.
 */
static inline TfwConnection *
tfw_sched_get_srv_sticky_conn(TfwMsg *msg, TfwSrvGroup *main_sg,
			      TfwSrvGroup *backup_sg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwConnection *conn;

	TFW_DBG2("sched: use sticky connections\n");

	conn = sched_conn_sticky(msg, main_sg);

	if (unlikely(conn == (void *)(-1)))
		return NULL;

	if (unlikely(!conn && backup_sg)) {
		conn = sched_conn_sticky(msg, backup_sg);
		if (unlikely(conn == (void *)(-1)))
			return NULL;
	}

	if (conn && tfw_http_sess_save_conn(req, main_sg, conn))
		return NULL;

	return conn;
}

/**
 * Helper for group schedulers: schedule message for the most apropriate server.
 * Supports sticky sessions.
 */
TfwConnection *
tfw_sched_get_conn_from_sg(TfwMsg *msg, TfwSrvGroup *main_sg,
			   TfwSrvGroup *backup_sg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwHttpSess *sess = req->sess;

	BUG_ON(!main_sg);

	if (tfw_cfg_sticky_sessions) {
		if (sess)
			return tfw_sched_get_srv_sticky_conn(msg, main_sg,
							     backup_sg);

		TFW_WARN("sticky sessions are enabled but sticky cookies are "
			 "not enforced\n");
	}

	return sched_conn(msg, main_sg, backup_sg);
}
EXPORT_SYMBOL(tfw_sched_get_conn_from_sg);

/**
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
TfwConnection *
tfw_sched_get_srv_conn(TfwMsg *msg)
{
	TfwConnection *conn;
	TfwScheduler *sched;

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &sched_list, list) {
		if (!sched->sched_grp)
			break;
		conn = sched->sched_grp(msg);
		if (conn) {
			rcu_read_unlock();
			return conn;
		}
	}
	rcu_read_unlock();

	return NULL;
}

/**
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

/**
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

/**
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
	/* Clear up scheduler for future use */
	INIT_LIST_HEAD(&sched->list);
}
EXPORT_SYMBOL(tfw_sched_unregister);
