/**
 *		Tempesta FW
 *
 * Servers handling.
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
#include <linux/slab.h>
#include <linux/rwsem.h>

#include "lib/hash.h"
#include "apm.h"
#include "client.h"
#include "log.h"
#include "server.h"

/* Use SLAB for frequent server allocations in forward proxy mode. */
static struct kmem_cache *srv_cache;
/* Total number of created server groups. */
static atomic64_t act_sg_n = ATOMIC64_INIT(0);

/*
 * Server group management.
 *
 * There are two lists of server groups (hashes are used to speedup lookups
 * in installations with thousands of server groups):
 *
 * sg_hash		- list of active groups,
 * sg_hash_reconfig	- list of groups filled during configuration parsing.
 *
 * On the TempestaFW start or live reconfiguration a new configuration is
 * parsed and all server groups declared in the configuration are added into
 * sg_hash_reconfig. If the configuration is valid sg_hash_reconfig replaces
 * sg_hash by tfw_sg_apply_reconfig(). Otherwize reconfig list is cleared by
 * sock_srv.c
 *
 * The same server group instance may be listed in both sg_hash and
 * sg_hash_reconfig lists. That's why TfwSrvGroup has members .list and
 * .list_reconfig.
 *
 * The list of active server groups may change only during configuration
 * processing.
 *
 * Lifetime of both TfwServer and TfwSrvGroup is controlled by reference
 * counters. Note, that TfwSrvGroup stores references to servers while
 * TfwServer stores back reference to it's server group. Thus servers
 * must be removed from a server group to break the reference loop.
 * When a server connection is scheduled for connect it increments server's
 * reference count and decrements it after intended disconnect.
 */
#define TFW_SG_HBITS	10
static DECLARE_HASHTABLE(sg_hash, TFW_SG_HBITS);
static DECLARE_HASHTABLE(sg_hash_reconfig, TFW_SG_HBITS);
/*
 * The lock is used in process context only (e.g. (re-)configuration or
 * procfs), so it should be sleepable and don't care too much about
 * concurrently.
 */
static DECLARE_RWSEM(sg_sem);

void
tfw_server_destroy(TfwServer *srv)
{
	if (srv->cleanup)
		srv->cleanup(srv);
	/* Close all connections before freeing the server! */
	BUG_ON(!list_empty(&srv->conn_list));
	BUG_ON(timer_pending(&srv->gs_timer));

	tfw_apm_del_srv(srv);
	if (srv->sg)
		tfw_sg_put(srv->sg);
	kmem_cache_free(srv_cache, srv);
}

TfwServer *
tfw_server_create(const TfwAddr *addr)
{
	TfwServer *srv = kmem_cache_alloc(srv_cache, GFP_KERNEL | __GFP_ZERO);
	if (!srv)
		return NULL;

	tfw_peer_init((TfwPeer *)srv, addr);
	INIT_LIST_HEAD(&srv->list);
	atomic64_set(&srv->refcnt, 1);

	return srv;
}

TfwServer *
tfw_server_lookup(TfwSrvGroup *sg, TfwAddr *addr)
{
	TfwServer *srv;

	down_read(&sg_sem);

	list_for_each_entry(srv, &sg->srv_list, list) {
		if (tfw_addr_eq(&srv->addr, addr)) {
			tfw_server_get(srv);
			up_read(&sg_sem);
			return srv;
		}
		tfw_srv_loop_sched_rcu();
	}

	up_read(&sg_sem);

	return NULL;
}

int
tfw_server_start_sched(TfwServer *srv)
{
	TFW_DBG_ADDR("Start scheduler for server", &srv->addr, TFW_WITH_PORT);
	if (srv->sg->sched->add_srv)
		return srv->sg->sched->add_srv(srv);

	return 0;
}

void
tfw_server_stop_sched(TfwServer *srv)
{
	TFW_DBG_ADDR("Stop scheduler for server", &srv->addr, TFW_WITH_PORT);
	if (srv->sg->sched && srv->sg->sched->del_srv)
		srv->sg->sched->del_srv(srv);
}

/**
 * Look up Server Group by name, and return it to caller.
 *
 * The search is performed across active groups list.
 */
TfwSrvGroup *
tfw_sg_lookup(const char *name, unsigned int len)
{
	TfwSrvGroup *sg;
	unsigned long key = hash_calc(name, len);

	down_read(&sg_sem);
	hash_for_each_possible(sg_hash, sg, list, key) {
		if (tfw_sg_name_match(sg, name, len)) {
			tfw_sg_get(sg);
			up_read(&sg_sem);
			return sg;
		}
		tfw_srv_loop_sched_rcu();
	}
	up_read(&sg_sem);

	return NULL;
}

/**
 * Look up Server Group by name, and return it to caller.
 *
 * This function is called on initial configuration or live reconfiguration.
 * The caller needs object available in the new configuration, so the search
 * is performed across reconfig list.
 */
TfwSrvGroup *
tfw_sg_lookup_reconfig(const char *name, unsigned int len)
{
	TfwSrvGroup *sg;
	unsigned long key = hash_calc(name, len);

	down_read(&sg_sem);
	hash_for_each_possible(sg_hash_reconfig, sg, list_reconfig, key) {
		if (tfw_sg_name_match(sg, name, len)) {
			tfw_sg_get(sg);
			up_read(&sg_sem);
			return sg;
		}
		tfw_srv_loop_sched_rcu();
	}
	up_read(&sg_sem);

	return NULL;
}
EXPORT_SYMBOL(tfw_sg_lookup_reconfig);

/**
 * Create a new Server Group.
 *
 * This function is called only on configuration processing.
 */
TfwSrvGroup *
tfw_sg_new(const char *name, unsigned int len, gfp_t flags)
{
	TfwSrvGroup *sg;
	size_t name_size = strlen(name) + 1;

	TFW_DBG("Create new server group: '%s'\n", name);

	sg = kzalloc(sizeof(*sg) + name_size, flags);
	if (!sg)
		return NULL;

	INIT_HLIST_NODE(&sg->list);
	INIT_HLIST_NODE(&sg->list_reconfig);
	INIT_LIST_HEAD(&sg->srv_list);
	atomic64_set(&sg->refcnt, 1);
	sg->nlen = len;
	memcpy(sg->name, name, name_size);

	atomic64_inc(&act_sg_n);

	return sg;
}

/**
 * Add a Server Group to the list.
 *
 * This function is called only on configuration processing.
 */
int
tfw_sg_add_reconfig(TfwSrvGroup *sg)
{
	unsigned long key;

	TFW_DBG("Add new server group: '%s'\n", sg->name);

	if (tfw_sg_lookup_reconfig(sg->name, sg->nlen)) {
		TFW_ERR("duplicate server group: '%s'\n", sg->name);
		return -EINVAL;
	}

	key = hash_calc(sg->name, sg->nlen);

	tfw_sg_get(sg);
	down_write(&sg_sem);
	hash_add(sg_hash_reconfig, &sg->list_reconfig, key);
	up_write(&sg_sem);

	return 0;
}

/**
 * Replace active Server Group list with reconfig group list.
 *
 * This function is called when configuration is processed successfully.
 * Server groups unused in new configuration are removed from all lists,
 * but not destroyed since some modules could still use them. sock_srv.c is
 * responsible for destroying them.
 */
void
tfw_sg_apply_reconfig(struct hlist_head *del_sg)
{
	int i;
	unsigned long key;
	struct hlist_node *tmp;
	TfwSrvGroup *sg;

	TFW_DBG("Apply reconfig groups\n");

	down_write(&sg_sem);

	hash_for_each_safe(sg_hash, i, tmp, sg, list) {
		if (hlist_unhashed(&sg->list_reconfig)) {
			hash_del(&sg->list);
			hlist_add_head(&sg->list, del_sg);
		}
		else {
			hash_del(&sg->list_reconfig);
			tfw_sg_put(sg);
		}
		tfw_srv_loop_sched_rcu();
	}
	hash_for_each_safe(sg_hash_reconfig, i, tmp, sg, list_reconfig) {
		hash_del(&sg->list_reconfig);
		key = hash_calc(sg->name, sg->nlen);
		hash_add(sg_hash, &sg->list, key);
		tfw_srv_loop_sched_rcu();
	}

	up_write(&sg_sem);
}

/**
 * Clear reconfig group list.
 *
 * This function is called when configuration processing is failed. Simply
 * clean reconfig list, sock_srv.c is responsible to remove all groups
 * added to the list.
 */
void
tfw_sg_drop_reconfig(void)
{
	int i;
	TfwSrvGroup *sg;
	struct hlist_node *tmp;

	down_write(&sg_sem);
	hash_for_each_safe(sg_hash_reconfig, i, tmp, sg, list_reconfig) {
		hash_del(&sg->list_reconfig);
		tfw_sg_put(sg);
		tfw_srv_loop_sched_rcu();
	}
	up_write(&sg_sem);
}

/**
 * Add a server to a server group.
 * This function is called only on configuration processing.
 */
void
tfw_sg_add_srv(TfwSrvGroup *sg, TfwServer *srv)
{
	BUG_ON(srv->sg);
	tfw_server_get(srv);
	tfw_sg_get(sg);
	srv->sg = sg;

	TFW_DBG2("Add new backend server to group '%s'\n", sg->name);
	down_write(&sg_sem);
	list_add(&srv->list, &sg->srv_list);
	++sg->srv_n;
	up_write(&sg_sem);
}

/**
 * Remove server from group.
 * This function is called only on configuration processing.
 */
void
__tfw_sg_del_srv(TfwSrvGroup *sg, TfwServer *srv, bool lock)
{
	BUG_ON(srv->sg != sg);
	/*
	 * Don't remove srv->sg reference, it's not supposed, that a server can
	 * change it's group on the fly.
	 */

	TFW_DBG2("Remove backend server from group '%s'\n", sg->name);

	if (lock)
		down_write(&sg_sem);
	list_del_init(&srv->list);
	--sg->srv_n;
	if (lock)
		up_write(&sg_sem);
	tfw_server_put(srv);
}

int
tfw_sg_start_sched(TfwSrvGroup *sg, TfwScheduler *sched, void *arg)
{
	TFW_DBG2("Start scheduler '%s' for group '%s'\n",
		 sched->name, sg->name);
	sg->sched = sched;
	if (sched->add_grp)
		return sched->add_grp(sg, arg);

	return 0;
}

void
tfw_sg_stop_sched(TfwSrvGroup *sg)
{
	TFW_DBG2("Stop scheduler '%s' for group '%s'\n",
		 (sg->sched ? sg->sched->name : ""), sg->name);
	if (sg->sched && sg->sched->del_grp)
		sg->sched->del_grp(sg);
}

/**
 * Iterate over all servers of given server group @sg and call @cb for
 * each server.
 * @cb is called under spin-lock, so can't sleep.
 * @cb is considered as updater, so write lock is used.
 */
int
__tfw_sg_for_each_srv(TfwSrvGroup *sg,
		      int (*cb)(TfwSrvGroup *sg, TfwServer *srv, void *data),
		      void *data)
{
	int r = 0;
	TfwServer *srv, *tmp;

	down_write(&sg_sem);
	list_for_each_entry_safe(srv, tmp, &sg->srv_list, list) {
		if ((r = cb(sg, srv, data)))
			break;
		tfw_srv_loop_sched_rcu();
	}
	up_write(&sg_sem);

	return r;
}

/**
 * Iterate over all the active server groups and call @cb for each server.
 * @cb is called under spin-lock, so can't sleep.
 * @cb is considered as updater, so write lock is used.
 */
int
tfw_sg_for_each_srv(int (*sg_cb)(TfwSrvGroup *sg),
		    int (*srv_cb)(TfwServer *srv))
{
	int i, r = 0;
	TfwSrvGroup *sg;
	TfwServer *srv, *tmp;

	down_write(&sg_sem);
	hash_for_each(sg_hash, i, sg, list) {
		if (sg_cb && (r = sg_cb(sg)))
			goto end;
		list_for_each_entry_safe(srv, tmp, &sg->srv_list, list) {
			if ((r = srv_cb(srv)))
				goto end;
			tfw_srv_loop_sched_rcu();
		}
		tfw_srv_loop_sched_rcu();
	}
end:
	up_write(&sg_sem);

	return r;
}

/**
 * Same as tfw_sg_for_each_srv() but iterates over reconfig server group lists.
 */
int
tfw_sg_for_each_srv_reconfig(int (*cb)(TfwServer *srv))
{
	int i, r = 0;
	TfwSrvGroup *sg;
	TfwServer *srv, *tmp;

	down_write(&sg_sem);
	hash_for_each(sg_hash_reconfig, i, sg, list_reconfig) {
		list_for_each_entry_safe(srv, tmp, &sg->srv_list, list)
			if ((r = cb(srv)))
				goto end;
		tfw_srv_loop_sched_rcu();
	}
end:
	up_write(&sg_sem);

	return r;
}

/**
 * Release a single server group with servers.
 */
void
tfw_sg_destroy(TfwSrvGroup *sg)
{
	TFW_DBG2("release group: '%s'\n", sg->name);
	WARN_ON(!list_empty(&sg->srv_list));

	kfree(sg);
	atomic64_dec(&act_sg_n);
}
EXPORT_SYMBOL(tfw_sg_destroy);

/**
 * Release server group and prepare it for removal. The group will be destroyed
 * once it's reference count will reach zero.
 */
void
tfw_sg_release(TfwSrvGroup *sg)
{
	TfwServer *srv, *srv_tmp;

	tfw_sg_stop_sched(sg);

	down_write(&sg_sem);
	list_for_each_entry_safe(srv, srv_tmp, &sg->srv_list, list) {
		__tfw_sg_del_srv(sg, srv, false);
		tfw_srv_loop_sched_rcu();
	}
	up_write(&sg_sem);
}

/**
 * Release all active server groups with all servers.
 */
void
tfw_sg_release_all(void)
{
	int i;
	TfwSrvGroup *sg;
	struct hlist_node *tmp;
	TfwServer *srv, *srv_tmp;

	down_write(&sg_sem);

	hash_for_each_safe(sg_hash, i, tmp, sg, list) {
		tfw_sg_stop_sched(sg);
		list_for_each_entry_safe(srv, srv_tmp, &sg->srv_list, list) {
			__tfw_sg_del_srv(sg, srv, false);
			tfw_srv_loop_sched_rcu();
		}
		hash_del(&sg->list);
		tfw_sg_put(sg);
		tfw_srv_loop_sched_rcu();
	}
	hash_init(sg_hash);

	up_write(&sg_sem);
}

/**
 * Waiting for destruction of all server groups and servers.
 */
void
tfw_sg_wait_release(void)
{
	tfw_objects_wait_release(&act_sg_n, 5, "server group");
}

int __init
tfw_server_init(void)
{
	srv_cache = kmem_cache_create("tfw_srv_cache", sizeof(TfwServer),
				       0, 0, NULL);
	if (!srv_cache)
		return -ENOMEM;
	return 0;
}

void
tfw_server_exit(void)
{
	kmem_cache_destroy(srv_cache);
}
