/**
 *		Tempesta FW
 *
 * Servers handling.
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
#include <linux/slab.h>

#include "log.h"
#include "server.h"
#include "client.h"
#include "apm.h"

/* Use SLAB for frequent server allocations in forward proxy mode. */
static struct kmem_cache *srv_cache;
/* Total number of created server groups. */
static atomic64_t act_sg_n = ATOMIC64_INIT(0);

/*
 * Server group management.
 *
 * There are two lists of server groups:
 * sg_list		- list of active groups,
 * sg_list_reconfig	- list of groups filled during configuration parsing.
 *
 * On the TempestaFW start or live reconfiguration a new configuration is
 * parsed and all server groups declared in the configuration are added into
 * sg_list_reconfig. If the configuration is valid sg_list_reconfig replaces
 * sg_list by tfw_sg_apply_reconfig(). Otherwize reconfig list is cleared by
 * sock_srv.c
 *
 * The same server group instance may be listed in both sg_list and
 * sg_list_reconfig lists. That's why TfwSrvGroup has members .list and
 * .list_reconfig.
 *
 * The list of active server groups may change only during configuration
 * processing.
 *
 * Lifetime of both TfwServer and TfwSrvGroup is controlled by reference
 * counters. Note, that TfwSrvGroup stores references to servers while
 * TfwServer stores back reference to it's server group. Thus servers
 * must be removed from a server group to breack the reference loop.
 * When a server connection is scheduled for connect it increments server's
 * reference count and decrements it after inteded disconnect.
 */
static LIST_HEAD(sg_list);
static LIST_HEAD(sg_list_reconfig);
static DEFINE_RWLOCK(sg_lock);

void
tfw_server_destroy(TfwServer *srv)
{
	if (srv->cleanup)
		srv->cleanup(srv);
	/* Close all connections before freeing the server! */
	BUG_ON(!list_empty(&srv->conn_list));

	tfw_apm_del_srv(srv);
	if (srv->sg)
		tfw_sg_put(srv->sg);
	kmem_cache_free(srv_cache, srv);
}

TfwServer *
tfw_server_create(const TfwAddr *addr)
{
	TfwServer *srv = kmem_cache_alloc(srv_cache, GFP_ATOMIC | __GFP_ZERO);
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

	write_lock(&sg->lock);
	list_for_each_entry(srv, &sg->srv_list, list)
		if (tfw_addr_eq(&srv->addr, addr)) {
			tfw_server_get(srv);
			write_unlock(&sg->lock);
			return srv;
		}
	write_unlock(&sg->lock);

	return NULL;
}

/**
 * Look up Server Group by name, and return it to caller.
 *
 * The search is performed across active groups list.
 */
TfwSrvGroup *
tfw_sg_lookup(const char *name)
{
	TfwSrvGroup *sg;

	read_lock(&sg_lock);
	list_for_each_entry(sg, &sg_list, list) {
		if (!strcasecmp(sg->name, name)) {
			tfw_sg_get(sg);
			read_unlock(&sg_lock);
			return sg;
		}
	}
	read_unlock(&sg_lock);
	return NULL;
}
EXPORT_SYMBOL(tfw_sg_lookup);

/**
 * Look up Server Group by name, and return it to caller.
 *
 * This function is called on initial configuration or live reconfiguration.
 * The caller needs object available in the new configuration, so the search
 * is performed across reconfig list.
 */
TfwSrvGroup *
tfw_sg_lookup_reconfig(const char *name)
{
	TfwSrvGroup *sg;

	read_lock(&sg_lock);
	list_for_each_entry(sg, &sg_list_reconfig, list_reconfig) {
		if (!strcasecmp(sg->name, name)) {
			tfw_sg_get(sg);
			read_unlock(&sg_lock);
			return sg;
		}
	}
	read_unlock(&sg_lock);
	return NULL;
}
EXPORT_SYMBOL(tfw_sg_lookup_reconfig);

/**
 * Create a new Server Group.
 *
 * This function is called only on configuration processing.
 */
TfwSrvGroup *
tfw_sg_new(const char *name, gfp_t flags)
{
	TfwSrvGroup *sg;
	size_t name_size = strlen(name) + 1;

	TFW_DBG("Create new server group: '%s'\n", name);

	sg = kzalloc(sizeof(*sg) + name_size, flags);
	if (!sg)
		return NULL;

	INIT_LIST_HEAD(&sg->list);
	INIT_LIST_HEAD(&sg->list_reconfig);
	INIT_LIST_HEAD(&sg->srv_list);
	rwlock_init(&sg->lock);
	atomic64_set(&sg->refcnt, 1);
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
	TFW_DBG("Add new server group: '%s'\n", sg->name);

	if (tfw_sg_lookup_reconfig(sg->name)) {
		TFW_ERR("duplicate server group: '%s'\n", sg->name);
		return -EINVAL;
	}

	tfw_sg_get(sg);
	write_lock(&sg_lock);
	list_add(&sg->list_reconfig, &sg_list_reconfig);
	write_unlock(&sg_lock);

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
tfw_sg_apply_reconfig(struct list_head *del_sg)
{
	TfwSrvGroup *sg, *tmp;

	TFW_DBG("Apply reconfig groups\n");

	write_lock(&sg_lock);

	list_for_each_entry_safe(sg, tmp, &sg_list, list) {
		if (list_empty(&sg->list_reconfig)) {
			list_del_init(&sg->list);
			list_add(&sg->list, del_sg);
		}
		else {
			list_del_init(&sg->list_reconfig);
			tfw_sg_put(sg);
		}
	}
	list_for_each_entry_safe(sg, tmp, &sg_list_reconfig, list_reconfig) {
		list_del_init(&sg->list_reconfig);
		list_add(&sg->list, &sg_list);
	}

	write_unlock(&sg_lock);
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
	TfwSrvGroup *sg, *tmp;

	write_lock(&sg_lock);
	list_for_each_entry_safe(sg, tmp, &sg_list_reconfig, list_reconfig) {
		list_del_init(&sg->list_reconfig);
		tfw_sg_put(sg);
	}
	write_unlock(&sg_lock);
}

/**
 * Remove a Server Group from the list.
 * This function is called only on configuration processing.
 */
void
tfw_sg_del(TfwSrvGroup *sg)
{
	BUG_ON(list_empty_careful(&sg->list));

	write_lock(&sg_lock);
	list_del_init(&sg->list);
	write_unlock(&sg_lock);
	tfw_sg_put(sg);
}

unsigned int
tfw_sg_count(void)
{
	unsigned int count = 0;
	TfwSrvGroup *sg;

	read_lock(&sg_lock);
	list_for_each_entry(sg, &sg_list, list)
		++count;
	read_unlock(&sg_lock);

	return count;
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
	write_lock(&sg->lock);
	list_add(&srv->list, &sg->srv_list);
	++sg->srv_n;
	write_unlock(&sg->lock);
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
		write_lock(&sg->lock);
	list_del_init(&srv->list);
	--sg->srv_n;
	if (lock)
		write_unlock(&sg->lock);
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
 * Iterate over all server groups of given server grop @sg and call @cb for
 * each server.
 * @cb is called under spin-lock, so can't sleep.
 * @cb is considered as updater, so write lock is used.
 */
int
__tfw_sg_for_each_srv(TfwSrvGroup *sg, int (*cb)(TfwServer *srv))
{
	int ret = 0;
	TfwServer *srv;

	write_lock(&sg->lock);
	list_for_each_entry(srv, &sg->srv_list, list)
		if ((ret = cb(srv)))
			break;
	write_unlock(&sg->lock);
	return ret;
}

/**
 * Iterate over all the acive server groups and call @cb for each server group.
 * @cb is called under spin-lock, so can't sleep.
 * @cb is considered as updater, so write lock is used.
 */
int
tfw_sg_for_each_sg(int (*cb)(TfwSrvGroup *sg))
{
	int ret = 0;
	TfwSrvGroup *sg;

	write_lock(&sg_lock);
	list_for_each_entry(sg, &sg_list, list)
		if ((ret = cb(sg)))
			break;
	write_unlock(&sg_lock);
	return ret;
}

/**
 * Iterate over all the acive server groups and call @cb for each server.
 * @cb is called under spin-lock, so can't sleep.
 * @cb is considered as updater, so write lock is used.
 */
int
tfw_sg_for_each_srv(int (*cb)(TfwServer *srv))
{
	int ret = 0;
	TfwSrvGroup *sg;

	write_lock(&sg_lock);
	list_for_each_entry(sg, &sg_list, list)
		if ((ret = __tfw_sg_for_each_srv(sg, cb)))
			break;
	write_unlock(&sg_lock);
	return ret;
}

/**
 * Same as tfw_sg_for_each_srv() but iterates over reconfig server group lists.
 */
int
tfw_sg_for_each_srv_reconfig(int (*cb)(TfwServer *srv))
{
	int ret = 0;
	TfwSrvGroup *sg;

	write_lock(&sg_lock);
	list_for_each_entry(sg, &sg_list_reconfig, list_reconfig)
		if ((ret = __tfw_sg_for_each_srv(sg, cb)))
			break;
	write_unlock(&sg_lock);
	return ret;
}

/**
 * Release a single server group with servers.
 */
void
tfw_sg_destroy(TfwSrvGroup *sg)
{
	TFW_DBG2("release group: '%s'\n", sg->name);
	BUG_ON(!list_empty(&sg->srv_list));

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
	list_for_each_entry_safe(srv, srv_tmp, &sg->srv_list, list)
		tfw_sg_del_srv(sg, srv);
}


/**
 * Release all active server groups with all servers.
 */
void
tfw_sg_release_all(void)
{
	TfwSrvGroup *sg, *sg_tmp;

	write_lock(&sg_lock);

	list_for_each_entry_safe(sg, sg_tmp, &sg_list, list) {
		tfw_sg_release(sg);
		list_del_init(&sg->list);
		tfw_sg_put(sg);
	}
	INIT_LIST_HEAD(&sg_list);

	write_unlock(&sg_lock);
}

/**
 * Release all reconfig server groups with all servers.
 * ONLY for unittests.
 */
void
__tfw_sg_release_all_reconfig(void)
{
	TfwSrvGroup *sg, *sg_tmp;

	write_lock(&sg_lock);

	list_for_each_entry_safe(sg, sg_tmp, &sg_list_reconfig, list_reconfig) {
		tfw_sg_release(sg);
		list_del_init(&sg->list_reconfig);
		tfw_sg_put(sg);
	}
	INIT_LIST_HEAD(&sg_list_reconfig);

	write_unlock(&sg_lock);
}

/**
 * Wait until all server groups and server are destructed. The function is
 * called after ss_synchronize(): there is no active server connections.
 * The fuction is called after configuration cleanup: all references taken to
 * servers and groups are already released. Wait for servers with inactive
 * connections to be destroyed. Happen on short configurations with a lot of
 * offline servers.
 */
void
tfw_sg_wait_release(void)
{
	unsigned long tend = jiffies + HZ * 5;

	might_sleep();
	while (atomic64_read(&act_sg_n) && time_is_after_jiffies(tend))
		schedule();
	if (time_is_before_eq_jiffies(tend))
		TFW_WARN_NL("pending for server callbacks to complete for 5s\n");
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
	long leak = atomic64_read(&act_sg_n);

	kmem_cache_destroy(srv_cache);
	if (leak != 0)
		TFW_ERR_NL("leakage of %ld TfwSrvGroup!\n", leak);
}
