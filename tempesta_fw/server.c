/**
 *		Tempesta FW
 *
 * Servers handling.
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
#include <linux/slab.h>

#include "log.h"
#include "server.h"
#include "client.h"
#include "apm.h"

/* Use SLAB for frequent server allocations in forward proxy mode. */
static struct kmem_cache *srv_cache;

/*
 * Server group management.
 *
 * All server groups are defined in configuration. As configuration
 * is processed, server groups are placed in sg_list. After that
 * the list of server groups does not change. No groups are added
 * to or deleted from sg_list until Tempesta is stopped.
 */
static LIST_HEAD(sg_list);
static DEFINE_RWLOCK(sg_lock);

void
tfw_server_destroy(TfwServer *srv)
{
	/* Close all connections before freeing the server! */
	BUG_ON(!list_empty(&srv->conn_list));

	tfw_apm_destroy(srv->apm);
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

	return srv;
}

int
tfw_server_apm_create(TfwServer *srv)
{
	BUG_ON(!srv);

	if (!(srv->apm = tfw_apm_create()))
		return -ENOMEM;
	return 0;
}

/*
 * Look up Server Group by name, and return it to caller.
 *
 * This function is called only when Tempesta is starting, during
 * configuration processing. It's never called after tfw_sg_free()
 * was called, so there's no need to worry about stale entries.
 */
TfwSrvGroup *
tfw_sg_lookup(const char *name)
{
	TfwSrvGroup *sg;

	read_lock(&sg_lock);
	list_for_each_entry(sg, &sg_list, list) {
		if (!strcasecmp(sg->name, name)) {
			read_unlock(&sg_lock);
			return sg;
		}
	}
	read_unlock(&sg_lock);
	return NULL;
}
EXPORT_SYMBOL(tfw_sg_lookup);

/*
 * Create new Server Group and put it on the list.
 *
 * This function is called only when Tempesta is starting,
 * during configuration processing.
 */
TfwSrvGroup *
tfw_sg_new(const char *name, gfp_t flags)
{
	TfwSrvGroup *sg;
	size_t name_size = strlen(name) + 1;

	if (tfw_sg_lookup(name)) {
		TFW_ERR("duplicate server group: '%s'\n", name);
		return NULL;
	}

	TFW_DBG("new server group: '%s'\n", name);

	sg = kmalloc(sizeof(*sg) + name_size, flags);
	if (!sg)
		return NULL;

	INIT_LIST_HEAD(&sg->list);
	INIT_LIST_HEAD(&sg->srv_list);
	rwlock_init(&sg->lock);
	sg->sched = NULL;
	sg->sched_data = NULL;
	memcpy(sg->name, name, name_size);

	write_lock(&sg_lock);
	list_add(&sg->list, &sg_list);
	write_unlock(&sg_lock);

	return sg;
}

/*
 * Remove Server Group from the list, and free it.
 * This function is called only when Tempesta is stopping.
 */
void
tfw_sg_free(TfwSrvGroup *sg)
{
	read_lock(&sg->lock);
	if (!list_empty(&sg->srv_list))
		TFW_WARN("Free non-empty server group\n");
	read_unlock(&sg->lock);

	write_lock(&sg_lock);
	list_del(&sg->list);
	write_unlock(&sg_lock);

	kfree(sg);
}

int
tfw_sg_count(void)
{
	int count = 0;
	TfwSrvGroup *sg;

	read_lock(&sg_lock);
	list_for_each_entry(sg, &sg_list, list) {
		++count;
	}
	read_unlock(&sg_lock);

	return count;
}

/*
 * Add server to a server group.
 */
void
tfw_sg_add(TfwSrvGroup *sg, TfwServer *srv)
{
	BUG_ON(srv->sg);
	srv->sg = sg;

	TFW_DBG2("Add new backend server\n");
	write_lock(&sg->lock);
	list_add(&srv->list, &sg->srv_list);
	write_unlock(&sg->lock);
}

void
tfw_sg_add_conn(TfwSrvGroup *sg, TfwServer *srv, TfwConnection *conn)
{
	if (sg->sched && sg->sched->add_conn)
		sg->sched->add_conn(sg, srv, conn);
}

int
tfw_sg_set_sched(TfwSrvGroup *sg, const char *sched_name)
{
	TfwScheduler *s = tfw_sched_lookup(sched_name);

	if (!s)
		return -EINVAL;

	sg->sched = s;
	if (s->add_grp)
		s->add_grp(sg);

	return 0;
}

static int
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
 * Iterate over all server groups and call @cb for each server.
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
 * Release all server groups with all servers.
 */
void
tfw_sg_release_all(void)
{
	TfwServer *srv, *srv_tmp;
	TfwSrvGroup *sg, *sg_tmp;

	write_lock(&sg_lock);

	list_for_each_entry_safe(sg, sg_tmp, &sg_list, list) {
		write_lock(&sg->lock);

		list_for_each_entry_safe(srv, srv_tmp, &sg->srv_list, list)
			tfw_server_destroy(srv);

		write_unlock(&sg->lock);

		if (sg->sched && sg->sched->del_grp)
			sg->sched->del_grp(sg);

		kfree(sg);
	}

	INIT_LIST_HEAD(&sg_list);

	write_unlock(&sg_lock);
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
