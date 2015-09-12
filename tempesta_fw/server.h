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
#ifndef __SERVER_H__
#define __SERVER_H__

#include "addr.h"
#include "connection.h"
#include "peer.h"
#include "sched.h"

#define TFW_SRV_MAX_CONN	32	/* TfwConnection per TfwServer */
#define TFW_SG_MAX_SRV		32	/* TfwServer per TfwSrvGroup */
#define TFW_SG_MAX_CONN		(TFW_SG_MAX_SRV * TFW_SRV_MAX_CONN)

/**
 * Server descriptor, a TfwPeer successor.
 *
 * @list	- member pointer in the list of servers of a server group;
 * @sg		- back-reference to the server group;
 */
typedef struct {
	TFW_PEER_COMMON;
	struct list_head	list;
	struct tfw_srv_group_t	*sg;
	unsigned int		flags;
	int			stress;
} TfwServer;

/* The server should be considered online and used by schedulers. */
#define TFW_SRV_F_ON	0x01U

/**
 * The servers group with the same load balancing, failovering and eviction
 * policies.
 *
 * Reverse proxy must define load balancing policy. Forward proxy must define
 * eviction policy. While both of them should define failovering policy.
 *
 * @list		- member pointer in the list of server groups;
 * @srv_list		- list of servers belonging to the group;
 * @lock		- synchronizes the group readers with updaters;
 * @sched		- requests scheduling handler;
 * @sched_data		- private scheduler data for the server group;
 * @name		- name of the group specified in the configuration;
 */
typedef struct tfw_srv_group_t {
	struct list_head	list;
	struct list_head	srv_list;
	rwlock_t		lock;
	TfwScheduler		*sched;
	void			*sched_data;
	char			name[0];
} TfwSrvGroup;

/* Server specific routines. */

TfwServer *tfw_create_server(const TfwAddr *addr);
void tfw_destroy_server(TfwServer *srv);

static inline void
tfw_server_online(TfwServer *srv)
{
	srv->flags |= TFW_SRV_F_ON;
}

static inline void
tfw_server_offline(TfwServer *srv)
{
	srv->flags &= ~TFW_SRV_F_ON;
}

/* Server group routines. */

TfwSrvGroup *tfw_sg_lookup(const char *name);
TfwSrvGroup *tfw_sg_new(const char *name, gfp_t flags);
void tfw_sg_free(TfwSrvGroup *sg);
int tfw_sg_count(void);

void tfw_sg_add(TfwSrvGroup *sg, TfwServer *srv);
void tfw_sg_del(TfwSrvGroup *sg, TfwServer *srv);
void tfw_sg_update(TfwSrvGroup *sg);
int tfw_sg_set_sched(TfwSrvGroup *sg, const char *sched);
void tfw_sg_for_each_srv(void (*cb)(TfwServer *srv));
void tfw_sg_release_all(void);

#endif /* __SERVER_H__ */
