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

#ifndef __TFW_SCHED_HELPER_H__
#define __TFW_SCHED_HELPER_H__
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/freezer.h>
#include <net/inet_sock.h>
#include "tempesta_fw.h"
#include "connection.h"
#include "server.h"

typedef struct {
	TfwConnection		conn;
	struct timer_list	retry_timer;
	unsigned long		timeout;
	unsigned int		attempts;
} TestConnection;

//TfwSrvConnection *tfw_srv_conn_alloc(void);
//void tfw_srv_conn_free( TfwSrvConnection *conn);
int tfw_server_init(void);
void sched_helper_init(void);

TfwSrvGroup *test_create_sg(const char *name, const char *sched_name);
void test_sg_release_all(void);

TfwServer *test_create_srv(const char *in_addr, TfwSrvGroup *sg);

TestConnection *test_create_conn(TfwPeer *peer);
void test_conn_release_all(TfwSrvGroup *sg);

#endif /* __TFW_SCHED_HELPER_H__ */
