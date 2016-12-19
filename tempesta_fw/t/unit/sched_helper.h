/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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

#include "addr.h"
#include "cfg.h"
#include "connection.h"

int tfw_server_init(void);
int tfw_sched_rr_init(void);
void tfw_sched_rr_exit(void);
void sched_helper_init(void);

void test_spec_cleanup(TfwCfgSpec specs[]);
TfwSrvGroup *test_create_sg(const char *name, const char *sched_name);
void test_sg_release_all(void);

TfwServer *test_create_srv(const char *in_addr, TfwSrvGroup *sg);

TfwSrvConnection *test_create_conn(TfwPeer *peer);

void test_conn_release_all(TfwSrvGroup *sg);

struct TestSchedHelper {
	const char *sched;
	size_t conn_types;
	TfwMsg *(*get_sched_arg)(size_t conn_type);
	void (*free_sched_arg)(TfwMsg *);
};

void test_sched_sg_conn_empty_sg(struct TestSchedHelper *sched_helper);
void test_sched_sg_conn_one_srv_zero_conn(struct TestSchedHelper *sched_helper);
void test_sched_sg_conn_max_srv_zero_conn(struct TestSchedHelper *sched_helper);

void test_sched_srv_conn_one_srv_zero_conn(struct TestSchedHelper *sched_helper);
void test_sched_srv_conn_max_srv_zero_conn(struct TestSchedHelper *sched_helper);
void test_sched_srv_conn_offline_srv(struct TestSchedHelper *sched_helper);

#endif /* __TFW_SCHED_HELPER_H__ */
