/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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
#ifndef __TFW_CLIENT_H__
#define __TFW_CLIENT_H__

#include "http_limits.h"
#include "connection.h"

/**
 * Client descriptor.
 *
 * @class_prvt		- private client accounting data for classifier module.
 *			  Typically it's large and wastes memory in vain if
 *			  no any classification logic is used;
 * @conn_max		- maximum count of simultaneously opened connections during
 *			  training period. Not atomic, because it is changed under
 *			  `ra->lock`;
 * @cpu_max		- maximum cpu usage during training period;
 * @req_max		- maximum count of requests simultaneously added to server
 *			  connection queue (not answered).
 * @training_num_lock	- `spinlock` used for zeroing `*_max` values when new
 *			  trainging start;
 * @req_training_num	- number of trainging for current client. When new training
 *			  start we update global trainging number and use variable
 *			  to check, that we should zeroed `req_max` value;
 * @conn_training_num	- the same as previous, but for `conn_max` value;
 * @cpu_training_num	- the same as previous, but for `cpu_max` value;
 * @jiffies		- `mean` and `std` calculation of cpu usage are made during
 *			  `tfw_training_mod_period`, so during z-score calculation
 *			  we should also calculate it during the same time window;
 *			  This field is used for zeroing `cpu_curr` value;
 * @jiffies_lock	- lock for chaning `jiffies`;
 */
typedef struct {
	TFW_PEER_COMMON;
	TfwClassifierPrvt	class_prvt;
	u64			conn_max;
	atomic64_t		cpu_max;
	atomic64_t		req_max;
	atomic64_t		cpu_curr;
	atomic64_t		req_curr;
	spinlock_t		training_num_lock;
	unsigned int		req_training_num;
	unsigned int		conn_training_num;
	unsigned int		cpu_training_num;
	u64			jiffies;
	spinlock_t		jiffies_lock;
} TfwClient;

int tfw_client_init(void);
void tfw_client_exit(void);
TfwClient *tfw_client_obtain(TfwAddr addr, TfwAddr *cli_addr,
			     TfwStr *user_agent, void (*init)(void *));
void tfw_client_put(TfwClient *cli);
int tfw_client_for_each(int (*fn)(void *));
void tfw_cli_conn_release(TfwCliConn *cli_conn);
int tfw_cli_conn_send(TfwCliConn *cli_conn, TfwMsg *msg);
int tfw_cli_conn_abort_all(void *data);
void tfw_cli_abort_all(void);
void tfw_client_training_update(atomic64_t *max, u64 curr, int *training_num,
				spinlock_t *lock, void (*adjust)(u64, u64, bool));
void tfw_client_training_adjust_conn_num(u64 *max, u64 curr, int *training_num,
					 void (*adjust)(u64, u64, bool));
void tfw_client_new_cpu_num_wnd(TfwClient *cli);
void tfw_tls_connection_lost(TfwConn *conn);

#endif /* __TFW_CLIENT_H__ */
