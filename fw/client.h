/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2026 Tempesta Technologies, Inc.
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

/*
 * Client memory accounting structure for Tempesta FW.
 * 
 * @kill_work	- Workqueue item used for asynchronous structure
 *		  cleanup/destruction;
 * @next_free	- Pointer to the next free object in the freelist;
 * @refcnt	- Per-CPU reference counter. Provides scalable and
 *		  thread-safe reference tracking on SMP systems with
 *		  minimal contention;
 * @mem		- Per-CPU memory accounting storage.
 */
typedef struct tfw_client_mem_t {
	union {
		struct work_struct	kill_work;
		struct tfw_client_mem_t	*next_free;
	};
	struct percpu_ref	refcnt;
   	long __percpu		*mem;
} TfwClientMem;

/**
 * Client descriptor.
 *
 * @class_prvt		- private client accounting data for classifier module.
 *			  Typically it's large and wastes memory in vain if
 *			  no any classification logic is used;
 * @list_head		- entry in the lru list;
 * @cli_mem		- memory used by current client;
 * @conn_max		- maximum count of simultaneously opened connections
 *			  during training period. Not atomic, because it is
 *			  changed under `ra->lock`;
 * @conn_curr		- current count of simultaneously opened connections
 *			  during training period;
 * @conn_training_epoch	- training epoch identifier, used to zero @conn_max
 *			  and @conn_curr when the new training start;
 */
typedef struct {
	TFW_PEER_COMMON;
	TfwClassifierPrvt	class_prvt;
	struct list_head	list;
	TfwClientMem		*cli_mem;
	unsigned int		conn_max;
	int			conn_curr;
	unsigned int		conn_training_epoch;
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

void tfw_tls_connection_lost(TfwConn *conn);
bool tfw_client_training_adjust_conn_num(TfwClient *cli, int delta,
					 unsigned int *training_epoch);

#define CLIENT_MEM_FROM_CONN(conn)				\
	((TfwClient *)((TfwConn *)conn)->peer)->cli_mem

static inline void
tfw_client_adjust_mem(TfwClientMem *cli_mem, int delta)
{
	this_cpu_add(*cli_mem->mem, delta);
}

static inline bool
tfw_client_mem_get(TfwClientMem *cli_mem)
{
	return percpu_ref_tryget(&cli_mem->refcnt);
}

static inline void
tfw_client_mem_put(TfwClientMem *cli_mem)
{
	percpu_ref_put(&cli_mem->refcnt);
}

static inline long
tfw_client_mem(TfwClientMem *cli_mem)
{
	long mem = 0;
	int cpu;

	for_each_online_cpu(cpu)
		mem += *(per_cpu_ptr(cli_mem->mem, cpu));

	return mem;
}

#endif /* __TFW_CLIENT_H__ */
