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
#include "training.h"

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
   	long __percpu		*mem;
} TfwClientMem;

/*
 * Client non-idempotent requests accounting structure for Tempesta FW.
 *
 * counter	- percpu array to track current value of the tracked metric;
 * lock		- spinlock for serialized reset of @max and @counter when a
 *		  new training epoch starts.
 * max		- maximum observed value of the tracked metric within the
 *		  current training epoch (e.g. peak number of in-flight
 *		  non-idempotent requests or peak of client memory usage);
 * @epoch	- training epoch identifier. Compared against the global
 *		  @g_training_epoch to detect epoch change and trigger
 *		  reinitialization of @max and @counter.
 */
typedef struct {
	unsigned int __percpu		*counter;
	spinlock_t			lock;
	atomic_t			max;
	unsigned short			epoch;
} TfwClientReqCounter;

/*
 * Structure to track different client statistic.
 *
 * @kill_work	- workqueue item used for asynchronous structure
 *		  cleanup/destruction;
 * @next_free	- pointer to the next free object in the freelist;
 * @refcnt	- percpu reference counter. Provides scalable and
 *		  thread-safe reference tracking on SMP systems with
 *		  minimal contention;
 * cli_mem	- client memory accounting structure for Tempesta FW;
 * req_counter	- structure to track non-idempotent requests count in
 *		  fly for the current client;
 */
typedef struct tfw_client_counters_t {
	union {
		struct work_struct		kill_work;
		struct tfw_client_counters_t	*next_free;
	};
	struct percpu_ref	refcnt;
	TfwClientMem		cli_mem;
	TfwClientReqCounter	req_counter;
} TfwClientCounters;

/**
 * Client descriptor.
 *
 * @class_prvt		- private client accounting data for classifier module.
 *			  Typically it's large and wastes memory in vain if
 *			  no any classification logic is used;
 * @list_head		- entry in the lru list;
 * @counters		- structure to track different client statistic;
 * @conn_max		- maximum count of simultaneously opened connections
 *			  during training period. Not atomic, because it is
 *			  changed under `ra->lock`;
 * @conn_curr		- current count of simultaneously opened connections
 *			  during training period;
 * @conn_training_epoch	- training epoch identifier, used to zero @conn_max
 *			  and @conn_curr when the new training start;
 * @req_stat		- training statistic for non idempodent requests;
 */
typedef struct {
	TFW_PEER_COMMON;
	TfwClassifierPrvt	class_prvt;
	struct list_head	list;
	TfwClientCounters	*counters;
	unsigned int		conn_max;
	int			conn_curr;
	unsigned short		conn_training_epoch;
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
					 unsigned short *training_epoch);
void tfw_client_training_adjust_req_num(TfwClient *cli, int delta,
					unsigned short *training_epoch);
bool tfw_client_training_process_req_num(TfwClient *cli);
void tfw_client_filter_block_ip(TfwClient *cli);

#define CLIENT_MEM_FROM_CONN(conn)				\
	&((TfwClient *)((TfwConn *)conn)->peer)->counters->cli_mem

static inline void
tfw_client_adjust_mem(TfwClientMem *cli_mem, int delta)
{
	this_cpu_add(*cli_mem->mem, delta);
}

static inline bool
tfw_client_mem_get(TfwClientMem *cli_mem)
{
	TfwClientCounters *counters =
		container_of(cli_mem, TfwClientCounters, cli_mem);

	return percpu_ref_tryget(&counters->refcnt);
}

static inline void
tfw_client_mem_put(TfwClientMem *cli_mem)
{
	TfwClientCounters *counters =
		container_of(cli_mem, TfwClientCounters, cli_mem);

	percpu_ref_put(&counters->refcnt);
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
