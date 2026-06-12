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
 * counter	- percpu array to track current value of the tracked metric.
 * lock		- spinlock for serialized reset of @max and @counter when a
 *		  new training epoch starts.
 * max		- maximum observed value of the tracked metric within the
 *		  current training epoch (e.g. peak number of in-flight
 *		  non-idempotent requests or peak of client memory usage);Collapse commentComment on line R33const-t commented on Jun 15, 2026 const-ton Jun 15, 2026ContributorMore actionsFrom my point of view we should move this to training.h. All other related structs as wellReactWrite a replyResolve comment
 * @epoch	- training epoch identifier. Compared against the global
 *		  @g_training_epoch to detect epoch change and trigger
 *		  reinitialization of @max and @counter.
 */
typedef struct tfw_client_counter_t {
	s64 	__percpu	*counter;
	spinlock_t		lock;
	atomic_long_t		max;
	u16			epoch;
} TfwClientCounter;

/*
 * Client memory accounting structure for Tempesta FW.
 * 
 * @counter	- memory accounting storage for training;
 * @mem		- percpu memory accounting storage. Used for
 *		  soft/hard memory limits. Not zeroed on the new
 *		  training epoch;
 */
typedef struct tfw_client_mem_t {
	TfwClientCounter	counter;
   	s64 __percpu		*mem;
} TfwClientMem;

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
	TfwClientCounter	req_counter;
	TfwClientCounter	cpu_ema_counter;
} TfwClientCounters;

/**
 * Client descriptor.
 *
 * @class_prvt		- private client accounting data for classifier module.
 *			  Typically it's large and wastes memory in vain if
 *			  no any classification logic is used;
 * @list		- entry in the lru list;
 * @counters		- structure to track different client statistic;
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
	TfwClientCounters	*counters;
	unsigned int		conn_max;
	int			conn_curr;
	u16			conn_training_epoch;
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
					 u16 *training_epoch);
/*
 * Client non idempotent request/memory usage tracking splitted into
 * two parts. The next two functions are used only for statistic
 * accomulation in per-CPU counter without passing it to the training
 * module. They are invoked on every event, but very lightweight.
 */
void tfw_client_counter_training_adjust_req(TfwClientCounter *counter,
					    int delta, u16 *training_epoch);
void tfw_client_counter_training_adjust_mem(TfwClientCounter *counter,
					    int delta, u16 *training_epoch);
/*
 * The next two functions are used for appropriate statistic agregation
 * and passing it to the training module. They are invoked at the end of
 * `ss_tcp_process_data`, quite rare, so they don't affect performance.
 */
bool tfw_client_counter_training_check_req(TfwClientCounter *counter);
bool tfw_client_counter_training_check_mem(TfwClientCounter *counter);
bool tfw_client_counter_training_check_cpu(TfwClientCounter *counter,
					   u64 time_begin);
void tfw_client_filter_block_ip(TfwClient *cli);

#define CLIENT_MEM_FROM_CONN(conn)				\
	&((TfwClient *)((TfwConn *)conn)->peer)->counters->cli_mem

static inline s64
__percpu_summ_s64(s64	__percpu *val)
{
	s64 count = 0;
	int cpu;

	for_each_online_cpu(cpu)
		count += *(per_cpu_ptr(val, cpu));

	return count;
}

static inline void
tfw_client_counter_add(TfwClientCounter *counter, int delta)
{
	this_cpu_add(*counter->counter, delta);
}

static inline s64
tfw_client_counter_get(TfwClientCounter *counter)
{
	return __percpu_summ_s64(counter->counter);
}

static inline void
tfw_client_adjust_mem(TfwClientMem *cli_mem, int delta,
		      u16 *training_epoch)
{
	this_cpu_add(*cli_mem->mem, delta);
	tfw_client_counter_training_adjust_mem(&cli_mem->counter,
					       delta, training_epoch);
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

static inline s64
tfw_client_mem(TfwClientMem *cli_mem)
{
	return __percpu_summ_s64(cli_mem->mem);
}

#endif /* __TFW_CLIENT_H__ */
