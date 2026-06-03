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
#include "adaptive_limits.h"

/*
 * Client memory accounting structure for Tempesta FW.
 *
 * @mem	- Per-CPU memory accounting storage.
 */
typedef struct tfw_client_mem_t {
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
 * req_lim	- structure to track non-idempotent requests count in
 *		  fly for the current client. Used in adaptive_limits
 *		  module to collect statistic and z-score calculation;
 */
typedef struct tfw_adaptive_limits_t {
	union {
		struct work_struct		kill_work;
		struct tfw_adaptive_limits_t	*next_free;
	};
	struct percpu_ref	refcnt;
	TfwClientMem		cli_mem;
	TfwAdaptiveLimitLock	req_lim;
} TfwClientAdaptiveLimits;

/**
 * Client descriptor.
 *
 * @class_prvt		- private client accounting data for classifier module.
 *			  Typically it's large and wastes memory in vain if
 *			  no any classification logic is used;
 * @list		- entry in the lru list;
 * @conn_lim		- structure to track active connections count in
 *			  for the current client. Used in adaptive_limits
 *			  module to collect statistic and z-score calculation;
 * @limits		- structure to track different client statistic;
 */
typedef struct {
	TFW_PEER_COMMON;
	TfwClassifierPrvt	class_prvt;
	struct list_head	list;
	TfwAdaptiveLimit	conn_lim;
	TfwClientAdaptiveLimits	*limits;
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
void tfw_client_filter_block_ip(TfwClient *cli);

#define CLIENT_MEM_FROM_CONN(conn)				\
	&((TfwClient *)((TfwConn *)conn)->peer)->limits->cli_mem

static inline void
tfw_client_adjust_mem(TfwClientMem *cli_mem, int delta)
{
	this_cpu_add(*cli_mem->mem, delta);
}

static inline bool
tfw_client_mem_get(TfwClientMem *cli_mem)
{
	TfwClientAdaptiveLimits *limits =
		container_of(cli_mem, TfwClientAdaptiveLimits, cli_mem);

	return percpu_ref_tryget(&limits->refcnt);
}

static inline void
tfw_client_mem_put(TfwClientMem *cli_mem)
{
	TfwClientAdaptiveLimits *limits =
		container_of(cli_mem, TfwClientAdaptiveLimits, cli_mem);

	percpu_ref_put(&limits->refcnt);
}

static inline s64
tfw_client_mem(TfwClientMem *cli_mem)
{
	return tfw_percpu_s64_counter_sum(cli_mem->mem);
}

#endif /* __TFW_CLIENT_H__ */
