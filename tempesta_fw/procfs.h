/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2017 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_PROCFS_H__
#define __TFW_PROCFS_H__

#include "tempesta_fw.h"

/*
 * @pfl_hits		- The number of page frag lookup hits.
 * @pfl_misses		- The number of page frag lookup misses.
 */
typedef struct {
	u64	pfl_hits;
	u64	pfl_misses;
} TfwSsStat;

/*
 * @rx_messages		- The number of messages received from peers.
 * @msgs_forwarded	- The number of forwarded messages.
 * @msgs_parserr	- The number of messages with parsing errors.
 * @msgs_filtout	- The number of messages that were filtered out
 *			  in accordance with the rules in configuration.
 * @msgs_otherr		- The number of messages not accepted due to
 *			  other errors.
 *
 * @conn_attempts	- The number of connect attempts.
 * @conn_established	- The number of connections ever established
 *			  with peers while Tempesta is active.
 * @conn_disconnects	- The number of disconnects for any reason.
 *
 * @rx_bytes		- The number of bytes received from peers and
 *			  processed by Tempesta.
 */
#define TFW_STAT_COMMON							\
	u64	rx_messages;						\
	u64	msgs_forwarded;						\
	u64	msgs_parserr;						\
	u64	msgs_filtout;						\
	u64	msgs_otherr;						\
	u64	conn_attempts;						\
	u64	conn_established;					\
	u64	conn_disconnects;					\
	u64	rx_bytes;

typedef struct {
	TFW_STAT_COMMON;
} TfwSrvStat;

/*
 * @msgs_fromcache	- The number of messages served from cache.
 * @online		- The number of clients online.
 */
typedef struct {
	TFW_STAT_COMMON;
	u64	msgs_fromcache;
	u64	online;
} TfwClntStat;

/*
 * If cache is enabled, the following stats are produced.
 *
 * @hits	- The number of cache hits.
 * @misses	- The number of cache misses.
 */
typedef struct {
	u64	hits;
	u64	misses;
} TfwCacheStat;

typedef struct {
	TfwSsStat	ss;
	TfwClntStat	clnt;
	TfwSrvStat	serv;
	TfwCacheStat	cache;
} TfwPerfStat;

DECLARE_PER_CPU_ALIGNED(TfwPerfStat, tfw_perfstat);

/*
 * this_cpu_inc/add() macros are implemented via "do {} while(0)" code
 * block. (see <linux/percpu-defs.h>) Note that it is not a statement
 * expression, and so it can not be evaluated to a value. For that
 * reason the definitions below cannot be used with ?: operator.
 */
#define TFW_INC_STAT_BH(...)	this_cpu_inc(tfw_perfstat.__VA_ARGS__)
#define TFW_DEC_STAT_BH(...)	this_cpu_dec(tfw_perfstat.__VA_ARGS__)
#define TFW_ADD_STAT_BH(val, ...)	\
		this_cpu_add(tfw_perfstat.__VA_ARGS__, val)

#endif /* __TFW_PROCFS_H__ */
