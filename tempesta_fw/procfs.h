/**
 *		Tempesta FW
 *
 * Copyright (C) 2016 Tempesta Technologies, Inc.
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
 * @rx_messages		- Total number of messages received from peers.
 * @msgs_forward	- The number of forwarded messages.
 * @msgs_parserr	- The number of messages with parsing errors.
 * @msgs_filtout	- The number of messages that were filtered out
 *			  in accordance with the rules in configuration.
 * @msgs_otherr		- The number of messages not accepted due to
 *			  other errors.
 *
 * @conn_attempts	- Total number of connect attempts.
 * @conn_established	- Total number of connections ever established
 *			  with peers while Tempesta is active.
 * @conn_disconnects	- Total number of disconnects for any reason.
 *
 * @rx_bytes		- Total number of bytes received from a peer and
 *			  processed by Tempesta.
 */
typedef struct {
	u64	rx_messages;
	u64	msgs_forward;
	u64	msgs_parserr;
	u64	msgs_filtout;
	u64	msgs_otherr;

	u64	conn_attempts;
	u64	conn_established;
	u64	conn_disconnects;

	u64	rx_bytes;
} TfwPeerStat;

/*
 * @cache_hit		- Number of Web-cache (if enabled) hits.
 * @cache_miss		- Number of misses in Web-cache (if enabled).
 */
typedef struct {
	u64	cache_hit;
	u64	cache_miss;

	TfwPeerStat	clnt;
	TfwPeerStat	serv;
} TfwPerfStat;

DECLARE_PER_CPU_ALIGNED(TfwPerfStat, tfw_perfstat);

/*
 * this_cpu_inc/add() macros are implemented via "do {} while(0)" code
 * block. (see <linux/percpu-defs.h>) Note that it is not a statement
 * expression, and so it can not be evaluated to a value. For that
 * reason the definitions below cannot be used with ?: operator.
 */
#define TFW_INC_STAT_BH(...)	this_cpu_inc(tfw_perfstat.__VA_ARGS__)
#define TFW_ADD_STAT_BH(val, ...)	\
		this_cpu_add(tfw_perfstat.__VA_ARGS__, val)

#endif /* __TFW_PROCFS_H__ */
