/**
 *		Tempesta kernel library
 *
 * Copyright (C) 2016-2024 Tempesta Technologies, Inc.
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
#ifndef __TFW_STAT_H__
#define __TFW_STAT_H__

#include "http.h"

/* Shared structures used for statistics. */

/*
 * Structures for health monitoring statistics accountings in procfs.
 *
 * @code	- HTTP code for which the statistics is collected.
 * @tf_total	- Amount of responses for the period, limited by a time frame.
 * @total	- Amount of responses for the overall period.
 */
typedef struct {
	int		code;
	unsigned int	tf_total;
	u64		total;
} TfwHMCodeStats;

/*
 * @rtime	- time until next server health checking (can be unused if not
 *		  required);
 * @ccnt	- count of @rsums elements;
 * @rsums	- array of counters for separate HTTP codes;
 */
typedef struct {
	unsigned int	rtime;
	unsigned int	ccnt;
	TfwHMCodeStats	*rsums;
} TfwHMStats;

/**
 * The real size of TfwHMStats, used for memory allocation.
 *
 * TfwHMCodeStats is located monolithically in memory with TfwHMStats,
 * just after it.
 */
static inline size_t
tfw_hm_stats_size(int ccnt)
{
	return sizeof(TfwHMStats) + sizeof(TfwHMCodeStats) * ccnt;
}

/**
 * Use it right after memory allocation.
 *
 * Rsums content stays unitinitialized.
 */
static inline void
tfw_hm_stats_init(TfwHMStats *s, int ccnt)
{
	s->ccnt = ccnt;
	s->rsums = (TfwHMCodeStats *)(s + 1);
}

static inline void
tfw_hm_stats_clone(TfwHMStats *dest, TfwHMStats *src)
{
	if (!src)
		return;

	memcpy_fast(dest, src, tfw_hm_stats_size(src->ccnt));
	dest->rsums = (TfwHMCodeStats *)(dest + 1);
}

/**
 * The config entry @ce must be a list of HTTP codes, such as:
 * 'some_directive 403 404 5*'.
 *
 * Use it right after memory allocation.
 */
static inline int
tfw_hm_stats_init_from_cfg_entry(TfwHMStats *s, TfwCfgEntry *ce)
{
	int i, code;
	const char *val;
	tfw_hm_stats_init(s, ce->val_n);

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (tfw_cfgop_parse_http_status(val, &code)) {
			T_ERR_NL("Unable to parse http code value: '%s'\n",
				 val);
			return -EINVAL;
		}
		s->rsums[i].code = code;
	}
	return 0;
}


#endif /* __TFW_STAT_H__ */
