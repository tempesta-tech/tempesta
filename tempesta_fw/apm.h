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
#ifndef __TFW_APM_H__
#define __TFW_APM_H__

#include "pool.h"
#include "server.h"
#include "str.h"

/*
 * @ith		- array of percentile numbers, with space for min/max/avg;
 * @val		- array of percentile values, and values for min/max/avg;
 * @psz		- size of @ith and @val arrays;
 * @seq		- opaque data related to percentiles calculation;
 */
typedef struct {
	const unsigned int	*ith;
	unsigned int		*val;
	unsigned int		psz;
	unsigned int		seq;
} TfwPrcntlStats;

enum {
	TFW_PSTATS_IDX_MIN = 0,
	TFW_PSTATS_IDX_MAX,
	TFW_PSTATS_IDX_AVG,
	TFW_PSTATS_IDX_ITH,
	TFW_PSTATS_IDX_P50 = TFW_PSTATS_IDX_ITH,
	TFW_PSTATS_IDX_P75,
	TFW_PSTATS_IDX_P90,
	TFW_PSTATS_IDX_P95,
	TFW_PSTATS_IDX_P99,
	_TFW_PSTATS_IDX_COUNT
};

static const unsigned int tfw_pstats_ith[] = {
	[TFW_PSTATS_IDX_MIN ... TFW_PSTATS_IDX_AVG] = 0,
	[TFW_PSTATS_IDX_P50] = 50,
	[TFW_PSTATS_IDX_P75] = 75,
	[TFW_PSTATS_IDX_P90] = 90,
	[TFW_PSTATS_IDX_P95] = 95,
	[TFW_PSTATS_IDX_P99] = 99,
};

/*
 * Structures for health monitoring statistics accountings
 * in procfs.
 */
typedef struct {
	int		code;
	unsigned int	sum;
} TfwHMCodeStats;

/*
 * @rtime	- time until next server health checking;
 * @ccnt	- count of @rsums elements;
 * @rsums	- array of counters for separate HTTP codes;
 */
typedef struct {
	unsigned int	rtime;
	unsigned int	ccnt;
	TfwHMCodeStats	*rsums;
} TfwHMStats;

int tfw_apm_add_srv(TfwServer *srv);
void tfw_apm_del_srv(TfwServer *srv);
void tfw_apm_update(void *apmref, unsigned long jtstamp, unsigned long jrtime);
int tfw_apm_stats(void *apmref, TfwPrcntlStats *pstats);
int tfw_apm_stats_bh(void *apmref, TfwPrcntlStats *pstats);
int tfw_apm_pstats_verify(TfwPrcntlStats *pstats);
void tfw_apm_hm_srv_rcount_update(TfwStr *uri_path, void *apmref);
bool tfw_apm_hm_srv_alive(int status, TfwStr *body, void *apmref);
bool tfw_apm_hm_srv_limit(int status, void *apmref);
bool tfw_apm_hm_enable_srv(const char *name, TfwServer *srv);
void tfw_apm_hm_disable_srv(TfwServer *srv);
bool tfw_apm_hm_srv_eq(const char *name, TfwServer *srv);
TfwHMStats *tfw_apm_hm_stats(void *apmref);

#endif /* __TFW_APM_H__ */
