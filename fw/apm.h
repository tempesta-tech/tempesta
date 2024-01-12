/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2024 Tempesta Technologies, Inc.
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
#include "stat.h"
#include "str.h"

/*
 * @ith		- array of percentile numbers, with space for min/max/avg;
 * @val		- array of percentile values, and values for min/max/avg;
 * @seq		- opaque data related to percentiles calculation;
 */
typedef struct {
	const unsigned int	*ith;
	unsigned int		*val;
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

#define T_PSZ	_TFW_PSTATS_IDX_COUNT

int tfw_apm_add_srv(TfwServer *srv);
void tfw_apm_del_srv(TfwServer *srv);

/*
 * All blocks of the procedures listed below, separated by spaces, are not
 * data-coupled. It can be said that these are independent submodules of the
 * APM module.
 */

/* Procedures related to statistics (avg/min/max/percentiles).
 * Configured by the 'apm_stats' directive.
 */
void tfw_apm_update(void *apmref, unsigned long jtstamp, unsigned long jrtime);
int tfw_apm_stats(void *apmref, TfwPrcntlStats *pstats);
/* Displayed in the perfstat, not in a backend statistics. */
void tfw_apm_update_global(unsigned long jtstamp, unsigned long jrtime);
int tfw_apm_stats_global(TfwPrcntlStats *pstats);

/*
 * Although these procedures are used for health monitoring, they also collect
 * overall statistics on responses from each server. Therefore, if health
 * monitoring is not active for a server, these procedures are still executed.
 */
bool tfw_apm_hm_srv_limit(int status, void *apmref);
TfwHMStats *tfw_apm_hm_stats(void *apmref);

/* Health monitor procedures ('health_check' directive). */
void tfw_apm_hm_srv_rcount_update(TfwStr *uri_path, void *apmref);
bool tfw_apm_hm_srv_alive(int status, TfwStr *body, struct sk_buff *skb_head,
			  void *apmref);
void tfw_apm_hm_enable_srv(TfwServer *srv, const char *hm_name);
void tfw_apm_hm_disable_srv(TfwServer *srv);
bool tfw_apm_hm_srv_eq(const char *name, TfwServer *srv);
bool tfw_apm_check_hm(const char *name);

#endif /* __TFW_APM_H__ */
