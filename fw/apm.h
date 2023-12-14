/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2021 Tempesta Technologies, Inc.
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

#include "http.h"
#include "pool.h"
#include "server.h"
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

/*
 * Structures for health monitoring statistics accountings
 * in procfs.
 */
typedef struct {
	int		code;
	unsigned int	sum;
	u64		total;	/* Another sum for total stats; can be unused. */
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
		BUG_ON(i >= s->ccnt);

		if (tfw_cfgop_parse_http_status(val, &code)
		    || (code > HTTP_STATUS_5XX
			&& tfw_cfg_check_range(code, HTTP_CODE_MIN,
					       HTTP_CODE_MAX)))
		{
			T_ERR_NL("Unable to parse http code value: '%s'\n",
				 val);
			return -EINVAL;
		}
		s->rsums[i].code = code;
	}
	return 0;
}

static inline void
tfw_hm_stats_inc(TfwHMStats *s, int status)
{
	int i;

	if (!s)
		return;
	/*
	 * For faster access, alternative techniques like bitmask, binary search,
	 * or other methods could be employed. However, a linear search is deemed
	 * sufficient, given that the number of 'health_stat'/'health_stat_server'
	 * codes is typically not high.
	 */
	for (i = 0; i < s->ccnt; ++i) {
		if (tfw_http_status_eq(status, s->rsums[i].code)) {
			++s->rsums[i].sum;
			break;
		}
	}
}

int tfw_apm_add_srv(TfwServer *srv);
void tfw_apm_del_srv(TfwServer *srv);
void tfw_apm_update(void *apmref, unsigned long jtstamp, unsigned long jrtime);
int tfw_apm_stats(void *apmref, TfwPrcntlStats *pstats);
int tfw_apm_stats_bh(void *apmref, TfwPrcntlStats *pstats);
int tfw_apm_pstats_verify(TfwPrcntlStats *pstats);
void tfw_apm_hm_srv_rcount_update(TfwStr *uri_path, void *apmref);
bool tfw_apm_hm_srv_alive(int status, TfwStr *body, struct sk_buff *skb_head,
			  void *apmref);
bool tfw_apm_hm_srv_limit(int status, void *apmref);
void tfw_apm_hm_enable_srv(TfwServer *srv, const char *hm_name);
void tfw_apm_hm_disable_srv(TfwServer *srv);
bool tfw_apm_hm_srv_eq(const char *name, TfwServer *srv);
TfwHMStats *tfw_apm_hm_stats(void *apmref);
bool tfw_apm_check_hm(const char *name);

#endif /* __TFW_APM_H__ */
