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
};

static const unsigned int __read_mostly tfw_pstats_ith[] = {
	[TFW_PSTATS_IDX_MIN ... TFW_PSTATS_IDX_AVG] = 0,
	[TFW_PSTATS_IDX_P50] = 50,
	[TFW_PSTATS_IDX_P75] = 75,
	[TFW_PSTATS_IDX_P90] = 90,
	[TFW_PSTATS_IDX_P95] = 95,
	[TFW_PSTATS_IDX_P99] = 99,
};

void *tfw_apm_create(void);
void tfw_apm_destroy(void *data);
void tfw_apm_update(void *data, unsigned long jtstamp, unsigned long jrtime);
int tfw_apm_stats(void *data, TfwPrcntlStats *pstats);
int tfw_apm_pstats_verify(TfwPrcntlStats *pstats);

#endif /* __TFW_APM_H__ */
