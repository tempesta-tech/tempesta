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
 * @ith		- array of percentile numbers;
 * @val		- array of percentile values;
 * @psz		- size of @ith and @val arrays;
 * @min		- minimal value;
 * @max		- maximal value;
 * @avg		- average value;
 * @seq		- opaque data related to percentiles calculation;
 */
typedef struct {
	const unsigned int	*ith;
	unsigned int		*val;
	unsigned int		psz;
	unsigned int		min;
	unsigned int		max;
	unsigned int		avg;
	unsigned int		seq;
} TfwPrcntlStats;

/* A superset of percentiles for all users. */
static const unsigned int __read_mostly tfw_pstats_ith[] = {
	50, 75, 90, 95, 99
};

void *tfw_apm_create(void);
void tfw_apm_destroy(void *data);
void tfw_apm_update(void *data, unsigned long jtstamp, unsigned long jrtime);
int tfw_apm_stats(void *data, TfwPrcntlStats *pstats);
int tfw_apm_stats_bh(void *data, TfwPrcntlStats *pstats);
int tfw_apm_pstats_verify(TfwPrcntlStats *pstats);

#endif /* __TFW_APM_H__ */
