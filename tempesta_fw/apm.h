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
 * @ith	- percentile number.
 * @val	- percentile value.
 */
typedef struct {
	unsigned int	ith;
	unsigned int	val;
} TfwPrcntl;

/*
 * @stats	- Percentile Stats array.
 * @stsz	- @stats array size.
 * @min		- Minimal value.
 * @max		- Maximal value.
 * @avg		- Average value.
 * @seq		- opaque data related to percentiles calculation.
 */
typedef struct {
	TfwPrcntl	*prcntl;
	unsigned int	prcntlsz;
	unsigned int	min;
	unsigned int	max;
	unsigned int	avg;
	unsigned int	seq;
} TfwPrcntlStats;

void *tfw_apm_create(void);
void tfw_apm_destroy(void *data);
void tfw_apm_update(void *data, unsigned long jtstamp, unsigned long jrtime);
int tfw_apm_stats(void *data, TfwPrcntlStats *pstats);
int tfw_apm_stats_bh(void *data, TfwPrcntlStats *pstats);
int tfw_apm_prcntl_verify(TfwPrcntl *prcntl, unsigned int prcntlsz);

#endif /* __TFW_APM_H__ */
