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
} PrcntlStats;

/*
 * @stats	- Percentile Stats array.
 * @stsz	- @stats array size.
 * @seq		- opaque data related to percentiles calculation.
 */
typedef struct {
	PrcntlStats	*pstats;
	unsigned int	pstsz;
	unsigned int	seq;
} Percentile;

void *tfw_apm_create(void);
void tfw_apm_destroy(void *data);
void tfw_apm_update(void *data, unsigned long jtstamp, unsigned long jrtime);
int tfw_apm_stats(void *data, Percentile *prcntl);
int tfw_apm_percentile_verify(Percentile *prcntl);

#endif /* __TFW_APM_H__ */
