/**
 *		Tempesta FW
 *
 * Internal scheduler declarations.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_SCHED_MATCH_H__
#define __TFW_SCHED_MATCH_H__

#include "tempesta.h"
#include "addr.h"

#define LOG_BANNER "tfw_sched_match: "
#define ERR(...) TFW_ERR(LOG_BANNER __VA_ARGS__)
#define LOG(...) TFW_LOG(LOG_BANNER __VA_ARGS__)
#define DBG(...) TFW_DBG(LOG_BANNER __VA_ARGS__)

#define RULE_MAX_COUNT 64
#define RULE_PATTERN_SIZE 256
#define RULE_ADDR_COUNT 16

typedef enum {
	SUBJ_NA = 0,
	SUBJ_HOST,
	SUBJ_URI,
	SUBJ_HEADER
} subj_t;

typedef enum {
	OP_NA = 0,
	OP_EQUAL,
	OP_PREFIX,
} op_t;

typedef struct {
	subj_t subj;
	op_t op;
	size_t addrs_n;
	char pattern[RULE_PATTERN_SIZE];
	TfwAddr addrs[RULE_ADDR_COUNT];
} Rule;

typedef struct {
	size_t rules_n;
	Rule rules[RULE_MAX_COUNT];
} RuleTbl;

int apply_new_rules(const RuleTbl *tbl);

op_t op_from_str(const char *str, size_t maxlen);
subj_t subj_from_str(const char *str, size_t maxlen);

#endif /* __TFW_SCHED_MATCH_H__ */
