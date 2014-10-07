/**
 *		Tempesta FW
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
#ifndef __TFW_HTTP_MATCH_H__
#define __TFW_HTTP_MATCH_H__

#include "addr.h"
#include "pool.h"
#include "http.h"

typedef enum {
	TFW_MATCH_SUBJ_NA = 0,
	TFW_MATCH_SUBJ_METHOD,
	TFW_MATCH_SUBJ_URI,
	TFW_MATCH_SUBJ_HOST,
	TFW_MATCH_SUBJ_HEADERS,
	_TFW_MATCH_SUBJ_COUNT,
} tfw_match_subj_t;

typedef enum {
	TFW_MATCH_OP_NA = 0,
	TFW_MATCH_OP_EQ,
	TFW_MATCH_OP_PREFIX,
	_TFW_MATCH_OP_COUNT,
} tfw_match_op_t;

typedef struct {
	short len;
	char data[];
} TfwMatchArgStr;

typedef union {
	unsigned char method;
	TfwMatchArgStr str;
} TfwMatchArg;

typedef struct {
	tfw_match_subj_t subj;	/* A field to compare: uri/host/header/etc. */
	tfw_match_op_t op;	/* Comparison operation: eq/prefix/regex/etc. */
	TfwMatchArg arg;	/* A value for matching with the field. */
} TfwMatchRule;

typedef struct {
	TfwPool *pool;
	int rules_n;
	int rules_max;
	TfwMatchRule *rules[];
} TfwMatchTbl;



TfwMatchTbl *tfw_match_tbl_alloc(void);
void tfw_match_tbl_free(TfwMatchTbl *);
int tfw_match_tbl_rise(TfwMatchTbl **tbl, TfwMatchRule **rule, int rule_arg_len);

const TfwMatchRule *tfw_match_http_req(const TfwHttpReq *, const TfwMatchTbl *);

#endif /* __TFW_HTTP_MATCH_H__ */
