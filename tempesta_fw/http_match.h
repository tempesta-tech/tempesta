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

#include <linux/list.h>

#include "pool.h"
#include "http.h"

typedef enum {
	TFW_HTTP_MATCH_F_NA = 0,
	TFW_HTTP_MATCH_F_METHOD,
	TFW_HTTP_MATCH_F_URI,
	TFW_HTTP_MATCH_F_HOST,
	TFW_HTTP_MATCH_F_HEADERS,
	_TFW_HTTP_MATCH_F_COUNT,
} tfw_http_match_fld_t;

typedef enum {
	TFW_HTTP_MATCH_O_NA = 0,
	TFW_HTTP_MATCH_O_EQ,
	TFW_HTTP_MATCH_O_PREFIX,
	_TFW_HTTP_MATCH_O_COUNT,
} tfw_http_match_op_t;

typedef struct {
	short len;
	const char *s;
} TfwMatchArgStr;

typedef union {
	unsigned char method;
	TfwAddr addr;
	TfwMatchArgStr str;
} TfwMatchArg;

typedef struct {
	struct list_head	list;
	tfw_http_match_fld_t	field;
	tfw_http_match_op_t 	op;
	TfwMatchArg 		arg;
	char extra[0];  /* May be consumed for variable-length @arg. */
} TfwHttpMatchRule;

typedef struct {
	struct list_head list;
	TfwPool *pool;
} TfwHttpMatchList;


TfwHttpMatchList *tfw_http_match_list_alloc(void);
void tfw_http_match_list_free(TfwHttpMatchList *);
TfwHttpMatchRule *tfw_http_match_rule_new(TfwHttpMatchList *, size_t extra_len);
TfwHttpMatchRule * tfw_http_match_req(const TfwHttpReq *, const TfwHttpMatchList *);

#define tfw_http_match_req_entry(req, mlst, container, member) 		\
({ 									\
	container *_c = NULL;						\
	TfwHttpMatchRule *_r = tfw_http_match_req((req), (mlst)); 	\
	if (_r)								\
		_c = container_of(_r, container, member);		\
	_c;								\
})

#define tfw_http_match_entry_new(mlst, container, member, extra_len) 	\
({ 									\
	size_t _s = sizeof(container) + (extra_len); 			\
	container *_c = tfw_pool_alloc((mlst)->pool, _s);		\
	if (!_c) {							\
		TFW_ERR("Can't allocate memory from pool\n");		\
	} else { 							\
		memset(_c, 0, _s);					\
		INIT_LIST_HEAD(&_c->member.list);			\
		list_add_tail(&_c->member.list, &(mlst)->list);		\
	}								\
	_c;								\
})


#endif /* __TFW_HTTP_MATCH_H__ */
