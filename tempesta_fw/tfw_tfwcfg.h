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
#include "str.h"
#include "http_match.h"

typedef tfw_http_match_op_t	tfw_match_t;

/*
 * List of Tempesta configuration directives. 
 *
 * "stmt" (statement) word is used to make
 * ithe name of the variable short and concise.
 */
typedef enum {
	/* Cache directives. */
	TFW_D_CACHE_BYPASS,
	TFW_D_CACHE_FULFILL,
	TFW_D_CACHE_DEFAULT,

	_TFW_D_COUNT
} tfw_stmt_t;

typedef struct {
	tfw_stmt_t	stmt;
	tfw_match_t	op;
	const char	*arg;
	unsigned int	len;
} TfwCfgCacheMatch;

typedef struct {
	tfw_match_t		op;
	const char		*arg;
	unsigned int		len;
	TfwCfgCacheMatch	**cam;
	unsigned int		cam_sz;
	unsigned int		cam_max;
} TfwCfgLocation;


const char * tfw_stmt_string(tfw_stmt_t stmt);
TfwCfgCacheMatch * tfw_camatch_match(TfwCfgLocation *loc, TfwStr *arg);
TfwCfgLocation * tfw_location_match(TfwStr *arg);
