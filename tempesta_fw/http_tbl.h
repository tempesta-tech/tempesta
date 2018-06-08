/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#ifndef __HTTP_TBL__
#define __HTTP_TBL__

#include "http.h"

/**
 * HTTP chain. Contains list of rules for matching.
 *
 * @list	- Entry in list of all HTTP chains in current HTTP table.
 * @mark_list	- List of configured mark rules (processed primarily).
 * @match_list	- List of configured match rules (processed after mark rules).
 * @name	- Name of HTTP chain.
 * @pool	- Pointer to parent table's pool for rules allocations.
 */
typedef struct {
	struct list_head list;
	struct list_head mark_list;
	struct list_head match_list;
	const char *name;
	TfwPool *pool;
} TfwHttpChain;

/**
 * HTTP table. Contains list of HTTP chains.
 *
 * @head	- List of configured HTTP chains.
 * @chain_dflt	- Flag to indicate whether the chain with default rule is
 *		  present in configuration or not.
 * @pool	- Allocation pool for HTTP table (and all its chains and rules).
 */
typedef struct {
	struct list_head head;
	bool chain_dflt;
	TfwPool *pool;
} TfwHttpTable;

TfwVhost *tfw_http_tbl_vhost(TfwMsg *msg, bool *block);
int tfw_http_tbl_method(const char *arg, tfw_http_meth_t *method);

#endif /* __HTTP_TBL__ */
