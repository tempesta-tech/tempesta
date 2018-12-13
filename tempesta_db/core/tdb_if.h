/**
 *		Tempesta DB
 *
 * User-space communication interfaces.
 *
 * Copyright (C) 2015-2018 Tempesta Technologies.
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
#ifndef __TDB_IF_H__
#define __TDB_IF_H__

#include "extent.h"

#ifndef NETLINK_TEMPESTA
#define NETLINK_TEMPESTA	22
#endif
#ifndef SOL_NETLINK
#define SOL_NETLINK		270
#endif

#define TDB_SUFFIX		".tdb"
#define TDB_TBLNAME_LEN		15
#define TDB_PATH_LEN		128
#define NL_FR_SZ		16384

enum tdb_msg_type {
	__TDB_MSG_UNSPEC,
	__TDB_MSG_BASE,
	TDB_MSG_INFO	= __TDB_MSG_BASE,
	TDB_MSG_OPEN,
	TDB_MSG_CLOSE,
	TDB_MSG_INSERT,
	TDB_MSG_SELECT,
	__TDB_MSG_TYPE_MAX
};

#define TDB_NLF_TYPE_MASK	0x00ff
#define TDB_NLF_RESP_OK		0x0100 /* good response status */
#define TDB_NLF_RESP_TRUNC	0x0200 /* response was truncated */
#define TDB_NLF_RESP_END	0x0400 /* end of chunked response */

/**
 * Record for create table command.
 */
typedef struct {
	size_t		tbl_size;
	unsigned int	rec_size;
	unsigned int	path_len;
	char		path[0];
} TdbCrTblRec;

/**
 * Record specification used for update and select queries.
 *
 * @klen	- key length;
 * @dlen	- data length;
 * @data	- record key followed by body
 */
typedef struct {
	unsigned int	klen;
	unsigned int	dlen;
	char		data[0];
} TdbMsgRec;

#define TDB_MSGREC_LEN(r)	(sizeof(*(r)) + (r)->klen + (r)->dlen)
#define TDB_MSGREC_DATA(r)	((r)->data + (r)->klen)

/**
 * @type	- message type;
 * @rec_n	- number of record specifications;
 * @t_name	- table name;
 * @recs	- record specifications (keys only for select or <key,value>
 * 		  for inserts and updates);
 */
typedef struct {
	unsigned int	type;
	unsigned int	rec_n;
	char		t_name[TDB_TBLNAME_LEN + 1];
	TdbMsgRec	recs[0];
} TdbMsg;

#ifdef __KERNEL__
int tdb_if_init(void);
void tdb_if_exit(void);
#endif

#endif /* __TDB_IF_H__ */
