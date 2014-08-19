/**
 *		Tempesta FW
 *
 * HTTP cache (see RFC 2616).
 * Here is implementation of expiration and validation models and other HTTP
 * specific stuff. The cache is backed by physical storage layer.
 *
 * TODO:
 * 1. Cache-Control, Expires, ETag, Last-Modified, Vary and some other
 *    RFC 2616 HTTP cache control facilities are not supported yet.
 *    RFC 3143 also affects the caching design.
 *
 * 2. Purge cache by individual entities (e.g. curl -X PURGE <URL>)
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
#include "tempesta.h"
#include "cache.h"

#include "tdb.h"

#define CKEY_SZ		2

static TDB *db;

void
tfw_cache_add(TfwHttpResp *resp)
{
	if (!tfw_cfg.cache)
		return;

	/* TODO prepare resp to writable format: size and raw data. */

	tdb_write(db);
}

TfwCacheEntry *
tfw_cache_lookup(TfwHttpReq *req)
{
	TfwCacheEntry *ce;
	unsigned long key[CKEY_SZ];

	if (!tfw_cfg.cache)
		return NULL;

	/* TODO set key */

	ce = tdb_lookup(db, key);
	if (!ce)
		return NULL;

	/* TODO prcess ce? */

	return ce;
}

int __init
tfw_cache_init(void)
{
	if (!tfw_cfg.cache)
		return 0;

	db = tdb_open(tfw_cfg.c_path, tfw_cfg.c_size,
		      TDB_IDX_TREE, CKEY_SZ, TDB_EVC_LRU);
	if (!db)
		return 1;

	return 0;
}

void
tfw_cache_exit(void)
{
	if (!tfw_cfg.cache)
		return;

	tdb_close(db);
}
