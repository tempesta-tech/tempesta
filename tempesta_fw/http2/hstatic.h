/**
 *		Tempesta FW
 *
 * Static table from HPACK standard (RFC-7541).
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef HPACK_STATIC_H
#define HPACK_STATIC_H

#include "common.h"
#include "../str.h"
#include "hpack.h"
#include "hindex.h"

#define TFW_STATIC(s, n) {s, NULL, n, 0, 0}

static HPackEntry hpack_static_table [] = {
	{TFW_STATIC(":authority", 10),                  TFW_STATIC(NULL, 0)},
	{TFW_STATIC(":method", 7),                      TFW_STATIC("GET", 3)},
	{TFW_STATIC(":method", 7),                      TFW_STATIC("POST", 4)},
	{TFW_STATIC(":path", 5),                        TFW_STATIC("/", 1)},
	{TFW_STATIC(":path", 5),                        TFW_STATIC("/index.html", 11)},
	{TFW_STATIC(":scheme", 7),                      TFW_STATIC("http", 4)},
	{TFW_STATIC(":scheme", 7),                      TFW_STATIC("https", 5)},
	{TFW_STATIC(":status", 7),                      TFW_STATIC("200", 3)},
	{TFW_STATIC(":status", 7),                      TFW_STATIC("204", 3)},
	{TFW_STATIC(":status", 7),                      TFW_STATIC("206", 3)},
	{TFW_STATIC(":status", 7),                      TFW_STATIC("304", 3)},
	{TFW_STATIC(":status", 7),                      TFW_STATIC("400", 3)},
	{TFW_STATIC(":status", 7),                      TFW_STATIC("404", 3)},
	{TFW_STATIC(":status", 7),                      TFW_STATIC("500", 3)},
	{TFW_STATIC("accept-charset", 14),              TFW_STATIC(NULL, 0)},
	{TFW_STATIC("accept-encoding", 15),             TFW_STATIC("gzip, deflate", 13)},
	{TFW_STATIC("accept-language", 15),             TFW_STATIC(NULL, 0)},
	{TFW_STATIC("accept-ranges", 13),               TFW_STATIC(NULL, 0)},
	{TFW_STATIC("accept", 6),                       TFW_STATIC(NULL, 0)},
	{TFW_STATIC("access-control-allow-origin", 27), TFW_STATIC(NULL, 0)},
	{TFW_STATIC("age", 3),                          TFW_STATIC(NULL, 0)},
	{TFW_STATIC("allow", 5),                        TFW_STATIC(NULL, 0)},
	{TFW_STATIC("authorization", 13),               TFW_STATIC(NULL, 0)},
	{TFW_STATIC("cache-control", 13),               TFW_STATIC(NULL, 0)},
	{TFW_STATIC("content-disposition", 19),         TFW_STATIC(NULL, 0)},
	{TFW_STATIC("content-encoding", 16),            TFW_STATIC(NULL, 0)},
	{TFW_STATIC("content-language", 16),            TFW_STATIC(NULL, 0)},
	{TFW_STATIC("content-length", 14),              TFW_STATIC(NULL, 0)},
	{TFW_STATIC("content-location", 16),            TFW_STATIC(NULL, 0)},
	{TFW_STATIC("content-range", 13),               TFW_STATIC(NULL, 0)},
	{TFW_STATIC("content-type", 12),                TFW_STATIC(NULL, 0)},
	{TFW_STATIC("cookie", 6),                       TFW_STATIC(NULL, 0)},
	{TFW_STATIC("date", 4),                         TFW_STATIC(NULL, 0)},
	{TFW_STATIC("etag", 4),                         TFW_STATIC(NULL, 0)},
	{TFW_STATIC("expect", 6),                       TFW_STATIC(NULL, 0)},
	{TFW_STATIC("expires", 7),                      TFW_STATIC(NULL, 0)},
	{TFW_STATIC("from", 4),                         TFW_STATIC(NULL, 0)},
	{TFW_STATIC("host", 4),                         TFW_STATIC(NULL, 0)},
	{TFW_STATIC("if-match", 8),                     TFW_STATIC(NULL, 0)},
	{TFW_STATIC("if-modified-since", 17),           TFW_STATIC(NULL, 0)},
	{TFW_STATIC("if-none-match", 13),               TFW_STATIC(NULL, 0)},
	{TFW_STATIC("if-range", 8),                     TFW_STATIC(NULL, 0)},
	{TFW_STATIC("if-unmodified-since", 19),         TFW_STATIC(NULL, 0)},
	{TFW_STATIC("last-modified", 13),               TFW_STATIC(NULL, 0)},
	{TFW_STATIC("link", 4),                         TFW_STATIC(NULL, 0)},
	{TFW_STATIC("location", 8),                     TFW_STATIC(NULL, 0)},
	{TFW_STATIC("max-forwards", 12),                TFW_STATIC(NULL, 0)},
	{TFW_STATIC("proxy-authenticate", 18),          TFW_STATIC(NULL, 0)},
	{TFW_STATIC("proxy-authorization", 19),         TFW_STATIC(NULL, 0)},
	{TFW_STATIC("range", 5),                        TFW_STATIC(NULL, 0)},
	{TFW_STATIC("referer", 7),                      TFW_STATIC(NULL, 0)},
	{TFW_STATIC("refresh", 7),                      TFW_STATIC(NULL, 0)},
	{TFW_STATIC("retry-after", 11),                 TFW_STATIC(NULL, 0)},
	{TFW_STATIC("server", 6),                       TFW_STATIC(NULL, 0)},
	{TFW_STATIC("set-cookie", 10),                  TFW_STATIC(NULL, 0)},
	{TFW_STATIC("strict-transport-security", 25),   TFW_STATIC(NULL, 0)},
	{TFW_STATIC("transfer-encoding", 17),           TFW_STATIC(NULL, 0)},
	{TFW_STATIC("user-agent", 10),                  TFW_STATIC(NULL, 0)},
	{TFW_STATIC("vary", 4),                         TFW_STATIC(NULL, 0)},
	{TFW_STATIC("via", 3),                          TFW_STATIC(NULL, 0)},
	{TFW_STATIC("www-authenticate", 16),            TFW_STATIC(NULL, 0)}
};

#define HPACK_STATIC_ENTRIES (sizeof(hpack_static_table) / sizeof(HPackEntry))

#endif
