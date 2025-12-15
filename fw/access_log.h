/**
 *		Tempesta FW
 *
 * Copyright (C) 2022-2025 Tempesta Technologies, Inc.
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
#ifndef __TFW_ACCESS_LOG_H__
#define __TFW_ACCESS_LOG_H__

#ifdef __KERNEL__

#include "http_types.h"
#include <linux/types.h>

#else /* __KERNEL__ */

#include <stdint.h>

#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#endif /* __KERNEL__ */

#define TFW_MMAP_LOG_TYPE_LEN 3

/*
 * @type	- The type of the event, look at TfwBinLogType;
 * @timestamp	- the time when the event occurred;
 * @fields	- bits of fields presence.
 */
typedef struct __attribute__((packed)) {
	u16	type : TFW_MMAP_LOG_TYPE_LEN;
	u16	fields : 16 - TFW_MMAP_LOG_TYPE_LEN;
	u64	timestamp;
} TfwBinLogEvent;

typedef enum {
	TFW_MMAP_LOG_TYPE_ACCESS,
	TFW_MMAP_LOG_TYPE_SECURITY,
	TFW_MMAP_LOG_TYPE_ERROR,
} TfwBinLogType;

typedef enum {
	TFW_MMAP_LOG_ADDR,
	TFW_MMAP_LOG_METHOD,
	TFW_MMAP_LOG_VERSION,
	TFW_MMAP_LOG_STATUS,
	TFW_MMAP_LOG_RESP_CONT_LEN,
	TFW_MMAP_LOG_RESP_TIME,
	TFW_MMAP_LOG_VHOST,
	TFW_MMAP_LOG_URI,
	TFW_MMAP_LOG_REFERER,
	TFW_MMAP_LOG_USER_AGENT,
	TFW_MMAP_LOG_TFT,
	TFW_MMAP_LOG_TFH,
	TFW_MMAP_LOG_DROPPED,
	TFW_MMAP_LOG_MAX
} TfwBinLogFields;

#define TFW_MMAP_LOG_FIELD_IS_SET(event, field) \
	((event)->fields >> field & 1)
#define TFW_MMAP_LOG_FIELD_SET(event, field) \
	do { (event)->fields |= 1 << (field); } while (0)
#define TFW_MMAP_LOG_FIELD_RESET(event, field) \
	do { (event)->fields &= ~((u16)1 << (field)); } while (0)
#define TFW_MMAP_LOG_ALL_FIELDS_MASK ((1 << TFW_MMAP_LOG_MAX) - 1)

static inline int tfw_mmap_log_field_len(TfwBinLogFields field)
{
	static const int TfwBinLogFieldsLens[] = {
		[TFW_MMAP_LOG_ADDR] = 16,
		[TFW_MMAP_LOG_METHOD] = 1,
		[TFW_MMAP_LOG_VERSION] = 1,
		[TFW_MMAP_LOG_STATUS] = 2,
		[TFW_MMAP_LOG_RESP_CONT_LEN] = 8,
		[TFW_MMAP_LOG_RESP_TIME] = 4,
		[TFW_MMAP_LOG_VHOST] = 0, /* 0 - string */
		[TFW_MMAP_LOG_URI] = 0,
		[TFW_MMAP_LOG_REFERER] = 0,
		[TFW_MMAP_LOG_USER_AGENT] = 0,
		[TFW_MMAP_LOG_TFT] = 8,
		[TFW_MMAP_LOG_TFH] = 8,
		[TFW_MMAP_LOG_DROPPED] = 8
	};
	return TfwBinLogFieldsLens[field];
}

#ifdef __KERNEL__

int tfw_access_log_init(void);
void tfw_access_log_exit(void);
void do_access_log_req(TfwHttpReq *req, int status, unsigned long content_length);

#endif

#endif /* __TFW_ACCESS_LOG_H__ */
