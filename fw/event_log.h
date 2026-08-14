/**
 *		Tempesta FW
 *
 * Copyright (C) 2026 Tempesta Technologies, Inc.
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

#ifndef __EVENT_LOG_H__
#define __EVENT_LOG_H__

#ifdef __KERNEL__

#include "http_types.h"
#include "addr.h"
#include <linux/types.h>

#else /* __KERNEL__ */

#include <stdint.h>

#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#endif /* __KERNEL__ */

extern int access_log_type;

#define EVENT_TO_FMT(name) (name##_binary_fmt)
#define EVENT_TO_TEXT_FMT(name) (name##_text_fmt)

typedef enum {
#define DEFINE_EVENT(name, bin_fmt, text_fmt)	name,
#define DEFINE_EVENT_NO_PARAMS(name, text_str) name,
	TFW_LOG_EVENT_INVALID = 0,
#include "event_types.h"
	TFW_LOG_EVENT_MAX
#undef DEFINE_EVENT
#undef DEFINE_EVENT_NO_PARAMS
} TfwLogEventType;

#ifdef __KERNEL__

typedef struct {
	unsigned int type;
	unsigned int fields_max;
	unsigned int body_field;
	unsigned int dropped_field;
} TfwEventParams;

static inline void __printf(1, 2)
__tfw_event_text_printf_check(const char *fmt, ...)
{

}

#define DEFINE_EVENT(name, bin_fmt, text_fmt)				\
	static const char * const name##_binary_fmt = bin_fmt;		\
	static const char name##_text_fmt[] = text_fmt;

/*
 * @text_str is a fixed string, not a format with parameters, so it must not
 * contain conversion specifications such as "%s" or "%u". The generated
 * inline function passes @text_str to the printf checker with no arguments.
 * Its body is checked even if the function is never called, which makes an
 * invalid @text_str fail compilation when the event is declared. The unused
 * function has no runtime cost; "%%" remains valid for a literal percent sign.
 */
#define DEFINE_EVENT_NO_PARAMS(name, text_str)				\
	DEFINE_EVENT(name, NULL, text_str)				\
	static inline void name##_text_fmt_check(void)			\
	{								\
		__tfw_event_text_printf_check(name##_text_fmt);		\
	}
#include "event_types.h"
#undef DEFINE_EVENT
#undef DEFINE_EVENT_NO_PARAMS

typedef unsigned short TfwLogFieldLen;
#endif /* __KERNEL__ */

#define ACCESS_LOG_OFF   0
#define ACCESS_LOG_DMESG 1
#define ACCESS_LOG_MMAP  2

#define TFW_EVENT_LOG_MAX_BIN_LEN 65535U

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
	TFW_MMAP_LOG_TYPE_WEB_ATTACK,
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
} TfwAccessLogFields;

typedef enum {
	TFW_DOS_LOG_ADDR,
	TFW_DOS_LOG_CLIENT_PORT,
	TFW_DOS_LOG_LOCAL_PORT,
	TFW_DOS_LOG_EVENT_TYPE,
	TFW_DOS_LOG_EVENT_BODY,
	TFW_DOS_LOG_IP_BLOCK,
	TFW_DOS_LOG_DROPPED,
	TFW_DOS_LOG_MAX
} TfwDosLogFields;

typedef enum {
	TFW_WA_LOG_ADDR,
	TFW_WA_LOG_CLIENT_PORT,
	TFW_WA_LOG_LOCAL_PORT,
	TFW_WA_LOG_EVENT_TYPE,
	TFW_WA_LOG_EVENT_BODY,
	TFW_WA_LOG_IP_BLOCK,
	TFW_WA_LOG_DROPPED,
	TFW_WA_LOG_MAX
} TfwWebAttackLogFields;

#define TFW_MMAP_LOG_FIELD_IS_SET(event, field) \
	((event)->fields >> field & 1)
#define TFW_MMAP_LOG_FIELD_SET(event, field) \
	((event)->fields |= 1 << (field))
#define TFW_MMAP_LOG_FIELD_RESET(event, field) \
	((event)->fields &= ~((u16)1 << (field)))
#define TFW_MMAP_LOG_ENABLE_ALL_FIELDS(type) ((1 << type) - 1)

enum format_type {
	FORMAT_TYPE_NONE, /* Unknown type */
	FORMAT_TYPE_INVALID,
	FORMAT_TYPE_PRECISION,
	FORMAT_TYPE_CHAR,
	FORMAT_TYPE_STR,
	FORMAT_TYPE_ULONG,
	FORMAT_TYPE_LONG,
	FORMAT_TYPE_UBYTE,
	FORMAT_TYPE_BYTE,
	FORMAT_TYPE_USHORT,
	FORMAT_TYPE_SHORT,
	FORMAT_TYPE_UINT,
	FORMAT_TYPE_INT,
};

static inline int
tfw_mmap_log_field_len(TfwAccessLogFields field)
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

/**
 * c, i, d, u.
 * s
 * l, h, hh.
 */
static inline int
format_decode(const char *fmt, unsigned char *type, int *precision)
{
#define SIGN	1		/* unsigned/signed, must be 1 */

	const char *start = fmt;
	char qualifier = 0;
	int spec_sign = 0;

	/* we finished early by reading the precision */
	if (*type == FORMAT_TYPE_PRECISION) {
		if (*precision < 0)
			*precision = 0;

		*type = FORMAT_TYPE_NONE;
		goto format;
	}

	/* By default */
	*type = FORMAT_TYPE_NONE;

	for (; *fmt ; ++fmt) {
		if (*fmt == '%')
			break;
	}

	/* Return the current non-format string */
	if (fmt != start || !*fmt)
		return fmt - start;

	++fmt;

	if (*fmt == '.') {
		++fmt;
		if (*fmt == '*') {
			/* it's the next argument */
			*type = FORMAT_TYPE_PRECISION;
			return ++fmt - start;
		}
	}

	*precision = -1;
	/* get the conversion qualifier */
	if (*fmt == 'h' || *fmt == 'l') {
		qualifier = *fmt++;
		if (qualifier == *fmt && *fmt == 'h') {
			qualifier = 'H';
			++fmt;
		}
	}

format:
	switch (*fmt) {
	case 'c':
		*type = FORMAT_TYPE_CHAR;
		return ++fmt - start;

	case 's':
		*type = FORMAT_TYPE_STR;
		return ++fmt - start;

	/* integer number formats - "break" */
	case 'd':
	case 'i':
		spec_sign = SIGN;
		break;
	case 'u':
		break;
	default:
#ifdef __KERNEL__
		WARN_ONCE(1, "Unsupported format %%%c string\n", *fmt);
#endif
		*type = FORMAT_TYPE_INVALID;
		return fmt - start;
	}

	if (qualifier == 'l') {
#ifdef __KERNEL__
		BUILD_BUG_ON(FORMAT_TYPE_ULONG + SIGN != FORMAT_TYPE_LONG);
#endif
		*type = FORMAT_TYPE_ULONG + spec_sign;
	}
	else if (qualifier == 'H') {
#ifdef __KERNEL__
		BUILD_BUG_ON(FORMAT_TYPE_UBYTE + SIGN != FORMAT_TYPE_BYTE);
#endif
		*type = FORMAT_TYPE_UBYTE + spec_sign;
	}
	else if (qualifier == 'h') {
#ifdef __KERNEL__
		BUILD_BUG_ON(FORMAT_TYPE_USHORT + SIGN != FORMAT_TYPE_SHORT);
#endif
		*type = FORMAT_TYPE_USHORT + spec_sign;
	}
	else {
#ifdef __KERNEL__
		BUILD_BUG_ON(FORMAT_TYPE_UINT + SIGN != FORMAT_TYPE_INT);
#endif
		*type = FORMAT_TYPE_UINT + spec_sign;
	}

	return ++fmt - start;

#undef SIGN
}

#ifdef __KERNEL__

int tfw_event_log_init(void);
void tfw_event_log_exit(void);
void do_access_log_req(TfwHttpReq *req, int status, unsigned long content_length);
void do_access_log(TfwHttpResp *resp);
static inline bool
access_log_mmap_enabled(void)
{
	return access_log_type & ACCESS_LOG_MMAP;
}

static inline bool
access_log_dmesg_enabled(void)
{
	return access_log_type & ACCESS_LOG_DMESG;
}

void _log_security_event(TfwLogEventType event_type, TfwEventParams params,
			 const TfwAddr *addr, unsigned short local_port,
			 bool ip_block, const char *fmt, ...);

#define log_dos_event(event_type, addr, local_port, ip_block, ...)		\
do {										\
	TfwEventParams params = {						\
			 .type = TFW_MMAP_LOG_TYPE_SECURITY,			\
			 .fields_max =						\
				TFW_MMAP_LOG_ENABLE_ALL_FIELDS(TFW_DOS_LOG_MAX),\
			 .body_field = TFW_DOS_LOG_EVENT_BODY,			\
			 .dropped_field = TFW_DOS_LOG_DROPPED			\
	};									\
	_log_security_event(event_type, params, addr, local_port, ip_block,	\
			    EVENT_TO_FMT(event_type), ##__VA_ARGS__);		\
	__tfw_event_text_printf_check(EVENT_TO_TEXT_FMT(event_type),		\
				      ##__VA_ARGS__);				\
} while (0)

#define log_web_attack_event(event_type, addr, local_port, ip_block, ...)	\
do {										\
	TfwEventParams params = {						\
			 .type = TFW_MMAP_LOG_TYPE_WEB_ATTACK,			\
			 .fields_max =						\
				TFW_MMAP_LOG_ENABLE_ALL_FIELDS(TFW_WA_LOG_MAX),	\
			 .body_field = TFW_WA_LOG_EVENT_BODY,			\
			 .dropped_field = TFW_WA_LOG_DROPPED			\
	};									\
	_log_security_event(event_type, params, addr, local_port, ip_block,	\
			    EVENT_TO_FMT(event_type), ##__VA_ARGS__);		\
	__tfw_event_text_printf_check(EVENT_TO_TEXT_FMT(event_type),		\
				      ##__VA_ARGS__);				\
} while (0)
#endif

#endif /* __EVENT_LOG_H__ */
