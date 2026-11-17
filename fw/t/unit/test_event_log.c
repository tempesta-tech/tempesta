/**
 *		Tempesta FW
 *
 * Copyright (C) 2024-2026 Tempesta Technologies, Inc.
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

#include "test.h"
#include "event_log.c"

/* procfs.c is not linked into the unit-test module. */
DEFINE_PER_CPU_ALIGNED(u64[TFW_LOG_EVENT_MAX], log_event_counters);

struct event_bin_data {
	long		_long;
	unsigned long	_ulong;
	unsigned int	_uint;
	int		_int;
	short		_short;
	unsigned short	_ushort;
	char		_byte;
	unsigned char	_ubyte;
	unsigned char	_char;
	unsigned char	_char_fill; //The second char just to not have hole.
};

static int
buffer_write(char *buff, unsigned int *room_size, const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = tfw_log_vwrite_bin(&buff, room_size, fmt, args);
	va_end(args);

	return r;
}

TEST(event_log, write_read_buffer)
{
	int r;
	unsigned int size = 1024;
	struct event_bin_data event = {};
	const char bounded_str[] = { 'T', 'e', 'm', 'p', 'e', 's', 't', 'a' };
	char *str = "Tempesta FW is an all-in-one open-source solution";

	event._long = -932;
	event._ulong = 712;
	event._uint = 102;
	event._int = -563;
	event._ushort = 222;
	event._short = -156;
	event._ubyte = 63;
	event._byte = -44;
	event._char = 'q';
	event._char_fill = 'b';

	void *buff = kzalloc(GFP_KERNEL, size);

	if (!buff) {
		EXPECT_NOT_NULL(buff);
		return;
	}

	r = buffer_write(buff, &size, "%ld%lu%u%d%hd%hu%hhd%hhu%c%c%s",
			 event._long, event._ulong, event._uint, event._int,
			 event._short, event._ushort, event._byte, event._ubyte,
			 event._char, event._char_fill, str);
	if (r) {
		EXPECT_OK(r);
		goto out;
	}

	/* Size of all written elements except string */
	unsigned short written_size = (*(TfwLogFieldLen *)buff) -
		sizeof(TfwLogFieldLen) - strlen(str);

	EXPECT_EQ(written_size, sizeof(event));

	char *data = buff + sizeof(TfwLogFieldLen);

	EXPECT_ZERO(memcmp(&event, data, written_size));

	char *stored_str = data + written_size;
	unsigned short str_size = (*(TfwLogFieldLen *)stored_str);
	char *str_data = stored_str + sizeof(TfwLogFieldLen);

	EXPECT_EQ(str_size, strlen(str));
	EXPECT_ZERO(memcmp(str_data, str, str_size));

	/* A precision-limited string does not have to be null-terminated. */
	size = 1024;
	memset(buff, 0, size);
	r = buffer_write(buff, &size, "%.*s", (int)sizeof(bounded_str),
			 bounded_str);
	EXPECT_OK(r);
	if (r)
		goto out;

	stored_str = buff + sizeof(TfwLogFieldLen);
	str_size = *(TfwLogFieldLen *)stored_str;
	str_data = stored_str + sizeof(TfwLogFieldLen);

	EXPECT_EQ(*(TfwLogFieldLen *)buff,
		  sizeof(TfwLogFieldLen) + sizeof(bounded_str));
	EXPECT_EQ(str_size, sizeof(bounded_str));
	EXPECT_ZERO(memcmp(str_data, bounded_str, str_size));

out:
	kfree(buff);
}

TEST(event_log, event_counters)
{
	TfwMmapBufferHolder *saved_buffer = mmap_buffer, *holder;
	TfwMmapBuffer *buf;
	u64 dos_count, web_count, suspicious_count;
	u64 saved_dropped, head, event_size;
	unsigned int size;
	long payload_evaluated = 0;
	int socket_evaluated = 0;
	int mode;
	int saved_log_type = access_log_type;

	holder = tfw_mmap_buffer_create(NULL, TFW_MMAP_BUFFER_MIN_SIZE);
	EXPECT_NOT_NULL(holder);
	if (!holder)
		return;

	local_bh_disable();
	mmap_buffer = holder;
	buf = *this_cpu_ptr(holder->buf);
	size = buf->size;
	saved_dropped = this_cpu_read(mmap_log_dropped);
	this_cpu_write(mmap_log_dropped, 0);
	dos_count = this_cpu_read(log_event_counters[TFW_LOG_EVENT_MAX_CONN_EXCEEDED]);
	web_count = this_cpu_read(log_event_counters[TFW_LOG_EVENT_EMPTY_CT_HDR]);
	suspicious_count = this_cpu_read(log_event_counters[TFW_LOG_EVENT_SPLITTING_ATTACK]);

	/* Count with mmap disabled, without touching sockets or payloads. */
	for (mode = ACCESS_LOG_OFF; mode <= ACCESS_LOG_DMESG; ++mode) {
		access_log_type = mode;
		log_dos_event(TFW_LOG_EVENT_MAX_CONN_EXCEEDED, NULL, false,
			      ++payload_evaluated, 2L);
		log_web_attack_event(TFW_LOG_EVENT_EMPTY_CT_HDR, NULL, false);
		log_suspicious_event(TFW_LOG_EVENT_SPLITTING_ATTACK,
				     (++socket_evaluated, NULL));
	}
	EXPECT_ZERO(payload_evaluated);
	EXPECT_ZERO(socket_evaluated);
	EXPECT_ZERO(buf->head);
	EXPECT_ZERO(this_cpu_read(mmap_log_dropped));
	EXPECT_EQ(this_cpu_read(log_event_counters[TFW_LOG_EVENT_MAX_CONN_EXCEEDED]),
		  dos_count + 2);
	EXPECT_EQ(this_cpu_read(log_event_counters[TFW_LOG_EVENT_EMPTY_CT_HDR]),
		  web_count + 2);
	EXPECT_EQ(this_cpu_read(log_event_counters[TFW_LOG_EVENT_SPLITTING_ATTACK]),
		  suspicious_count + 2);

	access_log_type = ACCESS_LOG_MMAP;
	log_dos_event(TFW_LOG_EVENT_MAX_CONN_EXCEEDED, NULL, false, 1L, 2L);
	log_web_attack_event(TFW_LOG_EVENT_EMPTY_CT_HDR, NULL, false);
	head = buf->head;
	log_suspicious_event(TFW_LOG_EVENT_SPLITTING_ATTACK, NULL);
	event_size = buf->head - head;
	EXPECT_GT(event_size, 0);
	EXPECT_EQ(this_cpu_read(log_event_counters[TFW_LOG_EVENT_MAX_CONN_EXCEEDED]),
		  dos_count + 3);
	EXPECT_EQ(this_cpu_read(log_event_counters[TFW_LOG_EVENT_EMPTY_CT_HDR]),
		  web_count + 3);
	EXPECT_EQ(this_cpu_read(log_event_counters[TFW_LOG_EVENT_SPLITTING_ATTACK]),
		  suspicious_count + 3);

	/* Count the event even if the buffer cannot fit the record. */
	buf->head = size - 1;
	log_suspicious_event(TFW_LOG_EVENT_SPLITTING_ATTACK, NULL);
	buf->head = size - 1 - sizeof(TfwBinLogEvent);
	log_suspicious_event(TFW_LOG_EVENT_SPLITTING_ATTACK, NULL);
	EXPECT_EQ(this_cpu_read(log_event_counters[TFW_LOG_EVENT_SPLITTING_ATTACK]),
		  suspicious_count + 5);
	EXPECT_EQ(this_cpu_read(mmap_log_dropped), 2);

	/* Fill the advertised room exactly to make the commit itself fail. */
	buf->head = 0;
	buf->size = event_size + 1;
	this_cpu_write(mmap_log_dropped, 0);
	log_suspicious_event(TFW_LOG_EVENT_SPLITTING_ATTACK, NULL);
	EXPECT_ZERO(buf->head);
	EXPECT_EQ(this_cpu_read(mmap_log_dropped), 1);
	EXPECT_EQ(this_cpu_read(log_event_counters[TFW_LOG_EVENT_SPLITTING_ATTACK]),
		  suspicious_count + 6);

	buf->size = size;
	this_cpu_write(mmap_log_dropped, 0);
	access_log_type = ACCESS_LOG_MMAP | ACCESS_LOG_DMESG;
	log_suspicious_event(TFW_LOG_EVENT_SPLITTING_ATTACK, NULL);
	EXPECT_GT(buf->head, 0);
	EXPECT_EQ(this_cpu_read(log_event_counters[TFW_LOG_EVENT_SPLITTING_ATTACK]),
		  suspicious_count + 7);

	this_cpu_write(mmap_log_dropped, saved_dropped);
	mmap_buffer = saved_buffer;
	access_log_type = saved_log_type;
	local_bh_enable();
	tfw_mmap_buffer_free(holder);
}

TEST_SUITE(event_log)
{
	TEST_RUN(event_log, write_read_buffer);
	TEST_RUN(event_log, event_counters);
}
