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
#include "access_log.c"

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

TEST_SUITE(event_log)
{
	TEST_RUN(event_log, write_read_buffer);
}
