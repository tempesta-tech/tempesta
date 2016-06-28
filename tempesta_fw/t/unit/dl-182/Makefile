#		Tempesta FW
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015 Tempesta Technologies, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.

CC = gcc
CFLAGS = -Os -ggdb -I. -std=c99
AVXFLAGS = -mavx2 -D__ENABLE_AVX__
LDFLAGS =

ifdef DEBUG
	EXTRA_CFLAGS += -DDEBUG=$(DEBUG)
else
	EXTRA_CFLAGS += -DDEBUG=0
endif

DEPS = sse_parser.h http_parser.h pool.h helpers.h http_parser_impl.c

all: http_parser http_parser_avx

http_parser: http_parser.o http_msg.o str.o pool.o skbuff.o main.o
	$(CC) -o $@ $^ $(LDFLAGS)

http_parser_avx: avx_http_parser.o avx_routines.o avx_http_msg.o avx_str.o pool.o skbuff.o main.o
	$(CC) -o $@ $^ $(LDFLAGS)

avx_http_parser.o:
	$(CC) -c -o avx_http_parser.o http_parser.c $(AVXFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)

avx_routines.o:
	$(CC) -c -o avx_routines.o avx_routines.c $(AVXFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)

avx_http_msg.o:
	$(CC) -c -o avx_http_msg.o http_msg.c $(AVXFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)

avx_str.o:
	$(CC) -c -o avx_str.o str.c $(AVXFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(EXTRA_CFLAGS)

.PHONY: clean

clean:
	rm -f *.o *~ test_*
