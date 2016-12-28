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
CFLAGS = -mssse3 -Os -ggdb -I. -std=c99
LDFLAGS =

ifdef DEBUG
	EXTRA_CFLAGS += -DDEBUG=$(DEBUG)
else
	EXTRA_CFLAGS += -DDEBUG=0
endif

DEPS = sse_parser.h http_parser.h pool.h helpers.h http_parser_impl.c

all: test_sse_symbolmap test_sse_tokenset test_sse_http_request http_parser

http_parser: http_parser.o goto_parser.o http_parser_main.o helpers.o
	$(CC) -o $@ $^ $(LDFLAGS)

test_sse_symbolmap: sse_parser.o sse_charset.o
	$(CC) -o $@ $^ $(LDFLAGS)

test_sse_tokenset: sse_parser.o sse_tokenset.o
	$(CC) -o $@ $^ $(LDFLAGS)

test_sse_http_request: sse_parser.o sse_http_request.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(EXTRA_CFLAGS)

.PHONY: clean

clean:
	rm -f *.o *~ test_*
