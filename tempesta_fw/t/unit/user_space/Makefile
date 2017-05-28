#		Tempesta FW
#
# User-space unit tests.
#
# Copyright (C) 2016-207 Tempesta Technologies, Inc.
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

ifndef CC
	CC	= gcc
endif
ifndef CXX
	CXX	= g++
endif

CACHELINE := $(shell getconf LEVEL1_DCACHE_LINESIZE)

CFLAGS		= -O0 -ggdb -Wall -Werror \
		  -pthread -DL1_CACHE_BYTES=$(CACHELINE) \
		  -I../../../../ktest
CXXFLAGS	= -std=c++11 ${CFLAGS}
TARGETS		= alb percentiles slr

all : $(TARGETS)

percentiles : percentiles.c
	$(CC) $(CFLAGS) -o $@ $^

alb : alb.c
	$(CC) $(CFLAGS) -o $@ $^

slr : slr.cc
	$(CXX) $(CXXFLAGS) -o $@ $^

clean : FORCE
	rm -f *.o *~ *.orig $(TARGETS)

FORCE :
