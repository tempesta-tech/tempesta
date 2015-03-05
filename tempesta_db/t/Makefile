# Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015 Tempesta Technologies Ltd.
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

CACHELINE := $(shell getconf LEVEL1_DCACHE_LINESIZE)

CFLAGS		= -O2 -msse4.2 -ggdb -Wall -Werror -fno-strict-aliasing \
		  -lpthread -DL1_CACHE_BYTES=$(CACHELINE) \
		  -I../../ktest
TARGETS		= tdb_htrie

all : $(TARGETS)

tdb_htrie : tdb_htrie.o
	$(CC) $(CFLAGS) -o $@ $^

%.o : %.cc
	$(CC) $(CFLAGS) -c $< -o $@

clean : FORCE
	rm -f *.o *~ *.orig $(TARGETS)

FORCE :
