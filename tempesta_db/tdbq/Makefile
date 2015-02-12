#		Tempesta DB Query Tool
#
# Copyright (C) 2015 Tempesta Technologies.
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

CXX		= g++
CFLAGS		= -O2 -ggdb -Wall
LDFLAGS		= -L/usr/local/lib -lboost_program_options
INCLUDES	= -I/usr/local/include/boost-1_38
DEBUG		= -DDEBUG

OBJECTS	= main.o

all : tdbq

tdbq: $(OBJECTS)
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CXX) $(CFLAGS) $(DEBUG) $(INCLUDES) -c $< -o $@

clean: FORCE
	rm -f *.o* *~ tdbq tags *.core

FORCE:

