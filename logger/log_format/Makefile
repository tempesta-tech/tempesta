#		Tempesta FW
#
# Copyright (C) 2026 Tempesta Technologies, Inc.
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

CXX := g++
CXXFLAGS := -Wall -Wextra -std=c++23 -march=native -mtune=native \
	    -MMD -MP

OBJS := $(patsubst %.cc, %.o, $(wildcard *.cc))
DEPS := $(OBJS:.o=.d)
TARGET := eventlog_format

DEBUG ?= 0
ifeq ($(DEBUG), 0)
	CXXFLAGS += -O3 -DNDEBUG -s
else
	CXXFLAGS += -DDEBUG=1 -O0 -ggdb3
endif

all: $(TARGET)

$(OBJS): Makefile

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS)

-include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)

.PHONY: all clean
