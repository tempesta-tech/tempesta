#		Tempesta FW
#
# Copyright (C) 2024-2025 Tempesta Technologies, Inc.
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

ifeq ($(shell which pkgconf), )
$(error "pkgconf not found in $(PATH)")
endif

# We don't need to build clickhouse - it would be build by access_log_plugin as .a
SUBDIRS := access_log_plugin

CXX := g++
LDFLAGS := -lfmt -lboost_program_options -lboost_filesystem
LDFLAGS += -ltus -L ../libtus -Wl,-rpath,'$$ORIGIN/../lib:$$ORIGIN/../libtus'
LDFLAGS += $(shell pkgconf -libs spdlog)
LDFLAGS += -rdynamic -ldl
PAGE_SIZE := $(shell getconf PAGE_SIZE)
CXXFLAGS := -Wall -Wextra -std=c++23 -march=native -mtune=native \
	    -DPAGE_SIZE=$(PAGE_SIZE)

CXXFLAGS += $(shell pkgconf --cflags spdlog)
CXXFLAGS += -DSPDLOG_COMPILED_LIB

OBJS := $(patsubst %.cc, %.o, $(wildcard *.cc))
TARGET := tfw_logger

DEBUG ?= 0
ifeq ($(DEBUG), 0)
	CXXFLAGS += -O3 -DNDEBUG -s
else
	CXXFLAGS += -DDEBUG=1 -O0 -ggdb3
endif

all:
	@for dir in $(SUBDIRS); do	\
		$(MAKE) -C $$dir;	\
	done
	$(MAKE) $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	@for dir in $(SUBDIRS); do	\
		$(MAKE) -C $$dir clean;	\
	done
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean $(SUBDIRS)
