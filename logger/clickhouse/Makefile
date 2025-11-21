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

# TARGET_DIR and CXXFLAGS can be overridden from outside.
#
# TARGET_DIR is used to place all generated object files and the final static
# library into an isolated build directory. This prevents build races when the
# same source tree is compiled by multiple different compilers or toolchains
# concurrently.
#
# Using an external TARGET_DIR also ensures that the resulting static
# ClickHouse wrapper library can be safely consumed by plugins built with
# different compilers, build modes, or ABI configurations, without mixing their
# intermediate files or polluting the source directory.
TARGET_DIR ?= $(abspath .)

CLICKHOUSE_DIR := $(CURDIR)/clickhouse-cpp
CLICKHOUSE_BUILD_DIR := $(TARGET_DIR)/clickhouse-build
CLICKHOUSE_REPO_URL := https://github.com/ClickHouse/clickhouse-cpp.git
CLICKHOUSE_LIB := $(CLICKHOUSE_BUILD_DIR)/clickhouse/libclickhouse-cpp-lib.a

LDFLAGS := $(shell pkgconf --libs spdlog)
LDFLAGS += -rdynamic -ldl

PAGE_SIZE := $(shell getconf PAGE_SIZE)
CXXFLAGS ?= -Wall -Wextra -std=c++23 -march=native -mtune=native \
	    -DPAGE_SIZE=$(PAGE_SIZE) -fPIC
CXXFLAGS += $(shell pkgconf -cflags spdlog)
CXXFLAGS += -I $(CLICKHOUSE_DIR)
CXXFLAGS += -I $(CLICKHOUSE_DIR)/contrib/absl

OBJS := $(patsubst %.cc,$(TARGET_DIR)/%.o,$(wildcard *.cc))
TARGET := $(TARGET_DIR)/tfw_clickhouse.a

DEBUG ?= 0
ifeq ($(DEBUG),0)
	CXXFLAGS += -O3 -DNDEBUG -s
else
	CXXFLAGS += -DDEBUG=1 -O0 -ggdb3
endif

all:
	$(MAKE) clickhouse
	$(MAKE) $(TARGET)

$(TARGET): $(OBJS) $(CLICKHOUSE_LIB)
	ar rcs $@ $^

$(TARGET_DIR)/%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean: clickhouse_clean
	rm -f $(OBJS) $(TARGET)

#We need DCMAKE_POSITION_INDEPENDENT_CODE=ON to build a shared library wrapper with -fPIC
clickhouse: $(CLICKHOUSE_DIR)
	mkdir -p $(CLICKHOUSE_BUILD_DIR)
	cd $(CLICKHOUSE_BUILD_DIR) && cmake $(CLICKHOUSE_DIR) -DCMAKE_POSITION_INDEPENDENT_CODE=ON && $(MAKE) -j$(shell nproc)

$(CLICKHOUSE_DIR):
	git clone $(CLICKHOUSE_REPO_URL) $(CLICKHOUSE_DIR)

clickhouse_clean:
	$(RM) -rf $(CLICKHOUSE_DIR)
	$(RM) -rf $(CLICKHOUSE_BUILD_DIR)

.PHONY: all clean clickhouse clickhouse_clean
