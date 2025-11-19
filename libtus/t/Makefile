#		Tempesta FW Unit Tests
#
# Copyright (C) 2025 Tempesta Technologies, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.

ifeq ($(shell which pkgconf), )
$(error "pkgconf not found in $(PATH)")
endif

CXX := g++
CXXFLAGS := -std=c++23 -Wall -Wextra -g -O0
CXXFLAGS += -I/usr/include
CXXFLAGS += $(shell pkgconf --cflags spdlog)
CXXFLAGS += -I.. -I../.. -I../../libtus

LDFLAGS := -lgtest -lgtest_main -L/usr/lib/x86_64-linux-gnu
LDFLAGS += $(shell pkgconf --libs spdlog)
LDFLAGS += -lboost_filesystem -lboost_system
LDFLAGS += -pthread

PARENT_SRCS := ../pidfile.cc
PARENT_OBJS := $(PARENT_SRCS:.cc=.o)

TEST_SRCS := test_pidfile.cc
TEST_OBJS := $(TEST_SRCS:.cc=.o)

TARGET := tfw_libtus_tests

all: $(TARGET)

$(TARGET): $(TEST_OBJS) $(PARENT_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

../%.o: ../%.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TEST_OBJS) $(PARENT_OBJS) $(TARGET)

install_deps:
	@echo "Installing test dependencies..."
	sudo apt-get update
	sudo apt-get install -y libgtest-dev pkg-config
	sudo apt-get install -y libspdlog-dev libboost-filesystem-dev

.PHONY: all test clean install_deps help
