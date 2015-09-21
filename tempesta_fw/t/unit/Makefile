#		Tempesta FW
#
# Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

tfw_root = $(src)/../../../

EXTRA_CFLAGS += -Werror -O0 -g3 -DDEBUG -I$(tfw_root)/tempesta_fw \
		-I$(tfw_root)/tempesta_db/core -I$(tfw_root)/sync_socket
ifdef DEBUG
	EXTRA_CFLAGS += -DDBG_LVL=$(DEBUG)
else
	EXTRA_CFLAGS += -DDBG_LVL=0
endif

obj-m += tfw_test.o
tfw_test-objs = \
	main.o \
	test.o \
	helpers.o \
	test_addr.o \
	test_cfg.o \
	test_hash.o \
	test_http_match.o \
	tfw_str_helper.o \
	test_tfw_str.o \
	test_http_parser.o \
	sched_helper.o \
	test_sched_rr.o \
	test_sched_hash.o \
	test_sched_http.o \
	test_http_sticky.o \
	kallsyms_helper.o
