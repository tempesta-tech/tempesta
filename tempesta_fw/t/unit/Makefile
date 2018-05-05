#		Tempesta FW
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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

EXTRA_CFLAGS += $(TFW_CFLAGS) -I$(tfw_root)/tempesta_fw -I$(tfw_root)/tempesta_fw/t \
		-I$(tfw_root) -I$(tfw_root)/tempesta_db/core
EXTRA_CFLAGS += $(TTLS_CFLAGS)

obj-m += tfw_test.o
tfw_test-objs = \
	main.o \
	test.o \
	helpers.o \
	test_addr.o \
	test_cfg.o \
	test_hash.o \
	test_http_match.o \
	test_http_msg.o \
	tfw_str_helper.o \
	test_tfw_str.o \
	test_mem_fast.o \
	test_http_parser.o \
	sched_helper.o \
	test_sched_ratio.o \
	test_sched_hash.o \
	test_sched_http.o \
	test_http_sticky.o \
	test_wq.o \
	kallsyms_helper.o \
	test_tls.o
