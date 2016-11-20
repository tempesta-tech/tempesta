#		Tempesta FW
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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

TTLS_CFLAGS += -I$(src)/../tls -I$(src)/../tls/dummy_headers -include ttls.h
export TTLS_CFLAGS

EXTRA_CFLAGS += $(TFW_CFLAGS) $(TTLS_CFLAGS) -I$(src)/../tempesta_db/core

obj-m	= tempesta_fw.o 

tempesta_fw-objs = \
	addr.o \
	apm.o \
	cache.o \
	cfg.o \
	classifier.o \
	client.o \
	connection.o \
	filter.o \
	gfsm.o \
	hash.o \
	http.o \
	http_match.o \
	http_msg.o \
	http_parser.o \
	http_sess.o \
	main.o \
	pool.o \
	procfs.o \
	sched.o \
	server.o \
	sock.o \
	sock_clnt.o \
	sock_srv.o \
	ss_skb.o \
	stress.o \
	str.o \
	str_simd.o \
	tls.o \
	vhost.o \
	work_queue.o

obj-m	+= log/ classifier/ stress/ sched/ t/
