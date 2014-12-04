#		Tempesta FW
#
# Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

EXTRA_CFLAGS += -Werror -I$(src)/../sync_socket -I$(src)/../tempesta_db

ifneq ($(NDEBUG), 1)
EXTRA_CFLAGS += -DDEBUG -O0 -g3
endif

obj-m	= tempesta_fw.o
tempesta_fw-objs = addr.o cache.o classifier.o client.o connection.o debugfs.o \
		   cfg_node.o cfg_mod.o cfg_spec.o cfg_parser.o cfg_userspace_if.o \
		   filter.o gfsm.o hash.o http.o http_match.o http_msg.o \
		   http_parser.o main.o pool.o sched.o server.o session.o \
		   sock_backend.o sock_frontend.o stress.o str.o

obj-m	+= log/ classifier/ stress/ sched/ filter/ t/
