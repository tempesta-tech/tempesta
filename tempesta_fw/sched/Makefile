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

EXTRA_CFLAGS += -Werror  -I$(src)/../ -I$(src)/../../tempesta_db/core \
		-I$(src)/../../sync_socket

ifneq ($(NDEBUG), 1)
EXTRA_CFLAGS += -DDEBUG -O0 -g3
endif

obj-m = tfw_sched_hash.o tfw_sched_http.o tfw_sched_rr.o
