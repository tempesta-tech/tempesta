#		Tempesta FW
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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

EXTRA_CFLAGS += -Werror -I$(src)/..
ifdef DEBUG
	EXTRA_CFLAGS += -DDEBUG=$(DEBUG)
else
	EXTRA_CFLAGS += -DDEBUG=0
endif

obj-m += sync_sockets/ unit/

obj-m += tfw_fuzzer.o
tfw_fuzzer-objs = \
	fuzzer.o

obj-m += tfw_bomber.o
tfw_bomber-objs = \
	bomber.o
