#		Tempesta FW
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2023 Tempesta Technologies, INC.
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
export TFW_CFLAGS

EXTRA_CFLAGS += $(TFW_CFLAGS) -I$(src)/.. -I$(src)/../../
EXTRA_CFLAGS += $(TTLS_CFLAGS)

obj-m += unit/

obj-m += tfw_fuzzer.o
tfw_fuzzer-objs = \
	fuzzer.o
