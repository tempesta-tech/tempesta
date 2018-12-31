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

TTLS_CFLAGS += -I$(src)/../tls -I$(src)/../tls/dummy_headers
export TTLS_CFLAGS

EXTRA_CFLAGS += $(TFW_CFLAGS) $(TTLS_CFLAGS)
EXTRA_CFLAGS += -I$(src)/../tempesta_db/core -I$(src)/../

obj-m	= tempesta_fw.o t/

tfw-srcs = $(wildcard $(obj)/*.c)
tfw-objs = $(patsubst %.c, %.o, $(tfw-srcs))

tempesta_fw-objs = $(subst $(src)/,,$(tfw-objs))
