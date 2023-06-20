#		Tempesta FW
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2023 Tempesta Technologies, Inc.
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

tfw_root = $(src)/../../../

EXTRA_CFLAGS += $(TFW_CFLAGS) -I$(tfw_root)/fw -I$(tfw_root) \
		-I$(tfw_root)/fw/t -I$(tfw_root)/db/core
EXTRA_CFLAGS += $(TTLS_CFLAGS)
EXTRA_AFLAGS += -I$(tfw_root)

obj-m += tfw_test.o

# Some of source files in this directory are symlinks to sources in /fw with
# the same name. The build system doesn't care, and treats symlinks as regular
# files. Incidentally that's what's needed, as this cause build scripts to write
# object files right here in this directory, which prevents accidental
# concurrent overwrites when compiling in parallel. The price is building some
# of the code twice.

t-srcs = $(wildcard $(obj)/*.c)
t-objs = $(patsubst %.c, %.o, $(t-srcs))
ifdef AVX2
	t-objs += str_avx2.o
endif

tfw_test-objs = $(subst $(src)/,,$(t-objs))
