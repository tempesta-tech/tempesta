#		Tempesta DB
#
# Copyright (C) 2018-2019 Tempesta Technologies, Inc.
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

EXTRA_CFLAGS += $(TFW_CFLAGS)

obj-m	= tempesta_lib.o

GCOV_PROFILE := $(TFW_GCOV)

tempesta_lib-objs = hash.o main.o
ifdef AVX2
	tempesta_lib-objs += str_simd.o
endif
