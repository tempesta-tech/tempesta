#		Tempesta FW
#
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

EXTRA_CFLAGS += -Werror -I$(src) -I$(src)/dummy_headers -include ttls.h
ifdef DEBUG
	EXTRA_CFLAGS += -DDEBUG=$(DEBUG)
endif
EXTRA_CFLAGS += -Wframe-larger-than=4096

obj-m = tempesta_tls.o

ttls-srcs = $(wildcard $(src)/*.c)
ttls-objs = $(patsubst %.c, %.o, $(ttls-srcs))

# exclude some original files (see tempesta_fw/ for re-implementation)
ttls-objs := $(filter-out	\
	$(src)/ssl_tls.o	\
	$(src)/ssl_srv.o	\
	, $(ttls-objs))

tempesta_tls-objs = $(subst $(src)/,,$(ttls-objs))
