#		Tempesta FW
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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

TFW_CFLAGS = $(DEFINES) -Werror -mpreferred-stack-boundary=4
ifdef DEBUG
	TFW_CFLAGS += -DDEBUG=$(DEBUG)
endif

# Use `$ TFW_GCOV=y make` to compile Tempesta modules with GCOV.
# The kernel should be built with:
#	CONFIG_GCOV_KERNEL=y
#	CONFIG_GCOV_PROFILE_ALL=y
#	CONFIG_GCOV_FORMAT_AUTODETECT=y
TFW_GCOV ?= n

# Specify the defines below if you need to build Tempesta FW with
# debugging of the subsystem, e.g. for Tempesta TLS:
#
#	$ DEBUG=3 DBG_SS=1 DBG_TLS=1 make clean all
#
DBG_CFG ?= 0
DBG_HTTP_PARSER ?= 0
DBG_SS ?= 0
DBG_TLS ?= 0
DBG_APM ?= 0
DBG_HTTP_FRAME ?= 0
DBG_HTTP_STREAM ?= 0
DBG_HPACK ?= 0
TFW_CFLAGS += -DDBG_CFG=$(DBG_CFG) -DDBG_HTTP_PARSER=$(DBG_HTTP_PARSER)
TFW_CFLAGS += -DDBG_SS=$(DBG_SS) -DDBG_TLS=$(DBG_TLS) -DDBG_APM=$(DBG_APM)
TFW_CFLAGS += -DDBG_HTTP_FRAME=$(DBG_HTTP_FRAME)
TFW_CFLAGS += -DDBG_HTTP_STREAM=$(DBG_HTTP_STREAM)
TFW_CFLAGS += -DDBG_HPACK=$(DBG_HPACK)

PROC = $(shell cat /proc/cpuinfo)
ARCH = $(shell uname -m)
ifneq ($(ARCH), x86_64)
	ERROR="Architecture $(ARCH) isn't supported"
endif
ifeq (, $(findstring sse4_2, $(PROC)))
	ERROR = "SSE 4.2 support is required"
endif
ifeq (, $(findstring pse, $(PROC)))
	ERROR = "1MB huge pages support is required"
endif
ifneq (, $(findstring avx2, $(PROC)))
	AVX2 = "y"
	TFW_CFLAGS += -DAVX2=1
endif
ifneq (, $(findstring bmi2, $(PROC)))
	BMI2 = "y"
	TFW_CFLAGS += -DBMI2=1
else
	ERROR = "BMI2 CPU extension is required for Tempesta TLS"
endif
ifneq (, $(findstring adx, $(PROC)))
	ADX = "y"
	TFW_CFLAGS += -DADX=1
else
	ERROR = "ADX CPU extension is required for Tempesta TLS"
endif

TFW_CFLAGS += -mmmx -msse4.2

KERNEL = /lib/modules/$(shell uname -r)/build

export KERNEL TFW_CFLAGS AVX2 BMI2 ADX TFW_GCOV

obj-m	+= lib/ tempesta_db/core/ tempesta_fw/ tls/

all: build

build:
ifdef ERROR
	$(error $(ERROR))
endif
ifndef AVX2
	$(warning !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!)
	$(warning WARNING: YOUR PLATFORM IS TOO OLD AND IS NOT UNSUPPORTED)
	$(warning WARNING: THIS AFFECT PERFORMANCE AND MIGHT AFFECT SECURITY)
	$(warning WARNING: PLEASE DO NOT USE THE BUILD IN PRODUCTION)
	$(warning !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!)
endif
	$(MAKE) -C tls/t generate_tables
	$(MAKE) -C tempesta_db
	$(MAKE) -C $(KERNEL) M=$(shell pwd) modules

test: build
	./scripts/tempesta.sh --stop
	./scripts/tempesta.sh --load
	./tempesta_fw/t/unit/run_all_tests.sh
	./scripts/tempesta.sh --unload

clean:
	$(MAKE) -C $(KERNEL) M=$(shell pwd) clean
	$(MAKE) -C tempesta_db clean
	$(MAKE) -C tls clean
	find . \( -name \*~ -o -name \*.orig -o -name \*.symvers \) \
		-exec rm -f {} \;
