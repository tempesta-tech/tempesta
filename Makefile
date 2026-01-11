#		Tempesta FW
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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

# if intcmp is supported use it
ifeq ($(intcmp 1,0,,,y),y)
test-gt = $(intcmp $(strip $1)0, $(strip $2)0,,,y)
else
test-gt = $(shell test $(strip $1)0 -gt $(strip $2)0 && echo y)
endif

TFW_CFLAGS = $(DEFINES) -Werror
ifdef DEBUG
	ifeq ($(call test-gt, 1, $(DEBUG)), y)
		ERROR = "DEBUG must be greater than 0"
	endif
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
#	$ DEBUG=1 DBG_SS=2 DBG_TLS=3 make clean all
#
# The most debug-output subsystems have their own DBG_* option, but the
# rest of code prints debug messages solely on DEBUG variable.
# DEBUG can be undefined to smoothly compile with 3-party code using the
# same variable.
#
# In the example above TLS code is built with the maximum verbosity,
# sockets code with verbosity 2, and the rest of the code, non having
# designated debugging options, with the smalles debugging verbosity.
#
# You also can just use
#
# 	$ DBG_TLS=3 make
#
# to build the TLS only subsystem with the maximum debug level.
#
# While some C-files having their own debugging options, e.g. sock.c and DBG_SS
# correspondingly, undefine the DEBUG symbol, unit tests may include several
# such C-files, so DEBUG will be undefined. If you work with such a test, then
# store the DEBUG value before the C-file inclusion and restore the value after
# the inclusion.
#
DBG_CFG ?= 0
DBG_HTTP_PARSER ?= 0
DBG_SS ?= 0
DBG_TLS ?= 0
DBG_WS ?= 0
DBG_APM ?= 0
DBG_GFSM ?= 0
DBG_HTTP ?= 0
DBG_HTTP2 ?= 0
DBG_HTTP_FRAME ?= 0
DBG_HTTP_SESS ?= 0
DBG_HTTP_STREAM ?= 0
DBG_HTTP_STREAM_SCHED ?= 0
DBG_HPACK ?= 0
DBG_CACHE ?= 0
DBG_SRV ?= 0
DBG_VHOST ?= 0
DBG_TEST ?= 0
DBG_ENABLE_2556_DEBUG ?= 0
TFW_CFLAGS += -DDBG_CFG=$(DBG_CFG) -DDBG_HTTP_PARSER=$(DBG_HTTP_PARSER)
TFW_CFLAGS += -DDBG_SS=$(DBG_SS) -DDBG_TLS=$(DBG_TLS) -DDBG_WS=$(DBG_WS)
TFW_CFLAGS += -DDBG_APM=$(DBG_APM) -DDBG_GFSM=$(DBG_GFSM) -DDBG_HTTP=$(DBG_HTTP)
TFW_CFLAGS += -DDBG_HTTP_FRAME=$(DBG_HTTP_FRAME)
TFW_CFLAGS += -DDBG_HTTP_SESS=$(DBG_HTTP_SESS)
TFW_CFLAGS += -DDBG_HTTP_STREAM=$(DBG_HTTP_STREAM)
TFW_CFLAGS += -DDBG_HTTP_STREAM_SCHED=$(DBG_HTTP_STREAM_SCHED)
TFW_CFLAGS += -DDBG_HPACK=$(DBG_HPACK) -DDBG_CACHE=$(DBG_CACHE)
TFW_CFLAGS += -DDBG_SRV=$(DBG_SRV) -DDBG_VHOST=$(DBG_VHOST) -DDBG_TEST=$(DBG_TEST)
TFW_CFLAGS += -DDBG_HTTP2=$(DBG_HTTP2)
TFW_CFLAGS += -DDBG_ENABLE_2556_DEBUG=$(DBG_ENABLE_2556_DEBUG)

# By default Tempesta TLS randomizes elliptic curve points using RDRAND
# instruction, which provides a high speed random numbers generator.
# However, if you do not trust your CPU vendor, then use CRYPTO_CONST_TIME
# to make all the computations constant time to prevent side channel attacks.
ifdef CRYPTO_CONST_TIME
	TFW_CFLAGS += -DCRYPTO_CONST_TIME
endif

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
else
ifdef M
	DIR = $(M)/
endif
	# Some cloud providers hide ADX support bit in vCPU, but it still present,
	# make run-rime check to discard false negative cases
	CHECK_CONF = $(DIR)scripts/check_conf.pl
	ADX_SUPPORTED := $(shell $(CHECK_CONF) 2>/dev/null | \
	grep ADX | if grep -q ': found'; then echo y; fi)
ifeq ($(ADX_SUPPORTED), y)
	ADX = "y"
else
	ERROR = "ADX CPU extension is required for Tempesta TLS"
endif
endif
ifeq ($(ADX),y)
	TFW_CFLAGS += -DADX=1
endif

KERNEL = /lib/modules/$(shell uname -r)/build

export KERNEL TFW_CFLAGS AVX2 BMI2 ADX TFW_GCOV

obj-m	+= lib/ db/core/ fw/ tls/

all: build

build:
ifdef ERROR
	$(error $(ERROR))
endif
ifndef AVX2
	$(warning !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!)
	$(warning WARNING: YOUR PLATFORM IS TOO OLD AND IS NOT SUPPORTED)
	$(warning WARNING: THIS AFFECT PERFORMANCE AND MIGHT AFFECT SECURITY)
	$(warning WARNING: PLEASE DO NOT USE THE BUILD IN PRODUCTION)
	$(warning !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!)
endif
	$(MAKE) -C tls/t generate_tables
	$(MAKE) -C db
	$(MAKE) -C utils
	$(MAKE) -C $(KERNEL) M=$(shell pwd) modules

test: build
	./scripts/tempesta.sh --stop
	./fw/t/unit/run_all_tests.sh

clean:
	$(MAKE) -C $(KERNEL) M=$(shell pwd) clean
	$(MAKE) -C db clean
	$(MAKE) -C tls clean
	$(MAKE) -C tls/t clean
	$(MAKE) -C utils clean
	find . \( -name \*~ -o -name \*.orig -o -name \*.symvers \) \
		-exec rm -f {} \;
