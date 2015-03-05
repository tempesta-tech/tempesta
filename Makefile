#		Tempesta FW
#
# Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

EXTRA_CFLAGS = $(DEFINES) -DDEBUG
ifdef NORMALIZATION
	EXTRA_FLAGS += -DTFW_HTTP_NORMALIZATION
endif

obj-m	+= sync_socket/ tempesta_db/core/ tempesta_fw/

KERNEL = /lib/modules/$(shell uname -r)/build

export KERNEL EXTRA_CFLAGS

all: build
	
build:
	make -C tempesta_db
	make -C $(KERNEL) M=$(PWD) modules

test: build
	./tempesta.sh load_modules
	./tempesta_fw/t/unit/run_all_tests.sh
	./tempesta.sh unload_modules

clean:
	make -C $(KERNEL) M=$(PWD) clean
	make -C tempesta_db clean
	find . \( -name \*~ -o -name \*.orig -o -name \*.symvers \) \
		-exec rm -f {} \;
