srcdir := $(top_srcdir)/tools/usb/usbip

# Make sure we don't override top_srcdir in the sub-make.  'unexport
# top_srcdir' is *not* sufficient; nor is adding 'MAKEFLAGS=' to the
# sub-make command line.
unexport MAKEFLAGS

all: export CFLAGS := $(shell dpkg-buildflags --get CFLAGS)
all: export CPPFLAGS := $(shell dpkg-buildflags --get CFLAGS) \
	-isystem $(top_srcdir)/debian/build/build-tools/include
all: export LDFLAGS := $(shell dpkg-buildflags --get LDFLAGS)
all:
	rsync -a $(srcdir)/ .
	./autogen.sh
	./configure \
		--prefix=/usr \
		--with-tcp-wrappers \
		--with-usbids-dir=/usr/share/misc \
		--disable-shared \
		--host=$(shell dpkg-architecture -qDEB_HOST_GNU_TYPE)
	$(MAKE)

install:
	$(MAKE) install
ifneq (,$(filter nodoc,$(DEB_BUILD_PROFILES)))
	rm -rf $(DESTDIR)/usr/share/man
endif

clean:
	rm -rf *
