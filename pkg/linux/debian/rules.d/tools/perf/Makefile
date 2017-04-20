include $(top_rulesdir)/Makefile.inc

ifeq ($(filter nopython,$(DEB_BUILD_PROFILES)),)

DEB_HOST_ARCH_CPU := $(shell dpkg-architecture -qDEB_HOST_ARCH_CPU)

ifeq ($(DEB_HOST_ARCH_CPU),alpha)
  KERNEL_ARCH_PERF = alpha
else ifeq ($(DEB_HOST_ARCH_CPU),arm)
  KERNEL_ARCH_PERF = arm
else ifeq ($(DEB_HOST_ARCH_CPU),arm64)
  KERNEL_ARCH_PERF = arm64
else ifneq ($(filter mips%,$(DEB_HOST_ARCH_CPU)),)
  KERNEL_ARCH_PERF = mips
else ifeq ($(DEB_HOST_ARCH_CPU),hppa)
  KERNEL_ARCH_PERF = parisc
else ifneq ($(filter powerpc% ppc%,$(DEB_HOST_ARCH_CPU)),)
  KERNEL_ARCH_PERF = powerpc
else ifneq ($(filter s390%,$(DEB_HOST_ARCH_CPU)),)
  KERNEL_ARCH_PERF = s390
else ifeq ($(DEB_HOST_ARCH_CPU),sh4)
  KERNEL_ARCH_PERF = sh
else ifneq ($(filter sparc%,$(DEB_HOST_ARCH_CPU)),)
  KERNEL_ARCH_PERF = sparc
else ifneq ($(filter amd64 i386,$(DEB_HOST_ARCH_CPU)),)
  # But x32 isn't supported yet
  ifneq ($(shell dpkg-architecture -qDEB_HOST_ARCH),x32)
    KERNEL_ARCH_PERF = x86
  endif
endif

MAKE_PERF := $(MAKE) O=$(CURDIR) prefix=/usr V=1 ARCH=$(KERNEL_ARCH_PERF) EXTRA_WARNINGS=-Wno-error EXTRA_CFLAGS='$(CFLAGS) $(CPPFLAGS)' LDFLAGS='$(LDFLAGS)'

# Disable Gtk UI until it's more usable
MAKE_PERF += NO_GTK2=1

# Include version in all directory names
MAKE_PERF += perfexecdir=lib/perf_$(VERSION)-core plugindir=/usr/lib/traceevent_$(VERSION)/plugins STRACE_GROUPS_DIR=share/perf_$(VERSION)-core/strace/groups tipdir=share/doc/linux-perf-$(VERSION)

# perf can link against libbfd if available, but the result is
# undistributable as they are licenced under GPL v2 and v3+
# respectively.  Override detection of libbfd and insist that
# cplus_demangle() can be found in libiberty (LGPL v2.1+).
MAKE_PERF += feature-libbfd=0 HAVE_CPLUS_DEMANGLE_SUPPORT=1

# perf can link against libcrypto if available, but the result is
# undistributable as GPL v2 and OpenSSL are not compatible without
# an explicit exception.  Override detection of libcrypto.
MAKE_PERF += NO_LIBCRYPTO=1

all:
ifdef KERNEL_ARCH_PERF
# perf changes some default directories depending on whether DESTDIR is
# set.  We must define it even when building to avoid a rebuild when we
# run 'make install'.
	+$(MAKE_PERF) -C $(top_srcdir)/tools/perf -f Makefile.perf all VERSION=$(VERSION) DESTDIR=dummy
ifeq (,$(filter nodoc,$(DEB_BUILD_PROFILES)))
	+$(MAKE_PERF) -C $(top_srcdir)/tools/perf/Documentation man VERSION=$(VERSION)
endif
# Check that perf didn't get linked against libbfd or libcrypto
	type ldd
	! ldd $(CURDIR)/perf | grep -E '\blib(bfd|crypto)'
# Check that it includes cplus_demangle from libiberty
	grep cplus_demangle $(CURDIR)/perf
endif

install:
ifdef KERNEL_ARCH_PERF
	+$(MAKE_PERF) -C $(top_srcdir)/tools/perf -f Makefile.perf install VERSION=$(VERSION)
# Don't install a 'trace' alias yet:
# - We need a wrapper for it anyway, so there's little point adding a
#   versioned link
# - It doesn't work out-of-the-box as non-root (it depends on debugfs),
#   so it's less widely useful than strace
# - 'perf trace' doesn't take much more typing
	rm -f $(DESTDIR)/usr/bin/trace_$(VERSION)
endif
	mkdir -p $(DESTDIR)/usr/share/bash-completion/
	mv $(DESTDIR)/etc/bash_completion.d \
		$(DESTDIR)/usr/share/bash-completion/completions
	rmdir --ignore-fail-on-non-empty $(DESTDIR)/etc
# Check for unversioned files that are likely to result in file conflicts
	! find $(DESTDIR) -name '*perf*' \! -path '*[_-]$(VERSION)*' | grep .

endif # !nopython
