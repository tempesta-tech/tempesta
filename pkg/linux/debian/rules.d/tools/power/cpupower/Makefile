include $(top_rulesdir)/Makefile.inc

MAKE_CPUPOWER := $(shell dpkg-buildflags --export=cmdline) $(MAKE) O=$(CURDIR) CPUFREQ_BENCH=false V=true mandir=/usr/share/man

MAKE_CPUPOWER += DEBUG=$(if $(findstring nostrip,$(DEB_BUILD_OPTIONS)),true,)

MAKE_CPUPOWER += CROSS='$(CROSS_COMPILE)'

MAKE_CPUPOWER += PACKAGE_BUGREPORT='Debian\ \(reportbug\ linux-cpupower\)'

all:
	$(MAKE_CPUPOWER) -C $(top_srcdir)/tools/power/cpupower

install:
	$(MAKE_CPUPOWER) -C $(top_srcdir)/tools/power/cpupower install DESTDIR=$(DESTDIR)
ifneq (,$(filter nodoc,$(DEB_BUILD_PROFILES)))
	rm -rf $(DESTDIR)/usr/share/man
endif

clean:
	$(MAKE_CPUPOWER) -C $(top_srcdir)/tools/power/cpupower clean
