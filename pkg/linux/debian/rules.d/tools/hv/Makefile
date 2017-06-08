ifeq ($(filter i386 amd64 x32,$(DEB_HOST_ARCH)),)

# Build nothing
include $(top_rulesdir)/Makefile.inc

else

PROGS = \
	hv_fcopy_daemon \
	hv_kvp_daemon \
	hv_vss_daemon

installdir = /usr/sbin

include $(top_rulesdir)/Makefile.inc

# Handle check-hyperv separately since it's installed in a different directory
all-local: check-hyperv
install-local:
	install -D -m755 check-hyperv '$(DESTDIR)/lib/hyperv-daemons/check-hyperv'

endif
