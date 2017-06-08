DATA = \
	Kbuild \
	Makefile \

SUBDIRS = \
	scripts \
	tools

include $(top_rulesdir)/Makefile.inc

# Build userland headers first
unexport VERSION
all-local:
	mkdir -p headers-tools
	$(MAKE) -C $(top_srcdir) ARCH=$(KERNEL_ARCH) O=$(CURDIR)/headers-tools \
		INSTALL_HDR_PATH=$(CURDIR) headers_install
all-recursive: all-local
