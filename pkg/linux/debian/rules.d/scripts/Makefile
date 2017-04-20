PROGS = \
	conmakehash \
	extract-cert \
	kallsyms \
	pnmtologo \
	recordmcount \
	sign-file \
	unifdef

DATA = \
	Kbuild.include \
	Makefile.* \
	mkversion \
	module-common.lds

SCRIPTS =  \
	checkincludes.pl \
	checkstack.pl \
	checkversion.pl \
	depmod.sh \
	gcc-*.sh \
	gen_initramfs_list.sh \
	headers_install.sh \
	kernel-doc \
	Lindent \
	makelst \
	mksysmap \
	mkuboot.sh \
	namespace.pl \
	patch-kernel \
	recordmcount.pl \
	setlocalversion \
	ver_linux

SUBDIRS = \
	basic \
	genksyms \
	kconfig \
	mod

include $(top_rulesdir)/Makefile.inc

CPPFLAGS += -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
extract-cert sign-file: LDLIBS += -lcrypto
