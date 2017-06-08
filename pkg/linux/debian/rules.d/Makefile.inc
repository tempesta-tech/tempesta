# Normalise OUTDIR to avoid triggering rebuilds
override OUTDIR := $(patsubst ./%,%,$(OUTDIR))

VPATH = $(top_rulesdir)/$(OUTDIR) $(top_srcdir)/$(OUTDIR)

SHELL = /bin/sh -e

CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
CFLAGS := $(shell dpkg-buildflags --get CFLAGS) -Wall
CPPFLAGS := $(shell dpkg-buildflags --get CPPFLAGS) \
	-I$(top_srcdir)/$(OUTDIR) \
	-I$(top_srcdir)/debian/build/build-tools/$(OUTDIR) \
	-isystem $(top_srcdir)/debian/build/build-tools/include
CXXFLAGS := $(shell dpkg-buildflags --get CXXFLAGS) -Wall
LDFLAGS := $(shell dpkg-buildflags --get LDFLAGS)

installdir ?= $(prefix)/$(OUTDIR)

all: all-local all-recursive
clean: clean-recursive
install: install-local install-recursive

%-recursive:
	+@list='$(SUBDIRS)'; \
	for subdir in $$list; do \
	  echo "Making $* in $$subdir"; \
	  mkdir -p $$subdir; \
	  $(MAKE) -C $$subdir -f $(top_rulesdir)/$(OUTDIR)/$$subdir/Makefile OUTDIR=$(OUTDIR)/$$subdir $*; \
	done

all-local: $(PROGS)

install-local: install-local-progs install-local-scripts install-local-data

install-local-progs: $(PROGS)
	@for p in $^; do \
	  echo " install -m755 '$$p' '$(DESTDIR)/$(installdir)'"; \
	  install -D -m755 "$$p" "$(DESTDIR)/$(installdir)/$$(basename $$p)"; \
	done

SCRIPTS_REAL = $(wildcard $(addprefix $(top_srcdir)/$(OUTDIR)/,$(SCRIPTS)))

install-local-scripts: $(SCRIPTS_REAL)
	@for p in $^; do \
	  echo " install -m755 '$$p' '$(DESTDIR)/$(installdir)'"; \
	  install -D -m755 "$$p" "$(DESTDIR)/$(installdir)/$$(basename $$p)"; \
	done

DATA_REAL = $(wildcard $(addprefix $(top_srcdir)/$(OUTDIR)/,$(DATA)))

install-local-data: $(DATA_REAL)
	@for p in $^; do \
	  echo " install -m644 '$$p' '$(DESTDIR)/$(installdir)'"; \
	  install -D -m644 "$$p" "$(DESTDIR)/$(installdir)/$$(basename $$p)"; \
	done

