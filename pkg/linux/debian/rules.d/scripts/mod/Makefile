PROGS = \
	modpost \
	modpost.real-lsb-32 \
	modpost.real-lsb-64 \
	modpost.real-msb-32 \
	modpost.real-msb-64

include $(top_rulesdir)/Makefile.inc

wrapperdir = $(top_rulesdir)/$(OUTDIR)

modpost.real-%:
	$(MAKE) -f $(wrapperdir)/Makefile.real TYPE=$* SOURCEDIR=$(top_srcdir)/scripts/mod

%: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

modpost-opts.h: $(top_srcdir)/scripts/mod/modpost.c
	python $(wrapperdir)/gendef.py $< > $@

modpost.o: modpost.c modpost-opts.h
	$(CC) $(CFLAGS) -I $(CURDIR) -c -o $@ $<
