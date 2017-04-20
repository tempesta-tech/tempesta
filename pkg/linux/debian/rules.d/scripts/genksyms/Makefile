PROGS = genksyms

include $(top_rulesdir)/Makefile.inc

genksyms: genksyms.o parse.tab.o lex.lex.o

lex.lex.o: keywords.hash.c parse.tab.h

%.c: %.c_shipped
	ln -s $< $@

%.h: %.h_shipped
	ln -s $< $@
