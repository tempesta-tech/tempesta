options = -Wall -Wextra -Wstrict-overflow=5 -fno-strict-overflow -O3

hfiles = hfcode.h

all: hfstate.h

hfstate.h: hgen
	./hgen > hfstate.h

hgen: $(hfiles)
hgen: hgen.c
	gcc $(options) -o $@ $<
