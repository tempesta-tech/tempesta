ifneq ($(OS),Windows_NT)
LIBEXT = .a
SOEXT  = .so
EXEEXT =
else
LIBEXT = .lib
SOEXT  = .dll
EXEEXT = .exe
endif

options = -Wall -Wextra -Wstrict-overflow=5 -Wno-unused-parameter \
	  -O3 -fno-strict-overflow -fstrict-aliasing -fno-math-errno \
	  -ftree-loop-im -fivopts -fira-hoist-pressure \
	  -fbranch-target-load-optimize

hfiles = ../common.h ../bits.h ../netconv.h ../rotate.h
hfiles += ../subs.h ../hash.h
hfiles += ../buffers.h ../errors.h ../hfstate.h ../huffman.h

shared = ../subs.c ../hash.c ../buffers.c ../huffman.c pool_emulator.c

all: huffman_test fragments_test hpack_test

hftestdata.h: hgendata
	./hgendata > $@

hgendata: ../hgen/hfcode.h ../huffman.h
hgendata: hgentest.c
	gcc $(options) -o $@ $< $(shared)

huffman_test: $(hfiles) hftestdata.h
huffman_test: huffman_test.c $(shared) ngx_http_v2_huff_decode.c
	gcc $(options) -o $@ $< $(shared) ngx_http_v2_huff_decode.c

fragments_test: $(hfiles) hftestdata.h
fragments_test: fragments_test.c $(shared)
	gcc $(options) -o $@ $< $(shared)

hpack_test: $(hfiles) hptestdata.h ../hstatic.h
hpack_test: hpack_test.c $(shared) ../hpack_decoder.c ../hindex.c
	gcc $(options) -o $@ $< $(shared) ../hpack_decoder.c ../hindex.c

clean:
	$(RM) ./huffman_test$(EXEEXT)
	$(RM) ./fragments_test$(EXEEXT)
	$(RM) ./hpack_test$(EXEEXT)
