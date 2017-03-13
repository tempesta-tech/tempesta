options = -Wall -Wextra -Wstrict-overflow=5 -Wno-unused-parameter \
	  -O3 -fno-strict-overflow -fstrict-aliasing -fno-math-errno \
	  -ftree-loop-im -fivopts -fira-hoist-pressure \
	  -fbranch-target-load-optimize

hfiles = ../common.h ../netconv.h ../rotate.h
hfiles += ../buffers.h ../errors.h ../hfstate.h ../huffman.h

shared = ../buffers.c ../huffman.c pool_emulator.c

all: huffman_test fragments_test hpack_test

hftestdata.h: hgendata
	./hgendata > hftestdata.h

hgendata: ../common.h ../huffman.h ../hgen/hfcode.h
hgendata: hgentest.c
	gcc $(options) -o $@ $< $(shared)

huffman_test: $(hfiles) hftestdata.h
huffman_test: huffman_test.c $(shared) ngx_http_v2_huff_decode.c
	gcc $(options) -o $@ $< $(shared) ngx_http_v2_huff_decode.c

fragments_test: $(hfiles) hftestdata.h
fragments_test: fragments_test.c $(shared)
	gcc $(options) -o $@ $< $(shared)

hpack_test: $(hfiles) hptestdata.h
hpack_test: hpack_test.c $(shared) ../hpack_decoder.c ../hindex.c
	gcc $(options) -o $@ $< $(shared) ../hpack_decoder.c ../hindex.c

clean:
	rm -rf ./huffman_test
	rm -rf ./fragments_test
	rm -rf ./hpack_test
	rm -rf ./huffman_test.exe
	rm -rf ./fragments_test.exe
	rm -rf ./hpack_test.exe
