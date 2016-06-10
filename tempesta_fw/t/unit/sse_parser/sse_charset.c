#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "sse_parser.h"

void print_sse(Vector sm) {
    unsigned char * data = (unsigned char*)&sm;
    printf("|  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 "
           "|  8 |  9 | 10 | 11 | 12 | 13 | 14 | 15 |\n");

    printf("+----+----+----+----+----+----+----+----"
           "+----+----+----+----+----+----+----+----+\n");
    for(int i = 0; i < 16; ++i)
    printf(", 0x%02x", data[i]);
    printf("|\n");
    for(int i = 0; i < 16; ++i)
    printf("|  %c ", isprint(data[i]) ? data[i] : '.');
    printf("|\n");
}

int testSymbolMap(const char * set) {
    int fail = 0;
    SymbolMap sm  = createSymbolMapFromCharset(set);
    //dump tokenset structure:
    print_sse(sm);
    for(int i = 1; i < 256; ++i) {
        Vector v = _mm_set1_epi8(i);
        int    expect = (strchr(set, i) ? 16 : 0);
        int    got = matchSymbolsCount(sm, v);
        if (got != expect) {
            printf("FAIL: %02x (expect %d got %d)\n", i, expect, got);
            ++fail;
        }
    }
    return fail;
}

int main()
{
    int i;
    sse_init_constants();

    int fail = 0;

    const char * ascii_low_cs = "HTTP/1.0\r\n";
    fail += testSymbolMap(ascii_low_cs);

    const char * uri_cs = ":/";
    fail += testSymbolMap(uri_cs);

    const char * r_cs = "r";
    fail += testSymbolMap(r_cs);

    printf("N = %d\n", matchSymbolsCount(createSymbolMapFromCharset(uri_cs), strToVec("/folder/file")));
    print_sse(matchSymbolsMask(createSymbolMapFromCharset(uri_cs), strToVec("/folder/file")));

    if (fail) return 1;
    return 0;
}

