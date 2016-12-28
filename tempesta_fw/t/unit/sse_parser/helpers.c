#include "helpers.h"
#include "str.h"
#include <tmmintrin.h>
#include <ctype.h>

void __print_sse(const char * prefix, __m128i sm) {
    unsigned char * data = (unsigned char*)&sm;
    printf("%s\n", prefix);
    printf("|  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 "
           "|  8 |  9 | 10 | 11 | 12 | 13 | 14 | 15 |\n");

    printf("+----+----+----+----+----+----+----+----"
           "+----+----+----+----+----+----+----+----+\n");
    for(int i = 0; i < 16; ++i)
    printf("| %02x ", data[i]);
    printf("|\n");
    for(int i = 0; i < 16; ++i)
    printf("|  %c ", isprint(data[i]) ? data[i] : '.');
    printf("|\n");
}
