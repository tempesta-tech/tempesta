#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "sse_parser.h"

int dumpTokenSet(TokenSet * ts, const char ** tokens) {
    //dump tokenset structure:
    printf("Token set lenght: %d\n", ts->iterations);
    printf("|  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 "
           "|  8 |  9 | 10 | 11 | 12 | 13 | 14 | 15 |\n");

    unsigned char * data = (unsigned char*)&ts->data;
    for(int n = 0; n < ts->iterations; ++n) {
        printf("+----+----+----+----+----+----+----+----"
               "+----+----+----+----+----+----+----+----+\n");
        for(int i = 0; i < 16; ++i)
        printf("| %02x ", data[n*16+i]);
        printf("|\n");
        for(int i = 0; i < 16; ++i)
        printf("|  %c ", isprint(data[n*16+i]) ? data[n*16+i] : '.');
        printf("|\n");
    }
    //make sure all tokens were parsed successfully
    int fail = 0;
    for(int i = 0; tokens[i]; ++i) {
        int result = matchTokenSet(ts, strToVec(tokens[i]));
        printf("token: %s: %04x: ", tokens[i], result);
        if (strlen(tokens[i]) != MATCH_LENGTH(result)) {
            ++fail;
            printf("FAIL(length)\n");
        } else if (MATCH_CODE(result) != i) {
            ++fail;
            printf("FAIL(token index)\n");
        } else {
            printf("SUCCESS\n");
        }
    }
    return fail;
}

int main()
{
    sse_init_constants();

    TokenSet * ts = NULL;
    int        ts_len;
    int        fail = 0;

    const char * tokens[] = {
        "GET", "PUT", "POST", "COPY", "MOVE", "LOCK", "HEAD", "PATCH",
        "TRACK", "DELETE", "UNLOCK", "MKCOL", "OPTIONS", "PROPFIND", "PROPPATCH",
        NULL
    };
    ts_len = tokenSetLength(tokens);
    void * ts_buffer = NULL;
    if (posix_memalign(&ts_buffer, 16, ts_len)) {
        printf("malloc error\n");
        return 1;
    }
    ts = initTokenSet(tokens, ts_buffer, ts_len);
    if (!ts) {
        printf("token set lenght mismatch(%p)\n", ts);
        return 1;
    }
    fail += dumpTokenSet(ts, tokens);
    free(ts);


    static const char * tokens_sch[] = {
        "https://", "http://",
        NULL
    };
    ts_len = tokenSetLength(tokens_sch);
    if (posix_memalign(&ts_buffer, 16, ts_len)) {
        printf("malloc error\n");
        return 1;
    }
    ts = initTokenSet(tokens_sch, ts_buffer, ts_len);
    if (!ts) {
        printf("token set lenght mismatch(%p)\n", ts);
        return 1;
    }
    fail += dumpTokenSet(ts, tokens_sch);

    printf("**************************************************\n");
    int r = matchTokenSet(ts, strToVec("http://yandex.ru"));
    printf("parse str: %04x\n", r);
    if (!r) {
        printf("failed to parse host\n");
        ++fail;
    }

    free(ts);

    if (fail) return 1;
    return 0;
}

