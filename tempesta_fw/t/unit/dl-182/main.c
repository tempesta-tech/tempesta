#include "http.h"
#include <sys/time.h>
#include <assert.h>
#include <stdio.h>

static inline unsigned long
tv_to_ms(const struct timeval *tv)
{
    return ((unsigned long)tv->tv_sec * 1000000 + tv->tv_usec) / 1000;
}

int main(int argc, char ** argv)
{
    unsigned long iterations = 10;
    int nfile = 1;
    TfwPool * pool = (TfwPool*)malloc(sizeof(*pool));
    assert(pool != NULL);

    TfwHttpReq req;

    if (argc == 1) {
        printf("Usage: %s [-n iterations] file1 [fileN...]\n");
        return 0;
    }

    if (!strcmp(argv[1], "-n")) {
        if (argc < 4) {
            printf("Usage: %s [-n iterations] file1 [fileN...]\n");
            return 1;
        }
        iterations = strtoul(argv[2], NULL, 10);
        nfile = 3;
    }

    FILE * source = fopen(argv[nfile], "rt");
    if (!source) {
        printf("error: input file '%s' cannot be opened\n", argv[nfile]);
        return 1;
    }

    fseek(source, 0, SEEK_END);
    size_t len = ftell(source);
    if (len <= 0) {
        printf("error: input file '%s' is empty\n", argv[nfile]);
        return 1;
    }
    unsigned char * data = (unsigned char*)malloc(len);
    if (!data) {
        printf("error: memory allocation error\n");
        return 1;
    }
    fread(data, len, 1, source);

    //first get a result============================
    const char * result_str;
    memset(&req, 0, sizeof(req));
    req.pool = pool;
    int result = tfw_http_parse_req(&req, data, len);
    switch(result) {
    case TFW_BLOCK:result_str = "TFW_BLOCK";break;
    case TFW_PASS:result_str = "TFW_BLOCK";break;
    case TFW_POSTPONE:result_str = "TFW_BLOCK";break;
    default:result_str = "unexpected!!!!";
    }
    printf("Result = %s\n", result_str);
    if (result != TFW_PASS) return 0;

    struct timeval tv0, tv1;

    gettimeofday(&tv0, NULL);					\
    for(unsigned long n = 0; n < iterations*1000; ++n) {
        memset(&req, 0, sizeof(req));
        req.pool = pool;

        memset(&req, 0, sizeof(req));
        req.pool = pool;
        tfw_http_parse_req(&req, data, len);
    }
    gettimeofday(&tv0, NULL);					\

    printf("Benchmark result:\t%llu\n", tv_to_ms(&tv1) - tv_to_ms(&tv0));
}
