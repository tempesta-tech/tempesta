#ifndef _TFW_SSE_UTILS_H_
#define _TFW_SSE_UTILS_H_

#include <tmmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef __m128i Vector;

typedef int (*BufferCallback)(void ** buf, int size, void * userarg);

/***************************************************
 *
 * aux
 *
 ***************************************************/
void sse_init_constants();
long long parseNumber(Vector vec, int * restrict len, char * restrict invchar);

#define vecToSymbolCount(vec)\
    (__builtin_ctz(_mm_movemask_epi8(vec) | 0x10000))

Vector strToVec(const char * restrict str);
/***************************************************
 *
 * SYMBOL MAPS
 *
 ***************************************************/
//symbol maps: maches only ascii charset(0-127)
//you can get
typedef __m128i SymbolMap;
SymbolMap createEmptySymbolMap();
SymbolMap createSymbolMapFromCharset(const char * cs);
SymbolMap appendSymbolMapFromCharset(SymbolMap sm, const char * cs);
Vector matchSymbolsMask(SymbolMap sm, Vector v);
int matchSymbolsCount(SymbolMap sm, Vector v);

/***************************************************
 *
 * INPUT
 *
 ***************************************************/
//input stream
typedef struct {
    __m128i latch[2];
    int     bytesin;
    const char *  position;
    int     readlen;
} InputIterator;

void initInputIterator(InputIterator * restrict i);
void appendInputIterator(InputIterator * restrict i, const char * restrict buf, int size);
#define shouldAppendInputIterator(i) ((i)->bytesin < 16)
#define consumeInputIterator(i, n) {(i)->bytesin -= n;}
int  inputIteratorReadable(InputIterator * restrict i);
Vector readIterator(InputIterator * restrict i);
int  containsNewline(Vector v);

/***************************************************
 *
 * TOKEN SET
 *
 ***************************************************/
typedef struct {
    int iterations;
    __m128i data[1];
}TokenSet;
typedef unsigned int MatchResult;

TokenSet *initTokenSet(const char ** tokens, void *buf, int bufsize);
int tokenSetLength(const char ** tokens);
//match tokenset: matches token set and returns MR(id + num_bytes_consumed)
//match tokensetsp: same as above, but also consumes all trailing spaces
MatchResult matchTokenSet(const TokenSet * set, Vector vec);
#define MATCH_LENGTH(mr) (mr>>8)
#define MATCH_CODE(mr) (mr & 0xFF)
/****************************************************
 * Decodes a url-encoded string:
 * performs symbol set checking
 * parses '%xx' -> %xx'
 *        '%00' -> error
 ****************************************************/
Vector decodeUrlEncoded(Vector vec);

/***************************************************
 *
 * OUTPUT STREAM
 *
 * output stream is dedicated for storing 2 kinds of data
 * a) parser results
 * b) reconstructed http request out of parser results
 *
 * I had no idea how we will handle situations when
 * we are out of space in output buffer, but,
 * in general, we expect a large enough buffer
 * where we can fit all parser results.
 * in case we have no enough buffer space, an optional
 * callback is available to get more data
 *
 * NOTE: you have to track allocated buffers on your own!
 *
 ***************************************************/
typedef struct {
    __m128i latch;
    __m128i *store;
    int     bytesin;
    int     storesize;

    BufferCallback callback;
    void   *userarg;
    int     allocationSize;
} OutputIterator;

void initOutputIterator(OutputIterator * restrict i, void * buffer, int size);
int  initOutputIteratorEx(OutputIterator * restrict i, BufferCallback cb, void * userarg, int allocsize);
/*
 * storing aligned data: source data may be misaligned,
 * but destination will be always aligned.
 */

//push n bytes to output
char * outputPushStart(OutputIterator * restrict i, Vector vec, int n);
int    outputPush(OutputIterator * restrict i, Vector vec, int n);
void   outputFlush(OutputIterator * restrict i);
//ensures output is finalized with \0 and checks if there were errors
int    outputFinish(OutputIterator * restrict i);

/*****************************************************
 *****************************************************
 * HTTP PARSER;
 *
 * Let we have a parsed request(spaces are \0):
 *
 * GET    http://yandex.ru:80/dir/file.php?arg=foo+bar%30  HTTP/1.1\r\n
 * Header: value1\r\n
 * Header-1-6-bytes:   value2\r\n
 * VeryVeryLongHeader: value3\r\n
 * \r\n
 *
 * 0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
 * G   E   T                                                      <= request
 * h   t   t   p                                                  <= scheme
 * y   a   n   d   e   x   .   r   u                              <= host
 * /   d   i   r   /   f   i   l   e   .   p   h   p              <= uri(parsed)
 * a   r   g   =   f   o   o  ' '  b   a   r   0                  <= args
 * h   e   a   d   e   r                                          <= header[0].name
 * v   a   l   u   e   1                                          <= header[0].value
 * h   e   a   d   e   r   -   1   -   6   -   b   y   t   e   s  <= header[1].name
 *
 * v   a   l   u   e   2                                          <= header[1].value
 * v   e   r   y   v   e   r   y   l   o   n   g   h   e   a   d  <= header[2].name
 * e   r
 * v   a   l   u   e   3                                          <= header[2].value
 *
 ******************************************************
 ******************************************************/
enum HttpMethodCodes {
    HTTP_GET,
    HTTP_PUT,
    HTTP_POST,
    HTTP_COPY,
    HTTP_MOVE,
    HTTP_LOCK,
    HTTP_HEAD,
    HTTP_PATCH,
    HTTP_TRACK,
    HTTP_DELETE,
    HTTP_UNLOCK,
    HTTP_MKCOL,
    HTTP_OPTIONS,
    HTTP_PROPFIND,
    HTTP_PROPPATCH,
};
enum HttpVersionCodes {
    HTTP_1_0 = 100,
    HTTP_1_1 = 101,
    HTTP_0_9 =   9,
};
enum SchemaCodes {
    HTTP_SCHEMA_HTTPS,
    HTTP_SCHEMA_HTTP,
};

enum ParseResult {
    Parse_NeedMoreData,
    Parse_Failure,
    Parse_Success
};

struct SSEHttpRequest {
    InputIterator          input;
    OutputIterator         output;
    int                    state;
    int                    method;
    int                    schema;
    int                    version;
    int                    complex_uri;
    int                    uri_lenght;//used to cut uri at \s
    int                    uri_lenght_extra;

    char                  *uri_host;
    char                  *uri_path;
    char                  *uri_args;
    int                    uri_port;
    //headers
    char                  *host;
    char                  *connection;
    char                  *if_modified_since;
    char                  *if_unmodified_since;
    char                  *if_match;
    char                  *if_none_match;
    char                  *user_agent;
    char                  *referer;
    char                  *content_length;
    char                  *content_type;
    char                  *range;
    char                  *if_range;
    char                  *transfer_encoding;
    char                  *expect;
    char                  *upgrade;
};

int initHttpRequest(struct SSEHttpRequest * r, void * outputbuffer, int buflen);
int ParseHttpRequest(struct SSEHttpRequest * r, const void * buffer, int len);
int ParseHttpResponse(struct SSEHttpRequest * r, const void * buffer, int len);
int constructRequest(struct SSEHttpRequest * r);

int copyHeader(const Vector * h, const Vector * v, OutputIterator * out);
int copyHeaders(const Vector ** hdrs, OutputIterator * out);
//add \r\n and return pointer to write data
void * finalizeHttpRequest(OutputIterator * out);

#ifdef __cplusplus
}
#endif

#endif // _TFW_SSE_UTILS_H_
