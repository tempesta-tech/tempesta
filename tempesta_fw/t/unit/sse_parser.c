#include "sse_parser.h"
#ifndef _NO_DEBUG_

#include <stdio.h>
#include <assert.h>
#include <ctype.h>

#define XASSERT(xxx) assert(xxx)
static void PRINTM(const char * vname, Vector vval) {
    printf("%s:\n+----+----+----+----+----+----+----+----"
           "+----+----+----+----+----+----+----+----+\n", vname);
    printf("|  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 "
           "|  8 |  9 | 10 | 11 | 12 | 13 | 14 | 15 |\n");
    printf("+----+----+----+----+----+----+----+----"
           "+----+----+----+----+----+----+----+----+\n");
    char data[16];
    _mm_storeu_si128((__m128i*)data, vval);

    for(int i = 0; i < 16; ++i)
    printf("| %02x ", data[i]);
    printf("|\n");
    for(int i = 0; i < 16; ++i)
    printf("|  %c ", isprint(data[i]) ? data[i] : '.');
    printf("|\n");

    printf("+----+----+----+----+----+----+----+----"
           "+----+----+----+----+----+----+----+----+\n");
}
#define PRINTSTATE(xxx) \
    printf()

#else

#define XASSERT(xxx)
#define PRINTM(vname, vval)

#endif

#define likely(a)	__builtin_expect((a), 1)
#define unlikely(a)	__builtin_expect((a), 0)

struct Constants {
    //shuffle
    __m128i shuffle[4];
    //_mm_masktest
    __m128i masktest1, masktest2;
    //token compare
    __m128i tokencmp;
    //symbols
    __m128i _r, _n;
    __m128i spaces, semicolons, slashes, tabs, plus, nine, zero;
    //conversion
    __m128i tabs2spaces, plus2spaces;
    //end of line
    __m128i newline1, newline2;
    //decode quoted
    __m128i dq0, dq1, dq2, dq3, dq4, dq5;
    //http version
    __m128i HTTP1x, HTTP1xHelper;
    //directories
    __m128i directoryPatterns;
    //bitmasks for different types of data
    __m128i alnumDotMinusBitmask;
    __m128i hostnameLiteralBitmask;
    __m128i uriBitmask;
    __m128i uriArgsBitmask;
    __m128i uriAsIsBitmask;
    __m128i headerNameBitmask;
    __m128i headerValueBitmask;

    union {
        TokenSet ts;
        __m128i  buffer[25];
    } http_method;
};

static struct Constants cc;

void sse_init_constants() {
    struct Constants * c = &cc;
    int ret;

    c->shuffle[0] = c->shuffle[1] = _mm_setr_epi8(
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    c->shuffle[2] = _mm_set1_epi8(0xFF);
    c->shuffle[3] = _mm_setzero_si128();
    c->masktest1  = _mm_setr_epi8(1,2,4,8,16,32,64,128,0,0,0,0,0,0,0,0);
    c->masktest2  = _mm_set1_epi8(0xF);
    c->tokencmp   = _mm_setr_epi8(1, 0, 2, 0, 4, 0, 8, 0, 16, 0, 32, 0, 64, 0, 128, 0);

    c->spaces = _mm_set1_epi8(0x20);
    c->semicolons = _mm_set1_epi8(':');
    c->slashes = _mm_set1_epi8('/');
    c->tabs = _mm_set1_epi8('\t');
    c->plus = _mm_set1_epi8('+');
    c->nine = _mm_set1_epi8('9');
    c->zero = _mm_set1_epi8('0');
    c->_n   = _mm_set1_epi8('\n');
    c->_r   = _mm_set1_epi8('\r');

    c->tabs2spaces = _mm_set1_epi8(' '-'\t');
    c->plus2spaces = _mm_set1_epi8('+'-' ');

    c->masktest1 = _mm_setr_epi8(1,2,4,8,16,32,64,128,0,0,0,0,0,0,0,0);
    c->masktest2 = _mm_set1_epi8(0xF);

    c->newline1 = _mm_setr_epi8('\n','\n', 0  , 0  ,
                                '\r','\n','\n', 0  ,
                                '\n','\r','\n', 0  ,
                                '\r','\n','\r','\n');
    c->newline2 = _mm_setr_epi8(0xFF,0xFF, 0  , 0  ,
                                0xFF,0xFF,0xFF, 0  ,
                                0xFF,0xFF,0xFF, 0  ,
                                0xFF,0xFF,0xFF,0xFF);
    c->HTTP1x =
            _mm_setr_epi8('\r','\n','\n','H',
                          'T' ,'T' ,'P' ,'/',
                          '1' ,'.' ,'Z' ,'0',
                          '1','\r','\n','\n');
    c->HTTP1xHelper =
            _mm_setr_epi8(0,  1,  0,  0,
                          1,  2,  3,  4,
                          5,  6,  0,  7,
                          7,  8,  9,  8);
    c->dq0 = _mm_setr_epi8(
                0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    c->dq1 = _mm_setr_epi8(
                0x00, 0x00, 0x20, 0x20, 0x00, 0x00, 0x20, 0x20,
                0x00, 0x00, 0x20, 0x20, 0x00, 0x00, 0x20, 0x20);
    c->dq2 = _mm_setr_epi8(
                0x2F, 0x39, 0x60, 0x66, 0x2F, 0x39, 0x60, 0x66,
                0x2F, 0x39, 0x60, 0x66, 0x2F, 0x39, 0x60, 0x66);
    c->dq3 = _mm_set1_epi16(0x00FF);
    c->dq4 = _mm_setr_epi8(
                0x30, 0xFF, 0x57, 0xFF, 0x30, 0xFF, 0x57, 0xFF,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00);
    c->dq5 = _mm_setr_epi16(
                16, 16, 1, 1, 0, 0, 0, 0);

    c->directoryPatterns =
            _mm_setr_epi8('/', '.', '.', '/',
                          '/', '.', '/',  0 ,
                          '/', '/',  0 ,  0 ,
                           0 ,  0 ,  0 ,  0 );

    static const char * http_m[] = {
        "GET", "PUT", "POST", "COPY", "MOVE", "LOCK", "HEAD", "PATCH",
        "TRACK", "DELETE", "UNLOCK", "MKCOL", "OPTIONS", "PROPFIND", "PROPPATCH",
        NULL
    };
    XASSERT(sizeof(c->http_method) >= tokenSetLength(http_m));
    initTokenSet(http_m, &c->http_method, sizeof(c->http_method));

    c->alnumDotMinusBitmask =
            _mm_setr_epi8(0xC8, 0xF8, 0xF8, 0xF8,
                          0xF8, 0xF8, 0xF8, 0xF8,
                          0xF8, 0xF8, 0xF0, 0x50,
                          0x50, 0x54, 0x54, 0x50);
    c->hostnameLiteralBitmask =
            _mm_setr_epi8(0xD8, 0xFC, 0xF8, 0xF8,
                          0xFC, 0xF8, 0xFC, 0xF8,
                          0xFC, 0xFC, 0xFC, 0x5C,
                          0x74, 0x5C, 0xD4, 0x70);
    c->uriBitmask =
            _mm_setr_epi8(0xC8, 0xFC, 0xF8, 0xF8,
                          0xFC, 0xF8, 0xF8, 0xF8,
                          0xFC, 0xFC, 0xF4, 0x54,
                          0x54, 0x54, 0x54, 0x70);
    c->uriArgsBitmask =
            _mm_setr_epi8(0xC8, 0xFC, 0xF8, 0xF8,
                          0xFC, 0xF8, 0xF8, 0xF8,
                          0xFC, 0xFC, 0xF4, 0x54,
                          0x54, 0x5C, 0x54, 0x70);
    c->uriAsIsBitmask =
            _mm_setr_epi8(0xF8, 0xFC, 0xFC, 0xFC,
                          0xFC, 0xFC, 0xFC, 0xFC,
                          0xFC, 0xFC, 0xFC, 0xFC,
                          0xF4, 0xFC, 0xFC, 0x7C);
    c->headerNameBitmask =
            _mm_setr_epi8(0xA8, 0xF8, 0xF8, 0xF8,
                          0xF8, 0xF8, 0xF8, 0xF8,
                          0xF8, 0xF8, 0xF0, 0x50,
                          0x50, 0x54, 0x50, 0x50);
    c->headerValueBitmask =
            _mm_setr_epi8(0xAC, 0xF8, 0xF8, 0xF8,
                          0xF8, 0xF8, 0xF8, 0xF8,
                          0xFC, 0xFC, 0xFC, 0x5C,
                          0x5C, 0x5C, 0x5C, 0x5C);
}


Vector strToVec(const char * restrict str) {
    char tmp[16];
    int  i;

    for(i = 0; i < 16; ++i) {
        tmp[i] = str[i];
        if (!str[i])break;
    }
    for(; i < 16; ++i)
        tmp[i] = 0;
    return _mm_lddqu_si128((__m128i*)tmp);
}


#define _mm_rm(n) _mm_lddqu_si128((__m128i*)(((char*)&cc.shuffle[0])+n))
#define _mm_bm(n) _mm_lddqu_si128((__m128i*)(((char*)&cc.shuffle[2])+n))
#define _mm_blend(a,b,mask) \
    _mm_or_si128(_mm_and_si128(mask, a),_mm_andnot_si128(mask, b))

inline void initInputIterator(InputIterator * restrict i) {
    i->latch[0] = i->latch[1] = _mm_setzero_si128();
    i->bytesin = 0;
    i->position = 0;
    i->readlen = 0;
}

inline int appendInputIterator(InputIterator * restrict i, const char * restrict buf, int size) {
    if (unlikely(size < 16)) {
        char tmp[16];
        int j;
        for(j = 0; j < size; ++j)
            tmp[j] = buf[j];
        __m128i r = _mm_rm(size);
        __m128i b = _mm_bm(size);

        __m128i v1 = _mm_shuffle_epi8(_mm_lddqu_si128((__m128i*)tmp), r);
        __m128i v2 = _mm_shuffle_epi8(i->latch[1], r);
        i->latch[1] = _mm_blend(v2, v1, b);
        i->latch[0] = v2;
        i->bytesin += size;
        i->position = 0;
        i->readlen = 0;
        return size;
    } else {
        i->latch[0] = i->latch[1];
        i->latch[1] = _mm_lddqu_si128((const __m128i*)buf);
        return 16;
    }
}

inline int inputIteratorReadable(InputIterator * restrict i)
{
    //test if there are >=16 bytes or there is a newline
    int q = 1;
    if (i->bytesin < 16) {
        __m128i r = _mm_rm(32 - i->bytesin);
        __m128i b = _mm_bm(32 - i->bytesin);

        Vector v = _mm_blend(_mm_shuffle_epi8(i->latch[0], r),
                         _mm_shuffle_epi8(i->latch[1], r),
                         b);
        v = _mm_cmpeq_epi8(v, cc._n);
        q = _mm_movemask_epi8(v);
    }
    return q;
}

inline Vector readIterator(InputIterator * restrict i)
{
    __m128i r = _mm_rm(32 - i->bytesin);
    __m128i b = _mm_bm(32 - i->bytesin);

    return _mm_blend(_mm_shuffle_epi8(i->latch[0], r),
                     _mm_shuffle_epi8(i->latch[1], r),
                     b);
}

inline int  containsNewline(Vector v) {
    __m128i n = _mm_cmpeq_epi8(v, cc._n);
    return _mm_movemask_epi8(n);
}

inline SymbolMap createEmptySymbolMap() {
   return _mm_setzero_si128();
}

SymbolMap createSymbolMapFromCharset(const char * cs) {
    char set[16];
    int i;
    for(i = 0; i < 16; ++i)set[i] = 0;
    while(*cs) {
        if (cs[0] & 0x80) continue;
        set[cs[0] & 0x0F] |= (1<<(cs[0]>>4));
        ++cs;
    }
    return _mm_lddqu_si128((__m128i*)set);
}

SymbolMap appendSymbolMapFromCharset(SymbolMap sm, const char * cs) {
    return _mm_or_si128(sm, createSymbolMapFromCharset(cs));
}

inline Vector matchSymbolsMask(SymbolMap sm, Vector v) {
    __m128i mask1 = _mm_shuffle_epi8(sm, v);
    __m128i mask2 = _mm_and_si128(
                cc.masktest2,
                _mm_srli_epi16(v, 4));
    __m128i mask3 = _mm_shuffle_epi8(
                cc.masktest1,
                mask2);
    __m128i mask4 = _mm_and_si128(
                mask3,
                mask1);
    __m128i vec = _mm_cmpgt_epi8(
                mask4,
                _mm_setzero_si128());
    return vec;
}

inline int matchSymbolsCount(SymbolMap sm, Vector v) {
    __m128i mask1 = _mm_shuffle_epi8(sm, v);
    __m128i mask2 = _mm_and_si128(
                cc.masktest2,
                _mm_srli_epi16(v, 4));
    __m128i mask3 = _mm_shuffle_epi8(
                cc.masktest1,
                mask2);
    __m128i mask4 = _mm_and_si128(
                mask3,
                mask1);
    __m128i vec = _mm_cmpeq_epi8(
                _mm_setzero_si128(),
                mask4);

    return __builtin_ctz(0x10000 | _mm_movemask_epi8(vec));
}

MatchResult matchTokenSet(const TokenSet * ts, Vector vec) {
    __m128i cmp1, cmp2, carry;
    int     mask, n, maxn;

    carry = _mm_setzero_si128();
    maxn  = ts->iterations;
    n     = 0;     
    //we must fit this cycle into 28 instructions to make if fast!
    while(n < maxn) {
        //prepare comparison masks for first bundle
        cmp1 = _mm_shuffle_epi8(vec, ts->data[n++]);
        cmp1 = _mm_cmpeq_epi32(cmp1, ts->data[n++]);
        cmp2 = _mm_packs_epi32(carry, cmp1);
        carry = cmp1;
        cmp2 = _mm_and_si128(cmp2, cc.tokencmp);
        cmp2 = _mm_hadd_epi16(cmp2, cmp2);
        cmp2 = _mm_hadd_epi16(cmp2, cmp2);
        cmp2 = _mm_hadd_epi16(cmp2, cmp2);
        cmp2 = _mm_cmpeq_epi16(cmp2, ts->data[n++]);
        mask = 0xFF & _mm_movemask_epi8(cmp2);
        cmp2 = _mm_and_si128(cmp2, ts->data[n++]);
        if (mask) break;
    }
    if (mask) {
        cmp2 = _mm_hadd_epi16(cmp2, cmp2);
        cmp2 = _mm_hadd_epi16(cmp2, cmp2);
        cmp2 = _mm_hadd_epi16(cmp2, cmp2);
        mask = _mm_extract_epi16(cmp2, 0);
    }
    return mask;
}

#define MakeCode(len, cd) ((len<<16)|cd)

int tokenSetLength(const char ** tokens)
{
    //count number of words required for map
    int i, j, k;
    for(i = 0, k = 0; tokens[i]; ++i) {
        for(j = 0; tokens[i][j]; ++j);
        k += (j+3)>>2;
    }
    //round number of words
    return 16+64*((k+3)>>2);
}

TokenSet * initTokenSet(const char ** tokens,
                 void               * buf,
                 int                  bufsize)
{
    static const unsigned char cmap[4][4]= {
        {0x10, 0x18, 0x1c, 0x1e},
        {0x20, 0x30, 0x38, 0x3c},
        {0x40, 0x60, 0x70, 0x78},
        {0x80, 0xc0, 0xe0, 0xf0}
    };
    //check if buf is aligned
    if (((long)buf) & 0xF) return NULL;

    TokenSet * ts = (TokenSet*)buf;
    //count number of words required for map
    int i, j, k, p, nwords;
    for(i = 0, k = 0; tokens[i]; ++i) {
        for(j = 0; tokens[i][j]; ++j);
        k += (j+3)>>2; 
    }
    //round number of words 
    nwords = (k+3)>>2;
    //check buffer size
    if (bufsize < (16 + 64*nwords)) return NULL;

    ts->iterations = nwords*4;
    unsigned char * bytes = (unsigned char*)ts->data;
    for(i = 0, k = 0; tokens[i]; ++i) {
        for(j = 0; tokens[i][j]; ++j) {
            bytes[k]    = j;
            bytes[k+16] = tokens[i][j];
            bytes[k+32] = 0xFF;
            bytes[k+48] = 0;
            p = k;
            if ((k & 0xF) == 0xF) {
                k = k + 49;
            } else {
                k = k + 1;
            }
        }

        while(k & 3) {
            bytes[k]    = 0xFF;
            bytes[k+16] = 0;
            bytes[k+32] = 0xFF;
            bytes[k+48] = 0;

            if ((k & 0xF) == 0xF) {
                k = k + 49;
            } else {
                k = k + 1;
            }
        }

        //WEIRD CODE!!!!
        int offset = (p & 0xFFC0) + ((p & 0xC) >> 1);
        int d      = cmap[0x3&(p>>2)][(j-1)>>2];
        bytes[offset+32] = d;
        bytes[offset+33] = 0;
        bytes[offset+48] = i;
        bytes[offset+49] = j;
    }
    return ts;
}

inline Vector decodeUrlEncoded(Vector data) {
    //для массового сравнения размножим байты 1 и 2 в последовательности "%xx"
    __m128i muxed = _mm_shuffle_epi8(data, cc.dq0);
    //в байтах 4-7 и 12-15 будет сравниваться a-zA-Z, lowercase его
    muxed = _mm_or_si128(muxed, cc.dq1);
    //сравним (c1>'0'-1, c1>'9', c1>'a'-1, c1>'f')...
    //должно получиться FF00FF00FF00FF00???????
    __m128i mask  = _mm_cmpgt_epi8(muxed, cc.dq2);
    mask = _mm_cmpeq_epi16(mask, cc.dq3);
    //вычтем константы '0' и 'a'-9 из соответствующих байт
    muxed = _mm_subs_epu8(muxed, cc.dq4);
    //затрем неправильные позиции чтоб не мешали
    muxed = _mm_and_si128(muxed, mask);
    //что у нас получилось:
    //  C1_09   0   C1_af   0   C2_09   0   C2_af   0
    //    *16         *16         *1          *1
    //          +                       +
    //                      +
    //  byte_C2C1
    //теперь объединим байты:
    muxed = _mm_madd_epi16(muxed, cc.dq5);
    muxed = _mm_hadd_epi32(muxed, muxed);
    return muxed;
}

void initOutputIterator(OutputIterator * i, void * buffer, int size)
{
    i->bytesin = 0;
    i->callback = 0;
    i->allocationSize = size;
    i->store = (__m128i*)buffer;
    i->storesize = size;
}

int  initOutputIteratorEx(OutputIterator * i, BufferCallback cb, void * userarg, int allocsize)
{
    i->bytesin        = 0;
    i->callback       = cb;
    i->userarg        = userarg;
    i->allocationSize = allocsize;
    void * pb;
    int ret = cb(&pb, allocsize, userarg);
    i->store = (__m128i*)pb;
    i->storesize = allocsize;
    return ret;
}

enum ParserState {
    HTTP_REQ_METHOD,
    HTTP_REQ_SCHEME,
    HTTP_REQ_HOST,
    HTTP_REQ_PORT,
    HTTP_REQ_URI,
    HTTP_REQ_ARGS,
    HTTP_REQ_MAYBE_HTTPV,
    HTTP_HDR_START,
    HTTP_HDR_CONT,
    HTTP_HDR_VAL,
    HTTP_FINISHED,
    HTTP_ERROR,
    HTTP_SKIP_SPACE = 0x8000
};

int initHttpRequest(struct HttpRequest * r, void * outputbuffer, int buflen)
{
    //misaligned check
    if (((long)outputbuffer) & 15) return -1;

    initInputIterator(&r->input);
    initOutputIterator(&r->output, outputbuffer, buflen);

    r->state = HTTP_REQ_METHOD;
    r->connection = 0;
    r->content_length = 0;
    r->content_type = 0;
    r->expect = 0;
    r->host = 0;
    r->if_match = 0;
    r->if_none_match = 0;
    r->if_modified_since = 0;
    r->if_unmodified_since = 0;
    r->if_range = 0;
    r->range = 0;
    r->user_agent = 0;

    return 0;
}
