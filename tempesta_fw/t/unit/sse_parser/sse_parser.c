#include "sse_parser.h"
#ifndef _DEBUG_

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
    unsigned char data[16];
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
    printf("State: %s\n", #xxx);

#else

#define XASSERT(xxx)
#define PRINTM(vname, vval)
#define PRINTSTATE(xxx)

#endif

#define FORCEINLINE  __attribute__((always_inline))
#define likely(a)	__builtin_expect((a), 1)
#define unlikely(a)	__builtin_expect((a), 0)

struct Constants {
    //shuffle
    __m128i shuffle[4];
    //_mm_masktest
    __m128i masktest1, masktest2;
    //token compare
    __m128i tokencmp;
    //swap bytes
    __m128i swapbytes16;
    //digit conversion
    __m128i cvt10_2_bytes;
    __m128i cvt10_2_words;
    __m128i cvt10_2_dwords;
    //symbols
    __m128i _r, _n;
    __m128i spaces, semicolons, slashes, tabs, plus, nine, zero;
    //conversion
    __m128i tabs2spaces, plus2spaces;
    //end of line
    __m128i newline1, newline2;
    //decode quoted
    __m128i dq0, dq1, dq2, dq3, dq4, dq5;
    //digits
    __m128i digits;
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
    union {
        TokenSet ts;
        __m128i  buffer[9];
    } http_schema;
    union {
        TokenSet ts;
        __m128i  buffer[17];
    } http_version;
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
    c->swapbytes16 = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    c->cvt10_2_bytes = _mm_set1_epi16(256+10);
    c->cvt10_2_words = _mm_set1_epi32(65536+100);

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

    static const char * http_sch[] = {
        "https://", "http://", NULL
    };
    XASSERT(sizeof(c->http_schema) >= tokenSetLength(http_sch));
    initTokenSet(http_sch, &c->http_schema, sizeof(c->http_schema));

    static const char * http_v[] = {
        "\n", "\r\n", "HTTP/1.0\n", "HTTP/1.0\r\n",
        "HTTP/1.1\n", "HTTP/1.1\r\n", NULL
    };
    XASSERT(sizeof(c->http_version) >= tokenSetLength(http_v));
    initTokenSet(http_v, &c->http_version, sizeof(c->http_version));

    c->digits =
            _mm_setr_epi8(0x08, 0x08, 0x08, 0x08,
                          0x08, 0x08, 0x08, 0x08,
                          0x08, 0x08, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00);
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
            _mm_setr_epi8(0xa8, 0xf8, 0xf8, 0xf8,
                          0xf8, 0xf8, 0xf8, 0xf8,
                          0xf8, 0xf8, 0xf0, 0x54,
                          0x50, 0x54, 0x54, 0x54);
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

inline static __m128i _mm_align(__m128i pd, __m128i nd, int n) {
    __m128i mask1 = _mm_rm(n);
    __m128i mask2 = _mm_bm(n);
    return _mm_blend(_mm_shuffle_epi8(pd, mask1), _mm_shuffle_epi8(nd, mask1), mask2);
} FORCEINLINE

inline  static __m128i _mm_align_up(__m128i data, int n) {
    return _mm_shuffle_epi8(data, _mm_rm(n));
} FORCEINLINE

inline void initInputIterator(InputIterator * restrict i) {
    i->latch[0] = i->latch[1] = _mm_setzero_si128();
    i->bytesin = 0;
    i->position = 0;
    i->readlen = 0;
}

inline void appendInputIterator(InputIterator * restrict i, const char * restrict buf, int size) {
    i->position = buf;
    i->readlen = size;
}

inline int inputIteratorReadable(InputIterator * restrict i)
{
    //test if there are >=16 bytes or there is a newline
    int q = 1;
    if ((i->bytesin + i->readlen) < 16) {
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
    if (i->bytesin < 16) {
        if (unlikely(i->readlen < 16)) {
            char tmp[16];
            int j;
            for(j = 0; j < i->readlen; ++j)
                tmp[j] = i->position[j];
            i->readlen = 0;
            i->position += j;

            __m128i r = _mm_rm(j);
            __m128i b = _mm_bm(j);
            __m128i v1 = _mm_shuffle_epi8(_mm_lddqu_si128((__m128i*)tmp), r);
            __m128i v2 = _mm_shuffle_epi8(i->latch[1], r);
            i->latch[1] = _mm_blend(v2, v1, b);
            i->latch[0] = v2;
            i->bytesin += j;
        } else {
            i->latch[0] = i->latch[1];
            i->latch[1] = _mm_lddqu_si128((const __m128i*)i->position);
            i->bytesin += 16;
            i->readlen -= 16;
            i->position += 16;
        }
    }
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
    __m128i vec1 = _mm_cmpgt_epi8(
                mask4,
                _mm_setzero_si128());
    __m128i vec2 = _mm_cmplt_epi8(
                mask4,
                _mm_setzero_si128());
    return _mm_or_si128(vec1,vec2);
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

inline long long parseNumber(Vector vec, int * restrict p_len, char * restrict invchar) {
    Vector mask = matchSymbolsMask(cc.digits, vec);
    int len = __builtin_ctz(~_mm_movemask_epi8(mask));
    int buf[4] __attribute__((aligned(16)));
    Vector shuffle = _mm_rm(len);
    Vector v = _mm_subs_epi8(vec, cc.zero);
    v = _mm_and_si128(v, mask);
    v = _mm_shuffle_epi8(v, shuffle);

    //save first wrong character
    invchar[0] = (char)_mm_extract_epi16(
                _mm_shuffle_epi8(vec, shuffle), 0);
    if (!len) return -1;
    //convert from bytes to dwords
    v = _mm_maddubs_epi16(v, cc.cvt10_2_bytes);
    v = _mm_madd_epi16(v, cc.cvt10_2_words);
    _mm_store_si128((__m128i*)buf, v);

    long long result = buf[0];
    result = 10000LL*result + buf[1];
    result = 10000LL*result + buf[2];
    result = 10000LL*result + buf[3];
    *p_len = len;
    return result;
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
        cmp2 = _mm_and_si128(cmp2, ts->data[n]);
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

struct UriResult {
    int num_matched_symbols;
    int num_extra_symbols;
    Vector output; //symbols to push
};

inline static struct UriResult matchUri(Vector data) {
    Vector spaces  = _mm_cmpeq_epi8(cc.spaces, data);
    Vector matched = matchSymbolsMask(cc.uriBitmask, data);
    Vector push = _mm_blend(cc.plus, data, spaces);
    struct UriResult result;

    //expand matched uri by
    int nms = __builtin_ctz(~_mm_movemask_epi8(matched));
    int nspaces = __builtin_ctz(~(_mm_movemask_epi8(spaces)>>nms));
    result.num_matched_symbols = nms;
    result.num_extra_symbols   = nms + nspaces;
    result.output = push;
    return result;
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
    i->bytesin = -1;
    i->callback = 0;
    i->allocationSize = size;
    i->store = (__m128i*)buffer;
    i->storesize = size;
}

int  initOutputIteratorEx(OutputIterator * i, BufferCallback cb, void * userarg, int allocsize)
{
    i->bytesin        = -1;
    i->callback       = cb;
    i->userarg        = userarg;
    i->allocationSize = allocsize;
    void * pb;
    int ret = cb(&pb, allocsize, userarg);
    i->store = (__m128i*)pb;
    i->storesize = allocsize;
    return ret;
}

inline char * outputPushStart(OutputIterator * restrict i, Vector vec, int n) {
    if (unlikely(i->storesize <= 16))
        return (char*)&i->latch; //never return 0

    if (i->bytesin > 0) {
        Vector v = _mm_align(i->latch,
                             _mm_setzero_si128(),
                             16-i->bytesin);
        _mm_store_si128(i->store, v);
        ++i->store;
        i->storesize -= 16;
    } else if (i->bytesin == 0) {
        _mm_store_si128(i->store, _mm_setzero_si128());
        ++i->store;
        i->storesize -= 16;
    }

    char * ret = (char*)i->store;
    if (n == 16) {
        _mm_store_si128(i->store, vec);
        ++i->store;
        i->storesize -= 16;
        i->bytesin = 0;
    } else {
        i->latch = _mm_align_up(vec, n);
        i->bytesin = n;
    }
    return ret;
}

inline int   outputPush(OutputIterator * restrict i, Vector vec, int n) {
    if (unlikely(i->storesize <= 16))
        return 0;

    int k = n + i->bytesin;
    if (k < 16) {
        i->latch = _mm_align(i->latch, vec, n);
        i->bytesin += n;
    } else {
        Vector v = _mm_align(i->latch, vec, 16-i->bytesin);
        _mm_store_si128(i->store, v);
        ++i->store;
        i->storesize -= 16;

        i->latch = _mm_align_up(vec, k - 16);
        i->bytesin = k - 16;
    }
    return n;
}

inline void   outputFlush(OutputIterator * restrict i) {
    if (unlikely(i->storesize <= 16))
        return;

    if (i->bytesin >= 0) {
        Vector v = _mm_align(i->latch,
                             _mm_setzero_si128(),
                             16-i->bytesin);
        _mm_store_si128(i->store, v);
        ++i->store;
        i->storesize -= 16;
        i->bytesin = -1;
    }
}

//ensures output is finalized with \0 and checks if there were errors
inline int    outputFinish(OutputIterator * restrict i) {
    if (unlikely(i->storesize <= 16))
        return -1;

    if (i->bytesin > 0) {
        Vector v = _mm_align(i->latch,
                             _mm_setzero_si128(),
                             16-i->bytesin);
        _mm_store_si128(i->store, v);
        ++i->store;
        i->storesize -= 16;
    } else if (i->bytesin == 0) {
        _mm_store_si128(i->store, _mm_setzero_si128());
        ++i->store;
        i->storesize -= 16;
    }

    return 0;
}


enum ParserState {
    HTTP_REQ_METHOD,
    HTTP_REQ_SCHEMA,
    HTTP_REQ_HOST, HTTP_REQ_HOST_C,
    HTTP_REQ_PORT,
    HTTP_REQ_URI, HTTP_REQ_URI_C, HTTP_REQ_URI_SP,
    HTTP_REQ_ARGS,
    HTTP_REQ_MAYBE_HTTPV, HTTP_REQ_MAYBE_HTTPV_C,
    HTTP_REQ_HTTPV,
    HTTP_HDR_START,
    HTTP_HDR_CONT,
    HTTP_HDR_VAL,
    HTTP_FINISHED,
    HTTP_ERROR,
    HTTP_SKIP_SPACE = 0x8000,
};

int initHttpRequest(struct SSEHttpRequest * r, void * outputbuffer, int buflen)
{
    //misaligned check
    if (((long)outputbuffer) & 15) return -1;

    initInputIterator(&r->input);
    initOutputIterator(&r->output, outputbuffer, buflen);

    r->method = -1;
    r->schema = -1;
    r->version = HTTP_0_9;
    r->complex_uri = 0;
    r->uri_lenght = 0;
    r->uri_lenght_extra = 0;

    r->uri_host = 0;
    r->uri_path = 0;
    r->uri_args = 0;
    r->uri_port = 0;

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

#define STATE(s) case s: s: PRINTSTATE(s);
#define GOTO(s) {state = s; goto s;}
#define MOVE(s) {state = s; break; }
#define GOTO_SS(s) {state = s|HTTP_SKIP_SPACE; goto HTTP_SKIP_SPACE;}
#define MOVE_SS(s) {state = s|HTTP_SKIP_SPACE; break; }
int ParseHttpRequest(struct SSEHttpRequest * r, const void * buffer, int len) {
    static const int versions[] = {HTTP_0_9, HTTP_1_0, HTTP_1_1};
    int consumed = 0;
    int state = r->state;

    appendInputIterator(&r->input, buffer, len);

    for(;;) {
        if (!inputIteratorReadable(&r->input))
            return Parse_NeedMoreData;

        Vector data = readIterator(&r->input);
        //PRINTM("data", data);

        consumed = 0;
        if (state & HTTP_SKIP_SPACE) {
            int sm = _mm_movemask_epi8(_mm_cmpeq_epi8(data, cc.spaces));
            if (!(sm & 1)) {
                state = HTTP_ERROR;
                break;
            }
            if (sm != 0xFFFF)
                state &= ~ HTTP_SKIP_SPACE;
            consumeInputIterator(&r->input, __builtin_ctz(~sm));
            continue;
        }

        switch(state) {
        STATE(HTTP_SKIP_SPACE) {
            int sm = _mm_movemask_epi8(_mm_cmpeq_epi8(data, cc.spaces));
            if (!(sm & 1)) GOTO(HTTP_ERROR);
            if (sm != 0xFFFF)
                state &= ~ HTTP_SKIP_SPACE;
            consumed = __builtin_ctz(~sm);
            break;
        }
        STATE(HTTP_REQ_METHOD) {
            int method = matchTokenSet(&cc.http_method.ts, data);
            if (!method) GOTO(HTTP_ERROR);
            consumed  = MATCH_LENGTH(method);
            r->method = MATCH_CODE(method);
            MOVE_SS(HTTP_REQ_SCHEMA);
        }
        STATE(HTTP_REQ_SCHEMA) {
            int schema = matchTokenSet(&cc.http_schema.ts, data);
            if (!schema) GOTO(HTTP_REQ_HOST);
            consumed  = MATCH_LENGTH(schema);
            r->schema = MATCH_CODE(schema);
            MOVE(HTTP_REQ_HOST);
        }
        STATE(HTTP_REQ_HOST) {
            int ns = matchSymbolsCount(cc.alnumDotMinusBitmask, data);
            if (ns) {
                //check if host name starts with '.'
                char c = (char)_mm_extract_epi16(data, 0);
                if (c == '.') GOTO(HTTP_ERROR);

                r->uri_host = outputPushStart(&r->output, data, ns);
                consumed = ns;
                if (ns == 16)
                    MOVE(HTTP_REQ_HOST_C)
                else
                    MOVE(HTTP_REQ_PORT);
            }
            GOTO(HTTP_REQ_URI);
        }
        STATE(HTTP_REQ_HOST_C) {
            int ns = matchSymbolsCount(cc.uriBitmask, data);
            if (ns) {
                outputPush(&r->output, data, ns);
                consumed = ns;
                if (ns == 16)
                    break;
                MOVE(HTTP_REQ_PORT);
            }
            GOTO(HTTP_REQ_PORT);
        }
        STATE(HTTP_REQ_PORT) {
            short c2 = _mm_extract_epi16(data, 0);
            char c = (char)c2;
            if (c == ':') {
                //remove ':' and leave only port
                data = _mm_alignr_epi8(_mm_setzero_si128(), data, 1);
                int portlen;
                long long port = parseNumber(data, &portlen, &c);

                if (port < 1 || port > 65535) GOTO(HTTP_ERROR);
                r->uri_port = port;
                consumed = portlen + 1;
                MOVE(HTTP_REQ_URI);
            }
            switch(c) {
            case '/':
                GOTO(HTTP_REQ_URI);
            case ' ':
                MOVE_SS(HTTP_REQ_HTTPV);
            case '\r':
                if (c2 != 0x0A0D)
                    GOTO(HTTP_ERROR);
                ++consumed;
            case '\n':
                ++consumed;
                GOTO(HTTP_FINISHED);
            default:
                GOTO(HTTP_ERROR);
            }
            break;
        }
        STATE(HTTP_REQ_URI) {
            int n;
            struct UriResult mr;
            char c = (char)_mm_extract_epi16(data, 0);
            switch (c) {
            case ' ':
                GOTO_SS(HTTP_REQ_HTTPV);
            case '\r':
            case '\n':
                GOTO(HTTP_REQ_HTTPV);
            case '/':
                mr = matchUri(data);
                r->uri_path = outputPushStart(&r->output, mr.output, mr.num_extra_symbols);
                r->uri_lenght = mr.num_matched_symbols;
                r->uri_lenght_extra = mr.num_extra_symbols;
                consumed = mr.num_extra_symbols;
                if (mr.num_extra_symbols == 16) MOVE(HTTP_REQ_URI_C);
                if (mr.num_extra_symbols > mr.num_matched_symbols)
                    MOVE(HTTP_REQ_MAYBE_HTTPV);
                MOVE(HTTP_REQ_URI_SP);
            default:
                GOTO(HTTP_ERROR);
            }
            break;
        }
        STATE(HTTP_REQ_URI_C) {
            struct UriResult mr;
            mr = matchUri(data);
            outputPush(&r->output, mr.output, mr.num_extra_symbols);

            r->uri_lenght = r->uri_lenght_extra + mr.num_matched_symbols;
            r->uri_lenght_extra += mr.num_extra_symbols;
            consumed = mr.num_extra_symbols;
            if (mr.num_extra_symbols == 16) break;

            if (mr.num_extra_symbols > mr.num_matched_symbols)
                MOVE(HTTP_REQ_MAYBE_HTTPV);
            MOVE(HTTP_REQ_URI_SP);
        }
        STATE(HTTP_REQ_URI_SP) {
            char c = (char)_mm_extract_epi16(data, 0);
            switch(c) {
            case ' ':
                GOTO_SS(HTTP_REQ_MAYBE_HTTPV);
            case '\r':
            case '\n':
                GOTO(HTTP_REQ_MAYBE_HTTPV);
            case '?':
                outputFlush(&r->output);
            default:
                GOTO(HTTP_REQ_URI_C);
            }
            break;
        }
        STATE(HTTP_REQ_MAYBE_HTTPV) {
            char x = _mm_extract_epi16(data, 0);
            int n;

            switch(x) {
            case '\r':
            case '\n':
            case 'H':
                n = matchTokenSet(&cc.http_version.ts, data);
                if (!n) {
                    if (x == 'H')
                        GOTO(HTTP_REQ_URI_C);
                    GOTO(HTTP_ERROR);
                }
                outputFlush(&r->output);
                XASSERT(MATCH_CODE(n) < 6);
                r->version = versions[MATCH_CODE(n)>>1];
                consumed = MATCH_LENGTH(n);
                GOTO(HTTP_FINISHED);
            case ' ':
                n = _mm_movemask_epi8(_mm_cmpeq_epi8(data, cc.spaces));
                consumed = __builtin_ctz(~n);
                outputPush(&r->output, data, consumed);
                break;//just go on with spaces
            default:
                GOTO(HTTP_REQ_URI_C);
            }
            break;
        }
        STATE(HTTP_REQ_HTTPV) {
            int n = matchTokenSet(&cc.http_version.ts, data);
            if (!n) GOTO(HTTP_ERROR);
            XASSERT(MATCH_CODE(n) < 3);
            r->version = versions[MATCH_CODE(n)];
            consumed = MATCH_LENGTH(n);
            GOTO(HTTP_FINISHED);
        }
        STATE(HTTP_ERROR) {
            r->state = state;
            return Parse_Failure;
        }
        STATE(HTTP_FINISHED) {
            r->state = state;
            consumeInputIterator(&r->input, consumed);
            //check if we have no buffer problems
            if (outputFinish(&r->output))
                return Parse_Failure;
            //finalize uri
            if (r->uri_path)
                r->uri_path[r->uri_lenght] = 0;

            return Parse_Success;
        }
        }

        //skip space quickly
        if (state & HTTP_SKIP_SPACE) {
            int sm = _mm_movemask_epi8(_mm_cmpeq_epi8(data, cc.spaces));
            sm >>= consumed;

            consumed += __builtin_ctz(~sm);
            if (consumed != 16)
                state &= ~ HTTP_SKIP_SPACE;
        }

        consumeInputIterator(&r->input, consumed);
    }
}
/*
int sse_parse_request(struct sse_ngx_http_request_t * r, unsigned const char * input, int size) {
    const struct Constants * c = &C;

    int state = r->state,
        state_after_space = r->state_after_space,
        after_space_if_not_version = r->state_after_space_if_not_version;
    int bytes_in_pd = r->bytes_in_pd,
        bytes_in_wd = r->bytes_in_wd,
        consumed;

    __m128i     data, pd, nd, wd, *destination, *edge;
    const __m128i *source;

    nd          = r->prev_data;
    wd          = r->write_data;
    source      = (const __m128i*)(input);
    destination = r->wpos;
    edge        = r->wend;
    unsigned char tempbuf[16];

    for(;;) {
        consumed = 0;
        switch(state) {
        case PS_Initial:{
            PRINTSTATE(PS_Initial);
            __m128i tmp, mask1, mask2, mask3, mask4, mask5;

            data = _mm_add_epi8(data,
                     _mm_and_si128(c->tabs2spaces, \
                       _mm_cmpeq_epi8(data, c->tabs)));
            tmp  = _mm_shuffle_epi32(data, _MM_SHUFFLE(0,0,0,0));
            mask1= _mm_cmpeq_epi32(c->method1, tmp);
            mask2= _mm_cmpeq_epi32(c->method2, tmp);
            mask3= _mm_cmpeq_epi32(c->method3, tmp);
            tmp  = _mm_shuffle_epi32(data, _MM_SHUFFLE(1,1,0,0));
            mask4= _mm_cmpeq_epi32(c->method4, tmp);
            mask1= _mm_packs_epi32(mask1, mask2);
            mask3= _mm_packs_epi32(mask3, mask4);
            tmp = _mm_shuffle_epi8(data, c->method5);
            mask5 = _mm_cmpeq_epi16(tmp, c->method6);
            //mask id 0         1         2         3         4         5         6         7
            //mask1 = GET       PUT       POST      COPY      MOVE      LOCK      HEAD      PROP
            //        ****      ****      ****      ****      ****      ****      ****      ****
            //mask3 = PATCH     TRACE     DELETE    UNLOCK    MKCOL     OPTIONS   PROPFIND  PROPPATCH
            //        ****      ****      ****      ****      ****      ****          ****      ****
            //mask5 = PATCH     TRACE     DELETE    UNLOCK    MKCOL     OPTIONS   OPTIONS   PROPPATCH
            //            **        **        **        **        **        **          **          **
            tmp   = _mm_shuffle_epi8(mask5, c->method7);
            tmp   = _mm_and_si128(tmp, mask5);
            tmp   = _mm_or_si128(tmp, c->method7);
            tmp   = _mm_srai_epi16(tmp, 15);
            mask3 = _mm_and_si128(mask3, tmp);
            mask2 = _mm_or_si128(mask2, c->method8);
            mask3 = _mm_and_si128(mask3, mask2);
            //mask id 0         1         2         3         4         5         6         7
            //mask1 = GET       PUT       POST      COPY      MOVE      LOCK      HEAD      PROP
            //mask3 = PATCH     TRACE     DELETE    UNLOCK    MKCOL     OPTIONS   PROPFIND  PROPPATCH
            mask1 = _mm_and_si128(mask1, c->method9);
            mask3 = _mm_and_si128(mask3, c->method10);
            tmp   = _mm_hadd_epi16(mask1, mask3);
            tmp   = _mm_hadd_epi16(tmp, tmp);
            tmp   = _mm_hadd_epi16(tmp, tmp);
            tmp   = _mm_hadd_epi16(tmp, tmp);
            int result = _mm_extract_epi16(tmp, 0);
            if (!result) {
                GOTO(PS_BadState)
            }
            r->method = 1 << (result & 0xF);
            consumed  = result >> 8;
            SKIPSPACES(PS_Schema)
            break;
        }
        case PS_SkipSpaces: PS_SkipSpaces:{
            PRINTSTATE(PS_SkipSpaces);
            int bits = ~_mm_cmpmask_epi8(data, c->spaces);
            bits = __builtin_ctz(0x10000 | bits);
            if (bits == 0) {
                GOTO(PS_BadState)
            }
            if (bits < 16) {
                state = state_after_space;
                state_after_space = PS_BadState;
            }
            consumed = bits;
            break;
        }
        case PS_Schema: {
            PRINTSTATE(PS_Schema);
            //schema must start from A-Za-z
            int ch = (0xFF & _mm_extract_epi16(data, 0));
            if (ch == '/') {
                GOTO(PS_UriStart)
            }
            ch |= 0x20;
            if (ch < 'a' || ch > 'z') {
                GOTO(PS_BadState)
            }
            //count number of A-Za-z0-9\.\- , more than 11 is too much
            __m128i mask = _mm_masktest_si128(c, data, c->alnumDotMinusBitmask);
            int bits = __builtin_ctz(0x8000 | _mm_movemask_epi8(mask));
            if (unlikely(bits > 11)) {
                MOVE(PS_BadState)
            }
            //check for "://" after schema
            int sc = 0x1 & (_mm_cmpmask_epi8(data, c->semicolons)>>bits);
            sc    |= 0x6 & (_mm_cmpmask_epi8(data, c->slashes)>>bits);
            if (unlikely(sc !=7)) {
                MOVE(PS_BadState)
            }
            //save schema position and consume sizeof(schema)+sizeof("://") bytes
            r->schema_start = (unsigned char *)r->wpos;
            r->schema_end   = r->schema_start + bits;
            _mm_store_a(c, destination, edge, _mm_mask(c, data, bits), GOTO(PS_TooLong));
            consumed = bits + 3;//schema + "://"
            MOVE(PS_HostnameStart)
        }
        case PS_HostnameStart: {
            PRINTSTATE(PS_HostnameStart);
            int ch = 0xFF & _mm_extract_epi16(data, 0);
            switch(ch) {
            case '[':
                r->host_start = (unsigned char*)destination;
                consumed = 1;
                MOVE(PS_HostnameLiteral)
            case '.':
            case '-':
                GOTO(PS_BadState)
            default: {
                __m128i mask = _mm_masktest_si128(c, data, c->alnumDotMinusBitmask);
                int bits = __builtin_ctz(0x10000 | _mm_movemask_epi8(mask));
                if (!bits) {
                    GOTO(PS_BadState)
                }
                consumed = bits;
                r->host_start = (unsigned char*)destination;
                r->host_end = r->host_start + bits;
                _mm_store_a(c, destination, edge, _mm_mask(c, data, bits), GOTO(PS_TooLong));
                if (bits == 16) {
                    MOVE(PS_Hostname)
                }
                MOVE(PS_HostnameEnd)
              }
            }
            break;
        }
        case PS_Hostname: {
            PRINTSTATE(PS_Hostname);
            int mask = _mm_masktest(c, data, c->alnumDotMinusBitmask);
            int bits = __builtin_ctz(0x10000 | mask);
            consumed = bits;
            r->host_end = ((unsigned char*)destination) + bits;
            //if bits == 0, then GOTO hostname_end
            //if bits != 0, store data
            //if bits < 16, then MOVE hostname_end
            if (!bits) {
                GOTO(PS_HostnameEnd)
            }
            _mm_store_a(c, destination, edge, _mm_mask(c, data, bits), GOTO(PS_TooLong));
            if (bits < 16) {
                MOVE(PS_HostnameEnd);
            }
            break;
        }
        case PS_HostnameEnd: PS_HostnameEnd:{
            PRINTSTATE(PS_HostnameEnd);
            int c = _mm_extract_epi16(data, 0);
            switch (c & 0xFF) {
            case ':':
                GOTO(PS_Port)
            case '/':
                GOTO(PS_UriStart)
            case '\r':
            case '\n':
                r->http_major = 0;
                r->http_minor = 9;
                r->uri_start = r->schema_end + 1;
                r->uri_end = r->schema_end + 2;
                GOTO(PS_Eol)
            case ' ':
                r->uri_start = r->schema_end + 1;
                r->uri_end = r->schema_end + 2;
                SKIPSPACES_NOW(PS_Version)
            default:
                GOTO(PS_BadState);
            }
            break;
        }
        case PS_Port: PS_Port:{
            PRINTSTATE(PS_Port);
            //beware: we arrive here with leading ':' !!
            int mask = _mm_movemask_epi8(
                          _mm_or_si128(
                             _mm_cmpgt_epi8(data, c->nine),
                             _mm_cmplt_epi8(data, c->zero)));
            int bits = __builtin_ctz(0x8000 | (mask>>1));
            if (!bits || bits > 8) {
                GOTO(PS_BadState)
            }
            _mm_store_a(c, destination, edge, _mm_mask(c, data, bits), GOTO(PS_TooLong));
            r->port_end = r->host_end + bits + 1;
            consumed = bits+1;
            MOVE(PS_PortEnd)
        }
        case PS_PortEnd: {
            PRINTSTATE(PS_PortEnd);
            int c = _mm_extract_epi16(data, 0);
            switch (c & 0xFF) {
            case '/':
                GOTO(PS_UriStart)
            case '\r':
            case '\n':
                r->http_major = 0;
                r->http_minor = 9;
                r->uri_start = r->schema_end + 1;
                r->uri_end = r->schema_end + 2;
                GOTO(PS_Eol)
            case ' ':
                r->uri_start = r->schema_end + 1;
                r->uri_end = r->schema_end + 2;
                SKIPSPACES_NOW(PS_Version);
            default:
                state = PS_BadState;
            }
            break;
        }
        case PS_HostnameLiteral: {
            PRINTSTATE(PS_HostnameLiteral);
            int mask = _mm_masktest(c, data, c->hostnameLiteralBitmask);
            int bits = __builtin_ctz(0x10000 | mask);
            consumed = bits;
            r->host_end = ((unsigned char*)destination) + bits;
            //if bits == 0, then GOTO hostname_end
            //if bits != 0, store data
            //if bits < 16, then MOVE hostname_end
            if (!bits) {
                GOTO(PS_HostnameEnd)
            }
            _mm_store_a(c, destination, edge, _mm_mask(c, data, bits), GOTO(PS_TooLong));
            if (bits < 16) {
                state = PS_HostnameLiteralEnd;
            }
            break;
        }
        case PS_HostnameLiteralEnd: {
            PRINTSTATE(PS_HostnameLiteralEnd);
            int c = _mm_extract_epi16(data, 0);
            if ((c & 0xFF) != ']') {
                GOTO(PS_BadState)
            }
            consumed = 1;
            MOVE(PS_HostnameEnd)
        }
        case PS_Version: {
            PRINTSTATE(PS_Version);
            r->http_major = 0;
            r->http_minor = 9;
            //codes
            //              0 1 2 3 4 5 6 7 8 9 A B C D E F
            //              r n n H T T P / 1 . Z 0 1 r n n
            //\n            0 0 1 0 ? ? ? ? ? ? 0 ? ? ? ? ?
            //\r\n          1 1 0 0 0 ? ? ? ? ? 0 ? ? ? ? ?
            //HTTP/1.0\n    0 0 0 1 1 1 1 1 1 1 0 1 0 0 0 1
            //HTTP/1.1\n    0 0 0 1 1 1 1 1 1 1 0 0 1 0 0 1
            //HTTP/1.0\r\n  0 0 0 1 1 1 1 1 1 1 0 1 0 1 1 0
            //HTTP/1.1\r\n  0 0 0 1 1 1 1 1 1 1 0 0 1 1 1 0

            //code + 0x2809
            //              0 1 2 3 4 5 6 7 8 9 A B C D E F
            //              r n n H T T P / 1 . Z 0 1 r n n
            //\n            1 0 1 1 ? ? ? ? ? ? 0 ? ? ? ? ?
            //\r\n          0 0 1 1 0 ? ? ? ? ? 0 ? ? ? ? ?
            //HTTP/1.0\n    1 0 0 0 0 0 0 0 0 0 1 0 1 1 0 1
            //HTTP/1.1\n    1 0 0 0 0 0 0 0 0 0 1 1 1 1 0 1
            //HTTP/1.0\r\n  1 0 0 0 0 0 0 0 0 0 1 0 1 0 0 1
            //HTTP/1.1\r\n  1 0 0 0 0 0 0 0 0 0 1 1 1 0 0 1

            //(code + 0x2809) & 0x9404
            //              0 1 2 3 4 5 6 7 8 9 A B C D E F
            //              r n n H T T P / 1 . Z 0 1 r n n
            //\n            0 0 1 0 0 0 0 0 0 0 0 0 ? 0 0 ?
            //\r\n          0 0 1 0 0 ? 0 0 0 0 0 0 ? 0 0 ?
            //HTTP/1.0\n    0 0 0 0 0 0 0 0 0 0 1 0 1 0 0 1
            //HTTP/1.1\n    0 0 0 0 0 0 0 0 0 0 1 0 1 0 0 1
            //HTTP/1.0\r\n  0 0 0 0 0 0 0 0 0 0 1 0 1 0 0 1
            //HTTP/1.1\r\n  0 0 0 0 0 0 0 0 0 0 1 0 1 0 0 1
            int mask = _mm_cmpmask_epi8(_mm_shuffle_epi8(data, c->HTTP1xHelper), c->HTTP1x);
            int code = (mask + 0x2809) & 0x9404;

            if (code & 0x4) {
                _mm_flush(c, destination, edge, wd, bytes_in_wd, GOTO(PS_TooLong));
                GOTO(PS_Eol)
            }
            if (code == 0x9400) {
                int ch = _mm_extract_epi16(data, 3);
                ch = (ch >> 8) - 0x30;
                r->http_major = 1;
                r->http_minor = ch;
                consumed = 8;
                _mm_flush(c, destination, edge, wd, bytes_in_wd, GOTO(PS_TooLong));
                MOVE(PS_Eol)
            }
            state = after_space_if_not_version;
            break;
        }
        case PS_UriStart: PS_UriStart:{
            PRINTSTATE(PS_UriStart);

            after_space_if_not_version = PS_UriAddSpace;
            bytes_in_wd  = 0;
            r->uri_start = (unsigned char *)destination;
            GOTO(PS_UriCheckSymbols);
        }
        case PS_UriAddSpace:
            _mm_store_1(c, destination, edge, wd, c->spaces, bytes_in_wd, GOTO(PS_TooLong));
            //fall through
        case PS_UriCheckSlash: PS_UriCheckSlash: {
            PRINTSTATE(PS_UriCheckSlash);
            int dirmask = ~_mm_cmpmask_epi8(_mm_shuffle_epi32(data, 0), c->directoryPatterns);
            int mask    = _mm_masktest(c, data, c->uriBitmask);
            if (!(dirmask & 0x000F)) {// "/../"
                if (!r->path_depth) {
                    GOTO(PS_BadState)
                }
                const unsigned char * newdest = r->uri_start + r->path_offsets[--r->path_depth];
                _mm_revert(c, destination, wd, bytes_in_wd, newdest);
                consumed = 3;
                break;
            }
            if (!(dirmask & 0x0070)) {// "/./"
                consumed = 2;
                break;
            }
            if (!(dirmask & 0x0300)) { // "//"
                consumed = 1;
                break;
            }
            if (!(dirmask & 0x0100)) {
                if (r->path_depth >= MAX_PATH_DEPTH) {
                    GOTO(PS_BadState)
                }
                r->path_offsets[r->path_depth++] = (unsigned char*)destination + bytes_in_wd - r->uri_start;
                mask &= 0xFFFE;
            }
            int bits = __builtin_ctz(0x10000 | mask);
            if (bits) {
                __m128i tmp = _mm_sub_epi8(data,
                                           _mm_and_si128(c->plus2spaces, \
                                           _mm_cmpeq_epi8(data, c->plus)));
                _mm_store_n(c, destination, edge, wd, tmp, bytes_in_wd, bits, GOTO(PS_TooLong));
                consumed = bits;
            }
            if (bits < 16) {
                MOVE(PS_UriCheckSymbols)
            }
            break;
        }
        case PS_UriCheckSymbols: PS_UriCheckSymbols:{
            PRINTSTATE(PS_UriCheckSymbols);
            int ch = _mm_extract_epi16(data, 0) & 0xFF;
            switch(ch) {
            case '/':
                GOTO(PS_UriCheckSlash)
            case ' ':
                r->uri_end = (unsigned char*)destination + bytes_in_wd;
                SKIPSPACES_NOW(PS_Version)
            case '\r':
            case '\n':
                r->uri_end = (unsigned char*)destination + bytes_in_wd;
                r->http_major = 0;
                r->http_minor = 9;
                _mm_flush(c, destination, edge, wd, bytes_in_wd, GOTO(PS_TooLong));
                GOTO(PS_Eol)
            case '?':
                r->args_start = (unsigned char*)destination + bytes_in_wd;
                _mm_store_1(c, destination, edge, wd, data, bytes_in_wd, GOTO(PS_TooLong));
                consumed = 1;
                MOVE(PS_UriArgs)
            case '#':
                _mm_store_1(c, destination, edge, wd, data, bytes_in_wd, GOTO(PS_TooLong));
                consumed = 1;
                MOVE(PS_UriCopyAsIs)
            case '%':{
                __m128i dec = _mm_decode_quoted_si128(c, data);
                if (!_mm_extract_epi16(dec, 0)) {
                    GOTO(PS_BadState)
                }
                _mm_store_1(c, destination, edge, wd, dec, bytes_in_wd, GOTO(PS_TooLong));
                consumed = 3;
                break;}
                //hex encoded
            default:
                if (!(0x1 & _mm_masktest(c, data, c->uriBitmask))) {
                    GOTO(PS_UriCheckSlash)
                }
                GOTO(PS_BadState)
            }
            break;
        }
        case PS_UriArgs: PS_UriArgs: {
            PRINTSTATE(PS_UriArgs);
            after_space_if_not_version = PS_UriArgs;
            int mask = _mm_masktest(c, data, c->uriArgsBitmask);
            int bits = __builtin_ctz(0x10000 | mask);
            if (bits) {
                __m128i tmp = _mm_sub_epi8(data,
                                           _mm_and_si128(c->plus2spaces, \
                                           _mm_cmpeq_epi8(data, c->plus)));
                _mm_store_n(c, destination, edge, wd, tmp, bytes_in_wd, bits, GOTO(PS_TooLong));
                consumed = bits;
            }
            if (bits < 16) {
                MOVE(PS_UriArgsCheckSymbols);
            }
            break;
        }
        case PS_UriArgsCheckSymbols: {
            PRINTSTATE(PS_ArgsCheckSymbols);
            int ch = _mm_extract_epi16(data, 0) & 0xFF;
            switch(ch) {
            case ' ':
                r->uri_end = (unsigned char*)destination + bytes_in_wd;
                SKIPSPACES_NOW(PS_Version)
            case '\r':
            case '\n':
                r->uri_end = (unsigned char*)destination + bytes_in_wd;
                r->http_major = 0;
                r->http_minor = 9;
                _mm_flush(c, destination, edge, wd, bytes_in_wd, GOTO(PS_TooLong));
                GOTO(PS_Eol)
            case '#':
                GOTO(PS_UriCopyAsIs)
            case '%':{
                __m128i dec = _mm_decode_quoted_si128(c, data);
                if (!_mm_extract_epi16(dec, 0)) {
                    GOTO(PS_BadState)
                }
                _mm_store_1(c, destination, edge, wd, dec, bytes_in_wd, GOTO(PS_TooLong));
                consumed = 3;
                break;}
                //hex encoded
            default:
                if (!(0x1 & _mm_masktest(c, data, c->uriArgsBitmask))) {
                    GOTO(PS_UriArgs)
                }
                GOTO(PS_BadState)
            }
            break;
        }
        case PS_UriCopyAsIs: PS_UriCopyAsIs: {
            PRINTSTATE(PS_UriCopyAsIs);
            after_space_if_not_version = PS_UriCopyAsIs;
            int mask = _mm_masktest(c, data, c->uriAsIsBitmask);
            int bits = __builtin_ctz(0x10000 | mask);
            if (bits) {
                _mm_store_n(c, destination, edge, wd, data, bytes_in_wd, bits, GOTO(PS_TooLong));
                consumed = bits;
            }
            if (bits < 16) {
                MOVE(PS_UriCopyAsIsCheckSymbols)
            }
            break;
        }
        case PS_UriCopyAsIsCheckSymbols: {
            PRINTSTATE(PS_UriCopyAsIsCheckSymbols);
            int ch = _mm_extract_epi16(data, 0) & 0xFF;
            switch(ch) {
            case ' ':
                r->uri_end = (unsigned char*)destination + bytes_in_wd;
                SKIPSPACES_NOW(PS_Version)
            case '\r':
            case '\n':
                r->uri_end = (unsigned char*)destination + bytes_in_wd;
                r->http_major = 0;
                r->http_minor = 9;
                _mm_flush(c, destination, edge, wd, bytes_in_wd, GOTO(PS_TooLong));
                GOTO(PS_Eol)
            default:
                GOTO(PS_BadState)
            }
            break;
        }
        case PS_Eol: PS_Eol: {
            PRINTSTATE(PS_Eol);
            __m128i tmp = _mm_and_si128(
                            c->newline2,
                            _mm_cmpeq_epi8(
                              c->newline1,
                              _mm_shuffle_epi32(data, _MM_SHUFFLE(0,0,0,0))));
            int flags_nn = _mm_movemask_epi8(
                             _mm_cmpeq_epi32(tmp, c->newline2));
            if (flags_nn) {
                consumed = 0xF & (((flags_nn & 0x4332) * 0x1111) >> 12);
                GOTO(PS_Finish);
            }

            consumed = 1;
            //check \r\n and add 1 byte to consumed if there is \r\n
            int ch = _mm_extract_epi16(tmp, 2);
            if (ch == 0x00FF) {
                GOTO(PS_BadState)
            }
            if (ch == 0xFFFF) {
                ++consumed;
            }
            MOVE(r->state_after_newline)
        }
        case PS_HeaderStart: {
            PRINTSTATE(PS_HeaderStart);
            r->headers_start = (const unsigned char*)destination;
            r->headers_end = (const unsigned char*)destination;
            r->state_after_newline = PS_HeaderNext;
            GOTO(PS_HeaderName)
        }
        case PS_HeaderNext: {
            PRINTSTATE(PS_HeaderNext);
            int ch = _mm_extract_epi16(data, 0) & 0xFF;
            if (ch == ' ')
                GOTO(PS_HeaderValue);
        }
        case PS_HeaderName: PS_HeaderName: {
            PRINTSTATE(PS_HeaderName);
            int mask = _mm_masktest(c, data, c->headerNameBitmask);
            int bits = __builtin_ctz(0x10000 | mask);
            consumed = bits;
            //always store something to have \0 at the end of header name
            _mm_store_a(c, destination, edge, _mm_mask(c, data, bits), GOTO(PS_TooLong));
            if (bits < 16) {
                MOVE(PS_HeaderNameCheckSymbols)
            }
            if (!bits) {
                GOTO(PS_HeaderNameCheckSymbols)
            }
            break;
        }
        case PS_HeaderNameCheckSymbols: PS_HeaderNameCheckSymbols: {
            PRINTSTATE(PS_HeaderNameCheckSymbols);
            int ch = _mm_extract_epi16(data, 0);
            switch(ch & 0xFF) {
            case ':':
                consumed = 1;
                if (ch == 0x203A) {
                    SKIPSPACES(PS_HeaderValue)
                }
                MOVE(PS_HeaderValue)
            default:
                GOTO(PS_BadState)
            }
            break;
        }
        case PS_HeaderValue: PS_HeaderValue: {
            PRINTSTATE(PS_HeaderValue);
            int mask = _mm_masktest(c, data, c->headerValueBitmask);
            int bits = __builtin_ctz(0x10000 | mask);
            consumed = bits;
            _mm_store_a(c, destination, edge, _mm_mask(c, data, bits), GOTO(PS_TooLong));
            if (bits < 16) {
                MOVE(PS_HeaderValueCheckSymbols)
            }
            break;
        }
        case PS_HeaderValueCheckSymbols:{
            PRINTSTATE(PS_HeaderValueCheckSymbols);
            int ch = _mm_extract_epi16(data, 0);
            switch(ch & 0xFF) {
            case '\r':
            case '\n':
                r->headers_end = (const unsigned char*)destination;
                GOTO(PS_Eol)
            default:
                GOTO(PS_BadState)
            }
        }
        case PS_TooLong: PS_TooLong: {
             PRINTSTATE(PS_TooLong);
             return SPR_TOO_LONG;
        }
        case PS_Finish: PS_Finish: {
            PRINTSTATE(PS_Finish);
            //FIXME: return number of parsed bytes
            return SPR_COMPLETED;
        }
        case PS_BadState: PS_BadState:
        default:
            PRINTSTATE(PS_BadState);
            return SPR_BAD_REQUEST;
        }
        bytes_in_pd -= consumed;
    }
}

*/





