#ifndef HTTP_SSE_H
#define HTTP_SSE_H

#include <tmmintrin.h>

#define likely(a)	__builtin_expect((a), 1)
#define unlikely(a)	__builtin_expect((a), 0)
#define FORCEINLINE  __attribute__((always_inline))
//comment out debug for testing performance
#define __DEBUG__

struct Constants {
    //shuffle
    __m128i shuffle1[2], shuffle2[2], shuffle3[2], shufnb, shufpb;
    //bytes
    __m128i spaces, semicolons, slashes, tabs, plus, nine, zero, _n, _r;
    //conversion
    __m128i tabs2spaces, plus2spaces;
    //_mm_masktest
    __m128i masktest1, masktest2;
    //end of line
    __m128i newline1, newline2;
    //decode quoted
    __m128i dq0, dq1, dq2, dq3, dq4, dq5;
    //http method
    __m128i method1, method2, method3, method4, method5, method6, method7, method8, method9, method10;
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
};

void sse_init_constants();

#define _mm_blend(a,b,mask) \
    _mm_or_si128(_mm_and_si128(mask, a),_mm_andnot_si128(mask, b))

#define _mm_store_1(c, wpos, wend, wdata, data, bytes, onerror) \
    do {\
        ++bytes;\
        wdata = _mm_alignr_epi8(data, wdata, 1);\
        if (bytes >= 16) {\
            _mm_store_si128(wpos++, wdata);\
            if (unlikely(wpos >= wend)) {onerror;} \
            bytes = 0;\
        }\
    }while(0);

#define _mm_store_a(c, wpos, wend, data, onerror) \
    do {\
        _mm_store_si128(wpos++, data);\
        if (unlikely(wpos >= wend)) {onerror;} \
    }while(0);

#define _mm_store_n(c, wpos, wend, wdata, data, bytes, n, onerror) \
    do {\
        int k = bytes+n;\
        if (k >= 16) {\
            wdata = _mm_align(c, wdata, data, bytes);\
            _mm_store_si128(wpos++, wdata);\
            if (unlikely(wpos >= wend)) {onerror} \
            wdata = _mm_align_up(c, data, n);\
            bytes = k - 16;\
        } else {\
            wdata = _mm_align(c, wdata, data, n);\
            bytes = k;\
        }\
    }while(0);

#define _mm_flush(c, wpos, wend, wdata, bytes, onerror) \
    if(bytes) {\
        wdata = _mm_align(c, wdata, _mm_setzero_si128(),16-bytes);\
        _mm_store_si128(wpos++, wdata);\
        bytes = 0;\
        if (unlikely(wpos >= wend)) {onerror} \
    }

#define _mm_revert(c, wpos, wdata, bytes, newpos) \
    do {\
        long newpos_lng = (long)newpos;\
        bytes = newpos_lng & 0xF;\
        wpos  = (__m128i*)(newpos_lng &~ 0xF);\
        wdata = _mm_align_up(c, _mm_load_si128(wpos), bytes);\
    }while(0);

inline static int _mm_cmpmask_epi8(__m128i source, __m128i mask) {
    return _mm_movemask_epi8(_mm_cmpeq_epi8(source, mask));
} FORCEINLINE

inline static __m128i _mm_mask(const struct Constants * c, __m128i d, int n) {
    __m128i mask = _mm_lddqu_si128((const __m128i*)(((const char*)c->shuffle2)+16-n));
    return _mm_and_si128(d, mask);
} FORCEINLINE

inline static __m128i _mm_align(const struct Constants * c, __m128i pd, __m128i nd, int n) {
    __m128i mask1 = _mm_lddqu_si128((const __m128i*)(((const char*)c->shuffle1)+n));
    __m128i mask2 = _mm_lddqu_si128((const __m128i*)(((const char*)c->shuffle2)+n));
    return _mm_blend(_mm_shuffle_epi8(pd, mask1), _mm_shuffle_epi8(nd, mask1), mask2);
} FORCEINLINE

inline  static __m128i _mm_align_up(const struct Constants * c, __m128i data, int n) {
    __m128i mask1 = _mm_lddqu_si128((const __m128i*)(((const char*)c->shuffle1)+n));
    return _mm_shuffle_epi8(data, mask1);
} FORCEINLINE

inline static __m128i _mm_decode_quoted_si128(const struct Constants * c, __m128i data) {
    //для массового сравнения размножим байты 1 и 2 в последовательности "%xx"
    __m128i muxed = _mm_shuffle_epi8(data, c->dq0);
    //в байтах 4-7 и 12-15 будет сравниваться a-zA-Z, lowercase его
    muxed = _mm_or_si128(muxed, c->dq1);
    //сравним (c1>'0'-1, c1>'9', c1>'a'-1, c1>'f')...
    //должно получиться FF00FF00FF00FF00???????
    __m128i mask  = _mm_cmpgt_epi8(muxed, c->dq2);
    mask = _mm_cmpeq_epi16(mask, c->dq3);
    //вычтем константы '0' и 'a'-9 из соответствующих байт
    muxed = _mm_subs_epu8(muxed, c->dq4);
    //затрем неправильные позиции чтоб не мешали
    muxed = _mm_and_si128(muxed, mask);
    //что у нас получилось:
    //  C1_09   0   C1_af   0   C2_09   0   C2_af   0
    //    *16         *16         *1          *1
    //          +                       +
    //                      +
    //  byte_C2C1
    //теперь объединим байты:
    muxed = _mm_madd_epi16(muxed, c->dq5);
    muxed = _mm_hadd_epi32(muxed, muxed);
    return muxed;
}

inline static __m128i _mm_masktest_si128(const struct Constants * cc,
                        __m128i source,
                        __m128i mask)
{
    __m128i mask1 = _mm_shuffle_epi8(mask, source);
    __m128i mask2 = _mm_and_si128(
                cc->masktest2,
                _mm_srli_epi16(source, 4));
    __m128i mask3 = _mm_shuffle_epi8(
                cc->masktest1,
                mask2);
    __m128i mask4 = _mm_and_si128(
                mask3,
                mask1);
    return _mm_cmpeq_epi8(
          _mm_setzero_si128(),
          mask4);
} FORCEINLINE

inline static int _mm_masktest(const struct Constants * cc,
                        __m128i source,
                        __m128i mask)
{
    return _mm_movemask_epi8(_mm_masktest_si128(cc, source, mask));
} FORCEINLINE

#ifdef __DEBUG__
void printm128(const char * msg, __m128i m);
#define PRINTM(text, m) printm128(text, m)
#define PRINTSTATE(state) printf("%s\n", #state)
#else
#define PRINTM(text, m)
#define PRINTSTATE(state)
#endif

#define MAX_PATH_DEPTH 64

struct sse_ngx_http_request_t {
    int state,
        state_after_space,
        state_after_space_if_not_version,
        state_after_newline;

    int bytes_in_pd, bytes_in_wd;
    __m128i      prev_data, write_data;
    __m128i    * wpos, * wend;
    int          method, http_minor, http_major;
    unsigned char       * wpos_char;
    const unsigned char * schema_start, * schema_end;
    const unsigned char * host_start, * host_end, * port_end;
    const unsigned char * uri_start, * uri_end, * args_start;
    const unsigned char * headers_start, * headers_end;
    int          path_depth;
    short        path_offsets[MAX_PATH_DEPTH];
    void       * pbuffer;

};

enum SseParseRequestResult {
    SPR_NEED_MORE_DATA,
    SPR_BAD_REQUEST,
    SPR_TOO_LONG,
    SPR_COMPLETED,
    
    SPH_FORBIDDEN,
    SPH_PASSED,
};

void sse_ngx_request_init(struct sse_ngx_http_request_t * r, void * membuf, long membuf_size);
int  sse_parse_request(struct sse_ngx_http_request_t * r, unsigned const char * input, int size);
int  sse_parse_headers(struct sse_ngx_http_request_t * r);
#endif // HTTP_SSE_H

