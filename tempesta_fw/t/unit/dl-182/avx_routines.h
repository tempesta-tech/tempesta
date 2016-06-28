#ifndef AVX_ROUTINES_H
#define AVX_ROUTINES_H

#ifdef __ENABLE_AVX__

#pragma GCC push_options
#pragma GCC target("sse","sse2","sse3","ssse3","sse4.1","avx","avx2")
#define _MM_MALLOC_H_INCLUDED
#include <x86intrin.h>
#undef  _MM_MALLOC_H_INCLUDED
#pragma GCC pop_options

extern const unsigned char __c_avx_data[];
extern const unsigned char __c_avx_header_names[];
extern const unsigned char __c_avx_method[];

#define __constants2 _mm256_loadu_si256((const __m256i*)(__c_avx_data+32)
#define _mm256_loadu(p) _mm256_lddqu_si256((const __m256i*)p)
#define _mm256_load(p)  _mm256_load_si256((const __m256i*)p)

#define __DEFINE_AVX_VARIABLES \
    register __m256i HEADER_CHARSET /*asm("xmm15")*/; \
    register __m256i __avx_constants1 /*asm("xmm14")*/; \
    register __m256i __avx_constants2 /*asm("xmm13")*/; \
    register __m256i __avx_constants3 /*asm("xmm12")*/; \
    unsigned char __avx_realign[64] __attribute__((aligned(64))); \
    do {\
        __m256i tmp      = _mm256_load(__c_avx_data);\
        HEADER_CHARSET   = _mm256_permute2f128_si256(tmp, tmp, 0x00);\
        __m256i tmp3     = _mm256_permute4x64_epi64(tmp, 0xEE);\
        tmp3 = _mm256_unpacklo_epi32(tmp3, tmp3);\
        __avx_constants1 = tmp3;\
        __avx_constants2 = _mm256_load(__c_avx_data+32);\
        __avx_constants3 = _mm256_load(__c_avx_data+64);\
    }while(0);

#define AVX_SKIP_HEADER_BODY(s, n) do{ \
        __m256i __avx_constants2 = _mm256_load(__c_avx_data+32);\
        int mask = -1;\
        while(n >= 32) {\
            __m256i text = _mm256_loadu(s), mask1;\
            AVX_HDR_VALUE(mask1, text);\
            mask = _mm256_movemask_epi8(mask1)+1;\
            if (mask) break;\
            s += 32;\
            n -= 32;\
        };\
        mask = __builtin_ctz(mask);\
        s += mask;\
        n -= mask;\
    }while(0);

#define __mm_align(value, n) do { \
    _mm256_store_si256((__m256i*)__avx_realign, value);\
    _mm256_store_si256((__m256i*)(__avx_realign+32, _mm256_setzero_si256()));\
    value = _mm256_loadu_si256((__m256i*)(__avx_realign+n));\
    }while(0);

enum {
    __AVX_C1_LOWERCASE1  = 0x00,
    __AVX_C1_LOWERCASE2  = 0x55,
    __AVX_C1_SPACES      = 0xAA,
    __AVX_C1_SEMICOLON   = 0xFF,
    __AVX_C2_CHARSET_M1  = 0x00,
    __AVX_C2_CHARSET_M2  = 0x55,
    __AVX_C2_CONTROL1    = 0xAA,
    __AVX_C2_CONTROL2    = 0xFF,
    __AVX_C3_TABS        = 0x00,
};

#define AVX_HDR_VALUE(out, in) do { \
        out = _mm256_and_si256(\
        _mm256_cmpgt_epi8(text, _mm256_shuffle_epi32(__avx_constants2, __AVX_C2_CONTROL1)),\
        _mm256_cmpgt_epi8(_mm256_shuffle_epi32(__avx_constants2, __AVX_C2_CONTROL2), in));\
    }while(0);

#define AVX_LOWERCASE(out, in) do { \
        __m256i c1 = _mm256_cmpgt_epi8(in, \
            _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_LOWERCASE1)); \
        __m256i c2 = _mm256_cmpgt_epi8(in, \
            _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_LOWERCASE2)); \
        __m256i c3 = _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_SPACES); \
        c3 = _mm256_and_si256(c1, c3); \
        c3 = _mm256_andnot_si256(c2, c3); \
        out = _mm256_or_si256(in, c3); \
    } while(0);

#define AVX_MATCH_CHARSET(result, text, charset) do { \
        __m256i mask1 = _mm256_shuffle_epi8( \
                    charset, text); \
        __m256i mask2 = _mm256_and_si256( \
                    _mm256_shuffle_epi32(__avx_constants2, __AVX_C2_CHARSET_M1), \
                    _mm256_srli_epi16(text, 4)); \
        __m256i mask3 = _mm256_shuffle_epi8( \
                    _mm256_shuffle_epi32(__avx_constants2, __AVX_C2_CHARSET_M2), \
                    mask2); \
        __m256i mask4 = _mm256_and_si256( \
                    mask3, mask1); \
        result = _mm256_cmpeq_epi8( \
                    mask4, _mm256_setzero_si256()); \
    } while(0);

//==================================================
//DATA#  0low 0hi  1low 1hi  2low 2hi  3low 3hi
//DWORD#
// 0     Host Tran X-Fo Cont Cach Cook Conn User
// 1          sfer rwar ent- e-Co ie   ecti -age
// 2     Type -Enc ded- Leng ntro g    on   nt
// 3          odin For  th   l
//==================================================

#define AVX_MATCH_HEADER_NAME(result, text) do {\
    /*mask 1 = rows 0-1, columns 0low-1hi*/\
    __m256i mask1 = _mm256_cmpeq_epi64(\
        _mm256_and_si256(_mm256_permute4x64_epi64(text, 0x00),\
                         _mm256_load(__c_avx_header_names)),\
        _mm256_load((__c_avx_header_names+32)));\
    /*mask 2 = rows 0-1, columns 2low-3hi*/\
    __m256i mask2 = _mm256_cmpeq_epi64(\
        _mm256_and_si256(_mm256_permute4x64_epi64(text, 0x00),\
                         _mm256_load(__c_avx_header_names+64)),\
        _mm256_load((__c_avx_header_names+96)));\
    /*mask 3 = rows 2-3, columns 0low-1hi*/\
    __m256i mask3 = _mm256_cmpeq_epi64(\
        _mm256_and_si256(_mm256_permute4x64_epi64(text, 0x55),\
                         _mm256_load(__c_avx_header_names+128)),\
        _mm256_load((__c_avx_header_names+160)));\
    /*mask 4 = rows 2-3, columns 2low-3hi*/\
    __m256i mask4 = _mm256_cmpeq_epi64(\
        _mm256_and_si256(_mm256_permute4x64_epi64(text, 0x95),\
                         _mm256_load(__c_avx_header_names+192)),\
        _mm256_load((__c_avx_header_names+224)));\
    /*extract mask for host*/\
    int bm = 0x1 & _mm256_movemask_epi8(mask1);\
    /*combine mask1 and mask3*/\
    mask1 = _mm256_and_si256(_mm256_permute4x64_epi64(mask1, 0xe7),\
                             mask3);\
    mask1 = _mm256_and_si256(mask1, _mm256_blend_epi32(mask1, mask4, 0x0c));\
    /*combine mask2 and mask4*/\
    mask2 = _mm256_and_si256(mask2, _mm256_blend_epi32(mask2, mask4, 0xf3));\
    bm |= 0x05040302 & _mm256_movemask_epi8(mask1);\
    bm |= 0x09080706 & _mm256_movemask_epi8(mask2);\
    bm = bm | (bm>>16);\
    bm = bm | (bm>>8);\
    result = 0xFF & bm;} while(0);

#define AVX_HDRID_TO_TAG(out, n) do {\
    static const int ids[10] = {\
        TFW_HTTP_HDR_RAW,\
        TFW_HTTP_HDR_HOST,\
        TFW_HTTP_HDR_CONTENT_TYPE,\
        TFW_HTTP_HDR_TRANSFER_ENCODING,\
        TFW_HTTP_HDR_X_FORWARDED_FOR,\
        TFW_HTTP_HDR_CONTENT_LENGTH,\
        TFW_HTTP_HDR_RAW,\
        TFW_HTTP_HDR_COOKIE,\
        TFW_HTTP_HDR_CONNECTION,\
        TFW_HTTP_HDR_USER_AGENT,\
    };\
    BUG_ON(n < 0 || n >= ARRAY_SIZE(ids));\
    out = ids[n];}while(0);

#define AVX_HDRID_TO_STATE(out, n) do {\
    static const int ids[10] = {\
        RGen_HdrOther,\
        Req_HdrHostV,\
        Req_HdrContent_TypeV,\
        Req_HdrTransfer_EncodingV,\
        Req_HdrX_Forwarded_ForV,\
        Req_HdrContent_LengthV,\
        Req_HdrCache_ControlV,\
        Req_HdrCookieV,\
        Req_HdrConnectionV,\
        Req_HdrUser_AgentV,\
    };\
    BUG_ON(n < 0 || n >= ARRAY_SIZE(ids));\
    out = ids[n];}while(0);

#define AVX_QUICK_PARSE_METHOD(method_name_out, nextstate) \
    if (__data_available(p, 32)) {\
        /* load 32 bytes of text, and replace tabs with spaces */\
        __m256i text = _mm256_loadu(p);\
        __m256i tabs = _mm256_shuffle_epi32(__avx_constants3, __AVX_C3_TABS);\
        tabs = _mm256_cmpeq_epi8(text, tabs);\
        __m256i spaces = _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_SPACES);\
        text = _mm256_blendv_epi8(text, spaces, tabs);\
        /* lowercase all characters */\
        text = _mm256_or_si256(text, spaces);\
        __m256i mdata = _mm256_load_si256((const __m256i*)__c_avx_method);\
        /* extract spaces mask: first space is end of method, next non-space */\
        /* after spaces after method is beginning of the url */\
        spaces = _mm256_cmpeq_epi8(text, spaces);\
        /* terminate method name with zero and compare it using 32bit comparisons */\
        __m256i method = _mm256_andnot_si256(spaces, text);\
        method = _mm256_cmpeq_epi32(_mm256_shuffle_epi32(method, 0), mdata);\
        /* get space mask and transform it in such way it's first 1 bit will point to url: */\
        /* request:    GET    http://yandex.ru... */\
        /* mask:          **** ?????????????????? */\
        int mask = _mm256_movemask_epi8(spaces);\
        /* mask(ored): ******* ?????????????????? */\
        /* mask(+1):          *?????????????????? */\
        mask = (mask | (mask-1)) + 1;\
        /* bpos will point to start of uri, but we will try to skip schema if possible */\
        int bpos = __builtin_ctz(mask | 0x10000);\
        /* we have a lot of latency at this point, so we will switch to another task: */\
        /* get method id from comparison mask */\
        int methodname = (TFW_HTTP_METH_POST<<8)|(TFW_HTTP_METH_HEAD<<4)|(TFW_HTTP_METH_GET);\
        methodname &= _mm256_movemask_epi8(method);\
        methodname |= methodname>>8;\
        methodname |= methodname>>4;\
        methodname &= 0xF;\
        /* instead of adjusting data, we adjust mask: it is faster */\
        mdata = _mm256_loadu_si256((const __m256i*)(__c_avx_method+16-bpos));\
        mdata = _mm256_permute4x64_epi64(mdata, 0x94);\
        /* we expect total length of method and following spaces */\
        /* less than 16 bytes. if scheme is located somewhere in */\
        /* bytes 8-23, we shift it 8 bytes right to bytes 0-15   */\
        if (unlikely((mask & 0xFF)==0)) text = _mm256_permute4x64_epi64(text, 0xF9);\
        /* then we clone scheme and compare it to adjusted mask  */\
        text  = _mm256_permute4x64_epi64(text, 0x44);\
        int auxmask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(mdata, text));\
        /* at this point, we should have already method name and */\
        /* beginning of url in first 16 bytes; if not bail out   */\
        if (unlikely((bpos >= 16))) return TFW_BLOCK;\
        if (unlikely(!methodname)) return TFW_BLOCK;\
        /* adjust compare mask to possible beginning of schema   */\
        /* and clear bits which we don't want to test            */\
        /* use addition to collect all bits set and a mask       */\
        auxmask = (auxmask >> bpos) & 0x00FF007F;\
        auxmask = (auxmask + 0x00010081) & 0x08000800;\
        auxmask = (auxmask*0xF) & 0x08000700;\
        bpos = bpos + (auxmask>>8) + (auxmask>>24);\
        method_name_out = methodname;\
        __FSM_MOVE_n(nextstate, bpos);\
    }

#define AVX_QUICK_PARSE_HEADER(nextstate) \
    if (__data_available(p, 32)) {\
        /* load 32 bytes of text, and replace tabs with spaces */\
        __m256i text = _mm256_loadu(p);\
        __m256i tabs = _mm256_shuffle_epi32(__avx_constants3, __AVX_C3_TABS);\
        __m256i spaces = _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_SPACES); \
        tabs = _mm256_cmpeq_epi8(text, tabs);\
        /* lowercase all characters */\
        __m256i c1 = _mm256_cmpgt_epi8(\
            text, _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_LOWERCASE2)); \
        __m256i c2 = _mm256_cmpgt_epi8(\
            _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_LOWERCASE1), text); \
        text = _mm256_blendv_epi8(text, spaces, tabs);\
        c1 = _mm256_or_si256(c1, c2); \
        c1 = _mm256_andnot_si256(c1, spaces); \
        text = _mm256_or_si256(text, c1); \
        /* extract spaces mask: first space is end of method, next non-space */\
        /* after spaces after method is beginning of the header value */\
        __m256i mask1;\
        AVX_MATCH_CHARSET(mask1, text, HEADER_CHARSET);\
        int bitmask1 = _mm256_movemask_epi8(mask1);\
        int bitmask2 = _mm256_movemask_epi8(\
            _mm256_cmpeq_epi8(text, _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_SEMICOLON)));\
        int bitmask3 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(text, spaces));\
        /* we need at least one valid character in header name */\
        if (unlikely(!(bitmask1 & 0x1))) return TFW_BLOCK;\
        /* first 1-bit in tmp will point to ':' position... */\
        int tmp = (~bitmask1)+1;\
        tmp &= bitmask2;\
        /* ...and we make sure we have ':' there */\
        if (unlikely(!tmp)) return TFW_BLOCK;\
        int headerid = 0;\
        /* zero-terminate header name before matching */\
        mask1 = _mm256_andnot_si256(mask1, text);\
        AVX_MATCH_HEADER_NAME(headerid, mask1);\
        /* get next state id and header tag using 2 tables */\
        AVX_HDRID_TO_TAG(parser->_hdr_tag, headerid);\
        AVX_HDRID_TO_STATE(parser->_i_st, headerid);\
        /* first bit in tmp will point to first byte of header value */\
        tmp = tmp + tmp + bitmask3;\
        tmp = ((~tmp)+1) & tmp;\
        /* ctz makes undefined results if all bits set to zero */\
        if (unlikely(!tmp)) {\
            __FSM_MOVE_n(nextstate, 32);\
        }\
        __FSM_MOVE_n(nextstate, __builtin_сtz(tmp));\
    }

#else
#define __DEFINE_AVX_VARIABLES
#define AVX_QUICK_PARSE_METHOD(method_name_out, nextstate)
#define AVX_QUICK_PARSE_HEADER(nextstate)
#define AVX_SKIP_HEADER_BODY(s, n)
#endif

#endif // AVX_ROUTINES_H

