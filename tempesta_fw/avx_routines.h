#ifndef AVX_ROUTINES_H
#define AVX_ROUTINES_H

#pragma GCC push_options
#pragma GCC target("sse","sse2","sse3","ssse3","sse4.1","avx","avx2")
#define _MM_MALLOC_H_INCLUDED
#include <x86intrin.h>
#undef  _MM_MALLOC_H_INCLUDED
#pragma GCC pop_options

extern const unsigned char __c_avx_header_charset[];
extern const unsigned char __c_avx_hvalue_charset[];
extern const unsigned char __c_avx_const1[];
extern const unsigned char __c_avx_const2[];
extern const unsigned char __c_avx_header_names[];
extern const unsigned int  __c_avx_header_names_len;

#define __header_charset _mm256_loadu2_m128i((const __m128i*)__c_avx_header_charset, (const __m128i*)__c_avx_header_charset)
#define __hvalue_charset _mm256_loadu2_m128i((const __m128i*)__c_avx_hvalue_charset, (const __m128i*)__c_avx_hvalue_charset)
#define __constants1 _mm256_loadu2_m128i((const __m128i*)__c_avx_const1, (const __m128i*)__c_avx_const1)
#define __constants2 _mm256_loadu2_m128i((const __m128i*)__c_avx_const2, (const __m128i*)__c_avx_const2)
#define _mm256_loadu(p) _mm256_loadu_si256((const __m256*)p)

#define __DEFINE_AVX_VARIABLES \
    __m256 HEADER_CHARSET   = __header_charset; \
    __m256 HVALUE_CHARSET   = __hvalue_charset; \
    __m256 __avx_constants1 = __constants1; \
    __m256 __avx_constants1 = __constants1;

enum {
    __AVX_C1_LOWERCASE1  = 0x00,
    __AVX_C1_LOWERCASE2  = 0x55,
    __AVX_C1_SPACES      = 0xAA,
    __AVX_C1_SEMICOLON   = 0xFF,
    __AVX_C2_CHARSET_M1  = 0x00,
    __AVX_C2_CHARSET_M2  = 0x55,
    __AVX_C2_CONTORL1    = 0xAA,
    __AVX_C2_CONTROL2    = 0xFF,
};

#define AVX_LOWERCASE(out, in) do { \
        __m256 c1 = _mm256_cmpgt_epi8(in, \
            _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_LOWERCASE1)); \
        __m256 c2 = _mm256_cmpgt_epi8(in, \
            _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_LOWERCASE2)); \
        __m256 c3 = _mm256_shuffle_epi32(__avx_constants1, __AVX_C1_SPACES)); \
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
//DATA#  0low 0hi  1low 1hi  2low 2hi
//DWORD#
// 0     Host Tran X-Fo Cont Cont User Conn Cook
// 1     Cach sfer rwar ent- ent- -age ecti ie
// 2     e-Co -Enc ded- Leng Type nt   on
// 3     ntro odin For  th
// 4     l    g
//==================================================

#define AVX_MATCH_STRING(result, text, stringset) do { \
    FIXME \
    } while(0);


#endif // AVX_ROUTINES_H

