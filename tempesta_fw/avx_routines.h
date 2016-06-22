#ifndef AVX_ROUTINES_H
#define AVX_ROUTINES_H

#pragma GCC push_options
#pragma GCC target("sse","sse2","sse3","ssse3","sse4.1","avx","avx2")
#define _MM_MALLOC_H_INCLUDED
#include <x86intrin.h>
#undef  _MM_MALLOC_H_INCLUDED
#pragma GCC pop_options

extern const unsigned char __c_avx_data[];
extern const unsigned char __c_avx_const1[];
extern const unsigned char __c_avx_const2[];
extern const unsigned char __c_avx_header_names[];

#define __header_charset _mm256_loadu2_m128i((const __m128i*)__c_avx_data, (const __m128i*)__c_avx_data)
#define __constants _mm256_loadu2_m128i((const __m128i*)__c_avx_data+16, (const __m128i*)__c_avx_data+16)
#define _mm256_loadu(p) _mm256_loadu_si256((const __m256*)p)
#define _mm256_load(p)  _mm256_load_si256((const __m256*)p)

#define __DEFINE_AVX_VARIABLES \
    __m256 HEADER_CHARSET, __c_avx_constants1, __c_avx_constants2; do {\
        __m256 tmp = _mm256_load(__c_avx_data);\
        __m256 tmp2 = _mm256_load(__c_avx_data+32);\
        HEADER_CHARSET = _mm256_permute2f128_si256(tmp, tmp, 0x00);\
        __m256 tmp3 = _mm256_permute4x64_epi64(tmp, 0xEE);\
        tmp2 = _mm256_unpacklo_epi32(tmp3, tmp3);\
        __c_avx_constants1 = tmp3;\
        __c_avx_constants2 = tmp2;\
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

#define AVX_MATCH_HEADER(result, text, charset) do { \
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
// 0     Host Tran X-Fo Cont Cont User Conn Cook
// 1     Cach sfer rwar ent- ent- -age ecti ie
// 2     e-Co -Enc ded- Leng Type nt   on
// 3     ntro odin For  th
// 4     l    g
//==================================================

#define AVX_MATCH_HEADER_NAME(result, text) do {\
    /*mask 1 = rows 0-1, columns 0low-1hi*/\
    __m256i mask1 = _mm256_cmpeq_epi64(\
        _mm256_and_si256(_mm256_permute4x64_epi64(text, 0x00), _mm256_load(__c_avx_header_names+0)),\
        _mm256_load((__c_avx_header_names+32)));\
    /*mask 2 = rows 0-1, columns 2low-3hi*/\
    __m256i mask2 = _mm256_cmpeq_epi64(\
        _mm256_and_si256(_mm256_permute4x64_epi64(text, 0x00), _mm256_load(__c_avx_header_names+64)),\
        _mm256_load((__c_avx_header_names+96)));\
    /*mask 3 = rows 2-3, columns 0low-1hi*/\
    __m256i mask3 = _mm256_cmpeq_epi64(\
        _mm256_and_si256(_mm256_permute4x64_epi64(text, 0x55), _mm256_load(__c_avx_header_names+128)),\
        _mm256_load((__c_avx_header_names+160)));\
    /*mask 4 = rows 2-3, columns 2low-3hi*/\
    __m256i mask4 = _mm256_cmpeq_epi64(\
        _mm256_and_si256(_mm256_permute4x64_epi64(text, 0x55), _mm256_load(__c_avx_header_names+192)),\
        _mm256_load((__c_avx_header_names+224)));\
    /*mask5 = row 4*/\
    __m256i mask5 = _mm256_cmpeq_epi64(\
        _mm256_and_si256(_mm256_permute4x64_epi64(text, 0xAA), _mm256_load(__c_avx_header_names+256)),\
        _mm256_load((__c_avx_header_names+288)));\
    mask1 = _mm256_and_si256(_mm256_and_si256(mask1, mask3), mask5);\
    mask2 = _mm256_and_si256(mask2, mask4);\
    int mask = _mm256_movemask_epi8(_mm256_packus_epi32(mask1, mask2));\
    mask &= 0x87654321;\
    mask = mask | (mask>>16);\
    mask = mask | (mask>>8);\
    mask = mask | (mask>>4);\
    result = 0xFF & mask;} while(0);


#endif // AVX_ROUTINES_H

