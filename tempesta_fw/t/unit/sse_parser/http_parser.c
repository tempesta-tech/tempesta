#include "http_parser.h"
#include "gfsm.h"

#include <string.h>
#include <assert.h>
#include <ctype.h>

extern void __print_sse(const char * prefix, __m128i sm);

/* Main (parent) HTTP request processing states. */
enum {
    Req_0,
    /* Request line. */
    Req_Method,
    Req_BeginSchema,
    Req_Schema,
    Req_HostReset,
    Req_Host,
    Req_HostEnd,
    Req_HostIpv6Reset,
    Req_HostIpv6,
    Req_Port,
    Req_Uri,
    //Req_UriNext,
    Req_HttpVersion,
    /* Headers. */
    Req_Hdr,
    Req_HdrN,
    Req_HdrName,
    //Req_HdrValue,
    Req_HdrValueN,
    /* Final state */
    Req_End,
    Req_CheckRestart,
    /* Special state flags */
    Req_Spaces = 0x8000, //skip spaces
    /* Fast-forward states */
    Req_FastForward = 0x10000,
    Req_UriNext,
    Req_HdrValue,
};

#define __FSM_DECLARE_VARS(ptr)						\
    TfwHttpMsg *msg = (TfwHttpMsg *)(ptr);			\
    TfwHttpParser *parser = &msg->parser;				\
    ;

//===========================================================
// BEGIN SSE CONTSTANTS BLOCK
//===========================================================

static const unsigned char __sse_alignment[64] __attribute__((aligned(64))) = {
//        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
//        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
//        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const int allmethod_mask = ( 
	(TFW_HTTP_METH_GET)|
	(TFW_HTTP_METH_PUT<<4)|
	(TFW_HTTP_METH_HEAD<<8)|
	(TFW_HTTP_METH_POST<<12));
static const int allmethod_len = 0x4433;

static const unsigned char __sse_method[16] __attribute__((aligned(16))) = {
    'G','E','T',' ','P','U','T',' ','H','E','A','D','P','O','S','T'
};
static const unsigned char __sse_schema[16]  __attribute__((aligned(16))) = {
    'h','t','t','p',':','/','/',0,' ','h','t','t','p',':','/','/'
};
static const unsigned char __sse_version[32] __attribute__((aligned(32))) = {
    0,  1,  0,  0,  1,  2,  3,  4,  5,  6,  0,  7,  7,  8,  9,  8,
    '\r','\n','\n','H', 'T' ,'T' ,'P' ,'/', '1' ,'.' ,'Z' ,'0', '1','\r','\n','\n'
};
static const unsigned char __sse_newline[16] __attribute__((aligned(16))) = {
    '\n','\n','\n','\n','\n','\n','\n','\n',
    '\n','\n','\n','\n','\n','\n','\n','\n'
};
static const unsigned char __sse_zeros[16] __attribute__((aligned(16))) = {
    '0','0','0','0','0','0','0','0',
    '0','0','0','0','0','0','0','0'
};
static const unsigned char __sse_spaces[16] __attribute__((aligned(16))) = {
    ' ',' ',' ',' ',' ',' ',' ',' ',
    ' ',' ',' ',' ',' ',' ',' ',' '
};


static const unsigned char __sse_method_charset[16] __attribute__((aligned(16))) = {
    0x20, 0x00, 0x00, 0x20, 0x20, 0x30, 0x00, 0x10,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};
static const unsigned char __sse_scheme_charset[16] __attribute__((aligned(16))) = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x04
};
static const unsigned char __sse_spaces_charset[16] __attribute__((aligned(16))) = {
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char __sse_host_charset[16] __attribute__((aligned(16))) = {
    0xa8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8,
    0xf8, 0xf8, 0xf0, 0x50, 0x50, 0x54, 0x54, 0x50
};
static const unsigned char __sse_host_ipv6_charset[16] __attribute__((aligned(16))) = {
    0x08, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x08,
    0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char __sse_digit_charset[16] __attribute__((aligned(16))) = {
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char __sse_null_charset[16] __attribute__((aligned(16))) = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0
};
static const unsigned char __sse_uri_charset[16] __attribute__((aligned(16))) = {
    0xa8, 0xf8, 0xf8, 0xfc, 0xfc, 0xfc, 0xfc, 0xf8,
    0xf8, 0xf8, 0xf4, 0x5c, 0x54, 0x5c, 0x54, 0x5c
};
static const unsigned char __sse_version_charset[16] __attribute__((aligned(16))) = {
    0x28, 0x08, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x04, 0x04
};
static const unsigned char __sse_header_charset[16] __attribute__((aligned(16))) = {
    0xa8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8,
    0xf8, 0xf8, 0xf0, 0x50, 0x50, 0x54, 0x50, 0x50
};
static const unsigned char __sse_value_charset[16] __attribute__((aligned(16))) = {
    0xac, 0xf8, 0xf8, 0xf8, 0xf8, 0xfc, 0xf8, 0xf8,
    0xfc, 0xfc, 0xf4, 0x5c, 0xd4, 0x5c, 0x54, 0x74
};
static const unsigned short __sse_atoi_1[8] __attribute__((aligned(16))) = {
        266,266,266,266,266,266,266,266
};
static const unsigned int __sse_atoi_2[4] __attribute__((aligned(16))) = {
        65636,65636,65636,65636
};
static const unsigned char __sse_charset[32]  __attribute__((aligned(32))) = {
        0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF,
        1,2,4,8,16,32,64,128,0,0,0,0,0,0,0,0
};
static const unsigned char __sse_lowecase_c[32]  __attribute__((aligned(32))) = {
        'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A','A',
        'Z','Z','Z','Z','Z','Z','Z','Z','Z','Z','Z','Z','Z','Z','Z','Z'
};

#define _mm_right(n) _mm_lddqu_si128((__m128i*)(__sse_alignment+16+(n)))
#define _mm_left(n) _mm_lddqu_si128((__m128i*)(__sse_alignment+16-(n)))
#define _mm_ref(ptr) _mm_load_si128((const __m128i*)(ptr))
//#define _mm_ref(ptr) *((const __m128i*)(ptr)) -- this is slower

static inline __m128i __sse_lowercase(__m128i data) {
    __m128i l = _mm_cmplt_epi8(_mm_ref(__sse_lowecase_c), data);
    __m128i g = _mm_cmpgt_epi8(_mm_ref(__sse_lowecase_c+16), data);
    __m128i s = _mm_andnot_si128(_mm_or_si128(l, g), _mm_ref(__sse_spaces));
    return _mm_or_si128(data, s);
} __attribute__((always_inline))


static inline __m128i __match_charset(__m128i sm, __m128i data, __m128i D1, __m128i D2)
{
    __m128i mask1 = _mm_shuffle_epi8(sm, data);
    __m128i mask2 = _mm_and_si128(
                D1,
                _mm_srli_epi16(data, 4));
    __m128i mask3 = _mm_shuffle_epi8(
                D2,
                mask2);
    __m128i mask4 = _mm_and_si128(
                mask3,
                mask1);
    return _mm_cmpeq_epi8(
                mask4,
                _mm_setzero_si128());
} __attribute__((always_inline))

//#define __builtin_ctz(z) __ctz(z)

inline int __ctz(int zi) {
    int z = zi;
    z |= z<<1;
    z |= z<<2;
    z |= z<<4;
    z |= z<<8;
    z = ~z;

    z  = (z & 0x5555) + ((z>>1) & 0x5555);//8x2
    z  = (z & 0x3333) + ((z>>2) & 0x3333);//4x4
    z  = (z & 0x0F0F) + ((z>>4) & 0x0F0F);//2x8
    printf("CTZ: %08x -- %08x\n", zi, z);
    return 0x1F & (z + (z>>8));
} __attribute__((always_inline))


static inline long long __parse_number(__m128i vec, int len) {
    int buf[4] __attribute__((aligned(16)));
    __m128i shuffle = _mm_lddqu_si128((const __m128i*)(__sse_alignment+len));
    __m128i mask    = _mm_lddqu_si128((const __m128i*)(__sse_alignment+len+32));
    __m128i tmp = _mm_subs_epi8(vec, _mm_load_si128((const __m128i*)__sse_zeros));
    tmp = _mm_and_si128(tmp, mask);
    tmp = _mm_shuffle_epi8(tmp, shuffle);

    //convert from bytes to dwords
    tmp = _mm_maddubs_epi16(tmp, _mm_load_si128((const __m128i*)(__sse_atoi_1)));
    tmp = _mm_madd_epi16(tmp, _mm_load_si128((const __m128i*)(__sse_atoi_1)));
    _mm_store_si128((__m128i*)buf, tmp);

    long long result = buf[0];
    result = 10000LL*result + buf[1];
    result = 10000LL*result + buf[2];
    result = 10000LL*result + buf[3];
    return result;
}

//#define NO_TEMPESTA_OVERHEAD
#ifdef NO_TEMPESTA_OVERHEAD

#define __fixup_address(n) n
#define __check_hdraddr(n)

#define tfw_http_msg_hdr_open(hm, hdr_start)
#define tfw_http_msg_hdr_chunk_fixup(hm, data, len)
#define tfw_http_msg_hdr_close(hm, id)

#define __msg_field_open(str, pos)
#define __msg_field_fixup(str, pos)
#define __msg_field_finish_n(str)
#define __msg_field_finish(str, pos)

#else
static void
tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start);
static void
tfw_http_msg_hdr_chunk_fixup(TfwHttpMsg *hm, char *data, int len);
static int
tfw_http_msg_hdr_close(TfwHttpMsg *hm, int id);

static unsigned char * __fixup_address_impl(unsigned char * addr,
                                     unsigned char * base,
                                     unsigned char * end,
                                     int offset) {
    assert(addr+offset >= base);
    assert(addr+offset <= end);
    return addr+offset;
}

static void __check_hdraddr_impl(unsigned char * addr,
                          unsigned char * base,
                          unsigned char * end) {
    assert(addr >= base);
    assert(addr <= end);
}

//#define __fixup_address(n) __fixup_address_impl(fixup_ptr, base, end, n)
#define __fixup_address(n) (fixup_ptr + n)
//#define __check_hdraddr(n) __check_hdraddr_impl(n, base, end)
#define __check_hdraddr(n)

static inline void __msg_field_open(TfwStr * str, unsigned char * pos) {
    TFW_DBG("Open string at %p\n", pos);
    str->ptr = pos;
}
static inline void __msg_field_fixup(TfwStr * str, unsigned char * pos) {
    TFW_DBG("End string chunk at %p\n", pos);
    str->ptr = pos;
}
static inline void __msg_field_finish_n(TfwStr * str) {
    TFW_DBG("Finish string\n");
    str->flags |= TFW_STR_COMPLETE;				\
}
static inline void __msg_field_finish(TfwStr * str, unsigned char * pos) {
    __msg_field_fixup(str, pos);
    __msg_field_finish_n(str);
}
#endif

#define TFW_PARSE_HEADER_NAME tfw_http_parse_header
#define TFW_PARSE_REQ_NAME tfw_http_parse_req
#include "http_parser_impl.c"

#undef TFW_PARSE_HEADER_NAME
#undef TFW_PARSE_REQ_NAME

#define TFW_PARSE_HEADER_NAME tfw_http_parse_header_ff
#define TFW_PARSE_REQ_NAME tfw_http_parse_req_ff
#define ENABLE_FAST_FORWARD

#include "http_parser_impl.c"

#ifndef NO_TEMPESTA_OVERHEAD
/**
 * Open currently parsed header.
 */
static void
tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start)
{
    TFW_DBG3("open header at char [%c]\n", *hdr_start);
}

/**
 * Fixup the new data chunk to currently parsed HTTP field.
 *
 * @len could be 0 if the field was fully read, but we realized this only
 * now by facinng CRLF at begin of current data chunk.
 */
static void
tfw_http_msg_field_chunk_fixup(TfwHttpMsg *hm, TfwStr *field,
                   char *data, int len)
{
    TFW_DBG3("store field chunk len=%d data=%p\n",
         len, data);
}

/**
 * Fixup the new data chunk to currently parsed HTTP header.
 *
 * @len could be 0 if the header was fully read, but we realized this only
 * now by facinng CRLF at begin of current data chunk.
 */
static void
tfw_http_msg_hdr_chunk_fixup(TfwHttpMsg *hm, char *data, int len)
{
    tfw_http_msg_field_chunk_fixup(hm, &hm->parser.hdr, data, len);
}

/**
 * Store fully parsed, probably compound, header (i.e. close it) to
 * HTTP message headers list.
 */
static int
tfw_http_msg_hdr_close(TfwHttpMsg *hm, int id)
{
    TFW_DBG3("close header with id %d\n", id);
    return TFW_PASS;
}
#endif
