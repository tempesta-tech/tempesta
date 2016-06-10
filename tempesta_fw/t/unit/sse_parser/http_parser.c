#include "http_parser.h"
#include "gfsm.h"

#include <string.h>
#include <assert.h>
#include <ctype.h>

#define __FSM_STATE(st) case st: st: TFW_DBG("\n\tState: %s\n", #st);

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
    Req_UriNext,
    Req_HttpVersion,
    /* Headers. */
    Req_Hdr,
    Req_HdrN,
    Req_HdrName,
    Req_HdrValue,
    Req_HdrValueN,
    /* Final state */
    Req_End,
    Req_CheckRestart,
    /* Special state flags */
    Req_Spaces = 0x8000, //skip spaces
};

#define __FSM_DECLARE_VARS(ptr)						\
    TfwHttpMsg *msg = (TfwHttpMsg *)(ptr);			\
    TfwHttpParser *parser = &msg->parser;				\
    ;

//===========================================================
// BEGIN SSE CONTSTANTS BLOCK
//===========================================================

static const unsigned char __sse_alignment[64] __attribute__((aligned(64))) = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static const unsigned char __sse_method[48] __attribute__((aligned(64))) = {
        0, 1, 2, 0xFF, 0, 1, 2, 3,     0, 1, 2, 3, 0, 1, 2, 0xFF,
        'G','E','T',0, 'H','E','A','D','P','O','S','T','P','U','T',0,
        TFW_HTTP_METH_GET, 3,0,0,
        TFW_HTTP_METH_POST, 4,0,0,
        TFW_HTTP_METH_HEAD, 4,0,0,
        TFW_HTTP_METH_PUT, 3,0,0,
};
static const unsigned char __sse_schema[16]  __attribute__((aligned(16))) = {
        'h', 't', 't', 'p', ':', '/', '/', 0, 0, 0, 0, 0, 0, 0, 0, 0
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
        0xa8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8,
        0xf8, 0xf8, 0xf0, 0x54, 0x50, 0x54, 0x54, 0x54
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

static inline __m128i __sse_lowercase(__m128i data) {
    __m128i l = _mm_cmplt_epi8(_mm_load_si128((const __m128i*)__sse_lowecase_c), data);
    __m128i g = _mm_cmpgt_epi8(_mm_load_si128((const __m128i*)(__sse_lowecase_c+16)), data);
    __m128i s = _mm_andnot_si128(_mm_or_si128(l, g), _mm_load_si128((const __m128i*)__sse_spaces));
    return _mm_or_si128(data, s);
}

static inline __m128i __match_charset(__m128i sm, __m128i data)
{
    __m128i mask1 = _mm_shuffle_epi8(sm, data);
    __m128i mask2 = _mm_and_si128(
                _mm_load_si128((const __m128i*)__sse_charset),
                _mm_srli_epi16(data, 4));
    __m128i mask3 = _mm_shuffle_epi8(
                _mm_load_si128((const __m128i*)(__sse_charset+16)),
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


void
tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start);
void
tfw_http_msg_hdr_chunk_fixup(TfwHttpMsg *hm, char *data, int len);
int
tfw_http_msg_hdr_close(TfwHttpMsg *hm, int id);

unsigned char * __fixup_address_impl(unsigned char * addr,
                                     unsigned char * base,
                                     unsigned char * end,
                                     int offset) {
    assert(addr+offset >= base);
    assert(addr+offset <= end);
    return addr+offset;
}

void __check_hdraddr_impl(unsigned char * addr,
                          unsigned char * base,
                          unsigned char * end) {
    assert(addr >= base);
    assert(addr <= end);
}

#define __fixup_address(n) __fixup_address_impl(fixup_ptr, base, end, n)
#define __check_hdraddr(n) __check_hdraddr_impl(n, base, end)

void __msg_field_open(TfwStr * str, unsigned char * pos) {
    TFW_DBG("Open string at %p\n", pos);
    str->ptr = pos;
}
void __msg_field_fixup(TfwStr * str, unsigned char * pos) {
    TFW_DBG("End string chunk at %p\n", pos);
    str->ptr = pos;
}
void __msg_field_finish_n(TfwStr * str) {
    TFW_DBG("Finish string\n");
    str->flags |= TFW_STR_COMPLETE;				\
}
void __msg_field_finish(TfwStr * str, unsigned char * pos) {
    __msg_field_fixup(str, pos);
    __msg_field_finish_n(str);
}

int
tfw_http_parse_req(void *req_data, unsigned char *data, size_t len)
{
    int r = TFW_BLOCK;
    TfwHttpReq *req = (TfwHttpReq *)req_data;
    __FSM_DECLARE_VARS(req);

    register __m128i compresult;
    register __m128i _r_charset;// asm("xmm15");
    register __m128i _r_spaces;// asm("xmm14");

    unsigned char * base = data, * end = data + len;
    int bytes_cached = parser->bytes_cached;
    int bytes_shifted = parser->bytes_shifted;
    int nc, bc, state, prevstate;

    state = parser->state;
    prevstate = Req_0;
    if (unlikely(state == Req_0)) {
        state = Req_Method;
        parser->charset1 = __sse_method_charset;
        bytes_cached = 0;
        bytes_shifted = 0;
    }

    _r_charset = _mm_load_si128((const __m128i*)parser->charset1);
    _r_spaces  = _mm_load_si128((const __m128i*)__sse_spaces);

    TFW_DBG("parse %lu client data bytes (%.*s) on req=%p\n",
        len, (int)len, data, req);

    for(;;) {
        //если пакет закончился, надо fixupнуть строки
        //потому что больше мы никогда не увидим этот SKB
        if ((bytes_shifted == 0 && state == prevstate)
            || (len + bytes_cached == 0))
        {
            if (parser->current_field) {
                if (parser->header_chunk_start) {
                    tfw_http_msg_hdr_chunk_fixup(msg,
                                                 parser->header_chunk_start,
                                                 data - parser->header_chunk_start);
                    parser->header_chunk_start = NULL;
                } else {
                    __msg_field_fixup(parser->current_field, data);
                }
            }
            r = TFW_POSTPONE;
            break;
        }

        prevstate = state;

        unsigned char * p = data;
        //нам в дальнейшем потребуется указатель для fixupов
        //мы будем делать fuxupы относительно некоторого базового
        //указателя и количества байт опознаных алгоритмом.
        unsigned char * fixup_ptr = data - bytes_cached;
        //мы дополняем буфер до 16 байт
        while (bytes_cached < 16 && len) {
            parser->latch16[bytes_shifted + bytes_cached] = p[0];
            ++bytes_cached;
            ++p;
            --len;
        }
        //надо обязательно занулить первый несчитанный байт
        parser->latch16[bytes_shifted+bytes_cached] = 0;

        //========================================================
        //THIS REGION MUST BE OPTIMIZED BY COMPILER
        //========================================================
        //load bytes
        __m128i vec = _mm_loadu_si128((__m128i*)(parser->latch16+bytes_shifted));
        //match charset and auxillarycharset
        __m128i charset1 = __match_charset(_r_charset, vec);
        __m128i charset2 = _mm_cmpeq_epi8(vec, _r_spaces);
        int avail_mask = 0xFFFFFFFF << bytes_cached;
        int mask1 = (~_mm_movemask_epi8(charset1))|avail_mask;
        int mask2 = (~_mm_movemask_epi8(charset2))|avail_mask;

        //matched chars with 1st char
        int nchars1 = __builtin_ctz(mask1);
        //realign pending bytes
        _mm_store_si128((__m128i*)parser->latch16, vec);
        bytes_shifted = 0;

        //========================================================
        //end of region to be optimized
        //========================================================
        //pre-skip spaces if they are expected
        if (unlikely(state & Req_Spaces)) {
            nc = ~_mm_movemask_epi8(_mm_cmpeq_epi8(vec, _r_spaces));
            nc = __builtin_ctz(nc);
            if (nc < bytes_cached) state &= ~ Req_Spaces;
            if (nc) {
                //store bytes back to parser state for further realignment
                bytes_shifted = nc;
                bytes_cached -= nc;
                //move to the end of sequence
                data = p;
                continue;
            }
        }

        switch (state) {
        __FSM_STATE(Req_Method) {
            //
            // в этом состоянии, мы уверены в следующем:
            // 1)parser->current_field = 0;
            // 2)parser->aux_field = 0;
            // 3)у нас есть некоторое количество подходящих байт и некоторое количество пробелов после.
            //
            //если мы не нашли пробелов после строки, просто ожидаем
            if (nchars1 >= bytes_cached) break;
            if (parser->latch16[nchars1] != ' ') return TFW_BLOCK;
            //we support only GET/HEAD/POST
            compresult = _mm_shuffle_epi8(vec, _mm_load_si128((__m128i*)__sse_method));
            compresult = _mm_cmpeq_epi32(compresult, _mm_load_si128((__m128i*)(__sse_method+16)));
            compresult = _mm_and_si128(compresult, _mm_load_si128((__m128i*)(__sse_method+32)));
            compresult = _mm_hadd_epi32(compresult, compresult);
            compresult = _mm_hadd_epi32(compresult, compresult);
            nc = _mm_extract_epi16(compresult, 0);
            //make sure we have parsed string correctly
            if (!nc || (nc>>8)!= nchars1) return TFW_BLOCK;//unsupported method
            req->method = 0xFF & nc;
            //consume all bytes and spaces
            bytes_shifted = nchars1 + __builtin_ctz(mask2 >> nchars1);
            parser->charset1 = __sse_host_charset;
            //schedule skip_spaces skip if we have parsed all available bytes
            if (bytes_shifted < bytes_cached) goto Req_BeginSchema;
            state = Req_BeginSchema|Req_Spaces;
            break;}
        __FSM_STATE(Req_BeginSchema) {
            state = Req_Schema;
            parser->current_field = &req->host;
            __msg_field_open(&req->host, __fixup_address(bytes_shifted));
            if (bytes_shifted)break;}
        __FSM_STATE(Req_Schema) {
            //мы можем столкнуться со следующими видами строк:
            // "dir/file"
            // "/dir/file"
            // "host.ru/dir/file"
            // "http://host/dir/file"
            // "host.ru:80/dir/file"
            // "http://host:80/dir/file"
            //
            //какова наша стратегия в этом случае?
            // не сдвигать latch16 до тех пор пока мы не убедимся
            // что, перед нами http:// или подобное им
            // либо пока мы не убедимся, что перед нами точно не
            // одно из них, либо пока байт не накопится 16
            //при этом накапливать строку

            //сравним то что есть в лоб
            nc = ~_mm_movemask_epi8(_mm_cmpeq_epi8(vec, _mm_load_si128((const __m128i*)__sse_schema)));
            nc |= avail_mask;
            nc |= nc<<1;
            nc |= nc<<2;
            nc |= nc<<4;
            nc |= nc<<8;
            //попробуем понять, точно ли перед нами http://
            //проверим, есть ли расхождения:
            //байт есть 1 2 3 4 5 6 7 8
            //bytes1    1 2 3 4 4 4 4 х
            //bytes2    0 0 0 0 1 2 3 х
            //nc        1 2 3 4 5 6 7 7

            //если скорее всего получили http://
            if (likely(nc == -128)) {
                bytes_shifted = 7;
                TFW_STR_INIT(&req->host);
                parser->current_field = NULL;
                parser->charset1 = __sse_host_charset;
                state = Req_HostReset;
                break;
            }

            if (unlikely(nc > avail_mask)) {
                if (nc > -32) {
                    state = Req_Host;
                    break;
                }
                if (nc == -32) {
                    //check if field is already closed!
                    if (parser->current_field) {
                        __msg_field_finish_n(parser->current_field);
                        parser->current_field = NULL;
                    }
                    bytes_shifted = 5;
                    parser->charset1 = __sse_digit_charset;
                    state = Req_Port;
                    break;
                }
                return TFW_BLOCK;
            } else {
                if (nc == -32) {
                    __msg_field_finish_n(parser->current_field);
                    parser->current_field = NULL;
                }
            }
            break;}
        __FSM_STATE(Req_HostReset) {
            parser->current_field = &req->host;
            __msg_field_open(&req->host, __fixup_address(0));
            state = Req_Host;
            /* continue */}
        __FSM_STATE(Req_Host) {
            bytes_shifted = nchars1;
            if (nchars1 == bytes_cached) break;

            unsigned char c = parser->latch16[nchars1];
            if (c == '@') {
                //проверка как в tempesta
                if (!TFW_STR_EMPTY(&req->userinfo)) {
                    TFW_DBG("Second '@' in authority\n");
                    return TFW_BLOCK;
                }
                TFW_DBG3("Authority contains userinfo\n");
                /* copy current host to userinfo */
                req->userinfo = req->host;
                __msg_field_finish(&req->userinfo, __fixup_address(nchars1));
                //новый host надо инициализовать
                TFW_STR_INIT(&req->host);
                parser->current_field = NULL;
                bytes_shifted = nchars1 + 1;
                state = Req_HostReset;
                break;
            }
            if (c == '[') {
                //убеждаемся, что host пуст
                if (!TFW_STR_EMPTY(&req->host))
                    return TFW_BLOCK;
                //снова забываем host, и создаем по новой
                TFW_STR_INIT(&req->host);
                parser->current_field = NULL;
                bytes_shifted = 1;
                parser->charset1 = __sse_host_ipv6_charset;
                state = Req_HostIpv6Reset;
                break;
            }
            if (nchars1)
                __msg_field_finish(&req->host, __fixup_address(nchars1));
            else
                __msg_field_finish_n(&req->host);
            parser->current_field = NULL;
            /* continue */}
        __FSM_STATE(Req_HostEnd) {
            BUG_ON(parser->current_field);
            unsigned char c = parser->latch16[nchars1];
            switch (c) {
            case ':':
                ++bytes_shifted;
                parser->charset1 = __sse_digit_charset;
                state = Req_Port;
                break;
            case '/':
                parser->charset1 = __sse_uri_charset;
                state = Req_Uri;
                break;
            case ' ': case '\r': case '\n':
                parser->charset1 = __sse_version_charset;
                state = Req_HttpVersion|Req_Spaces;
                break;
            default:
                return TFW_BLOCK;
            }
            break;}
        __FSM_STATE(Req_HostIpv6Reset) {
            parser->current_field = &req->host;
            __msg_field_open(&req->host, __fixup_address(0));
            /* continue */}
        __FSM_STATE(Req_HostIpv6) {
            bytes_shifted = nchars1;
            if (nchars1 >= bytes_cached) break;

            unsigned char c = parser->latch16[nchars1];
            if (c != ']') return TFW_BLOCK;
            __msg_field_finish(&req->host, __fixup_address(nchars1));
            parser->current_field = NULL;
            parser->charset1 = __sse_null_charset;
            state = Req_HostEnd;
            break;}
        __FSM_STATE(Req_Port) {
            BUG_ON(parser->current_field);
            if (nchars1 == bytes_cached) break;
            long long port = __parse_number(vec, nchars1);
            if (port < 1 || port > 65535)
                return TFW_BLOCK;
            //FIXME: store or check port number
            bytes_shifted = nchars1;
            unsigned char c = parser->latch16[nchars1];
            switch (c) {
            case '/':
                parser->charset1 = __sse_uri_charset;
                state = Req_Uri;
                break;
            case ' ': case '\r': case '\n':
                parser->charset1 = __sse_version_charset;
                state = Req_HttpVersion|Req_Spaces;
                break;
            default:
                return TFW_BLOCK;
            }
            break;}
        __FSM_STATE(Req_Uri) {
            parser->current_field = &req->uri_path;
            __msg_field_open(&req->uri_path, __fixup_address(0));
            state = Req_UriNext;
            /* continue */}
        __FSM_STATE(Req_UriNext) {
            bytes_shifted = nchars1;
            if (nchars1 == bytes_cached) break;

            if (nchars1)
                __msg_field_finish(&req->uri_path, __fixup_address(nchars1));
            else
                __msg_field_finish_n(&req->uri_path);
            parser->current_field = NULL;

            unsigned char c = parser->latch16[nchars1];
            switch (c) {
            case '\r': case '\n':
                parser->charset1 = __sse_version_charset;
                state = Req_HttpVersion;
                break;
            case ' ':
                parser->charset1 = __sse_version_charset;
                state = Req_HttpVersion|Req_Spaces;
                break;
            default:
                return TFW_BLOCK;
            }
            break;}
        __FSM_STATE(Req_HttpVersion) {
            BUG_ON(parser->current_field);
            compresult = _mm_cmpeq_epi8(vec, _mm_load_si128((__m128i*)(__sse_newline)));
            int nc = ~_mm_movemask_epi8(compresult);
            nc |= avail_mask;
            //need more data?
            if (nc == -1) break;

            compresult = _mm_shuffle_epi8(vec, _mm_load_si128((const __m128i*)__sse_version));
            compresult = _mm_cmpeq_epi8(compresult, _mm_load_si128((const __m128i*)(__sse_version+16)));
            int ms = _mm_movemask_epi8(compresult);
            ms = (ms + 0x2809) & 0x9404;

            if (ms & 0x4) {
                req->version = TFW_HTTP_VER_09;
            } else if (ms == 0x9400) {
                req->version = TFW_HTTP_VER_10 +
                    (parser->latch16[7]-'0');
            } else {
                return TFW_BLOCK;
            }
            bytes_shifted = __builtin_ctz(nc+1)+1;
            parser->charset1 = __sse_header_charset;
            state = Req_Hdr;
            break;}
        __FSM_STATE(Req_Hdr) {
            BUG_ON(parser->current_field != NULL);
            //don't support multiline headers
            if (!nchars1) {
                //check if headers are over
                if (parser->latch16[0] == '\r') {
                    bytes_shifted = 1;
                    if (unlikely(bytes_cached < 2)) {
                        parser->charset1 = __sse_null_charset;
                        state = Req_HdrN;
                        break;
                    }
                }
                if (unlikely(parser->latch16[bytes_shifted] != '\n'))
                    return TFW_BLOCK;
                ++bytes_shifted;
                goto Req_End;
            }
            //fast path for short headers which are likely
            //to fit into SKB
            if (likely(nchars1 < bytes_cached)) {
                if (parser->latch16[nchars1] != ':')
                    return TFW_BLOCK;
                tfw_http_msg_hdr_open(msg, __fixup_address(0));
                tfw_http_msg_hdr_chunk_fixup(msg,
                                             __fixup_address(0),
                                             nchars1+1);
                //we don't start a chunk on spaces
                parser->current_field = &parser->hdr;
                parser->header_chunk_start = 0;
                //continue with value
                bytes_shifted= nchars1 +
                        __builtin_ctz(mask2 >> (nchars1+1))
                        + 1;
                parser->charset1 = __sse_value_charset;
                state = Req_HdrValue|Req_Spaces;
                break;
            }

            tfw_http_msg_hdr_open(msg, __fixup_address(0));

            parser->current_field = &parser->hdr;
            parser->header_chunk_start = __fixup_address(0);

            bytes_shifted = nchars1;
            state = Req_HdrName;
            break;}
        __FSM_STATE(Req_HdrN) {
            if (unlikely(parser->latch16[0] != '\n')) return TFW_BLOCK;
            ++bytes_shifted;
            goto Req_End;}
        __FSM_STATE(Req_HdrName) {
            BUG_ON(parser->current_field == NULL);
            if (likely(nchars1 < bytes_cached)) {
                if (parser->latch16[nchars1] != ':')
                    return TFW_BLOCK;
                //fixup header
                if (!parser->header_chunk_start)
                    parser->header_chunk_start = __fixup_address(0);
                tfw_http_msg_hdr_chunk_fixup(msg,
                                             parser->header_chunk_start,
                                             __fixup_address(nchars1) - parser->header_chunk_start + 1);
                //we don't start a chunk on spaces
                parser->header_chunk_start = 0;
                //continue with value
                bytes_shifted= nchars1 +
                        __builtin_ctz(mask2 >> (nchars1+1))
                        + 1;
                parser->charset1 = __sse_value_charset;
                state = Req_HdrValue|Req_Spaces;
                break;
            }
            //continue grabbing data
            if (!parser->header_chunk_start)
                parser->header_chunk_start = __fixup_address(0);
            bytes_shifted = nchars1;
            break;}
        __FSM_STATE(Req_HdrValue) {
            BUG_ON(parser->current_field == NULL);
            if (likely(nchars1 < bytes_cached)) {
                if (!parser->header_chunk_start)
                    parser->header_chunk_start = __fixup_address(0);
                //fixup header
                tfw_http_msg_hdr_chunk_fixup(msg,
                                             parser->header_chunk_start,
                                             __fixup_address(nchars1) - parser->header_chunk_start);
                tfw_http_msg_hdr_close(msg, 0);//FIXME:
                //remove current field
                parser->current_field = 0;
                parser->header_chunk_start = 0;
                //check if headers are over
                bytes_shifted = nchars1;
                if (parser->latch16[nchars1] == '\r') {
                    ++bytes_shifted;
                    if (unlikely(bytes_cached == bytes_shifted)) {
                        parser->charset1 = __sse_null_charset;
                        state = Req_HdrValueN;
                        break;
                    }
                }
                if (unlikely(parser->latch16[bytes_shifted] != '\n'))
                    return TFW_BLOCK;

                ++bytes_shifted;
                parser->charset1 = __sse_header_charset;
                state = Req_Hdr;
                break;
            }
            //continue grabbing data
            if (!parser->header_chunk_start)
                parser->header_chunk_start = __fixup_address(0);
            bytes_shifted = nchars1;
            break;}
        __FSM_STATE(Req_HdrValueN) {
            if (unlikely(parser->latch16[0] != '\n')) return TFW_BLOCK;
            ++bytes_shifted;
            parser->charset1 = __sse_header_charset;
            state = Req_Hdr;
            break;}
        __FSM_STATE(Req_End)
            r = TFW_PASS;
            break;
        default:
            TFW_DBG3("unexpected state %d\n", state);
            return TFW_BLOCK;
        }
        _r_charset = _mm_load_si128((const __m128i*)parser->charset1);

        data = p;
        bytes_cached -= bytes_shifted;
        if (r == TFW_PASS)
            break;
    }
    parser->state = state;
    parser->bytes_cached = bytes_cached;
    parser->bytes_shifted = bytes_shifted;
    return r;
}


/**
 * Open currently parsed header.
 */
void
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
void
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
void
tfw_http_msg_hdr_chunk_fixup(TfwHttpMsg *hm, char *data, int len)
{
    tfw_http_msg_field_chunk_fixup(hm, &hm->parser.hdr, data, len);
}

/**
 * Store fully parsed, probably compound, header (i.e. close it) to
 * HTTP message headers list.
 */
int
tfw_http_msg_hdr_close(TfwHttpMsg *hm, int id)
{
    TFW_DBG3("close header with id %d\n", id);
    return TFW_PASS;
}
