#include "http_parser.h"
#include <string.h>
#include <assert.h>
#include <ctype.h>

#define likely(a)	__builtin_expect((a), 1)
#define unlikely(a)	__builtin_expect((a), 0)

#define TFW_DBG printf
#define TFW_DBG3 printf
#define __FSM_STATE(st) case st: st: printf("\n\tPos: %s\n\tState: %s\n", p, #st);
#define BUG_ON(expr)							\
  ((expr)								\
   ? __assert_fail (__STRING(expr), __FILE__, __LINE__, __ASSERT_FUNCTION) \
   : __ASSERT_VOID_CAST(0));

/* Main (parent) HTTP request processing states. */
enum {
    Req_0,
    /* Request line. */
    Req_Method,
    Req_Schema,
    Req_UriAuthorityStart,
    Req_UriAuthority,
    Req_UriAuthorityEnd,
    Req_UriAuthorityIPv6,
    Req_UriHost,
    Req_UriPort,
    Req_UriPortEnd,
    Req_Uri,
    Req_UriTail,
    Req_HttpVersion,
    /* Headers. */
    Req_Hdr,
    Req_HdrN,
    Req_HdrName,
    Req_HdrValue,
    Req_HdrValueN,
    /* Final state */
    Req_End,
    /* Special state flags */
    Req_Spaces = 0x8000, //skip spaces
    Req_ForceStart = 0x4000, //force startup of parser
};

#define __FSM_DECLARE_VARS(ptr)						\
    TfwHttpMsg	*msg = (TfwHttpMsg *)(ptr);			\
    TfwHttpParser	*parser = &msg->parser;				\
    unsigned char	*p = data;					\
    unsigned char	c = *p;						\
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
        0, 1, 2, 0xFF, 0, 1, 2, 3,     0, 1, 2, 3, 0xFF, 0xFF, 0xFF, 0xFF,
        'G','E','T',0, 'H','E','A','D','P','O','S','T',0,0,0,0,
        TFW_HTTP_METH_GET, 3,0,0,
        TFW_HTTP_METH_POST, 4,0,0,
        TFW_HTTP_METH_HEAD, 4,0,0,
        TFW_HTTP_METH_NONE, 0,0,0,
};
static const unsigned char __sse_schema[32] __attribute__((aligned(32))) = {
        0, 1, 2, 3,      4, 5, 6, 0xFF, 4, 5, 6, 7, 0xFF, 0xFF, 0xFF, 0xFF,
        'h','t','t','p', ':','/','/',0,'s',':','/','/',0,0,0,0
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
static const unsigned char __authority_charset[16] __attribute__((aligned(16))) = {
        0xa8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8,
        0xf8, 0xf8, 0xf0, 0x50, 0x50, 0x54, 0x54, 0x50
};
static const unsigned char __ipv6_hex_charset[16] __attribute__((aligned(16))) = {
        0x08, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x08,
        0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char __digit_charset[16] __attribute__((aligned(16))) = {
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char __uri_charset[16] __attribute__((aligned(16))) = {
        0xa8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8,
        0xf8, 0xf8, 0xf0, 0x54, 0x50, 0x54, 0x54, 0x54
};
static const unsigned char __header_charset[16] __attribute__((aligned(16))) = {
        0xa8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8,
        0xf8, 0xf8, 0xf0, 0x50, 0x50, 0x54, 0x50, 0x50
};
static const unsigned char __value_charset[16] __attribute__((aligned(16))) = {
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

static inline __m128i __match_charset(const unsigned char * charset, __m128i data) {
    __m128i sm = _mm_load_si128((const __m128i*)charset);
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
}

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

#define __store_symbols(p, n, vec) \
    do {\
       _mm_store_si128((__m128i*)storebuf, vec);\
       for(int i = 0; i < n; ++i) {p[i] = storebuf[i];}\
    } while(0);
#define __msg_checkend(len, bytes) \
    len |= (1<<(bytes-1));

void __msg_field_add(TfwStr * str, unsigned char * pos) {
    unsigned char ** n = (unsigned char**)realloc(str->chunks, (str->num_chunks+1)*sizeof(unsigned char*));
    assert(n != NULL);
    str->chunks = n;
    str->chunks[str->num_chunks++] = pos;
}

void __msg_field_open(TfwStr * str, unsigned char * pos) {
    assert(str->flags == TFW_STR_EMPTY);
    str->flags = TFW_STR_OPEN;
    str->chunks = 0;
    str->num_chunks = 0;
    __msg_field_add(str, pos);
}
void __msg_field_fixup(TfwStr * str, unsigned char * pos) {
    assert(str->flags == TFW_STR_OPEN);
    __msg_field_add(str, pos);
}
void __msg_field_finish(TfwStr * str, unsigned char * pos) {
    assert(str->flags == TFW_STR_OPEN);
    __msg_field_add(str, pos);
    str->flags = TFW_STR_CLOSED;
}

#define TFW_STR_INIT(str) {(str)->flags = TFW_STR_EMPTY; (str)->chunks = 0; (str)->num_chunks = 0;}
#define TFW_STR_EMPTY(str) ((str)->flags == TFW_STR_EMPTY)

void __print_sse(const char * prefix, __m128i sm) {
    unsigned char * data = (unsigned char*)&sm;
    printf(prefix);
    printf("|  0 |  1 |  2 |  3 |  4 |  5 |  6 |  7 "
           "|  8 |  9 | 10 | 11 | 12 | 13 | 14 | 15 |\n");

    printf("+----+----+----+----+----+----+----+----"
           "+----+----+----+----+----+----+----+----+\n");
    for(int i = 0; i < 16; ++i)
    printf("| %02x ", data[i]);
    printf("|\n");
    for(int i = 0; i < 16; ++i)
    printf("|  %c ", isprint(data[i]) ? data[i] : '.');
    printf("|\n");
}

void
tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start);
void
tfw_http_msg_hdr_chunk_fixup(TfwHttpMsg *hm, char *data, int len);
int
tfw_http_msg_hdr_close(TfwHttpMsg *hm, int id);

void
tfw_http_parse_init(void *req_data)
{
    TfwHttpReq *req = (TfwHttpReq *)req_data;
    memset(req, 0, sizeof(*req));
    req->parser.state = Req_Method;
}

int
tfw_http_parse_req(void *req_data, unsigned char *data, size_t len)
{
    int r = TFW_BLOCK;
    TfwHttpReq *req = (TfwHttpReq *)req_data;

    int bytes_cached = req->bytes_cached;
    int bytes_shifted = req->bytes_shifted;
    int nc;

    unsigned char storebuf[16] __attribute__((aligned(16)));

    __FSM_DECLARE_VARS(req);

    TFW_DBG("parse %lu client data bytes (%.*s) on req=%p\n",
        len, (int)len, data, req);

    for(;;) {
        printf("bytes cached %d, bytes_shifted %d, len %d\n", bytes_cached, bytes_shifted, len);
        //read some bytes until we get a end of buffer or 16 bytes
        while (bytes_cached < 16 && len) {
            req->latch16[bytes_shifted + bytes_cached] = data[0];
            ++bytes_cached;
            ++data;
            --len;
        }
        printf("bytes cached %d, bytes_shifted %d, len %d\n", bytes_cached, bytes_shifted, len);
        //load bytes
        __m128i compresult;
        __m128i vec = _mm_loadu_si128((__m128i*)(req->latch16+bytes_shifted));
        c = req->latch16[bytes_shifted];
        __print_sse("**************************************\n", vec);
        //check if there are enough bytes or at least a newline
        //or we have an unfinished chunk

        if (bytes_cached < 16)
        {
            //force parser start in following states:
            //a)req->current_field != 0
            //b)at least one byte is available and state is:
            //   Req_UriAuthorityStart
            //   Req_UriAuthority
            //   Req_UriHost
            //   Req_UriAuthorityIPv6
            //   Req_Hdr
            //force field fixup if we ate all chars
            if (parser->state & Req_ForceStart) {
                if (!bytes_cached) {
                    if (req->current_field)
                        __msg_field_fixup(req->current_field, p);
                    if (req->current_header_head)
                        tfw_http_msg_hdr_chunk_fixup(msg,
                                                 req->current_header_head,
                                                 req->current_header_len);
                    req->current_header_head = 0;

                    req->bytes_cached = 0;
                    req->bytes_shifted = 0;
                    r = TFW_POSTPONE;
                    break;
                }
            } else {
                nc = _mm_movemask_epi8(_mm_cmpeq_epi8(vec, _mm_load_si128((__m128i*)__sse_newline)));
                nc = __builtin_ctz(nc+1);
                if (nc > bytes_cached) {
                    req->bytes_cached = bytes_cached;
                    req->bytes_shifted = bytes_shifted;
                    r = TFW_POSTPONE;
                    break;
                }
            }
        }
        _mm_storeu_si128((__m128i*)req->latch16, vec);
        bytes_shifted = 0;

        //pre-skip spaces if they are expected
        if (parser->state & Req_Spaces) {
            nc = _mm_movemask_epi8(_mm_cmpeq_epi8(vec, _mm_load_si128((__m128i*)__sse_spaces)));
            nc = __builtin_ctz(nc+1);
            if (!nc) return TFW_BLOCK;
            if (nc != 16) parser->state &= ~ Req_Spaces;

            //store bytes back to parser state for further realignment
            bytes_shifted = nc;
            bytes_cached -= nc;
            p += nc;
            continue;
        }

        switch((parser->state &~ Req_ForceStart)) {
        __FSM_STATE(Req_0){
            parser->state = Req_Method;
            }
        __FSM_STATE(Req_Method){
            BUG_ON(req->current_field != 0);
            //we support only GET/HEAD/POST
            compresult = _mm_shuffle_epi8(vec, _mm_load_si128((__m128i*)__sse_method));
            compresult = _mm_cmpeq_epi32(compresult, _mm_load_si128((__m128i*)(__sse_method+16)));
            compresult = _mm_and_si128(compresult, _mm_load_si128((__m128i*)(__sse_method+32)));
            compresult = _mm_hadd_epi32(compresult, compresult);
            compresult = _mm_hadd_epi32(compresult, compresult);
            nc = _mm_extract_epi16(compresult, 0);
            req->method = 0xFF & nc;
            bytes_shifted = nc>>8;
            if (!bytes_shifted) return TFW_BLOCK;
            parser->state = Req_Schema|Req_Spaces;
            break;}
        __FSM_STATE(Req_Schema){
            BUG_ON(req->current_field != 0);
            //we support only http:// and https://
            //FIXME: should we support https://?
            compresult = _mm_shuffle_epi8(vec, _mm_load_si128((__m128i*)__sse_schema));
            compresult = _mm_cmpeq_epi32(compresult, _mm_load_si128((__m128i*)(__sse_schema+16)));
            int nc = _mm_movemask_epi8(compresult);
            parser->state = Req_UriAuthorityStart|Req_ForceStart;
            if (nc != 0xF0FF && nc != 0xFF0F)
                goto Req_UriAuthorityStart;

            nc = (0x1 & (nc >> 8)) + 7;//lenght of "http://"
            bytes_shifted = nc;
            break;}
        __FSM_STATE(Req_UriAuthorityStart){
            compresult = __match_charset(__authority_charset, vec);
            nc = _mm_movemask_epi8(compresult);
            //check if we've run out of bytes and consume only
            __msg_checkend(nc, bytes_cached);
            nc = __builtin_ctz(nc+1);
            if (nc > 0) {
                //lowercase symbols
                __msg_field_open(&req->host, p);
                vec = __sse_lowercase(vec);
                __store_symbols(p, nc, vec);
                req->current_field = &req->host;
                req->current_field_tail = p+nc;
                bytes_shifted = nc;

                parser->state = Req_UriAuthority|Req_ForceStart;
                break;
            }
            if (c == '/') {
                TFW_DBG3("Handling http:///path\n");
                __msg_field_open(&req->host, p);
                __msg_field_finish(&req->host, p);

                parser->state = Req_Uri|Req_ForceStart;
                goto Req_Uri;
            } else if (c == '[') {
                __msg_field_open(&req->host, p);
                req->current_field = &req->host;
                req->current_field_tail = p;
                bytes_shifted = 1;
                parser->state = Req_UriAuthorityIPv6|Req_ForceStart;
                break;
            }
            return TFW_BLOCK;}
        __FSM_STATE(Req_UriAuthority){
            switch (c) {
            case '@':
                if (!TFW_STR_EMPTY(&req->userinfo)) {
                    TFW_DBG("Second '@' in authority\n");
                    return TFW_BLOCK;
                }
                TFW_DBG3("Authority contains userinfo\n");
                /* copy current host to userinfo */
                req->userinfo = req->host;

                __msg_field_finish(&req->userinfo, p);
                req->current_field = 0;
                req->current_field_tail = 0;

                TFW_STR_INIT(&req->host);

                bytes_shifted = 1;
                parser->state = Req_UriHost|Req_ForceStart;
                break;
            case '\r':case '\n':
            case ':':case '/':case ' ':
                __msg_field_finish(&req->host, p);
                req->current_field = 0;
                req->current_field_tail = 0;

                goto Req_UriAuthorityEnd;
            default:
                compresult = __match_charset(__authority_charset, vec);
                nc = _mm_movemask_epi8(compresult);
                __msg_checkend(nc, bytes_cached);
                nc = __builtin_ctz(nc+1);
                if (!nc) return TFW_BLOCK;

                vec = __sse_lowercase(vec);
                __store_symbols(p, nc, vec);
                req->current_field = &req->host;
                req->current_field_tail = p+nc;
                bytes_shifted = nc;

                break;
            }
            break;}
        __FSM_STATE(Req_UriHost){
            if (likely(c != '[')) {
                compresult = __match_charset(__authority_charset, vec);
                nc = _mm_movemask_epi8(compresult);
                __msg_checkend(nc, bytes_cached);
                nc = __builtin_ctz(nc+1);
                if (!nc) return TFW_BLOCK;

                __msg_field_open(&req->host, p);
                vec = __sse_lowercase(vec);
                __store_symbols(p, nc, vec);
                req->current_field = &req->host;
                req->current_field_tail = p+nc;
                bytes_shifted = nc;
                parser->state = Req_UriAuthority|Req_ForceStart;
                break;
            }
            }//move to ipv6
        __FSM_STATE(Req_UriAuthorityIPv6){
            if (c == ']') {
                __msg_field_finish(&req->host, p);
                req->current_field = 0;
                req->current_field_tail = 0;

                bytes_shifted = 1;
                parser->state = Req_UriAuthorityEnd;
                break;
            }
            compresult = __match_charset(__ipv6_hex_charset, vec);
            nc = _mm_movemask_epi8(compresult);
            __msg_checkend(nc, bytes_cached);
            nc = __builtin_ctz(nc+1);
            if (!nc) return TFW_BLOCK;

            vec = __sse_lowercase(vec);
            __store_symbols(p, nc, vec);
            req->current_field = &req->host;
            req->current_field_tail = p+nc;
            bytes_shifted = nc;
            break;}
        __FSM_STATE(Req_UriAuthorityEnd){
            switch(c) {
            case ':':
                parser->state = Req_UriPort;
                goto Req_UriPort;
            case '/':
                parser->state = Req_Uri|Req_ForceStart;
                goto Req_Uri;
            case ' ':
                parser->state = Req_HttpVersion|Req_Spaces;
                break;
            case '\r':case '\n':
                parser->state = Req_HttpVersion;
                goto Req_HttpVersion;
            default:
                return TFW_BLOCK;
            }
            break;}
        __FSM_STATE(Req_UriPort){
            vec = _mm_alignr_epi8(_mm_setzero_si128(), vec, 1);
            compresult = __match_charset(__digit_charset, vec);
            nc = _mm_movemask_epi8(compresult);
            nc = __builtin_ctz(nc+1);
            if (!nc) return TFW_BLOCK;
            //make sure port is valid
            do {
                long long pn = __parse_number(vec, nc);
                if (pn < 1 || pn > 65535) return TFW_BLOCK;
            }while(0);

            bytes_shifted = nc;
            parser->state = Req_UriPortEnd;
            break;}
        __FSM_STATE(Req_UriPortEnd){
            switch(c) {
            case '/':
                parser->state = Req_Uri|Req_ForceStart;
                goto Req_Uri;
            case ' ':
                parser->state = Req_HttpVersion|Req_Spaces;
                goto Req_HttpVersion;
            default:
                return TFW_BLOCK;
            }}
        __FSM_STATE(Req_Uri){
            __msg_field_open(&req->uri_path, p);
            compresult = __match_charset(__uri_charset, vec);
            nc = _mm_movemask_epi8(compresult);
            __msg_checkend(nc, bytes_cached);
            nc = __builtin_ctz(nc+1);
            req->current_field = &req->uri_path;
            req->current_field_tail = p+nc;
            bytes_shifted = nc;
            parser->state = Req_UriTail|Req_ForceStart;
            break;}
        __FSM_STATE(Req_UriTail){
            compresult = __match_charset(__uri_charset, vec);
            nc = _mm_movemask_epi8(compresult);
            __msg_checkend(nc, bytes_cached);
            nc = __builtin_ctz(nc+1);

            if (!nc) {
                __msg_field_finish(req->current_field, req->current_field_tail);
                req->current_field = 0;
                req->current_field_tail = 0;
                if (c == ' ') {
                    parser->state = Req_HttpVersion|Req_Spaces;
                    break;
                }
                if (c == '\r' || c == '\n') {
                    parser->state = Req_HttpVersion;
                    goto Req_HttpVersion;
                }
            }

            req->current_field = &req->uri_path;
            req->current_field_tail = p+nc;
            bytes_shifted = nc;
            break;}
        __FSM_STATE(Req_HttpVersion){
            compresult = _mm_shuffle_epi8(vec, _mm_load_si128((const __m128i*)__sse_version));
            compresult = _mm_cmpeq_epi8(compresult, _mm_load_si128((const __m128i*)(__sse_version+16)));
            nc = _mm_movemask_epi8(compresult);
            nc = (nc + 0x2809) & 0x9404;

            compresult = _mm_cmpeq_epi8(vec, _mm_load_si128((const __m128i*)__sse_newline));
            __print_sse("NL\n", compresult);

            if (nc & 0x4) {
                req->version = TFW_HTTP_VER_09;
            } else if (nc == 0x9400) {
                req->version = TFW_HTTP_VER_10 +
                    (req->latch16[7]-'0');
            } else {
                return TFW_BLOCK;
            }
            nc = _mm_movemask_epi8(compresult);
            bytes_shifted = __builtin_ctz(nc|0x10000)+1;
            parser->state = Req_Hdr;
            break;}
        __FSM_STATE(Req_Hdr){
            //don't support multiline headers
            if (c == ' ')
                return TFW_BLOCK;
            //check if headers are over
            if (c == '\n') goto Req_End;
            if (c == '\r') {
                bytes_shifted = 1;
                parser->state = Req_HdrN;
                break;
            }
            //grab as many characters as possible
            compresult = __match_charset(__header_charset, vec);
            nc = _mm_movemask_epi8(compresult);
            __msg_checkend(nc, bytes_cached);
            nc = __builtin_ctz(nc+1);
            if (!nc) return TFW_BLOCK;

            //store prefix for later checks
            //_mm_store_si128((__m128i*)req->header_prefix, vec);

            //open header and add
            tfw_http_msg_hdr_open(msg, p);
            req->current_header_head = p;
            req->current_header_len  = nc;
            bytes_shifted = nc;
            parser->state = Req_HdrName|Req_ForceStart;
            break;}
        __FSM_STATE(Req_HdrN){
            if (unlikely(c != '\n')) return TFW_BLOCK;
            goto Req_End;}
        __FSM_STATE(Req_HdrName){
            if (c == ':') {
                if (!req->current_header_head) {
                    req->current_header_head = p;
                    req->current_header_len = 1;
                }
                tfw_http_msg_hdr_chunk_fixup(msg,
                                             req->current_header_head,
                                             req->current_header_len+1);
                //FIXME: parse name of header and store it's index
                bytes_shifted = 1;
                parser->state = Req_HdrValue|Req_Spaces|Req_ForceStart;
                break;
            }
            //grab as many characters as possible
            compresult = __match_charset(__header_charset, vec);
            nc = _mm_movemask_epi8(compresult);
            __msg_checkend(nc, bytes_cached);
            nc = __builtin_ctz(nc+1);
            if (!nc) return TFW_BLOCK;

            if (!req->current_header_head) {
                req->current_header_head = p;
                req->current_header_len = 0;
            }

            req->current_header_len+=nc;
            bytes_shifted = nc;
            break;}
        __FSM_STATE(Req_HdrValue){
            if (c == '\n') goto Req_HdrValueN;
            if (c == '\r') {
                parser->state = Req_HdrValueN;
                bytes_shifted = 1;
                break;
            }
            //grab as many characters as possible
            compresult = __match_charset(__value_charset, vec);
            nc = _mm_movemask_epi8(compresult);
            __msg_checkend(nc, bytes_cached);
            nc = __builtin_ctz(nc+1);
            if (!nc) return TFW_BLOCK;
            if (!req->current_header_head) {
                req->current_header_head = p;
                req->current_header_len = 0;
            }

            req->current_header_len += nc;
            bytes_shifted = nc;
            break;}
        __FSM_STATE(Req_HdrValueN){
            if (unlikely(c != '\n')) return TFW_BLOCK;
            if (req->current_header_head) {
                tfw_http_msg_hdr_chunk_fixup(msg,
                                             req->current_header_head,
                                             req->current_header_len);
                req->current_header_head = 0;
            }
            tfw_http_msg_hdr_close(msg, 0);
            bytes_shifted = 1;
            parser->state = Req_Hdr|Req_ForceStart;
            break;}
        __FSM_STATE(Req_End)
            r = TFW_PASS;
            break;
        }

        p += bytes_shifted;
        bytes_cached -= bytes_shifted;

        if (r == TFW_PASS)
            break;
    }
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
