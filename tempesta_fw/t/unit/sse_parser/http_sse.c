#include "http_sse.h"
#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <x86intrin.h>
#include <alloca.h>

enum {
    PS_Initial,
    PS_SkipSpaces,
    PS_BadState,
    PS_TooLong,
    PS_Method,
    PS_Schema,
    PS_HostnameStart,
    PS_Hostname,
    PS_HostnameEnd,
    PS_HostnameLiteral,
    PS_HostnameLiteralEnd,
    PS_Port,
    PS_PortEnd,
    PS_UriStart,
    PS_UriAddSpace,
    PS_UriCheckSlash,
    PS_UriCheckSymbols,
    PS_UriArgs,
    PS_UriArgsCheckSymbols,
    PS_UriCopyAsIs,
    PS_UriCopyAsIsCheckSymbols,
    PS_Eol,
    PS_Version,
    PS_Finish,

    PS_HeaderStart,
    PS_HeaderNext,
    PS_HeaderName,
    PS_HeaderNameCheckSymbols,
    PS_HeaderValue,
    PS_HeaderValueCheckSymbols,
};

#define GOTO(s1) {state = s1; goto s1;}
#define SKIPSPACES_NOW(s1) {state = PS_SkipSpaces; state_after_space = s1; goto PS_SkipSpaces;}

#define MOVE(s1) {state = s1; break;}
#define SKIPSPACES(s1) {state = PS_SkipSpaces; state_after_space = s1; break;}

void sse_ngx_request_init(struct sse_ngx_http_request_t * r, void * membuf, long membuf_size) {
    r->state = PS_Initial;
    r->state_after_newline = PS_HeaderStart;
    r->bytes_in_pd = r->bytes_in_wd = 0;
    r->method = 0;
    r->http_minor = r->http_major = 0;
    r->schema_start = r->schema_end =
    r->host_start = r->host_end = r->port_end =
    r->uri_start = r->uri_end = r->args_start = 0;
    r->pbuffer = membuf;
    long p = (long)membuf;
    long a = p & 0xF;
    p = (p + 0xF) &~ 0xF;
    a = (membuf_size - a) >> 4;
    r->wpos = (__m128i*)p;
    r->wend = (__m128i*)p + a;
    r->path_depth = 0;
    assert(r->wend > r->wpos);
}

extern struct Constants C;
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
        if (bytes_in_pd + size < 16) {
            int i;
            for(i = 0; i < size; ++i)
                tempbuf[i] = input[i];
            tempbuf[size] = 0;
            __m128i tmp   = _mm_lddqu_si128((const __m128i*)tempbuf);
            //test if there is a \r\n\r\n or equivalient
            int f = _mm_movemask_epi8(_mm_cmpeq_epi8(nd, c->_r));
            int n = _mm_movemask_epi8(_mm_cmpeq_epi8(nd, c->_n));
            f   >>= (16-bytes_in_pd);
            n   >>= (16-bytes_in_pd);
            int have_nn = n & (n>>1);
            int have_nrn = n & (f>>1) & (n>>2);

            if ((have_nn | have_nrn) == 0) {
                nd = _mm_align(c, nd, tmp, size);
                bytes_in_pd  += size;
                r->prev_data  = nd;
                r->write_data = wd;
                r->wpos       = destination;
                r->bytes_in_pd= bytes_in_pd;
                r->bytes_in_wd= bytes_in_wd;
                r->state      = state;
                r->state_after_space=state_after_space;
                r->state_after_space_if_not_version=after_space_if_not_version;
                return SPR_NEED_MORE_DATA;
            }
            //if we cannot fill a single sse register,
            //fill as much as possible, and check if
            //we have to force
            nd = _mm_align(c, nd, tmp, 16-bytes_in_pd);
            bytes_in_pd  += size;
        }

        if (likely(bytes_in_pd < 16))
        {
            if (unlikely(size < 16)) {
                int i;
                for(i = 0; i < size; ++i)
                    tempbuf[i] = input[i];
                tempbuf[size] = 0;
                source = (const __m128i*)tempbuf;
            }
            pd      = nd;
            nd      = _mm_lddqu_si128(source);
            bytes_in_pd += 16;
            source += 1;
            input  += 16;
            size   -= 16;
        }

        data = _mm_align(c, pd, nd, 32-bytes_in_pd);
        PRINTM("DATA = ", data);

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

void printm128(const char * msg, __m128i m) {
    char buf[16];
    int i;
    _mm_storeu_si128((__m128i*)buf,m);
    printf("%s | %02x %02x %02x %02x "
              "| %02x %02x %02x %02x "
              "| %02x %02x %02x %02x "
              "| %02x %02x %02x %02x |\n",
           msg, 0xFF&buf[0], 0xFF&buf[1], 0xFF&buf[2], 0xFF&buf[3],
            0xFF&buf[4], 0xFF&buf[5], 0xFF&buf[6], 0xFF&buf[7],
            0xFF&buf[8], 0xFF&buf[9], 0xFF&buf[10], 0xFF&buf[11],
            0xFF&buf[12], 0xFF&buf[13], 0xFF&buf[14], 0xFF&buf[15]);
    printf("%s | ", msg);
    for(i = 0; i < 16; ++i) {
        char c = buf[i];
        if (c < 0 || !isprint(c)) c = '.';
        printf(" %c ", c);
        if ((i & 0x3) == 0x3)
            printf("| ");
    }
    printf("\n");
}


