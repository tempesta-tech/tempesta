int

TFW_PARSE_HEADER_NAME

(void *req_data, unsigned char *data, size_t len)
{
    TfwHttpReq *req = (TfwHttpReq *)req_data;
    _mm_store_si128((__m128i*)req->parser.latch16, _mm_setzero_si128());
    req->parser.state = Req_Hdr;
    req->parser.charset1 = __sse_header_charset;
    req->parser.bytes_cached = 0;
    req->parser.bytes_shifted = 0;
    req->parser.current_field = 0;
    req->parser.header_chunk_start = 0;
    return TFW_PARSE_REQ_NAME(req, data, len);
}

int

TFW_PARSE_REQ_NAME

(void * restrict req_data, unsigned char * restrict data, size_t len)
{
    int r = TFW_BLOCK;
    TfwHttpReq *req = (TfwHttpReq *)req_data;
    __FSM_DECLARE_VARS(req);

    register __m128i vec;
    register __m128i _r_charset;
    register __m128i _r_spaces;
    register __m128i _r_cset1;
    register __m128i _r_cset2;

    _r_spaces  = _mm_load_si128((const __m128i*)__sse_spaces);
    _r_cset1   = _mm_load_si128((const __m128i*)__sse_charset);
    _r_cset2   = _mm_load_si128((const __m128i*)(__sse_charset+16));

    unsigned char * base = data, * end = data + len;
    int bytes_cached = parser->bytes_cached;
    int bytes_shifted = parser->bytes_shifted;
    int state;

	TFW_DBG("parse %lu client data bytes (%.*s) on req=%p\n",
    len, (int)len, data, req);

    state = parser->state;
    vec   = _mm_load_si128((const __m128i*)parser->latch16);
    if (unlikely(state == Req_0)) {
        bytes_cached = 0;
        bytes_shifted = 0;
        parser->current_field = 0;
        parser->header_chunk_start = 0;
        vec = _mm_setzero_si128();
        TFW_STR_INIT(&req->host);
        TFW_STR_INIT(&req->uri_path);
#ifdef ENABLE_FAST_FORWARD
        if (len >= 16) {
            vec = _mm_lddqu_si128((const __m128i*)data);
            //check method
            __m128i compresult = _mm_shuffle_epi32(vec, _MM_SHUFFLE(0,0,0,0));
            compresult = _mm_cmpeq_epi32(compresult, _mm_ref(__sse_method));
            int nc = _mm_movemask_epi8(compresult);
            if (unlikely(!nc)) return TFW_BLOCK;
            req->method = 0xF&((allmethod_mask & nc)*0x1111>>4);

            //don't delete nc: we will need to combine it with next result
            //check for "http:// " or " http://"
            compresult = _mm_shuffle_epi32(vec, _MM_SHUFFLE(2,1,2,1));
            //here we have a bad byte #7
            compresult = _mm_cmpeq_epi8(compresult, _mm_ref(__sse_schema));
            //we have to deal with it without SSE
            int sc = _mm_movemask_epi8(compresult);
            sc |= 0x80 & (sc<<3);//don't use bit #6!!!
            //sc must be 0xFF00 or 0x00FF, but due to per-byte comparisons, we will
            //have 'parasitic' bits
            //h t t p : / /
            //  h t t p : / /
            //    *       *
            // resulting in 0xFF44 and 0x44FF

            //allowed combinations of nc and sc are:
            //nc = 0x00FF and sc = anything; bytes_shifted = 4; state = Req_BeginSchema
            //nc = 0x00FF and sc = 0x44FF; bytes_shifted = 11; state = Req_HostReset
            //nc = 0xFF00 and sc = 0xFF44; bytes_shifted = 12; state = Req_HostReset
            //nc = 0xFF00 and sc = 0x0100; bytes_shifted = 5; state = Req_BeginSchema
            if (nc > 255) {
                if (!sc & 0x100) return TFW_BLOCK;

                bytes_shifted = 5;
                if (sc == 0xFF44) bytes_shifted = 12;
            } else {
                bytes_shifted = 4;
                if (sc == 0x44FF) bytes_shifted = 11;
            }
            bytes_cached = 16 - bytes_shifted;
            data += 16;
            len  -= 16;
            parser->charset1 = __sse_host_charset;
            state = Req_BeginSchema|Req_Spaces;
            if (bytes_shifted > 10)
                state = Req_HostReset|Req_Spaces;
        } else {
#endif
            parser->charset1 = __sse_method_charset;
            state = Req_Method;
#ifdef ENABLE_FAST_FORWARD
        }
#endif
    }
    vec = _mm_shuffle_epi8(vec, _mm_right(bytes_shifted));
    _r_charset = _mm_load_si128((const __m128i*)parser->charset1);

    for(;;) {
        unsigned char * fixup_ptr = data - bytes_cached;
        if (bytes_cached < 16) {
            if (unlikely(r == TFW_POSTPONE || (len + bytes_cached == 0)))
            {
                //если пакет закончился, надо fixupнуть строки
                //потому что больше мы никогда не увидим этот SKB
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
            int n = min(16 - bytes_cached, len);
            //avoid page faults here
            long ldata = (long)data;
            __m128i compresult;
            if (unlikely(len < 16 && (ldata&0xFF0 > 0xFF0))) {
                compresult = _mm_lddqu_si128((const __m128i*)(ldata & ~0xFL));
                compresult = _mm_shuffle_epi8(compresult, _mm_right(ldata & 0xF));
            } else {
                compresult = _mm_lddqu_si128((const __m128i*)ldata);
            }
            compresult = _mm_shuffle_epi8(compresult, _mm_left(bytes_cached));
            vec = _mm_or_si128(vec, compresult);
            bytes_cached += n;;
            data += n;
            len -= n;
            r = TFW_BLOCK;
        }
        if (unlikely(r == TFW_POSTPONE)) {
            r = TFW_BLOCK;
            break;
        }
        bytes_shifted = 0;
        //========================================================
        //THIS REGION MUST BE OPTIMIZED BY COMPILER
        //========================================================
        TFW_PSSE("DATA\n", vec);
        //sleep(1);//uncomment this to see how parser eats symbols in DEBUG version

        int avail_mask = 0xFFFFFFFF << bytes_cached;
        //pre-skip spaces if they are expected
        if (unlikely(state & Req_Spaces)) {
            __m128i charset = _mm_cmpeq_epi8(vec, _r_spaces);
            int mask = (~_mm_movemask_epi8(charset))|avail_mask;
            if (unlikely((mask & 0x1)==0)) {
                int nc = __builtin_ctz(mask);
                vec = _mm_shuffle_epi8(vec, _mm_right(nc));
                if (nc < bytes_cached) state &= ~ Req_Spaces;
                //store bytes back to parser state for further realignment
                bytes_shifted = nc;
                bytes_cached -= nc;
                //move to the end of sequence
                continue;
            }
            state &= ~ Req_Spaces;
        } 
        //match charset
        __m128i charset1 = __match_charset(_r_charset, vec, _r_cset1, _r_cset2);
        int mask1 = (_mm_movemask_epi8(charset1))|avail_mask;
#ifdef ENABLE_FAST_FORWARD
        //fast forward mode: 
        if (state > Req_FastForward) {
            while (mask1 == 0xFFFF0000) {
                bytes_shifted = 0;
                bytes_cached  = 0;
                vec = _mm_setzero_si128();
                //check if we can accelerate fast-forward mode                
                if (len < 16) break;
                vec = _mm_lddqu_si128((const __m128i*)data);
                charset1 = __match_charset(_r_charset, vec, _r_cset1, _r_cset2);
                mask1 = (_mm_movemask_epi8(charset1))|avail_mask;
                data += 16;
                len  -= 16;
                bytes_cached = 16;
            }
            if (!bytes_cached) continue;
        }
#endif
        int nchars1 = __builtin_ctz(mask1);
        unsigned int lastchar = _mm_extract_epi16(
            _mm_shuffle_epi8(vec, _mm_right(nchars1)), 0);
        #define LAST ((unsigned char)lastchar)
        #define LAST2 ((unsigned short)lastchar)

        //========================================================
        //end of region to be optimized
        //========================================================
        switch (state) {
        __FSM_STATE(Req_Method) {
            //
            // в этом состоянии, мы уверены в следующем:
            // 1)parser->current_field = 0;
            // 2)parser->aux_field = 0;
            // 3)у нас есть некоторое количество подходящих байт и некоторое количество пробелов после.
            //
            //если мы не нашли пробелов после строки, просто ожидаем
            if (nchars1 >= bytes_cached) {
                r = TFW_POSTPONE;
                break;
            }
            if (LAST != ' ') return TFW_BLOCK;
            //we support only GET/HEAD/POST
            __m128i compresult = _mm_shuffle_epi32(vec, _MM_SHUFFLE(0,0,0,0));
            compresult = _mm_cmpeq_epi32(compresult, _mm_ref(__sse_method));
            int nc = _mm_movemask_epi8(compresult);
            if (!nc) return TFW_BLOCK;

            req->method = 0xF&((allmethod_mask & nc)*0x1111>>12);
            nc = 0xF&((allmethod_len & nc)*0x1111>>12);
            if (nc != nchars1) return TFW_BLOCK;//wrong lenght

            //consume all bytes and spaces
            bytes_shifted = nchars1+1;
            parser->charset1 = __sse_host_charset;
            //schedule skip_spaces skip if we have parsed all available bytes
            state = Req_BeginSchema;
            if (unlikely(LAST2 == 0x2020 || LAST2 == 0x0020)) {
                state |= Req_Spaces;
                break;
            }}
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
            int nc = ~_mm_movemask_epi8(_mm_cmpeq_epi8(vec, _mm_ref(__sse_schema)));
			nc |= 0xFFFFFF80;
            nc |= avail_mask;
            //попробуем понять, точно ли перед нами http://
            //проверим, есть ли расхождения:
            //байт есть 1 2 3 4 5 6 7 8
            //bytes1    1 2 3 4 4 4 4 х
            //bytes2    0 0 0 0 1 2 3 х
            //nc        1 2 3 4 5 6 7 7

            //если скорее всего получили http://
            if (likely((nc & 0x7F) == 0)) {
                bytes_shifted = 7;
                TFW_STR_INIT(&req->host);
                parser->current_field = NULL;
                parser->charset1 = __sse_host_charset;
                state = Req_HostReset;
                break;
            }

            if (unlikely(nc &~ avail_mask)) {
                if (nc & 0x1F) {
                    state = Req_Host;
                    break;
                }
                if (nc & 0x20) {
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
                if (nc & 0x20) {
                    __msg_field_finish_n(parser->current_field);
                    parser->current_field = NULL;
                }
            }
            r = TFW_POSTPONE;
            break;}
        __FSM_STATE(Req_HostReset) {
            parser->current_field = &req->host;
            __msg_field_open(&req->host, __fixup_address(0));
            state = Req_Host;
            /* continue */}
        __FSM_STATE(Req_Host) {
            bytes_shifted = nchars1;
            if (nchars1 == bytes_cached) break;

            unsigned char c = LAST;
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
            unsigned char c = LAST;
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
            case ' ': 
                parser->charset1 = __sse_version_charset;
                state = Req_HttpVersion;
                break;
            case '\r': case '\n':
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

            unsigned char c = LAST;
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
            unsigned char c = LAST;
            switch (c) {
            case '/':
                parser->charset1 = __sse_uri_charset;
                state = Req_Uri;
                break;
            case ' ': 
                parser->charset1 = __sse_version_charset;
                state = Req_HttpVersion;
                break;
            case '\r': case '\n':
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

            unsigned char c = LAST;
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
			__m128i compresult;

            compresult = _mm_cmpeq_epi8(vec, _mm_load_si128((__m128i*)(__sse_newline)));
            int nc = ~_mm_movemask_epi8(compresult);
            nc |= avail_mask;
            //need more data?
            if (nc == -1) {
                r = TFW_POSTPONE;
                break;
            }

            compresult = _mm_shuffle_epi8(vec, _mm_load_si128((const __m128i*)__sse_version));
            compresult = _mm_cmpeq_epi8(compresult, _mm_load_si128((const __m128i*)(__sse_version+16)));
            int ms = _mm_movemask_epi8(compresult);
            ms = (ms + 0x2809) & 0x9404;

            if (ms & 0x4) {
                req->version = TFW_HTTP_VER_09;
            } else if (ms == 0x9400) {
                unsigned char c = _mm_extract_epi16(vec, 3)>>8;
                req->version = TFW_HTTP_VER_10 +
                    (c-'0');
            } else {
                return TFW_BLOCK;
            }
            bytes_shifted = __builtin_ctz(nc+1)+1;
            parser->charset1 = __sse_header_charset;
            state = Req_Hdr;
            break;}
        __FSM_STATE(Req_Hdr) {
            BUG_ON(parser->current_field != NULL);
			TFW_STR_INIT(&parser->hdr);
            //don't support multiline headers
            if (!nchars1) {
                //check if headers are over
                unsigned short c2 = _mm_extract_epi16(vec, 0);
                if ((unsigned char)c2 == '\r') {
                    bytes_shifted = 1;
                    if (unlikely(bytes_cached < 2)) {
                        parser->charset1 = __sse_null_charset;
                        state = Req_HdrN;
                        break;
                    }
                }
                if (unlikely((c2>>8) != '\n'))
                    return TFW_BLOCK;
                ++bytes_shifted;
                goto Req_End;
            }
            //fast path for short headers which are likely
            //to fit into SKB
            if (likely(nchars1 < bytes_cached)) {
                if (LAST != ':')
                    return TFW_BLOCK;
                tfw_http_msg_hdr_open(msg, __fixup_address(0));
                tfw_http_msg_hdr_chunk_fixup(msg,
                                             __fixup_address(0),
                                             nchars1+1);
                //we don't start a chunk on spaces
                parser->current_field = &parser->hdr;
                parser->header_chunk_start = 0;
                //continue with value
                bytes_shifted= nchars1+1;
                if (LAST2 == 0x203A) ++bytes_shifted;
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
            if (unlikely(((unsigned char)_mm_extract_epi16(vec, 0)) != '\n')) return TFW_BLOCK;
            ++bytes_shifted;
            goto Req_End;}
        __FSM_STATE(Req_HdrName) {
            BUG_ON(parser->current_field == NULL);
            if (likely(nchars1 < bytes_cached)) {
                if (LAST != ':')
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
                bytes_shifted= nchars1+1;
                if (LAST2 == 0x203A) ++bytes_shifted;
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
                if (LAST == '\r') {
                    ++bytes_shifted;
                    if (unlikely(bytes_cached == bytes_shifted)) {
                        parser->charset1 = __sse_null_charset;
                        state = Req_HdrValueN;
                        break;
                    }
                    lastchar>>=8;
                }
                if (unlikely(LAST != '\n'))
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
            if (((unsigned char)_mm_extract_epi16(vec, 0)) != '\n') return TFW_BLOCK;
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
        if (r == TFW_PASS)
            break;
        vec = _mm_shuffle_epi8(vec, _mm_right(bytes_shifted));
        _r_charset = _mm_load_si128((const __m128i*)parser->charset1);

        bytes_cached -= bytes_shifted;
    }
    parser->state = state;
    parser->bytes_cached = bytes_cached;
    parser->bytes_shifted = bytes_shifted;
    _mm_store_si128((__m128i*)parser->latch16, vec);

    return r;
}
