/**
 * This is very similar that Ragel generates, bu it uses states only to
 * save current state between calls and the states aren't used for the
 * machine process.
 */
#include <stdint.h>
#include <string.h>

#include "goto_parser.h"

#define FSM_START(s)							\
switch (s)

#define STATE(st)							\
case st:								\
st:

#define EXIT(st)							\
do {									\
    r->state = st;							\
    goto done;							\
} while (0)

#define MOVE_n(from, to, n)						\
do {									\
    p += n;								\
    ch = *p;							\
    if (__builtin_expect(!ch || p == buf + len, 0))			\
        EXIT(from);						\
    goto to;							\
} while (0)

#define MOVE(from, to)	MOVE_n(from, to, 1)

/**
 * Light weight version of Nginx header parser.
 */
int
goto_header_line(ngx_http_request_t *r, unsigned char *buf, int len)
{
    unsigned char	  c, ch, *p = buf;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_almost_done,
        sw_header_almost_done
    };

    // init
    ch = *p;
    FSM_START(r->state) {

    /* first char */
    STATE(sw_start) {
        r->header_name_start = p;
        r->invalid_header = 0;

        switch (ch) {
        case '\r':
            r->header_end = p;
            MOVE(sw_start, sw_header_almost_done);
        case '\n':
            r->header_end = p;
            goto done;
        default:
            if (ch == '\0')
                return 1;
            MOVE(sw_start, sw_name);
        }
    }

    /* header name */
    STATE(sw_name) {
        if (ch == '_')
            MOVE(sw_name, sw_name);

        if (ch == ':') {
            r->header_name_end = p;
            MOVE(sw_name, sw_space_before_value);
        }

        if (ch == '\r') {
            r->header_name_end = p;
            r->header_start = p;
            r->header_end = p;
            MOVE(sw_name, sw_almost_done);
        }

        if (ch == '\n') {
            r->header_name_end = p;
            r->header_start = p;
            r->header_end = p;
            goto done;
        }

        if (ch == '\0')
            return 1;

        MOVE(sw_name, sw_name);
    }

    /* space* before header value */
    STATE(sw_space_before_value) {
        switch (ch) {
        case ' ':
            MOVE(sw_space_before_value, sw_space_before_value);
        case '\r':
            r->header_start = p;
            r->header_end = p;
            MOVE(sw_space_before_value, sw_almost_done);
        case '\n':
            r->header_start = p;
            r->header_end = p;
            goto done;
        case '\0':
            return 1;
        default:
            r->header_start = p;
            MOVE(sw_space_before_value, sw_value);
        }
    }

    /* header value */
    STATE(sw_value) {
        switch (ch) {
        case '\r':
            r->header_end = p;
            MOVE(sw_value, sw_almost_done);
        case '\n':
            r->header_end = p;
            goto done;
        case '\0':
            return 1;
        }
        MOVE(sw_value, sw_value);
    }

    /* end of header line */
    STATE(sw_almost_done) {
        switch (ch) {
        case '\n':
            goto done;
        case '\r':
            MOVE(sw_almost_done, sw_almost_done);
        default:
            return 1;
        }
    }

    /* end of header */
    STATE(sw_header_almost_done) {
        switch (ch) {
        case '\n':
            goto done;
        default:
            return 1;
        }
    }
    } // FSM_START

done:
    return 0;
}

/**
 * Big version of Nginx header parser to test huge automatons.
 */
int
goto_big_header_line(ngx_http_request_t *r, unsigned char *buf, int len)
{
    unsigned char	  c, ch, *p = buf;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_almost_done,
        sw_header_almost_done,
        s0_0, s0_1, s0_2, s0_3, s0_4, s0_5, s0_6, s0_7, s0_8, s0_9,
        s1_0, s1_1, s1_2, s1_3, s1_4, s1_5, s1_6, s1_7, s1_8, s1_9,
        s2_0, s2_1, s2_2, s2_3, s2_4, s2_5, s2_6, s2_7, s2_8, s2_9,
        s3_0, s3_1, s3_2, s3_3, s3_4, s3_5, s3_6, s3_7, s3_8, s3_9,
        s4_0, s4_1, s4_2, s4_3, s4_4, s4_5, s4_6, s4_7, s4_8, s4_9,
        s5_0, s5_1, s5_2, s5_3, s5_4, s5_5, s5_6, s5_7, s5_8, s5_9,
        s6_0, s6_1, s6_2, s6_3, s6_4, s6_5, s6_6, s6_7, s6_8, s6_9,
        s7_0, s7_1, s7_2, s7_3, s7_4, s7_5, s7_6, s7_7, s7_8, s7_9,
        s8_0, s8_1, s8_2, s8_3, s8_4, s8_5, s8_6, s8_7, s8_8, s8_9,
        s9_0, s9_1, s9_2, s9_3, s9_4, s9_5, s9_6, s9_7, s9_8, s9_9,
        s10_0, s10_1, s10_2, s10_3, s10_4, s10_5, s10_6, s10_7, s10_8, s10_9,
        s11_0, s11_1, s11_2, s11_3, s11_4, s11_5, s11_6, s11_7, s11_8, s11_9,
        s12_0, s12_1, s12_2, s12_3, s12_4, s12_5, s12_6, s12_7, s12_8, s12_9,
        s13_0, s13_1, s13_2, s13_3, s13_4, s13_5, s13_6, s13_7, s13_8, s13_9,
        s14_0, s14_1, s14_2, s14_3, s14_4, s14_5, s14_6, s14_7, s14_8, s14_9,
        s15_0, s15_1, s15_2, s15_3, s15_4, s15_5, s15_6, s15_7, s15_8, s15_9,
        s16_0, s16_1, s16_2, s16_3, s16_4, s16_5, s16_6, s16_7, s16_8, s16_9,
        s17_0, s17_1, s17_2, s17_3, s17_4, s17_5, s17_6, s17_7, s17_8, s17_9,
        s18_0, s18_1, s18_2, s18_3, s18_4, s18_5, s18_6, s18_7, s18_8, s18_9,
        s19_0, s19_1, s19_2, s19_3, s19_4, s19_5, s19_6, s19_7, s19_8, s19_9,
        s20_0, s20_1, s20_2, s20_3, s20_4, s20_5, s20_6, s20_7, s20_8, s20_9,
        s21_0, s21_1, s21_2, s21_3, s21_4, s21_5, s21_6, s21_7, s21_8, s21_9,
        s22_0, s22_1, s22_2, s22_3, s22_4, s22_5, s22_6, s22_7, s22_8, s22_9,
        s23_0, s23_1, s23_2, s23_3, s23_4, s23_5, s23_6, s23_7, s23_8, s23_9,
        s24_0, s24_1, s24_2, s24_3, s24_4, s24_5, s24_6, s24_7, s24_8, s24_9,
        s25_0, s25_1, s25_2, s25_3, s25_4, s25_5, s25_6, s25_7, s25_8, s25_9,
        s26_0, s26_1, s26_2, s26_3, s26_4, s26_5, s26_6, s26_7, s26_8, s26_9,
        s27_0, s27_1, s27_2, s27_3, s27_4, s27_5, s27_6, s27_7, s27_8, s27_9,
        s28_0, s28_1, s28_2, s28_3, s28_4, s28_5, s28_6, s28_7, s28_8, s28_9,
        s29_0, s29_1, s29_2, s29_3, s29_4, s29_5, s29_6, s29_7, s29_8, s29_9,
        s30_0, s30_1, s30_2, s30_3, s30_4, s30_5, s30_6, s30_7, s30_8, s30_9,
        s31_0, s31_1, s31_2, s31_3, s31_4, s31_5, s31_6, s31_7, s31_8, s31_9,
        s32_0, s32_1, s32_2, s32_3, s32_4, s32_5, s32_6, s32_7, s32_8, s32_9,
        s33_0, s33_1, s33_2, s33_3, s33_4, s33_5, s33_6, s33_7, s33_8, s33_9,
        s34_0, s34_1, s34_2, s34_3, s34_4, s34_5, s34_6, s34_7, s34_8, s34_9,
        s35_0, s35_1, s35_2, s35_3, s35_4, s35_5, s35_6, s35_7, s35_8, s35_9,
        s36_0, s36_1, s36_2, s36_3, s36_4, s36_5, s36_6, s36_7, s36_8, s36_9,
        s37_0, s37_1, s37_2, s37_3, s37_4, s37_5, s37_6, s37_7, s37_8, s37_9,
        s38_0, s38_1, s38_2, s38_3, s38_4, s38_5, s38_6, s38_7, s38_8, s38_9,
        s39_0, s39_1, s39_2, s39_3, s39_4, s39_5, s39_6, s39_7, s39_8, s39_9,
    };

    // init
    ch = *p;
    FSM_START(r->state) {

    /* first char */
    STATE(sw_start) {
        r->header_name_start = p;
        r->invalid_header = 0;

        switch (ch) {
        case '\r':
            r->header_end = p;
            MOVE(sw_start, sw_header_almost_done);
        case '\n':
            r->header_end = p;
            goto done;
        default:
            if (ch == '\0')
                return 1;
            MOVE(sw_start, sw_name);
        }
    }

    /* header name */
    STATE(sw_name) {
        if (ch == '_')
            MOVE(sw_name, sw_name);

        if (ch == ':') {
            r->header_name_end = p;
            MOVE(sw_name, sw_space_before_value);
        }

        if (ch == '\r') {
            r->header_name_end = p;
            r->header_start = p;
            r->header_end = p;
            MOVE(sw_name, sw_almost_done);
        }

        if (ch == '\n') {
            r->header_name_end = p;
            r->header_start = p;
            r->header_end = p;
            goto done;
        }

        if (ch == '\0')
            return 1;

        MOVE(sw_name, sw_name);
    }

    /* space* before header value */
    STATE(sw_space_before_value) {
        switch (ch) {
        case ' ':
            MOVE(sw_space_before_value, sw_space_before_value);
        case '\r':
            r->header_start = p;
            r->header_end = p;
            MOVE(sw_space_before_value, sw_almost_done);
        case '\n':
            r->header_start = p;
            r->header_end = p;
            goto done;
        case '\0':
            return 1;
        default:
            r->header_start = p;
            MOVE(sw_space_before_value, sw_value);
        }
    }

    /* header value */
    STATE(sw_value) {
        switch (ch) {
        case 'a': MOVE(sw_value, s0_0);
        case 'b': MOVE(sw_value, s1_0);
        case 'c': MOVE(sw_value, s2_0);
        case 'd': MOVE(sw_value, s3_0);
        case 'e': MOVE(sw_value, s4_0);
        case 'f': MOVE(sw_value, s5_0);
        case 'g': MOVE(sw_value, s6_0);
        case 'h': MOVE(sw_value, s7_0);
        case 'i': MOVE(sw_value, s8_0);
        case 'j': MOVE(sw_value, s9_0);
        case 'k': MOVE(sw_value, s10_0);
        case 'l': MOVE(sw_value, s11_0);
        case 'm': MOVE(sw_value, s12_0);
        case 'n': MOVE(sw_value, s13_0);
        case 'o': MOVE(sw_value, s14_0);
        case 'p': MOVE(sw_value, s15_0);
        case 'q': MOVE(sw_value, s16_0);
        case 'r': MOVE(sw_value, s17_0);
        case 's': MOVE(sw_value, s18_0);
        case 't': MOVE(sw_value, s19_0);
        case 'u': MOVE(sw_value, s20_0);
        case 'v': MOVE(sw_value, s21_0);
        case 'w': MOVE(sw_value, s22_0);
        case 'x': MOVE(sw_value, s23_0);
        case 'y': MOVE(sw_value, s24_0);
        case 'z': MOVE(sw_value, s25_0);
        case '0': MOVE(sw_value, s26_0);
        case '1': MOVE(sw_value, s27_0);
        case '2': MOVE(sw_value, s28_0);
        case '3': MOVE(sw_value, s29_0);
        case '4': MOVE(sw_value, s30_0);
        case '5': MOVE(sw_value, s31_0);
        case '6': MOVE(sw_value, s32_0);
        case '7': MOVE(sw_value, s33_0);
        case '8': MOVE(sw_value, s34_0);
        case '9': MOVE(sw_value, s35_0);
        case 'A': MOVE(sw_value, s36_0);
        case 'B': MOVE(sw_value, s37_0);
        case 'C': MOVE(sw_value, s38_0);
        case 'D': MOVE(sw_value, s39_0);
        case '\r':
            r->header_end = p;
            MOVE(sw_value, sw_almost_done);
        case '\n':
            r->header_end = p;
            goto done;
        case '\0':
            return 1;
        }
        MOVE(sw_value, sw_value);
    }

#define __DUMMY_STATE_0(i)						\
    STATE(s ## i ## _0) {						\
        switch (ch) {						\
        case 'a': MOVE(s ## i ## _0, s ## i ## _1);		\
        case 'b': MOVE(s ## i ## _0, s ## i ## _2);		\
        case 'c': MOVE(s ## i ## _0, s ## i ## _3);		\
        case 'd': MOVE(s ## i ## _0, s ## i ## _4);		\
        case 'e': MOVE(s ## i ## _0, s ## i ## _5);		\
        case 'f': MOVE(s ## i ## _0, s ## i ## _6);		\
        case 'g': MOVE(s ## i ## _0, s ## i ## _7);		\
        case 'h': MOVE(s ## i ## _0, s ## i ## _8);		\
        case 'i': MOVE(s ## i ## _0, s ## i ## _9);		\
        case '\r':						\
            r->header_end = p;				\
            MOVE(s ## i ## _0, sw_almost_done);		\
        case '\n':						\
            r->header_end = p;				\
            goto done;					\
        case '\0':						\
            return 1;					\
        default:						\
            MOVE(s ## i ## _0, sw_value);			\
        }							\
    }

#define __DUMMY_STATE_n(i, j)						\
    STATE(s ## i ## _ ## j) {					\
        switch (ch) {						\
        case '\r':						\
            r->header_end = p;				\
            MOVE(s ## i ## _ ## j, sw_almost_done);		\
        case '\n':						\
            r->header_end = p;				\
            goto done;					\
        case '\0':						\
            return 1;					\
        default:						\
            MOVE(s ## i ## _ ## j, sw_value);		\
        }							\
    }

#define DUMMY_STATE(s)							\
    __DUMMY_STATE_0(s);	__DUMMY_STATE_n(s, 1);			\
    __DUMMY_STATE_n(s, 2); __DUMMY_STATE_n(s, 3);			\
    __DUMMY_STATE_n(s, 4); __DUMMY_STATE_n(s, 5);			\
    __DUMMY_STATE_n(s, 6); __DUMMY_STATE_n(s, 7);			\
    __DUMMY_STATE_n(s, 8); __DUMMY_STATE_n(s, 9)

    DUMMY_STATE(0); DUMMY_STATE(1); DUMMY_STATE(2); DUMMY_STATE(3);
    DUMMY_STATE(4); DUMMY_STATE(5); DUMMY_STATE(6); DUMMY_STATE(7);
    DUMMY_STATE(8); DUMMY_STATE(9); DUMMY_STATE(10); DUMMY_STATE(11);
    DUMMY_STATE(12); DUMMY_STATE(13); DUMMY_STATE(14); DUMMY_STATE(15);
    DUMMY_STATE(16); DUMMY_STATE(17); DUMMY_STATE(18); DUMMY_STATE(19);
    DUMMY_STATE(20); DUMMY_STATE(21); DUMMY_STATE(22); DUMMY_STATE(23);
    DUMMY_STATE(24); DUMMY_STATE(25); DUMMY_STATE(26); DUMMY_STATE(27);
    DUMMY_STATE(28); DUMMY_STATE(29); DUMMY_STATE(30); DUMMY_STATE(31);
    DUMMY_STATE(32); DUMMY_STATE(33); DUMMY_STATE(34); DUMMY_STATE(35);
    DUMMY_STATE(36); DUMMY_STATE(37); DUMMY_STATE(38); DUMMY_STATE(39);

    /* end of header line */
    STATE(sw_almost_done) {
        switch (ch) {
        case '\n':
            goto done;
        case '\r':
            MOVE(sw_almost_done, sw_almost_done);
        default:
            return 1;
        }
    }

    /* end of header */
    STATE(sw_header_almost_done) {
        switch (ch) {
        case '\n':
            goto done;
        default:
            return 1;
        }
    }
    } // FSM_START

done:
    return 0;
}

#define LF	(unsigned char)10
#define CR	(unsigned char)13

#define ngx_str3_cmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define ngx_str3Ocmp(m, c0, c1, c2, c3)                                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define ngx_str4cmp(m, c0, c1, c2, c3)                                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && m[4] == c4

#define ngx_str6cmp(m, c0, c1, c2, c3, c4, c5)                                \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && (((uint32_t *) m)[1] & 0xffff) == ((c5 << 8) | c4)

#define ngx_str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                       \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define ngx_str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define ngx_str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
    *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
        && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)  \
        && m[8] == c8

static uint32_t  usual[] = {
    0xffffdbfe, /* 1111 1111 1111 1111  1101 1011 1111 1110 */

                /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */

                /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
};

int
goto_request_line(ngx_http_request_t *r, unsigned char *buf, int len)
{
    unsigned char c, ch, *m, *p = buf;
    enum {
        sw_start = 0,
        sw_method,
        sw_spaces_before_uri,
        sw_schema,
        sw_schema_slash,
        sw_schema_slash_slash,
        sw_host_start,
        sw_host,
        sw_host_end,
        sw_host_ip_literal,
        sw_port,
        sw_host_http_09,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_check_uri_http_09,
        sw_uri,
        sw_http_09,
        sw_http_H,
        sw_http_HT,
        sw_http_HTT,
        sw_http_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_spaces_after_digit,
        sw_almost_done
    } state;

    // init
    ch = *p;
    FSM_START(r->state) {

    STATE(sw_start) {
        r->request_start = p;

        if (ch == '\r' || ch == '\n')
            MOVE(sw_start, sw_start);

        if ((ch < 'A' || ch > 'Z') && ch != '_')
            return 1;

        MOVE(sw_start, sw_method);
    }

    STATE(sw_method) {
        if (ch == ' ') {
            r->method_end = p - 1;
            m = r->request_start;

            switch (p - m) {
            case 3:
                if (ngx_str3_cmp(m, 'G', 'E', 'T', ' '))
                    r->method = NGX_HTTP_GET;
                else if (ngx_str3_cmp(m, 'P', 'U', 'T', ' '))
                    r->method = NGX_HTTP_PUT;
                MOVE(sw_method, sw_spaces_before_uri);
            case 4:
                if (m[1] == 'O') {
                    if (ngx_str4cmp(m, 'P', 'O', 'S', 'T'))
                        r->method = NGX_HTTP_POST;
                    else if (ngx_str4cmp(m, 'C', 'O', 'P', 'Y'))
                        r->method = NGX_HTTP_COPY;
                    else if (ngx_str4cmp(m, 'M', 'O', 'V', 'E'))
                        r->method = NGX_HTTP_MOVE;
                    else if (ngx_str4cmp(m, 'L', 'O', 'C', 'K'))
                        r->method = NGX_HTTP_LOCK;
                } else {
                    if (ngx_str4cmp(m, 'H', 'E', 'A', 'D'))
                        r->method = NGX_HTTP_HEAD;
                }
                MOVE(sw_method, sw_spaces_before_uri);
            case 5:
                if (ngx_str5cmp(m, 'M', 'K', 'C', 'O', 'L'))
                    r->method = NGX_HTTP_MKCOL;
                else if (ngx_str5cmp(m, 'P', 'A', 'T', 'C', 'H'))
                    r->method = NGX_HTTP_PATCH;
                else if (ngx_str5cmp(m, 'T', 'R', 'A', 'C', 'E'))
                    r->method = NGX_HTTP_TRACE;
                MOVE(sw_method, sw_spaces_before_uri);
            case 6:
                if (ngx_str6cmp(m, 'D', 'E', 'L', 'E', 'T', 'E'))
                    r->method = NGX_HTTP_DELETE;
                else if (ngx_str6cmp(m, 'U', 'N', 'L', 'O', 'C', 'K'))
                    r->method = NGX_HTTP_UNLOCK;
                MOVE(sw_method, sw_spaces_before_uri);
            case 7:
                if (ngx_str7_cmp(m, 'O', 'P', 'T', 'I', 'O', 'N', 'S', ' '))
                    r->method = NGX_HTTP_OPTIONS;
                MOVE(sw_method, sw_spaces_before_uri);
            case 8:
                if (ngx_str8cmp(m, 'P', 'R', 'O', 'P', 'F', 'I', 'N', 'D'))
                    r->method = NGX_HTTP_PROPFIND;
                MOVE(sw_method, sw_spaces_before_uri);
            case 9:
                if (ngx_str9cmp(m, 'P', 'R', 'O', 'P', 'P', 'A', 'T', 'C', 'H'))
                    r->method = NGX_HTTP_PROPPATCH;
                MOVE(sw_method, sw_spaces_before_uri);
            }

            MOVE(sw_method, sw_spaces_before_uri);
        }

        if ((ch < 'A' || ch > 'Z') && ch != '_')
            return 1;

        MOVE(sw_method, sw_method);
    }

    /* space* before URI */
    STATE(sw_spaces_before_uri) {
        if (ch == '/') {
            r->uri_start = p;
            MOVE(sw_spaces_before_uri, sw_after_slash_in_uri);
        }

        c = (unsigned char) (ch | 0x20);
        if (c >= 'a' && c <= 'z') {
            r->schema_start = p;
            MOVE(sw_spaces_before_uri, sw_schema);
        }

        switch (ch) {
        case ' ':
            MOVE(sw_spaces_before_uri, sw_spaces_before_uri);
        default:
            return 1;
        }
        MOVE(sw_spaces_before_uri, sw_spaces_before_uri);
    }

    STATE(sw_schema) {
        c = (unsigned char) (ch | 0x20);
        if (c >= 'a' && c <= 'z')
            MOVE(sw_schema, sw_schema);

        switch (ch) {
        case ':':
            r->schema_end = p;
            MOVE(sw_schema, sw_schema_slash);
        default:
            return 1;
        }
        MOVE(sw_schema, sw_schema);
    }

    STATE(sw_schema_slash) {
        switch (ch) {
        case '/':
            MOVE(sw_schema_slash, sw_schema_slash_slash);
        default:
            return 1;
        }
        MOVE(sw_schema_slash, sw_schema_slash);
    }

    STATE(sw_schema_slash_slash) {
        switch (ch) {
        case '/':
            MOVE(sw_schema_slash_slash, sw_host_start);
        default:
            return 1;
        }
        MOVE(sw_schema_slash_slash, sw_schema_slash_slash);
    }

    STATE(sw_host_start) {
        r->host_start = p;
        if (ch == '[')
            MOVE(sw_host_start, sw_host_ip_literal);
    }

    /* fall through */

    STATE(sw_host) {
        c = (unsigned char) (ch | 0x20);
        if (c >= 'a' && c <= 'z')
            MOVE(sw_host, sw_host);
        if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-')
            MOVE(sw_host, sw_host);
    }

    /* fall through */

    STATE(sw_host_end) {
        r->host_end = p;

        switch (ch) {
        case ':':
            MOVE(sw_host_end, sw_port);
        case '/':
            r->uri_start = p;
            MOVE(sw_host_end, sw_after_slash_in_uri);
        case ' ':
            r->uri_start = r->schema_end + 1;
            r->uri_end = r->schema_end + 2;
            MOVE(sw_host_end, sw_host_http_09);
        default:
            return 1;
        }
        MOVE(sw_host_end, sw_host_end);
    }

    STATE(sw_host_ip_literal) {
        if (ch >= '0' && ch <= '9')
            MOVE(sw_host_ip_literal, sw_host_ip_literal);

        c = (unsigned char) (ch | 0x20);
        if (c >= 'a' && c <= 'z')
            MOVE(sw_host_ip_literal, sw_host_ip_literal);

        switch (ch) {
        case ':':
            MOVE(sw_host_ip_literal, sw_host_ip_literal);
        case ']':
            MOVE(sw_host_ip_literal, sw_host_end);
        case '-':
        case '.':
        case '_':
        case '~':
        case '!':
        case '$':
        case '&':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case ',':
        case ';':
        case '=':
            MOVE(sw_host_ip_literal, sw_host_ip_literal);
        default:
            return 1;
        }
        MOVE(sw_host_ip_literal, sw_host_ip_literal);
    }

    STATE(sw_port) {
        if (ch >= '0' && ch <= '9')
            MOVE(sw_port, sw_port);

        switch (ch) {
        case '/':
            r->port_end = p;
            r->uri_start = p;
            MOVE(sw_port, sw_after_slash_in_uri);
        case ' ':
            r->port_end = p;
            r->uri_start = r->schema_end + 1;
            r->uri_end = r->schema_end + 2;
            MOVE(sw_port, sw_host_http_09);
        default:
            return 1;
        }
        MOVE(sw_port, sw_port);
    }

    /* space+ after "http://host[:port] " */
    STATE(sw_host_http_09) {
        switch (ch) {
        case ' ':
            MOVE(sw_host_http_09, sw_host_http_09);
        case CR:
            r->http_minor = 9;
            MOVE(sw_host_http_09, sw_almost_done);
        case LF:
            r->http_minor = 9;
            goto done;
        case 'H':
            MOVE(sw_host_http_09, sw_http_H);
        default:
            return 1;
        }
        MOVE(sw_host_http_09, sw_host_http_09);
    }

    /* check "/.", "//", "%", and "\" (Win32) in URI */
    STATE(sw_after_slash_in_uri) {
        if (usual[ch >> 5] & (1 << (ch & 0x1f)))
            MOVE(sw_after_slash_in_uri, sw_check_uri);
        switch (ch) {
        case ' ':
            r->uri_end = p;
            MOVE(sw_after_slash_in_uri, sw_check_uri_http_09);
        case CR:
            r->uri_end = p;
            r->http_minor = 9;
            MOVE(sw_after_slash_in_uri, sw_almost_done);
        case LF:
            r->uri_end = p;
            r->http_minor = 9;
            goto done;
        case '.':
        case '%':
        case '/':
            MOVE(sw_after_slash_in_uri, sw_uri);
        case '?':
            r->args_start = p + 1;
            MOVE(sw_after_slash_in_uri, sw_uri);
        case '#':
            MOVE(sw_after_slash_in_uri, sw_uri);
        case '+':
            MOVE(sw_after_slash_in_uri, sw_after_slash_in_uri);
        case '\0':
            return 1;
        default:
            MOVE(sw_after_slash_in_uri, sw_check_uri);
        }
        MOVE(sw_after_slash_in_uri, sw_after_slash_in_uri);
    }

    /* check "/", "%" and "\" (Win32) in URI */
    STATE(sw_check_uri) {
        if (usual[ch >> 5] & (1 << (ch & 0x1f)))
            MOVE(sw_check_uri, sw_check_uri);
        switch (ch) {
        case '/':
            MOVE(sw_check_uri, sw_after_slash_in_uri);
        case '.':
            MOVE(sw_check_uri, sw_check_uri);
        case ' ':
            r->uri_end = p;
            MOVE(sw_check_uri, sw_check_uri_http_09);
        case CR:
            r->uri_end = p;
            r->http_minor = 9;
            MOVE(sw_check_uri, sw_almost_done);
        case LF:
            r->uri_end = p;
            r->http_minor = 9;
            goto done;
        case '%':
            MOVE(sw_check_uri, sw_uri);
        case '?':
            r->args_start = p + 1;
        case '#':
            MOVE(sw_check_uri, sw_uri);
        case '+':
            MOVE(sw_check_uri, sw_check_uri);
        case '\0':
            return 1;
        }
        MOVE(sw_check_uri, sw_check_uri);
    }

    /* space+ after URI */
    STATE(sw_check_uri_http_09) {
        switch (ch) {
        case ' ':
            MOVE(sw_check_uri_http_09, sw_check_uri_http_09);
        case CR:
            r->http_minor = 9;
            MOVE(sw_check_uri_http_09, sw_almost_done);
        case LF:
            r->http_minor = 9;
            goto done;
        case 'H':
            MOVE(sw_check_uri_http_09, sw_http_H);
        default:
            MOVE(sw_check_uri_http_09, sw_check_uri);
        }
        MOVE(sw_check_uri_http_09, sw_check_uri_http_09);
    }

    /* URI */
    STATE(sw_uri) {
        if (usual[ch >> 5] & (1 << (ch & 0x1f)))
            MOVE(sw_uri, sw_uri);
        switch (ch) {
        case ' ':
            r->uri_end = p;
            MOVE(sw_uri, sw_http_09);
        case CR:
            r->uri_end = p;
            r->http_minor = 9;
            MOVE(sw_uri, sw_almost_done);
        case LF:
            r->uri_end = p;
            r->http_minor = 9;
            goto done;
        case '#':
            MOVE(sw_uri, sw_uri);
        case '\0':
            return 1;
        }
        MOVE(sw_uri, sw_uri);
    }

    /* space+ after URI */
    STATE(sw_http_09) {
        switch (ch) {
        case ' ':
            MOVE(sw_http_09, sw_http_09);
        case CR:
            r->http_minor = 9;
            MOVE(sw_http_09, sw_almost_done);
        case LF:
            r->http_minor = 9;
            goto done;
        case 'H':
            MOVE(sw_http_09, sw_http_H);
        default:
            MOVE(sw_http_09, sw_uri);
        }
        MOVE(sw_http_09, sw_http_09);
    }

    STATE(sw_http_H) {
        switch (ch) {
        case 'T':
            MOVE(sw_http_H, sw_http_HT);
        default:
            return 1;
        }
        MOVE(sw_http_H, sw_http_H);
    }

    STATE(sw_http_HT) {
        switch (ch) {
        case 'T':
            MOVE(sw_http_HT, sw_http_HTT);
        default:
            return 1;
        }
        MOVE(sw_http_HT, sw_http_HT);
    }

    STATE(sw_http_HTT) {
        switch (ch) {
        case 'P':
            MOVE(sw_http_HTT, sw_http_HTTP);
        default:
            return 1;
        }
        MOVE(sw_http_HTT, sw_http_HTT);
    }

    STATE(sw_http_HTTP) {
        switch (ch) {
        case '/':
            MOVE(sw_http_HTTP, sw_first_major_digit);
        default:
            return 1;
        }
        MOVE(sw_http_HTTP, sw_http_HTTP);
    }

    /* first digit of major HTTP version */
    STATE(sw_first_major_digit) {
        if (ch < '1' || ch > '9')
            return 1;
        r->http_major = ch - '0';
        MOVE(sw_first_major_digit, sw_major_digit);
    }

    /* major HTTP version or dot */
    STATE(sw_major_digit) {
        if (ch == '.')
            MOVE(sw_major_digit, sw_first_minor_digit);
        if (ch < '0' || ch > '9')
            return 1;
        r->http_major = r->http_major * 10 + ch - '0';
        MOVE(sw_major_digit, sw_major_digit);
    }

    /* first digit of minor HTTP version */
    STATE(sw_first_minor_digit) {
        if (ch < '0' || ch > '9')
            return 1;
        r->http_minor = ch - '0';
        MOVE(sw_first_minor_digit, sw_minor_digit);
    }

    /* minor HTTP version or end of request line */
    STATE(sw_minor_digit) {
        if (ch == CR)
            MOVE(sw_minor_digit, sw_almost_done);
        if (ch == LF)
            goto done;
        if (ch == ' ')
            MOVE(sw_minor_digit, sw_spaces_after_digit);
        if (ch < '0' || ch > '9')
            return 1;
        r->http_minor = r->http_minor * 10 + ch - '0';
        MOVE(sw_minor_digit, sw_minor_digit);
    }

    STATE(sw_spaces_after_digit) {
        switch (ch) {
        case ' ':
            MOVE(sw_spaces_after_digit, sw_spaces_after_digit);
        case CR:
            MOVE(sw_spaces_after_digit, sw_almost_done);
        case LF:
            goto done;
        default:
            return 1;
        }
        MOVE(sw_spaces_after_digit, sw_spaces_after_digit);
    }

    /* end of request line */
    STATE(sw_almost_done) {
        r->request_end = p - 1;
        switch (ch) {
        case LF:
            goto done;
        default:
            return 1;
        }
    }
    } // FSM_START

done:
    return 0;
}

int
goto_opt_request_line(ngx_http_request_t *r, unsigned char *buf, int len)
{
    unsigned char c, ch, *p = buf;
    enum {
        sw_start = 0,
        sw_method,
        sw_spaces_before_uri,
        sw_schema,
        sw_schema_slash,
        sw_schema_slash_slash,
        sw_host_start,
        sw_host,
        sw_host_end,
        sw_host_ip_literal,
        sw_port,
        sw_host_http_09,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_check_uri_http_09,
        sw_uri,
        sw_http_09,
        sw_http_H,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_spaces_after_digit,
        sw_almost_done
    } state;

    // init
    ch = *p;
    FSM_START(r->state) {

    STATE(sw_start) {
        r->request_start = p;

        /* OPTIMIZATION: static branch prediction */
        if (unlikely(ch == '\r' || ch == '\n'))
            MOVE(sw_start, sw_start);
    }

    /* OPTIMIZATION: fall through */

    STATE(sw_method) {
        /* OPTIMIZATION: Move most frequent methods forward. */
        if (likely(ngx_str3_cmp(p, 'G', 'E', 'T', ' '))) {
            int n = sizeof("GET") - 1;
            r->method = NGX_HTTP_GET;
            r->method_end = p + n;
            MOVE_n(sw_method, sw_spaces_before_uri, n + 1);
        }
        else if (likely(ngx_str3_cmp(p, 'P', 'U', 'T', ' '))) {
            int n = sizeof("PUT") - 1;
            r->method = NGX_HTTP_PUT;
            r->method_end = p + n;
            MOVE_n(sw_method, sw_spaces_before_uri, n + 1);
        }
        else if (likely(ngx_str4cmp(p, 'P', 'O', 'S', 'T'))) {
            int n = sizeof("POST") - 1;
            r->method = NGX_HTTP_POST;
            r->method_end = p + n;
            MOVE_n(sw_method, sw_spaces_before_uri, n);
        }

#define MATCH(num, str)							\
do {									\
    int n = sizeof(str) - 1;					\
    r->method = num;						\
    r->method_end = p + n;						\
    MOVE_n(sw_method, sw_spaces_before_uri, n);			\
} while (0)

        switch (ch) {
        /* OPTIMIZATION: observe the data only once. */
        case 'G':
            if (ngx_str5cmp(p, 'P', 'A', 'T', 'C', 'H')) {
                MATCH(NGX_HTTP_PATCH, "PATCH");
            }
            else if (ngx_str8cmp(p, 'P', 'R', 'O', 'P', 'F', 'I',
                        'N', 'D'))
            {
                MATCH(NGX_HTTP_PROPFIND, "PROPFIND");
            }
            else if (ngx_str9cmp(p, 'P', 'R', 'O', 'P', 'P', 'A',
                        'T', 'C', 'H'))
            {
                MATCH(NGX_HTTP_PROPPATCH, "PROPPATCH");
            }
            break;
        case 'C':
            if (ngx_str4cmp(p, 'C', 'O', 'P', 'Y'))
                MATCH(NGX_HTTP_COPY, "COPY");
            break;
        case 'D':
            if (ngx_str6cmp(p, 'D', 'E', 'L', 'E', 'T', 'E'))
                MATCH(NGX_HTTP_DELETE, "DELETE");
            break;
        case 'H':
            if (ngx_str4cmp(p, 'H', 'E', 'A', 'D'))
                MATCH(NGX_HTTP_HEAD, "HEAD");
            break;
        case 'L':
            if (ngx_str4cmp(p, 'L', 'O', 'C', 'K'))
                MATCH(NGX_HTTP_LOCK, "LOCK");
            break;
        case 'M':
            if (ngx_str4cmp(p, 'M', 'O', 'V', 'E')) {
                MATCH(NGX_HTTP_MOVE, "MOVE");
            }
            else if (ngx_str5cmp(p, 'M', 'K', 'C', 'O', 'L')) {
                MATCH(NGX_HTTP_MKCOL, "MKCOL");
            }
            break;
        case 'O':
            if (ngx_str7_cmp(p, 'O', 'P', 'T', 'I', 'O', 'N', 'S', ' '))
                MATCH(NGX_HTTP_OPTIONS, "OPTIONS");
            break;
        case 'T':
             if (ngx_str5cmp(p, 'T', 'R', 'A', 'C', 'E'))
                MATCH(NGX_HTTP_TRACE, "TRACE");
             break;
        case 'U':
            if (ngx_str6cmp(p, 'U', 'N', 'L', 'O', 'C', 'K'))
                MATCH(NGX_HTTP_UNLOCK, "UNLOCK");
            break;
        }

        return 1;
    }

    /* space* before URI */
    STATE(sw_spaces_before_uri) {
        if (likely(ch == '/')) {
            r->uri_start = p;
            MOVE(sw_spaces_before_uri, sw_after_slash_in_uri);
        }

        c = (unsigned char) (ch | 0x20);
        if (likely(c >= 'a' && c <= 'z')) {
            r->schema_start = p;
            MOVE(sw_spaces_before_uri, sw_schema);
        }

        switch (ch) {
        case ' ':
            MOVE(sw_spaces_before_uri, sw_spaces_before_uri);
        default:
            return 1;
        }
    }

    STATE(sw_schema) {
        c = (unsigned char) (ch | 0x20);
        if (c >= 'a' && c <= 'z')
            MOVE(sw_schema, sw_schema);

        switch (ch) {
        case ':':
            r->schema_end = p;
            MOVE(sw_schema, sw_schema_slash);
        default:
            return 1;
        }
    }

    STATE(sw_schema_slash) {
        switch (ch) {
        case '/':
            MOVE(sw_schema_slash, sw_schema_slash_slash);
        default:
            return 1;
        }
    }

    STATE(sw_schema_slash_slash) {
        switch (ch) {
        case '/':
            MOVE(sw_schema_slash_slash, sw_host_start);
        default:
            return 1;
        }
    }

    STATE(sw_host_start) {
        r->host_start = p;
        if (ch == '[')
            MOVE(sw_host_start, sw_host_ip_literal);
    }

    /* fall through */

    STATE(sw_host) {
        c = (unsigned char) (ch | 0x20);
        if (c >= 'a' && c <= 'z')
            MOVE(sw_host, sw_host);
        if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-')
            MOVE(sw_host, sw_host);
    }

    /* fall through */

    STATE(sw_host_end) {
        r->host_end = p;

        switch (ch) {
        case ':':
            MOVE(sw_host_end, sw_port);
        case '/':
            r->uri_start = p;
            MOVE(sw_host_end, sw_after_slash_in_uri);
        case ' ':
            r->uri_start = r->schema_end + 1;
            r->uri_end = r->schema_end + 2;
            MOVE(sw_host_end, sw_host_http_09);
        default:
            return 1;
        }
    }

    STATE(sw_host_ip_literal) {
        if (ch >= '0' && ch <= '9')
            MOVE(sw_host_ip_literal, sw_host_ip_literal);

        c = (unsigned char) (ch | 0x20);
        if (c >= 'a' && c <= 'z')
            MOVE(sw_host_ip_literal, sw_host_ip_literal);

        switch (ch) {
        case ':':
            MOVE(sw_host_ip_literal, sw_host_ip_literal);
        case ']':
            MOVE(sw_host_ip_literal, sw_host_end);
        case '-':
        case '.':
        case '_':
        case '~':
        case '!':
        case '$':
        case '&':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case ',':
        case ';':
        case '=':
            MOVE(sw_host_ip_literal, sw_host_ip_literal);
        default:
            return 1;
        }
    }

    STATE(sw_port) {
        if (ch >= '0' && ch <= '9')
            MOVE(sw_port, sw_port);

        switch (ch) {
        case '/':
            r->port_end = p;
            r->uri_start = p;
            MOVE(sw_port, sw_after_slash_in_uri);
        case ' ':
            r->port_end = p;
            r->uri_start = r->schema_end + 1;
            r->uri_end = r->schema_end + 2;
            MOVE(sw_port, sw_host_http_09);
        default:
            return 1;
        }
    }

    /* space+ after "http://host[:port] " */
    STATE(sw_host_http_09) {
        switch (ch) {
        case ' ':
            MOVE(sw_host_http_09, sw_host_http_09);
        case CR:
            r->http_minor = 9;
            MOVE(sw_host_http_09, sw_almost_done);
        case LF:
            r->http_minor = 9;
            goto done;
        case 'H':
            MOVE(sw_host_http_09, sw_http_H);
        default:
            return 1;
        }
    }

    /* check "/.", "//", "%", and "\" (Win32) in URI */
    STATE(sw_after_slash_in_uri) {
        if (usual[ch >> 5] & (1 << (ch & 0x1f)))
            MOVE(sw_after_slash_in_uri, sw_check_uri);
        switch (ch) {
        case ' ':
            r->uri_end = p;
            MOVE(sw_after_slash_in_uri, sw_check_uri_http_09);
        case CR:
            r->uri_end = p;
            r->http_minor = 9;
            MOVE(sw_after_slash_in_uri, sw_almost_done);
        case LF:
            r->uri_end = p;
            r->http_minor = 9;
            goto done;
        case '?':
            r->args_start = p + 1;
        case '#':
        case '.':
        case '%':
        case '/':
            MOVE(sw_after_slash_in_uri, sw_uri);
        case '+':
            MOVE(sw_after_slash_in_uri, sw_after_slash_in_uri);
        case '\0':
            return 1;
        default:
            MOVE(sw_after_slash_in_uri, sw_check_uri);
        }
    }

    /* check "/", "%" and "\" (Win32) in URI */
    STATE(sw_check_uri) {
        if (usual[ch >> 5] & (1 << (ch & 0x1f)))
            MOVE(sw_check_uri, sw_check_uri);
        switch (ch) {
        case '/':
            MOVE(sw_check_uri, sw_after_slash_in_uri);
        case '.':
            MOVE(sw_check_uri, sw_check_uri);
        case ' ':
            r->uri_end = p;
            MOVE(sw_check_uri, sw_check_uri_http_09);
        case CR:
            r->uri_end = p;
            r->http_minor = 9;
            MOVE(sw_check_uri, sw_almost_done);
        case LF:
            r->uri_end = p;
            r->http_minor = 9;
            goto done;
        case '%':
            MOVE(sw_check_uri, sw_uri);
        case '?':
            r->args_start = p + 1;
        case '#':
            MOVE(sw_check_uri, sw_uri);
        case '+':
            MOVE(sw_check_uri, sw_check_uri);
        case '\0':
            return 1;
        }
        MOVE(sw_check_uri, sw_check_uri);
    }

    /* space+ after URI */
    STATE(sw_check_uri_http_09) {
        switch (ch) {
        /* OPTIMIZATION: move the most frequent path to begin. */
        case 'H':
            MOVE(sw_check_uri_http_09, sw_http_H);
        case ' ':
            MOVE(sw_check_uri_http_09, sw_check_uri_http_09);
        case CR:
            r->http_minor = 9;
            MOVE(sw_check_uri_http_09, sw_almost_done);
        case LF:
            r->http_minor = 9;
            goto done;
        default:
            MOVE(sw_check_uri_http_09, sw_check_uri);
        }
    }

    /* URI */
    STATE(sw_uri) {
        if (usual[ch >> 5] & (1 << (ch & 0x1f)))
            MOVE(sw_uri, sw_uri);
        switch (ch) {
        case ' ':
            r->uri_end = p;
            MOVE(sw_uri, sw_http_09);
        case CR:
            r->uri_end = p;
            r->http_minor = 9;
            MOVE(sw_uri, sw_almost_done);
        case LF:
            r->uri_end = p;
            r->http_minor = 9;
            goto done;
        case '#':
            MOVE(sw_uri, sw_uri);
        case '\0':
            return 1;
        }
        MOVE(sw_uri, sw_uri);
    }

    /* space+ after URI */
    STATE(sw_http_09) {
        switch (ch) {
        case ' ':
            MOVE(sw_http_09, sw_http_09);
        case CR:
            r->http_minor = 9;
            MOVE(sw_http_09, sw_almost_done);
        case LF:
            r->http_minor = 9;
            goto done;
        case 'H':
            MOVE(sw_http_09, sw_http_H);
        default:
            MOVE(sw_http_09, sw_uri);
        }
    }

    /* OPTIMIZATION: read "HTTP/" at once. */
    STATE(sw_http_H) {
        if (unlikely(!ngx_str4cmp(p, 'T', 'T', 'P', '/')))
            return 1;
        MOVE_n(sw_http_H, sw_first_major_digit, 4);
    }

    /* first digit of major HTTP version */
    STATE(sw_first_major_digit) {
        if (ch < '1' || ch > '9')
            return 1;
        r->http_major = ch - '0';
        MOVE(sw_first_major_digit, sw_major_digit);
    }

    /* major HTTP version or dot */
    STATE(sw_major_digit) {
        if (ch == '.')
            MOVE(sw_major_digit, sw_first_minor_digit);
        if (ch < '0' || ch > '9')
            return 1;
        r->http_major = r->http_major * 10 + ch - '0';
        MOVE(sw_major_digit, sw_major_digit);
    }

    /* first digit of minor HTTP version */
    STATE(sw_first_minor_digit) {
        if (ch < '0' || ch > '9')
            return 1;
        r->http_minor = ch - '0';
        MOVE(sw_first_minor_digit, sw_minor_digit);
    }

    /* minor HTTP version or end of request line */
    STATE(sw_minor_digit) {
        if (ch == CR)
            MOVE(sw_minor_digit, sw_almost_done);
        if (ch == LF)
            goto done;
        if (ch == ' ')
            MOVE(sw_minor_digit, sw_spaces_after_digit);
        if (ch < '0' || ch > '9')
            return 1;
        r->http_minor = r->http_minor * 10 + ch - '0';
        MOVE(sw_minor_digit, sw_minor_digit);
    }

    STATE(sw_spaces_after_digit) {
        switch (ch) {
        case ' ':
            MOVE(sw_spaces_after_digit, sw_spaces_after_digit);
        case CR:
            MOVE(sw_spaces_after_digit, sw_almost_done);
        case LF:
            goto done;
        default:
            return 1;
        }
    }

    /* end of request line */
    STATE(sw_almost_done) {
        r->request_end = p - 1;
        switch (ch) {
        case LF:
            goto done;
        default:
            return 1;
        }
    }
    } // FSM_START

done:
    return 0;
}


