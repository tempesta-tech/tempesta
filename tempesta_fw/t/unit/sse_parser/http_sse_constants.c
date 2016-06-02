#include "http_sse.h"

#define NGX_HTTP_GET_BIT                 1//      0x0002
#define NGX_HTTP_HEAD_BIT                2//      0x0004
#define NGX_HTTP_POST_BIT                3//      0x0008
#define NGX_HTTP_PUT_BIT                 4//      0x0010
#define NGX_HTTP_DELETE_BIT              5//      0x0020
#define NGX_HTTP_MKCOL_BIT               6//      0x0040
#define NGX_HTTP_COPY_BIT                7//      0x0080
#define NGX_HTTP_MOVE_BIT                8//      0x0100
#define NGX_HTTP_OPTIONS_BIT             9//      0x0200
#define NGX_HTTP_PROPFIND_BIT            10//     0x0400
#define NGX_HTTP_PROPPATCH_BIT           11//     0x0800
#define NGX_HTTP_LOCK_BIT                12//     0x1000
#define NGX_HTTP_UNLOCK_BIT              13//     0x2000
#define NGX_HTTP_PATCH_BIT               14//     0x4000
#define NGX_HTTP_TRACE_BIT               15//     0x8000

struct Constants C;
void sse_init_constants() {
    struct Constants * c = &C;
    c->shuffle1[0] = c->shuffle1[1] = _mm_setr_epi8(
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    c->shuffle2[0] = c->shuffle3[1] = _mm_set1_epi8(0xFF);
    c->shuffle2[1] = c->shuffle3[0] = _mm_setzero_si128();
    c->shufnb = _mm_setr_epi8(
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x80);
    c->shufpb = _mm_setr_epi8(
                0x80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14);


    c->spaces = _mm_set1_epi8(0x20);
    c->semicolons = _mm_set1_epi8(':');
    c->slashes = _mm_set1_epi8('/');
    c->tabs = _mm_set1_epi8('\t');
    c->plus = _mm_set1_epi8('+');
    c->nine = _mm_set1_epi8('9');
    c->zero = _mm_set1_epi8('0');
    c->_n   = _mm_set1_epi8('\n');
    c->_r   = _mm_set1_epi8('\r');

    c->tabs2spaces = _mm_set1_epi8(' '-'\t');
    c->plus2spaces = _mm_set1_epi8('+'-' ');

    c->masktest1 = _mm_setr_epi8(1,2,4,8,16,32,64,128,0,0,0,0,0,0,0,0);
    c->masktest2 = _mm_set1_epi8(0xF);

    c->newline1 = _mm_setr_epi8('\n','\n', 0  , 0  ,
                                '\r','\n','\n', 0  ,
                                '\n','\r','\n', 0  ,
                                '\r','\n','\r','\n');
    c->newline2 = _mm_setr_epi8(0xFF,0xFF, 0  , 0  ,
                                0xFF,0xFF,0xFF, 0  ,
                                0xFF,0xFF,0xFF, 0  ,
                                0xFF,0xFF,0xFF,0xFF);
    c->HTTP1x =
            _mm_setr_epi8('\r','\n','\n','H',
                          'T' ,'T' ,'P' ,'/',
                          '1' ,'.' ,'Z' ,'0',
                          '1','\r','\n','\n');
    c->HTTP1xHelper =
            _mm_setr_epi8(0,  1,  0,  0,
                          1,  2,  3,  4,
                          5,  6,  0,  7,
                          7,  8,  9,  8);
    c->dq0 = _mm_setr_epi8(
                0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    c->dq1 = _mm_setr_epi8(
                0x00, 0x00, 0x20, 0x20, 0x00, 0x00, 0x20, 0x20,
                0x00, 0x00, 0x20, 0x20, 0x00, 0x00, 0x20, 0x20);
    c->dq2 = _mm_setr_epi8(
                0x2F, 0x39, 0x60, 0x66, 0x2F, 0x39, 0x60, 0x66,
                0x2F, 0x39, 0x60, 0x66, 0x2F, 0x39, 0x60, 0x66);
    c->dq3 = _mm_set1_epi16(0x00FF);
    c->dq4 = _mm_setr_epi8(
                0x30, 0xFF, 0x57, 0xFF, 0x30, 0xFF, 0x57, 0xFF,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00);
    c->dq5 = _mm_setr_epi16(
                16, 16, 1, 1, 0, 0, 0, 0);

    c->directoryPatterns =
            _mm_setr_epi8('/', '.', '.', '/',
                          '/', '.', '/',  0 ,
                          '/', '/',  0 ,  0 ,
                           0 ,  0 ,  0 ,  0 );

    c->method1 = _mm_setr_epi8('G','E','T',' ','P','U','T',' ','P','O','S','T','C','O','P','Y');
    c->method2 = _mm_setr_epi8('M','O','V','E','L','O','C','K','H','E','A','D','P','R','O','P');
    c->method3 = _mm_setr_epi8('P','A','T','C','T','R','A','C','D','E','L','E','U','N','L','O');
    c->method4 = _mm_setr_epi8('M','K','C','O','O','P','T','I','F','I','N','D','P','A','T','C');
    c->method5 = _mm_setr_epi8( 4 , 5 , 4 , 5 , 4 , 5 , 4 , 5 , 4 , 5 , 4 , 5 , 6 , 7 , 8 , 9 );
    c->method6 = _mm_setr_epi8('H',' ','E',' ','T','E','C','K','L',' ','O','N','S',' ','H',' ');
    c->method7 = _mm_setr_epi8( 0 , 1 , 2 , 3 , 4 , 5 , 6 , 7 , 8 , 9 ,12 ,13 ,255,255,14 ,15 );
    c->method8 = _mm_setr_epi32(-1, -1, -1, 0);
    c->method9 = _mm_setr_epi8(NGX_HTTP_GET_BIT, 3, NGX_HTTP_PUT_BIT, 3, NGX_HTTP_POST_BIT, 4, NGX_HTTP_COPY_BIT, 4,
                              NGX_HTTP_MOVE_BIT, 4, NGX_HTTP_LOCK_BIT, 4, NGX_HTTP_HEAD_BIT, 4, 0, 0);
    c->method10= _mm_setr_epi8(NGX_HTTP_PATCH_BIT, 5, NGX_HTTP_TRACE_BIT, 5, NGX_HTTP_DELETE_BIT, 6, NGX_HTTP_UNLOCK_BIT, 6,
                  NGX_HTTP_MKCOL_BIT, 5, NGX_HTTP_OPTIONS_BIT, 7, NGX_HTTP_PROPFIND_BIT, 8, NGX_HTTP_PROPPATCH_BIT, 9);
    c->alnumDotMinusBitmask =
            _mm_setr_epi8(0xC8, 0xF8, 0xF8, 0xF8,
                          0xF8, 0xF8, 0xF8, 0xF8,
                          0xF8, 0xF8, 0xF0, 0x50,
                          0x50, 0x54, 0x54, 0x50);
    c->hostnameLiteralBitmask =
            _mm_setr_epi8(0xD8, 0xFC, 0xF8, 0xF8,
                          0xFC, 0xF8, 0xFC, 0xF8,
                          0xFC, 0xFC, 0xFC, 0x5C,
                          0x74, 0x5C, 0xD4, 0x70);
    c->uriBitmask =
            _mm_setr_epi8(0xC8, 0xFC, 0xF8, 0xF8,
                          0xFC, 0xF8, 0xF8, 0xF8,
                          0xFC, 0xFC, 0xF4, 0x54,
                          0x54, 0x54, 0x54, 0x70);
    c->uriArgsBitmask =
            _mm_setr_epi8(0xC8, 0xFC, 0xF8, 0xF8,
                          0xFC, 0xF8, 0xF8, 0xF8,
                          0xFC, 0xFC, 0xF4, 0x54,
                          0x54, 0x5C, 0x54, 0x70);
    c->uriAsIsBitmask =
            _mm_setr_epi8(0xF8, 0xFC, 0xFC, 0xFC,
                          0xFC, 0xFC, 0xFC, 0xFC,
                          0xFC, 0xFC, 0xFC, 0xFC,
                          0xF4, 0xFC, 0xFC, 0x7C);
    c->headerNameBitmask =
            _mm_setr_epi8(0xA8, 0xF8, 0xF8, 0xF8,
                          0xF8, 0xF8, 0xF8, 0xF8,
                          0xF8, 0xF8, 0xF0, 0x50,
                          0x50, 0x54, 0x50, 0x50);
    c->headerValueBitmask =
            _mm_setr_epi8(0xAC, 0xF8, 0xF8, 0xF8,
                          0xF8, 0xF8, 0xF8, 0xF8,
                          0xFC, 0xFC, 0xFC, 0x5C,
                          0x5C, 0x5C, 0x5C, 0x5C);
};
