#ifndef GOTO_PARSER_H
#define GOTO_PARSER_H

#define NGX_HTTP_LC_HEADER_LEN             32

//#define __DEBUG__

typedef struct {
    int upstream, state, header_hash, lowcase_index, invalid_header;
    unsigned char *header_name_start, *header_name_end, *header_start, *header_end;
    unsigned char lowcase_header[NGX_HTTP_LC_HEADER_LEN];

    unsigned char *request_start, *request_end, *method_end, *uri_start, *uri_end;
    unsigned char *schema_start, *schema_end, *port_end, *args_start;
    unsigned char *host_start, *host_end;
    int method, http_minor, http_major;
} ngx_http_request_t;

#define DECLARE_PARSE(prefix)						\
int prefix ## _header_line(ngx_http_request_t *r, unsigned char *buf, int len)

DECLARE_PARSE(ngx);
DECLARE_PARSE(ngx_lw);
DECLARE_PARSE(ngx_big);
DECLARE_PARSE(hsm);
DECLARE_PARSE(tbl);
DECLARE_PARSE(tbl_big);
DECLARE_PARSE(goto);
DECLARE_PARSE(goto_big);

int ngx_request_line(ngx_http_request_t *r, unsigned char *buf, int len);
int goto_request_line(ngx_http_request_t *r, unsigned char *buf, int len);
int goto_opt_request_line(ngx_http_request_t *r, unsigned char *buf, int len);

#define NGX_HTTP_UNKNOWN                   0x0001
#define NGX_HTTP_GET                       0x0002
#define NGX_HTTP_HEAD                      0x0004
#define NGX_HTTP_POST                      0x0008
#define NGX_HTTP_PUT                       0x0010
#define NGX_HTTP_DELETE                    0x0020
#define NGX_HTTP_MKCOL                     0x0040
#define NGX_HTTP_COPY                      0x0080
#define NGX_HTTP_MOVE                      0x0100
#define NGX_HTTP_OPTIONS                   0x0200
#define NGX_HTTP_PROPFIND                  0x0400
#define NGX_HTTP_PROPPATCH                 0x0800
#define NGX_HTTP_LOCK                      0x1000
#define NGX_HTTP_UNLOCK                    0x2000
#define NGX_HTTP_PATCH                     0x4000
#define NGX_HTTP_TRACE                     0x8000

#define likely(a)	__builtin_expect((a), 1)
#define unlikely(a)	__builtin_expect((a), 0)


#endif // GOTO_PARSER_H

