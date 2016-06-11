#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "http_parser.h"
#include "goto_parser.h"
#include "gfsm.h"

static inline unsigned long
tv_to_ms(const struct timeval *tv)
{
    return ((unsigned long)tv->tv_sec * 1000000 + tv->tv_usec) / 1000;
}

#define STR(s)	{s, sizeof(s) - 1}

static struct {
    unsigned char	*str;
    size_t 		len;
} headers[] = {
    STR("Host: github.com\r\n\r\n"),
    STR("Connection: keep-alive\r\n\r\n"),
    STR("Cache-Control: max-age=0\r\n\r\n"),
    STR("Accept-Encoding: gzip,deflate,sdch\r\n\r\n"),
    STR("Accept-Language: zh-CN,zh;q=0.8,en;q=0.6\r\n\r\n"),
    STR("Accept-Charset: gb18030,utf-8;q=0.7,*;q=0.3\r\n\r\n"),
    STR("If-None-Match: 7f9c6a2baf61233cedd62ffa906b604f\r\n\r\n"),
    STR("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\r\n"),
    STR("User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11\r\n\r\n"),
    STR("Cookie: tracker=http%3A%2F%2Fnodejs.org%2F; _gh_sess=BAh7DyIVemVkc2hhdy9tb25ncmVsMnsGOhhpmNkYUlzclBoalhpZWR5a2NzS3M9OhBmaW5nZXJwcmludCIlYTM3YTg2ODQ0M2Q4ZWJiZDM4OGM4NThlMTc3OWMwZTM6DGNvbnRleHQiBi86D3Nlc3Npb25faWQiJWQ2ODVjZjM5YTcxZTg5NmZkYmI0NmNlMDY3NmUwMGFlIhNyeS9odHRwLXBhcnNlcnsAOhFsb2NhbGVfZ3Vlc3MiB3poIhhwaGVuZHJ5eC9zdXBlcnB1dHR5ewAiCmZsYXNoSUM6J0FjdGlvbkNvbnRyb2xsZXI6OkZsYXNoOjpGbGFzaEhhc2h7AAY6CkB1c2VkewA6CXVzZXJpA57pEQ%3D%3D--e3154a27f5cdb7f1a8b0351f997b7e3d752f4636; __utmz=1.1327920052.183.88.utmcsr=nodejs.org|utmccn=(referral)|utmcmd=referral|utmcct=/\r\n\r\n"),    
    STR("Cookie: tracker=http%3A%2F%2Fnodejs.org%2F; _gh_sess=BAh7DyIVemVkc2hhdy9tb25ncmVsMnsGOhhpc3N1ZV92aWV3X3NldHRpbmdzewgiCXNvcnQiDGNyZWF0ZWQiDmRpcmVjdGlvbiIJZGVzYyIKc3RhdGUiC2Nsb3NlZDoQX2NzcmZfdG9rZW4iMUw0eVBPdE5SVXU4eHYwZlRuZFJHY2x6QmNkYUlzclBoalhpZWR5a2NzS3M9OhBmaW5nZXJwcmludCIlYTM3YTg2ODQ0M2Q4ZWJiZDM4OGM4NThlMTc3OWMwZTM6DGNvbnRleHQiBi86D3Nlc3Npb25faWQiJWQ2ODVjZjM5YTcxZTg5NmZkYmI0NmNlMDY3NmUwMGFlIhNyeS9odHRwLXBhcnNlcnsAOhFsb2NhbGVfZ3Vlc3MiB3poIhhwaGVuZHJ5eC9zdXBlcnB1dHR5ewAiCmZsYXNoSUM6J0FjdGlvbkNvbnRyb2xsZXI6OkZsYXNoOjpGbGFzaEhhc2h7AAY6CkB1c2VkewA6CXVzZXJpA57pEQ%3D%3D--e3154a27f5cdb7f1a8b0351f997b7e3d752f4636; __utma=1.1355277945.1305645384.1329633368.1329635599.209; __utmc=1; __utmz=1.1327920052.183.88.utmcsr=nodejs.org|utmccn=(referral)|utmcmd=referral|utmcct=/\r\n\r\n"),
    STR("Cookie: tracker=http%3A%2F%2Fnodejs.org%2F; _gh_sess=BAh7DyIVemVkc2hhdy9tb25ncmVsMnsGOhhpc3N1ZV92aWV3X3NldHRpbmdzewgiCXNvcnQiDGNyZWF0ZWQiDmRpcmVjdGlvbiIJZGVzYyIKc3RhdGUiC2Nsb3NlZDoQX2NzcmZfdG9rZW4iMUw0eVBPdE5SVXU4eHYwZlRuZFJHY2x6QmNkYUlzclBoalhpZWR5a2NzS3M9OhBmaW5nZXJwcmludCIlYTM3YTg2ODQ0M2Q4ZWJiZDM4OGM4NThlMTc3OWMwZTM6DGNvbnRleHQiBi86D3Nlc3Npb25faWQiJWQ2ODVjZjM5YTcxZTg5NmZkYmI0NmNlMDY3NmUwMGFlIhNyeS9odHRwLXBhcnNlcnsAOhFsb2NhbGVfZ3Vlc3MiB3poIhhwaGVuZHJ5eC9zdXBlcnB1dHR5ewAiCmZsYXNoSUM6J0FjdGlvbkNvbnRyb2xsZXI6OkZsYXNoOjpGbGFzaEhhc2h7AAY6CkB1c2VkewA6CXVzZXJpA57pEQ%3D%3D--e3154a27f5cdb7f1a8b0351f997b7e3d752f4636; spy_repo=joyent%2Fhttp-parser; spy_repo_at=Sun%20Feb%2019%202012%2015%3A20%3A31%20GMT%2B0800%20(%E4%B8%AD%E5%9B%BD%E6%A0%87%E5%87%86%E6%97%B6%E9%97%B4); __utma=1.1355277945.1305645384.1329633368.1329635599.209; __utmc=1; __utmz=1.1327920052.183.88.utmcsr=nodejs.org|utmccn=(referral)|utmcmd=referral|utmcct=/\r\n\r\n"),
},

requests[] = {
    STR("GET / HTTP/1.1\r\n\r\n"),
    //unsupported by tempesta parser: STR("GET ftp://mail.ru/index.html HTTP/1.1\r\n"),
    STR("POST /script1?a=44,fd=6 HTTP/1.1\r\n\r\n"),
    STR("GET /joyent/http-parser HTTP/1.1\r\n\r\n"),
    STR("PUT   http://mail.ru/index.html HTTP/1.1\r\n\r\n"),
    STR("POST /api/2/thread/404435440?1340553000964 HTTP/1.1\r\n\r\n"),
    STR("GET http://pipelined-host-C.co.uk/somepage.abc/hjkhasdfdaf23df$#ffgse4wds/fdsgsg/sfdgfg/sfdgsf0fsgfg/sfgfs/0dsdfsggsgfgsdfdsdgdfsg/345/sdfgf/4er/3453/gnnv,/,m,/5463234/567&*%&*$&3/gfg/ggdh/gdhgdhgdhg/00 HTTP/1.1\n\r\n"),
    STR("GET /pixel;r=657222568;a=p-2945K0QbJw0BA;fpan=0;fpa=P0-456992954-1322415728212;ns=0;ce=1;je=0;sr=1280x800x24;enc=n;dst=1;et=1340553300515;tzo=-240;ref=;url=http%3A%2F%2Fitman.livejournal.com%2F474249.html%3Fthread%3D5941385%23t5941385;ogl=title.%D0%9F%D0%BE%D1%87%D0%B5%D0%BC%D1%83%20%D0%BA%D0%BE%D0%BC%D0%BF%D1%8C%D1%8E%D1%82%D0%B5%D1%80%20--%20%D1%8D%D1%82%D0%BE%20%D0%BD%D0%B5%20%D0%BA%D0%BE%D0%BD%D0%B5%D1%87%D0%BD%D1%8B%D0%B9%20%D0%B0%D0%B2%D1%82%D0%BE%D0%BC%D0%B0%D1%82%3F%2Cdescription.BE%D0%B5%20%D0%BA%D0%BE%D0%BB%D0%B8%D1%87%D0%B5%D1%81%D1%82%D0%B2%D0%BE%20%D0%BB%D1%8E%D0%B4%D0%B5%D0%B9%20%D1%81%D1%87%D0%B8%D1%82%D0%B0%D0%B5%D1%82%252C%20%D1%87%2Cimage.http%3A%2F%2Fl-userpic%252Elivejournal%252Ecom%2F113387160%2F8313909 HTTP/1.1\r\n\r\n"),    
    STR("GET /pixel;r=657222568;a=p-2945K0QbJw0BA;fpan=0;fpa=P0-456992954-1322415728212;ns=0;ce=1;je=0;sr=1280x800x24;enc=n;dst=1;et=1340553300515;tzo=-240;ref=;url=http%3A%2F%2Fitman.livejournal.com%2F474249.html%3Fthread%3D5941385%23t5941385;ogl=title.%D0%9F%D0%BE%D1%87%D0%B5%D0%BC%D1%83%20%D0%BA%D0%BE%D0%BC%D0%BF%D1%8C%D1%8E%D1%82%D0%B5%D1%80%20--%20%D1%8D%D1%82%D0%BE%20%D0%BD%D0%B5%20%D0%BA%D0%BE%D0%BD%D0%B5%D1%87%D0%BD%D1%8B%D0%B9%20%D0%B0%D0%B2%D1%82%D0%BE%D0%BC%D0%B0%D1%82%3F%2Cdescription.%D0%A1%D1%82%D0%BE%D0%BB%D0%B5%D1%82%D0%B8%D1%8E%20%D0%A2%D1%8C%D1%8E%D1%80%D0%B8%D0%BD%D0%B3%D0%B0%20%D0%BF%D0%BE%D1%81%D0%B2%D1%8F%D1%89%D0%B0%D0%B5%D1%82%D1%81%D1%8F%252E%20%D0%9E%D0%BA%D0%B0%D0%B7%D1%8B%D0%B2%D0%B0%D0%B5%D1%82%D1%81%D1%8F%252C%20%D0%BE%D0%B3%D1%80%D0%BE%D0%BC%D0%BD%D0%BE%D0%B5%20%D0%BA%D0%BE%D0%BB%D0%B8%D1%87%D0%B5%D1%81%D1%82%D0%B2%D0%BE%20%D0%BB%D1%8E%D0%B4%D0%B5%D0%B9%20%D1%81%D1%87%D0%B8%D1%82%D0%B0%D0%B5%D1%82%252C%20%D1%87%2Cimage.http%3A%2F%2Fl-userpic%252Elivejournal%252Ecom%2F113387160%2F8313909 HTTP/1.1\r\n\r\n"),
};

unsigned char long_request_with_hdrs[] = {"PUT   http://mail.ru/index.html HTTP/1.1\r\n"
              "Host: github.com\r\n"
              "Connection: keep-alive\r\n"
              "Cache-Control: max-age=0\r\n"
              "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11\r\n"
              "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
              "Accept-Encoding: gzip,deflate,sdch\r\n"
              "Accept-Language: zh-CN,zh;q=0.8,en;q=0.6\r\n"
              "Accept-Charset: gb18030,utf-8;q=0.7,*;q=0.3\r\n"
              "If-None-Match: 7f9c6a2baf61233cedd62ffa906b604f\r\n"
              "Cookie: tracker=http%3A%2F%2Fnodejs.org%2F; _gh_sess=BAh7DyIVemVkc2hhdy9tb25ncmVsMnsGOhhpc3N1ZV92aWV3X3NldHRpbmdzewgiCXNvcnQiDGNyZWF0ZWQiDmRpcmVjdGlvbiIJZGVzYyIKc3RhdGUiC2Nsb3NlZDoQX2NzcmZfdG9rZW4iMUw0eVBPdE5SVXU4eHYwZlRuZFJHY2x6QmNkYUlzclBoalhpZWR5a2NzS3M9OhBmaW5nZXJwcmludCIlYTM3YTg2ODQ0M2Q4ZWJiZDM4OGM4NThlMTc3OWMwZTM6DGNvbnRleHQiBi86D3Nlc3Npb25faWQiJWQ2ODVjZjM5YTcxZTg5NmZkYmI0NmNlMDY3NmUwMGFlIhNyeS9odHRwLXBhcnNlcnsAOhFsb2NhbGVfZ3Vlc3MiB3poIhhwaGVuZHJ5eC9zdXBlcnB1dHR5ewAiCmZsYXNoSUM6J0FjdGlvbkNvbnRyb2xsZXI6OkZsYXNoOjpGbGFzaEhhc2h7AAY6CkB1c2VkewA6CXVzZXJpA57pEQ%3D%3D--e3154a27f5cdb7f1a8b0351f997b7e3d752f4636; spy_repo=joyent%2Fhttp-parser; spy_repo_at=Sun%20Feb%2019%202012%2015%3A20%3A31%20GMT%2B0800%20(%E4%B8%AD%E5%9B%BD%E6%A0%87%E5%87%86%E6%97%B6%E9%97%B4); __utma=1.1355277945.1305645384.1329633368.1329635599.209; __utmc=1; __utmz=1.1327920052.183.88.utmcsr=nodejs.org|utmccn=(referral)|utmcmd=referral|utmcct=/\r\n"
              "\r\n\r\n"
};

int tfw_parse_req(unsigned char * text, int pktsz, int expect) {
    int len;

    if (pktsz <= 0) {
        len = strlen(text);
        if (pktsz == 0) pktsz = len;
        else pktsz = -pktsz;
    } else {
        len = pktsz;
    }

    TfwHttpReq req;

    int r, i, j;

    req.parser.state = 0;
    for(i = 0; i < len; i += pktsz) {
        j = len > pktsz ? pktsz : len;
        r = tfw_http_parse_req(&req, text+i, j);
        if (r != TFW_POSTPONE) break;
    }
    req.parser.state = 0;
    if (r != expect) return 0;
    for(i = 0; i < len; i += pktsz) {
        j = len > pktsz ? pktsz : len;
        r = tfw_http_parse_req_ff(&req, text+i, j);
        if (r != TFW_POSTPONE) break;
    }
    if (r != expect) return 0;
    return 1;
}

int tfw_parse_hdr(unsigned char * text, int pktsz, int expect) {
    int len;

    if (pktsz <= 0) {
        len = strlen(text);
        if (pktsz == 0) pktsz = len;
        else pktsz = -pktsz;
    } else {
        len = pktsz;
    }

    TfwHttpReq req;
    memset(&req, 0, sizeof(req));
    int r, i, j;
    for(i = 0; i < len; i += pktsz) {
        j = len > pktsz ? pktsz : len;
        r = tfw_http_parse_header(&req, text+i, j);
        if (r != TFW_POSTPONE) break;
    }
    if (r != expect) return 0;
    memset(&req, 0, sizeof(req));
    for(i = 0; i < len; i += pktsz) {
        j = len > pktsz ? pktsz : len;
        r = tfw_http_parse_header_ff(&req, text+i, j);
        if (r != TFW_POSTPONE) break;
    }
    if (r != expect) return 0;
    return 1;
}

#define test(data, fn, fn2, fn3)							\
do {									\
    gettimeofday(&tv0, NULL);					\
    for (unsigned i = 0; i < duration * 1000; ++i)				\
        for (unsigned j = 0; j < sizeof(data)/sizeof(data[0]); ++j) { \
            goto_ctx.state = goto_ctx.lowcase_index = 0;			\
            fn(&goto_ctx, (unsigned char *)data[j].str, data[j].len); \
        }							\
    gettimeofday(&tv1, NULL);					\
    for (unsigned i = 0; i < duration * 1000; ++i)				\
        for (unsigned j = 0; j < sizeof(data)/sizeof(data[0]); ++j) { \
            sse_ctx.parser.state = 0;			\
            fn2(&sse_ctx, (unsigned char *)data[j].str, data[j].len); \
        }				\
    gettimeofday(&tv2, NULL);					\
    for (unsigned i = 0; i < duration * 1000; ++i)				\
        for (unsigned j = 0; j < sizeof(data)/sizeof(data[0]); ++j) { \
            sse_ctx.parser.state = 0;			\
            fn3(&sse_ctx, (unsigned char *)data[j].str, data[j].len); \
        }				\
    gettimeofday(&tv3, NULL);					\
} while (0)

#define test_n(data, j, fn, fn2, fn3)							\
do {									\
    gettimeofday(&tv0, NULL);					\
    for (unsigned i = 0; i < duration * 1000; ++i)				\
        {  \
            goto_ctx.state = goto_ctx.lowcase_index = 0;			\
            fn(&goto_ctx, (unsigned char *)data[j].str, data[j].len); \
        }							\
    gettimeofday(&tv1, NULL);					\
    for (unsigned i = 0; i < duration * 1000; ++i)				\
        { \
            sse_ctx.parser.state = 0;			\
            fn2(&sse_ctx, (unsigned char *)data[j].str, data[j].len); \
        }				\
    gettimeofday(&tv2, NULL);					\
    for (unsigned i = 0; i < duration * 1000; ++i)				\
        { \
            sse_ctx.parser.state = 0;			\
            fn3(&sse_ctx, (unsigned char *)data[j].str, data[j].len); \
        }				\
    gettimeofday(&tv3, NULL);					\
} while (0)


#define FMT(S, L) min(L, (int)S.len-4), S.str, max(0, L-(int)S.len+4), filling_spaces

int main(int argc, char ** argv) {
    int duration = 1000;
    int perform_tests = 'a'; 
    int specific_test = -1;   
    int i;

    if (argc > 1) {
        switch (argv[1][0]) {
        case 'h':case 'r':case 'a':
            perform_tests = argv[1][0];
            break;
        default:
            return 1;
        }
        if (argv[1][1] >= '0' && argv[1][1] <= '9') {
            specific_test = argv[1][1] - '0';
            if (argv[1][2] >= '0' && argv[1][2] <= '9') {
                specific_test = specific_test*10 + argv[1][2] - '0';
            }
        }


        if (argc > 2) {
            duration = atol(argv[2])*100;
        }
    }

    //verify parser=================================
    if (perform_tests == 'a') {
        for(i = 0; i < sizeof(requests)/sizeof(requests[0]); ++i)
        {
            printf("Test(req) %d:", i);

            if (!tfw_parse_req(requests[i].str,
                               requests[i].len,
                               TFW_PASS)) {
                printf("\tfull string: FAIL\n");
                return 1;
            }
            if (!tfw_parse_req(requests[i].str,
                               requests[i].len,
                               TFW_PASS)) {
                printf("\tby bytes: FAIL\n");
                return 1;
            }
            printf("\tPASS\n");
        }
        for(i = 0; i < sizeof(headers)/sizeof(headers[0]); ++i)
        {
            printf("Test(hdr) %d:", i);

            if (!tfw_parse_hdr((unsigned char *)headers[i].str,
                               headers[i].len,
                               TFW_PASS)) {
                printf("\tfull string: FAIL\n");
                return 1;
            }
            if (!tfw_parse_hdr((unsigned char *)headers[i].str,
                               headers[i].len,
                               TFW_PASS)) {
                printf("\tby bytes: FAIL\n");
                return 1;
            }
            printf("\tPASS\n");
        }
        //as a last step: parser runs with all headers from above and
        int test_result;

        test_result = tfw_parse_req(long_request_with_hdrs, 
                        sizeof(long_request_with_hdrs), TFW_PASS);
        printf("Full request:\t%s\n",
               test_result ? "PASS":"FAIL");
        if (!test_result)
            return 1;
        test_result = tfw_parse_req(long_request_with_hdrs, -1200, TFW_PASS);
        printf("Chunked(1200b):\t%s\n",
               test_result ? "PASS":"FAIL");
        if (!test_result)
            return 1;
    }
    //end verify parser==============================

    //benchmark parser===============================
    ngx_http_request_t goto_ctx;
    TfwHttpReq         sse_ctx;
    struct timeval tv0, tv1, tv2, tv3;
    //we use these chars to make output more beautiful
    char filling_spaces[]={"                                   "};

    

    printf("=====================================================================\n"
           " BENCHMARK               ||    GOTO     ||    SSE      ||   SSE-ff   \n"
           "=====================================================================\n");
    if (specific_test < 0) {
        if (perform_tests == 'a' || perform_tests == 'r') {
            test(requests, goto_request_line, tfw_http_parse_req, tfw_http_parse_req_ff);
            printf(
           " ALL REQUESTS            ||  % 6lums   ||  % 6lums   ||  % 6lums  \n",
                tv_to_ms(&tv1) - tv_to_ms(&tv0), 
                tv_to_ms(&tv2) - tv_to_ms(&tv1), 
                tv_to_ms(&tv3) - tv_to_ms(&tv2));

            for (unsigned j = 0; j < sizeof(requests)/sizeof(requests[0]); ++j) {
                test_n(requests, j, goto_request_line, tfw_http_parse_req, tfw_http_parse_req_ff);
                printf(
               " [%.04d]%.*s%.*s  ||  % 6lums   ||  % 6lums   ||  % 6lums  \n",
                requests[j].len, FMT(requests[j], 16),  
                tv_to_ms(&tv1) - tv_to_ms(&tv0), 
                tv_to_ms(&tv2) - tv_to_ms(&tv1), 
                tv_to_ms(&tv3) - tv_to_ms(&tv2));
            }
        }
        if (perform_tests == 'a' || perform_tests == 'h') {
            test(headers, goto_header_line, tfw_http_parse_header, tfw_http_parse_header_ff);
            printf(
           " ALL HEADERS             ||  % 6lums   ||  % 6lums   ||  % 6lums  \n",
                tv_to_ms(&tv1) - tv_to_ms(&tv0), 
                tv_to_ms(&tv2) - tv_to_ms(&tv1), 
                tv_to_ms(&tv3) - tv_to_ms(&tv2));

            for (unsigned j = 0; j < sizeof(headers)/sizeof(headers[0]); ++j) {
                test_n(headers, j, goto_header_line, tfw_http_parse_header, tfw_http_parse_header_ff);
                printf(
               " [%.04d]%.*s%.*s  ||  % 6lums   ||  % 6lums   ||  % 6lums  \n",
                headers[j].len, FMT(headers[j], 16),   
                tv_to_ms(&tv1) - tv_to_ms(&tv0), 
                tv_to_ms(&tv2) - tv_to_ms(&tv1), 
                tv_to_ms(&tv3) - tv_to_ms(&tv2));
            }
        }
    } else {
        if (perform_tests == 'a' || perform_tests == 'r') {
            if (specific_test < sizeof(requests)/sizeof(requests[0])) {
                test_n(requests, specific_test, goto_request_line, tfw_http_parse_req, tfw_http_parse_req_ff);
                printf(
               " [%.04d]%.*s%.*s  ||  % 6lums   ||  % 6lums   ||  % 6lums  \n",
                requests[specific_test].len, FMT(requests[specific_test], 16),  
                tv_to_ms(&tv1) - tv_to_ms(&tv0), 
                tv_to_ms(&tv2) - tv_to_ms(&tv1), 
                tv_to_ms(&tv3) - tv_to_ms(&tv2));
            }
        }
        if (perform_tests == 'a' || perform_tests == 'h') {
            if (specific_test < sizeof(headers)/sizeof(headers[0])) {
                test_n(headers, specific_test, goto_header_line, tfw_http_parse_header, tfw_http_parse_header_ff);
                printf(
               " [%.04d]%.*s%.*s  ||  % 6lums   ||  % 6lums   ||  % 6lums  \n",
                headers[specific_test].len, FMT(headers[specific_test], 16),  
                tv_to_ms(&tv1) - tv_to_ms(&tv0), 
                tv_to_ms(&tv2) - tv_to_ms(&tv1), 
                tv_to_ms(&tv3) - tv_to_ms(&tv2));
            }
        }
    }
    return 0;
}
