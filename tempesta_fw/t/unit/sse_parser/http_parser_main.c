#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "http_parser.h"

int do_parse_req(void * req, const unsigned char * text) {
    unsigned char * tmp = strdupa(text);
    unsigned char * msg = "unknown return code";
    int ret = tfw_http_parse_req(req, tmp, strlen(text));
    switch(ret) {
    case TFW_BLOCK:
        msg = "TFW_BLOCK"; break;
    case TFW_PASS:
        msg = "TFW_PASS"; break;
    case TFW_POSTPONE:
        msg = "TFW_POSTPONE"; break;
    }
    printf("Result = %s\n", msg);
}

int main() {
    TfwHttpReq req;
    memset(&req, 0, sizeof(req));
    int result = do_parse_req(&req, "GET http://yandex.ru/file HTTP/1.0\r\nHost: yandex.ru\r\n\r\n");
    return result;
}
