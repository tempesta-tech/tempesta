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
    return ret;
}
int do_parse_mp_req(const unsigned char ** text) {
    TfwHttpReq req;
    int r, i;
    memset(&req, 0, sizeof(req));
    for(i = 0; text[i]; ++i) {
        r = do_parse_req(&req, text[i]);
        if (r != TFW_POSTPONE) continue;
    }
    return r;
}
int main() {

    const unsigned char * r1[] = {
        "GET http://yandex.ru/file HTTP/1.0\r\nHost: yandex.ru\r\n\r\n",
        NULL};
    do_parse_mp_req(r1);
    const unsigned char * r2[] = {
        "G","E","T"," ","h","t",
        "t","p",":","/","/","y",
        "a","n","d","e","x",".",
        "ru/file HTTP/1.0\r\nHost: yandex.ru\r\n\r\n",
        NULL};
    do_parse_mp_req(r2);
    return 0;
}
