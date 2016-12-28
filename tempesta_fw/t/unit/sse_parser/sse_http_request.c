#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "sse_parser.h"

int main()
{
    sse_init_constants();

    int i;

    __m128i * buffer;
    if (posix_memalign((void**)&buffer, 64, 8192)) {
        printf("allocation error\n");
    }

    static const char * requests[] = {
        "GET http://yandex.ru\r\n",
        "GET   https://yandex.ru:80\r\n",
        "GET  yandex.ru/file\r\n",
        "GET  yandex.ru/file HTTP/1.0\r\n",
        "POST yandex.ru:80/folderrrrr/file afterspace   HTTP/1.0\n",
        NULL,
    };

    struct SSEHttpRequest r;
    for(i = 0; requests[i]; ++i) {
        initHttpRequest(&r, buffer, 8192);
        int result = ParseHttpRequest(&r, requests[i], strlen(requests[i]));
        switch(result) {
        case Parse_NeedMoreData:
            printf("%s\n: Need more data\n",requests[i]);
            break;
        case Parse_Failure:
            printf("%s\n: Failure\n",requests[i]);
            break;
        case Parse_Success:
            printf("%s\n: Success\n",requests[i]);
            printf("METHOD:\t%d\n"
                   "SCHEMA:\t%d\n"
                   "HOST:\t'%s'\n"
                   "PORT:\t%d\n"
                   "URI:\t'%s'\n",
                   r.method, r.schema, r.uri_host, r.uri_port, r.uri_path);

            break;
        default:
            printf("%s\n: Unexpected error code\n",requests[i]);
        }
    }

    free(buffer);
    return 0;
}
