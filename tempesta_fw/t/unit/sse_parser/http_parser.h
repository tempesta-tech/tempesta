#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <stdlib.h>
#include <stdio.h>
#include "str.h"

//something wrong happens with GCC when i try to compile code
//with this on Core i7-4820k: it generates invalid opcodes
//gcc 4.8.4

//#pragma GCC push_options
//#pragma GCC target ("mmx", "avx")
//#define  _MM_MALLOC_H_INCLUDED
#include <tmmintrin.h>
//#undef _MM_MALLOC_H_INCLUDED
//#pragma GCC pop_options

int
tfw_http_parse_req(void *req_data, unsigned char *data, size_t len);


#endif // HTTP_PARSER_H

