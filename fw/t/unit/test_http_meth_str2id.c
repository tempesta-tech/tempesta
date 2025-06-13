/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define TFW_HTTP_METH_GET         1
#define TFW_HTTP_METH_PUT         2
#define TFW_HTTP_METH_POST        3
#define TFW_HTTP_METH_HEAD        4
#define TFW_HTTP_METH_MOVE        5
#define TFW_HTTP_METH_LOCK        6
#define TFW_HTTP_METH_COPY        7
#define TFW_HTTP_METH_MKCOL       8
#define TFW_HTTP_METH_TRACE       9
#define TFW_HTTP_METH_PATCH       10
#define TFW_HTTP_METH_PURGE       11
#define TFW_HTTP_METH_DELETE      12
#define TFW_HTTP_METH_UNLOCK      13
#define TFW_HTTP_METH_OPTIONS     14
#define TFW_HTTP_METH_PROPFIND    15
#define TFW_HTTP_METH_PROPPATCH   16
#define _TFW_HTTP_METH_COUNT      17
#define _TFW_HTTP_METH_INCOMPLETE 18
#define _TFW_HTTP_METH_UNKNOWN    255

#define H2_METH_HDR_VLEN 8

typedef struct {
	unsigned char *data;
	size_t len;
} Chunk;

typedef struct {
	int flags;
	size_t len;
	int nchunks;
	Chunk *chunk;
} TfwStr;

unsigned char

tfw_http_meth_str2id(const TfwStr *m_hdr)
{
	const Chunk *chunk;
	const unsigned char *p;
	size_t len;

	len = m_hdr->len - H2_METH_HDR_VLEN;
	chunk = m_hdr->chunk;
	p = chunk->data;

	switch (len) {
	case 3:
		if (chunk->len == 3)
			if (p[0] == 'G' && p[1] == 'E' && p[2] == 'T')
				return TFW_HTTP_METH_GET;
			else if (p[0] == 'P' && p[1] == 'U' && p[2] == 'T')
				return TFW_HTTP_METH_PUT;
		break;
	case 4:
		if (chunk->len == 4)
			if (*(unsigned int *)p == *(unsigned int *)"POST")
				return TFW_HTTP_METH_POST;
			else if (*(unsigned int *)p == *(unsigned int *)"HEAD")
				return TFW_HTTP_METH_HEAD;
			else if (*(unsigned int *)p == *(unsigned int *)"MOVE")
				return TFW_HTTP_METH_MOVE;
			else if (*(unsigned int *)p == *(unsigned int *)"LOCK")
				return TFW_HTTP_METH_LOCK;
			else if (*(unsigned int *)p == *(unsigned int *)"COPY")
				return TFW_HTTP_METH_COPY;
		break;
	case 5:
		if (chunk->len == 5)
			if (!memcmp(p, "MKCOL", 5))
				return TFW_HTTP_METH_MKCOL;
			else if (!memcmp(p, "TRACE", 5))
				return TFW_HTTP_METH_TRACE;
			else if (!memcmp(p, "PATCH", 5))
				return TFW_HTTP_METH_PATCH;
			else if (!memcmp(p, "PURGE", 5))
				return TFW_HTTP_METH_PURGE;
			else if (!memcmp(p, "COUNT", 5))
				return _TFW_HTTP_METH_COUNT;
		break;
	case 6:
		if (chunk->len == 6)
			if (!memcmp(p, "DELETE", 6))
				return TFW_HTTP_METH_DELETE;
			else if (!memcmp(p, "UNLOCK", 6))
				return TFW_HTTP_METH_UNLOCK;
		break;
	case 7:
		if (chunk->len == 7)
			if (!memcmp(p, "OPTIONS", 7))
				return TFW_HTTP_METH_OPTIONS;
		break;
	case 8:
		if (chunk->len == 8)
			if (!memcmp(p, "PROPFIND", 8))
				return TFW_HTTP_METH_PROPFIND;
		break;
	case 9:
		if (chunk->len == 9)
			if (!memcmp(p, "PROPPATCH", 9))
				return TFW_HTTP_METH_PROPPATCH;
		break;
	case 10:
		if (chunk->len == 10)
			if (!memcmp(p, "INCOMPLETE", 10))
				return _TFW_HTTP_METH_INCOMPLETE;
		break;
	default:
		break;
	}

	return _TFW_HTTP_METH_UNKNOWN;
}

#define TEST(method_str, expected) \
	do { \
		unsigned char *data = (unsigned char *)method_str; \
		Chunk chk = { .data = data, .len = strlen(method_str) }; \
		TfwStr hdr = { .flags = 0, .len = strlen(method_str) + H2_METH_HDR_VLEN, \
			.nchunks = 1, .chunk = &chk }; \
		unsigned char id = tfw_http_meth_str2id(&hdr); \
		assert(id == expected); \
	} while (0)

int
main(void)
{
	TEST("GET", TFW_HTTP_METH_GET);
	TEST("POST", TFW_HTTP_METH_POST);
	TEST("COPY", TFW_HTTP_METH_COPY);
	TEST("PUT", TFW_HTTP_METH_PUT);
	TEST("PATCH", TFW_HTTP_METH_PATCH);
	TEST("OPTIONS", TFW_HTTP_METH_OPTIONS);
	TEST("PROPFIND", TFW_HTTP_METH_PROPFIND);
	TEST("PROPPATCH", TFW_HTTP_METH_PROPPATCH);
	TEST("UNLOCK", TFW_HTTP_METH_UNLOCK);
	TEST("INCOMPLETE", _TFW_HTTP_METH_INCOMPLETE);
	TEST("UNKNOWN", _TFW_HTTP_METH_UNKNOWN);
	TEST("GETX", _TFW_HTTP_METH_UNKNOWN);

	printf("All tfw_http_meth_str2id() tests passed.\n");
	return 0;
}
