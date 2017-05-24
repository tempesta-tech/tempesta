/**
 *		Tempesta FW
 *
 * HTTP/2 Huffman decoder test and benchmark (plain version).
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "../common.h"
#include "../huffman.h"

typedef struct {
	const char *source;
	uint32_t source_len;
	const char *encoded;
	uint32_t encoded_len;
} HTestData;

#include "hftestdata.h"

#define ITEMS (sizeof(test) / sizeof(HTestData))

int ngx_http_v2_huff_decode(const unsigned char *src,
			    size_t len, unsigned char *dst, unsigned int last);
#define With_Compare 0
#define Iterations 768

int common_cdecl
main(void)
{
	static char buf[64 * 4];
	unsigned int k, i;
	uintptr_t ts;
	double tm;

	ts = clock();
	for (k = 0; k < Iterations; k++) {
		for (i = 0; i < ITEMS; i++) {
			int rc;

			rc = ngx_http_v2_huff_decode((const unsigned char *)
						     test[i].encoded,
						     test[i].encoded_len,
						     (unsigned char *)buf, 1);
			if (rc) {
				printf("Bug #1: Iteration: %u, rc = %d...\n", i,
				       rc);
				return 1;
			}
#if With_Compare
			if (memcmp(test[i].source, buf, test[i].source_len)) {
				printf
				    ("Bug #1: Iteration: %u, Invalid decoded data...\n",
				     i);
				return 1;
			}
#endif
		}
	}
	tm = (double)(clock() - ts) / CLOCKS_PER_SEC;
	printf("nginx time = %g\n", tm);
	ts = clock();
	for (k = 0; k < Iterations; k++) {
		for (i = 0; i < ITEMS; i++) {
			unsigned int rc;

			rc = huffman_decode(test[i].encoded, buf,
					    test[i].encoded_len);
			if (rc) {
				printf("Bug #1: Iteration: %u, rc = %u...\n", i,
				       rc);
				return 1;
			}
#if With_Compare
			if (memcmp(test[i].source, buf, test[i].source_len)) {
				printf
				    ("Bug #2: Iteration: %u, Invalid decoded data...\n",
				     i);
				return 1;
			}
#endif
		}
	}
	tm = (double)(clock() - ts) / CLOCKS_PER_SEC;
	printf("our time = %g\n", tm);
	return 0;
}
