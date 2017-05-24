/**
 *		Tempesta FW
 *
 * HTTP/2 Huffman decoder test and benchmark (fragmented version).
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
#include "../../pool.h"
#include "../../str.h"
#include "../buffers.h"
#include "../huffman.h"

typedef struct {
	const char *source;
	uint32_t source_len;
	const char *encoded;
	uint32_t encoded_len;
} HTestData;

#include "hftestdata.h"

#define ITEMS (sizeof(test) / sizeof(HTestData))

#define With_Compare 1
#define Iterations 768

#define rm_a 1664525
#define rm_b 22695477

#define rm_c1 1013904223
#define rm_c2 1

static unsigned int Random_x = 0x55555555;
static unsigned int Random_y = 0xAAAAAAAA;

/* Very simple random number generator, designed for */
/* test purposes only, based on two mod 2^32 LCGs: */

static unsigned int
Random32(void)
{
	const unsigned int x = Random_x * rm_a + rm_c1;
	const unsigned int y = Random_y * rm_b + rm_c2;

	Random_x = x;
	Random_y = y;
	return (x >> 8) ^ (y << 8);
}

/* Unbiased random index in the {0; n} range: */

static unsigned int
Random32_Index(const unsigned int n)
{
	if (n) {
		unsigned int limit = 4294967295U - 4294967295U % n;
		unsigned int x;

		do {
			x = Random32();
		} while (x >= limit);
		return x % n;
	} else {
		return 0;
	}
}

int common_cdecl
main(void)
{
	static TfwStr fragments[3];
	static TfwStr root;
	static char buf1[4 * 64];
	static char buf2[4 * 64];
	static char buf3[4 * 64];
	static HTTP2Input in;
	static HTTP2Output out;
	unsigned int k, i;
	uintptr_t ts;
	double tm;

	ts = clock();
	fragments[0].ptr = buf2;
	fragments[1].ptr = buf1;
	fragments[2].ptr = buf3;
	buffer_new(&out, NULL, 0);
	for (k = 0; k < Iterations; k++) {
		for (i = 0; i < ITEMS; i++) {
			const char *__restrict encoded = test[i].encoded;
			unsigned int rc;
			uintptr_t n;
			unsigned int length = test[i].encoded_len;

			if (length == 1) {
				root.ptr = buf1;
				root.len = 1;
				root.flags = 0;
				buf1[0] = encoded[0];
			} else {
				root.ptr = fragments;
				root.len = length;
				if (length == 2) {
					root.flags = 2 << TFW_STR_CN_SHIFT;
					fragments[0].len = 1;
					fragments[1].len = 1;
					buf2[0] = encoded[0];
					buf1[0] = encoded[1];
				} else {
					const unsigned int split2 =
					    Random32_Index(length - 1) + 1;
					const unsigned int split1 =
					    Random32_Index(split2) + 1;
					if (split1 == split2) {
						root.flags =
						    2 << TFW_STR_CN_SHIFT;
						fragments[0].len = split1;
						fragments[1].len =
						    length - split1;
						memcpy(buf2, encoded, split1);
						memcpy(buf1, encoded + split1,
						       length - split1);
					} else {
						root.flags =
						    3 << TFW_STR_CN_SHIFT;
						fragments[0].len = split1;
						fragments[1].len =
						    split2 - split1;
						fragments[2].len =
						    length - split2;
						memcpy(buf2, encoded, split1);
						memcpy(buf1, encoded + split1,
						       split2 - split1);
						memcpy(buf3, encoded + split2,
						       length - split2);
					}
				}
			}
			buffer_from_tfwstr(&in, &root);
			rc = huffman_decode_fragments(&in, &out, length);
			if (rc) {
				printf("Bug #1: Iteration: %u, "
				       "rc = %u...\n", i, rc);
				return 1;
			}
			n = out.str.len;
			if (n != test[i].source_len) {
				printf("Bug #3: Iteration: %u, "
				       "length = %u...\n", i, (unsigned int)n);
				return 1;
			}
#if With_Compare
			{
				const char *source = test[i].source;

				if (TFW_STR_PLAIN(&out.str)) {
					if (memcmp(source, out.str.ptr, n)) {
						printf("Bug #2: Iteration: %u, "
						       "Invalid decoded data...\n",
						       i);
						return 1;
					}
				} else {
					TfwStr *__restrict fp =
					    (TfwStr *) out.str.ptr;
					const unsigned int count =
					    TFW_STR_CHUNKN(&out.str);
					unsigned int cnt = count;

					do {
						const unsigned int m = fp->len;

						if (m == 0) {
							printf
							    ("Bug #4: Iteration: %u, "
							     "Zero-length fragment...\n",
							     i);
							return 1;
						}
						if (memcmp(source, fp->ptr, m)) {
							printf
							    ("Bug #2: Iteration: %u, "
							     "Invalid decoded data...\n",
							     i);
							return 1;
						}
						source += m;
						fp++;
					} while (--cnt);
					tfw_pool_free(NULL, out.str.ptr,
						      sizeof(TfwStr) * count);
				}
			}
#else
			if (!TFW_STR_PLAIN(&out.str)) {
				const unsigned int count =
				    TFW_STR_CHUNKN(&out.str);
				tfw_pool_free(NULL, out.str.ptr,
					      sizeof(TfwStr) * count);
			}
#endif
		}
	}
	tm = (double)(clock() - ts) / CLOCKS_PER_SEC;
	printf("Time = %g\n", tm);
	return 0;
}
