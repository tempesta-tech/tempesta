/**
 *		Tempesta FW
 *
 * HTTP/2 Huffman decoder test data generator.
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
#include <math.h>
#include "../common.h"
#include "../huffman.h"

#include "../hgen/hfcode.h"

#define Probability_Shape 0.25

#define ITERATIONS 16384
#define MAXLEN 64

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

static double ranges[HF_SYMBOLS - 1];

static uint32_t counters[256];

int __cdecl
main(void)
{
	unsigned int i;
	double end;

	end = 0;
	for (i = 0; i < HF_SYMBOLS - 1; i++) {
		end += 1 / pow(1 << source[i].length, Probability_Shape);
		ranges[i] = end;
	}
	printf("/* This is generated file, please do not edit it... */\n\n");
	puts("static const HTestData test [] = {");
	for (i = 0; i < ITERATIONS; i++) {
		char buf[MAXLEN];
		char encoded[MAXLEN * 4];
		unsigned int n = Random32_Index(MAXLEN) + 1;
		unsigned int k = 0;
		unsigned int m;

		do {
			int16_t symbol;
			const double x =
			    end * (Random32() / (double)(uint32_t) - 1);
			unsigned int l, u;

			l = 1;
			u = HF_SYMBOLS - 1;
			do {
				const unsigned int j = (l + u) / 2;
				const double qx = ranges[j - 1];

				if (qx > x) {
					u = j - 1;
				} else if (likely(qx < x)) {
					l = j + 1;
				} else {
					l = j;
					break;
				}
			} while (l <= u);
			if ((int)(l - 1) < 0 || (l - 1) >= HF_SYMBOLS - 1) {
				puts("BUG in binary search or range generation!");
				return 1;
			}
			symbol = source[l - 1].symbol;
			buf[k++] = symbol;
			counters[symbol]++;
		} while (--n);
		n = k;
		printf("/* Iteration: %u */\n", i);
		printf("\t{\"");
		for (k = 0; k < n; k++) {
			printf("\\x%02X", (unsigned char)buf[k]);
		}
		printf("\", %u,\n\t \"", n);
		m = huffman_encode(buf, encoded, n);
		if (m != huffman_encode_length(buf, n)) {
			puts("Huffman length error...");
			return 1;
		}
		for (k = 0; k < m; k++) {
			printf("\\x%02X", (unsigned char)encoded[k]);
		}
		printf("\", %u%s\n", m, i == ITERATIONS - 1 ? "}" : "},");
	}
	puts("};");
/*
   for (i = 0; i < 256; i++) {
      printf("%3u: %u\n", i, counters[i]);
   }
*/
	return 0;
}
