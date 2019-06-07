/**
 *		Tempesta FW
 *
 * HTTP/2 Huffman state machine generator.
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
#include <inttypes.h>

#include "hfcode.h"

#define ht_debug 0

#define nbits 7
#define mbits 3

#define big (1 << nbits)
#define small (1 << mbits)
#define step (1 << (nbits - mbits))

static uint32_t codes[257];
static uint8_t codes_n[257];

typedef struct htree {
	int16_t symbol;
	uint8_t shift;
	uint8_t count;
	uint8_t max;
	uint16_t offset;
	struct htree *down;
} htree;

static htree root[big];

static void
ht_add(htree * __restrict base, uint32_t code, uint8_t length, int16_t symbol)
{
	unsigned int index = code >> (32 - nbits);
	int remain = length - nbits;

	if (remain <= 0) {
		base[index].symbol = symbol;
		base[index].shift = length;
		if (remain < 0) {
			unsigned int n = 1 << (unsigned int)-remain;
			unsigned int j;

			for (j = 1; j < n; j++) {
				base[index + j].symbol = symbol;
				base[index + j].shift = length;
			}
		}
	} else {
		htree *__restrict hb = base + index;
		htree *__restrict hp;

		hp = hb->down;
		if (hp == NULL) {
			unsigned int j;

			hp = calloc(big * sizeof(htree), 1);
			if (hp == NULL) {
				puts("Memory allocation error...");
				exit(1);
			}
			hb->down = hp;
			for (j = 0; j < big; j++) {
				hp[j].symbol = -2;
			}
		}
		hb->count++;
		if (hb->max < remain) {
			hb->max = remain;
		}
		ht_add(hp, code << nbits, remain, symbol);
	}
}

#if ht_debug

static void
ht_print(htree * __restrict base)
{
	unsigned int i;

	for (i = 0; i < big; i++) {
		if (base[i].down == NULL) {
			printf("%3u --> %3d, %2u\n", i,
			       base[i].symbol, base[i].shift);
		} else {
			printf("%3u --> (%u, max: %u)\n", i,
			       base[i].count, base[i].max);
		}
	}
	puts("---");
	for (i = 0; i < big; i++) {
		htree *__restrict hp = base[i].down;

		if (hp) {
			ht_print(hp);
		}
	}
}

#endif

static unsigned int
ht_gen(htree * __restrict base, unsigned int offset)
{
	unsigned int i;

	offset += big;
	for (i = 0; i < big; i++) {
		htree *__restrict hp = base[i].down;

		if (hp && base[i].max > mbits) {
			base[i].offset = offset;
			offset = ht_gen(hp, offset);
		}
	}
	return offset;
}

static unsigned int
ht_gen16(htree * __restrict base, unsigned int offset)
{
	unsigned int i;

	for (i = 0; i < big; i++) {
		htree *__restrict hp = base[i].down;

		if (hp) {
			if (base[i].max <= mbits) {
				base[i].offset = offset;
				offset += small;
			} else {
				offset = ht_gen16(hp, offset);
			}
		}
	}
	return offset;
}

static unsigned char Incomplete_Path = 0;

static unsigned int
ht_out(const htree * __restrict base,
       unsigned int offset, const unsigned int last)
{
	unsigned int i;

	printf("/* --- [TABLE-%u: offset = %u] --- */\n", big, offset);
	offset += big;
	for (i = 0; i < big; i++) {
		char comma = ',';

		if (i == big - 1 && offset == last) {
			comma = ' ';
		}
		if (base[i].down == NULL) {
			unsigned int shift = base[i].shift;
			int symbol = base[i].symbol;

			if (symbol == -1) {
				printf("\t{%u,  %4d}%c /* %u: EOS */\n",
				       shift, 0, comma, shift);
			} else if (symbol == -2) {
				printf("\t{-%u, %4d}%c /* %u: Bug */\n",
				       shift, -1, comma, shift);
				Incomplete_Path = 1;
			} else if (symbol == '\\') {
				printf("\t{%u,  %4d}%c /* %u: '\\\\' (%d) */\n",
				       shift, (signed char)symbol, comma, shift,
				       symbol);
			} else if (symbol == '\'') {
				printf("\t{%u,  %4d}%c /* %u: '\\'' (%d) */\n",
				       shift, (signed char)symbol, comma, shift,
				       symbol);
			} else if (symbol >= 32 && symbol < 127) {
				printf("\t{%u,  %4d}%c /* %u: '%c' (%d) */\n",
				       shift, (signed char)symbol, comma, shift,
				       symbol, symbol);
			} else {
				printf
				    ("\t{%u,  %4d}%c /* %u: '\\x%02X' (%d) */\n",
				     shift, (signed char)symbol, comma, shift,
				     symbol, symbol);
			}
		} else {
			printf("\t{-%u, %4u}%c /* %u: ---> TABLE %u */\n",
			       nbits, base[i].offset, comma, nbits,
			       base[i].offset);
		}
	}
	for (i = 0; i < big; i++) {
		htree *__restrict hp = base[i].down;

		if (hp && base[i].max > mbits) {
			offset = ht_out(hp, offset, last);
		}
	}
	return offset;
}

static unsigned int
ht_out16(const htree * __restrict base,
	 unsigned int offset, const unsigned int last)
{
	unsigned int i;

	for (i = 0; i < big; i++) {
		htree *__restrict hp = base[i].down;

		if (hp) {
			if (base[i].max <= mbits) {
				unsigned int j;

				printf
				    ("/* --- [TABLE-%u: offset = %u] --- */\n",
				     small, offset);
				offset += small;
				for (j = 0; j < big; j += step) {
					unsigned int shift = hp[j].shift;
					unsigned int shift2 =
					    shift + nbits - mbits;
					int symbol = hp[j].symbol;
					char comma = ',';

					if (i == big - step && offset == last) {
						comma = ' ';
					}
					if (symbol == -1) {
						printf
						    ("\t{%u,  %4d}%c /* %u: EOS */\n",
						     shift2, 0, comma, shift);
					} else if (symbol == -2) {
						printf
						    ("\t{-%u, %4d}%c /* %u: Bug */\n",
						     shift2, -1, comma, shift);
						Incomplete_Path = 1;
					} else if (symbol == '\\') {
						printf
						    ("\t{%u,  %4d}%c /* %u: '\\\\' (%d) */\n",
						     shift2,
						     (signed char)symbol, comma,
						     shift, symbol);
					} else if (symbol == '\'') {
						printf
						    ("\t{%u,  %4d}%c /* %u: '\\'' (%d) */\n",
						     shift2,
						     (signed char)symbol, comma,
						     shift, symbol);
					} else if (symbol >= 32 && symbol < 127) {
						printf
						    ("\t{%u,  %4d}%c /* %u: '%c' (%d) */\n",
						     shift2,
						     (signed char)symbol, comma,
						     shift, symbol, symbol);
					} else {
						printf
						    ("\t{%u,  %4d}%c /* %u: '\\x%02X' (%d) */\n",
						     shift2,
						     (signed char)symbol, comma,
						     shift, symbol, symbol);
					}
				}
			} else {
				offset = ht_out16(hp, offset, last);
			}
		}
	}
	return offset;
}

int common_cdecl
main(void)
{
	unsigned int i;
	unsigned int offset;
	unsigned int offset16;

	for (i = 0; i < big; i++) {
		root[i].symbol = -2;
	}
	for (i = 0; i < HF_SYMBOLS; i++) {
		unsigned int code = source[i].code;
		unsigned int length = source[i].length;
		int16_t symbol = source[i].symbol;
		unsigned int index = symbol >= 0 ? symbol : 256;

		codes[index] = code;
		codes_n[index] = length;
		code <<= 32 - length;
		ht_add(root, code, length, symbol);
	}
#if ht_debug
	ht_print(root);
#endif
	offset = ht_gen(root, 0);
	offset16 = ht_gen16(root, offset);
	printf("/* This is generated file, please do not edit it... */\n\n");
	if (Incomplete_Path) {
		puts("/* Unbalanced huffman tree is not supported */");
		puts("/* by current version of the decoder... */");
		return 1;
	}
	printf("#define HT_NBITS %u\n", nbits);
	printf("#define HT_MBITS %u\n\n", mbits);
	printf("#define HT_NMASK %u\n", big - 1);
	printf("#define HT_MMASK %u\n\n", small - 1);
	printf("#define HT_SMALL %u\n", offset);
	printf("#define HT_TOTAL %u\n\n", offset16);
	printf("static const uint32_t ht_encode [] = {\n\t");
	for (i = 0; i < 256; i += 4) {
		unsigned int j;
		unsigned int code;

		for (j = 0; j < 3; j++) {
			code = codes[i + j];
			printf("0x%08X, ", code);
		}
		code = codes[i + j];
		if (i != 256 - 4) {
			printf("0x%08X,\n\t", code);
		} else {
			printf("0x%08X\n};\n\n", code);
		}
	}
	printf("static const uint8_t ht_length [] = {\n\t");
	for (i = 0; i < 256; i += 16) {
		unsigned int j;

		for (j = 0; j < 15; j++) {
			printf("%2u, ", codes_n[i + j]);
		}
		if (i != 240) {
			printf("%2u,\n\t", codes_n[i + j]);
		} else {
			printf("%2u\n};\n\n", codes_n[i + j]);
		}
	}
	{
		unsigned int code = codes[256];
		unsigned int length = codes_n[256];

		printf("#define HT_EOS 0x%08X\n", code);
		printf("#define HT_EOS_HIGH 0x%02X\n", code >> (length - 8));
		printf("#define HT_EOS_LENGTH %u\n\n", length);
	}
	puts("static const HTState ht_decode [] = {");
	ht_out(root, 0, offset16);
	ht_out16(root, offset, offset16);
	puts("};");
	return 0;
}
