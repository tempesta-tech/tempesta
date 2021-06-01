/**
 *		Tempesta FW
 *
 * HTTP/2 Huffman state machine generator.
 *
 * Copyright (C) 2017-2019 Tempesta Technologies, Inc.
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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

typedef struct {
	int16_t		symbol;
	uint32_t	code;
	uint8_t		length;
} HCode;

/*
 * Huffman code RFC 7541, Apendix B.
 * <symbol> <hex code> <length in bits>
 */
static HCode source[] = {
	{0, 0x1ff8, 13},
	{1, 0x7fffd8, 23},
	{2, 0xfffffe2, 28},
	{3, 0xfffffe3, 28},
	{4, 0xfffffe4, 28},
	{5, 0xfffffe5, 28},
	{6, 0xfffffe6, 28},
	{7, 0xfffffe7, 28},
	{8, 0xfffffe8, 28},
	{9, 0xffffea, 24},
	{10, 0x3ffffffc, 30},
	{11, 0xfffffe9, 28},
	{12, 0xfffffea, 28},
	{13, 0x3ffffffd, 30},
	{14, 0xfffffeb, 28},
	{15, 0xfffffec, 28},
	{16, 0xfffffed, 28},
	{17, 0xfffffee, 28},
	{18, 0xfffffef, 28},
	{19, 0xffffff0, 28},
	{20, 0xffffff1, 28},
	{21, 0xffffff2, 28},
	{22, 0x3ffffffe, 30},
	{23, 0xffffff3, 28},
	{24, 0xffffff4, 28},
	{25, 0xffffff5, 28},
	{26, 0xffffff6, 28},
	{27, 0xffffff7, 28},
	{28, 0xffffff8, 28},
	{29, 0xffffff9, 28},
	{30, 0xffffffa, 28},
	{31, 0xffffffb, 28},
	{32, 0x14, 6},
	{33, 0x3f8, 10},
	{34, 0x3f9, 10},
	{35, 0xffa, 12},
	{36, 0x1ff9, 13},
	{37, 0x15, 6},
	{38, 0xf8, 8},
	{39, 0x7fa, 11},
	{40, 0x3fa, 10},
	{41, 0x3fb, 10},
	{42, 0xf9, 8},
	{43, 0x7fb, 11},
	{44, 0xfa, 8},
	{45, 0x16, 6},
	{46, 0x17, 6},
	{47, 0x18, 6},
	{48, 0x0, 5},
	{49, 0x1, 5},
	{50, 0x2, 5},
	{51, 0x19, 6},
	{52, 0x1a, 6},
	{53, 0x1b, 6},
	{54, 0x1c, 6},
	{55, 0x1d, 6},
	{56, 0x1e, 6},
	{57, 0x1f, 6},
	{58, 0x5c, 7},
	{59, 0xfb, 8},
	{60, 0x7ffc, 15},
	{61, 0x20, 6},
	{62, 0xffb, 12},
	{63, 0x3fc, 10},
	{64, 0x1ffa, 13},
	{65, 0x21, 6},
	{66, 0x5d, 7},
	{67, 0x5e, 7},
	{68, 0x5f, 7},
	{69, 0x60, 7},
	{70, 0x61, 7},
	{71, 0x62, 7},
	{72, 0x63, 7},
	{73, 0x64, 7},
	{74, 0x65, 7},
	{75, 0x66, 7},
	{76, 0x67, 7},
	{77, 0x68, 7},
	{78, 0x69, 7},
	{79, 0x6a, 7},
	{80, 0x6b, 7},
	{81, 0x6c, 7},
	{82, 0x6d, 7},
	{83, 0x6e, 7},
	{84, 0x6f, 7},
	{85, 0x70, 7},
	{86, 0x71, 7},
	{87, 0x72, 7},
	{88, 0xfc, 8},
	{89, 0x73, 7},
	{90, 0xfd, 8},
	{91, 0x1ffb, 13},
	{92, 0x7fff0, 19},
	{93, 0x1ffc, 13},
	{94, 0x3ffc, 14},
	{95, 0x22, 6},
	{96, 0x7ffd, 15},
	{97, 0x3, 5},
	{98, 0x23, 6},
	{99, 0x4, 5},
	{100, 0x24, 6},
	{101, 0x5, 5},
	{102, 0x25, 6},
	{103, 0x26, 6},
	{104, 0x27, 6},
	{105, 0x6, 5},
	{106, 0x74, 7},
	{107, 0x75, 7},
	{108, 0x28, 6},
	{109, 0x29, 6},
	{110, 0x2a, 6},
	{111, 0x7, 5},
	{112, 0x2b, 6},
	{113, 0x76, 7},
	{114, 0x2c, 6},
	{115, 0x8, 5},
	{116, 0x9, 5},
	{117, 0x2d, 6},
	{118, 0x77, 7},
	{119, 0x78, 7},
	{120, 0x79, 7},
	{121, 0x7a, 7},
	{122, 0x7b, 7},
	{123, 0x7ffe, 15},
	{124, 0x7fc, 11},
	{125, 0x3ffd, 14},
	{126, 0x1ffd, 13},
	{127, 0xffffffc, 28},
	{128, 0xfffe6, 20},
	{129, 0x3fffd2, 22},
	{130, 0xfffe7, 20},
	{131, 0xfffe8, 20},
	{132, 0x3fffd3, 22},
	{133, 0x3fffd4, 22},
	{134, 0x3fffd5, 22},
	{135, 0x7fffd9, 23},
	{136, 0x3fffd6, 22},
	{137, 0x7fffda, 23},
	{138, 0x7fffdb, 23},
	{139, 0x7fffdc, 23},
	{140, 0x7fffdd, 23},
	{141, 0x7fffde, 23},
	{142, 0xffffeb, 24},
	{143, 0x7fffdf, 23},
	{144, 0xffffec, 24},
	{145, 0xffffed, 24},
	{146, 0x3fffd7, 22},
	{147, 0x7fffe0, 23},
	{148, 0xffffee, 24},
	{149, 0x7fffe1, 23},
	{150, 0x7fffe2, 23},
	{151, 0x7fffe3, 23},
	{152, 0x7fffe4, 23},
	{153, 0x1fffdc, 21},
	{154, 0x3fffd8, 22},
	{155, 0x7fffe5, 23},
	{156, 0x3fffd9, 22},
	{157, 0x7fffe6, 23},
	{158, 0x7fffe7, 23},
	{159, 0xffffef, 24},
	{160, 0x3fffda, 22},
	{161, 0x1fffdd, 21},
	{162, 0xfffe9, 20},
	{163, 0x3fffdb, 22},
	{164, 0x3fffdc, 22},
	{165, 0x7fffe8, 23},
	{166, 0x7fffe9, 23},
	{167, 0x1fffde, 21},
	{168, 0x7fffea, 23},
	{169, 0x3fffdd, 22},
	{170, 0x3fffde, 22},
	{171, 0xfffff0, 24},
	{172, 0x1fffdf, 21},
	{173, 0x3fffdf, 22},
	{174, 0x7fffeb, 23},
	{175, 0x7fffec, 23},
	{176, 0x1fffe0, 21},
	{177, 0x1fffe1, 21},
	{178, 0x3fffe0, 22},
	{179, 0x1fffe2, 21},
	{180, 0x7fffed, 23},
	{181, 0x3fffe1, 22},
	{182, 0x7fffee, 23},
	{183, 0x7fffef, 23},
	{184, 0xfffea, 20},
	{185, 0x3fffe2, 22},
	{186, 0x3fffe3, 22},
	{187, 0x3fffe4, 22},
	{188, 0x7ffff0, 23},
	{189, 0x3fffe5, 22},
	{190, 0x3fffe6, 22},
	{191, 0x7ffff1, 23},
	{192, 0x3ffffe0, 26},
	{193, 0x3ffffe1, 26},
	{194, 0xfffeb, 20},
	{195, 0x7fff1, 19},
	{196, 0x3fffe7, 22},
	{197, 0x7ffff2, 23},
	{198, 0x3fffe8, 22},
	{199, 0x1ffffec, 25},
	{200, 0x3ffffe2, 26},
	{201, 0x3ffffe3, 26},
	{202, 0x3ffffe4, 26},
	{203, 0x7ffffde, 27},
	{204, 0x7ffffdf, 27},
	{205, 0x3ffffe5, 26},
	{206, 0xfffff1, 24},
	{207, 0x1ffffed, 25},
	{208, 0x7fff2, 19},
	{209, 0x1fffe3, 21},
	{210, 0x3ffffe6, 26},
	{211, 0x7ffffe0, 27},
	{212, 0x7ffffe1, 27},
	{213, 0x3ffffe7, 26},
	{214, 0x7ffffe2, 27},
	{215, 0xfffff2, 24},
	{216, 0x1fffe4, 21},
	{217, 0x1fffe5, 21},
	{218, 0x3ffffe8, 26},
	{219, 0x3ffffe9, 26},
	{220, 0xffffffd, 28},
	{221, 0x7ffffe3, 27},
	{222, 0x7ffffe4, 27},
	{223, 0x7ffffe5, 27},
	{224, 0xfffec, 20},
	{225, 0xfffff3, 24},
	{226, 0xfffed, 20},
	{227, 0x1fffe6, 21},
	{228, 0x3fffe9, 22},
	{229, 0x1fffe7, 21},
	{230, 0x1fffe8, 21},
	{231, 0x7ffff3, 23},
	{232, 0x3fffea, 22},
	{233, 0x3fffeb, 22},
	{234, 0x1ffffee, 25},
	{235, 0x1ffffef, 25},
	{236, 0xfffff4, 24},
	{237, 0xfffff5, 24},
	{238, 0x3ffffea, 26},
	{239, 0x7ffff4, 23},
	{240, 0x3ffffeb, 26},
	{241, 0x7ffffe6, 27},
	{242, 0x3ffffec, 26},
	{243, 0x3ffffed, 26},
	{244, 0x7ffffe7, 27},
	{245, 0x7ffffe8, 27},
	{246, 0x7ffffe9, 27},
	{247, 0x7ffffea, 27},
	{248, 0x7ffffeb, 27},
	{249, 0xffffffe, 28},
	{250, 0x7ffffec, 27},
	{251, 0x7ffffed, 27},
	{252, 0x7ffffee, 27},
	{253, 0x7ffffef, 27},
	{254, 0x7fffff0, 27},
	{255, 0x3ffffee, 26},
	{-1, 0x3fffffff, 30} /* EOS */
};

#define HF_SYMBOLS	(sizeof(source) / sizeof(HCode))

#define NBITS		7
#define MBITS		3
#define BIG		(1 << NBITS)
#define SMALL		(1 << MBITS)
#define STEP		(1 << (NBITS - MBITS))

#define BAD_SYMBOL	(-2)

static uint32_t codes[257];
static uint8_t codes_n[257];

typedef struct htree_t {
	int16_t		symbol;
	uint8_t		shift;
	uint8_t		count;
	uint8_t		max;
	uint16_t	offset;
	struct htree_t	*down;
} HTree;

static HTree root[BIG];

static void
ht_add(HTree * __restrict base, uint32_t code, uint8_t length, int16_t symbol)
{
	unsigned int j, n, index = code >> (32 - NBITS);
	int remain = length - NBITS;

	if (remain <= 0) {
		base[index].symbol = symbol;
		base[index].shift = length;
		if (remain < 0) {
			n = 1 << (unsigned int)-remain;
			for (j = 1; j < n; j++) {
				base[index + j].symbol = symbol;
				base[index + j].shift = length;
			}
		}
	} else {
		HTree *hb = base + index;
		HTree *hp;

		hp = hb->down;
		if (!hp) {
			if (!(hp = calloc(BIG * sizeof(HTree), 1))) {
				puts("Memory allocation error...");
				exit(1);
			}
			hb->down = hp;
			for (j = 0; j < BIG; j++)
				hp[j].symbol = BAD_SYMBOL;
		}
		hb->count++;
		if (hb->max < remain)
			hb->max = remain;

		ht_add(hp, code << NBITS, remain, symbol);
	}
}

#ifdef DEBUG
static void
ht_print(HTree *base)
{
	unsigned int i;

	for (i = 0; i < BIG; i++) {
		if (!base[i].down) {
			printf("%3u --> %3d, %2u\n", i,
			       base[i].symbol, base[i].shift);
		} else {
			printf("%3u --> (%u, max: %u)\n", i,
			       base[i].count, base[i].max);
		}
	}
	puts("---");
	for (i = 0; i < BIG; i++)
		if (base[i].down)
			ht_print(base[i].down);
}
#endif

static unsigned int
ht_gen(HTree *base, unsigned int offset)
{
	unsigned int i;

	offset += BIG;
	for (i = 0; i < BIG; i++) {
		if (base[i].down && base[i].max > MBITS) {
			base[i].offset = offset;
			offset = ht_gen(base[i].down, offset);
		}
	}

	return offset;
}

static unsigned int
ht_gen16(HTree *base, unsigned int offset)
{
	unsigned int i;

	for (i = 0; i < BIG; i++) {
		if (!base[i].down)
			continue;
		if (base[i].max <= MBITS) {
			base[i].offset = offset;
			offset += SMALL;
		} else {
			offset = ht_gen16(base[i].down, offset);
		}
	}

	return offset;
}

static unsigned int
ht_out(const HTree *base, unsigned int offset, const unsigned int last)
{
	unsigned int i, shift;
	int symbol;

	printf("/* --- [TABLE-%u: offset = %u] --- */\n", BIG, offset);
	offset += BIG;
	for (i = 0; i < BIG; i++) {
		char comma = (i == BIG - 1 && offset == last) ? ' ' : ',';

		if (base[i].down) {
			printf("\t{-%u, %4u}%c /* %u: ---> TABLE %u */\n",
			       NBITS, base[i].offset, comma, NBITS,
			       base[i].offset);
			continue;
		}

		shift = base[i].shift;
		symbol = base[i].symbol;
		assert(symbol != BAD_SYMBOL);

		if (symbol == -1) {
			printf("\t{-%u, %4d}%c /* %u: EOS */\n",
			       shift, 0, comma, shift);
		}
		else if (symbol == '\\') {
			printf("\t{%u,  %4d}%c /* %u: '\\\\' (%d) */\n",
			       shift, (signed char)symbol, comma, shift,
			       symbol);
		}
		else if (symbol == '\'') {
			printf("\t{%u,  %4d}%c /* %u: '\\'' (%d) */\n",
			       shift, (signed char)symbol, comma, shift,
			       symbol);
		}
		else if (symbol >= 32 && symbol < 127) {
			printf("\t{%u,  %4d}%c /* %u: '%c' (%d) */\n",
			       shift, (signed char)symbol, comma, shift,
			       symbol, symbol);
		}
		else {
			printf("\t{%u,  %4d}%c /* %u: '\\x%02X' (%d) */\n",
			       shift, (signed char)symbol, comma, shift,
			       symbol, symbol);
		}
	}
	for (i = 0; i < BIG; i++)
		if (base[i].down && base[i].max > MBITS)
			offset = ht_out(base[i].down, offset, last);

	return offset;
}

static unsigned int
ht_out16(const HTree *base, unsigned int offset, const unsigned int last)
{
	unsigned int i, j, shift, shift2;
	int symbol;
	char comma;

	for (i = 0; i < BIG; i++) {
		HTree *hp = base[i].down;
		if (!hp)
			continue;

		if (base[i].max > MBITS) {
			offset = ht_out16(hp, offset, last);
			continue;
		}

		printf("/* --- [TABLE-%u: offset = %u] --- */\n",
		       SMALL, offset);

		offset += SMALL;
		for (j = 0; j < BIG; j += STEP) {
			shift = hp[j].shift;
			shift2 = shift + NBITS - MBITS;
			symbol = hp[j].symbol;
			comma = (i == BIG - STEP && offset == last) ? ' ' : ',';

			assert(symbol != BAD_SYMBOL);

			if (symbol == -1) {
				printf("\t{-%u, %4d}%c /* %u: EOS */\n",
				       shift2, 0, comma, shift);
			}
			else if (symbol == '\\') {
				printf("\t{%u,  %4d}%c /* %u: '\\\\' (%d) */\n",
				       shift2, (signed char)symbol, comma,
				       shift, symbol);
			}
			else if (symbol == '\'') {
				printf("\t{%u,  %4d}%c /* %u: '\\'' (%d) */\n",
				       shift2, (signed char)symbol, comma,
				       shift, symbol);
			}
			else if (symbol >= 32 && symbol < 127) {
				printf("\t{%u,  %4d}%c /* %u: '%c' (%d) */\n",
				       shift2, (signed char)symbol, comma,
				       shift, symbol, symbol);
			} else {
				printf("\t{%u,  %4d}%c /* %u: '\\x%02X' (%d) */"
				       "\n", shift2, (signed char)symbol, comma,
				       shift, symbol, symbol);
			}
		}
	}

	return offset;
}

int
main(int argc, char *argv[])
{
	unsigned int i, j, offset, offset16, code, length, index;
	int symbol;

	for (i = 0; i < BIG; i++)
		root[i].symbol = BAD_SYMBOL;

	for (i = 0; i < HF_SYMBOLS; i++) {
		code = source[i].code;
		length = source[i].length;
		symbol = source[i].symbol;
		index = symbol >= 0 ? symbol : 256;

		codes[index] = code;
		codes_n[index] = length;
		code <<= 32 - length;
		ht_add(root, code, length, symbol);
	}
#ifdef DEBUG
	ht_print(root);
#endif
	offset = ht_gen(root, 0);
	offset16 = ht_gen16(root, offset);

	printf("#define HT_NBITS\t%u\n", NBITS);
	printf("#define HT_MBITS\t%u\n", MBITS);
	printf("#define HT_NMASK\t%u\n", BIG - 1);
	printf("#define HT_MMASK\t%u\n", SMALL - 1);
	printf("#define HT_SMALL\t%u\n", offset);

	code = codes[256];
	length = codes_n[256];
	printf("#define HT_EOS_HIGH\t0x%02X\n\n", code >> (length - 8));

	printf("static const unsigned int ht_encode[] __page_aligned_data"
	       " = {\n\t");
	for (i = 0; i < 256; i += 4) {
		for (j = 0; j < 3; j++)
			printf("0x%08X, ", codes[i + j]);
		if (i != 256 - 4)
			printf("0x%08X,\n\t", codes[i + j]);
		else
			printf("0x%08X\n};\n\n", codes[i + j]);
	}

	printf("static const unsigned char ht_length[] ____cacheline_aligned"
	       " = {\n\t");
	for (i = 0; i < 256; i += 16) {
		for (j = 0; j < 15; j++)
			printf("%2u, ", codes_n[i + j]);
		if (i != 240)
			printf("%2u,\n\t", codes_n[i + j]);
		else
			printf("%2u\n};\n\n", codes_n[i + j]);
	}

	puts("static const HTState ht_decode[] __page_aligned_data = {");
	ht_out(root, 0, offset16);
	ht_out16(root, offset, offset16);
	puts("};\n\n#endif /* __TFW_HTTP_HPACK_TBL_H__ */");

	return 0;
}
