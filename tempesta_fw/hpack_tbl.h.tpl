/**
 *		Tempesta FW
 *
 * Copyright (C) 2019 Tempesta Technologies, Inc.
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
#ifndef __TFW_HTTP_HPACK_TBL_H__
#define __TFW_HTTP_HPACK_TBL_H__

/* This file is auto generated, please do not edit it... */

/**
 * Huffman decoder state machine:
 * |shift| = modulus of the "shift" field always contains
 *	     number of bits in the Huffman-encoded representation,
 *	     which must be taken by decoder on this step.
 * NB! for short tables (f.e. 8-entries tables) difference
 *     in the prefix length (f.e. 7 bits for the big tables
 *     minus 3 bits for short tables = 4 bits) was pre-added
 *     to the value of "shift" field (just to speedup the decoder),
 *     thus true value of the Huffman-encoded prefix, which must
 *     be taken by decoder on this step is equal to the "shift"
 *     minus three.
 * shift > 0 ---> normal symbol:
 *    offset = signed char representation of the decoded symbol.
 * shift < 0 && offset == 0 ---> EOS.
 *    |shift| = number of bits in the truncated path.
 * shift < 0 && offset > 0 ---> jump to next table:
 *    offset = offset of the next table.
 */
typedef struct {
	short	shift;
	short	offset;
} HTState;

#define HT_NBITS			7
#define HT_MBITS			3
#define HT_NMASK			127
#define HT_MMASK			7
#define HT_SMALL			640
#define HT_EOS_HIGH			0xFF

static const HTState ht_decode[ [% TABLE_SIZE %] ] ____cacheline_aligned = {
    [% TABLE %]
};

#endif /* __TFW_HTTP_HPACK_TBL_H__ */
