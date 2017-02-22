/**
 *		Tempesta FW
 *
 * HTTP/2 Huffman encoders and decoders.
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

#include "common.h"
#include "netconv.h"
#include "buffers.h"
#include "huffman.h"

/*
 * Huffman decoder state machine:
 * |shift| = modulus of the "shift" field always contains
 *	     number of bits in the Huffman-encoded representation,
 *	     which must be taken by decoder on this step.
 * NB! for short tables (16-entries tables) difference
 *     in the prefix length (7 bits for the big tables
 *     minus 4 bits for short tables = 3 bits) was pre-added
 *     to the value of "shift" field (just to speedup the decoder),
 *     thus true value of the Huffman-encoded prefix, which must
 *     be taken by decoder on this step is equal to the "shift"
 *     minus three.
 * shift > 0 ---> normal symbol:
 *    offset = signed char representation of the decoded symbol.
 * shift < 0 && offset == -1 ---> EOS.
 * shift < 0 && offset == -2 ---> Bug, we need to stop decoder:
 *    |shift| = number of bits in the truncated path.
 * shift < 0 && offset > 0 ---> jump to next table:
 *    offset = offset of the next table.
 */
typedef struct {
	int8 shift;
	int16 offset;
} HTState;

#include "hfstate.h"

static fast
http2_huffman_decode_tail (ufast c,
			   char * __restrict dst,
			   fast current,
			   const HTState * __restrict state)
{
	ufast i;
	for (;;) {
		fast shift;
		if (Opt_Unlikely(current == -7)) {
			if (Opt_Likely(state == HTDecode)) {
				return 0;
			}
			else {
				return HTTP2Error_Huffman_CodeTooShort;
			}
		}
		i = (c << -current) & 127;
		shift = state[i].shift;
		if (shift >= 0) {
			if (shift > current + 7) {
				break;
			}
			* dst++ = (char) state[i].offset;
			current -= shift;
			state = HTDecode;
		}
		else {
		     /*
		      * Last 7-bit prefix also processed here, to allow
		      * EOS padding detection. Condition here equivalent to
		      * the "-shift >= current + 7", but working faster:
		      */
			if (Opt_Likely(shift <= -7 - current)) {
				break;
			}
			#ifdef HT_BALANCED_TREE
				return state[i].offset < 0 ? HTTP2Error_Huffman_UnexpectedEOS :
							     HTTP2Error_Huffman_InvalidCode;
			#else
				return state[i].offset == -1 ? HTTP2Error_Huffman_UnexpectedEOS :
							       HTTP2Error_Huffman_InvalidCode;
			#endif
		}
	}
	if (Opt_Likely(state == HTDecode &&
	       (i ^ (HT_EOS_HIGH >> 1)) < (1U << -current)))
	{
		return 0;
	}
	else {
		return HTTP2Error_Huffman_CodeTooShort;
	}
}

static fast
http2_huffman_decode_tail16 (ufast c,
			     char * __restrict dst,
			     fast current,
			     const HTState * __restrict state)
{
	int16 offset;
	fast shift;
	ufast i;
	if (Opt_Unlikely(current == -4)) {
		return HTTP2Error_Huffman_CodeTooShort;
	}
	i = (c << -current) & 15;
	shift = state[i].shift;
	offset = state[i].offset;
	if (Opt_Likely(shift >= 0)) {
		if (Opt_Unlikely(shift > current + 7)) {
			return HTTP2Error_Huffman_CodeTooShort;
		}
		* dst++ = (char) offset;
		current -= shift;
		return http2_huffman_decode_tail(c, dst, current, HTDecode);
	}
	else {
		if (Opt_Unlikely(-shift > current + 7)) {
			return HTTP2Error_Huffman_CodeTooShort;
		}
		#ifdef HT_BALANCED_TREE
			return offset < 0 ? HTTP2Error_Huffman_UnexpectedEOS :
					    HTTP2Error_Huffman_InvalidCode;
		#else
			return offset == -1 ? HTTP2Error_Huffman_UnexpectedEOS :
					      HTTP2Error_Huffman_InvalidCode;
		#endif
	}
}

fast
http2_huffman_decode (const char * __restrict source,
			    char * __restrict dst,
			    uwide	      n)
{
	if (n) {
		const uchar * __restrict src = (const uchar *) source;
		ufast c = * src++;
		fast current = 8 - 7;
		int16 offset;
		n--;
		for (;;) {
			const HTState * __restrict state;
Root:			state = HTDecode;
			for (;;) {
				fast shift;
				ufast i;
				if (current <= 0) {
					if (Opt_Likely(n)) {
						current += 8;
						c = Bit_Join8(c, * src++);
						n--;
					}
					else {
					     /* Last 7-bit prefix also processed here (see current <= 0 above): */
						return http2_huffman_decode_tail(c, dst, current, state);
					}
				}
				i = (c >> current) & 127;
				shift = state[i].shift;
				offset = state[i].offset;
				if (shift >= 0) {
					* dst++ = (char) offset;
					current -= shift;
					goto Root;
				}
				else {
					current += shift;
					if (Opt_Unlikely(offset < 0)) {
						goto End;
					}
					state = HTDecode + offset;
					if (offset >= HT_SMALL) {
						break;
					}
				}
			}
			current += 3;
			{
				fast shift;
				ufast i;
				if (current < 0) {
					if (Opt_Likely(n)) {
						current += 8;
						c = Bit_Join8(c, * src++);
						n--;
					}
					else {
						return http2_huffman_decode_tail16(c, dst, current, state);
					}
				}
				i = (c >> current) & 15;
				shift = state[i].shift;
				offset = state[i].offset;
				if (Opt_Likely(shift >= 0)) {
					* dst++ = (char) offset;
					current -= shift;
				}
				else {
					break;
				}
			}
		}
	     /* Optimization pass in MSVC generates non-optimal code here: */
		#if defined(HT_BALANCED_TREE) && ! defined(_MSC_VER)
End:			return HTTP2Error_Huffman_UnexpectedEOS;
		#else
End:			return offset == -1 ? HTTP2Error_Huffman_UnexpectedEOS :
					      HTTP2Error_Huffman_InvalidCode;
		#endif
	}
	else {
		return 0;
	}
}

fast
http2_huffman_decode_fragments (HTTP2Buffer * const __restrict source,
				char	    *	    __restrict dst,
				uwide			       n)
{
	if (n) {
		uwide m;
		const uchar * __restrict src = source->get(source, &m);
		ufast c = * src++;
		fast current = 8 - 7;
		int16 offset;
		n--;
		m--;
		for (;;) {
			const HTState * __restrict state;
Root:			state = HTDecode;
			for (;;) {
				fast shift;
				ufast i;
				if (current <= 0) {
					if (Opt_Likely(n)) {
						if (m == 0) {
							src = source->next(source, &m);
							m--;
						}
						current += 8;
						c = Bit_Join8(c, * src++);
						n--;
					}
					else {
					     /* Last 7-bit prefix also processed here (see current <= 0 above): */
						return http2_huffman_decode_tail(c, dst, current, state);
					}
				}
				i = (c >> current) & 127;
				shift = state[i].shift;
				offset = state[i].offset;
				if (shift >= 0) {
					* dst++ = (char) offset;
					current -= shift;
					goto Root;
				}
				else {
					current += shift;
					if (Opt_Unlikely(offset < 0)) {
						goto End;
					}
					state = HTDecode + offset;
					if (offset >= HT_SMALL) {
						break;
					}
				}
			}
			current += 3;
			{
				fast shift;
				ufast i;
				if (current < 0) {
					if (Opt_Likely(n)) {
						if (m == 0) {
							src = source->next(source, &m);
							m--;
						}
						current += 8;
						c = Bit_Join8(c, * src++);
						n--;
					}
					else {
						return http2_huffman_decode_tail16(c, dst, current, state);
					}
				}
				i = (c >> current) & 15;
				shift = state[i].shift;
				offset = state[i].offset;
				if (Opt_Likely(shift >= 0)) {
					* dst++ = (char) offset;
					current -= shift;
				}
				else {
					break;
				}
			}
		}
	     /* Optimization pass in MSVC generates non-optimal code here: */
		#if defined(HT_BALANCED_TREE) && ! defined(_MSC_VER)
End:			return HTTP2Error_Huffman_UnexpectedEOS;
		#else
End:			return offset == -1 ? HTTP2Error_Huffman_UnexpectedEOS :
					      HTTP2Error_Huffman_InvalidCode;
		#endif
	}
	else {
		return 0;
	}
}

#ifdef Platform_32bit
#define Write1()		     \
	dst[0] = (char) (aux >> 24)
#define Write2()		     \
	Write1();		     \
	dst[1] = (char) (aux >> 16)
#define Write4()		     \
	Write2();		     \
	dst[2] = (char) (aux >> 8);  \
	dst[3] = (char) aux
#define WriteAux Write4
#else
#define Write1()		     \
	dst[0] = (char) (aux >> 56)
#define Write2()		     \
	Write1();		     \
	dst[1] = (char) (aux >> 48)
#define Write4()		     \
	Write2();		     \
	dst[2] = (char) (aux >> 40); \
	dst[3] = (char) (aux >> 32)
#define WriteAux()		     \
	Write4();		     \
	dst[4] = (char) (aux >> 24); \
	dst[5] = (char) (aux >> 16); \
	dst[6] = (char) (aux >> 8);  \
	dst[7] = (char) aux
#endif

uwide
http2_huffman_encode (const char * __restrict source,
			    char * __restrict dst,
			    uwide	      n)
{
	char * __restrict const dst_saved = dst;
	if (n) {
		const uchar * __restrict src = (const uchar *) source;
		fast current = 0;
		uwide aux = 0;
		do {
			const ufast s = * src++;
			const ufast d = Bit_Capacity - current;
			const ufast c = HTEncode[s];
			const ufast m = HTLength[s];
			current += m;
			if (m <= d) {
				aux = Bit_Join(aux, m, c);
			}
			else {
				current -= Bit_Capacity;
				aux = Bit_Join(aux, d, c >> current);
				#ifndef Platform_Alignment
					#ifdef Platform_Little
					   aux = SwapBytes(aux);
					#endif
					* (uwide *) dst = aux;
				#else
					WriteAux();
				#endif
				dst += Word_Size;
				aux = c;
			}
		} while (--n);
		if (current) {
			ufast tail = current & 7;
			if (tail) {
				ufast d = 8 - tail;
				aux = Bit_Join(aux, d, HT_EOS_HIGH >> tail);
				current += d;
			}
			aux <<= Bit_Capacity - current;
			#if defined(Platform_Little) && !defined(Platform_Alignment)
			   aux = SwapBytes(aux);
			#endif
			#ifdef Platform_64bit
				if (current == Bit_Capacity) {
					#ifndef Platform_Alignment
						* (uwide *) dst = aux;
					#else
						WriteAux();
					#endif
					dst += Word_Size;
					current = 0;
				}
			#endif
			if (current > 31) {
				#ifndef Platform_Alignment
					* (uint32 *) dst = (uint32) aux;
				#else
					Write4();
				#endif
				dst += 4;
				#ifdef Platform_32bit
					current = 0;
				#else
					#ifndef Platform_Alignment
						aux >>= 32;
					#else
						aux <<= 32;
					#endif
					current -= 32;
				#endif
			}
			if (current > 15) {
				#ifndef Platform_Alignment
					* (uint16 *) dst = (uint16) aux;
				#else
					Write2();
				#endif
				dst += 2;
				#ifndef Platform_Alignment
					aux >>= 16;
				#else
					aux <<= 16;
				#endif
				current -= 16;
			}
			if (current) {
				#ifndef Platform_Alignment
					* dst++ = (char) aux;
				#else
					Write1();
					dst++;
				#endif
			}
		}
	}
	return dst - dst_saved;
}
