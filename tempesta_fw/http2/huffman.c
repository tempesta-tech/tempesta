/**
 *		Tempesta FW
 *
 * HPACK (RFC-7541) Huffman encoders and decoders.
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

#include <stdint.h>
#include <inttypes.h>
#include "errors.h"
#include "buffers.h"
#include "huffman.h"
#include "hpack_helpers.h"

/*
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
	int8_t shift;
	int16_t offset;
} HTState;

#include "hfstate.h"

#if HT_NBITS + HT_MBITS < 8
#error "The end-of-string detection code requires \
that the sum of NBITS + MBITS is greater than one byte"
#endif

static unsigned int
huffman_decode_tail(unsigned int c,
		    char *__restrict dst, int current, unsigned int offset)
{
	unsigned int i;

	for (;;) {
		if (current != -HT_NBITS) {
			int shift;

			i = (c << -current) & HT_NMASK;
			shift = ht_decode[offset + i].shift;
			if (likely(shift >= 0)) {
				if (shift <= current + HT_NBITS) {
					*dst++ =
					    (char)ht_decode[offset + i].offset;
					current -= shift;
					offset = 0;
				} else {
					break;
				}
			} else {
				/*
				 * Last full prefix processed here, to allow
				 * EOS padding detection:
				 */
				if (likely(offset == 0)) {
					if ((i ^ (HT_EOS_HIGH >> 1)) <
					    (1U << -current)) {
						return 0;
					}
				}
				/*
				 * Condition here equivalent to the
				 * "-shift <= current + HT_NBITS", but
				 * working faster:
				 */
				if (shift >= -HT_NBITS - current) {
					if (ht_decode[offset + i].offset == 0) {
						return
						    Err_Huffman_UnexpectedEOS;
					}
				}
				return Err_Huffman_CodeTooShort;
			}
		} else if (likely(offset == 0)) {
			return 0;
		} else {
			return Err_Huffman_CodeTooShort;
		}
	}
	if (likely(offset == 0)) {
		if ((i ^ (HT_EOS_HIGH >> 1)) < (1U << -current)) {
			return 0;
		}
	}
	return Err_Huffman_CodeTooShort;
}

static unsigned int
huffman_decode_tail_s(unsigned int c,
		      char *__restrict dst, int current, unsigned int offset)
{
	if (current != -HT_MBITS) {
		int shift;
		const unsigned int i = (c << -current) & HT_MMASK;

		shift = ht_decode[offset + i].shift;
		if (likely(shift >= 0)) {
			if (likely(shift <= current + HT_NBITS)) {
				*dst++ = (char)ht_decode[offset + i].offset;
				current -= shift;
				return huffman_decode_tail(c, dst, current, 0);
			}
		} else {
			/*
			 * Condition here equivalent to the
			 * "-shift <= current + HT_NBITS", but
			 * working faster:
			 */
			if (shift >= -HT_NBITS - current) {
				if (ht_decode[offset + i].offset == 0) {
					return Err_Huffman_UnexpectedEOS;
				}
			}
		}
	}
	return Err_Huffman_CodeTooShort;
}

#define GET_UWIDE(tail) 		  \
do {					  \
	current = 64 - tail;	  	  \
	c = BigWide(* (uintptr_t *) src); \
	src += sizeof(uintptr_t);	  \
	n -= sizeof(uintptr_t);		  \
} while (0)

#define GET_UINT(bits)					   \
do {							   \
	current += bits;				   \
	c = Bit_Join(c, bits,				   \
		     Big##bits(* (uint##bits##_t *) src)); \
	src += bits / 8;				   \
	n -= bits / 8;					   \
} while (0)

#define GET_FIRST_UINT(bits, tail)		 \
do {						 \
	current = bits - tail;			 \
	c = Big##bits(* (uint##bits##_t *) src); \
	src += bits / 8;			 \
	n -= bits / 8;				 \
} while (0)

#define GET_BYTE()		   \
do {				   \
	current += 8;		   \
	c = Bit_Join8(c, * src++); \
	n--;			   \
} while (0)

#define GET_FIRST_BYTE(tail) \
do {			     \
	current = 8 - tail;  \
	c = * src++;	     \
	n--;		     \
} while (0)

#define GET_OCTETS_BY_8(tail)		   \
do {					   \
	current += 8;			   \
	c = Bit_Join8(c, * src++);	   \
	if (--n) {			   \
		current += 8;		   \
		c = Bit_Join8(c, * src++); \
		if (--n) {		   \
			GET_BYTE();	   \
		}			   \
	}				   \
} while (0)

#define GET_FIRST_BY_8(tail)		   \
do {					   \
	current = 8 - tail;		   \
	c = * src++;			   \
	if (--n) {			   \
		current += 8;		   \
		c = Bit_Join8(c, * src++); \
		if (--n) {		   \
			GET_BYTE();	   \
		}			   \
	}				   \
} while (0)

#define GET_CASCADE()							 \
	if ((uintptr_t) src & 2) {					 \
		if (space <= (64 - 8) - 16) { 		 		 \
			space += 16;					 \
			c = Bit_Join(c, 16, Big16(* (uint16_t *) src));  \
			src += 2;					 \
L1:									 \
			if (space <= (64 - 8) - 32) { 	 		 \
				space += 32;				 \
				c = Bit_Join(c, 32,			 \
					     Big32(* (uint32_t *) src)); \
				src += 4;				 \
			}						 \
			if (space <= (64 - 8) - 16) { 	 		 \
				space += 16;				 \
				c = Bit_Join(c, 16,			 \
					     Big16(* (uint16_t *) src)); \
				src += 2;				 \
			}						 \
		}							 \
		if (space <= (64 - 8) - 8) {			 	 \
			c = Bit_Join8(c, * src++);			 \
		}							 \
	}								 \
	else goto L1

#define GET_OCTETS(tail)			    \
do {						    \
	unsigned int space = 0; 		    \
	if (n < sizeof(uintptr_t) - 1) {	    \
		space = (64 - 8) - n * 8; 	    \
		n = sizeof(uintptr_t) - 1;	    \
		current -= space;		    \
	}					    \
	if ((uintptr_t) src & 1) {		    \
		c = Bit_Join8(c, * src++);	    \
		space += 8;			    \
	}					    \
	current += (sizeof(uintptr_t) - 1) * 8;	    \
	n -= sizeof(uintptr_t) - 1;		    \
	GET_CASCADE();				    \
} while (0)

#define GET_FIRST_CASCADE()						   \
do {									   \
	c = 0;								   \
	if ((uintptr_t) src & 1) {					   \
		c = * src++;						   \
		space += 8;						   \
	}								   \
	if ((uintptr_t) src & 2) {					   \
		if (space <= 64 - 16) {			   		   \
			space += 16;					   \
			c = Bit_Join(c, 16,				   \
				     Big16(* (uint16_t *) src));	   \
			src += 2;					   \
L0:									   \
			if (space <= 64 - 32) {		   		   \
				space += 32;				   \
				c = Bit_Join(c, 32,			   \
					     Big32(* (uint32_t *) src));   \
				src += 4;				   \
			}						   \
			if (space <= 64 - 16) {		   		   \
				space += 16;				   \
				c = Bit_Join(c, 16,			   \
					     Big16(* (uint16_t *) src));   \
				src += 2;				   \
			}						   \
		}							   \
		if (space <= 64 - 8) {			   		   \
			c = Bit_Join8(c, * src++);			   \
		}							   \
	}								   \
	else if (space) {						   \
		goto L0;						   \
	}								   \
	else {								   \
		c = BigWide(						   \
			Bit_Join((uintptr_t) * (uint32_t *) (src + 4), 32, \
					     * (uint32_t *) src)	   \
		);							   \
		src += sizeof(uintptr_t);				   \
	}								   \
} while (0)

#define GET_FIRST(tail) 				\
do {							\
	unsigned int space = 0; 			\
	current = 64 - HT_NBITS;			\
	if (((uintptr_t) src & (sizeof(uintptr_t) - 1)) == 0) { \
		if (n < sizeof(uintptr_t)) {		\
			goto Z0;			\
		}					\
		c = BigWide(* (uintptr_t *) src);	\
		src += sizeof(uintptr_t);		\
	}						\
	else {						\
		if (n < sizeof(uintptr_t)) {		\
Z0:							\
			space = 64 - n * 8;		\
			n = sizeof(uintptr_t);		\
			current -= space;		\
		}					\
	}						\
	GET_FIRST_CASCADE();				\
	n -= sizeof(uintptr_t);				\
} while (0)

unsigned int
huffman_decode(const char *__restrict source, char *__restrict dst, uintptr_t n)
{
	if (n) {
		const unsigned char *__restrict src =
		    (const unsigned char *)source;
		uintptr_t c;
		int current;
		unsigned int offset;

		GET_FIRST(HT_NBITS);
		for (;;) {
			offset = 0;
			for (;;) {
				int shift;
				unsigned int i;

				if (current <= 0) {
					if (likely(n)) {
						GET_OCTETS_BY_8(HT_NBITS);
					} else {
						/* Last full prefix also processed here */
						/* (see current <= 0 above): */
						return huffman_decode_tail(c,
									   dst,
									   current,
									   offset);
					}
				}
				i = (c >> current) & HT_NMASK;
				shift = ht_decode[offset + i].shift;
				offset = ht_decode[offset + i].offset;
				if (shift >= 0) {
					*dst++ = (char)offset;
					current -= shift;
					offset = 0;
				} else {
					current += shift;
					if (offset >= HT_SMALL) {
						break;
					}
					if (unlikely(offset == 0)) {
						goto End;
					}
				}
			}
			current += HT_NBITS - HT_MBITS;
			/* With various optimization options, the anonymous block */
			/* here leads to the generation of more efficient code:   */
			{
				int shift;
				unsigned int i;

				if (current < 0) {
					if (likely(n)) {
						GET_OCTETS(HT_MBITS);
					} else {
						return huffman_decode_tail_s(c,
									     dst,
									     current,
									     offset);
					}
				}
				i = (c >> current) & HT_MMASK;
				shift = ht_decode[offset + i].shift;
				offset = ht_decode[offset + i].offset;
				if (likely(shift >= 0)) {
					*dst++ = (char)offset;
					current -= shift;
				} else {
					break;
				}
			}
		}
 End:
		return Err_Huffman_UnexpectedEOS;
	} else {
		return 0;
	}
}

static unsigned int
huffman_decode_tail_f(unsigned int c,
		      HTTP2Output * __restrict out,
		      int current,
		      unsigned int offset,
		      unsigned char *__restrict dst, unsigned int k)
{
	unsigned int i;

	for (;;) {
		if (current != -HT_NBITS) {
			int shift;

			i = (c << -current) & HT_NMASK;
			shift = ht_decode[offset + i].shift;
			if (likely(shift >= 0)) {
				if (shift <= current + HT_NBITS) {
					CheckByte(out);
					*dst++ =
					    (unsigned char)ht_decode[offset +
								     i].offset;
					k--;
					current -= shift;
					offset = 0;
				} else {
					break;
				}
			} else {
				/*
				 * Last full prefix processed here, to allow
				 * EOS padding detection:
				 */
				if (likely(offset == 0)) {
					if ((i ^ (HT_EOS_HIGH >> 1)) <
					    (1U << -current)) {
						return buffer_emit(out, k);
					}
				}
				/*
				 * Condition here equivalent to the
				 * "-shift <= current + HT_NBITS", but
				 * working faster:
				 */
				if (shift >= -HT_NBITS - current) {
					if (ht_decode[offset + i].offset == 0) {
						return
						    Err_Huffman_UnexpectedEOS;
					}
				}
				return Err_Huffman_CodeTooShort;
			}
		} else if (likely(offset == 0)) {
			return buffer_emit(out, k);
		} else {
			return Err_Huffman_CodeTooShort;
		}
	}
	if (likely(offset == 0)) {
		if ((i ^ (HT_EOS_HIGH >> 1)) < (1U << -current)) {
			return buffer_emit(out, k);
		}
	}
	return Err_Huffman_CodeTooShort;
}

static unsigned int
huffman_decode_tail_s_f(unsigned int c,
			HTTP2Output * __restrict out,
			int current,
			unsigned int offset,
			unsigned char *__restrict dst, unsigned int k)
{
	if (current != -HT_MBITS) {
		int shift;
		const unsigned int i = (c << -current) & HT_MMASK;

		shift = ht_decode[offset + i].shift;
		if (likely(shift >= 0)) {
			if (likely(shift <= current + HT_NBITS)) {
				CheckByte(out);
				*dst++ =
				    (unsigned char)ht_decode[offset + i].offset;
				k--;
				current -= shift;
				return huffman_decode_tail_f(c, out, current, 0,
							     dst, k);
			}
		} else {
			/*
			 * Condition here equivalent to the
			 * "-shift <= current + HT_NBITS", but
			 * working faster:
			 */
			if (shift >= -HT_NBITS - current) {
				if (ht_decode[offset + i].offset == 0) {
					return Err_Huffman_UnexpectedEOS;
				}
			}
		}
	}
	return Err_Huffman_CodeTooShort;
}

#define GET_UWIDE_FR(tail)		  \
do {					  \
	current = 64 - tail;	  	  \
	c = BigWide(* (uintptr_t *) src); \
	src += sizeof(uintptr_t);	  \
	n -= sizeof(uintptr_t);		  \
	m -= sizeof(uintptr_t);		  \
} while (0)

#define GET_UINT_FR(bits)				   \
do {							   \
	current += bits;				   \
	c = Bit_Join(c, bits,				   \
		     Big##bits(* (uint##bits##_t *) src)); \
	src += bits / 8;				   \
	n -= bits / 8;					   \
	m -= bits / 8;					   \
} while (0)

#define GET_FIRST_UINT_FR(bits, tail)		 \
do {						 \
	current = bits - tail;			 \
	c = Big##bits(* (uint##bits##_t *) src); \
	src += bits / 8;			 \
	n -= bits / 8;				 \
	m -= bits / 8;				 \
} while (0)

#define GET_BYTE_FR()		   \
do {				   \
	current += 8;		   \
	c = Bit_Join8(c, * src++); \
	n--;			   \
	m--;			   \
} while (0)

#define GET_FIRST_BYTE_FR(tail) \
do {				\
	current = 8 - tail;	\
	c = * src++;		\
	n--;			\
	m--;			\
} while (0)

#define GET_OCTETS_BY_8_FR(tail)	   \
do {					   \
	current += 8;			   \
	c = Bit_Join8(c, * src++);	   \
	--n;				   \
	if (--m && n) { 		   \
		current += 8;		   \
		c = Bit_Join8(c, * src++); \
		--n;			   \
		if (--m && n) { 	   \
			GET_BYTE_FR();	   \
		}			   \
	}				   \
} while (0)

#define GET_FIRST_BY_8_FR(tail) 	   \
do {					   \
	current = 8 - tail;		   \
	c = * src++;			   \
	--n;				   \
	if (--m && n) { 		   \
		current += 8;		   \
		c = Bit_Join8(c, * src++); \
		--n;			   \
		if (--m && n) { 	   \
			GET_BYTE_FR();	   \
		}			   \
	}				   \
} while (0)

#define GET_OCTETS_FR(tail)		       \
do {					       \
	unsigned int space = m;		       \
	if (m > n) {			       \
		space = n;		       \
	}				       \
	if (space >= sizeof(uintptr_t) - 1) {  \
		space = 0;		       \
	}				       \
	else {				       \
		space = sizeof(uintptr_t) - 1 - space; \
		n += space;		       \
		m += space;		       \
		space <<= 3;		       \
		current -= space;	       \
	}				       \
	if ((uintptr_t) src & 1) {	       \
		c = Bit_Join8(c, * src++);     \
		space += 8;		       \
	}				       \
	current += (sizeof(uintptr_t) - 1) * 8;\
	n -= sizeof(uintptr_t) - 1;	       \
	m -= sizeof(uintptr_t) - 1;	       \
	GET_CASCADE();			       \
} while (0)

#define GET_FIRST_FR(tail) 				\
do {							\
	unsigned int space = m; 			\
	if (m > n) {					\
		space = n;				\
	}						\
	current = 64 - HT_NBITS;			\
	if (((uintptr_t) src & (sizeof(uintptr_t) - 1)) == 0) { \
		if (space < sizeof(uintptr_t)) {	\
			goto Z0;			\
		}					\
		c = BigWide(* (uintptr_t *) src);	\
		src += sizeof(uintptr_t);		\
	}						\
	else {						\
		if (space >= sizeof(uintptr_t)) {	\
			space = 0;			\
		}					\
		else {					\
Z0:							\
			space = sizeof(uintptr_t) -     \
			        space;                  \
			n += space;			\
			m += space;			\
			space <<= 3;			\
			current -= space;		\
		}					\
	}						\
	GET_FIRST_CASCADE();				\
	n -= sizeof(uintptr_t);				\
	m -= sizeof(uintptr_t);				\
} while (0)

unsigned int
huffman_decode_fragments(HTTP2Input * __restrict source,
			 HTTP2Output * __restrict out, uintptr_t n)
{
	if (n) {
		uintptr_t m;
		const unsigned char *__restrict src = buffer_get(source, &m);
		uintptr_t c;
		int current;
		unsigned int offset;
		unsigned int k;
		unsigned char *__restrict dst = buffer_open(out, &k, 0);

		GET_FIRST_FR(HT_NBITS);
		for (;;) {
			offset = 0;
			for (;;) {
				int shift;
				unsigned int i;

				if (current <= 0) {
					if (likely(n)) {
						if (unlikely(m == 0)) {
							src =
							    buffer_next(source,
									&m);
						}
						GET_OCTETS_BY_8_FR(HT_NBITS);
					} else {
						/* Last full prefix also processed here */
						/* (see current <= 0 above): */
						buffer_close(source, m);
						return huffman_decode_tail_f(c,
									     out,
									     current,
									     offset,
									     dst,
									     k);
					}
				}
				i = (c >> current) & HT_NMASK;
				shift = ht_decode[offset + i].shift;
				offset = ht_decode[offset + i].offset;
				if (shift >= 0) {
					CheckByte(out);
					*dst++ = (unsigned char)offset;
					k--;
					current -= shift;
					offset = 0;
				} else {
					current += shift;
					if (offset >= HT_SMALL) {
						break;
					}
					if (unlikely(offset == 0)) {
						goto End;
					}
				}
			}
			current += HT_NBITS - HT_MBITS;
			/* With various optimization options, the anonymous block */
			/* here leads to the generation of more efficient code:   */
			{
				int shift;
				unsigned int i;

				if (current < 0) {
					if (likely(n)) {
						if (unlikely(m == 0)) {
							src =
							    buffer_next(source,
									&m);
						}
						GET_OCTETS_FR(HT_MBITS);
					} else {
						buffer_close(source, m);
						return
						    huffman_decode_tail_s_f(c,
									    out,
									    current,
									    offset,
									    dst,
									    k);
					}
				}
				i = (c >> current) & HT_MMASK;
				shift = ht_decode[offset + i].shift;
				offset = ht_decode[offset + i].offset;
				if (likely(shift >= 0)) {
					CheckByte(out);
					*dst++ = (unsigned char)offset;
					k--;
					current -= shift;
				} else {
					break;
				}
			}
		}
 End:
		return Err_Huffman_UnexpectedEOS;
	} else {
		return 0;
	}
}

#define Write4Big()		     \
	dst[0] = (char) (aux >> 24); \
	dst[1] = (char) (aux >> 16); \
	dst[2] = (char) (aux >> 8);  \
	dst[3] = (char) aux

#define Write8Big()		     \
	dst[0] = (char) (aux >> 56); \
	dst[1] = (char) (aux >> 48); \
	dst[2] = (char) (aux >> 40); \
	dst[3] = (char) (aux >> 32); \
	dst[4] = (char) (aux >> 24); \
	dst[5] = (char) (aux >> 16); \
	dst[6] = (char) (aux >> 8);  \
	dst[7] = (char) aux

#define Write2()		   \
	dst[0] = (char) aux;	   \
	dst[1] = (char) (aux >> 7)

#define Write4()		     \
	Write2();		     \
	dst[2] = (char) (aux >> 16); \
	dst[3] = (char) (aux >> 24)

#define Write8()		     \
	Write4();		     \
	dst[4] = (char) (aux >> 32); \
	dst[5] = (char) (aux >> 40); \
	dst[6] = (char) (aux >> 48); \
	dst[7] = (char) (aux >> 56)

#define WriteAux Write8Big

uintptr_t
huffman_encode(const char *__restrict source, char *__restrict dst, uintptr_t n)
{
	char *__restrict const dst_saved = dst;

	if (n) {
		const unsigned char *__restrict src =
		    (const unsigned char *)source;
		int current = 0;
		uintptr_t aux = 0;

		do {
			const unsigned int s = *src++;
			const unsigned int d = 64 - current;
			const unsigned int c = ht_encode[s];
			const unsigned int l = ht_length[s];

			current += l;
			if (l <= d) {
				aux = Bit_Join(aux, l, c);
			} else {
				current -= 64;
				aux = Bit_Join(aux, d, c >> current);
				aux = Big64(aux);
				*(uintptr_t *) dst = aux;
				dst += sizeof(uintptr_t);
				aux = c;
			}
		} while (--n);
		if (current) {
			unsigned int tail = current & 7;

			if (tail) {
				unsigned int d = 8 - tail;

				aux = Bit_Join(aux, d, HT_EOS_HIGH >> tail);
				current += d;
			}
			aux <<= 64 - current;
			aux = Bug64(aux);
			if (current == 64) {
				*(uintptr_t *) dst = aux;
				dst += sizeof(uintptr_t);
				goto Exit;
			}
			if (current > 31) {
				*(uint32_t *) dst = (uint32_t) aux;
				dst += 4;
				aux >>= 32;
				current -= 32;
			}
			if (current > 15) {
				*(uint16_t *) dst = (uint16_t) aux;
				dst += 2;
				aux >>= 16;
				current -= 16;
			}
			if (current) {
				*dst++ = (char)aux;
			}
		}
	}
 Exit:
	return dst - dst_saved;
}

#define WriteBytes(n)			  \
do {					  \
	unsigned int __n = n;		  \
	do {				  \
		CheckByte_goto(out, Bug); \
		* dst++ = (char) aux;	  \
		aux >>= 8;		  \
		k--;			  \
	} while (--__n);		  \
} while (0)

unsigned char *
huffman_encode_fragments(HTTP2Output * __restrict out,
			 unsigned char *__restrict dst,
			 unsigned int *__restrict k_new,
			 const TfwStr * __restrict source,
			 unsigned int *__restrict rc)
{
	uintptr_t n = source->len;

	if (TFW_STR_PLAIN(source)) {
		return huffman_encode_plain(out, dst, k_new, source->ptr, n,
					    rc);
	}
	if (n) {
		const TfwStr *__restrict fp = source->ptr;
		const unsigned char *__restrict src = fp->ptr;
		uintptr_t m = fp->len;
		unsigned int k = *k_new;
		int current = 0;
		uintptr_t aux = 0;

		fp++;
		do {
			if (unlikely(m == 0)) {
				src = fp->ptr;
				m = fp->len;
				fp++;
			}
			{
				const unsigned int s = *src++;
				const unsigned int d = 64 - current;
				const unsigned int c = ht_encode[s];
				const unsigned int l = ht_length[s];

				current += l;
				if (l <= d) {
					aux = Bit_Join(aux, l, c);
				} else {
					current -= 64;
					aux = Bit_Join(aux, d, c >> current);
					if (k >= sizeof(uintptr_t)) {
						aux = Big64(aux);
						*(uintptr_t *) dst = aux;
						dst += sizeof(uintptr_t);
					} else {
						WriteBytes(sizeof(uintptr_t));
					}
					aux = c;
				}
			}
			m--;
		} while (--n);
		if (current) {
			unsigned int tail = current & 7;

			if (tail) {
				unsigned int d = 8 - tail;

				aux = Bit_Join(aux, d, HT_EOS_HIGH >> tail);
				current += d;
			}
			aux <<= 64 - current;
			aux = Big64(aux);
			if (current == 64) {
				if (k >= sizeof(uintptr_t)) {
					*(uintptr_t *) dst = aux;
					dst += sizeof(uintptr_t);
				} else {
					WriteBytes(sizeof(uintptr_t));
				}
				goto Exit;
			}
			if (current > 31) {
				if (k >= 4) {
					*(uint32_t *) dst = (uint32_t) aux;
					dst += 4;
				} else {
					WriteBytes(4);
				}
				aux >>= 32;
				current -= 32;
			}
			if (current > 15) {
				if (k >= 2) {
					*(uint16_t *) dst = (uint16_t) aux;
					dst += 2;
				} else {
					WriteBytes(2);
				}
				aux >>= 16;
				current -= 16;
			}
			if (current) {
				CheckByte_goto(out, Bug);
				*dst++ = (char)aux;
			}
		}
 Exit:
		*k_new = k;
	}
	*rc = 0;
	return dst;
 Bug:
	*rc = Err_HTTP2_OutOfMemory;
	*k_new = 0;
	return NULL;
}

unsigned char *
huffman_encode_plain(HTTP2Output * __restrict out,
		     unsigned char *__restrict dst,
		     unsigned int *__restrict k_new,
		     unsigned char *__restrict src,
		     uintptr_t n, unsigned int *__restrict rc)
{
	if (n) {
		unsigned int k = *k_new;
		int current = 0;
		uintptr_t aux = 0;

		do {
			const unsigned int s = *src++;
			const unsigned int d = 64 - current;
			const unsigned int c = ht_encode[s];
			const unsigned int l = ht_length[s];

			current += l;
			if (l <= d) {
				aux = Bit_Join(aux, l, c);
			} else {
				current -= 64;
				aux = Bit_Join(aux, d, c >> current);
				if (k >= sizeof(uintptr_t)) {
					aux = Big64(aux);
					*(uintptr_t *) dst = aux;
					dst += sizeof(uintptr_t);
				} else {
					WriteBytes(sizeof(uintptr_t));
				}
				aux = c;
			}
		} while (--n);
		if (current) {
			unsigned int tail = current & 7;

			if (tail) {
				unsigned int d = 8 - tail;

				aux = Bit_Join(aux, d, HT_EOS_HIGH >> tail);
				current += d;
			}
			aux <<= 64 - current;
			aux = Big64(aux);
			if (current == 64) {
				if (k >= sizeof(uintptr_t)) {
					*(uintptr_t *) dst = aux;
					dst += sizeof(uintptr_t);
				} else {
					WriteBytes(sizeof(uintptr_t));
				}
				goto Exit;
			}
			if (current > 31) {
				if (k >= 4) {
					*(uint32_t *) dst = (uint32_t) aux;
					dst += 4;
				} else {
					WriteBytes(4);
				}
				aux >>= 32;
				current -= 32;
			}
			if (current > 15) {
				if (k >= 2) {
					*(uint16_t *) dst = (uint16_t) aux;
					dst += 2;
				} else {
					WriteBytes(2);
				}
				aux >>= 16;
				current -= 16;
			}
			if (current) {
				CheckByte_goto(out, Bug);
				*dst++ = (char)aux;
			}
		}
 Exit:
		*k_new = k;
	}
	*rc = 0;
	return dst;
 Bug:
	*rc = Err_HTTP2_OutOfMemory;
	*k_new = 0;
	return NULL;
}

uintptr_t
huffman_encode_length(const char *__restrict source, uintptr_t n)
{
	if (n) {
		const unsigned char *__restrict src =
		    (const unsigned char *)source;
		uintptr_t current = ht_length[*src++];

		while (--n) {
			current += ht_length[*src++];
		}
		return (current + 7) >> 3;
	} else {
		return 0;
	}
}

/* Same as http2_huffman_encode_check, but stops calculating */
/* length if encoding longer than source:		     */

uintptr_t
huffman_check(const char *__restrict source, uintptr_t n)
{
	if (n) {
		const unsigned char *__restrict src =
		    (const unsigned char *)source;
		uintptr_t current = ht_length[*src++];
		uintptr_t limit = n << 3;

		while (--n && current < limit) {
			current += ht_length[*src++];
		}
		current = (current + 7) >> 3;
		return current <= n ? current : n;
	} else {
		return 0;
	}
}

uintptr_t
huffman_check_fragments(const TfwStr * __restrict source, uintptr_t n)
{
	if (TFW_STR_PLAIN(source)) {
		return huffman_check(source->ptr, n);
	}
	if (n) {
		const TfwStr *__restrict fp = source->ptr;
		const unsigned char *__restrict src = fp->ptr;
		uintptr_t m = fp->len;
		uintptr_t current = 0;
		uintptr_t limit = 0;

		fp++;
		do {
			while (unlikely(m == 0)) {
				src = fp->ptr;
				m = fp->len;
				fp++;
			}
			do {
				current += ht_length[*src++];
				--n;
			} while (--m && current < limit);
		} while (current < limit && n);
		current = (current + 7) >> 3;
		return current <= n ? current : n;
	} else {
		return 0;
	}
}
