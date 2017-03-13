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

#include "common.h"
#include "netconv.h"
#include "errors.h"
#include "buffers.h"
#include "huffman.h"

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
	int8 shift;
	int16 offset;
} HTState;

#include "hfstate.h"

static fast
huffman_decode_tail(ufast c,
		    char *__restrict dst,
		    fast current, const HTState * __restrict state)
{
	ufast i;

	for (;;) {
		fast shift;

		if (unlikely(current == -HT_NBITS)) {
			if (likely(state == ht_decode)) {
				return 0;
			} else {
				return Err_Huffman_CodeTooShort;
			}
		}
		i = (c << -current) & HT_NMASK;
		shift = state[i].shift;
		if (shift >= 0) {
			if (shift > current + HT_NBITS) {
				break;
			}
			*dst++ = (char)state[i].offset;
			current -= shift;
			state = ht_decode;
		} else {
			/*
			 * Last full prefix also processed here, to allow
			 * EOS padding detection. Condition here equivalent to
			 * the "-shift >= current + HT_NBITS", but working faster:
			 */
			if (likely(shift <= -HT_NBITS - current)) {
				break;
			}
			return state[i].offset ==
			    0 ? Err_Huffman_UnexpectedEOS :
			    Err_Huffman_InvalidCode;
		}
	}
	if (state == ht_decode && (i ^ (HT_EOS_HIGH >> 1)) < (1U << -current)) {
		return 0;
	} else {
		return Err_Huffman_CodeTooShort;
	}
}

static fast
huffman_decode_tail_s(ufast c,
		      char *__restrict dst,
		      fast current, const HTState * __restrict state)
{
	int16 offset;
	fast shift;
	ufast i;

	if (unlikely(current == -HT_MBITS)) {
		return Err_Huffman_CodeTooShort;
	}
	i = (c << -current) & HT_MMASK;
	shift = state[i].shift;
	offset = state[i].offset;
	if (likely(shift >= 0)) {
		if (unlikely(shift > current + HT_NBITS)) {
			return Err_Huffman_CodeTooShort;
		}
		*dst++ = (char)offset;
		current -= shift;
		return huffman_decode_tail(c, dst, current, ht_decode);
	} else {
		/*
		 * Condition here equivalent to the "-shift > current + HT_NBITS",
		 * but working faster:
		 */
		if (unlikely(shift < -HT_NBITS - current)) {
			return Err_Huffman_CodeTooShort;
		}
		return offset == 0 ? Err_Huffman_UnexpectedEOS :
		    Err_Huffman_InvalidCode;
	}
}

#define GET_UWIDE(tail) 	       \
do {				       \
	current = Bit_Capacity - tail; \
	c = BigWide(* (uwide *) src);  \
	src += Word_Size;	       \
	n -= Word_Size; 	       \
} while (0)

#define GET_UINT(bits)				       \
do {						       \
	current += bits;			       \
	c = Bit_Join(c, bits,			       \
		     Big##bits(* (uint##bits *) src)); \
	src += bits / 8;			       \
	n -= bits / 8;				       \
} while (0)

#define GET_FIRST_UINT(bits, tail)	     \
do {					     \
	current = bits - tail;		     \
	c = Big##bits(* (uint##bits *) src); \
	src += bits / 8;		     \
	n -= bits / 8;			     \
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

#ifdef Platform_Alignment

#define GET_OCTETS(tail)		     \
	if (current != -tail || 	     \
	    (uwide) src & (Word_Size - 1) || \
	    n < Word_Size)		     \
		GET_OCTETS_BY_8(tail);	     \
	else				     \
		GET_UWIDE(tail)

#define GET_FIRST(tail) 			    \
	if (((uwide) src & (Word_Size - 1)) == 0 && \
	    n >= Word_Size)			    \
		GET_UWIDE(tail);		    \
	else					    \
		GET_FIRST_BY_8(tail)

#else

#define GET_OCTETS(tail)		       \
	if (current != -tail || n < Word_Size) \
		GET_OCTETS_BY_8(tail);	       \
	else				       \
		GET_UWIDE(tail)

#define GET_FIRST(tail) 	     \
	if (n >= Word_Size)	     \
		GET_UWIDE(tail);     \
	else			     \
		GET_FIRST_BY_8(tail)

#endif

fast
huffman_decode(const char *__restrict source, char *__restrict dst, uwide n)
{
	if (n) {
		const uchar *__restrict src = (const uchar *)source;
		uwide c;
		fast current;
		int16 offset;

#ifdef Platform_32bit
		GET_FIRST(HT_NBITS);
#else
		current = Bit_Capacity - HT_NBITS;
		if (((uwide) src & (Word_Size - 1)) == 0) {
			if (n < Word_Size) {
				goto Z0;
			}
			c = BigWide(*(uwide *) src);
			src += Word_Size;
		} else {
			ufast space = 0;

			if (n < Word_Size) {
 Z0:
				space = Bit_Capacity - n * 8;
				n = Word_Size;
				current -= space;
			}
			c = 0;
			if ((uwide) src & 1) {
				c = *src++;
				space += 8;
			}
			if ((uwide) src & 2) {
				if (space <= Bit_Capacity - 16) {
					space += 16;
					c = Bit_Join(c, 16,
						     Big16(*(uint16 *) src));
					src += 2;
 L0:
					if (space <= Bit_Capacity - 32) {
						space += 32;
						c = Bit_Join(c, 32,
							     Big32(*(uint32 *)
								   src));
						src += 4;
					}
					if (space <= Bit_Capacity - 16) {
						space += 16;
						c = Bit_Join(c, 16,
							     Big16(*(uint16 *)
								   src));
						src += 2;
					}
				}
				if (space <= Bit_Capacity - 8) {
					c = Bit_Join8(c, *src++);
				}
			} else if (space) {
				goto L0;
			} else {
				c = BigWide(Bit_Join
					    ((uwide) * (uint32 *) (src + 4), 32,
					     *(uint32 *) src)
				    );
				src += Word_Size;
			}
		}
		n -= Word_Size;
#endif
		for (;;) {
			const HTState *__restrict state;

 Root:
			state = ht_decode;
			for (;;) {
				fast shift;
				ufast i;

				if (current <= 0) {
					if (likely(n)) {
						GET_OCTETS_BY_8(HT_NBITS);
					} else {
						/* Last full prefix also processed here */
						/* (see current <= 0 above): */
						return huffman_decode_tail(c,
									   dst,
									   current,
									   state);
					}
				}
				i = (c >> current) & HT_NMASK;
				shift = state[i].shift;
				offset = state[i].offset;
				if (shift >= 0) {
					*dst++ = (char)offset;
					current -= shift;
					goto Root;
				} else {
					current += shift;
					if (unlikely(offset == 0)) {
						goto End;
					}
					state = ht_decode + offset;
					if (offset >= HT_SMALL) {
						break;
					}
				}
			}
			current += HT_NBITS - HT_MBITS;
			/* With various optimization options, the anonymous block */
			/* here leads to the generation of more efficient code:   */
			{
				fast shift;
				ufast i;

				if (current < 0) {
					if (likely(n)) {
#ifdef Platform_32bit
						GET_OCTETS(HT_MBITS);
#else
						ufast space = 0;

						if (n < Word_Size - 1) {
							space =
							    (Bit_Capacity - 8) -
							    n * 8;
							n = Word_Size - 1;
							current -= space;
						}
						if ((uwide) src & 1) {
							c = Bit_Join8(c,
								      *src++);
							space += 8;
						}
						current += (Word_Size - 1) * 8;
						n -= Word_Size - 1;
						if ((uwide) src & 2) {
							if (space <=
							    (Bit_Capacity - 8) -
							    16) {
								space += 16;
								c = Bit_Join(c,
									     16,
									     Big16
									     (*
									      (uint16
									       *)
									      src));
								src += 2;
 L1:
								if (space <=
								    (Bit_Capacity
								     - 8) -
								    32) {
									space +=
									    32;
									c = Bit_Join(c, 32, Big32(*(uint32 *) src));
									src +=
									    4;
								}
								if (space <=
								    (Bit_Capacity
								     - 8) -
								    16) {
									space +=
									    16;
									c = Bit_Join(c, 16, Big16(*(uint16 *) src));
									src +=
									    2;
								}
							}
							if (space <=
							    (Bit_Capacity - 8) -
							    8) {
								c = Bit_Join8(c,
									      *src++);
							}
						} else {
							goto L1;
						}
#endif
					} else {
						return huffman_decode_tail_s(c,
									     dst,
									     current,
									     state);
					}
				}
				i = (c >> current) & HT_MMASK;
				shift = state[i].shift;
				offset = state[i].offset;
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

static fast
huffman_decode_tail_f(ufast c,
		      HTTP2Output * __restrict destination,
		      fast current,
		      const HTState * __restrict state,
		      uchar * __restrict dst, ufast k)
{
	ufast i;

	for (;;) {
		fast shift;

		if (unlikely(current == -HT_NBITS)) {
			if (likely(state == ht_decode)) {
				return buffer_emit(destination, k);
			} else {
				return Err_Huffman_CodeTooShort;
			}
		}
		i = (c << -current) & HT_NMASK;
		shift = state[i].shift;
		if (shift >= 0) {
			if (shift > current + HT_NBITS) {
				break;
			}
			if (unlikely(k == 0)) {
				dst = buffer_expand(destination, &k);
				if (unlikely(k == 0)) {
					return Err_HTTP2_OutOfMemory;
				}
			}
			*dst++ = (uchar) state[i].offset;
			k--;
			current -= shift;
			state = ht_decode;
		} else {
			/*
			 * Last full prefix also processed here, to allow
			 * EOS padding detection. Condition here equivalent to
			 * the "-shift >= current + HT_NBITS", but working faster:
			 */
			if (likely(shift <= -HT_NBITS - current)) {
				break;
			}
			return state[i].offset ==
			    0 ? Err_Huffman_UnexpectedEOS :
			    Err_Huffman_InvalidCode;
		}
	}
	if (state == ht_decode && (i ^ (HT_EOS_HIGH >> 1)) < (1U << -current)) {
		return buffer_emit(destination, k);
	} else {
		return Err_Huffman_CodeTooShort;
	}
}

static fast
huffman_decode_tail_s_f(ufast c,
			HTTP2Output * __restrict destination,
			fast current,
			const HTState * __restrict state,
			uchar * __restrict dst, ufast k)
{
	int16 offset;
	fast shift;
	ufast i;

	if (unlikely(current == -HT_MBITS)) {
		return Err_Huffman_CodeTooShort;
	}
	i = (c << -current) & HT_MMASK;
	shift = state[i].shift;
	offset = state[i].offset;
	if (likely(shift >= 0)) {
		if (unlikely(shift > current + HT_NBITS)) {
			return Err_Huffman_CodeTooShort;
		}
		if (unlikely(k == 0)) {
			dst = buffer_expand(destination, &k);
			if (unlikely(k == 0)) {
				return Err_HTTP2_OutOfMemory;
			}
		}
		*dst++ = (uchar) offset;
		k--;
		current -= shift;
		return huffman_decode_tail_f(c, destination, current, ht_decode,
					     dst, k);
	} else {
		/*
		 * Condition here equivalent to the "-shift > current + HT_NBITS",
		 * but working faster:
		 */
		if (unlikely(shift < -HT_NBITS - current)) {
			return Err_Huffman_CodeTooShort;
		}
		return offset == 0 ? Err_Huffman_UnexpectedEOS :
		    Err_Huffman_InvalidCode;
	}
}

#define GET_UWIDE_FR(tail)	       \
do {				       \
	current = Bit_Capacity - tail; \
	c = BigWide(* (uwide *) src);  \
	src += Word_Size;	       \
	n -= Word_Size; 	       \
	m -= Word_Size; 	       \
} while (0)

#define GET_UINT_FR(bits)			       \
do {						       \
	current += bits;			       \
	c = Bit_Join(c, bits,			       \
		     Big##bits(* (uint##bits *) src)); \
	src += bits / 8;			       \
	n -= bits / 8;				       \
	m -= bits / 8;				       \
} while (0)

#define GET_FIRST_UINT_FR(bits, tail)	     \
do {					     \
	current = bits - tail;		     \
	c = Big##bits(* (uint##bits *) src); \
	src += bits / 8;		     \
	n -= bits / 8;			     \
	m -= bits / 8;			     \
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

#ifdef Platform_Alignment

#define GET_OCTETS_FR(tail)		     \
	if (current != -tail || 	     \
	    (uwide) src & (Word_Size - 1) || \
	    n < Word_Size || m < Word_Size)  \
		GET_OCTETS_BY_8_FR(tail);    \
	else				     \
		GET_UWIDE_FR(tail)

#define GET_FIRST_FR(tail)			    \
	if (((uwide) src & (Word_Size - 1)) == 0 && \
	    n >= Word_Size && m >= Word_Size)	    \
		GET_UWIDE_FR(tail);		    \
	else					    \
		GET_FIRST_BY_8_FR(tail)

#else

#define GET_OCTETS_FR(tail)		       \
	if (current != -tail || n < Word_Size  \
			     || m < Word_Size) \
		GET_OCTETS_BY_8_FR(tail);      \
	else				       \
		GET_UWIDE_FR(tail)

#define GET_FIRST_FR(tail)		      \
	if (n >= Word_Size && m >= Word_Size) \
		GET_UWIDE_FR(tail);	      \
	else				      \
		GET_FIRST_BY_8_FR(tail)

#endif

fast
huffman_decode_fragments(HTTP2Input * __restrict source,
			 HTTP2Output * __restrict destination, uwide n)
{
	if (n) {
		uwide m;
		const uchar *__restrict src = buffer_get(source, &m);
		uwide c;
		fast current;
		int16 offset;
		ufast k;
		uchar *__restrict dst = buffer_open(destination, &k);

#ifdef Platform_32bit
		GET_FIRST_FR(HT_NBITS);
#else
		ufast space = m;

		if (m > n) {
			space = n;
		}
		current = Bit_Capacity - HT_NBITS;
		if (((uwide) src & (Word_Size - 1)) == 0) {
			if (space < Word_Size) {
				goto Z0;
			}
			c = BigWide(*(uwide *) src);
			src += Word_Size;
		} else {
			if (space >= Word_Size) {
				space = 0;
			} else {
 Z0:
				space = Word_Size - space;
				n += space;
				m += space;
				space <<= 3;
				current -= space;
			}
			c = 0;
			if ((uwide) src & 1) {
				c = *src++;
				space += 8;
			}
			if ((uwide) src & 2) {
				if (space <= Bit_Capacity - 16) {
					space += 16;
					c = Bit_Join(c, 16,
						     Big16(*(uint16 *) src));
					src += 2;
 L0:
					if (space <= Bit_Capacity - 32) {
						space += 32;
						c = Bit_Join(c, 32,
							     Big32(*(uint32 *)
								   src));
						src += 4;
					}
					if (space <= Bit_Capacity - 16) {
						space += 16;
						c = Bit_Join(c, 16,
							     Big16(*(uint16 *)
								   src));
						src += 2;
					}
				}
				if (space <= Bit_Capacity - 8) {
					c = Bit_Join8(c, *src++);
				}
			} else if (space) {
				goto L0;
			} else {
				c = BigWide(Bit_Join
					    ((uwide) * (uint32 *) (src + 4), 32,
					     *(uint32 *) src)
				    );
				src += Word_Size;
			}
		}
		n -= Word_Size;
		m -= Word_Size;
#endif
		for (;;) {
			const HTState *__restrict state;

 Root:
			state = ht_decode;
			for (;;) {
				fast shift;
				ufast i;

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
									     destination,
									     current,
									     state,
									     dst,
									     k);
					}
				}
				i = (c >> current) & HT_NMASK;
				shift = state[i].shift;
				offset = state[i].offset;
				if (shift >= 0) {
					if (unlikely(k == 0)) {
						dst =
						    buffer_expand(destination,
								  &k);
						if (unlikely(k == 0)) {
							return
							    Err_HTTP2_OutOfMemory;
						}
					}
					*dst++ = (uchar) offset;
					k--;
					current -= shift;
					goto Root;
				} else {
					current += shift;
					if (unlikely(offset == 0)) {
						goto End;
					}
					state = ht_decode + offset;
					if (offset >= HT_SMALL) {
						break;
					}
				}
			}
			/* With various optimization options, the anonymous block */
			/* here leads to the generation of more efficient code:   */
			current += HT_NBITS - HT_MBITS;
			{
				fast shift;
				ufast i;

				if (current < 0) {
					if (likely(n)) {
						if (unlikely(m == 0)) {
							src =
							    buffer_next(source,
									&m);
						}
#ifdef Platform_32bit
						GET_OCTETS_FR(HT_MBITS);
#else
						space = m;
						if (m > n) {
							space = n;
						}
						if (space >= Word_Size - 1) {
							space = 0;
						} else {
							space =
							    Word_Size - 1 -
							    space;
							n += space;
							m += space;
							space <<= 3;
							current -= space;
						}
						if ((uwide) src & 1) {
							c = Bit_Join8(c,
								      *src++);
							space += 8;
						}
						current += (Word_Size - 1) * 8;
						n -= Word_Size - 1;
						m -= Word_Size - 1;
						if ((uwide) src & 2) {
							if (space <=
							    (Bit_Capacity - 8) -
							    16) {
								space += 16;
								c = Bit_Join(c,
									     16,
									     Big16
									     (*
									      (uint16
									       *)
									      src));
								src += 2;
 L1:
								if (space <=
								    (Bit_Capacity
								     - 8) -
								    32) {
									space +=
									    32;
									c = Bit_Join(c, 32, Big32(*(uint32 *) src));
									src +=
									    4;
								}
								if (space <=
								    (Bit_Capacity
								     - 8) -
								    16) {
									space +=
									    16;
									c = Bit_Join(c, 16, Big16(*(uint16 *) src));
									src +=
									    2;
								}
							}
							if (space <=
							    (Bit_Capacity - 8) -
							    8) {
								c = Bit_Join8(c,
									      *src++);
							}
						} else {
							goto L1;
						}
#endif
					} else {
						buffer_close(source, m);
						return
						    huffman_decode_tail_s_f(c,
									    destination,
									    current,
									    state,
									    dst,
									    k);
					}
				}
				i = (c >> current) & HT_MMASK;
				shift = state[i].shift;
				offset = state[i].offset;
				if (likely(shift >= 0)) {
					if (unlikely(k == 0)) {
						dst =
						    buffer_expand(destination,
								  &k);
						if (unlikely(k == 0)) {
							return
							    Err_HTTP2_OutOfMemory;
						}
					}
					*dst++ = (uchar) offset;
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
huffman_encode(const char *__restrict source, char *__restrict dst, uwide n)
{
	char *__restrict const dst_saved = dst;

	if (n) {
		const uchar *__restrict src = (const uchar *)source;
		fast current = 0;
		uwide aux = 0;

		do {
			const ufast s = *src++;
			const ufast d = Bit_Capacity - current;
			const ufast c = ht_encode[s];
			const ufast m = ht_length[s];

			current += m;
			if (m <= d) {
				aux = Bit_Join(aux, m, c);
			} else {
				current -= Bit_Capacity;
				aux = Bit_Join(aux, d, c >> current);
#ifndef Platform_Alignment
#ifdef Platform_Little
				aux = SwapBytes(aux);
#endif
				*(uwide *) dst = aux;
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
#ifdef Platform_Alignment
				WriteAux();
#else
				*(uwide *) dst = aux;
#endif
				dst += Word_Size;
				goto Exit;
			}
#endif
			if (current > 31) {
#ifdef Platform_Alignment
				Write4();
#else
				*(uint32 *) dst = (uint32) aux;
#endif
				dst += 4;
#ifdef Platform_32bit
				goto Exit;
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
				*(uint16 *) dst = (uint16) aux;
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
				*dst++ = (char)aux;
#else
				Write1();
				dst++;
#endif
			}
		}
	}
 Exit:
	return dst - dst_saved;
}

uwide
huffman_encode_length(const char *__restrict source, uwide n)
{
	if (n) {
		const uchar *__restrict src = (const uchar *)source;
		uwide current = ht_length[*src++];

		while (--n) {
			current += ht_length[*src++];
		}
		return (current + 7) >> 3;
	} else {
		return 0;
	}
}

/* Same as http2_huffman_encode_check, but stops calculating */
/* length if encoding longer than source: */

uwide
huffman_encode_check(const char *__restrict source, uwide n)
{
	if (n) {
		const uchar *__restrict src = (const uchar *)source;
		uwide current = ht_length[*src++];
		uwide limit = n << 3;

		while (--n && current < limit) {
			current += ht_length[*src++];
		}
		return (current + 7) >> 3;
	} else {
		return 0;
	}
}
