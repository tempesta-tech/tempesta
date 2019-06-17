/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#pragma GCC optimize("O3", "unroll-loops", "inline", "no-strict-aliasing")
#ifdef AVX2
#pragma GCC target("mmx", "sse4.2", "avx2")
#else
#pragma GCC target("mmx", "sse4.2")
#endif
#include <linux/ctype.h>
#include <linux/frame.h>
#include <linux/kernel.h>

#if DBG_HTTP_PARSER == 0
#undef DEBUG
#endif

#include "gfsm.h"
#include "http_msg.h"
#include "htype.h"
#include "http_sess.h"
#include "lib/str.h"

/*
 * ------------------------------------------------------------------------
 *	Common HTTP parsing routines
 * ------------------------------------------------------------------------
 */
/**
 * The following __data_{} macros help to reduce the amount of direct
 * @data/@len manipulations.
 */
#define __data_off(pos)			(size_t)((pos) - data)
#define __data_remain(pos)		(len - __data_off(pos))
#define __data_available(pos, num)	(num <= __data_remain(pos))

/**
 * The following set of macros is for use in generic field processing.
 * @__msg_field_open macro is used for field opening, @__msg_field_fixup
 * is used for updating, and @__msg_field_finish is used when the field
 * is finished. The latter means that the TfwStr{} flag TFW_STR_COMPLETE
 * must be raised. The behavior of macros with @_pos suffixes differ from
 * the ones specified above in the sense that they fixate the field chunk
 * with respect to an explicitly defined pointer (instead of only relative
 * start of the data).n
 */
#define __msg_field_open(field, pos)					\
	tfw_http_msg_set_str_data(msg, field, pos)

#define __msg_field_fixup(field, pos)					\
	tfw_http_msg_add_str_data(msg, field, data, __data_off(pos))

#define __msg_field_finish(field, pos)					\
do {									\
	__msg_field_fixup(field, pos);					\
	(field)->flags |= TFW_STR_COMPLETE;				\
} while (0)

#define __msg_field_fixup_pos(field, data, len)				\
	tfw_http_msg_add_str_data(msg, field, data, len)

#define __msg_field_finish_pos(field, data, len)			\
do {									\
	__msg_field_fixup_pos(field, data, len);			\
	(field)->flags |= TFW_STR_COMPLETE;				\
} while (0)

#define __msg_hdr_chunk_fixup(data, len)				\
	tfw_http_msg_add_str_data(msg, &msg->stream->parser.hdr, data, len)

/**
 * GCC 4.8 (CentOS 7) does a poor work on memory reusage of automatic local
 * variables in nested blocks, so we declare all required temporal variables
 * used in the defines below here to reduce stack frame usage.
 * Since the variables are global now, be careful with them.
 */
#define __FSM_DECLARE_VARS(ptr)						\
	TfwHttpMsg	*msg = (TfwHttpMsg *)(ptr);			\
	TfwHttpParser	*parser = &msg->stream->parser;			\
	unsigned char	*p = data;					\
	unsigned char	c = *p;						\
	int		__maybe_unused __fsm_n;				\
	size_t		__maybe_unused __fsm_sz;			\
	TfwStr		__maybe_unused *chunk = &parser->_tmp_chunk;	\

#define TFW_PARSER_BLOCK(st)						\
do {									\
	T_WARN("Parser error: state=" #st " input=%#x('%.*s')"		\
	       " data_len=%lu off=%lu\n",				\
	       (char)c, min(16U, (unsigned int)(data + len - p)), p,	\
	       len, p - data);						\
	return TFW_BLOCK;						\
} while (0)

#define __FSM_START(s)							\
T_DBG3("enter FSM at state %pK\n", s);					\
if (unlikely(s))							\
	goto *s; /* Fall through to the first state otherwise. */

#define __FSM_START_ALT(s)						\
T_DBG3("enter FSM at state %pK\n", s);					\
if (s == __I_EoL)							\
	goto I_EoL;							\
if (s)									\
	goto *s; /* Fall through to the first state otherwise. */

#define __FSM_STATE(st)							\
barrier();								\
st: __attribute__((unused)) 						\
	c = *p;								\
	T_DBG3("parser at " #st ": c=%#x(%c), p_off=%ld\n",		\
		 c, isprint(c) ? c : '.', p - data);

#define __FSM_EXIT(ret)							\
do {									\
	r = ret;							\
	goto done;							\
} while (0)

#define FSM_EXIT(ret)							\
do {									\
	p += 1; /* eat current character */				\
	__FSM_EXIT(ret);						\
} while (0)

#define __FSM_FINISH(m)							\
done:									\
	/* Remaining number of bytes to process in the data chunk. */	\
	*parsed = __data_off(p);

#define __FSM_MOVE_nofixup_n(to, n)					\
do {									\
	p += n;								\
	if (unlikely(__data_off(p) >= len)) {				\
		parser->state = &&to; /* start from state @to next time */\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
	goto to;							\
} while (0)

#define __FSM_MOVE_nf(to, n, field)					\
do {									\
	p += n;								\
	if (unlikely(__data_off(p) >= len)) {				\
		parser->state = &&to; /* start from state @to next time */\
		/* Close currently parsed field chunk. */		\
		BUG_ON(!(field)->data);					\
		__msg_field_fixup(field, data + len);			\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
	goto to;							\
} while (0)

#define __FSM_MOVE_nofixup(to)		__FSM_MOVE_nofixup_n(to, 1)
#define __FSM_MOVE_n(to, n)						\
	__FSM_MOVE_nf(to, n, &msg->stream->parser.hdr)
#define __FSM_MOVE_f(to, field)		__FSM_MOVE_nf(to, 1, field)
#define __FSM_MOVE(to)							\
	__FSM_MOVE_nf(to, 1, &msg->stream->parser.hdr)
/* The same as __FSM_MOVE_n(), but exactly for jumps w/o data moving. */
#define __FSM_JMP(to)			do { goto to; } while (0)

#define __FSM_MATCH_MOVE_fixup_pos(alphabet, to, field, fixup_pos)	\
do {									\
	__fsm_n = __data_remain(p);					\
	__fsm_sz = tfw_match_##alphabet(p, __fsm_n);			\
	if (unlikely(__fsm_sz == __fsm_n)) {				\
		/* Continue field processing on next skb. */		\
		BUG_ON(!(field)->data);					\
		if (fixup_pos)						\
			__msg_field_fixup_pos(field, p, __fsm_sz);	\
		else							\
			__msg_field_fixup(field, data + len);		\
		parser->state = &&to;					\
		p += __fsm_sz;						\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
} while (0)

#define __FSM_MATCH_MOVE_f(alphabet, to, field)				\
	__FSM_MATCH_MOVE_fixup_pos(alphabet, to, field, false)

#define __FSM_MATCH_MOVE_pos_f(alphabet, to, field)			\
	__FSM_MATCH_MOVE_fixup_pos(alphabet, to, field, true)

#define __FSM_MATCH_MOVE(alphabet, to)					\
	__FSM_MATCH_MOVE_f(alphabet, to, &msg->stream->parser.hdr)

#define __FSM_MATCH_MOVE_nofixup(alphabet, to)				\
do {									\
	__fsm_n = __data_remain(p);					\
	__fsm_sz = tfw_match_##alphabet(p, __fsm_n);			\
	p += __fsm_sz;							\
	if (unlikely(__fsm_sz == __fsm_n)) {				\
		parser->state = &&to;					\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
} while (0)

/*
 * __FSM_I_* macros are intended to help with parsing of message
 * header values. That is done with separate, nested, or interior
 * FSMs, and so _I_ in the name means "interior" FSM.
 */

#define __FSM_I_field_chunk_flags(field, flag)				\
do {									\
	T_DBG3("parser: add chunk flags: %u\n", flag);			\
	TFW_STR_CURR(field)->flags |= flag;				\
} while (0)

#define __FSM_I_chunk_flags(flag)					\
	__FSM_I_field_chunk_flags(&msg->stream->parser.hdr, flag)

#define __FSM_I_MOVE_n(to, n)						\
do {									\
	parser->_i_st = &&to;						\
	p += n;								\
	if (unlikely(__data_off(p) >= len)) {				\
		/* Close currently parsed field chunk. */		\
		__msg_hdr_chunk_fixup(data, len);			\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
	goto to;							\
} while (0)

#define __FSM_I_MOVE(to)		__FSM_I_MOVE_n(to, 1)
/* The same as __FSM_I_MOVE_n(), but exactly for jumps w/o data moving. */
#define __FSM_I_JMP(to)			goto to

#define __FSM_I_MATCH_MOVE_finish(alphabet, to, finish)			\
do {									\
	__fsm_n = __data_remain(p);					\
	__fsm_sz = tfw_match_##alphabet(p, __fsm_n);			\
	if (unlikely(__fsm_sz == __fsm_n)) {				\
		__msg_hdr_chunk_fixup(data, len);			\
		parser->_i_st = &&to;					\
		r = TFW_POSTPONE;					\
		finish;							\
		__FSM_EXIT(r); /* let finish update the @r */		\
	}								\
} while (0)

#define __FSM_I_MATCH_MOVE(alphabet, n)					\
	__FSM_I_MATCH_MOVE_finish(alphabet, n, {})

/*
 * The macros below control chunks within a string:
 * i.e. a caller can explicitly chop an ingress contiguous string
 * into multiple chunks thus generating efficient key/value pairs.
 *
 * Fixup the current chunk that starts at the current data pointer
 * @p and has the size @n. Move forward to just after the chunk.
 * We have at least @n bytes as we parsed them before the fixup.
 */
#define __FSM_I_MOVE_fixup_f(to, n, field, flag)			\
do {									\
	BUG_ON(!(field)->data);						\
	__msg_field_fixup_pos(field, p, n);				\
	__FSM_I_field_chunk_flags(field, flag);				\
	parser->_i_st = &&to;						\
	p += n;								\
	if (unlikely(__data_off(p) >= len))				\
		__FSM_EXIT(TFW_POSTPONE);				\
	goto to;							\
} while (0)

#define __FSM_I_MOVE_fixup(to, n, flag)					\
	__FSM_I_MOVE_fixup_f(to, n, &msg->stream->parser.hdr, flag)

#define __FSM_I_MATCH_MOVE_fixup(alphabet, to, flag)			\
do {									\
	__fsm_n = __data_remain(p);					\
	__fsm_sz = tfw_match_##alphabet(p, __fsm_n);			\
	if (unlikely(__fsm_sz == __fsm_n)) {				\
		__msg_hdr_chunk_fixup(p, __fsm_sz);			\
		__FSM_I_chunk_flags(flag);				\
		parser->_i_st = &&to;					\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
} while (0)

/* Conditional transition from state @st to @st_next. */
#define __FSM_TX_COND(st, condition, st_next, field) 			\
__FSM_STATE(st) {							\
	if (likely(condition))						\
		__FSM_MOVE_f(st_next, field);				\
	TFW_PARSER_BLOCK(st);						\
}

#define __FSM_TX_COND_nofixup(st, condition, st_next) 			\
__FSM_STATE(st) {							\
	if (likely(condition))						\
		__FSM_MOVE_nofixup(st_next);				\
	TFW_PARSER_BLOCK(st);						\
}

/* Automaton transition from state @st to @st_next on character @ch. */
#define __FSM_TX(st, ch, st_next)					\
	__FSM_TX_COND(st, c == (ch), st_next, NULL)
#define __FSM_TX_f(st, ch, st_next, field)				\
	__FSM_TX_COND(st, c == (ch), st_next, field)
#define __FSM_TX_nofixup(st, ch, st_next)				\
	__FSM_TX_COND_nofixup(st, c == (ch), st_next)

/* Case-insensitive version of __FSM_TX(). */
#define __FSM_TX_LC(st, ch, st_next) 					\
	__FSM_TX_COND(st, TFW_LC(c) == (ch), st_next)
#define __FSM_TX_LC_nofixup(st, ch, st_next) 				\
	__FSM_TX_COND_nofixup(st, TFW_LC(c) == (ch), st_next)

/* Automaton transition with alphabet checking and fallback state. */
#define __FSM_TX_AF(st, ch, st_next)					\
__FSM_STATE(st) {							\
	if (likely(TFW_LC(c) == ch))					\
		__FSM_MOVE(st_next);					\
	/* It should be checked in st_fallback if `c` is allowed */	\
	__FSM_JMP(RGen_HdrOther);					\
}

/* As above, but reads OWS through transitional state. */
#define __FSM_TX_AF_OWS(st, st_next)					\
__FSM_STATE(st) {							\
	if (likely(c == ':')) {						\
		parser->_i_st = &&st_next;				\
		__FSM_MOVE(RGen_OWS);					\
	}								\
	/* It should be checked in st_fallback if `c` is allowed */	\
	__FSM_JMP(RGen_HdrOther);					\
}

#define __FSM_METH_MOVE(st, ch, st_next)				\
__FSM_STATE(st) {							\
	if (likely(c == (ch)))						\
		__FSM_MOVE_nofixup(st_next);				\
	__FSM_MOVE_nofixup(Req_MethodUnknown);				\
}

#define __FSM_METH_MOVE_finish(st, ch, m_type)				\
__FSM_STATE(st) {							\
	if (unlikely(c != (ch)))					\
		__FSM_MOVE_nofixup(Req_MethodUnknown);			\
	req->method = (m_type);						\
	__FSM_MOVE_nofixup(Req_MUSpace);				\
}

/* 4-byte (Integer) access to a string Pointer. */
#define PI(p)	(*(unsigned int *)(p))

/**
 * Little endian.
 * These two at the below can be used for characters only.
 */
#define TFW_LC_INT	0x20202020
#define TFW_LC_INT3	0x00202020
#define TFW_LC_LONG	0x2020202020202020UL
#define TFW_LC_LONG7	0x0020202020202020UL
#define TFW_CHAR4_INT(a, b, c, d)					\
	 ((d << 24) | (c << 16) | (b << 8) | a)
#define TFW_CHAR8_INT(a, b, c, d, e, f, g, h)				\
	 (((long)h << 56) | ((long)g << 48) | ((long)f << 40)		\
	  | ((long)e << 32) | (d << 24) | (c << 16) | (b << 8) | a)
#define TFW_P2LCINT(p)	(PI(p) | TFW_LC_INT)
/*
 * Match 4 or 8 characters with conversion to lower case of 3, 4, 7, or
 * 8 first characters and type conversion to int or long type.
 */
#define C4_INT_LCM(p, a, b, c, d)					\
	 !((PI(p) | TFW_LC_INT) ^ TFW_CHAR4_INT(a, b, c, d))
#define C8_INT_LCM(p, a, b, c, d, e, f, g, h)				\
	 !((*(unsigned long *)(p) | TFW_LC_LONG)			\
	   ^ TFW_CHAR8_INT(a, b, c, d, e, f, g, h))
#define C4_INT3_LCM(p, a, b, c, d)					\
	 !((PI(p) | TFW_LC_INT3) ^ TFW_CHAR4_INT(a, b, c, d))
#define C8_INT7_LCM(p, a, b, c, d, e, f, g, h)				\
	 !((*(unsigned long *)(p) | TFW_LC_LONG7)			\
	   ^ TFW_CHAR8_INT(a, b, c, d, e, f, g, h))


#define IN_ALPHABET(c, a)	(a[c >> 6] & (1UL << (c & 0x3f)))

#define CSTR_EQ			0
#define CSTR_POSTPONE		TFW_POSTPONE	/* -1 */
#define CSTR_NEQ		TFW_BLOCK	/* -2 */
#define CSTR_BADLEN		-3
/**
 * Compare a mixed pair of strings with the string @str of length @str_len where
 * the first string is a part of the header @hdr which is being processed and
 * the second string is yet unhandled data of length @len starting from @p. The
 * @chunk->data is used to refer to the start of the first string within the
 * @hdr, while the @chunk->len is used to track gathered length.
 *
 * @str is always in lower case.
 *
 * @return
 * 	CSTR_NEQ:		not equal
 * 	> 0:			(partial) equal
 */
static int
__try_str(TfwStr *hdr, TfwStr* chunk, unsigned char *p, size_t len,
	  const unsigned char *str, size_t str_len)
{
	size_t offset = chunk->len;

	if (unlikely(offset > str_len || TFW_LC(*p) != str[offset]))
		return CSTR_NEQ;

	len = min(len, str_len - offset);
	if (tfw_cstricmp_2lc(p, str + offset, len) ||
	    (chunk->len && !tfw_str_eq_cstr_pos(hdr, chunk->data, str,
						chunk->len, TFW_STR_EQ_CASEI)))
		return CSTR_NEQ;

	chunk->len += len;
	return len;
}

/**
 * Parse probably chunked string representation of an decimal integer.
 * @return number of parsed bytes.
 */
static __always_inline int
__parse_ulong(unsigned char *__restrict data, size_t len,
              const unsigned long *__restrict delimiter_a,
              unsigned long *__restrict acc, unsigned long limit)
{
	unsigned char *p;

	for (p = data; p - data < len; ++p) {
		if (unlikely(IN_ALPHABET(*p, delimiter_a)))
			return p - data;
		if (unlikely(!isdigit(*p)))
			return CSTR_NEQ;
		if (unlikely(*acc > (limit - 10) / 10))
			return CSTR_BADLEN;
		*acc = *acc * 10 + *p - '0';
	}

	/*
	 * We are expecting the compiler to deduce this expression to
	 * a constant, to avoid division at run time.
	 */
	BUILD_BUG_ON(!__builtin_constant_p((limit - 10) / 10));

	return CSTR_POSTPONE;
}

/**
 * Parse an integer followed by a white space.
 */
static __always_inline int
__parse_ulong_ws(unsigned char *__restrict data, size_t len,
                 unsigned long *__restrict acc, unsigned long limit)
{
	/*
	 * Standard white-space characters are:
	 * ' '  (0x20) space (SPC)
	 * '\t' (0x09) horizontal tab (TAB)
	 * '\n' (0x0a) newline (LF)
	 * '\v' (0x0b) vertical tab (VT)
	 * '\f' (0x0c) feed (FF)
	 * '\r' (0x0d) carriage return (CR)
	 */
	static const unsigned long whitespace_a[] ____cacheline_aligned = {
		0x0000000100003e00UL, 0, 0, 0
	};
	return __parse_ulong(data, len, whitespace_a, acc, limit);
}

#define parse_int_a(data, len, a, acc)					\
	__parse_ulong(data, len, a, acc, UINT_MAX)

#define parse_int_ws(data, len, acc)					\
	__parse_ulong_ws(data, len, acc, UINT_MAX)

#define parse_ulong_ws(data, len, acc)					\
	__parse_ulong_ws(data, len, acc, ULONG_MAX)

/**
 * Parse an integer as part of HTTP list.
 */
static inline int
parse_int_list(unsigned char *data, size_t len, unsigned long *acc)
{
	/*
	 * Standard white-space plus comma characters are:
	 * '\t' (0x09) horizontal tab (TAB)
	 * '\n' (0x0a) newline (LF)
	 * '\v' (0x0b) vertical tab (VT)
	 * '\f' (0x0c) feed (FF)
	 * '\r' (0x0d) carriage return (CR)
	 * ' '  (0x20) space (SPC)
	 * ','  (0x2c) comma
	 */
	static const unsigned long ws_comma_a[] ____cacheline_aligned = {
		0x0000100100003e00UL, 0, 0, 0
	};
	return parse_int_a(data, len, ws_comma_a, acc);
}

/**
 * Parse probably chunked string representation of an hexadecimal integer.
 * @return number of parsed bytes.
 */
static int
parse_int_hex(unsigned char *data, size_t len, unsigned long *acc, unsigned short *cnt)
{
	unsigned char *p;

	for (p = data; p - data < len; ++p) {
		if (unlikely(IS_CRLF(*p) || (*p == ';'))) {
			if (unlikely(*acc > LONG_MAX))
				return CSTR_BADLEN;
			return p - data;
		}
		if (unlikely(!isxdigit(*p)))
			return CSTR_NEQ;
		if (unlikely(*cnt >= (sizeof(long) * 2)))
			return CSTR_BADLEN;
		*acc = (*acc << 4) + (*p & 0xf) + (*p >> 6) * 9;
		++*cnt;
	}

	return CSTR_POSTPONE;
}

/**
 * Mark existing spec headers of http message @hm as hop-by-hop if they were
 * listed in Connection header or in @tfw_http_init_parser_* function.
 */
static void
mark_spec_hbh(TfwHttpMsg *hm)
{
	TfwHttpHbhHdrs *hbh_hdrs = &hm->stream->parser.hbh_parser;
	unsigned int id;

	for (id = 0; id < TFW_HTTP_HDR_RAW; ++id) {
		TfwStr *hdr = &hm->h_tbl->tbl[id];
		if ((hbh_hdrs->spec & (0x1 << id)) && (!TFW_STR_EMPTY(hdr)))
			hdr->flags |= TFW_STR_HBH_HDR;
	}
}

/**
 * Mark raw header @hdr as hop-by-hop if its name was listed in Connection
 * header
 */
static void
mark_raw_hbh(TfwHttpMsg *hm, TfwStr *hdr)
{
	TfwHttpHbhHdrs *hbh = &hm->stream->parser.hbh_parser;
	unsigned int i;

	/*
	 * Multiple headers with the same name are saved to the same TfwStr,
	 * so once we bumped into the first of the headers and marked it with
	 * TFW_STR_HBH_HDR flag no need to keep comparing the header name to
	 * every other header in message.
	 *
	 * Unset TFW_STR_HBH_HDR flag for header name to indicate that
	 * corresponding hop-by-hop header was found.
	*/
	for (i = 0; i < hbh->off; ++i) {
		TfwStr *hbh_name = &hbh->raw[i];
		if ((hbh_name->flags & TFW_STR_HBH_HDR)
		    && !(tfw_stricmpspn(&hbh->raw[i], hdr, ':')))
		{
			hdr->flags |= TFW_STR_HBH_HDR;
			hbh_name->flags = hbh_name->flags &
					~(unsigned int)TFW_STR_HBH_HDR;
			break;
		}
	}
}

/**
 * Lookup for the header @hdr in already collected headers table @ht,
 * and mark it as hop-by-hop. The lookup is performed until ':', so header
 * name only is enough in @hdr.
 *
 * @return true if @hdr was found and marked as hop-by-hop
 */
static bool
__mark_hbh_hdr(TfwHttpMsg *hm, TfwStr *hdr)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	unsigned int hid = tfw_http_msg_hdr_lookup(hm, hdr);

	/*
	 * This function is called before hm->h_tbl is fully parsed,
	 * if header is empty, don't touch it
	 */
	if ((hid >= ht->off) || (TFW_STR_EMPTY(&ht->tbl[hid])))
		return false;

	ht->tbl[hid].flags |= TFW_STR_HBH_HDR;
	return true;
}

/**
 * Add header name listed in Connection header to table of raw headers.
 * If @last is true then (@data, @len) represents last chunk of header name and
 * chunk with ':' will be added to the end. Otherwize last header in table stays
 * open to add more data.
 *
 * After name of hop-by-hop header was completed, will search for headers
 * with that name and mark them as hop-by-hop.
 *
 * NOTE: Most of the headers listed in RFC 7231 are end-to-end and must not
 * be listed in the header. Instead of comparing connection tokens to all
 * end-to-end headers names compare only to headers parsed by
 * TFW_HTTP_PARSE_RAWHDR_VAL macro.
 */
static int
__hbh_parser_add_data(TfwHttpMsg *hm, char *data, unsigned long len, bool last)
{
	TfwStr *hdr, *append;
	TfwHttpHbhHdrs *hbh = &hm->stream->parser.hbh_parser;
	static const TfwStr block[] = {
		/* End-to-end spec and raw headers */
		TFW_STR_STRING("age:"),
		TFW_STR_STRING("authorization:"),
		TFW_STR_STRING("cache-control:"),
		TFW_STR_STRING("connection:"),
		TFW_STR_STRING("content-length:"),
		TFW_STR_STRING("content-type:"),
		TFW_STR_STRING("cookie:"),
		TFW_STR_STRING("date:"),
		TFW_STR_STRING("etag:"),
		TFW_STR_STRING("expires:"),
		TFW_STR_STRING("host:"),
		TFW_STR_STRING("pragma:"),
		TFW_STR_STRING("server:"),
		TFW_STR_STRING("transfer-encoding:"),
		TFW_STR_STRING("user-agent:"),
		TFW_STR_STRING("x-forwarded-for:"),
	};

	if (hbh->off == TFW_HBH_TOKENS_MAX)
		return CSTR_NEQ;
	hdr = &hbh->raw[hbh->off];

	if (!TFW_STR_EMPTY(hdr)) {
		append = tfw_str_add_compound(hm->pool, hdr);
	}
	else {
		append = (TfwStr *)tfw_pool_alloc(hm->pool, sizeof(TfwStr));
		hdr->chunks = append;
		hdr->nchunks = 1;
	}
	if (!append)
		return -ENOMEM;
	append->len = len;
	append->data = data;
	hdr->len += len;

	if (last) {
		TfwStr s_colon = { .data = ":", .len = 1 };
		append = tfw_str_add_compound(hm->pool, hdr);
		if (!append)
			return -ENOMEM;
		*append = s_colon;
		hdr->len += s_colon.len;
		++hbh->off;

		if (tfw_http_msg_find_hdr(hdr, block))
			return CSTR_NEQ;
		/*
		 * Don't set TFW_STR_HBH_HDR flag if such header was already
		 * parsed. See comment in mark_raw_hbh()
		 */
		if (!__mark_hbh_hdr(hm, hdr))
			hdr->flags |= TFW_STR_HBH_HDR;
	};

	return 0;
}

/*
 * Helping state identifiers used to define which jump address an FSM should
 * set as the entry point.
 * Don't introduce too much of such identifies!
 */
#define __I_EoL			(void *)1

/* Initialize TRY_STR parsing context */
#define TRY_STR_INIT()		TFW_STR_INIT(chunk)

/**
 * Parsing helpers.
 * @str in TRY_STR_LAMBDA must be in lower case.
 */
#define TRY_STR_LAMBDA_finish(str, lambda, finish, state)		\
	if (!chunk->data)						\
		chunk->data = p;					\
	__fsm_n = __try_str(&parser->hdr, chunk, p, __data_remain(p),	\
			    str, sizeof(str) - 1);			\
	if (__fsm_n > 0) {						\
		if (chunk->len == sizeof(str) - 1) {			\
			lambda;						\
			TRY_STR_INIT();					\
			__FSM_I_MOVE_n(state, __fsm_n);			\
		}							\
		__msg_hdr_chunk_fixup(data, len);			\
		finish;							\
		return CSTR_POSTPONE;					\
	}

/*
 * Store current state if we're going to exit in waiting for new data
 * (POSTPONE). We store current parser state only when we return from the
 * parser FSM - it's better that to store the state on each transition.
 */
#define TRY_STR_LAMBDA(str, lambda, curr_st, next_st)			\
	TRY_STR_LAMBDA_finish(str, lambda, {				\
			parser->_i_st = &&curr_st;			\
		}, next_st)

#define TRY_STR(str, curr_st, next_st)					\
	TRY_STR_LAMBDA_finish(str, { }, {				\
			parser->_i_st = &&curr_st;			\
		}, next_st)

/**
 * The same as @TRY_STR_LAMBDA_finish(), but @str must be of plain
 * @TfwStr{} type and variable @field is used (instead of hard coded
 * header field); besides, @finish parameter is not used in this macro.
 */
#define TRY_STR_LAMBDA_fixup(str, field, lambda, curr_st, next_st)	\
	BUG_ON(!TFW_STR_PLAIN(str));					\
	if (!chunk->data)						\
		chunk->data = p;					\
	__fsm_n = __try_str(field, chunk, p, __data_remain(p),		\
			    (str)->data, (str)->len);			\
	if (__fsm_n > 0) {						\
		if (chunk->len == (str)->len) {				\
			lambda;						\
			TRY_STR_INIT();					\
			__FSM_I_MOVE_fixup_f(next_st, __fsm_n, field, 0);\
		}							\
		__msg_field_fixup_pos(field, p, __fsm_n);		\
		parser->_i_st = &&curr_st;				\
		return CSTR_POSTPONE;					\
	}

/*
 * Headers EOL processing. Allow only LF and CRLF as a newline delimiters.
 *
 * Note also, that according to RFC 7230, HTTP-headers may appear in two
 * cases. The first one is header section (3.2) and the second one is
 * chunked-body trailer-part (4.1).
 */
#define RGEN_EOL()							\
__FSM_STATE(RGen_EoL) {							\
	if (c == '\r')							\
		__FSM_MOVE_nofixup(RGen_CR);				\
	if (c == '\n') {						\
		if (parser->hdr.data) {					\
			tfw_str_set_eolen(&parser->hdr, 1);		\
			if (tfw_http_msg_hdr_close(msg, parser->_hdr_tag)) \
				TFW_PARSER_BLOCK(RGen_EoL);		\
		}							\
		__FSM_MOVE_nofixup(RGen_Hdr);				\
	}								\
	TFW_PARSER_BLOCK(RGen_EoL);					\
}									\
__FSM_STATE(RGen_CR) {							\
	if (unlikely(c != '\n'))					\
		TFW_PARSER_BLOCK(RGen_CR);				\
	if (parser->hdr.data) {						\
		tfw_str_set_eolen(&parser->hdr, 2);			\
		if (tfw_http_msg_hdr_close(msg, parser->_hdr_tag))	\
			TFW_PARSER_BLOCK(RGen_CR);			\
	}								\
	/* Process next header if any. */				\
	__FSM_MOVE_nofixup(RGen_Hdr);					\
}

/*
 * Process the final CRLF, i.e. the end of the headers part or the whole
 * HTTP message. We may get here after trailing-part headers. In that
 * case @msg->crlf is already set and there is nothing to do.
 */
#define TFW_HTTP_PARSE_CRLF()						\
do {									\
	if (unlikely(c == '\r')) {					\
		if (msg->crlf.flags & TFW_STR_COMPLETE)			\
			__FSM_MOVE_nofixup(RGen_CRLFCR);		\
		if (!msg->crlf.data)					\
			/* The end of the headers part. */		\
			tfw_http_msg_set_str_data(msg, &msg->crlf, p);	\
		__FSM_MOVE_f(RGen_CRLFCR, &msg->crlf);			\
	}								\
	if (c == '\n') {						\
		if (!msg->crlf.data) {					\
			/*						\
			 * Set data and length explicitly for a single	\
			 * LF w/o calling complex __msg_field_fixup().	\
			 */						\
			tfw_http_msg_set_str_data(msg, &msg->crlf, p);	\
			msg->crlf.len = 1;				\
			msg->crlf.flags |= TFW_STR_COMPLETE;		\
			__FSM_JMP(RGen_BodyInit);			\
		}							\
		parser->state = &&RGen_Hdr;				\
		FSM_EXIT(TFW_PASS);					\
	}								\
} while (0)

/*
 * State processing a character just after CRLFCR, i.e. the final LF.
 */
#define RGEN_CRLF()							\
__FSM_STATE(RGen_CRLFCR) {						\
	if (unlikely(c != '\n'))					\
		TFW_PARSER_BLOCK(RGen_CRLFCR);				\
	mark_spec_hbh(msg);						\
	if (!(msg->crlf.flags & TFW_STR_COMPLETE)) {			\
		BUG_ON(!msg->crlf.data);				\
		__msg_field_finish(&msg->crlf, p + 1);			\
		__FSM_JMP(RGen_BodyInit);				\
	}								\
	parser->state = &&RGen_CRLFCR;					\
	FSM_EXIT(TFW_PASS);						\
}

/*
 * We have HTTP message descriptors and special headers,
 * however we still need to store full headers (instead of just their values)
 * as well as store headers which aren't need in further processing
 * (e.g. Content-Length which is doubled by TfwHttpMsg.content_length)
 * to mangle row skb data.
 */
#define __TFW_HTTP_PARSE_SPECHDR_VAL(st_curr, hm, func, id, saveval)	\
__FSM_STATE(st_curr) {							\
	BUG_ON(__data_off(p) > len);					\
	__fsm_sz = __data_remain(p);					\
	if (!parser->_i_st)						\
		TRY_STR_INIT();						\
	/*								\
	 * Check whether the header slot is acquired to catch		\
	 * duplicate headers in sense of RFC 7230 3.2.2.		\
	 */								\
	if (id < TFW_HTTP_HDR_NONSINGULAR				\
	    && unlikely(!TFW_STR_EMPTY(&(msg)->h_tbl->tbl[id])))	\
		TFW_PARSER_BLOCK(st_curr);				\
	/* Store header name and field in different chunks. */		\
	__msg_hdr_chunk_fixup(data, p - data);				\
	__fsm_n = func(hm, p, __fsm_sz);				\
	T_DBG3("parse special header " #func ": ret=%d data_len=%lu"	\
	       " id=%d\n", __fsm_n, __fsm_sz, id);			\
	switch (__fsm_n) {						\
	case CSTR_POSTPONE:						\
		/* The automaton state keeping is handled in @func. */	\
		p += __fsm_sz;						\
		parser->state = &&st_curr;				\
		__FSM_EXIT(TFW_POSTPONE);				\
	case CSTR_BADLEN: /* bad header length */			\
	case CSTR_NEQ: /* bad header value */				\
		TFW_PARSER_BLOCK(st_curr);				\
	default:							\
		BUG_ON(__fsm_n < 0);					\
		/* The header value is fully parsed, move forward. */	\
		if (saveval)						\
			__msg_hdr_chunk_fixup(p, __fsm_n);		\
		parser->_i_st = &&RGen_EoL;				\
		parser->_hdr_tag = id;					\
		__FSM_MOVE_n(RGen_OWS, __fsm_n); /* skip OWS */		\
	}								\
}

#define TFW_HTTP_PARSE_SPECHDR_VAL(st_curr, hm, func, id)		\
	__TFW_HTTP_PARSE_SPECHDR_VAL(st_curr, hm, func, id, 1)

#define __TFW_HTTP_PARSE_RAWHDR_VAL(st_curr, hm, func, saveval)		\
__FSM_STATE(st_curr) {							\
	BUG_ON(__data_off(p) > len);					\
	__fsm_sz = __data_remain(p);					\
	if (!parser->_i_st)						\
		TRY_STR_INIT();						\
	/* In 'func' the  pointer at the beginning of this piece of the request
	 * is not available to us. If the request ends in 'func', we can not
	 * correctly create a new chunk, which includes part of the request
	 * before the header-value, and we lose this part. It should be forced
	 * to save it.*/						\
	__msg_hdr_chunk_fixup(data, p - data);				\
	__fsm_n = func(hm, p, __fsm_sz);				\
	T_DBG3("parse raw header " #func ": ret=%d data_len=%lu\n",	\
	       __fsm_n, __fsm_sz);					\
	switch (__fsm_n) {						\
	case CSTR_POSTPONE:						\
		/* The automaton state keeping is handled in @func. */	\
		p += __fsm_sz;						\
		parser->state = &&st_curr;				\
		__FSM_EXIT(TFW_POSTPONE);				\
	case CSTR_BADLEN: /* bad header length */			\
	case CSTR_NEQ: /* bad header value */				\
		TFW_PARSER_BLOCK(st_curr);				\
	default:							\
		BUG_ON(__fsm_n < 0);					\
		/* The header value is fully parsed, move forward. */	\
		if (saveval)						\
			__msg_hdr_chunk_fixup(p, __fsm_n);		\
		mark_raw_hbh(msg, &parser->hdr);			\
		parser->_i_st = &&RGen_EoL;				\
		parser->_hdr_tag = TFW_HTTP_HDR_RAW;			\
		__FSM_MOVE_n(RGen_OWS, __fsm_n); /* skip OWS */		\
	}								\
}

#define TFW_HTTP_PARSE_RAWHDR_VAL(st_curr, hm, func)			\
	__TFW_HTTP_PARSE_RAWHDR_VAL(st_curr, hm, func, 1)

/*
 * Parse raw (common) HTTP headers.
 * Note that some of these can be extremely large.
 *
 * TODO Split the headers to header name and header field as special headers.
 */
#define RGEN_HDR_OTHER()						\
__FSM_STATE(RGen_HdrOther) {						\
	parser->_hdr_tag = TFW_HTTP_HDR_RAW;				\
	/* Fall through. */						\
}									\
__FSM_STATE(RGen_HdrOtherN) {						\
	__FSM_MATCH_MOVE(token, RGen_HdrOtherN);			\
	if (likely(*(p + __fsm_sz) == ':')) {				\
		parser->_i_st = &&RGen_HdrOtherV;			\
		__FSM_MOVE_n(RGen_OWS, __fsm_sz + 1);			\
	}								\
	TFW_PARSER_BLOCK(RGen_HdrOtherN);				\
}									\
__FSM_STATE(RGen_HdrOtherV) {						\
	/*								\
	 * The header content is opaque for us,				\
	 * so pass ctext and VCHAR.					\
	 */								\
	__FSM_MATCH_MOVE(ctext_vchar, RGen_HdrOtherV);			\
	if (!IS_CRLF(*(p + __fsm_sz)))					\
		TFW_PARSER_BLOCK(RGen_HdrOtherV);			\
	__msg_hdr_chunk_fixup(data, __data_off(p + __fsm_sz)); 		\
	mark_raw_hbh(msg, &parser->hdr);				\
	__FSM_MOVE_n(RGen_EoL, __fsm_sz);				\
}

/* Process according RFC 7230 3.3.3 */
#define TFW_HTTP_INIT_REQ_BODY_PARSING()				\
__FSM_STATE(RGen_BodyInit) {						\
	TfwStr *tbl = msg->h_tbl->tbl;					\
									\
	T_DBG3("parse request body: flags=%#lx content_length=%lu\n",	\
	       msg->flags[0], msg->content_length);			\
									\
	if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_TRANSFER_ENCODING])) {	\
		/*							\
		 * According to RFC 7230 3.3.3 p.3, more strict		\
		 * scenario has been implemented to exclude		\
		 * attempts of HTTP Request Smuggling or HTTP		\
		 * Response Splitting.					\
		 */							\
		if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_LENGTH]))	\
			TFW_PARSER_BLOCK(RGen_BodyInit);		\
		if (test_bit(TFW_HTTP_B_CHUNKED, msg->flags))		\
			__FSM_MOVE_nofixup(RGen_BodyStart);		\
		/*							\
		 * If "Transfer-Encoding:" header is present and	\
		 * there's NO "chunked" coding, then send 400 response	\
		 * (Bad Request) and close the connection.		\
		 */							\
		TFW_PARSER_BLOCK(RGen_BodyInit);			\
	}								\
	if (msg->content_length) {					\
		parser->to_read = msg->content_length;			\
		__FSM_MOVE_nofixup(RGen_BodyStart);			\
	}								\
	/* There is no body. */						\
	msg->body.flags |= TFW_STR_COMPLETE;				\
	parser->state = &&RGen_BodyInit;				\
	FSM_EXIT(TFW_PASS);						\
}

/* Process according RFC 7230 3.3.3 */
#define TFW_HTTP_INIT_RESP_BODY_PARSING()				\
__FSM_STATE(RGen_BodyInit) {						\
	TfwStr *tbl = msg->h_tbl->tbl;					\
									\
	T_DBG3("parse response body: flags=%#lx content_length=%lu\n",	\
	       msg->flags[0], msg->content_length);			\
									\
	/* There's no body. */						\
	if (test_bit(TFW_HTTP_B_VOID_BODY, msg->flags)) 		\
		goto no_body;			\
	if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_TRANSFER_ENCODING])) {	\
		/*							\
		 * According to RFC 7230 3.3.3 p.3, more strict		\
		 * scenario has been implemented to exclude		\
		 * attempts of HTTP Request Smuggling or HTTP		\
		 * Response Splitting.					\
		 */							\
		if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_LENGTH]))	\
			TFW_PARSER_BLOCK(RGen_BodyInit);		\
		if (test_bit(TFW_HTTP_B_CHUNKED, msg->flags))		\
			__FSM_MOVE_nofixup(RGen_BodyStart);		\
		__FSM_MOVE_nofixup(Resp_BodyUnlimStart);		\
	}								\
	if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_LENGTH])) {	\
		if (msg->content_length) {				\
			parser->to_read = msg->content_length;		\
			__FSM_MOVE_nofixup(RGen_BodyStart);		\
		}							\
		goto no_body;						\
	}								\
	/* Process the body until the connection is closed. */		\
	/*								\
	 * TODO: Currently Tempesta fully assembles response before	\
	 * transmitting it to a client. This behaviour is considered	\
	 * dangerous and the issue must be solved in generic way:	\
	 * Tempesta must use chunked transfer encoding for proxied	\
	 * responses w/o lengths. Refer issues #534 and #498 for more	\
	 * information.							\
	 */								\
	__set_bit(TFW_HTTP_B_UNLIMITED, msg->flags);			\
	__FSM_MOVE_nofixup(Resp_BodyUnlimStart);			\
no_body:								\
	msg->body.flags |= TFW_STR_COMPLETE;				\
	parser->state = &&RGen_BodyInit;				\
	FSM_EXIT(TFW_PASS);						\
}

#define TFW_HTTP_PARSE_BODY_UNLIM()					\
__FSM_STATE(Resp_BodyUnlimStart) {					\
	tfw_http_msg_set_str_data(msg, &msg->body, p);			\
	/* fall through */						\
}									\
__FSM_STATE(Resp_BodyUnlimRead) {					\
	__FSM_MOVE_nf(Resp_BodyUnlimRead, __data_remain(p), &msg->body); \
}

#define TFW_HTTP_PARSE_BODY()						\
/* Read request|response body. */					\
__FSM_STATE(RGen_BodyStart) {						\
	tfw_http_msg_set_str_data(msg, &msg->body, p);			\
	/* Fall through. */						\
}									\
__FSM_STATE(RGen_BodyChunk) {						\
	T_DBG3("read body: to_read=%ld\n", parser->to_read);		\
	if (parser->to_read == -1) {					\
		/* Prevent @parse_int_hex false positives. */		\
		if (!isxdigit(c))					\
			TFW_PARSER_BLOCK(RGen_BodyChunk);		\
		__FSM_JMP(RGen_BodyChunkLen);				\
	}								\
	/* Fall through. */						\
}									\
__FSM_STATE(RGen_BodyReadChunk) {					\
	BUG_ON(parser->to_read < 0);					\
	__fsm_sz = min_t(long, parser->to_read, __data_remain(p));	\
	parser->to_read -= __fsm_sz;					\
	if (parser->to_read)						\
		__FSM_MOVE_nf(RGen_BodyReadChunk, __fsm_sz, &msg->body); \
	if (test_bit(TFW_HTTP_B_CHUNKED, msg->flags)) {			\
		parser->to_read = -1;					\
		__FSM_MOVE_nf(RGen_BodyEoL, __fsm_sz, &msg->body);	\
	}								\
	/* We've fully read Content-Length bytes. */			\
	if (tfw_http_msg_add_str_data(msg, &msg->body, p, __fsm_sz))	\
		TFW_PARSER_BLOCK(RGen_BodyReadChunk);			\
	msg->body.flags |= TFW_STR_COMPLETE;				\
	p += __fsm_sz;							\
	parser->state = &&RGen_BodyReadChunk;				\
	__FSM_EXIT(TFW_PASS);						\
}									\
__FSM_STATE(RGen_BodyChunkLen) {					\
	__fsm_sz = __data_remain(p);					\
	/* Read next chunk length. */					\
	__fsm_n = parse_int_hex(p, __fsm_sz, &parser->_acc, &parser->_cnt); \
	T_DBG3("data chunk: remain_len=%zu ret=%d to_read=%lu\n",	\
	       __fsm_sz, __fsm_n, parser->_acc);			\
	switch (__fsm_n) {						\
	case CSTR_POSTPONE:						\
		__FSM_MOVE_nf(RGen_BodyChunkLen, __fsm_sz, &msg->body);	\
	case CSTR_BADLEN:						\
	case CSTR_NEQ:							\
		TFW_PARSER_BLOCK(RGen_BodyChunkLen);			\
	default:							\
		parser->to_read = parser->_acc;				\
		parser->_acc = 0;					\
		parser->_cnt = 0;					\
		__FSM_MOVE_nf(RGen_BodyChunkExt, __fsm_n, &msg->body);	\
	}								\
}									\
__FSM_STATE(RGen_BodyChunkExt) {					\
	if (unlikely(c == ';' || c == '=' || IS_TOKEN(c)))		\
		__FSM_MOVE_f(RGen_BodyChunkExt, &msg->body);		\
	/* Fall through. */						\
}									\
__FSM_STATE(RGen_BodyEoL) {						\
	if (likely(c == '\r'))						\
		__FSM_MOVE_f(RGen_BodyCR, &msg->body);			\
	/* Fall through. */						\
}									\
__FSM_STATE(RGen_BodyCR) {						\
	if (unlikely(c != '\n'))					\
		TFW_PARSER_BLOCK(RGen_BodyCR);				\
	if (parser->to_read)						\
		__FSM_MOVE_f(RGen_BodyChunk, &msg->body);		\
	/*								\
	 * We've fully read the chunked body.				\
	 * Add everything and the current character.			\
	 */								\
	if (tfw_http_msg_add_str_data(msg, &msg->body, data,		\
				      __data_off(p) + 1))		\
		TFW_PARSER_BLOCK(RGen_BodyCR);				\
	msg->body.flags |= TFW_STR_COMPLETE;				\
	/* Process the trailer-part. */					\
	__FSM_MOVE_nofixup(RGen_Hdr);					\
}

/*
 * Read OWS at arbitrary position and move to stashed state.
 * This is bit complicated (however you can think about this as
 * a plain pushdown automaton), but reduces FSM code size.
 */
#define RGEN_OWS()							\
__FSM_STATE(RGen_OWS) {							\
	if (likely(IS_WS(c)))						\
		__FSM_MOVE(RGen_OWS);					\
	parser->state = parser->_i_st;					\
	parser->_i_st = NULL;						\
	BUG_ON(unlikely(__data_off(p) >= len));				\
	goto *parser->state;						\
}

/**
 * Parse Connection header value, RFC 7230 6.1.
 *
 * Store names of listed headers in @hm->parser.hbh_parser to mark them as
 * hop-by-hop during parsing. Mark already parsed headers as hop-by-hop once
 * they appear in the header.
 *
 * @return CSTR_NEQ if the header contains end-to-end headers or too lot of
 * connection specific options/headers.
 */
static int
__parse_connection(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	BUILD_BUG_ON(sizeof(parser->hbh_parser.spec) * 8 < TFW_HTTP_HDR_RAW);

	__FSM_START(parser->_i_st);

/*
 * Save parsed data to list of raw hop-by-hop headers if data doesn't match
 * to @name and do @lambda otherwize
*/
#define TRY_CONN_TOKEN(name, lambda)					\
	TRY_STR_LAMBDA_finish(name, lambda, {				\
			if (__hbh_parser_add_data(hm, data, len, false))\
				r = CSTR_NEQ;				\
			else						\
				parser->_i_st = &&I_Conn;		\
		}, I_ConnTok)

	/*
	 * Connection header lists either boolean connection tokens or
	 * names of hop-by-hop headers.
	 *
	 * Sender must not list end-to-end headers in Connection header.
	 * In this function we check only spec headers that can be hop-by-hop.
	 * Other headers listed in the header will be compared with names of
	 * end-to-end headers during saving in __hbh_parser_add_data().
	 *
	 * TODO: RFC 6455 WebSocket Protocol
	 * During handshake client sets "Connection: update" and "Update" header.
	 * This headers should be passed to server unchanged to allow
	 * WebSocket protocol.
	 */
	__FSM_STATE(I_Conn) {
		WARN_ON_ONCE(parser->_acc);
		/* Boolean connection tokens */
		TRY_CONN_TOKEN("close", {
			__set_bit(TFW_HTTP_B_CONN_CLOSE, &parser->_acc);
		});
		/* Spec headers */
		TRY_CONN_TOKEN("keep-alive", {
			__set_bit(TFW_HTTP_B_CONN_KA, &parser->_acc);
		});
		TRY_STR_INIT();
		__FSM_I_JMP(I_ConnOther);
	}
#undef TRY_CONN_TOKEN

	__FSM_STATE(I_ConnTok) {
		WARN_ON_ONCE(!parser->_acc);

		if (!IS_WS(c) && c != ',' && !IS_CRLF(c))
			__FSM_I_JMP(I_ConnOther);

		if (test_bit(TFW_HTTP_B_CONN_KA, &parser->_acc)) {
			unsigned int hid = TFW_HTTP_HDR_KEEP_ALIVE;

			if (test_bit(TFW_HTTP_B_CONN_CLOSE, msg->flags))
				return CSTR_NEQ;
			__set_bit(TFW_HTTP_B_CONN_KA, msg->flags);

			parser->hbh_parser.spec |= 0x1 << hid;
			if (!TFW_STR_EMPTY(&msg->h_tbl->tbl[hid]))
				msg->h_tbl->tbl[hid].flags |= TFW_STR_HBH_HDR;
		}
		else if (test_bit(TFW_HTTP_B_CONN_CLOSE, &parser->_acc)) {
			if (test_bit(TFW_HTTP_B_CONN_KA, msg->flags))
				return CSTR_NEQ;
			__set_bit(TFW_HTTP_B_CONN_CLOSE, msg->flags);
		}

		__FSM_I_JMP(I_EoT);
	}

	/*
	 * Other connection tokens. Popular examples of the "Connection:"
	 * header value are "Keep-Alive, TE" or "TE, close". However,
	 * it could be names of any headers, including custom headers.
	 * Raw headers: add to @hm->parser.hbh_parser.raw table.
	 */
	__FSM_STATE(I_ConnOther) {
		__FSM_I_MATCH_MOVE_finish(token, I_ConnOther, {
			if (__hbh_parser_add_data(hm, p, __fsm_sz, false))
				r = CSTR_NEQ;
		});
		__set_bit(TFW_HTTP_B_CONN_EXTRA, msg->flags);
		c = *(p + __fsm_sz);
		if (__hbh_parser_add_data(hm, p, __fsm_sz, true))
			return  CSTR_NEQ;
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c)) {
			parser->_acc = 0;
			return __data_off(p + __fsm_sz);
		}
		return CSTR_NEQ;
	}

	/* End of token */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(I_EoT);

		parser->_acc = 0; /* reinit for next token */

		if (IS_TOKEN(c))
			__FSM_I_JMP(I_Conn);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	T_DBG3("parser: Connection parsed: flags %#lx\n", msg->flags[0]);

	return r;
}
STACK_FRAME_NON_STANDARD(__parse_connection);

/**
 * Parse Content-Length header value, RFC 7230 section 3.3.2.
 */
static int
__parse_content_length(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	int r;

	/*
	 * A server MUST NOT send a Content-Length header field in any response
	 * with a status code of 1xx (Informational) or 204 (No Content).
	 * TODO: server MUST NOT send a Content-Length header field in any 2xx
	 * (Successful) response to a CONNECT request
	 */
	if (TFW_CONN_TYPE(msg->conn) & Conn_Srv) {
		TfwHttpResp *resp = (TfwHttpResp *)msg;
		if (resp->status - 100U < 100U || resp->status == 204)
			return CSTR_NEQ;
	}
	/*
	 * According to RFC 7230 3.3.2, in cases of multiple Content-Length
	 * header fields with field-values consisting of the same decimal
	 * value, or a single Content-Length header field with a field
	 * value containing a list of identical decimal values, more strict
	 * implementation is chosen: message will be rejected as invalid,
	 * to exclude attempts of HTTP Request Smuggling or HTTP Response
	 * Splitting.
	 */
	r = parse_ulong_ws(data, len, &msg->content_length);
	if (r == CSTR_POSTPONE)
		__msg_hdr_chunk_fixup(data, len);

	T_DBG3("%s: content_length=%lu\n", __func__, msg->content_length);

	return r;
}

/**
 * Parse Content-Type header value, RFC 7231 3.1.1.5.
 */
static int
__resp_parse_content_type(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_ContType) {
		/*
		 * Just eat the header value: we're interested in
		 * type "/" subtype only and they're at begin of the value.
		 *
		 * RFC 7231 3.1.1.1 defines Media Type as
		 *
		 *	token "/" token *(OWS ";" OWS parameter)
		 *	parameter = token "=" (token / quoted-string)
		 *
		 * RFC 7230 defines
		 *
		 * 	quoted-string = DQUOTE *(qdtext / quoted-pair) DQUOTE
		 * 	qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / %x80-FF
		 * 	quoted-pair = "\" (HTAB / SP / VCHAR / %x80-FF)
		 *
		 * , so this is essentially ctext | VCHAR.
		 */
		__FSM_I_MATCH_MOVE(ctext_vchar, I_ContType);
		if (IS_CRLF(*(p + __fsm_sz)))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

done:
	return r;
}

static int
__strdup_multipart_boundaries(TfwHttpReq *req)
{
	unsigned char *data_raw, *data, *ptr_raw, *ptr;
	TfwStr *c, *end;

	data_raw = tfw_pool_alloc(req->pool, req->multipart_boundary_raw.len);
	data = tfw_pool_alloc(req->pool, req->multipart_boundary.len);

	if (!data_raw || !data)
		return -ENOMEM;

	ptr_raw = data_raw;
	ptr = data;
	TFW_STR_FOR_EACH_CHUNK(c, &req->multipart_boundary_raw, end) {
		memcpy_fast(ptr_raw, c->data, c->len);
		ptr_raw += c->len;
		if (c->flags & TFW_STR_VALUE) {
			memcpy_fast(ptr, c->data, c->len);
			ptr += c->len;
		}
	}

	if (ptr_raw != data_raw + req->multipart_boundary_raw.len ||
	    ptr != data + req->multipart_boundary.len)
	{
		T_WARN("Multipart boundary string length mismatch");
		return -1;
	}

	req->multipart_boundary_raw.data = data_raw;
	req->multipart_boundary.data = data;
	req->multipart_boundary_raw.nchunks = 0;
	req->multipart_boundary.nchunks = 0;

	return 0;
}

static int
__req_parse_content_type(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpReq *req = (TfwHttpReq *)hm;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_ContType) {
		if (req->method != TFW_HTTP_METH_POST)
			__FSM_I_JMP(I_EoL);
		/* Fall through. */;
	}

	__FSM_STATE(I_ContTypeMediaType) {
		static const TfwStr s_multipart_form_data =
			TFW_STR_STRING("multipart/form-data");
		TRY_STR_LAMBDA_fixup(&s_multipart_form_data, &parser->hdr, {},
				     I_ContTypeMediaType,
				     I_ContTypeMaybeMultipart);
		if (chunk->len >= sizeof("multipart/") - 1) {
			TRY_STR_INIT();
			__FSM_I_JMP(I_ContTypeOtherSubtype);
		} else {
			TRY_STR_INIT();
			__FSM_I_JMP(I_ContTypeOtherType);
		}
	}

	__FSM_STATE(I_ContTypeMaybeMultipart) {
		if (c == ';') {
			__set_bit(TFW_HTTP_B_CT_MULTIPART, req->flags);
			__FSM_I_MOVE_fixup(I_ContTypeParamOWS, 1, 0);
		}
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_ContTypeMultipartOWS, 1, 0);
		if (IS_CRLF(c)) {
			__set_bit(TFW_HTTP_B_CT_MULTIPART, req->flags);
			goto finalize;
		}
		__FSM_I_JMP(I_ContTypeOtherSubtype);
	}

	__FSM_STATE(I_ContTypeMultipartOWS) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_ContTypeMultipartOWS, 1, 0);
		if (c == ';') {
			__set_bit(TFW_HTTP_B_CT_MULTIPART, req->flags);
			__FSM_I_MOVE_fixup(I_ContTypeParamOWS, 1, 0);
		}
		if (IS_CRLF(c)) {
			__set_bit(TFW_HTTP_B_CT_MULTIPART, req->flags);
			goto finalize;
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_ContTypeParamOWS) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_ContTypeParamOWS, 1, 0);
		if (IS_CRLF(c))
			goto finalize;
		/* Fall through. */;
	}

	__FSM_STATE(I_ContTypeParam) {
		static const TfwStr s_boundary = TFW_STR_STRING("boundary=");
		if (!test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags))
			__FSM_I_JMP(I_ContTypeParamOther);

		TRY_STR_LAMBDA_fixup(&s_boundary, &parser->hdr, {
			/*
			 * Requests with multipart/form-data payload should have
			 * only one boundary parameter.
			 */
			if (__test_and_set_bit(
			      TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY, req->flags))
				return CSTR_NEQ;
		}, I_ContTypeParam, I_ContTypeBoundaryValue);
		TRY_STR_INIT();
		/* Fall through. */;
	}

	__FSM_STATE(I_ContTypeParamOther) {
		__FSM_I_MATCH_MOVE_fixup(token, I_ContTypeParamOther, 0);
		if (IS_CRLF(*(p + __fsm_sz))) {
			/* Line terminated just after parameter name. Value is
			 * missing.
			 */
			return CSTR_NEQ;
		}
		if (*(p + __fsm_sz) != '=')
			return CSTR_NEQ;
		__FSM_I_MOVE_fixup(I_ContTypeParamValue, __fsm_sz + 1, 0);
	}

	__FSM_STATE(I_ContTypeBoundaryValue) {
		req->multipart_boundary_raw.len = 0;
		req->multipart_boundary.len = 0;
		/*
		 * msg->parser.hdr.data can't be used as a base here, since its
		 * value can change due to reallocation during msg->parser.hdr
		 * growth. Let's store chunk number instead for now.
		 */
		req->multipart_boundary_raw.data =
			(char *)(size_t)parser->hdr.nchunks;
		if (*p == '"') {
			req->multipart_boundary_raw.len += 1;
			__FSM_I_MOVE_fixup(I_ContTypeBoundaryValueQuoted, 1, 0);
		}
		/* Fall through. */;
	}

	__FSM_STATE(I_ContTypeBoundaryValueUnquoted) {
		__fsm_n = __data_remain(p);
		__fsm_sz = tfw_match_token(p, __fsm_n);
		if (__fsm_sz > 0) {
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			__FSM_I_chunk_flags(TFW_STR_VALUE);
			req->multipart_boundary_raw.len += __fsm_sz;
			req->multipart_boundary.len += __fsm_sz;
		}
		if (unlikely(__fsm_sz == __fsm_n)) {
			parser->_i_st = &&I_ContTypeBoundaryValueUnquoted;
			return CSTR_POSTPONE;
		}

		p += __fsm_sz;
		req->multipart_boundary_raw.nchunks = parser->hdr.nchunks -
				     (size_t)req->multipart_boundary_raw.data;
		/* __fsm_sz != __fsm_n, therefore __data_remain(p) > 0 */
		__FSM_I_JMP(I_ContTypeParamValueOWS);
	}

	__FSM_STATE(I_ContTypeBoundaryValueQuoted) {
		__fsm_n = __data_remain(p);
		__fsm_sz = tfw_match_token(p, __fsm_n);
		if (__fsm_sz > 0) {
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			__FSM_I_chunk_flags(TFW_STR_VALUE);
			req->multipart_boundary_raw.len += __fsm_sz;
			req->multipart_boundary.len += __fsm_sz;
		}
		if (unlikely(__fsm_sz == __fsm_n)) {
			parser->_i_st = &&I_ContTypeBoundaryValueQuoted;
			return CSTR_POSTPONE;
		}
		p += __fsm_sz;

		if (*p == '\\') {
			req->multipart_boundary_raw.len += 1;
			__FSM_I_MOVE_fixup(I_ContTypeBoundaryValueEscapedChar,
					   1, 0);
		}
		if (IS_CRLF(*p)) {
			/* Missing closing '"'. */
			return CSTR_NEQ;
		}
		if (*p != '"') {
			/* TODO: faster qdtext/quoted-pair matcher. */
			req->multipart_boundary_raw.len += 1;
			req->multipart_boundary.len += 1;
			__FSM_I_MOVE_fixup(I_ContTypeBoundaryValueQuoted, 1,
					   TFW_STR_VALUE);
		}

		/* *p == '"' */
		__msg_hdr_chunk_fixup(p, 1);
		p += 1;
		req->multipart_boundary_raw.len += 1;
		req->multipart_boundary_raw.nchunks = parser->hdr.nchunks -
				     (size_t)req->multipart_boundary_raw.data;

		if (unlikely(__data_remain(p) == 0)) {
			parser->_i_st = &&I_ContTypeParamValueOWS;
			return CSTR_POSTPONE;
		}
		__FSM_I_JMP(I_ContTypeParamValueOWS);
	}

	__FSM_STATE(I_ContTypeBoundaryValueEscapedChar) {
		if (IS_CRLF(*p))
			return CSTR_NEQ;
		req->multipart_boundary_raw.len += 1;
		req->multipart_boundary.len += 1;
		__FSM_I_MOVE_fixup(I_ContTypeBoundaryValueQuoted, 1,
				   TFW_STR_VALUE);
	}

	__FSM_STATE(I_ContTypeParamValue) {
		if (*p == '"')
			__FSM_I_MOVE_fixup(I_ContTypeParamValueQuoted, 1, 0);
		__FSM_I_JMP(I_ContTypeParamValueUnquoted);
	}

	__FSM_STATE(I_ContTypeParamValueUnquoted) {
		__FSM_I_MATCH_MOVE_fixup(token, I_ContTypeParamValueUnquoted,
					 TFW_STR_VALUE);
		__FSM_I_MOVE_fixup(I_ContTypeParamValueOWS, __fsm_sz, 0);
	}

	__FSM_STATE(I_ContTypeParamValueOWS) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_ContTypeParamValueOWS, 1, 0);
		if (c == ';')
			__FSM_I_MOVE_fixup(I_ContTypeParamOWS, 1, 0);
		if (IS_CRLF(c))
			goto finalize;
		return CSTR_NEQ;
	}

	__FSM_STATE(I_ContTypeParamValueQuoted) {
		__FSM_I_MATCH_MOVE_fixup(token, I_ContTypeParamValueQuoted,
					 TFW_STR_VALUE);
		if (__fsm_sz > 0) {
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			__FSM_I_chunk_flags(TFW_STR_VALUE);
		}
		p += __fsm_sz;
		if (*p == '\\')
			__FSM_I_MOVE_fixup(I_ContTypeParamValueEscapedChar, 1,
					   0);
		if (*p == '"')
			__FSM_I_MOVE_fixup(I_ContTypeParamValueOWS, 1, 0);
		if (IS_CRLF(*p)) {
			/* Missing closing '"'. */
			return CSTR_NEQ;
		}
		/* TODO: faster qdtext/quoted-pair matcher. */
		__FSM_I_MOVE_fixup(I_ContTypeParamValueQuoted, 1, 0);
	}

	__FSM_STATE(I_ContTypeParamValueEscapedChar) {
		if (IS_CRLF(*p))
			return CSTR_NEQ;
		__FSM_I_MOVE_fixup(I_ContTypeParamValueQuoted, 1,
				   TFW_STR_VALUE);
	}

	__FSM_STATE(I_ContTypeOtherType) {
		__FSM_I_MATCH_MOVE_fixup(token, I_ContTypeOtherType, 0);
		if (IS_CRLF(*(p + __fsm_sz))) {
			p += __fsm_sz;
			goto finalize;
		}
		__FSM_I_MOVE_n(I_ContTypeOtherTypeSlash, __fsm_sz);
	}

	__FSM_STATE(I_ContTypeOtherTypeSlash) {
		if (c != '/')
			return CSTR_NEQ;
		__FSM_I_MOVE_fixup(I_ContTypeOtherSubtype, 1, 0);
	}

	__FSM_STATE(I_ContTypeOtherSubtype) {
		__FSM_I_MATCH_MOVE_fixup(token, I_ContTypeOtherSubtype, 0);
		__FSM_I_MOVE_fixup(I_ContTypeOtherTypeOWS, __fsm_sz, 0);
	}

	__FSM_STATE(I_ContTypeOtherTypeOWS) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_ContTypeOtherTypeOWS, 1, 0);
		if (c == ';')
			__FSM_I_MOVE_fixup(I_ContTypeParamOWS, 1, 0);
		if (IS_CRLF(c))
			goto finalize;
		return CSTR_NEQ;
	}

	__FSM_STATE(I_EoL) {
		__FSM_I_MATCH_MOVE_fixup(ctext_vchar, I_EoL, 0);
		if (IS_CRLF(*(p + __fsm_sz))) {
			p += __fsm_sz;
			goto finalize;
		}
		return CSTR_NEQ;
	}

done:
	return r;

finalize:
	if (req->multipart_boundary_raw.len > 0) {
		req->multipart_boundary_raw.chunks = parser->hdr.chunks +
			(size_t)req->multipart_boundary_raw.data;

		/*
		 * Raw value of multipart boundary is going to be used during
		 * Content-Type field composing. So to prevent memcpy'ing
		 * intersecting buffers, we have to make a separate copy.
		 */
		if (__strdup_multipart_boundaries(req))
			return CSTR_NEQ;
	}

	return __data_off(p);
}
STACK_FRAME_NON_STANDARD(__req_parse_content_type);

/**
 * Parse Transfer-Encoding header value, RFC 2616 14.41 and 3.6.
 */
static int
__parse_transfer_encoding(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	/*
	 * According to RFC 7230 section 3.3.1:
	 *
	 * TODO: In a response:
	 * A server MUST NOT send a Transfer-Encoding header field
	 * in any 2xx (Successful) response to a CONNECT request.
	 */
	__FSM_STATE(I_TransEncod) {
		if (TFW_CONN_TYPE(hm->conn) & Conn_Srv) {
			unsigned int status = ((TfwHttpResp *)hm)->status;
			if (status - 100U < 100U || status == 204)
				return CSTR_NEQ;
		}
		/* Fall through. */
	}

	__FSM_STATE(I_TransEncodTok) {

		/*
		 * A sender MUST NOT apply chunked more than once
		 * to a message body (i.e., chunking an already
		 * chunked message is not allowed). RFC 7230 3.3.1.
		 */
		TRY_STR("chunked", I_TransEncodTok, I_TransEncodChunked);
		TRY_STR_INIT();
		__FSM_I_JMP(I_TransEncodOther);
	}

	__FSM_STATE(I_TransEncodChunked) {
		if (IS_WS(c) || c == ',' || IS_CRLF(c)) {
			if (unlikely(test_bit(TFW_HTTP_B_CHUNKED, msg->flags)))
				return CSTR_NEQ;
			__set_bit(TFW_HTTP_B_CHUNKED, msg->flags);
			__FSM_I_JMP(I_EoT);
		}
		__FSM_I_JMP(I_TransEncodOther);
	}

	__FSM_STATE(I_TransEncodOther) {
		/*
		 * TODO: process transfer encodings: gzip, deflate, identity,
		 * compress;
		 */
		__FSM_I_MATCH_MOVE(token, I_TransEncodOther);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c)) {
			/* "chunked" must be the last coding. */
			if (unlikely(test_bit(TFW_HTTP_B_CHUNKED, msg->flags)))
				return CSTR_NEQ;
			return __data_off(p + __fsm_sz);
		}
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(I_EoT);
		if (IS_TOKEN(c))
			__FSM_I_JMP(I_TransEncodTok);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_transfer_encoding);

/*
 * ------------------------------------------------------------------------
 *	HTTP request parsing
 * ------------------------------------------------------------------------
 */
/**
 * Accept header parser, RFC 7231 5.3.2.
 */
static int
__req_parse_accept(TfwHttpReq *req, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_Accept) {
		TRY_STR("text/html", Req_I_Accept, Req_I_AcceptHtml);
		TRY_STR("*/*", Req_I_Accept, Req_I_AcceptHtml);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_AcceptOther);
	}

	__FSM_STATE(Req_I_AcceptHtml) {
		if (IS_WS(c) || c == ',' || c == ';' || IS_CRLF(c)) {
			__set_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags);
			__FSM_I_JMP(I_EoT);
		}
		__FSM_I_MOVE(Req_I_AcceptOther);
	}

	__FSM_STATE(Req_I_AcceptOther) {
		__FSM_I_MATCH_MOVE(uri, Req_I_AcceptOther);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c)) {
			return __data_off(p + __fsm_sz);
		}
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(I_EoT);
		if (c == ';')
			/* Skip weight parameter. */
			__FSM_I_MOVE(Req_I_AcceptOther);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_Accept);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__req_parse_accept);

static int
__req_parse_authorization(TfwHttpReq *req, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_Auth) {
		/*
		 * RFC 7235 requires handling quoted-string in auth-param,
		 * so almost any character can appear in the field.
		 */
		__FSM_I_MATCH_MOVE(ctext_vchar, Req_I_Auth);
		if (IS_CRLF(*(p + __fsm_sz))) {
			req->cache_ctl.flags |= TFW_HTTP_CC_HDR_AUTHORIZATION;
			return __data_off(p + __fsm_sz);
		}
		return CSTR_NEQ;
	}

done:
	return r;
}

/**
 * Parse request Cache-Control, RFC 2616 14.9
 */
static int
__req_parse_cache_control(TfwHttpReq *req, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_CC) {
		WARN_ON_ONCE(parser->_acc);
		switch (TFW_LC(c)) {
		case 'm':
			__FSM_I_JMP(Req_I_CC_m);
		case 'n':
			__FSM_I_JMP(Req_I_CC_n);
		case 'o':
			__FSM_I_JMP(Req_I_CC_o);
		}
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_m) {
		TRY_STR("max-age=", Req_I_CC_m, Req_I_CC_MaxAgeV);
		TRY_STR("min-fresh=", Req_I_CC_m, Req_I_CC_MinFreshV);
		TRY_STR("max-stale", Req_I_CC_m, Req_I_CC_MaxStale);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_n) {
		TRY_STR_LAMBDA("no-cache", {
			parser->_acc = TFW_HTTP_CC_NO_CACHE;
		}, Req_I_CC_n, Req_I_CC_Flag);
		TRY_STR_LAMBDA("no-store", {
			parser->_acc = TFW_HTTP_CC_NO_STORE;
		}, Req_I_CC_n, Req_I_CC_Flag);
		TRY_STR_LAMBDA("no-transform", {
			parser->_acc = TFW_HTTP_CC_NO_TRANSFORM;
		}, Req_I_CC_n, Req_I_CC_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_o) {
		TRY_STR_LAMBDA("only-if-cached", {
			parser->_acc = TFW_HTTP_CC_OIFCACHED;
		}, Req_I_CC_o, Req_I_CC_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_Flag) {
		WARN_ON_ONCE(!parser->_acc);
		if (IS_WS(c) || c == ',' || IS_CRLF(c)) {
			req->cache_ctl.flags |= parser->_acc;
			__FSM_I_JMP(Req_I_EoT);
		}
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_MaxAgeV) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0) {
			if (__fsm_n != CSTR_BADLEN)
				return __fsm_n;
			parser->_acc = UINT_MAX;
		}
		req->cache_ctl.max_age = parser->_acc;
		req->cache_ctl.flags |= TFW_HTTP_CC_MAX_AGE;
		__FSM_I_MOVE_n(Req_I_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_MinFreshV) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0) {
			if (__fsm_n != CSTR_BADLEN)
				return __fsm_n;
			parser->_acc = UINT_MAX;
		}
		req->cache_ctl.min_fresh = parser->_acc;
		req->cache_ctl.flags |= TFW_HTTP_CC_MIN_FRESH;
		__FSM_I_MOVE_n(Req_I_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_MaxStale) {
		if (c == '=')
			__FSM_I_MOVE(Req_I_CC_MaxStaleV);
		if (IS_WS(c) || c == ',' || IS_CRLF(c)) {
			req->cache_ctl.max_stale = UINT_MAX;
			req->cache_ctl.flags |= TFW_HTTP_CC_MAX_STALE;
			__FSM_I_JMP(Req_I_EoT);
		}
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_MaxStaleV) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0) {
			if (__fsm_n != CSTR_BADLEN)
				return __fsm_n;
			parser->_acc = UINT_MAX;
		}
		req->cache_ctl.max_stale = parser->_acc;
		req->cache_ctl.flags |= TFW_HTTP_CC_MAX_STALE;
		__FSM_I_MOVE_n(Req_I_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_Ext) {
		/* TODO: process cache extensions. */
		__FSM_I_MATCH_MOVE(qetoken, Req_I_CC_Ext);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(Req_I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c)) {
			parser->_acc = 0;
			return __data_off(p + __fsm_sz);
		}
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(Req_I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(Req_I_EoT);

		parser->_acc = 0; /* reinit for next token */

		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_CC);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__req_parse_cache_control);

static int
__req_parse_cookie(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	/*
	 * Cookie header is parsed according to RFC 6265 4.2.1.
	 *
	 * Here we build header value string manually to split it in chunks:
	 * chunk bounds are at least at name start, value start and value end.
	 * This simplifies cookie search, http_sticky uses it.
	 */
	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_CookieStart) {
		__FSM_I_MATCH_MOVE_fixup(token, Req_I_CookieName, TFW_STR_NAME);
		/*
		 * Name should contain at least 1 character.
		 * Store "=" with cookie parameter name.
		 */
		if (likely(__fsm_sz && *(p + __fsm_sz) == '='))
			__FSM_I_MOVE_fixup(Req_I_CookieVal, __fsm_sz + 1,
					   TFW_STR_NAME);
		return CSTR_NEQ;
	}

	/*
	 * At this state we know that we saw at least one character as
	 * cookie-name and now we can pass zero length token.
	 */
	__FSM_STATE(Req_I_CookieName) {
		__FSM_I_MATCH_MOVE_fixup(token, Req_I_CookieName, TFW_STR_NAME);
		if (*(p + __fsm_sz) != '=')
			return CSTR_NEQ;
		/* Store "=" with cookie parameter name. */
		__FSM_I_MOVE_fixup(Req_I_CookieVal, __fsm_sz + 1, TFW_STR_NAME);
	}

	/*
	 * Cookie-value can have zero length, but we still have to store it
	 * in separate TfwStr chunk.
	 */
	__FSM_STATE(Req_I_CookieVal) {
		__FSM_I_MATCH_MOVE_fixup(cookie, Req_I_CookieVal, TFW_STR_VALUE);
		c = *(p + __fsm_sz);
		if (c == ';') {
			if (likely(__fsm_sz)) {
				/* Save cookie-value w/o ';'. */
				__msg_hdr_chunk_fixup(p, __fsm_sz);
				__FSM_I_chunk_flags(TFW_STR_VALUE);
			}
			__FSM_I_MOVE_n(Req_I_CookieSemicolon, __fsm_sz);
		}
		if (unlikely(IS_CRLFWS(c))) {
			/* End of cookie header. Do not save OWS. */
			if (likely(__fsm_sz)) {
				__msg_hdr_chunk_fixup(p, __fsm_sz);
				__FSM_I_chunk_flags(TFW_STR_VALUE);
			}
			return __data_off(p + __fsm_sz);
		}
		return CSTR_NEQ;
	}

	/* ';' was already matched. */
	__FSM_STATE(Req_I_CookieSemicolon) {
		/*
		 * Fixup current delimiters chunk and move to next parameter
		 * if we can eat ';' and SP at once.
		 */
		if (likely(__data_available(p, 2))) {
			if (likely(*(p + 1) == ' '))
				__FSM_I_MOVE_fixup(Req_I_CookieStart, 2, 0);
			return CSTR_NEQ;
		}
		/*
		 * Only ';' is available now: fixup ';' as independent chunk,
		 * SP will be fixed up at next enter to the FSM.
		 */
		__FSM_I_MOVE_fixup(Req_I_CookieSP, 1, 0);
	}

	__FSM_STATE(Req_I_CookieSP) {
		if (unlikely(c != ' '))
			return CSTR_NEQ;
		/* Fixup current delimiters chunk and move to next parameter. */
		__FSM_I_MOVE_fixup(Req_I_CookieStart, 1, 0);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__req_parse_cookie);

#define __FSM_TX_ETAG(st, ch, st_next)					\
__FSM_STATE(st) {							\
	if (likely(c == (ch)))						\
		__FSM_I_MOVE_fixup(st_next, 1, 0);			\
	return CSTR_NEQ;						\
}

/**
 * Parse response ETag, RFC 7232 section-2.3
 */
static int
__parse_etag(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int weak, r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	/*
	 * ETag value and closing DQUOTE is placed into separate chunks marked
	 * with flags TFW_STR_VALUE and TFW_STR_ETAG_WEAK (optionally).
	 * Closing DQUOTE is used to support empty Etags. Opening is not added
	 * to simplify usage of tfw_stricmpspn()
	 *
	 * Note: Weak indicator is case-sensitive!
	 */

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_Etag) {
		TfwHttpReq *req = (TfwHttpReq *)hm; /* for If-None-Match. */

		if (likely(c == '"')) {
			if (TFW_CONN_TYPE(hm->conn) & Conn_Clnt)
				req->cond.flags |= TFW_HTTP_COND_ETAG_LIST;
			__FSM_I_MOVE_fixup(I_Etag_Val, 1, 0);
		}

		if (likely(__data_available(p, 3))
		    && (*p == 'W') && (*(p + 1) == '/') && (*(p + 2) == '"'))
		{
			__FSM_I_MOVE_fixup(I_Etag_Weak, 3, 0);
		}
		if (c == 'W')
			__FSM_I_MOVE_fixup(I_Etag_W, 1, 0);

		if ((TFW_CONN_TYPE(hm->conn) & Conn_Clnt) && c == '*') {
			if (req->cond.flags & TFW_HTTP_COND_ETAG_LIST)
				return CSTR_NEQ;

			req->cond.flags |= TFW_HTTP_COND_ETAG_ANY;
			__FSM_I_MOVE_fixup(I_EoL, 1, 0);
		}

		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_Etag, 1, 0);
		return CSTR_NEQ;
	}

	__FSM_TX_ETAG(I_Etag_W, '/', I_Etag_We);
	__FSM_TX_ETAG(I_Etag_We, '"', I_Etag_Weak);

	/*
	 * Need to store WEAK flag, it is safe to store the flag in parser->hdr,
	 * but only after first fixup in this function: header must became
	 * compound string.
	 */
	__FSM_STATE(I_Etag_Weak) {
		parser->hdr.flags |= TFW_STR_ETAG_WEAK;
		__FSM_JMP(I_Etag_Val);
	}

	/*
	 * ETag-value can have zero length, but we still have to store it
	 * in separate TfwStr chunk.
	 */
	__FSM_STATE(I_Etag_Val) {
		weak = parser->hdr.flags & TFW_STR_ETAG_WEAK;
		__FSM_I_MATCH_MOVE_fixup(token, I_Etag_Val,
					 (TFW_STR_VALUE | weak));
		c = *(p + __fsm_sz);
		if (likely(c == '"')) {
			parser->hdr.flags &= ~TFW_STR_ETAG_WEAK;
			__FSM_I_MOVE_fixup(I_EoT, __fsm_sz + 1,
					   TFW_STR_VALUE | weak);
		}
		return CSTR_NEQ;
	}

	/* End of token */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_EoT, 1, 0);
		if (IS_CRLF(c))
			return __data_off(p);
		if ((TFW_CONN_TYPE(hm->conn) & Conn_Clnt) && c == ',')
			__FSM_I_MOVE_fixup(I_Etag, 1, 0);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_EoL) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_EoL, 1, 0);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_etag);

/**
 * Parse request Host header, RFC 7230 5.4.
 *
 * TODO Per RFC 1035, 2181, max length of FQDN is 255.
 * What if it's UTF-8 encoded?
 */
static int
__req_parse_host(TfwHttpReq *req, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_H_Start) {
		if (likely(isalnum(c) || c == '.' || c == '-'))
			__FSM_I_MOVE(Req_I_H);
		if (likely(c == '['))
			__FSM_I_MOVE(Req_I_H_v6);
		if (unlikely(IS_CRLFWS(c)))
			return 0; /* empty Host header */
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_H) {
		/* See Req_UriAuthority processing. */
		if (likely(isalnum(c) || c == '.' || c == '-'))
			__FSM_I_MOVE(Req_I_H);
		if (c == ':')
			__FSM_I_MOVE(Req_I_H_Port);
		if (IS_CRLFWS(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_H_v6) {
		/* See Req_UriAuthorityIPv6 processing. */
		if (likely(isxdigit(c) || c == ':'))
			__FSM_I_MOVE(Req_I_H_v6);
		if (likely(c == ']'))
			__FSM_I_MOVE(Req_I_H_v6_End);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_H_v6_End) {
		if (likely(IS_CRLFWS(c)))
			return __data_off(p);
		if (likely(c == ':'))
			__FSM_I_MOVE(Req_I_H_Port);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_H_Port) {
		/* See Req_UriPort processing. */
		if (likely(isdigit(c)))
			__FSM_I_MOVE(Req_I_H_Port);
		if (IS_CRLFWS(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__req_parse_host);

static int
__req_parse_referer(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_Referer) {
		__FSM_I_MATCH_MOVE(uri, Req_I_Referer);
		if (IS_WS(*(p + __fsm_sz)))
			__FSM_I_MOVE_n(Req_I_EoT, __fsm_sz + 1);
		if (IS_CRLF(*(p + __fsm_sz)))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}
	__FSM_STATE(Req_I_EoT) {
		if (IS_WS(c))
			__FSM_I_MOVE(Req_I_EoT);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__req_parse_referer);

/**
 * Parse response Expires, RFC 2616 14.21.
 *
 * We support only RFC 1123 date as it's most usable by modern software.
 * However RFC 2616 requires that all server and client software MUST support
 * all 3 formats specified in 3.3.1 chapter. We leave this for TODO.
 *
 * @return number of seconds since epoch in GMT.
 */
#define SEC24H		(24 * 3600)
/* Seconds Before a month in a non leap year. */
#define SB_FEB		(31 * SEC24H)
#define SB_MAR		(SB_FEB + 28 * SEC24H)
#define SB_APR		(SB_MAR + 31 * SEC24H)
#define SB_MAY		(SB_APR + 30 * SEC24H)
#define SB_JUN		(SB_MAY + 31 * SEC24H)
#define SB_JUL		(SB_JUN + 30 * SEC24H)
#define SB_AUG		(SB_JUL + 31 * SEC24H)
#define SB_SEP		(SB_AUG + 31 * SEC24H)
#define SB_OCT		(SB_SEP + 30 * SEC24H)
#define SB_NOV		(SB_OCT + 31 * SEC24H)
#define SB_DEC		(SB_NOV + 30 * SEC24H)
/* Number of days before epoch including leap years. */
#define EPOCH_DAYS	(1970 * 365 + 1970 / 4 - 1970 / 100 + 1970 / 400)

static int
__year_day_secs(unsigned int year, unsigned int day_sec)
{
	unsigned int days = year * 365 + year / 4 - year / 100 + year / 400;

	/* Add SEC24H if the year is leap and we left Feb behind. */
	if (year % 4 == 0 && !(year % 100 == 0 && year % 400 != 0))
		day_sec += SEC24H;

	if (days < EPOCH_DAYS)
		return -1;

	return (days - EPOCH_DAYS) * SEC24H + day_sec;
}

static size_t
__skip_weekday(unsigned char *p, size_t len)
{
	unsigned char lc, *c, *end = p + len;

	for (c = p; c < end; ++c) {
		lc = TFW_LC(*c);
		if ((unsigned)(lc - 'a') > (unsigned)('z' - 'a') && lc != ',')
			return (*c != ' ') ? CSTR_NEQ : c - p;
	}
	return len;
}

static int
__parse_http_date(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	static const unsigned long colon_a[] ____cacheline_aligned = {
		/* ':' (0x3a)(58) Colon */
		0x0400000000000000UL, 0, 0, 0
	};
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START_ALT(parser->_i_st);

	__FSM_STATE(I_Date) {
		/*
		 * Skip a weekday with comma (e.g. "Sun,") as redundant
		 * information.
		 */
		__fsm_sz = __data_remain(p);
		__fsm_n = __skip_weekday(p, __fsm_sz);
		if (__fsm_sz == __fsm_n)
			__FSM_I_MOVE_n(I_Date, __fsm_sz);
		if (unlikely(__fsm_n == CSTR_NEQ))
			return CSTR_NEQ;
		__FSM_I_MOVE_n(I_DateDay, __fsm_n + 1);
	}

	__FSM_STATE(I_DateDay) {
		__fsm_sz = __data_remain(p);
		/* Parse a 2-digit day. */
		__fsm_n = parse_int_ws(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE) {
			parser->_i_st = &&I_DateDay;
			__msg_hdr_chunk_fixup(data, len);
		}
		if (__fsm_n < 0)
			return __fsm_n;
		if (parser->_acc < 1 || parser->_acc > 31)
			return CSTR_BADLEN;
		/* Add seconds in full passed days. */
		parser->_date = (parser->_acc - 1) * SEC24H;
		parser->_acc = 0;
		__FSM_I_MOVE_n(I_DateMonthSP, __fsm_n);
	}

	__FSM_STATE(I_DateMonthSP) {
		if (likely(c == ' '))
			__FSM_I_MOVE(I_DateMonth);
		return CSTR_NEQ;
	}

	/*
	 * RFC 7231 7.1.1.1: month and day fields are case sensitive.
	 * However, it's not clear whether there are RFC incompliant, but
	 * innocent, implementations (e.g. the application side may generate
	 * the header) sending date in wrong case. Also to require case
	 * insensitiveness of the field we need to introduce one more
	 * TRY_STR_LAMBDA() version.
	 */
	__FSM_STATE(I_DateMonth) {
		switch (TFW_LC(c)) {
		case 'a':
			__FSM_I_JMP(I_DateMonth_A);
		case 'j':
			__FSM_I_JMP(I_DateMonth_J);
		case 'm':
			__FSM_I_JMP(I_DateMonth_M);
		}
		__FSM_I_JMP(I_DateMonth_Other);
	}

	__FSM_STATE(I_DateMonth_A) {
		TRY_STR_LAMBDA("apr ", {
			parser->_date += SB_APR;
		}, I_DateMonth_A, I_DateYear);
		TRY_STR_LAMBDA("aug ", {
			parser->_date += SB_AUG;
		}, I_DateMonth_A, I_DateYear);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_DateMonth_J) {
		TRY_STR("jan ", I_DateMonth_J, I_DateYear);
		TRY_STR_LAMBDA("jun ", {
			parser->_date += SB_JUN;
		}, I_DateMonth_J, I_DateYear);
		TRY_STR_LAMBDA("jul ", {
			parser->_date += SB_JUL;
		}, I_DateMonth_J, I_DateYear);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_DateMonth_M) {
		TRY_STR_LAMBDA("mar ", {
			/* Add SEC24H for leap year on year parsing. */
			parser->_date += SB_MAR;
		}, I_DateMonth_M, I_DateYear);
		TRY_STR_LAMBDA("may ", {
			parser->_date += SB_MAY;
		}, I_DateMonth_M,I_DateYear);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_DateMonth_Other) {
		TRY_STR_LAMBDA("feb ", {
			parser->_date += SB_FEB;
		}, I_DateMonth_Other, I_DateYear);
		TRY_STR_LAMBDA("sep ", {
			parser->_date += SB_SEP;
		}, I_DateMonth_Other, I_DateYear);
		TRY_STR_LAMBDA("oct ", {
			parser->_date += SB_OCT;
		}, I_DateMonth_Other, I_DateYear);
		TRY_STR_LAMBDA("nov ", {
			parser->_date += SB_NOV;
		}, I_DateMonth_Other, I_DateYear);
		TRY_STR_LAMBDA("dec ", {
			parser->_date += SB_DEC;
		}, I_DateMonth_Other, I_DateYear);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	/* 4-digit year. */
	__FSM_STATE(I_DateYear) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_ws(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE) {
			parser->_i_st = &&I_DateYear;
			__msg_hdr_chunk_fixup(data, len);
		}
		if (__fsm_n < 0)
			return __fsm_n;
		parser->_date = __year_day_secs(parser->_acc, parser->_date);
		if (parser->_date < 0)
			return CSTR_NEQ;
		parser->_acc = 0;
		__FSM_I_MOVE_n(I_DateHourSP, __fsm_n);
	}

	__FSM_STATE(I_DateHourSP) {
		if (likely(c == ' '))
			__FSM_I_MOVE(I_DateHour);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_DateHour) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_a(p, __fsm_sz, colon_a, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE) {
			parser->_i_st = &&I_DateHour;
			__msg_hdr_chunk_fixup(data, len);
		}
		if (__fsm_n < 0)
			return __fsm_n;
		parser->_date += parser->_acc * 3600;
		parser->_acc = 0;
		__FSM_I_MOVE_n(I_DateMinCln, __fsm_n);
	}

	__FSM_STATE(I_DateMinCln) {
		if (likely(c == ':'))
			__FSM_I_MOVE(I_DateMin);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_DateMin) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_a(p, __fsm_sz, colon_a, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE) {
			parser->_i_st = &&I_DateMin;
			__msg_hdr_chunk_fixup(data, len);
		}
		if (__fsm_n < 0)
			return __fsm_n;
		parser->_date += parser->_acc * 60;
		parser->_acc = 0;
		__FSM_I_MOVE_n(I_DateSecCln, __fsm_n);
	}

	__FSM_STATE(I_DateSecCln) {
		if (likely(c == ':'))
			__FSM_I_MOVE(I_DateSec);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_DateSec) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_ws(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE) {
			parser->_i_st = &&I_DateSec;
			__msg_hdr_chunk_fixup(data, len);
		}
		if (__fsm_n < 0)
			return __fsm_n;
		parser->_date += parser->_acc;
		parser->_acc = 0;
		__FSM_I_MOVE_n(I_DateSecSP, __fsm_n);
	}

	__FSM_STATE(I_DateSecSP) {
		if (likely(c == ' '))
			__FSM_I_MOVE(I_DateZone);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_DateZone) {
		TRY_STR("gmt", I_DateZone, I_EoL);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_EoL) {
		/* Skip the rest of the line. */
		__FSM_I_MATCH_MOVE(nctl, I_EoL);
		if (!IS_CRLF(*(p + __fsm_sz)))
			return CSTR_NEQ;
		T_DBG3("%s: parsed date %lu", __func__, parser->_date);
		return __data_off(p + __fsm_sz);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_http_date);

/**
 * Parse If-modified-since.
 * RFC 7232 Section-3.3: A recipient MUST ignore the If-Modified-Since header
 * field if the received field-value is not a valid HTTP-date.
 */
static int
__req_parse_if_msince(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwHttpParser *parser = &msg->stream->parser;

	if (!(req->cond.flags & TFW_HTTP_COND_IF_MSINCE))
		r = __parse_http_date(msg, data, len);

	if (r < 0 && r != CSTR_POSTPONE) {
		/* On error just swallow the rest of the line. */
		parser->_date = 0;
		parser->_acc = 0;
		parser->_i_st = __I_EoL;
		r = __parse_http_date(msg, data, len);
	}

	if (r >= 0) {
		req->cond.m_date = parser->_date;
		req->cond.flags |= TFW_HTTP_COND_IF_MSINCE;
	}

	return r;
}

/**
 * Parse Pragma header field. Request semantics is described in RFC 7234 5.4.
 * The meaning of "Pragma: no-cache" in responses is not specified. However,
 * some applications may expect it to prevent caching being in responses as
 * well.
 */
static int
__parse_pragma(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_Pragma) {
		TRY_STR("no-cache", I_Pragma, I_Pragma_NoCache);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Pragma_Ext);
	}

	__FSM_STATE(I_Pragma_NoCache) {
		if (IS_WS(c) || c == ',' || IS_CRLF(c))
			msg->cache_ctl.flags |= TFW_HTTP_CC_PRAGMA_NO_CACHE;
		__FSM_I_JMP(I_Pragma_Ext);
	}

	__FSM_STATE(I_Pragma_Ext) {
		/* Verify and just skip the extensions. */
		__FSM_I_MATCH_MOVE(qetoken, I_Pragma_Ext);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(I_EoT);
		if (IS_CRLF(c))
			return __data_off(p);
		__FSM_I_JMP(I_Pragma_Ext);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_pragma);

static int
__req_parse_user_agent(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_UserAgent) {
		/*
		 * RFC 7231 5.5.3 and RFC 7230 3.2:
		 *
		 * 	User-Agent = product *( RWS ( product / comment ) )
		 * 	product = token ["/" product-version]
		 * 	product-version = token
		 * 	comment = "(" *( ctext / quoted-pair / comment ) ")"
		 */
		__FSM_I_MATCH_MOVE(ctext_vchar, Req_I_UserAgent);
		if (IS_CRLF(*(p + __fsm_sz)))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

done:
	return r;
}

/**
 * Parse X-Forwarded-For header, RFC 7239.
 */
static int
__req_parse_x_forwarded_for(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_XFF) {
		/* Eat OWS before the node ID. */
		if (unlikely(IS_WS(c)))
			__FSM_I_MOVE_fixup(Req_I_XFF, 1, 0);
		/*
		 * Eat IP address or host name.
		 *
		 * TODO: parse/validate IP addresses and textual IDs.
		 * Currently we just validate separate characters, but the
		 * whole value may be invalid (e.g. "---[_..[[").
		 */
		__FSM_I_MATCH_MOVE_fixup(xff, Req_I_XFF_Node_Id, TFW_STR_VALUE);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_I_MOVE_fixup(Req_I_XFF_Sep, __fsm_sz, TFW_STR_VALUE);
	}

	/*
	 * At this state we know that we saw at least one character as
	 * a host address and now we can pass zero length token.
	 */
	__FSM_STATE(Req_I_XFF_Node_Id) {
		__FSM_I_MATCH_MOVE_fixup(xff, Req_I_XFF_Node_Id, TFW_STR_VALUE);
		__FSM_I_MOVE_fixup(Req_I_XFF_Sep, __fsm_sz, TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_XFF_Sep) {
		/*
		 * Proxy chains are rare, so we expect that the list will end
		 * after the first node and we get EOL here.
		 */
		if (likely(IS_CRLF(c)))
			return __data_off(p);

		/* OWS before comma or before EOL (is unusual). */
		if (unlikely(IS_WS(c)))
			__FSM_I_MOVE_fixup(Req_I_XFF_Sep, 1, 0);

		/*
		 * Multiple subsequent commas look suspicious, so we don't
		 * stay in this state after the first comma is met.
		 */
		if (likely(c == ','))
			__FSM_I_MOVE_fixup(Req_I_XFF, 1, 0);

		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__req_parse_x_forwarded_for);

static int
__parse_keep_alive(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_KeepAlive) {
		TRY_STR("timeout=", I_KeepAlive, I_KeepAliveTO);
		TRY_STR_INIT();
		__FSM_I_JMP(I_KeepAliveExt);
	}

	__FSM_STATE(I_KeepAliveTO) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			return __fsm_n;
		hm->keep_alive = parser->_acc;
		parser->_acc = 0;
		__FSM_I_MOVE_n(I_EoT, __fsm_n);
	}

	/*
	 * Just ignore Keep-Alive extensions. Known extensions:
	 *	max=N
	 */
	__FSM_STATE(I_KeepAliveExt) {
		__FSM_I_MATCH_MOVE(qetoken, I_KeepAliveExt);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(I_EoT);
		if (c == '=')
			__FSM_I_MOVE(I_KeepAliveExt);
		if (IS_TOKEN(c))
			__FSM_I_JMP(I_KeepAlive);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_keep_alive);

static int
__parse_uri_mark(TfwHttpReq *req, unsigned char *data, size_t len)
{
	TfwStr *str;
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_UriMarkStart) {
		if (likely(c == '/')) {
			__msg_field_open(&req->mark, p);
			/* Place initial slash into separate chunk. */
			__FSM_I_MOVE_fixup_f(Req_I_UriMarkName, 1,
					     &req->mark, 0);
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_UriMarkName) {
		str = tfw_http_sess_mark_name();
		TRY_STR_LAMBDA_fixup(str, &req->mark, {
			parser->to_read = tfw_http_sess_mark_size();
		}, Req_I_UriMarkName, Req_I_UriMarkValue);
		/*
		 * Since mark isn't matched, copy accumulated
		 * TfwStr values to 'req->uri_path' - it will
		 * be finished in 'Req_UriAbsPath' state.
		 */
		req->uri_path = req->mark;
		TFW_STR_INIT(&req->mark);
		return __data_off(p);
	}

	__FSM_STATE(Req_I_UriMarkValue) {
		__fsm_n = min_t(long, parser->to_read, __data_remain(p));
		parser->to_read -= __fsm_n;
		if (parser->to_read)
			__FSM_I_MOVE_fixup_f(Req_I_UriMarkValue, __fsm_n,
					     &req->mark, TFW_STR_VALUE);
		parser->to_read = -1;
		__msg_field_finish_pos(&req->mark, p, __fsm_n);
		__FSM_I_field_chunk_flags(&req->mark, TFW_STR_VALUE);
		return __data_off(p + __fsm_n);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_uri_mark);

/**
 * Init parser fields common for both response and request.
 */
static inline void
__parser_init(TfwHttpParser *parser)
{
	bzero_fast(parser, sizeof(TfwHttpParser));
	parser->to_read = -1; /* unknown body size */
}

void
tfw_http_init_parser_req(TfwHttpReq *req)
{
	TfwHttpHbhHdrs *hbh_hdrs = &req->stream->parser.hbh_parser;

	__parser_init(&req->stream->parser);
	req->stream->parser.state = NULL;

	/*
	 * Expected hop-by-hop headers:
	 * - spec:
	 *     none;
	 * - raw:
	 *     Connection: RFC 7230 6.1.
	 */
	hbh_hdrs->spec = 0x1 << TFW_HTTP_HDR_CONNECTION;
}

int
tfw_http_parse_req(void *req_data, unsigned char *data, size_t len,
		   unsigned int *parsed)
{
	int r = TFW_BLOCK;
	TfwHttpReq *req = (TfwHttpReq *)req_data;
	__FSM_DECLARE_VARS(req);
	*parsed = 0;

	T_DBG("parse %lu client data bytes (%.*s%s) on req=%p\n",
	      len, min(500, (int)len), data, len > 500 ? "..." : "", req);

	__FSM_START(parser->state);

	/* ----------------    Request Line    ---------------- */

	/* Parser internal initializers, must be called once per message. */
	__FSM_STATE(Req_0) {
		if (unlikely(IS_CRLF(c)))
			__FSM_MOVE_nofixup(Req_0);
		/* fall through */
	}

/*
 * Fot most (or at least most frequent) methods @step_inc should be
 * optimized out. The macro is used to reduce the FSM size, so there is not
 * sense to use it specific versions for the few states, e.g. for 'GET '.
 */
#define __MATCH_METH(meth, step_inc)					\
do {									\
	req->method = TFW_HTTP_METH_##meth;				\
	__fsm_n += step_inc;						\
	goto match_meth;						\
} while (0)

	/* HTTP method. */
	__FSM_STATE(Req_Method) {
		if (likely(__data_available(p, 9))) {
			/*
			 * Move most frequent methods forward and do not use
			 * switch to make compiler not to merge it with the
			 * switch at the below.
			 *
			 * Usually we have enough data (smallest HTTP/1.1
			 * request is "GET / HTTP/1.1\n\n"), so handle the case
			 * for fast path and fail to 1-character FSM for slow
			 * path.
			 */
			__fsm_n = 4;
			if (likely(PI(p) == TFW_CHAR4_INT('G', 'E', 'T', ' ')))
			{
				req->method = TFW_HTTP_METH_GET;
				__FSM_MOVE_nofixup_n(Req_Uri, 4);
			}
			if (likely(PI(p) == TFW_CHAR4_INT('P', 'O', 'S', 'T')))
				__MATCH_METH(POST, 0);
			barrier();

			/*
			 * Other popular methods: HEAD, COPY, DELETE, LOCK,
			 * MKCOL, MOVE, OPTIONS, PATCH, PROPFIND, PROPPATCH,
			 * PUT, TRACE, UNLOCK, PURGE.
			 */
			switch (PI(p)) {
			case TFW_CHAR4_INT('H', 'E', 'A', 'D'):
				__MATCH_METH(HEAD, 0);
			/* PURGE Method for Tempesta Configuration: PURGE. */
			case TFW_CHAR4_INT('P', 'U', 'R', 'G'):
				if (likely(*(p + 4) == 'E'))
					__MATCH_METH(PURGE, 1);
				__FSM_MOVE_nofixup_n(Req_MethPurg, 4);
			case TFW_CHAR4_INT('C', 'O', 'P', 'Y'):
				__MATCH_METH(COPY, 0);
			case TFW_CHAR4_INT('D', 'E', 'L', 'E'):
				if (likely(*(p + 4) == 'T' && *(p + 5) == 'E'))
					__MATCH_METH(DELETE, 2);
				__FSM_MOVE_nofixup_n(Req_MethDele, 4);
			case TFW_CHAR4_INT('L', 'O', 'C', 'K'):
				__MATCH_METH(LOCK, 0);
			case TFW_CHAR4_INT('M', 'K', 'C', 'O'):
				if (likely(*(p + 4) == 'L'))
					__MATCH_METH(MKCOL, 1);
				__FSM_MOVE_nofixup_n(Req_MethMkco, 4);
			case TFW_CHAR4_INT('M', 'O', 'V', 'E'):
				__MATCH_METH(MOVE, 0);
			case TFW_CHAR4_INT('O', 'P', 'T', 'I'):
				if (likely(*((unsigned int *)p + 1)
					 == TFW_CHAR4_INT('O', 'N', 'S', ' ')))
				{
					req->method = TFW_HTTP_METH_OPTIONS;
					__FSM_MOVE_nofixup_n(Req_Uri, 8);
				}
				__FSM_MOVE_nofixup_n(Req_MethOpti, 4);
			case TFW_CHAR4_INT('P', 'A', 'T', 'C'):
				if (likely(*(p + 4) == 'H'))
					__MATCH_METH(PATCH, 1);
				__FSM_MOVE_nofixup_n(Req_MethPatc, 4);
			case TFW_CHAR4_INT('P', 'R', 'O', 'P'):
				if (likely(*((unsigned int *)p + 1)
					  == TFW_CHAR4_INT('F', 'I', 'N', 'D')))
				{
					__MATCH_METH(PROPFIND, 4);
				}
				if (likely(*((unsigned int *)p + 1)
					   == TFW_CHAR4_INT('P', 'A', 'T', 'C'))
						&& (*(p + 8) == 'H'))
				{
					__MATCH_METH(PROPPATCH, 5);
				}
				__FSM_MOVE_nofixup_n(Req_MethProp, 4);
			case TFW_CHAR4_INT('P', 'U', 'T', ' '):
				req->method = TFW_HTTP_METH_PUT;
				__FSM_MOVE_nofixup_n(Req_Uri, 4);
			case TFW_CHAR4_INT('T', 'R', 'A', 'C'):
				if (likely(*(p + 4) == 'E'))
					__MATCH_METH(TRACE, 1);
				__FSM_MOVE_nofixup_n(Req_MethTrac, 4);
			case TFW_CHAR4_INT('U', 'N', 'L', 'O'):
				if (likely(*(p + 4) == 'C' && *(p + 5) == 'K'))
					__MATCH_METH(UNLOCK, 2);
				__FSM_MOVE_nofixup_n(Req_MethUnlo, 4);
			default:
				__FSM_MOVE_nofixup(Req_MethodUnknown);
			}
			barrier();
match_meth:
			__FSM_MOVE_nofixup_n(Req_MUSpace, __fsm_n);
			barrier();
#undef __MATCH_METH
		}
		/* Slow path: step char-by-char. */
		switch (c) {
		case 'G':
			__FSM_MOVE_nofixup(Req_MethG);
		case 'H':
			__FSM_MOVE_nofixup(Req_MethH);
		case 'P':
			__FSM_MOVE_nofixup(Req_MethP);
		case 'C':
			__FSM_MOVE_nofixup(Req_MethC);
		case 'D':
			__FSM_MOVE_nofixup(Req_MethD);
		case 'L':
			__FSM_MOVE_nofixup(Req_MethL);
		case 'M':
			__FSM_MOVE_nofixup(Req_MethM);
		case 'O':
			__FSM_MOVE_nofixup(Req_MethO);
		case 'T':
			__FSM_MOVE_nofixup(Req_MethT);
		case 'U':
			__FSM_MOVE_nofixup(Req_MethU);
		}
		__FSM_MOVE_nofixup(Req_MethodUnknown);
	}
	__FSM_STATE(Req_MethodUnknown) {
		__FSM_MATCH_MOVE_nofixup(token, Req_MethodUnknown);
		req->method = _TFW_HTTP_METH_UNKNOWN;
		__FSM_MOVE_nofixup_n(Req_MUSpace, 0);
	}

	/*
	 * Eat SP before URI and HTTP (only) scheme.
	 * RFC 7230 3.1.1 requires only one SP.
	 */
	__FSM_STATE(Req_MUSpace) {
		if (unlikely(c != ' '))
			TFW_PARSER_BLOCK(Req_MUSpace);
		__FSM_MOVE_nofixup(Req_Uri);
	}

	__FSM_STATE(Req_Uri) {
		if (likely(c == '/'))
			__FSM_JMP(Req_UriMark);

		if (likely(__data_available(p, 7)
			   && C4_INT_LCM(p, 'h', 't', 't', 'p')
			   && *(p + 4) == ':' && *(p + 5) == '/'
			   && *(p + 6) == '/'))
			__FSM_MOVE_nofixup_n(Req_UriAuthorityStart, 7);

		/* "http://" slow path - step char-by-char. */
		if (likely(TFW_LC(c) == 'h'))
			__FSM_MOVE_nofixup(Req_UriSchH);

		TFW_PARSER_BLOCK(Req_Uri);
	}

	/*
	 * URI host part.
	 * RFC 3986 chapter 3.2: authority = [userinfo@]host[:port]
	 *
	 * Authority parsing: it can be "host" or "userinfo@host" (port is
	 * parsed later). At the beginning we don't know, which of variants we
	 * have. So we fill req->host, and if we get '@', we copy host to
	 * req->userinfo, reset req->host and fill it.
	 */
	__FSM_STATE(Req_UriAuthorityStart) {
		__set_bit(TFW_HTTP_B_URI_FULL, req->flags);
		if (likely(isalnum(c) || c == '.' || c == '-')) {
			__msg_field_open(&req->host, p);
			__FSM_MOVE_f(Req_UriAuthority, &req->host);
		} else if (likely(c == '/')) {
			/*
			 * The case where "Host:" header value is empty.
			 * A special TfwStr{} string is created that has
			 * a valid pointer and the length of zero.
			 */
			T_DBG3("Handling http:///path\n");
			tfw_http_msg_set_str_data(msg, &req->host, p);
			req->host.flags |= TFW_STR_COMPLETE;
			__FSM_JMP(Req_UriMark);
		} else if (c == '[') {
			__msg_field_open(&req->host, p);
			__FSM_MOVE_f(Req_UriAuthorityIPv6, &req->host);
		}
		TFW_PARSER_BLOCK(Req_UriAuthorityStart);
	}

	__FSM_STATE(Req_UriAuthority) {
		if (likely(isalnum(c) || c == '.' || c == '-' || c == '@')) {
			if (unlikely(c == '@')) {
				if (!TFW_STR_EMPTY(&req->userinfo)) {
					T_DBG("Second '@' in authority\n");
					TFW_PARSER_BLOCK(Req_UriAuthority);
				}
				T_DBG3("Authority contains userinfo\n");
				/* copy current host to userinfo */
				req->userinfo = req->host;
				__msg_field_finish(&req->userinfo, p);
				TFW_STR_INIT(&req->host);

				__FSM_MOVE_nofixup(Req_UriAuthorityResetHost);
			}

			__FSM_MOVE_f(Req_UriAuthority, &req->host);
		}
		__FSM_JMP(Req_UriAuthorityEnd);
	}

	__FSM_STATE(Req_UriAuthorityIPv6) {
		if (likely(isxdigit(c) || c == ':')) {
			__FSM_MOVE_f(Req_UriAuthorityIPv6, &req->host);
		} else if(c == ']') {
			__FSM_MOVE_f(Req_UriAuthorityEnd, &req->host);
		}
		TFW_PARSER_BLOCK(Req_UriAuthorityIPv6);
	}

	__FSM_STATE(Req_UriAuthorityResetHost) {
		if (likely(isalnum(c) || c == '.' || c == '-')) {
			__msg_field_open(&req->host, p);
			__FSM_MOVE_f(Req_UriAuthority, &req->host);
		} else if (c == '[') {
			__msg_field_open(&req->host, p);
			__FSM_MOVE_f(Req_UriAuthorityIPv6, &req->host);
		}
		__FSM_JMP(Req_UriAuthorityEnd);
	}

	__FSM_STATE(Req_UriAuthorityEnd) {
		if (c == ':')
			__FSM_MOVE_f(Req_UriPort, &req->host);
		/* Authority End */
		__msg_field_finish(&req->host, p);
		T_DBG3("Userinfo len = %i, host len = %i\n",
		       (int)req->userinfo.len, (int)req->host.len);
		if (likely(c == '/')) {
			__FSM_JMP(Req_UriMark);
		}
		else if (c == ' ') {
			__FSM_MOVE_nofixup(Req_HttpVer);
		}
		TFW_PARSER_BLOCK(Req_UriAuthorityEnd);
	}

	/* Host port in URI */
	__FSM_STATE(Req_UriPort) {
		if (likely(isdigit(c)))
			__FSM_MOVE_f(Req_UriPort, &req->host);
		__msg_field_finish(&req->host, p);
		if (likely(c == '/')) {
			__FSM_JMP(Req_UriMark);
		}
		else if (c == ' ') {
			__FSM_MOVE_nofixup(Req_HttpVer);
		}
		TFW_PARSER_BLOCK(Req_UriPort);
	}

	__FSM_STATE(Req_UriMark) {
		if (!tfw_http_sess_max_misses()) {
			/*
			 * Skip redirection mark processing and move to
			 * URI path parsing, if 'max_misses' for redirected
			 * requests is not enabled.
			 */
			__msg_field_open(&req->uri_path, p);
			__FSM_MOVE_f(Req_UriAbsPath, &req->uri_path);
		}

		if (!parser->_i_st)
			TRY_STR_INIT();
		__fsm_sz = __data_remain(p);
		__fsm_n = __parse_uri_mark(req, p, __fsm_sz);
		if (__fsm_n == CSTR_POSTPONE) {
			p += __fsm_sz;
			parser->state = &&Req_UriMark;
			__FSM_EXIT(TFW_POSTPONE);
		}
		if (__fsm_n < 0)
			TFW_PARSER_BLOCK(Req_UriMark);

		parser->_i_st = NULL;
		if (TFW_STR_EMPTY(&req->mark)) {
			/*
			 * If 'req->mark' is empty - the mark isn't matched,
			 * and we can move to 'Req_UriAbsPath' (because if
			 * we here, the initial '/' is already found).
			 */
			__FSM_MOVE_nf(Req_UriAbsPath, __fsm_n, &req->uri_path);
		}
		BUG_ON(!__fsm_n);
		__FSM_MOVE_nofixup_n(Req_UriMarkEnd, __fsm_n);
	}

	__FSM_STATE(Req_UriMarkEnd) {
		if (likely(c == '/')) {
			__msg_field_open(&req->uri_path, p);
			__FSM_MOVE_f(Req_UriAbsPath, &req->uri_path);
		}
		else if (c == ' ') {
			__FSM_MOVE_nofixup(Req_HttpVer);
		}
		TFW_PARSER_BLOCK(Req_UriMarkEnd);
	}

	/*
	 * URI abs_path.
	 *
	 * TODO: the code parses abs_path as well as query string.
	 * E.g., we get "/foo/bar/baz?query#fragment" instead of "/foo/bar/baz"
	 * as we should according to RFC 2616 (3.2.2) and RFC 7230 (2.7):
	 *
	 * http_URL = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]]
	 *
	 * So the alphabet contains characters valid for query but invalid for
	 * abs_path. In a similar way, that violates RFC 7230 that distinguishes
	 * "absolute-path" from "query" and "fragment" components.
	 *
	 * Meantime it's unclear whether we really need to distinguish these two
	 * string types, probably this work is for application layer...
	 */
	__FSM_STATE(Req_UriAbsPath) {
		/* Optimize single '/' case. */
		if (c == ' ') {
			__msg_field_finish_pos(&req->uri_path, p, 0);
			__FSM_MOVE_nofixup(Req_HttpVer);
		}
		__FSM_MATCH_MOVE_pos_f(uri, Req_UriAbsPath, &req->uri_path);
		if (unlikely(*(p + __fsm_sz) != ' '))
			TFW_PARSER_BLOCK(Req_UriAbsPath);
		__msg_field_finish_pos(&req->uri_path, p, __fsm_sz);
		__FSM_MOVE_nofixup_n(Req_HttpVer, __fsm_sz + 1);
	}

	/* HTTP version */
	__FSM_STATE(Req_HttpVer) {
		if (unlikely(!__data_available(p, 8))) {
			/* Slow path. */
			if (c == 'H')
				__FSM_MOVE_nofixup(Req_HttpVerT1);
			TFW_PARSER_BLOCK(Req_HttpVer);
		}
		/* Fast path. */
		switch (*(unsigned long *)p) {
		case TFW_CHAR8_INT('H', 'T', 'T', 'P', '/', '1', '.', '1'):
			req->version = TFW_HTTP_VER_11;
			__FSM_MOVE_nofixup_n(RGen_EoL, 8);
		case TFW_CHAR8_INT('H', 'T', 'T', 'P', '/', '1', '.', '0'):
			req->version = TFW_HTTP_VER_10;
			__FSM_MOVE_nofixup_n(RGen_EoL, 8);
		default:
			TFW_PARSER_BLOCK(Req_HttpVer);
		}
	}

	/* ----------------    Header Lines    ---------------- */

	/*
	 * The start of an HTTP header or the end of the header part
	 * of the request. There is a switch for the first character
	 * of a header field name.
	 */
	__FSM_STATE(RGen_Hdr) {
		TFW_HTTP_PARSE_CRLF();

		tfw_http_msg_hdr_open(msg, p);

		switch (TFW_LC(c)) {
		case 'a':
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'c', 'c', 'e', 'p')
				   && TFW_LC(*(p + 6)) == 't'
				   && *(p + 13) == ':'))
			{
				parser->_i_st = &&Req_HdrAcceptV;
				__FSM_MOVE_n(RGen_OWS, 7);
			}
			if (likely(__data_available(p, 14)
				   && C8_INT_LCM(p + 1, 'u', 't', 'h', 'o',
							'r', 'i', 'z', 'a')
				   && C4_INT_LCM(p + 9, 't', 'i', 'o', 'n')
				   && *(p + 13) == ':'))
			{
				parser->_i_st = &&Req_HdrAuthorizationV;
				__FSM_MOVE_n(RGen_OWS, 14);
			}
			__FSM_MOVE(Req_HdrA);
		case 'c':
			/* Ensure we have enough data for largest match. */
			if (unlikely(!__data_available(p, 14)))
				__FSM_MOVE(Req_HdrC);
			/* Quick switch for HTTP headers with the same prefix. */
			switch (TFW_P2LCINT(p + 1)) {
			case TFW_CHAR4_INT('a', 'c', 'h', 'e'):
				if (likely(*(p + 5) == '-'
					   && C8_INT7_LCM(p + 6, 'c', 'o', 'n',
							  't', 'r', 'o', 'l',
							  ':')))
				{
					parser->_i_st = &&Req_HdrCache_ControlV;
					__FSM_MOVE_n(RGen_OWS, 14);
				}
				__FSM_MOVE_n(RGen_HdrOther, 5);
			case TFW_CHAR4_INT('o', 'n', 'n', 'e'):
				if (likely(C4_INT_LCM(p + 5, 'c', 't', 'i', 'o')
					   && TFW_LC(*(p + 9)) == 'n'
					   && *(p + 10) == ':'))
				{
					parser->_i_st = &&Req_HdrConnectionV;
					__FSM_MOVE_n(RGen_OWS, 11);
				}
				__FSM_MOVE_n(RGen_HdrOther, 5);
			case TFW_CHAR4_INT('o', 'n', 't', 'e'):
				if (likely(TFW_LC(*(p + 5)) == 'n'
					   && TFW_LC(*(p + 6)) == 't'
					   && *(p + 7) == '-'))
				{
					__FSM_MOVE_n(Req_HdrContent_, 8);
				}
				__FSM_MOVE_n(RGen_HdrOther, 5);
			case TFW_CHAR4_INT('o', 'o', 'k', 'i'):
				if (likely(TFW_LC(*(p + 5)) == 'e'
					   && *(p + 6) == ':'))
				{
					parser->_i_st = &&Req_HdrCookieV;
					__FSM_MOVE_n(RGen_OWS, 7);
				}
				__FSM_MOVE_n(RGen_HdrOther, 5);
			default:
				__FSM_MOVE(RGen_HdrOther);
			}
		case 'h':
			if (likely(__data_available(p, 5)
				   && C4_INT3_LCM(p + 1, 'o', 's', 't', ':')))
			{
				parser->_i_st = &&Req_HdrHostV;
				parser->_hdr_tag = TFW_HTTP_HDR_HOST;
				__FSM_MOVE_n(RGen_OWS, 5);
			}
			__FSM_MOVE(Req_HdrH);
		case 'i':
			if (likely(__data_available(p, 18)
				   && TFW_LC(*(p + 1)) == 'f'
				   && *(p + 2) == '-'
				   && C8_INT_LCM(p + 3, 'm', 'o', 'd', 'i',
							'f', 'i', 'e', 'd')
				   && *(p + 11) == '-'
				   && C4_INT_LCM(p + 12, 's', 'i', 'n', 'c')
				   && TFW_LC(*(p + 16)) == 'e'
				   && *(p + 17) == ':'))
			{
				parser->_i_st = &&Req_HdrIf_Modified_SinceV;
				__FSM_MOVE_n(RGen_OWS, 18);
			}
			if (likely(__data_available(p, 14)
				   && TFW_LC(*(p + 1)) == 'f'
				   && *(p + 2) == '-'
				   && C4_INT_LCM(p + 3, 'n', 'o', 'n', 'e')
				   && *(p + 7) == '-'
				   && C4_INT_LCM(p + 8, 'm', 'a', 't', 'c')
				   && TFW_LC(*(p + 12)) == 'h'
				   && *(p + 13) == ':'))
			{
				parser->_i_st = &&Req_HdrIf_None_MatchV;
				__FSM_MOVE_n(RGen_OWS, 14);
			}
			__FSM_MOVE(Req_HdrI);
		case 'k':
			if (likely(__data_available(p, 11)
				   && C4_INT_LCM(p, 'k', 'e', 'e', 'p')
				   && *(p + 4) == '-'
				   && C4_INT_LCM(p + 5, 'a', 'l', 'i', 'v')
				   && TFW_LC(*(p + 9)) == 'e'
				   && *(p + 10) == ':'))
			{
				parser->_i_st = &&Req_HdrKeep_AliveV;
				__FSM_MOVE_n(RGen_OWS, 11);
			}
			__FSM_MOVE(Req_HdrK);
		case 'p':
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'r', 'a', 'g', 'm')
				   && TFW_LC(*(p + 5)) == 'a'
				   && *(p + 6) == ':'))
			{
				parser->_i_st = &&Req_HdrPragmaV;
				__FSM_MOVE_n(RGen_OWS, 7);
			}
			__FSM_MOVE(Req_HdrP);
		case 'r':
			if (likely(__data_available(p, 8)
				   && C4_INT_LCM(p + 1, 'e', 'f', 'e', 'r')
				   && TFW_LC(*(p + 5)) == 'e'
				   && TFW_LC(*(p + 6)) == 'r'
				   && *(p + 7) == ':'))
			{
				parser->_i_st = &&Req_HdrRefererV;
				__FSM_MOVE_n(RGen_OWS, 8);
			}
			__FSM_MOVE(Req_HdrR);
		case 't':
			if (likely(__data_available(p, 18)
				   && C8_INT_LCM(p, 't', 'r', 'a', 'n',
						    's', 'f', 'e', 'r')
				   && *(p + 8) == '-'
				   && C8_INT_LCM(p + 9, 'e', 'n', 'c', 'o',
							'd', 'i', 'n', 'g')
				   && *(p + 17) == ':'))
			{
				parser->_i_st = &&Req_HdrTransfer_EncodingV;
				__FSM_MOVE_n(RGen_OWS, 18);
			}
			__FSM_MOVE(Req_HdrT);
		case 'x':
			if (likely(__data_available(p, 16)
				   && *(p + 1) == '-'
				   && *(p + 11) == '-'
				   /* Safe match: '-' = 0x2d = 0x2d | 0x20. */
				   && C8_INT_LCM(p, 'x', '-', 'f', 'o',
						 'r', 'w', 'a', 'r')
				   && C8_INT7_LCM(p + 8, 'd', 'e', 'd', '-',
						  'f', 'o', 'r', ':')))
			{
				parser->_i_st = &&Req_HdrX_Forwarded_ForV;
				__FSM_MOVE_n(RGen_OWS, 16);
			}
			__FSM_MOVE(Req_HdrX);
		case 'u':
			if (likely(__data_available(p, 11)
				   && C4_INT_LCM(p, 'u', 's', 'e', 'r')
				   && *(p + 4) == '-'
				   && C4_INT_LCM(p + 5, 'a', 'g', 'e', 'n')
				   && TFW_LC(*(p + 9)) == 't'
				   && *(p + 10) == ':'))
			{
				parser->_i_st = &&Req_HdrUser_AgentV;
				__FSM_MOVE_n(RGen_OWS, 11);
			}
			__FSM_MOVE(Req_HdrU);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* Content-* headers. */
	__FSM_STATE(Req_HdrContent_) {
		switch (TFW_LC(c)) {
		case 'l':
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'e', 'n', 'g', 't')
				   && TFW_LC(*(p + 5)) == 'h'
				   && *(p + 6) == ':'))
			{
				parser->_i_st = &&Req_HdrContent_LengthV;
				__FSM_MOVE_n(RGen_OWS, 7);
			}
			__FSM_MOVE(Req_HdrContent_L);
		case 't':
			if (likely(__data_available(p, 5)
				   && C4_INT3_LCM(p + 1, 'y', 'p', 'e', ':')))
			{
				parser->_i_st = &&Req_HdrContent_TypeV;
				__FSM_MOVE_n(RGen_OWS, 5);
			}
			__FSM_MOVE(Req_HdrContent_T);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* 'Accept:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrAcceptV, req, __req_parse_accept);

	/* 'Authorization:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrAuthorizationV, req,
				  __req_parse_authorization);

	/* 'Cache-Control:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrCache_ControlV, req,
				  __req_parse_cache_control);

	/* 'Connection:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrConnectionV, msg, __parse_connection,
				   TFW_HTTP_HDR_CONNECTION);

	/* 'Content-Length:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrContent_LengthV, msg,
				   __parse_content_length,
				   TFW_HTTP_HDR_CONTENT_LENGTH);

	/* 'Content-Type:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrContent_TypeV, msg,
				     __req_parse_content_type,
				     TFW_HTTP_HDR_CONTENT_TYPE, 0);

	/* 'Host:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrHostV, req, __req_parse_host,
				   TFW_HTTP_HDR_HOST);

	/* 'If-None-Match:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrIf_None_MatchV, msg, __parse_etag,
				     TFW_HTTP_HDR_IF_NONE_MATCH, 0);

	/* 'If-Modified-Since:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrIf_Modified_SinceV, msg,
				  __req_parse_if_msince);

	/* 'Keep-Alive:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrKeep_AliveV, msg, __parse_keep_alive,
				   TFW_HTTP_HDR_KEEP_ALIVE);

	/* 'Pragma:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrPragmaV, msg, __parse_pragma);

	/* 'Referer:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrRefererV, msg, __req_parse_referer,
				   TFW_HTTP_HDR_REFERER);

	/* 'Transfer-Encoding:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrTransfer_EncodingV, msg,
				   __parse_transfer_encoding,
				   TFW_HTTP_HDR_TRANSFER_ENCODING);

	/* 'X-Forwarded-For:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrX_Forwarded_ForV, msg,
				     __req_parse_x_forwarded_for,
				     TFW_HTTP_HDR_X_FORWARDED_FOR, 0);

	/* 'User-Agent:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrUser_AgentV, msg,
				   __req_parse_user_agent,
				   TFW_HTTP_HDR_USER_AGENT);

	/* 'Cookie:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrCookieV, msg, __req_parse_cookie,
				     TFW_HTTP_HDR_COOKIE, 0);

	RGEN_HDR_OTHER();
	RGEN_OWS();
	RGEN_EOL();
	RGEN_CRLF();


	/* ----------------    Request body    ---------------- */

	TFW_HTTP_INIT_REQ_BODY_PARSING();
	TFW_HTTP_PARSE_BODY();

	/* ----------------    Improbable states    ---------------- */

	/* HTTP Method processing. */
	/* GET */
	__FSM_METH_MOVE(Req_MethG, 'E', Req_MethGe);
	__FSM_METH_MOVE_finish(Req_MethGe, 'T', TFW_HTTP_METH_GET);
	/* P* */
	__FSM_STATE(Req_MethP) {
		switch (c) {
		case 'O':
			__FSM_MOVE_nofixup(Req_MethPo);
		case 'A':
			__FSM_MOVE_nofixup(Req_MethPa);
		case 'R':
			__FSM_MOVE_nofixup(Req_MethPr);
		case 'U':
			__FSM_MOVE_nofixup(Req_MethPu);
		}
		__FSM_MOVE_nofixup(Req_MethodUnknown);
	}
	/* POST */
	__FSM_METH_MOVE(Req_MethPo, 'S', Req_MethPos);
	__FSM_METH_MOVE_finish(Req_MethPos, 'T', TFW_HTTP_METH_POST);
	/* PATCH */
	__FSM_METH_MOVE(Req_MethPa, 'T', Req_MethPat);
	__FSM_METH_MOVE(Req_MethPat, 'C', Req_MethPatc);
	__FSM_METH_MOVE_finish(Req_MethPatc, 'H', TFW_HTTP_METH_PATCH);
	/* PROP* */
	__FSM_METH_MOVE(Req_MethPr, 'O', Req_MethPro);
	__FSM_METH_MOVE(Req_MethPro, 'P', Req_MethProp);
	__FSM_STATE(Req_MethProp) {
		switch (c) {
		case 'F':
			__FSM_MOVE_nofixup(Req_MethPropf);
		case 'P':
			__FSM_MOVE_nofixup(Req_MethPropp);
		}
		__FSM_MOVE_nofixup(Req_MethodUnknown);
	}
	/* PROPFIND */
	__FSM_METH_MOVE(Req_MethPropf, 'I', Req_MethPropfi);
	__FSM_METH_MOVE(Req_MethPropfi, 'N', Req_MethPropfin);
	__FSM_METH_MOVE_finish(Req_MethPropfin, 'D', TFW_HTTP_METH_PROPFIND);
	/* PROPPATCH */
	__FSM_METH_MOVE(Req_MethPropp, 'A', Req_MethProppa);
	__FSM_METH_MOVE(Req_MethProppa, 'T', Req_MethProppat);
	__FSM_METH_MOVE(Req_MethProppat, 'C', Req_MethProppatc);
	__FSM_METH_MOVE_finish(Req_MethProppatc, 'H', TFW_HTTP_METH_PROPPATCH);
	/* PU* */
	__FSM_STATE(Req_MethPu) {
		switch (c) {
		case 'R':
			__FSM_MOVE_nofixup(Req_MethPur);
		case 'T':
			/* PUT */
			req->method = TFW_HTTP_METH_PUT;
			__FSM_MOVE_nofixup(Req_MUSpace);
		}
		__FSM_MOVE_nofixup(Req_MethodUnknown);
	}
	/* PURGE */
	__FSM_METH_MOVE(Req_MethPur, 'G', Req_MethPurg);
	__FSM_METH_MOVE_finish(Req_MethPurg, 'E', TFW_HTTP_METH_PURGE);
	/* HEAD */
	__FSM_METH_MOVE(Req_MethH, 'E', Req_MethHe);
	__FSM_METH_MOVE(Req_MethHe, 'A', Req_MethHea);
	__FSM_METH_MOVE_finish(Req_MethHea, 'D', TFW_HTTP_METH_HEAD);
	/* COPY */
	__FSM_METH_MOVE(Req_MethC, 'O', Req_MethCo);
	__FSM_METH_MOVE(Req_MethCo, 'P', Req_MethCop);
	__FSM_METH_MOVE_finish(Req_MethCop, 'Y', TFW_HTTP_METH_COPY);
	/* DELETE */
	__FSM_METH_MOVE(Req_MethD, 'E', Req_MethDe);
	__FSM_METH_MOVE(Req_MethDe, 'L', Req_MethDel);
	__FSM_METH_MOVE(Req_MethDel, 'E', Req_MethDele);
	__FSM_METH_MOVE(Req_MethDele, 'T', Req_MethDelet);
	__FSM_METH_MOVE_finish(Req_MethDelet, 'E', TFW_HTTP_METH_DELETE);
	/* LOCK */
	__FSM_METH_MOVE(Req_MethL, 'O', Req_MethLo);
	__FSM_METH_MOVE(Req_MethLo, 'C', Req_MethLoc);
	__FSM_METH_MOVE_finish(Req_MethLoc, 'K', TFW_HTTP_METH_LOCK);
	/* M* */
	__FSM_STATE(Req_MethM) {
		switch (c) {
		case 'K':
			__FSM_MOVE_nofixup(Req_MethMk);
		case 'O':
			__FSM_MOVE_nofixup(Req_MethMo);
		}
		__FSM_MOVE_nofixup(Req_MethodUnknown);
	}
	/* MKCOL */
	__FSM_METH_MOVE(Req_MethMk, 'C', Req_MethMkc);
	__FSM_METH_MOVE(Req_MethMkc, 'O', Req_MethMkco);
	__FSM_METH_MOVE_finish(Req_MethMkco, 'L', TFW_HTTP_METH_MKCOL);
	/* MOVE */
	__FSM_METH_MOVE(Req_MethMo, 'V', Req_MethMov);
	__FSM_METH_MOVE_finish(Req_MethMov, 'E', TFW_HTTP_METH_MOVE);
	/* OPTIONS */
	__FSM_METH_MOVE(Req_MethO, 'P', Req_MethOp);
	__FSM_METH_MOVE(Req_MethOp, 'T', Req_MethOpt);
	__FSM_METH_MOVE(Req_MethOpt, 'I', Req_MethOpti);
	__FSM_METH_MOVE(Req_MethOpti, 'O', Req_MethOptio);
	__FSM_METH_MOVE(Req_MethOptio, 'N', Req_MethOption);
	__FSM_METH_MOVE_finish(Req_MethOption, 'S', TFW_HTTP_METH_OPTIONS);
	/* TRACE */
	__FSM_METH_MOVE(Req_MethT, 'R', Req_MethTr);
	__FSM_METH_MOVE(Req_MethTr, 'A', Req_MethTra);
	__FSM_METH_MOVE(Req_MethTra, 'C', Req_MethTrac);
	__FSM_METH_MOVE_finish(Req_MethTrac, 'E', TFW_HTTP_METH_TRACE);
	/* UNLOCK */
	__FSM_METH_MOVE(Req_MethU, 'N', Req_MethUn);
	__FSM_METH_MOVE(Req_MethUn, 'L', Req_MethUnl);
	__FSM_METH_MOVE(Req_MethUnl, 'O', Req_MethUnlo);
	__FSM_METH_MOVE(Req_MethUnlo, 'C', Req_MethUnloc);
	__FSM_METH_MOVE_finish(Req_MethUnloc, 'K', TFW_HTTP_METH_UNLOCK);

	/* process URI scheme: "http://" */
	__FSM_TX_LC_nofixup(Req_UriSchH, 't', Req_UriSchHt);
	__FSM_TX_LC_nofixup(Req_UriSchHt, 't', Req_UriSchHtt);
	__FSM_TX_LC_nofixup(Req_UriSchHtt, 'p', Req_UriSchHttp);
	__FSM_TX_nofixup(Req_UriSchHttp, ':', Req_UriSchHttpColon);
	__FSM_TX_nofixup(Req_UriSchHttpColon, '/', Req_UriSchHttpColonSlash);
	__FSM_TX_nofixup(Req_UriSchHttpColonSlash, '/', Req_UriAuthorityStart);

	/* Parse HTTP version (1.1 and 1.0 are supported). */
	__FSM_TX_nofixup(Req_HttpVerT1, 'T', Req_HttpVerT2);
	__FSM_TX_nofixup(Req_HttpVerT2, 'T', Req_HttpVerP);
	__FSM_TX_nofixup(Req_HttpVerP, 'P', Req_HttpVerSlash);
	__FSM_TX_nofixup(Req_HttpVerSlash, '/', Req_HttpVer11);
	__FSM_TX_nofixup(Req_HttpVer11, '1', Req_HttpVerDot);
	__FSM_TX_nofixup(Req_HttpVerDot, '.', Req_HttpVer12);
	__FSM_STATE(Req_HttpVer12) {
		switch(c) {
		case '1':
			req->version = TFW_HTTP_VER_11;
			__FSM_MOVE_nofixup(RGen_EoL);
		case '0':
			req->version = TFW_HTTP_VER_10;
			__FSM_MOVE_nofixup(RGen_EoL);
		default:
			TFW_PARSER_BLOCK(Req_HttpVer12);
		}
	}

	__FSM_STATE(Req_HdrA) {
		switch (TFW_LC(c)) {
		case 'c':
			__FSM_MOVE(Req_HdrAc);
		case 'u':
			__FSM_MOVE(Req_HdrAu);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* Accept header processing. */
	__FSM_TX_AF(Req_HdrAc, 'c', Req_HdrAcc);
	__FSM_TX_AF(Req_HdrAcc, 'e', Req_HdrAcce);
	__FSM_TX_AF(Req_HdrAcce, 'p', Req_HdrAccep);
	__FSM_TX_AF(Req_HdrAccep, 't', Req_HdrAccept);
	__FSM_TX_AF(Req_HdrAccept, ':', Req_HdrAcceptV);

	/* Authorization header processing. */
	__FSM_TX_AF(Req_HdrAu, 't', Req_HdrAut);
	__FSM_TX_AF(Req_HdrAut, 'h', Req_HdrAuth);
	__FSM_TX_AF(Req_HdrAuth, 'o', Req_HdrAutho);
	__FSM_TX_AF(Req_HdrAutho, 'r', Req_HdrAuthor);
	__FSM_TX_AF(Req_HdrAuthor, 'i', Req_HdrAuthori);
	__FSM_TX_AF(Req_HdrAuthori, 'z', Req_HdrAuthoriz);
	__FSM_TX_AF(Req_HdrAuthoriz, 'a', Req_HdrAuthoriza);
	__FSM_TX_AF(Req_HdrAuthoriza, 't', Req_HdrAuthorizat);
	__FSM_TX_AF(Req_HdrAuthorizat, 'i', Req_HdrAuthorizati);
	__FSM_TX_AF(Req_HdrAuthorizati, 'o', Req_HdrAuthorizatio);
	__FSM_TX_AF(Req_HdrAuthorizatio, 'n', Req_HdrAuthorization);
	__FSM_TX_AF_OWS(Req_HdrAuthorization, Req_HdrAuthorizationV);

	__FSM_STATE(Req_HdrC) {
		switch (TFW_LC(c)) {
		case 'a':
			__FSM_MOVE(Req_HdrCa);
		case 'o':
			__FSM_MOVE(Req_HdrCo);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* Cache-Control header processing. */
	__FSM_TX_AF(Req_HdrCa, 'c', Req_HdrCac);
	__FSM_TX_AF(Req_HdrCac, 'h', Req_HdrCach);
	__FSM_TX_AF(Req_HdrCach, 'e', Req_HdrCache);
	__FSM_TX_AF(Req_HdrCache, '-', Req_HdrCache_);
	__FSM_TX_AF(Req_HdrCache_, 'c', Req_HdrCache_C);
	__FSM_TX_AF(Req_HdrCache_C, 'o', Req_HdrCache_Co);
	__FSM_TX_AF(Req_HdrCache_Co, 'n', Req_HdrCache_Con);
	__FSM_TX_AF(Req_HdrCache_Con, 't', Req_HdrCache_Cont);
	__FSM_TX_AF(Req_HdrCache_Cont, 'r', Req_HdrCache_Contr);
	__FSM_TX_AF(Req_HdrCache_Contr, 'o', Req_HdrCache_Contro);
	__FSM_TX_AF(Req_HdrCache_Contro, 'l', Req_HdrCache_Control);
	__FSM_TX_AF_OWS(Req_HdrCache_Control, Req_HdrCache_ControlV);

	__FSM_STATE(Req_HdrCo) {
		switch (TFW_LC(c)) {
		case 'n':
			__FSM_MOVE(Req_HdrCon);
		case 'o':
			__FSM_MOVE(Req_HdrCoo);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* Connection header processing. */
	__FSM_STATE(Req_HdrCon) {
		switch (TFW_LC(c)) {
		case 'n':
			__FSM_MOVE(Req_HdrConn);
		case 't':
			__FSM_MOVE(Req_HdrCont);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}
	__FSM_TX_AF(Req_HdrConn, 'e', Req_HdrConne);
	__FSM_TX_AF(Req_HdrConne, 'c', Req_HdrConnec);
	__FSM_TX_AF(Req_HdrConnec, 't', Req_HdrConnect);
	__FSM_TX_AF(Req_HdrConnect, 'i', Req_HdrConnecti);
	__FSM_TX_AF(Req_HdrConnecti, 'o', Req_HdrConnectio);
	__FSM_TX_AF(Req_HdrConnectio, 'n', Req_HdrConnection);
	__FSM_TX_AF_OWS(Req_HdrConnection, Req_HdrConnectionV);

	/* Content-* headers processing. */
	__FSM_TX_AF(Req_HdrCont, 'e', Req_HdrConte);
	__FSM_TX_AF(Req_HdrConte, 'n', Req_HdrConten);
	__FSM_TX_AF(Req_HdrConten, 't', Req_HdrContent);
	__FSM_TX_AF(Req_HdrContent, '-', Req_HdrContent_);

	/* Content-Length header processing. */
	__FSM_TX_AF(Req_HdrContent_L, 'e', Req_HdrContent_Le);
	__FSM_TX_AF(Req_HdrContent_Le, 'n', Req_HdrContent_Len);
	__FSM_TX_AF(Req_HdrContent_Len, 'g', Req_HdrContent_Leng);
	__FSM_TX_AF(Req_HdrContent_Leng, 't', Req_HdrContent_Lengt);
	__FSM_TX_AF(Req_HdrContent_Lengt, 'h', Req_HdrContent_Length);
	__FSM_TX_AF_OWS(Req_HdrContent_Length, Req_HdrContent_LengthV);

	/* Content-Type header processing. */
	__FSM_TX_AF(Req_HdrContent_T, 'y', Req_HdrContent_Ty);
	__FSM_TX_AF(Req_HdrContent_Ty, 'p', Req_HdrContent_Typ);
	__FSM_TX_AF(Req_HdrContent_Typ, 'e', Req_HdrContent_Type);
	__FSM_TX_AF_OWS(Req_HdrContent_Type, Req_HdrContent_TypeV);

	/* Host header processing. */
	__FSM_TX_AF(Req_HdrH, 'o', Req_HdrHo);
	__FSM_TX_AF(Req_HdrHo, 's', Req_HdrHos);
	__FSM_TX_AF(Req_HdrHos, 't', Req_HdrHost);
	/* NOTE: Allow empty host field-value there. RFC 7230 5.4. */
	__FSM_STATE(Req_HdrHost) {
		if (likely(c == ':')) {
			parser->_i_st = &&Req_HdrHostV;
			__FSM_MOVE(RGen_OWS);
		}
		__FSM_JMP(RGen_HdrOther);
	}

	/* If-* header processing. */
	__FSM_TX_AF(Req_HdrI, 'f', Req_HdrIf);
	__FSM_TX_AF(Req_HdrIf, '-', Req_HdrIf_);
	__FSM_STATE(Req_HdrIf_) {
		switch (TFW_LC(c)) {
		case 'm':
			__FSM_MOVE(Req_HdrIf_M);
		case 'n':
			__FSM_MOVE(Req_HdrIf_N);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* If-Modified-Since header processing. */
	__FSM_TX_AF(Req_HdrIf_M, 'o', Req_HdrIf_Mo);
	__FSM_TX_AF(Req_HdrIf_Mo, 'd', Req_HdrIf_Mod);
	__FSM_TX_AF(Req_HdrIf_Mod, 'i', Req_HdrIf_Modi);
	__FSM_TX_AF(Req_HdrIf_Modi, 'f', Req_HdrIf_Modif);
	__FSM_TX_AF(Req_HdrIf_Modif, 'i', Req_HdrIf_Modifi);
	__FSM_TX_AF(Req_HdrIf_Modifi, 'e', Req_HdrIf_Modifie);
	__FSM_TX_AF(Req_HdrIf_Modifie, 'd', Req_HdrIf_Modified);
	__FSM_TX_AF(Req_HdrIf_Modified, '-', Req_HdrIf_Modified_);
	__FSM_TX_AF(Req_HdrIf_Modified_, 's', Req_HdrIf_Modified_S);
	__FSM_TX_AF(Req_HdrIf_Modified_S, 'i', Req_HdrIf_Modified_Si);
	__FSM_TX_AF(Req_HdrIf_Modified_Si, 'n', Req_HdrIf_Modified_Sin);
	__FSM_TX_AF(Req_HdrIf_Modified_Sin, 'c', Req_HdrIf_Modified_Sinc);
	__FSM_TX_AF(Req_HdrIf_Modified_Sinc, 'e', Req_HdrIf_Modified_Since);
	__FSM_TX_AF_OWS(Req_HdrIf_Modified_Since, Req_HdrIf_Modified_SinceV);

	/* If-None-Match header processing. */
	__FSM_TX_AF(Req_HdrIf_N, 'o', Req_HdrIf_No);
	__FSM_TX_AF(Req_HdrIf_No, 'n', Req_HdrIf_Non);
	__FSM_TX_AF(Req_HdrIf_Non, 'e', Req_HdrIf_None);
	__FSM_TX_AF(Req_HdrIf_None, '-', Req_HdrIf_None_);
	__FSM_TX_AF(Req_HdrIf_None_, 'm', Req_HdrIf_None_M);
	__FSM_TX_AF(Req_HdrIf_None_M, 'a', Req_HdrIf_None_Ma);
	__FSM_TX_AF(Req_HdrIf_None_Ma, 't', Req_HdrIf_None_Mat);
	__FSM_TX_AF(Req_HdrIf_None_Mat, 'c', Req_HdrIf_None_Matc);
	__FSM_TX_AF(Req_HdrIf_None_Matc, 'h', Req_HdrIf_None_Match);
	__FSM_TX_AF_OWS(Req_HdrIf_None_Match, Req_HdrIf_None_MatchV);

	/* Keep-Alive header processing. */
	__FSM_TX_AF(Req_HdrK, 'e', Req_HdrKe);
	__FSM_TX_AF(Req_HdrKe, 'e', Req_HdrKee);
	__FSM_TX_AF(Req_HdrKee, 'p', Req_HdrKeep);
	__FSM_TX_AF(Req_HdrKeep, '-', Req_HdrKeep_);
	__FSM_TX_AF(Req_HdrKeep_, 'a', Req_HdrKeep_A);
	__FSM_TX_AF(Req_HdrKeep_A, 'l', Req_HdrKeep_Al);
	__FSM_TX_AF(Req_HdrKeep_Al, 'i', Req_HdrKeep_Ali);
	__FSM_TX_AF(Req_HdrKeep_Ali, 'v', Req_HdrKeep_Aliv);
	__FSM_TX_AF(Req_HdrKeep_Aliv, 'e', Req_HdrKeep_Alive);
	__FSM_TX_AF_OWS(Req_HdrKeep_Alive, Req_HdrKeep_AliveV);

	/* Pragma header processing. */
	__FSM_TX_AF(Req_HdrP, 'r', Req_HdrPr);
	__FSM_TX_AF(Req_HdrPr, 'a', Req_HdrPra);
	__FSM_TX_AF(Req_HdrPra, 'g', Req_HdrPrag);
	__FSM_TX_AF(Req_HdrPrag, 'm', Req_HdrPragm);
	__FSM_TX_AF(Req_HdrPragm, 'a', Req_HdrPragma);
	__FSM_TX_AF_OWS(Req_HdrPragma, Req_HdrPragmaV);

	/* Referer header processing. */
	__FSM_TX_AF(Req_HdrR, 'e', Req_HdrRe);
	__FSM_TX_AF(Req_HdrRe, 'f', Req_HdrRef);
	__FSM_TX_AF(Req_HdrRef, 'e', Req_HdrRefe);
	__FSM_TX_AF(Req_HdrRefe, 'r', Req_HdrRefer);
	__FSM_TX_AF(Req_HdrRefer, 'e', Req_HdrRefere);
	__FSM_TX_AF(Req_HdrRefere, 'r', Req_HdrReferer);
	__FSM_TX_AF_OWS(Req_HdrReferer, Req_HdrRefererV);

	/* Transfer-Encoding header processing. */
	__FSM_TX_AF(Req_HdrT, 'r', Req_HdrTr);
	__FSM_TX_AF(Req_HdrTr, 'a', Req_HdrTra);
	__FSM_TX_AF(Req_HdrTra, 'n', Req_HdrTran);
	__FSM_TX_AF(Req_HdrTran, 's', Req_HdrTrans);
	__FSM_TX_AF(Req_HdrTrans, 'f', Req_HdrTransf);
	__FSM_TX_AF(Req_HdrTransf, 'e', Req_HdrTransfe);
	__FSM_TX_AF(Req_HdrTransfe, 'r', Req_HdrTransfer);
	__FSM_TX_AF(Req_HdrTransfer, '-', Req_HdrTransfer_);
	__FSM_TX_AF(Req_HdrTransfer_, 'e', Req_HdrTransfer_E);
	__FSM_TX_AF(Req_HdrTransfer_E, 'n', Req_HdrTransfer_En);
	__FSM_TX_AF(Req_HdrTransfer_En, 'c', Req_HdrTransfer_Enc);
	__FSM_TX_AF(Req_HdrTransfer_Enc, 'o', Req_HdrTransfer_Enco);
	__FSM_TX_AF(Req_HdrTransfer_Enco, 'd', Req_HdrTransfer_Encod);
	__FSM_TX_AF(Req_HdrTransfer_Encod, 'i', Req_HdrTransfer_Encodi);
	__FSM_TX_AF(Req_HdrTransfer_Encodi, 'n', Req_HdrTransfer_Encodin);
	__FSM_TX_AF(Req_HdrTransfer_Encodin, 'g', Req_HdrTransfer_Encoding);
	__FSM_TX_AF_OWS(Req_HdrTransfer_Encoding, Req_HdrTransfer_EncodingV);

	/* X-Forwarded-For header processing. */
	__FSM_TX_AF(Req_HdrX, '-', Req_HdrX_);
	__FSM_TX_AF(Req_HdrX_, 'f', Req_HdrX_F);
	__FSM_TX_AF(Req_HdrX_F, 'o', Req_HdrX_Fo);
	__FSM_TX_AF(Req_HdrX_Fo, 'r', Req_HdrX_For);
	__FSM_TX_AF(Req_HdrX_For, 'w', Req_HdrX_Forw);
	__FSM_TX_AF(Req_HdrX_Forw, 'a', Req_HdrX_Forwa);
	__FSM_TX_AF(Req_HdrX_Forwa, 'r', Req_HdrX_Forwar);
	__FSM_TX_AF(Req_HdrX_Forwar, 'd', Req_HdrX_Forward);
	__FSM_TX_AF(Req_HdrX_Forward, 'e', Req_HdrX_Forwarde);
	__FSM_TX_AF(Req_HdrX_Forwarde, 'd', Req_HdrX_Forwarded);
	__FSM_TX_AF(Req_HdrX_Forwarded, '-', Req_HdrX_Forwarded_);
	__FSM_TX_AF(Req_HdrX_Forwarded_, 'f', Req_HdrX_Forwarded_F);
	__FSM_TX_AF(Req_HdrX_Forwarded_F, 'o', Req_HdrX_Forwarded_Fo);
	__FSM_TX_AF(Req_HdrX_Forwarded_Fo, 'r', Req_HdrX_Forwarded_For);
	/*
	 * NOTE: we don't eat OWS here because RGEN_OWS() doesn't allow
	 * '[' after OWS.
	 */
	__FSM_TX_AF_OWS(Req_HdrX_Forwarded_For,  Req_HdrX_Forwarded_ForV);

	/* User-Agent header processing. */
	__FSM_TX_AF(Req_HdrU, 's', Req_HdrUs);
	__FSM_TX_AF(Req_HdrUs, 'e', Req_HdrUse);
	__FSM_TX_AF(Req_HdrUse, 'r', Req_HdrUser);
	__FSM_TX_AF(Req_HdrUser, '-', Req_HdrUser_);
	__FSM_TX_AF(Req_HdrUser_, 'a', Req_HdrUser_A);
	__FSM_TX_AF(Req_HdrUser_A, 'g', Req_HdrUser_Ag);
	__FSM_TX_AF(Req_HdrUser_Ag, 'e', Req_HdrUser_Age);
	__FSM_TX_AF(Req_HdrUser_Age, 'n', Req_HdrUser_Agen);
	__FSM_TX_AF(Req_HdrUser_Agen, 't', Req_HdrUser_Agent);
	__FSM_TX_AF_OWS(Req_HdrUser_Agent, Req_HdrUser_AgentV);

	/* Cookie header processing. */
	__FSM_TX_AF(Req_HdrCoo, 'k', Req_HdrCook);
	__FSM_TX_AF(Req_HdrCook, 'i', Req_HdrCooki);
	__FSM_TX_AF(Req_HdrCooki, 'e', Req_HdrCookie);
	__FSM_TX_AF_OWS(Req_HdrCookie, Req_HdrCookieV);

	__FSM_FINISH(req);

	return r;
}
STACK_FRAME_NON_STANDARD(tfw_http_parse_req);

int
tfw_h2_parse_req(void *req_data, unsigned char *data, size_t len,
		 unsigned int *parsed)
{
	int r = TFW_POSTPONE;

	/*
	 * TODO: implement parsing of HTTP/2 frame's payload:
	 * HEADERS/CONTINUATION (through HPACK at first) and DATA.
	 */
	return r;
}

/*
 * ------------------------------------------------------------------------
 *	HTTP response parsing
 * ------------------------------------------------------------------------
 */
static int
__resp_parse_age(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Resp_I_Age) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_ws(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			return __fsm_n;
		resp->cache_ctl.age = parser->_acc;
		parser->_acc = 0;
		__FSM_I_MOVE_n(Resp_I_EoL, __fsm_n);
	}

	__FSM_STATE(Resp_I_EoL) {
		if (IS_WS(c))
			__FSM_I_MOVE(Resp_I_EoL);
		if (IS_CRLF(c)) {
			resp->cache_ctl.flags |= TFW_HTTP_CC_HDR_AGE;
			return __data_off(p);
		}
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__resp_parse_age);

/**
 * Parse response Cache-Control, RFC 2616 14.9
 */
static int
__resp_parse_cache_control(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Resp_I_CC) {
		WARN_ON_ONCE(parser->_acc);
		switch (TFW_LC(c)) {
		case 'm':
			__FSM_I_JMP(Resp_I_CC_m);
		case 'n':
			__FSM_I_JMP(Resp_I_CC_n);
		case 'p':
			__FSM_I_JMP(Resp_I_CC_p);
		case 's':
			__FSM_I_JMP(Resp_I_CC_s);
		}
		__FSM_I_JMP(Resp_I_Ext);
	}

	__FSM_STATE(Resp_I_CC_m) {
		TRY_STR("max-age=", Resp_I_CC_m, Resp_I_CC_MaxAgeV);
		TRY_STR_LAMBDA("must-revalidate", {
			parser->_acc = TFW_HTTP_CC_MUST_REVAL;
		}, Resp_I_CC_m, Resp_I_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Resp_I_Ext);
	}

	__FSM_STATE(Resp_I_CC_n) {
		TRY_STR_LAMBDA("no-cache", {
			parser->_acc = TFW_HTTP_CC_NO_CACHE;
		}, Resp_I_CC_n, Resp_I_Flag);
		TRY_STR_LAMBDA("no-store", {
			parser->_acc = TFW_HTTP_CC_NO_STORE;
		}, Resp_I_CC_n, Resp_I_Flag);
		TRY_STR_LAMBDA("no-transform", {
			parser->_acc = TFW_HTTP_CC_NO_TRANSFORM;
		}, Resp_I_CC_n, Resp_I_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Resp_I_Ext);
	}

	__FSM_STATE(Resp_I_CC_p) {
		TRY_STR_LAMBDA("public", {
			parser->_acc = TFW_HTTP_CC_PUBLIC;
		}, Resp_I_CC_p, Resp_I_Flag);
		TRY_STR_LAMBDA("private", {
			parser->_acc = TFW_HTTP_CC_PRIVATE;
		}, Resp_I_CC_p, Resp_I_Flag);
		TRY_STR_LAMBDA("proxy-revalidate", {
			parser->_acc = TFW_HTTP_CC_PROXY_REVAL;
		}, Resp_I_CC_p, Resp_I_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Resp_I_Ext);
	}

	__FSM_STATE(Resp_I_Flag) {
		WARN_ON_ONCE(!parser->_acc);
		if (IS_WS(c) || c == ',' || IS_CRLF(c)) {
			resp->cache_ctl.flags |= parser->_acc;
			parser->_acc = 0;
			__FSM_I_JMP(Resp_I_EoT);
		}
		__FSM_I_JMP(Resp_I_Ext);
	}

	__FSM_STATE(Resp_I_CC_s) {
		TRY_STR("s-maxage=", Resp_I_CC_s, Resp_I_CC_SMaxAgeV);
		TRY_STR_INIT();
		__FSM_I_JMP(Resp_I_Ext);
	}

	__FSM_STATE(Resp_I_CC_MaxAgeV) {
		if (unlikely(resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE)) {
			resp->cache_ctl.max_age = 0;
			__FSM_I_JMP(Resp_I_Ext);
		}
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0) {
			if (__fsm_n != CSTR_BADLEN)
				return __fsm_n;
			parser->_acc = UINT_MAX;
		}
		resp->cache_ctl.max_age = parser->_acc;
		resp->cache_ctl.flags |= TFW_HTTP_CC_MAX_AGE;
		__FSM_I_MOVE_n(Resp_I_EoT, __fsm_n);
	}

	__FSM_STATE(Resp_I_CC_SMaxAgeV) {
		if (unlikely(resp->cache_ctl.flags & TFW_HTTP_CC_S_MAXAGE)) {
			resp->cache_ctl.s_maxage = 0;
			__FSM_I_JMP(Resp_I_Ext);
		}
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0) {
			if (__fsm_n != CSTR_BADLEN)
				return __fsm_n;
			parser->_acc = UINT_MAX;
		}
		resp->cache_ctl.s_maxage = parser->_acc;
		resp->cache_ctl.flags |= TFW_HTTP_CC_S_MAXAGE;
		__FSM_I_MOVE_n(Resp_I_EoT, __fsm_n);
	}

	__FSM_STATE(Resp_I_Ext) {
		/* TODO: process cache extensions. */
		__FSM_I_MATCH_MOVE(qetoken, Resp_I_Ext);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(Resp_I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c)) {
			parser->_acc = 0;
			return __data_off(p + __fsm_sz);
		}
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(Resp_I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(Resp_I_EoT);

		parser->_acc = 0; /* reinit for next token */

		/*
		 * TODO
		 * - For the time being we don't support field values for
		 *   no-cache and private fields, so just skip '=[token]*'.
		 */
		if (c == '=')
			__FSM_I_MOVE(Resp_I_Ext);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Resp_I_CC);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__resp_parse_cache_control);

/*
 * The value of "Expires:" header field is a date in HTTP-Date format.
 * However, if the format of a date is invalid, that is interpreted
 * as representing a time in the past (i.e., "already expired").
 * See RFC 7234 5.3.
 */
static int
__resp_parse_expires(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	int r;
	TfwHttpResp *resp = (TfwHttpResp *)msg;
	TfwHttpParser *parser = &msg->stream->parser;

	/*
	 * A duplicate invalidates the header's value.
	 * @resp->expires is set to zero - already expired.
	 */
	if (resp->cache_ctl.flags & TFW_HTTP_CC_HDR_EXPIRES)
		parser->_i_st = __I_EoL;

	r = __parse_http_date(msg, data, len);
	if (r < 0 && r != CSTR_POSTPONE) {
		/*
		 * On error just swallow the rest of the line.
		 * @resp->expires is set to zero - already expired.
		 */
		parser->_date = 0;
		parser->_acc = 0;
		parser->_i_st = __I_EoL;
		r = __parse_http_date(msg, data, len);
	}

	if (r >= 0) {
		resp->cache_ctl.expires = parser->_date;
		resp->cache_ctl.flags |= TFW_HTTP_CC_HDR_EXPIRES;
	}

	return r;
}

static int
__resp_parse_date(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpResp *resp = (TfwHttpResp *)msg;
	TfwHttpParser *parser = &msg->stream->parser;

	if (!test_bit(TFW_HTTP_B_HDR_DATE, resp->flags))
		r = __parse_http_date(msg, data, len);

	if (r < 0 && r != CSTR_POSTPONE) {
		/*
		 * On error just swallow the rest of the line.
		 * @resp->expires is set to zero - already expired.
		 */
		parser->_date = 0;
		parser->_acc = 0;
		parser->_i_st = __I_EoL;
		r = __parse_http_date(msg, data, len);
	}

	if (r >= 0) {
		resp->date = parser->_date;
		__set_bit(TFW_HTTP_B_HDR_DATE, resp->flags);
	}

	return r;
}

static int
__resp_parse_if_modified(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpResp *resp = (TfwHttpResp *)msg;
	TfwHttpParser *parser = &msg->stream->parser;

	if (!test_bit(TFW_HTTP_B_HDR_LMODIFIED, resp->flags))
		r = __parse_http_date(msg, data, len);

	if (r < 0 && r != CSTR_POSTPONE) {
		/*
		 * On error just swallow the rest of the line.
		 * @resp->expires is set to zero - already expired.
		 */
		parser->_date = 0;
		parser->_acc = 0;
		parser->_i_st = __I_EoL;
		r = __parse_http_date(msg, data, len);
	}

	if (r >= 0) {
		resp->last_modified = parser->_date;
		__set_bit(TFW_HTTP_B_HDR_LMODIFIED, resp->flags);
	}

	return r;
}

static int
__resp_parse_server(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Resp_I_Server) {
		/*
		 * Just eat the header value: usually we just replace the header
		 * value. RFC 7231 7.4.2 and RFC 7230 3.2:
		 *
		 *	Server = product *( RWS ( product / comment ) )
		 * 	product = token ["/" product-version]
		 * 	comment = "(" *( ctext / quoted-pair / comment ) ")"
		 */
		__FSM_I_MATCH_MOVE(ctext_vchar, Resp_I_Server);
		if (IS_CRLF(*(p + __fsm_sz)))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

done:
	return r;
}

/*
 * The server connection is being closed. Terminate the current message.
 * Note that eolen is not set on the body string.
 */
int
tfw_http_parse_terminate(TfwHttpMsg *hm)
{
	BUG_ON(!hm);
	BUG_ON(!(TFW_CONN_TYPE(hm->conn) & Conn_Srv));

	if (!test_bit(TFW_HTTP_B_UNLIMITED, hm->flags))
		return TFW_BLOCK;

	/*
	 * If response has no framing information, end of response is indicated
	 * by connection close, RFC 7230 3.3.3. Upper level should provide
	 * correct message framing to the client somehow.
	 */
	BUG_ON(hm->body.flags & TFW_STR_COMPLETE);
	hm->body.flags |= TFW_STR_COMPLETE;

	return TFW_PASS;
}

void
tfw_http_init_parser_resp(TfwHttpResp *resp)
{
	TfwHttpHbhHdrs *hbh_hdrs = &resp->stream->parser.hbh_parser;

	__parser_init(&resp->stream->parser);

	/*
	 * Expected hop-by-hop headers:
	 * - spec:
	 *     none;
	 * - raw:
	 *     Connection: RFC 7230 6.1,
	 *     Server: hide protected server from the world.
	 */
	hbh_hdrs->spec = (0x1 << TFW_HTTP_HDR_CONNECTION) |
			 (0x1 << TFW_HTTP_HDR_SERVER);
}

/**
 * Adjust parser for response according to it's request.
 */
static void
tfw_http_adj_parser_resp(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;

	if (req->method == TFW_HTTP_METH_HEAD)
		__set_bit(TFW_HTTP_B_VOID_BODY, resp->flags);
}

int
tfw_http_parse_resp(void *resp_data, unsigned char *data, size_t len,
		    unsigned int *parsed)
{
	int r = TFW_BLOCK;
	TfwHttpResp *resp = (TfwHttpResp *)resp_data;
	__FSM_DECLARE_VARS(resp);
	*parsed = 0;

	T_DBG("parse %lu server data bytes (%.*s%s) on resp=%p\n",
	      len, min(500, (int)len), data, len > 500 ? "..." : "", resp);

	__FSM_START(parser->state);

	/* ----------------    Status Line    ---------------- */

	/* Parser internal initializers, must be called once per message. */
	__FSM_STATE(Resp_0) {
		if (unlikely(IS_CRLF(c)))
			__FSM_MOVE_nofixup(Resp_0);
		tfw_http_adj_parser_resp(resp);
		/* fall through */
	}

	/* HTTP version */
	__FSM_STATE(Resp_HttpVer) {
		if (unlikely(!__data_available(p, 9))) {
			/* Slow path. */
			if (c == 'H') {
				__msg_field_open(&resp->s_line, p);
				__FSM_MOVE_f(Resp_HttpVerT1, &resp->s_line);
			}
			TFW_PARSER_BLOCK(Resp_HttpVer);
		}
		/* Fast path. */
		switch (*(unsigned long *)p) {
		case TFW_CHAR8_INT('H', 'T', 'T', 'P', '/', '1', '.', '1'):
			resp->version = TFW_HTTP_VER_11;
			if (*(p + 8) == ' ') {
				__msg_field_open(&resp->s_line, p);
				__FSM_MOVE_nf(Resp_StatusCode, 9,
					      &resp->s_line);
			}
			TFW_PARSER_BLOCK(Resp_HttpVer);
		case TFW_CHAR8_INT('H', 'T', 'T', 'P', '/', '1', '.', '0'):
			resp->version = TFW_HTTP_VER_10;
			if (*(p + 8) == ' ') {
				__msg_field_open(&resp->s_line, p);
				__FSM_MOVE_nf(Resp_StatusCode, 9,
					      &resp->s_line);
			}
			/* fall through */
		default:
			TFW_PARSER_BLOCK(Resp_HttpVer);
		}
	}

	/* Response Status-Code. */
	__FSM_STATE(Resp_StatusCode) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_list(p, __fsm_sz, &parser->_acc);
		switch (__fsm_n) {
		case CSTR_POSTPONE:
			/* Not all the header data is parsed. */
			__FSM_MOVE_nf(Resp_StatusCode, __fsm_sz,
				      &resp->s_line);
		case CSTR_BADLEN:
		case CSTR_NEQ:
			/* bad status value */
			TFW_PARSER_BLOCK(Resp_StatusCode);
		default:
			/* Status code is fully parsed, move forward. */
			resp->status = parser->_acc;
			parser->_acc = 0;
			/* RFC 7230 3.3.3: some responses don't have a body. */
			/* TODO: Add (req == CONNECT && resp == 2xx) */
			if (resp->status - 100U < 100U || resp->status == 204
			    || resp->status == 304)
			{
				__set_bit(TFW_HTTP_B_VOID_BODY, resp->flags);
			}
			__FSM_MOVE_nf(Resp_ReasonPhrase, __fsm_n,
				      &resp->s_line);
		}
	}

	/*
	 * Reason-Phrase: just skip. RFC 7230 3.1.2:
	 *
	 *	reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
	 */
	__FSM_STATE(Resp_ReasonPhrase) {
		__FSM_MATCH_MOVE_f(ctext_vchar, Resp_ReasonPhrase,
				   &resp->s_line);
		if (IS_CRLF(*(p + __fsm_sz))) {
			__msg_field_finish(&resp->s_line, p + __fsm_sz);
			__FSM_MOVE_nofixup_n(RGen_EoL, __fsm_sz);
		}
		TFW_PARSER_BLOCK(Resp_ReasonPhrase);
	}

	/* ----------------    Header Lines    ---------------- */

	/*
	 * The start of an HTTP header or the end of the header part
	 * of the response. There is a switch for the first character
	 * of a header field name.
	 */
	__FSM_STATE(RGen_Hdr) {
		TFW_HTTP_PARSE_CRLF();

		tfw_http_msg_hdr_open(msg, p);

		switch (TFW_LC(c)) {
		case 'a':
			if (likely(__data_available(p, 4)
				   && C4_INT3_LCM(p, 'a', 'g', 'e', ':')))
			{
				parser->_i_st = &&Resp_HdrAgeV;
				__FSM_MOVE_n(RGen_OWS, 4);
			}
			__FSM_MOVE(Resp_HdrA);
		case 'c':
			/* Ensure we have enough data for largest match. */
			if (unlikely(!__data_available(p, 14)))
				__FSM_MOVE(Resp_HdrC);
			/* Quick switch for HTTP headers with the same prefix. */
			switch (TFW_P2LCINT(p + 1)) {
			case TFW_CHAR4_INT('a', 'c', 'h', 'e'):
				if (likely(*(p + 5) == '-'
					   && C8_INT7_LCM(p + 6, 'c', 'o', 'n',
							  't', 'r', 'o', 'l',
							  ':')))
				{
					parser->_i_st = &&Resp_HdrCache_CtrlV;
					__FSM_MOVE_n(RGen_OWS, 14);
				}
				__FSM_MOVE_n(RGen_HdrOther, 5);
			case TFW_CHAR4_INT('o', 'n', 'n', 'e'):
				if (likely(C4_INT_LCM(p + 5, 'c', 't', 'i', 'o')
					   && TFW_LC(*(p + 9)) == 'n'
					   && *(p + 10) == ':'))
				{
					parser->_i_st = &&Resp_HdrConnectionV;
					__FSM_MOVE_n(RGen_OWS, 11);
				}
				__FSM_MOVE_n(RGen_HdrOther, 5);
			case TFW_CHAR4_INT('o', 'n', 't', 'e'):
				if (likely(TFW_LC(*(p + 5)) == 'n'
					   && TFW_LC(*(p + 6)) == 't'
					   && *(p + 7) == '-'))
				{
					__FSM_MOVE_n(Resp_HdrContent_, 8);
				}
				__FSM_MOVE_n(RGen_HdrOther, 5);
			default:
				__FSM_MOVE(RGen_HdrOther);
			}
		case 'd':
			if (likely(__data_available(p, 5)
				   && C4_INT3_LCM(p + 1, 'a', 't', 'e', ':')))
			{
				parser->_i_st = &&Resp_HdrDateV;
				__FSM_MOVE_n(RGen_OWS, 5);
			}
			__FSM_MOVE(Resp_HdrD);
		case 'e':
			if (likely(__data_available(p, 5)
				   && C4_INT3_LCM(p + 1, 't', 'a', 'g', ':')))
			{
				parser->_i_st = &&Resp_HdrEtagV;
				__FSM_MOVE_n(RGen_OWS, 5);
			}
			if (likely(__data_available(p, 8)
				   && C8_INT7_LCM(p, 'e', 'x', 'p', 'i',
						  'r', 'e', 's', ':')))
			{
				parser->_i_st = &&Resp_HdrExpiresV;
				__FSM_MOVE_n(RGen_OWS, 8);
			}
			__FSM_MOVE(Resp_HdrE);
		case 'k':
			if (likely(__data_available(p, 11)
				   && C4_INT_LCM(p, 'k', 'e', 'e', 'p')
				   && *(p + 4) == '-'
				   && C4_INT_LCM(p + 5, 'a', 'l', 'i', 'v')
				   && TFW_LC(*(p + 9)) == 'e'
				   && *(p + 10) == ':'))
			{
				parser->_i_st = &&Resp_HdrKeep_AliveV;
				__FSM_MOVE_n(RGen_OWS, 11);
			}
			__FSM_MOVE(Resp_HdrK);
		case 'l':
			if (likely(__data_available(p, 14)
				   && C4_INT_LCM(p, 'l', 'a', 's', 't')
				   && *(p + 4) == '-'
				   && C8_INT_LCM(p + 5, 'm', 'o', 'd', 'i',
							'f', 'i', 'e', 'd')
				   && *(p + 13) == ':'))
			{
				parser->_i_st = &&Resp_HdrLast_ModifiedV;
				__FSM_MOVE_n(RGen_OWS, 14);
			}
			__FSM_MOVE(Resp_HdrL);

		case 'p':
			if (likely(__data_available(p, 7))
			           && C4_INT_LCM(p + 1, 'r', 'a', 'g', 'm')
			           && TFW_LC(*(p + 5)) == 'a'
			           && *(p + 6) == ':')
			{
				parser->_i_st = &&Resp_HdrPragmaV;
				__FSM_MOVE_n(RGen_OWS, 7);
			}
			__FSM_MOVE(Resp_HdrP);

		case 's':
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'e', 'r', 'v', 'e')
				   && TFW_LC(*(p + 5)) == 'r'
				   && *(p + 6) == ':'))
			{
				parser->_i_st = &&Resp_HdrServerV;
				__FSM_MOVE_n(RGen_OWS, 7);
			}
			__FSM_MOVE(Resp_HdrS);
		case 't':
			if (likely(__data_available(p, 18)
				   && C8_INT_LCM(p, 't', 'r', 'a', 'n',
					   	    's', 'f', 'e', 'r')
				   && *(p + 8) == '-'
				   && C8_INT_LCM(p + 9, 'e', 'n', 'c', 'o',
							'd', 'i', 'n', 'g')
				   && *(p + 17) == ':'))
			{
				parser->_i_st = &&Resp_HdrTransfer_EncodingV;
				__FSM_MOVE_n(RGen_OWS, 18);
			}
			__FSM_MOVE(Resp_HdrT);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* Content-* headers. */
	__FSM_STATE(Resp_HdrContent_) {
		switch (TFW_LC(c)) {
		case 'l':
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'e', 'n', 'g', 't')
				   && TFW_LC(*(p + 5)) == 'h'
				   && *(p + 6) == ':'))
			{
				parser->_i_st = &&Resp_HdrContent_LengthV;
				__FSM_MOVE_n(RGen_OWS, 7);
			}
			__FSM_MOVE(Resp_HdrContent_L);
		case 't':
			if (likely(__data_available(p, 5)
				   && C4_INT3_LCM(p + 1, 'y', 'p', 'e', ':')))
			{
				parser->_i_st = &&Resp_HdrContent_TypeV;
				__FSM_MOVE_n(RGen_OWS, 5);
			}
			__FSM_MOVE(Resp_HdrContent_T);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* 'Age:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrAgeV, resp, __resp_parse_age);

	/* 'Cache-Control:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrCache_CtrlV, resp,
				  __resp_parse_cache_control);

	/* 'Connection:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrConnectionV, msg, __parse_connection,
				   TFW_HTTP_HDR_CONNECTION);

	/* 'Content-Length:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrContent_LengthV, msg,
				   __parse_content_length,
				   TFW_HTTP_HDR_CONTENT_LENGTH);

	/* 'Content-Type:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrContent_TypeV, msg,
				   __resp_parse_content_type,
				   TFW_HTTP_HDR_CONTENT_TYPE);

	/* 'Date:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrDateV, msg, __resp_parse_date);

	/* 'ETag:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrEtagV, msg, __parse_etag,
				     TFW_HTTP_HDR_ETAG, 0);

	/* 'Expires:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrExpiresV, msg, __resp_parse_expires);

	/* 'Keep-Alive:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrKeep_AliveV, msg, __parse_keep_alive,
				   TFW_HTTP_HDR_KEEP_ALIVE);

	/* 'Last-Modified:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrLast_ModifiedV, msg,
				  __resp_parse_if_modified);

	/* 'Pragma:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrPragmaV, msg, __parse_pragma);

	/* 'Server:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrServerV, resp, __resp_parse_server,
				   TFW_HTTP_HDR_SERVER);

	/* 'Transfer-Encoding:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrTransfer_EncodingV, msg,
				   __parse_transfer_encoding,
				   TFW_HTTP_HDR_TRANSFER_ENCODING);

	RGEN_HDR_OTHER();
	RGEN_OWS();
	RGEN_EOL();
	RGEN_CRLF();

	/* ----------------    Response body    ---------------- */

	TFW_HTTP_INIT_RESP_BODY_PARSING();
	TFW_HTTP_PARSE_BODY();
	TFW_HTTP_PARSE_BODY_UNLIM();

	/* ----------------    Improbable states    ---------------- */

	/* Parse HTTP version and SP (1.1 and 1.0 are supported). */
	__FSM_TX_f(Resp_HttpVerT1, 'T', Resp_HttpVerT2, &resp->s_line);
	__FSM_TX_f(Resp_HttpVerT2, 'T', Resp_HttpVerP, &resp->s_line);
	__FSM_TX_f(Resp_HttpVerP, 'P', Resp_HttpVerSlash, &resp->s_line);
	__FSM_TX_f(Resp_HttpVerSlash, '/', Resp_HttpVer11, &resp->s_line);
	__FSM_TX_f(Resp_HttpVer11, '1', Resp_HttpVerDot, &resp->s_line);
	__FSM_TX_f(Resp_HttpVerDot, '.', Resp_HttpVer12, &resp->s_line);
	__FSM_STATE(Resp_HttpVer12) {
		switch (c) {
		case '1':
			resp->version = TFW_HTTP_VER_11;
			__FSM_MOVE_f(Resp_SSpace, &resp->s_line);
		case '0':
			resp->version = TFW_HTTP_VER_10;
			__FSM_MOVE_f(Resp_SSpace, &resp->s_line);
		default:
			TFW_PARSER_BLOCK(Resp_HttpVer12);
		}
	}
	__FSM_TX_f(Resp_SSpace, ' ', Resp_StatusCode, &resp->s_line);

	/* Age header processing. */
	__FSM_TX_AF(Resp_HdrA, 'g', Resp_HdrAg);
	__FSM_TX_AF(Resp_HdrAg, 'e', Resp_HdrAge);
	__FSM_TX_AF_OWS(Resp_HdrAge, Resp_HdrAgeV);

	__FSM_STATE(Resp_HdrC) {
		switch (TFW_LC(c)) {
		case 'a':
			__FSM_MOVE(Resp_HdrCa);
		case 'o':
			__FSM_MOVE(Resp_HdrCo);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* Cache-Control header processing. */
	__FSM_TX_AF(Resp_HdrCa, 'c', Resp_HdrCac);
	__FSM_TX_AF(Resp_HdrCac, 'h', Resp_HdrCach);
	__FSM_TX_AF(Resp_HdrCach, 'e', Resp_HdrCache);
	__FSM_TX_AF(Resp_HdrCache, '-', Resp_HdrCache_);
	__FSM_TX_AF(Resp_HdrCache_, 'c', Resp_HdrCache_C);
	__FSM_TX_AF(Resp_HdrCache_C, 'o', Resp_HdrCache_Co);
	__FSM_TX_AF(Resp_HdrCache_Co, 'n', Resp_HdrCache_Con);
	__FSM_TX_AF(Resp_HdrCache_Con, 't', Resp_HdrCache_Cont);
	__FSM_TX_AF(Resp_HdrCache_Cont, 'r', Resp_HdrCache_Contr);
	__FSM_TX_AF(Resp_HdrCache_Contr, 'o', Resp_HdrCache_Contro);
	__FSM_TX_AF(Resp_HdrCache_Contro, 'l', Resp_HdrCache_Control);
	__FSM_TX_AF_OWS(Resp_HdrCache_Control, Resp_HdrCache_CtrlV);

	/* Connection header processing. */
	__FSM_TX_AF(Resp_HdrCo, 'n', Resp_HdrCon);
	__FSM_STATE(Resp_HdrCon) {
		switch (TFW_LC(c)) {
		case 'n':
			__FSM_MOVE(Resp_HdrConn);
		case 't':
			__FSM_MOVE(Resp_HdrCont);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}
	__FSM_TX_AF(Resp_HdrConn, 'e', Resp_HdrConne);
	__FSM_TX_AF(Resp_HdrConne, 'c', Resp_HdrConnec);
	__FSM_TX_AF(Resp_HdrConnec, 't', Resp_HdrConnect);
	__FSM_TX_AF(Resp_HdrConnect, 'i', Resp_HdrConnecti);
	__FSM_TX_AF(Resp_HdrConnecti, 'o', Resp_HdrConnectio);
	__FSM_TX_AF(Resp_HdrConnectio, 'n', Resp_HdrConnection);
	__FSM_TX_AF_OWS(Resp_HdrConnection, Resp_HdrConnectionV);

	/* Content-* headers processing. */
	__FSM_TX_AF(Resp_HdrCont, 'e', Resp_HdrConte);
	__FSM_TX_AF(Resp_HdrConte, 'n', Resp_HdrConten);
	__FSM_TX_AF(Resp_HdrConten, 't', Resp_HdrContent);
	__FSM_TX_AF(Resp_HdrContent, '-', Resp_HdrContent_);

	/* Content-Length header processing. */
	__FSM_TX_AF(Resp_HdrContent_L, 'e', Resp_HdrContent_Le);
	__FSM_TX_AF(Resp_HdrContent_Le, 'n', Resp_HdrContent_Len);
	__FSM_TX_AF(Resp_HdrContent_Len, 'g', Resp_HdrContent_Leng);
	__FSM_TX_AF(Resp_HdrContent_Leng, 't', Resp_HdrContent_Lengt);
	__FSM_TX_AF(Resp_HdrContent_Lengt, 'h', Resp_HdrContent_Length);
	__FSM_TX_AF_OWS(Resp_HdrContent_Length, Resp_HdrContent_LengthV);

	/* Content-Type header processing. */
	__FSM_TX_AF(Resp_HdrContent_T, 'y', Resp_HdrContent_Ty);
	__FSM_TX_AF(Resp_HdrContent_Ty, 'p', Resp_HdrContent_Typ);
	__FSM_TX_AF(Resp_HdrContent_Typ, 'e', Resp_HdrContent_Type);
	__FSM_TX_AF_OWS(Resp_HdrContent_Type, Resp_HdrContent_TypeV);

	/* Date header processing. */
	__FSM_TX_AF(Resp_HdrD, 'a', Resp_HdrDa);
	__FSM_TX_AF(Resp_HdrDa, 't', Resp_HdrDat);
	__FSM_TX_AF(Resp_HdrDat, 'e', Resp_HdrDate);
	__FSM_TX_AF_OWS(Resp_HdrDate, Resp_HdrDateV);

	__FSM_STATE(Resp_HdrE) {
		switch (TFW_LC(c)) {
		case 't':
			__FSM_MOVE(Resp_HdrEt);
		case 'x':
			__FSM_MOVE(Resp_HdrEx);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}
	/* ETag header processing. */
	__FSM_TX_AF(Resp_HdrEt, 'a', Resp_HdrEta);
	__FSM_TX_AF(Resp_HdrEta, 'g', Resp_HdrEtag);
	__FSM_TX_AF_OWS(Resp_HdrEtag, Resp_HdrEtagV);

	/* Expires header processing. */
	__FSM_TX_AF(Resp_HdrEx, 'p', Resp_HdrExp);
	__FSM_TX_AF(Resp_HdrExp, 'i', Resp_HdrExpi);
	__FSM_TX_AF(Resp_HdrExpi, 'r', Resp_HdrExpir);
	__FSM_TX_AF(Resp_HdrExpir, 'e', Resp_HdrExpire);
	__FSM_TX_AF(Resp_HdrExpire, 's', Resp_HdrExpires);
	__FSM_TX_AF_OWS(Resp_HdrExpires, Resp_HdrExpiresV);

	/* Keep-Alive header processing. */
	__FSM_TX_AF(Resp_HdrK, 'e', Resp_HdrKe);
	__FSM_TX_AF(Resp_HdrKe, 'e', Resp_HdrKee);
	__FSM_TX_AF(Resp_HdrKee, 'p', Resp_HdrKeep);
	__FSM_TX_AF(Resp_HdrKeep, '-', Resp_HdrKeep_);
	__FSM_TX_AF(Resp_HdrKeep_, 'a', Resp_HdrKeep_A);
	__FSM_TX_AF(Resp_HdrKeep_A, 'l', Resp_HdrKeep_Al);
	__FSM_TX_AF(Resp_HdrKeep_Al, 'i', Resp_HdrKeep_Ali);
	__FSM_TX_AF(Resp_HdrKeep_Ali, 'v', Resp_HdrKeep_Aliv);
	__FSM_TX_AF(Resp_HdrKeep_Aliv, 'e', Resp_HdrKeep_Alive);
	__FSM_TX_AF_OWS(Resp_HdrKeep_Alive, Resp_HdrKeep_AliveV);

	/* Last-Modified header processing. */
	__FSM_TX_AF(Resp_HdrL, 'a', Resp_HdrLa);
	__FSM_TX_AF(Resp_HdrLa, 's', Resp_HdrLas);
	__FSM_TX_AF(Resp_HdrLas, 't', Resp_HdrLast);
	__FSM_TX_AF(Resp_HdrLast, '-', Resp_HdrLast_);
	__FSM_TX_AF(Resp_HdrLast_, 'm', Resp_HdrLast_M);
	__FSM_TX_AF(Resp_HdrLast_M, 'o', Resp_HdrLast_Mo);
	__FSM_TX_AF(Resp_HdrLast_Mo, 'd', Resp_HdrLast_Mod);
	__FSM_TX_AF(Resp_HdrLast_Mod, 'i', Resp_HdrLast_Modi);
	__FSM_TX_AF(Resp_HdrLast_Modi, 'f', Resp_HdrLast_Modif);
	__FSM_TX_AF(Resp_HdrLast_Modif, 'i', Resp_HdrLast_Modifi);
	__FSM_TX_AF(Resp_HdrLast_Modifi, 'e', Resp_HdrLast_Modifie);
	__FSM_TX_AF(Resp_HdrLast_Modifie, 'd', Resp_HdrLast_Modified);
	__FSM_TX_AF_OWS(Resp_HdrLast_Modified, Resp_HdrLast_ModifiedV);

	/* Pragma header processing. */
	__FSM_TX_AF(Resp_HdrP, 'r', Resp_HdrPr);
	__FSM_TX_AF(Resp_HdrPr, 'a', Resp_HdrPra);
	__FSM_TX_AF(Resp_HdrPra, 'g', Resp_HdrPrag);
	__FSM_TX_AF(Resp_HdrPrag, 'm', Resp_HdrPragm);
	__FSM_TX_AF(Resp_HdrPragm, 'a', Resp_HdrPragma);
	__FSM_TX_AF_OWS(Resp_HdrPragma, Resp_HdrPragmaV);

	/* Server header processing. */
	__FSM_TX_AF(Resp_HdrS, 'e', Resp_HdrSe);
	__FSM_TX_AF(Resp_HdrSe, 'r', Resp_HdrSer);
	__FSM_TX_AF(Resp_HdrSer, 'v', Resp_HdrServ);
	__FSM_TX_AF(Resp_HdrServ, 'e', Resp_HdrServe);
	__FSM_TX_AF(Resp_HdrServe, 'r', Resp_HdrServer);
	__FSM_TX_AF_OWS(Resp_HdrServer, Resp_HdrServerV);

	/* Transfer-Encoding header processing. */
	__FSM_TX_AF(Resp_HdrT, 'r', Resp_HdrTr);
	__FSM_TX_AF(Resp_HdrTr, 'a', Resp_HdrTra);
	__FSM_TX_AF(Resp_HdrTra, 'n', Resp_HdrTran);
	__FSM_TX_AF(Resp_HdrTran, 's', Resp_HdrTrans);
	__FSM_TX_AF(Resp_HdrTrans, 'f', Resp_HdrTransf);
	__FSM_TX_AF(Resp_HdrTransf, 'e', Resp_HdrTransfe);
	__FSM_TX_AF(Resp_HdrTransfe, 'r', Resp_HdrTransfer);
	__FSM_TX_AF(Resp_HdrTransfer, '-', Resp_HdrTransfer_);
	__FSM_TX_AF(Resp_HdrTransfer_, 'e', Resp_HdrTransfer_E);
	__FSM_TX_AF(Resp_HdrTransfer_E, 'n', Resp_HdrTransfer_En);
	__FSM_TX_AF(Resp_HdrTransfer_En, 'c', Resp_HdrTransfer_Enc);
	__FSM_TX_AF(Resp_HdrTransfer_Enc, 'o', Resp_HdrTransfer_Enco);
	__FSM_TX_AF(Resp_HdrTransfer_Enco, 'd', Resp_HdrTransfer_Encod);
	__FSM_TX_AF(Resp_HdrTransfer_Encod, 'i', Resp_HdrTransfer_Encodi);
	__FSM_TX_AF(Resp_HdrTransfer_Encodi, 'n', Resp_HdrTransfer_Encodin);
	__FSM_TX_AF(Resp_HdrTransfer_Encodin, 'g', Resp_HdrTransfer_Encoding);
	__FSM_TX_AF_OWS(Resp_HdrTransfer_Encoding, Resp_HdrTransfer_EncodingV);

	__FSM_FINISH(resp);

	return r;
}
STACK_FRAME_NON_STANDARD(tfw_http_parse_resp);
