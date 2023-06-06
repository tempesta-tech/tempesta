/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2023 Tempesta Technologies, Inc.
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
#include <linux/ctype.h>

#undef DEBUG
#if DBG_HTTP_PARSER > 0
#define DEBUG DBG_HTTP_PARSER
#endif

#include "gfsm.h"
#include "http_msg.h"
#include "htype.h"
#include "http_sess.h"
#include "hpack.h"
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
#define __data_processed(pos)		__data_off(pos)
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
 * start of the data).
 */
#define __msg_field_open(field, pos)					\
	tfw_http_msg_set_str_data(msg, field, pos)

#define __msg_field_fixup(field, pos)					\
do {									\
	if (unlikely(tfw_http_msg_add_str_data(msg, field, data,	\
					       __data_off(pos))))	\
		return CSTR_NEQ;					\
} while (0)

#define __msg_field_finish(field, pos)					\
do {									\
	__msg_field_fixup(field, pos);					\
	(field)->flags |= TFW_STR_COMPLETE;				\
} while (0)

#define __msg_field_fixup_pos(field, data, len)				\
do {									\
	if (unlikely(tfw_http_msg_add_str_data(msg, field, data, len)))	\
		return CSTR_NEQ;					\
} while (0)

#define __msg_field_finish_pos(field, data, len)			\
do {									\
	__msg_field_fixup_pos(field, data, len);			\
	(field)->flags |= TFW_STR_COMPLETE;				\
} while (0)

#define __msg_field_chunk_flags(field, flag)				\
do {									\
	T_DBG3("parser: add chunk flags: %u\n", flag);			\
	TFW_STR_CURR(field)->flags |= flag;				\
} while (0)

#define __msg_chunk_flags(flag)						\
	__msg_field_chunk_flags(&msg->stream->parser.hdr, flag)

/*
 * The macro is frequently used for headers opened by tfw_http_msg_hdr_open().
 * It sets the header's TfwStr->data to the current chunk pointer,
 * but leaves TfwStr->len = 0. This TfwStr->data value is used latter when
 * the parser will be reading "n" bytes of data using a pointer variable "p".
 * The underlying __tfw_http_msg_add_str_data() detects TfwStr->len == 0 and
 * sets the current TfwStr's length to p + n - TfwStr->data i.e. the final
 * string will effectively point to the original chunk's start and will contain
 * every parsed byte counting from the chunk's start.
*/
#define __msg_hdr_chunk_fixup(data, len)				\
do {									\
	if (unlikely(tfw_http_msg_add_str_data(msg,			\
			&msg->stream->parser.hdr, data, len)))		\
		return CSTR_NEQ;					\
} while (0)

#define __msg_hdr_set_hpack_index(idx)					\
	parser->hdr.hpack_idx = idx;

/**
 * GCC still does a poor work on memory reusage of automatic local
 * variables in nested blocks, so we declare all required temporal variables
 * used in the defines below here to reduce stack frame usage.
 * Since the variables are global now, be careful with them.
 *
 * objtool understands jump table, but our direct jumps are still opaque for it,
 * so use compiler barrier to avoid stack manipulations after jumps.
 *
 * @parser - stores FSM state across multiple chunk processing.
 * @p      - current parser's position within the current @data chunk.
 * @c      - current character at @p. Should preferably be assigned by
 *           __FSM_STATE label.
 * @__fsm_n and
 * @__fsm_sz - mostly just two local integer values of different
 *           types. Usually one of them is used to store __data_remaining(p),
 *           and the other one is a return value indicating actually parsed
 *           character count.
 * @chunk  - one of FSM states used by __try_str() and derrivatives
 *           (TRY_STR_LAMBDA_fixup(), TRY_STR(), etc) to match a multi-character
 *           string. Initialized by TRY_STR_INIT() before the matching.
 */
#define __FSM_DECLARE_VARS(ptr)						\
	TfwHttpMsg	*msg = (TfwHttpMsg *)(ptr);			\
	TfwHttpParser	*parser = &msg->stream->parser;			\
	unsigned char	*p = data;					\
	unsigned char	c = *p;						\
	int		__maybe_unused __fsm_n;				\
	size_t		__maybe_unused __fsm_sz;			\
	TfwStr		__maybe_unused *chunk = &parser->_tmp_chunk;	\
	barrier();

/**
 * The function prints the problem place of an HTTP message whenever there
 * is not enough functionality in our parser or there is an attack.
 * We need to give more context about the case, so we print the data with
 * 8 bytes (at most) backward offset and 48 bytes (at most) length.
 * The standard format printing deals with non-printable characters, so it's
 * safe to print the attack payload as is.
 */
#define TFW_PARSER_BLOCK(st)						\
do {									\
	register unsigned int __p_o = min_t(unsigned int, 8, p - data);	\
	register unsigned int __p_n = min_t(unsigned int, 48,		\
					    data + len + __p_o - p);	\
	T_WARN("Parser error: state=" #st " input(-%d)=%#x('%.*s')"	\
	       " data_len=%u off=%lu\n",				\
	       __p_o, (char)c, __p_n, p - __p_o, len, p - data);	\
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

#define __FSM_STATE(st, ...)						\
barrier();								\
st: __attribute__((unused, __VA_ARGS__))				\
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
	if (r == TFW_PASS)						\
		__set_bit(TFW_HTTP_B_FULLY_PARSED, msg->flags);		\
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

#define __FSM_MATCH_MOVE_fixup_pos(alphabet, to, field, flag, fixup_pos) \
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
		__msg_field_chunk_flags(field, flag);			\
		parser->state = &&to;					\
		p += __fsm_sz;						\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
} while (0)

/* Fixups p + __fsm_sz on chunk exhaustion */
#define __FSM_MATCH_MOVE_pos_f(alphabet, to, field, flag)		\
	__FSM_MATCH_MOVE_fixup_pos(alphabet, to, field, flag, true)

/* Fixups data + len on chunk exhaustion */
#define __FSM_MATCH_MOVE(alphabet, to, flag)				\
	__FSM_MATCH_MOVE_fixup_pos(alphabet, to, &msg->stream->parser.hdr, \
				  flag, false)

#define __FSM_MOVE_hdr_fixup(to, n)					\
do {									\
	__msg_hdr_chunk_fixup(p, n);					\
	p += n;								\
	if (unlikely(__data_off(p) >= len)) {				\
		parser->state = &&to;					\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
	goto to;							\
} while (0)

/*
 * __FSM_I_* macros are intended to help with parsing of message
 * header values. That is done with separate, nested, or interior
 * FSMs, and so _I_ in the name means "interior" FSM.
 */
#define __FSM_I_field_chunk_flags(field, flag)				\
	__msg_field_chunk_flags(field, flag)

#define __FSM_I_chunk_flags(flag)					\
	__msg_chunk_flags(flag)

#define __FSM_I_MOVE_BY_REF_n(to, n, flag)				\
do {									\
	BUG_ON(n < 0);							\
	parser->_i_st = to;						\
	p += n;								\
	if (unlikely(__data_off(p) >= len)) {				\
		/* Close currently parsed field chunk. */		\
		__msg_hdr_chunk_fixup(data, len);			\
		if (flag)						\
			__msg_chunk_flags(flag);			\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
	goto *to;							\
} while (0)

/* These four macroses fixup by data + len on chunk exhaustion */

#define __FSM_I_MOVE_n(to, n)						\
	__FSM_I_MOVE_BY_REF_n(&&to, n, 0)

#define __FSM_I_MOVE_flag(to, flag)					\
	__FSM_I_MOVE_BY_REF_n(&&to, 1, flag)

#define __FSM_I_MOVE_BY_REF(to)						\
	__FSM_I_MOVE_BY_REF_n(to, 1, 0)

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
 * __FSM_I_MOVE_fixup_xxx() and __FSM_I_MATCH_fixup_xxx() family macroses
 * fixup p + n and p + __fsm_sz appropriately. They are to be used for explicit
 * fine-grained control of chunking within a string, i.e. a caller can
 * explicitly chop an ingress contiguous string into multiple chunks thus
 * generating efficient key/value pairs.
 *
 * Normal MOVE macros fixup @data if there is not enough data and we're going to
 * return TFW_POSTPONE. We can not use @p since we don't know how many states we
 * executed on the current chunk, so we have no length of currently matched data.
 * In other words if you call a fixup function first and next you do normal
 * movement, then you might see the same data twice in the parsed data.
 *
 * Following rules must be meet for safe fixup logic:
 * 1. explicit fixups should not be mixed with regular fixups (__FSM_I_MOVE and
 *    others)
 * 2. call __msg_field_open() to initialize a new _empty_ TfwStr chunk (see
 *    __tfw_str_set_data()). Usually we use it to initialize header
 *    before using fixup functions to it. However, also we can use it to
 *    initialize chunk of TfwStr that have already been allocated before.
 *    (see __req_parse_forwarded()).
 * 3. fixup data in each state (so that you know how much data you processed)
 *    and make sure that __tfw_http_msg_add_str_data() is called by macros
 *    for @p, not @data. With this approach headers are processed, e.g. see
 *    __FSM_MOVE_hdr_fixup() with transition to Req_HdrAcceptV,
 *    __msg_hdr_chunk_fixup(p, __fsm_sz) in RGEN_OWS() and finally
 *    __msg_hdr_chunk_fixup(p, __fsm_n) in __TFW_HTTP_PARSE_RAWHDR_VAL().
 *
 * For complex headers we may need ability to open chunk in certain state
 * (that will save current data pointer) then travel to another stay or do
 * checks in loop and finally fixup all processed data.
 *
 * Approach which looks good(pseudo-code):
 * 1. Allocate new chunk. TfwStr *ch = tfw_str_add_compound(hm->pool,
 *							    &parser->hdr);
 * 2. Open chunk with __msg_field_open(ch, p).
 * 3. Do some processing in loop. Just move @p of parser function many times.
 * 4. Finnaly. Update the last chunk by calculating length using data pointer
 * that have been saved at first step. tfw_str_updlen(&parser->hdr, p);
 * For linear SKB this should works perfectly, but with fragmented data we will
 * get some problems. @p might point to new SKB, but last chunk in parser will
 * point to previous SKB and we must not to calculate offsets with different
 * SKBs. This implies we should fixup last chunk of header before postpone and
 * logic might be like this:
 *
 * Steps 1 and 2 as above.
 * 3. First of all we need to check last chunk. If chunk is fixuped we need to
 * allocate new chunk. Then we need to check bounds of @data, if it's
 * exhausted we should fixup current chunk then postpone message. Once message
 * parsing resumed repeat the step.
 * 4. Same as above.
 *
 * As we see, we need to allocate new chunk after message parsing jumped to next
 * data fragment. It's very important.
 */
/*
 * Fixup the current chunk that starts at the current data pointer
 * @p and has the size @n. Move forward to just after the chunk.
 * We have at least @n bytes as we parsed them before the fixup.
 * p+n should never exceed data+len i.e. we can fixup data
 * from the current chunk only.
 */
#define __FSM_I_MOVE_fixup_f(to, n, field, flag)			\
do {									\
	BUG_ON(!(field)->data);						\
	BUG_ON(n < 0);							\
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

#define __FSM_I_MATCH_MOVE_fixup_finish(alphabet, to, flag, finish)	\
do {									\
	__fsm_n = __data_remain(p);					\
	__fsm_sz = tfw_match_##alphabet(p, __fsm_n);			\
	if (unlikely(__fsm_sz == __fsm_n)) {				\
		__msg_hdr_chunk_fixup(p, __fsm_sz);			\
		__FSM_I_chunk_flags(flag);				\
		parser->_i_st = &&to;					\
		r = TFW_POSTPONE;					\
		finish;							\
		__FSM_EXIT(r);						\
	}								\
} while (0)

#define __FSM_I_MATCH_MOVE_fixup(alphabet, to, flag)			\
	__FSM_I_MATCH_MOVE_fixup_finish(alphabet, to, flag, {})

/* Conditional transition from state @st to @st_next. */
#define __FSM_TX_COND(st, condition, st_next, field, ...)		\
__FSM_STATE(st, __VA_ARGS__) {						\
	if (likely(condition))						\
		__FSM_MOVE_f(st_next, field);				\
	TFW_PARSER_BLOCK(st);						\
}

#define __FSM_TX_COND_nofixup(st, condition, st_next, ...)		\
__FSM_STATE(st, __VA_ARGS__) {						\
	if (likely(condition))						\
		__FSM_MOVE_nofixup(st_next);				\
	TFW_PARSER_BLOCK(st);						\
}

/* Automaton transition from state @st to @st_next on character @ch. */
#define __FSM_TX(st, ch, st_next, ...)					\
	__FSM_TX_COND(st, c == (ch), st_next, &parser->hdr, __VA_ARGS__)
#define __FSM_TX_nofixup(st, ch, st_next, ...)				\
	__FSM_TX_COND_nofixup(st, c == (ch), st_next, __VA_ARGS__)

/* Case-insensitive version of __FSM_TX(). */
#define __FSM_TX_LC(st, ch, st_next, field, ...)			\
	__FSM_TX_COND(st, TFW_LC(c) == (ch), st_next, field, __VA_ARGS__)
#define __FSM_TX_LC_nofixup(st, ch, st_next, ...)			\
	__FSM_TX_COND_nofixup(st, TFW_LC(c) == (ch), st_next, __VA_ARGS__)

/*
 * Automaton transition with alphabet checking and fallback state.
 * Improbable states only, so cold label.
 */
#define __FSM_TX_AF(st, ch, st_next)					\
__FSM_STATE(st, cold) {							\
	if (likely(TFW_LC(c) == ch))					\
		__FSM_MOVE(st_next);					\
	/* It should be checked in st_fallback if `c` is allowed */	\
	__FSM_JMP(RGen_HdrOtherN);					\
}

/*
 * As above, but reads OWS through transitional state. Note, that header
 * name, colon, LWS and value are stored in different chunks.
 */
#define __FSM_TX_AF_OWS(st, st_next)					\
__FSM_STATE(st, cold) {							\
	if (likely(c == ':')) {						\
		__msg_hdr_chunk_fixup(data, __data_off(p));		\
		parser->_i_st = &&st_next;				\
		__FSM_MOVE_hdr_fixup(RGen_LWS, 1);			\
	}								\
	/* It should be checked in st_fallback if `c` is allowed */	\
	__FSM_JMP(RGen_HdrOtherN);					\
}

/* As above, but with HPACK static index setting. */
#define __FSM_TX_AF_OWS_HP(st, st_next, hp_idx)				\
__FSM_STATE(st, cold) {							\
	if (likely(c == ':')) {						\
		__msg_hdr_chunk_fixup(data, __data_off(p));		\
		parser->_i_st = &&st_next;				\
		__msg_hdr_set_hpack_index(hp_idx);			\
		__FSM_MOVE_hdr_fixup(RGen_LWS, 1);			\
	}								\
	/* It should be checked in st_fallback if `c` is allowed */	\
	__FSM_JMP(RGen_HdrOtherN);					\
}

/* Used for improbable states only, so use cold label. */
#define __FSM_METH_MOVE(st, ch, st_next)				\
__FSM_STATE(st, cold) {							\
	if (likely(c == (ch)))						\
		__FSM_MOVE_nofixup(st_next);				\
	__FSM_JMP(Req_MethodUnknown);					\
}

#define __FSM_METH_MOVE_finish(st, ch, m_type)				\
__FSM_STATE(st, cold) {							\
	if (unlikely(c != (ch)))					\
		__FSM_JMP(Req_MethodUnknown);				\
	req->method = (m_type);						\
	__FSM_MOVE_nofixup(Req_MUSpace);				\
}

#define __FSM_REQUIRE(st, st_next, predicate)				\
__FSM_STATE(st) {							\
	if (unlikely(!predicate))					\
		return CSTR_NEQ;					\
	parser->_i_st = &&st_next;					\
}

#define __FSM_REQUIRE_FIRST_DIGIT(st, st_next)				\
	__FSM_REQUIRE(st, st_next, isdigit(c))

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

/*
 * Matching 4 to 8 characters without conversion to lower case (applicable
 * for HTTP/2 headers name comparison).
 */
#define C4_INT(p, a, b, c, d)						\
	!(PI(p) ^ TFW_CHAR4_INT(a, b, c, d))
#define C8_INT(p, a, b, c, d, e, f, g, h)				\
	!(*(unsigned long *)(p) ^ TFW_CHAR8_INT(a, b, c, d, e, f, g, h))

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
 * 	CSTR_NEQ:	not equal
 * 	> 0:		(partially) equal, length of matched chunk
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
		T_DBG3("__parse_ulong: acc=%lu p=%c len=%zu limit=%lu\n",
		       *acc, *p, len, limit);
		if (unlikely(IN_ALPHABET(*p, delimiter_a)))
			return p - data;
		if (unlikely(!isdigit(*p)))
			return CSTR_NEQ;
		if (unlikely(__builtin_uaddl_overflow(*acc * 10, *p - '0', acc)
			|| *acc > limit))
			return CSTR_BADLEN;
	}

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

/**
 * Parse an integer followed by delim.
 */
static __always_inline int
__parse_ulong_ws_delim(unsigned char *__restrict data, size_t len,
		       unsigned long *__restrict acc, unsigned long limit)
{
	/*
	 * Standard white-space plus semicolon and dquoute characters are:
	 * '\t' (0x09) horizontal tab (TAB)
	 * '\n' (0x0a) newline (LF)
	 * '\v' (0x0b) vertical tab (VT)
	 * '\f' (0x0c) feed (FF)
	 * '\r' (0x0d) carriage return (CR)
	 * ' '  (0x20) space (SPC)
	 * '"'  (0x22) dquote
	 * ';'  (0x3b) semicolon
	 */
	static const unsigned long ws_comma_a[] ____cacheline_aligned = {
		0x0800000500003e00UL, 0, 0, 0
	};
	return __parse_ulong(data, len, ws_comma_a, acc, limit);
}

#define parse_int_ws(data, len, acc)					\
	__parse_ulong_ws(data, len, acc, UINT_MAX)

#define parse_long_ws(data, len, acc)					\
	__parse_ulong_ws(data, len, acc, LONG_MAX)

/**
 * Parse an integer as part of HTTP list.
 */
static inline int
parse_ulong_list(unsigned char *data, size_t len, unsigned long *acc,
		 unsigned long limit)
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
	return __parse_ulong(data, len, ws_comma_a, acc, limit);
}


#define parse_uint_list(data, len, acc)					\
	parse_ulong_list(data, len, acc, UINT_MAX)

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
 * Parse OWS, i.e. the space or horizontal tab characters which
 * can exist before or after the header's value.
 * @return number of parsed bytes or CSTR_POSTPONE if all @len bytes
 * are parsed.
 */
static __always_inline int
parse_ows(unsigned char *__restrict data, size_t len)
{
	unsigned char *p;

	for (p = data; p - data < len; ++p) {
		if (!IS_WS(*p))
			return p - data;
	}
	return CSTR_POSTPONE;
}

/**
 * These headers should not be present in the list
 * of hop-by-hop headers.
 */
static const TfwStr ete_spec_raw_hdrs[] = {
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
	TFW_STR_STRING("forwarded:"),
	TFW_STR_STRING("host:"),
	TFW_STR_STRING("pragma:"),
	TFW_STR_STRING("server:"),
	TFW_STR_STRING("transfer-encoding:"),
	TFW_STR_STRING("user-agent:"),
	TFW_STR_STRING("x-forwarded-for:"),
};

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
		if ((hbh_hdrs->spec & (0x1 << id)) && (!TFW_STR_EMPTY(hdr))) {
			T_DBG3("%s: hm %pK, tbl[%u] flags +TFW_STR_HBH_HDR\n",
			       __func__, hm, id);
			hdr->flags |= TFW_STR_HBH_HDR;
		}
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
			T_DBG3("%s: hbh raw[%d], hm %pK, hdr %pK ->flags %x, "
			       "flags +TFW_STR_HBH_HDR\n",
			       __func__, i, hm, hdr, hdr->flags);
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

	T_DBG3("%s: hm %pK, hid %u, flags +TFW_STR_HBH_HDR\n",
	       __func__, hm, hid);
	ht->tbl[hid].flags |= TFW_STR_HBH_HDR;
	return true;
}

/**
 * Complete HBH header.
 * Chunk with ':' will be added to the end.
 * After name of hop-by-hop header was completed, the routine will search
 * for headers with that name and mark them as hop-by-hop.
 * Header might not be parsed yet, i.e. it comes after the Connection header.
 *
 * NOTE: Most of the headers listed in RFC 7231 are end-to-end and must not
 * be listed in the header. Instead of comparing connection tokens to all
 * end-to-end headers names compare only to headers parsed by
 * TFW_HTTP_PARSE_RAWHDR_VAL macro.
 */
static int
__hbh_parser_finalize(TfwHttpMsg *hm)
{
	TfwStr *hbh_hdr, *append;
	TfwStr s_colon = { .data = ":", .len = 1 };
	TfwHttpHbhHdrs *hbh = &hm->stream->parser.hbh_parser;
	hbh_hdr = &hbh->raw[hbh->off];

	T_DBG3("%s: hbh->off %d, hbh_h %pK, hbh_h->nchunks %d, hbh_h->len %lu\n",
	       __func__, hbh->off, hbh_hdr, hbh_hdr->nchunks, hbh_hdr->len);

	append = tfw_str_add_compound(hm->pool, hbh_hdr);
	if (!append)
		return -ENOMEM;
	*append = s_colon;

	hbh_hdr->len += s_colon.len;
	++hbh->off;

	if (tfw_http_msg_find_hdr(hbh_hdr, ete_spec_raw_hdrs))
		return CSTR_NEQ;
	/*
	 * Don't set TFW_STR_HBH_HDR flag if such header was already
	 * parsed. See comment in mark_raw_hbh()
	 */
	if (!__mark_hbh_hdr(hm, hbh_hdr))
		hbh_hdr->flags |= TFW_STR_HBH_HDR;

	return 0;
}

/**
 * Add header name listed in Connection header to hop-by-hop table of raw
 * headers. If @finalize_item is true then (@data, @len) represents
 * last chunk of header name and HBH header would be finalized.
 * Otherwise last header in table stays open to add more data.
 */
static int
__hbh_parser_add_data(TfwHttpMsg *hm, char *data, unsigned long len,
		      bool finalize_item)
{
	TfwStr *hbh_hdr, *append;
	TfwHttpHbhHdrs *hbh = &hm->stream->parser.hbh_parser;

	T_DBG3("%s: hm %pK, data %pK, *data [%c], len %lu, fin=%d\n",
	       __func__, hm, data, *data, len, finalize_item ? 1 : 0);

	if (hbh->off == TFW_HBH_TOKENS_MAX)
		return CSTR_NEQ;
	hbh_hdr = &hbh->raw[hbh->off];

	if (!TFW_STR_EMPTY(hbh_hdr)) {
		append = tfw_str_add_compound(hm->pool, hbh_hdr);
	} else {
		append = (TfwStr *)tfw_pool_alloc(hm->pool, sizeof(TfwStr));
		hbh_hdr->chunks = append;
		hbh_hdr->nchunks = 1;
	}

	if (!append)
		return -ENOMEM;
	append->len = len;
	append->data = data;
	hbh_hdr->len += len;

	T_DBG3("%s: hbh->off %d, hbh_h %pK, hbh_h->nchunks %d, hbh_h->len %lu\n",
	       __func__, hbh->off, hbh_hdr, hbh_hdr->nchunks, hbh_hdr->len);

	return finalize_item ? __hbh_parser_finalize(hm) : 0;
}

static int
process_trailer_hdr(TfwHttpMsg *hm, TfwStr *hdr, unsigned int id)
{
	if (!(hm->crlf.flags & TFW_STR_COMPLETE))
		return CSTR_EQ;

	/*
	 * RFC 7230 4.1.2:
	 *
	 * A sender MUST NOT generate a trailer that contains a field necessary
	 * for message framing (e.g., Transfer-Encoding and Content-Length),
	 * routing (e.g., Host), request modifiers (e.g., controls and
	 * conditionals in Section 5 of [RFC7231]), authentication (e.g., see
	 * [RFC7235] and [RFC6265]), response control data (e.g., see Section
	 * 7.1 of [RFC7231]), or determining how to process the payload (e.g.,
	 * Content-Encoding, Content-Type, Content-Range, and Trailer).
	 */
	switch (id) {
	case TFW_HTTP_HDR_HOST:
	case TFW_HTTP_HDR_CONTENT_LENGTH:
	case TFW_HTTP_HDR_CONTENT_TYPE:
	case TFW_HTTP_HDR_COOKIE:
	case TFW_HTTP_HDR_IF_NONE_MATCH:
	case TFW_HTTP_HDR_X_FORWARDED_FOR:
	case TFW_HTTP_HDR_TRANSFER_ENCODING:
	case TFW_HTTP_HDR_CONTENT_ENCODING:
	case TFW_HTTP_HDR_SET_COOKIE:
	case TFW_HTTP_HDR_FORWARDED:
		return CSTR_NEQ;
	}

	hdr->flags |= TFW_STR_TRAILER;
	__set_bit(TFW_HTTP_B_CHUNKED_TRAILER, hm->flags);

	return CSTR_EQ;
}

/**
 * Check whether response contains Content-Encoding and Transfer-Encoding
 * other than chunked.
 *
 * Return T_DROP on success.
 */
static int
__parse_check_encodings(TfwHttpResp *resp)
{
	TfwStr *tbl = resp->h_tbl->tbl;

	if (test_bit(TFW_HTTP_B_TE_EXTRA, resp->flags)
	    && !TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_ENCODING])) {
		T_WARN("Content-Encoding and Transfer-Encoding other than"
		       " chunked not allowed to be in same response.\n");
			return T_DROP;
	}

	return T_OK;
}

#define __FSM_I_MOVE_body_lambda(to, n, lambda)				\
do {									\
	p += n;								\
	if (unlikely(__data_off(p) >= len)) {				\
		lambda;							\
		parser->_i_st = &&to;					\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
	goto to;							\
} while (0)

#define __FSM_I_MOVE_body_nf(to, n)					\
	__FSM_I_MOVE_body_lambda(to, n, {})

static int
__req_parse_body(TfwHttpReq *req, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_BodyParseInit) {
		/* For chunked body need parse @to_read from chunk descriptor. */
		if (parser->to_read == -1)
			__FSM_JMP(I_BodyChunked);
	}

	__FSM_STATE(I_BodyReadData) {
		BUG_ON(parser->to_read < 0);
		T_DBG3("read body: to_read=%ld\n", parser->to_read);

		__fsm_sz = min_t(long, parser->to_read, __data_remain(p));
		parser->to_read -= __fsm_sz;
		if (parser->to_read)
			__FSM_I_MOVE_body_nf(I_BodyReadData, __fsm_sz);

		if (test_bit(TFW_HTTP_B_CHUNKED, msg->flags)) {
			parser->to_read = -1;
			__FSM_I_MOVE_body_nf(I_BodyEoL, __fsm_sz);
		}

		/* We've fully read Content-Length bytes. */
		p += __fsm_sz;
		return __data_off(p);
	}

	__FSM_STATE(I_BodyChunked) {
		/* Prevent @parse_int_hex false positives. */
		if (!isxdigit(c))
			__FSM_EXIT(TFW_BLOCK);
		/* Fall through. */
	}

	__FSM_STATE(I_BodyChunkLen) {
		__fsm_sz = __data_remain(p);
		/* Read next chunk length. */
		__fsm_n = parse_int_hex(p, __fsm_sz, &parser->_acc,
					&parser->_cnt);
		T_DBG3("data chunk: remain_len=%zu ret=%d to_read=%lu\n",
		       __fsm_sz, __fsm_n, parser->_acc);
		switch (__fsm_n) {
		case CSTR_POSTPONE:
			__FSM_I_MOVE_body_nf(I_BodyChunkLen, __fsm_sz);
		case CSTR_BADLEN:
		case CSTR_NEQ:
			__FSM_EXIT(TFW_BLOCK);
		default:
			parser->to_read = parser->_acc;
			parser->_acc = 0;
			parser->_cnt = 0;
			__FSM_I_MOVE_body_nf(I_BodyChunkExt, __fsm_n);
		}
	}

	__FSM_STATE(I_BodyChunkExt) {
		if (unlikely(c == ';' || c == '=' || IS_TOKEN(c)))
			__FSM_I_MOVE_body_nf(I_BodyChunkExt, 1);
		/* Fall through. */
	}

	__FSM_STATE(I_BodyEoL) {
		if (likely(c == '\r'))
			__FSM_I_MOVE_body_nf(I_BodyCR, 1);
		/* Fall through. */
	}

	__FSM_STATE(I_BodyCR) {
		if (unlikely(c != '\n'))
			__FSM_EXIT(TFW_BLOCK);
		if (parser->to_read == -1)
			__FSM_I_MOVE_body_nf(I_BodyChunked, 1);
		else if (parser->to_read > 0)
			/* We know size of chunk, parse data. */
			__FSM_I_MOVE_body_nf(I_BodyReadData, 1);

		/*
		 * We've fully read the chunked body.
		 * Add everything and the current character.
		 */
		return __data_off(++p);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__req_parse_body);

static int
__resp_parse_body(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

#define TFW_BODY_OPEN_CHUNK()						\
do {									\
	TfwStr *ch = tfw_str_add_compound(msg->pool, &parser->cut);	\
									\
	if (!ch) { 							\
		T_WARN("Cannot grow HTTP data string\n"); 		\
		return CSTR_NEQ; 					\
	} 								\
	__msg_field_open(ch, p); 					\
} while (0)

#define __FSM_I_MOVE_cut_fixup(to, n)					\
	__FSM_I_MOVE_body_lambda(to, n, {				\
		tfw_str_updlen(&parser->cut, p);			\
	})

	if (!TFW_STR_EMPTY(TFW_STR_CURR(&parser->cut)))
		TFW_BODY_OPEN_CHUNK();

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_BodyParseInit) {
		/* For chunked body need parse @to_read from chunk descriptor. */
		if (parser->to_read == -1)
			__FSM_JMP(I_BodyChunked);
	}

	__FSM_STATE(I_BodyReadData) {
		BUG_ON(parser->to_read < 0);
		T_DBG3("read body: to_read=%ld\n", parser->to_read);

		if (!parser->body_start_data) {
			parser->body_start_data = p;
			parser->body_start_skb =
				ss_skb_peek_tail(&msg->msg.skb_head);
		}
		__fsm_sz = min_t(long, parser->to_read, __data_remain(p));
		parser->to_read -= __fsm_sz;
		if (parser->to_read)
			__FSM_I_MOVE_body_nf(I_BodyReadData, __fsm_sz);

		if (test_bit(TFW_HTTP_B_CHUNKED, msg->flags)) {
			parser->to_read = -1;
			__FSM_I_MOVE_body_nf(I_ChunkDataEnd, __fsm_sz);
		}

		/* We've fully read Content-Length bytes. */
		p += __fsm_sz;
		return __data_off(p);
	}

	__FSM_STATE(I_BodyChunked) {
		/* Prevent @parse_int_hex false positives. */
		if (!isxdigit(c))
			__FSM_EXIT(TFW_BLOCK);
		/* Fall through. */
	}

	__FSM_STATE(I_BodyChunkLen) {
		__fsm_sz = __data_remain(p);
		/* Read next chunk length. */
		__fsm_n = parse_int_hex(p, __fsm_sz, &parser->_acc,
					&parser->_cnt);
		T_DBG3("data chunk: remain_len=%zu ret=%d to_read=%lu\n",
		       __fsm_sz, __fsm_n, parser->_acc);
		switch (__fsm_n) {
		case CSTR_POSTPONE:
			__FSM_I_MOVE_cut_fixup(I_BodyChunkLen, __fsm_sz);
		case CSTR_BADLEN:
		case CSTR_NEQ:
			__FSM_EXIT(TFW_BLOCK);
		default:
			parser->to_read = parser->_acc;
			parser->_acc = 0;
			parser->_cnt = 0;
			__FSM_I_MOVE_cut_fixup(I_BodyChunkExt, __fsm_n);
		}
	}

	__FSM_STATE(I_BodyChunkExt) {
		if (unlikely(c == ';' || c == '=' || IS_TOKEN(c)))
			__FSM_I_MOVE_cut_fixup(I_BodyChunkExt, 1);
		__FSM_JMP(I_BodyEoL);
	}

	/* Fixup chunked body data-part */
	__FSM_STATE(I_ChunkDataEnd) {
		/* Don't fixup chunk after resuming parsing. */
		if (!TFW_STR_EMPTY(TFW_STR_CURR(&parser->cut)))
			TFW_BODY_OPEN_CHUNK();
		else
			/*
			 * Need to reopen field, because last chunks points to
			 * address before data-part. Without reopening it
			 * leads to fixuping data-part.
			 */
			__msg_field_open(TFW_STR_CURR(&parser->cut), p);
		/* Fall through. */
	}

	__FSM_STATE(I_BodyEoL) {
		if (likely(c == '\r'))
			__FSM_I_MOVE_cut_fixup(I_BodyCR, 1);
		/* Fall through. */
	}

	__FSM_STATE(I_BodyCR) {
		if (unlikely(c != '\n'))
			__FSM_EXIT(TFW_BLOCK);
		if (parser->to_read == -1)
			__FSM_I_MOVE_cut_fixup(I_BodyChunked, 1);
		else if (parser->to_read > 0)
			/* We know size of chunk, parse data. */
			__FSM_I_MOVE_cut_fixup(I_BodyDescEnd, 1);

		/*
		 * We've fully read the chunked body.
		 * Add everything and the current character.
		 */
		tfw_str_updlen(&parser->cut, ++p);
		return __data_off(p);
	}

	/* Fixup parsed chunk size */
	__FSM_STATE(I_BodyDescEnd) {
		/* Don't fixup chunk after resuming parsing. */
		if (__data_off(p) > 0) {
			tfw_str_updlen(&parser->cut, p);
		}
		__FSM_JMP(I_BodyReadData);
	}
done:
	return r;

#undef TFW_BODY_OPEN_CHUNK
#undef __FSM_I_MOVE_cut_fixup
}
STACK_FRAME_NON_STANDARD(__resp_parse_body);

#undef __FSM_I_MOVE_body_nf
#undef __FSM_I_MOVE_body_lambda

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
 * TRY_STR_* macros are supposed to be used without explicit fixups, so the
 * whole data + len chunk will be fixed up on chunk exhaustion.
 * @str in TRY_STR_LAMBDA must be in lower case.
 * @lambda is called on successfull full string match.
 * @finish is called when the current data+len chunk is exhausted.
 */
#define TRY_STR_LAMBDA_BY_REF_finish(str, lambda, finish, state)	\
	if (!chunk->data)						\
		chunk->data = p;					\
	T_DBG3("TSLBR_pre: data %pK, p %pK, c [%c], len %zu, "		\
	       "str='%s'\n", data, p, c, len, str);			\
	__fsm_n = __try_str(&parser->hdr, chunk, p, __data_remain(p),	\
			    str, sizeof(str) - 1);			\
	T_DBG3("TSLBR_post: __fsm_n: %d, chunk->len %lu\n",		\
	       __fsm_n, chunk->len);					\
	if (__fsm_n > 0) {						\
		if (chunk->len == sizeof(str) - 1) {			\
			lambda;						\
			TRY_STR_INIT();					\
			__FSM_I_MOVE_BY_REF_n(state, __fsm_n, 0);	\
		}							\
		/* Here __fsm_n == __data_remain(p) i.e. chunk exhausted */ \
		__msg_hdr_chunk_fixup(data, len);			\
		finish;							\
		return CSTR_POSTPONE;					\
	}

#define TRY_STR_LAMBDA_finish(str, lambda, finish, state)		\
	TRY_STR_LAMBDA_BY_REF_finish(str, lambda, finish, &&state)

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

#define TRY_STR_BY_REF(str, curr_st, next_st)				\
	TRY_STR_LAMBDA_BY_REF_finish(str, { }, {			\
			parser->_i_st = curr_st;			\
		}, next_st)

/**
 * The same as @TRY_STR_LAMBDA_finish(), but @str must be of plain
 * @TfwStr{} type and variable @field is used (instead of hard coded
 * header field); besides, @finish parameter is not used in this macro.
 * xxx_fixup() family of functions is used to explicit chunking of strings.
 */
#define TRY_STR_LAMBDA_fixup_flag(str, field, lambda, curr_st, next_st,	\
				  flag)					\
	BUG_ON(!TFW_STR_PLAIN(str));					\
	if (!chunk->data)						\
		chunk->data = p;					\
	__fsm_n = __try_str(field, chunk, p, __data_remain(p),		\
			    (str)->data, (str)->len);			\
	if (__fsm_n > 0) {						\
		if (chunk->len == (str)->len) {				\
			lambda;						\
			TRY_STR_INIT();					\
			__FSM_I_MOVE_fixup_f(next_st, __fsm_n, field,	\
					     flag);			\
		}							\
		__msg_field_fixup_pos(field, p, __fsm_n);		\
		__FSM_I_field_chunk_flags(field, flag);			\
		parser->_i_st = &&curr_st;				\
		return CSTR_POSTPONE;					\
	}

#define TRY_STR_LAMBDA_fixup(str, field, lambda, curr_st, next_st)	\
	TRY_STR_LAMBDA_fixup_flag(str, field, lambda, curr_st,		\
				  next_st, 0)

#define TRY_STR_fixup(str, curr_st, next_st)				\
	TRY_STR_LAMBDA_fixup(str, &parser->hdr, { }, curr_st, next_st)

/*
 * Headers EOL processing. Allow only LF and CRLF as a newline delimiters.
 *
 * Note also, that according to RFC 7230, HTTP-headers may appear in two
 * cases. The first one is header section (3.2) and the second one is
 * chunked-body trailer-part (4.1).
 */
#define RGEN_EOL()							\
__FSM_STATE(RGen_EoL, hot) {						\
	if (c == '\r')							\
		__FSM_MOVE_nofixup(RGen_CR);				\
	if (c == '\n') {						\
		if (parser->hdr.data) {					\
			tfw_str_set_eolen(&parser->hdr, 1);		\
			if (tfw_http_msg_hdr_close(msg))		\
				TFW_PARSER_BLOCK(RGen_EoL);		\
		}							\
		__FSM_MOVE_nofixup(RGen_Hdr);				\
	}								\
	TFW_PARSER_BLOCK(RGen_EoL);					\
}									\
__FSM_STATE(RGen_CR, hot) {						\
	if (unlikely(c != '\n'))					\
		TFW_PARSER_BLOCK(RGen_CR);				\
	if (parser->hdr.data) {						\
		tfw_str_set_eolen(&parser->hdr, 2);			\
		if (tfw_http_msg_hdr_close(msg))			\
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
__FSM_STATE(RGen_CRLFCR, hot) {						\
	if (unlikely(c != '\n'))					\
		TFW_PARSER_BLOCK(RGen_CRLFCR);				\
	mark_spec_hbh(msg);						\
	if (!(msg->crlf.flags & TFW_STR_COMPLETE)) {			\
		BUG_ON(!msg->crlf.data);				\
		__msg_field_finish(&msg->crlf, p + 1);			\
		__FSM_JMP(RGen_BodyInit);				\
	}								\
	parser->state = &&RGen_CRLFCR;					\
	/* Don't fixup last CR, just set EOLEN for body which will	\
	 * be cutted during HTTP1 to HTTP2 transformation and will	\
	 * not be stored in cache. */					\
	if (TFW_CONN_TYPE(msg->conn) & Conn_Srv)			\
		tfw_str_set_eolen(&msg->body, 2);			\
	FSM_EXIT(TFW_PASS);						\
}

/*
 * We have HTTP message descriptors and special headers,
 * however we still need to store full headers (instead of just their values)
 * as well as store headers which aren't need in further processing
 * (e.g. Content-Length which is doubled by TfwHttpMsg.content_length)
 * to mangle row skb data.
 * Rule of thumb for @saveval: saveval = false for explicit chunking functions
 * i.e. the ones that use xxx_fixup() functions.
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
		r = process_trailer_hdr(msg, &parser->hdr, id);		\
		if (r < 0 && r != CSTR_POSTPONE)			\
			TFW_PARSER_BLOCK(st_curr);			\
		parser->_i_st = &&RGen_EoL;				\
		parser->_hdr_tag = id;					\
		parser->_acc = 0;					\
		p += __fsm_n;						\
		BUG_ON(unlikely(__data_off(p) >= len));			\
		__FSM_JMP(RGen_RWS); /* skip RWS */			\
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
		r = process_trailer_hdr(msg, &parser->hdr,		\
					TFW_HTTP_HDR_RAW);		\
		if (r < 0 && r != CSTR_POSTPONE)			\
			TFW_PARSER_BLOCK(st_curr);			\
		parser->_i_st = &&RGen_EoL;				\
		parser->_hdr_tag = TFW_HTTP_HDR_RAW;			\
		parser->_acc = 0;					\
		p += __fsm_n;						\
		BUG_ON(unlikely(__data_off(p) >= len));			\
		__FSM_JMP(RGen_RWS); /* skip RWS */			\
	}								\
}

#define TFW_HTTP_PARSE_RAWHDR_VAL(st_curr, hm, func)			\
	__TFW_HTTP_PARSE_RAWHDR_VAL(st_curr, hm, func, 1)

/*
 * Parse raw (common) HTTP headers.
 * Note that some of these can be extremely large.
 */
#define RGEN_HDR_OTHER()						\
__FSM_STATE(RGen_HdrOtherN) {						\
	__FSM_MATCH_MOVE(token, RGen_HdrOtherN, 0);			\
	if (likely(*(p + __fsm_sz) == ':')) {				\
		/*							\
		 * Header name must contain at least one character, but \
		 * ':' can be found at the beginning of a new skb or	\
		 * fragment, it's ok.					\
		*/							\
		if (unlikely(!__fsm_sz && TFW_STR_EMPTY(&parser->hdr)	\
			     && p == (unsigned char *)parser->hdr.data))\
		{							\
			TFW_PARSER_BLOCK(RGen_HdrOtherN);		\
		}							\
		__msg_hdr_chunk_fixup(data, __data_off(p + __fsm_sz));	\
		parser->_i_st = &&RGen_HdrOtherV;			\
		p += __fsm_sz;						\
		__FSM_MOVE_hdr_fixup(RGen_LWS, 1);			\
	}								\
	TFW_PARSER_BLOCK(RGen_HdrOtherN);				\
}									\
__FSM_STATE(RGen_HdrOtherV) {						\
	/*								\
	 * The header content is opaque for us,				\
	 * so pass ctext and VCHAR.					\
	 */								\
	__FSM_MATCH_MOVE_pos_f(ctext_vchar, RGen_HdrOtherV,		\
			       &msg->stream->parser.hdr, 0);		\
	if (!IS_CRLF(*(p + __fsm_sz)))					\
		TFW_PARSER_BLOCK(RGen_HdrOtherV);			\
	__msg_hdr_chunk_fixup(p, __fsm_sz);				\
	mark_raw_hbh(msg, &parser->hdr);				\
	r = process_trailer_hdr(msg, &parser->hdr, TFW_HTTP_HDR_RAW);	\
	if (r < 0 && r != CSTR_POSTPONE)				\
		TFW_PARSER_BLOCK(st_curr);				\
	parser->_hdr_tag = TFW_HTTP_HDR_RAW;				\
	__FSM_MOVE_nofixup_n(RGen_EoL, __fsm_sz);			\
}

#define WARN_BODY_ATTACK(msg_type, attack_type) 			\
	T_WARN("Transfer-Encoding chunked and Content-Length in same"   \
	       " %s considered as attempt to %s attack.\n", msg_type,   \
		attack_type)

#define BLOCK_REQUEST_SMUGGLING() {					\
	WARN_BODY_ATTACK("request", "Request smuggling");		\
	FSM_EXIT(TFW_BLOCK);						\
}

#define BLOCK_RESPONSE_SPLITTING() {					\
	WARN_BODY_ATTACK("reponse", "Response splitting");		\
	FSM_EXIT(TFW_BLOCK); 						\
}

/* Process according RFC 9112 6.3 */
#define TFW_HTTP_INIT_REQ_BODY_PARSING()				\
__FSM_STATE(RGen_BodyInit, cold) {					\
	register TfwStr *tbl = msg->h_tbl->tbl;				\
									\
	__set_bit(TFW_HTTP_B_HEADERS_PARSED, msg->flags);		\
	T_DBG3("parse request body: flags=%#lx content_length=%lu\n",	\
	       msg->flags[0], msg->content_length);			\
									\
	if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_TRANSFER_ENCODING])) {	\
		/*							\
		 * According to RFC 9112 6.3 p.3, more strict		\
		 * scenario has been implemented to exclude		\
		 * attempts of HTTP Request Smuggling or HTTP		\
		 * Response Splitting.					\
		 */							\
		if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_LENGTH]))	\
			BLOCK_REQUEST_SMUGGLING();			\
		if (test_bit(TFW_HTTP_B_CHUNKED, msg->flags))		\
			__FSM_MOVE_nofixup(RGen_BodyStart);		\
		/*							\
		 * If "Transfer-Encoding:" header is present and	\
		 * there's NO "chunked" coding, then send 400 response	\
		 * (Bad Request) and close the connection.		\
		 */							\
		TFW_PARSER_BLOCK(RGen_BodyInit);			\
	}								\
									\
	if (tfw_http_parse_check_bodyless_meth(req))			\
		FSM_EXIT(TFW_BLOCK);					\
									\
	if (msg->content_length) {					\
		parser->to_read = msg->content_length;			\
		__FSM_MOVE_nofixup(RGen_BodyStart);			\
	}								\
	/* There is no body. */						\
	msg->body.flags |= TFW_STR_COMPLETE;				\
	parser->state = &&RGen_BodyInit;				\
	FSM_EXIT(TFW_PASS);						\
}

/* Process according RFC 9112 6.3 */
#define TFW_HTTP_INIT_RESP_BODY_PARSING()				\
__FSM_STATE(RGen_BodyInit) {						\
	register TfwStr *tbl = msg->h_tbl->tbl;				\
									\
	__set_bit(TFW_HTTP_B_HEADERS_PARSED, msg->flags);		\
	T_DBG3("parse response body: flags=%#lx content_length=%lu\n",	\
	       msg->flags[0], msg->content_length);			\
									\
	/* There's no body. */						\
	if (test_bit(TFW_HTTP_B_VOID_BODY, msg->flags)) 		\
		goto no_body;						\
	if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_TRANSFER_ENCODING])) {	\
		/* 							\
		 * Block response which has Content-Encoding and 	\
		 * Transfer-Encoding other than chunked 		\
		 */ 							\
		if (__parse_check_encodings(resp))			\
			FSM_EXIT(TFW_BLOCK);				\
		if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_LENGTH])) {\
			/*						\
			 * Block responses which have transfer-encoding	\
			 * *chunked* and content-length. According to	\
			 * RFC 9112 6.3 p.3, more strict scenario has	\
			 * been implemented to exclude attempts of HTTP	\
			 * Request Smuggling or HTTP Response Splitting.\
			 * Encodings other than	*chunked* are allowed	\
			 * to be used with content-length header.	\
			 */						\
			if (test_bit(TFW_HTTP_B_CHUNKED, msg->flags))	\
				BLOCK_RESPONSE_SPLITTING();		\
			if (msg->content_length == 0)			\
				goto no_body;				\
			parser->to_read = msg->content_length;		\
			__FSM_MOVE_nofixup(RGen_BodyStart);		\
		}							\
		if (test_bit(TFW_HTTP_B_CHUNKED, msg->flags))		\
			__FSM_MOVE_nofixup(RGen_BodyStart);		\
		/* Process the body until the connection is closed. */	\
		__set_bit(TFW_HTTP_B_UNLIMITED, msg->flags);		\
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

#define TFW_HTTP_PARSE_BODY(...)					\
/* Read request|response body. */					\
__FSM_STATE(RGen_BodyStart, __VA_ARGS__) {				\
	__msg_field_open(&msg->body, p);				\
	__msg_field_open(&parser->cut, p);				\
	/* Fall through. */						\
}									\
__FSM_STATE(RGen_BodyParse, __VA_ARGS__) {				\
	__fsm_sz = __data_remain(p);					\
	if (TFW_CONN_TYPE(msg->conn) & Conn_Srv)			\
		__fsm_n = __resp_parse_body((TfwHttpResp*)msg, p, __fsm_sz);\
	else								\
		__fsm_n = __req_parse_body((TfwHttpReq*)msg, p, __fsm_sz);\
	T_DBG3("body parsed: ret=%d data_len=%lu", __fsm_n, __fsm_sz);	\
	switch (__fsm_n) {						\
	case CSTR_POSTPONE:						\
		parser->state = &&RGen_BodyParse;			\
		p += __fsm_sz;						\
		msg->body.len += __fsm_sz;				\
		__FSM_EXIT(TFW_POSTPONE);				\
	case CSTR_BADLEN:						\
	case CSTR_NEQ:							\
		TFW_PARSER_BLOCK(RGen_BodyParse);			\
	default:							\
		p += __fsm_n;						\
		msg->body.len += __fsm_n;				\
		msg->body.flags |= TFW_STR_COMPLETE;			\
		if (!test_bit(TFW_HTTP_B_CHUNKED, msg->flags)) {	\
			__FSM_EXIT(TFW_PASS);				\
		} else if (unlikely(__data_off(p) >= len)) {		\
			/* Chunked body parsed. Wait for trailer. */	\
			parser->state = &&RGen_Hdr;			\
			__FSM_EXIT(TFW_POSTPONE);			\
		}							\
		/* Process the trailer-part. */				\
		__FSM_JMP(RGen_Hdr);					\
	}								\
}									\

/*
 * Read OWS and move to stashed state. This is bit complicated (however
 * you can think about this as a plain pushdown automaton), but reduces
 * FSM code size.
 */
#define RGEN_OWS()							\
__FSM_STATE(RGen_LWS, hot) {						\
	__fsm_sz = __data_remain(p);					\
	__fsm_n = parse_ows(p, __fsm_sz);				\
	T_DBG3("parse LWS: __fsm_n=%d, __fsm_sz=%lu, len=%u,"		\
	       " off=%lu\n", __fsm_n, __fsm_sz, len, __data_off(p));	\
	if  (__fsm_n == CSTR_POSTPONE) {				\
		__msg_hdr_chunk_fixup(p, __fsm_sz);			\
		__msg_chunk_flags(TFW_STR_OWS);				\
		p += __fsm_sz;						\
		parser->state = &&RGen_LWS;				\
		__FSM_EXIT(TFW_POSTPONE);				\
	}								\
	BUG_ON(__fsm_n < 0);						\
	if (__fsm_n) {							\
		__msg_hdr_chunk_fixup(p, __fsm_n);			\
		__msg_chunk_flags(TFW_STR_OWS);				\
	}								\
	parser->state = parser->_i_st;					\
	parser->_i_st = NULL;						\
	p += __fsm_n;							\
	BUG_ON(unlikely(__data_off(p) >= len));				\
	goto *parser->state;						\
}									\
__FSM_STATE(RGen_RWS, hot) {						\
	if (likely(IS_WS(c)))						\
		__FSM_MOVE_nofixup(RGen_RWS);				\
	T_DBG3("parse RWS: len=%u, off=%lu\n", len, __data_off(p));	\
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
			if (__hbh_parser_add_data(hm, p, __fsm_n, false))\
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
	 * For WebSocket Protocol during handshake client sets
	 * "Connection: upgrade" and "Upgrade" header. This headers should be
	 * recreated before pass to backend.
	 */
	__FSM_STATE(I_Conn) {
		WARN_ON_ONCE(parser->_acc);
		/* Boolean connection tokens */
		TRY_CONN_TOKEN("close", {
			if (__hbh_parser_add_data(hm, p, __fsm_n, false))
				return CSTR_NEQ;
			__set_bit(TFW_HTTP_B_CONN_CLOSE, &parser->_acc);
		});
		/* Spec headers */
		TRY_CONN_TOKEN("keep-alive", {
			if (__hbh_parser_add_data(hm, p, __fsm_n, false))
				return CSTR_NEQ;
			__set_bit(TFW_HTTP_B_CONN_KA, &parser->_acc);
		});
		TRY_CONN_TOKEN("upgrade", {
			if (__hbh_parser_add_data(hm, p, __fsm_n, false))
				return CSTR_NEQ;
			__set_bit(TFW_HTTP_B_CONN_UPGRADE, &parser->_acc);
		});
		TRY_STR_INIT();
		__FSM_I_JMP(I_ConnOther);
	}
#undef TRY_CONN_TOKEN

	__FSM_STATE(I_ConnTok) {
		WARN_ON_ONCE(!parser->_acc);

		if (likely(IS_WS(c) || c == ',' || IS_CRLF(c))) {
			if (__hbh_parser_finalize(hm))
				return CSTR_NEQ;
		} else {
			__FSM_I_JMP(I_ConnOther);
		}

		if (test_bit(TFW_HTTP_B_CONN_KA, &parser->_acc)) {
			register unsigned int hid = TFW_HTTP_HDR_KEEP_ALIVE;

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
		else if (test_bit(TFW_HTTP_B_CONN_UPGRADE, &parser->_acc)) {
			register unsigned int hid = TFW_HTTP_HDR_UPGRADE;

			__set_bit(TFW_HTTP_B_CONN_UPGRADE, msg->flags);

			parser->hbh_parser.spec |= 0x1 << hid;
			if (!TFW_STR_EMPTY(&msg->h_tbl->tbl[hid]))
				msg->h_tbl->tbl[hid].flags |= TFW_STR_HBH_HDR;
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
		if (IS_CRLF(c))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

	/* End of token */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(I_EoT);

		if (IS_TOKEN(c)) {
			parser->_acc = 0; /* reinit for next token */
			__FSM_I_JMP(I_Conn);
		}
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
__parse_content_length(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_REQUIRE_FIRST_DIGIT(I_ContLenBeg, I_ContLen);

	__FSM_STATE(I_ContLen) {
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
		r = parse_long_ws(data, len, &msg->content_length);
		if (r == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);

		T_DBG3("%s: content_length=%lu\n", __func__, msg->content_length);

		return r;
	}
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
			__FSM_I_MOVE_fixup(I_EoL, __fsm_sz, 0);
		}
		__FSM_I_MOVE_fixup(I_ContTypeOtherTypeSlash, __fsm_sz, 0);
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
			__msg_hdr_chunk_fixup(p, __fsm_sz);
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
 * Parse Content-Encoding header value, RFC 9110 8.4.
 * Parse Transfer-Encoding header value, RFC 2616 14.41 and 3.6.
 *
 * We cut transfer-encoding for h2 responses, since the transfer-encoding is not
 * allowed over h2 connections. See RFC 9113 8.2.2
 */
static int
__parse_transfer_encoding(TfwHttpMsg *hm, unsigned char *data, size_t len,
			  bool client, bool content)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	/* Content-Encoding can't contain "chunked". Skip this part. */
	if (content)
		__FSM_I_JMP(I_EncodTok);

	__FSM_STATE(I_TransEncodTok) {
		/*
		 * A sender MUST NOT apply chunked more than once
		 * to a message body (i.e., chunking an already
		 * chunked message is not allowed). RFC 7230 3.3.1.
		 */
		TRY_STR_LAMBDA_fixup_flag(&TFW_STR_STRING("chunked"),
					  &parser->hdr, {}, I_TransEncodTok,
					  I_TransEncodChunked, 0);
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

	/*
	 * RFC 7230 3.3.1:
	 *
	 * If any transfer coding
	 * other than chunked is applied to a REQUEST payload body, the sender
	 * MUST apply chunked as the final transfer coding to ensure that the
	 * message is properly framed. If any transfer coding other than
	 * chunked is applied to a RESPONSE payload body, the sender MUST either
	 * apply chunked as the final transfer coding or terminate the message
	 * by closing the connection.
	 */
	__FSM_STATE(I_TransEncodOther) {
		__set_bit(TFW_HTTP_B_TE_EXTRA, msg->flags);
		/* Fall through. */
	}

	__FSM_STATE(I_EncodTok) {
		__FSM_I_MATCH_MOVE_fixup(token, I_EncodTok, TFW_STR_NAME);
		__msg_hdr_chunk_fixup(p, __fsm_sz);
		__FSM_I_chunk_flags(TFW_STR_NAME);
		p += __fsm_sz;

		if (content)
			__FSM_I_JMP(I_EoT);

		if (unlikely(test_bit(TFW_HTTP_B_CHUNKED, msg->flags))) {
			if (client)
				return CSTR_NEQ;
			if (TFW_MSG_H2(hm->req))
				return CSTR_NEQ;

			__clear_bit(TFW_HTTP_B_CHUNKED, msg->flags);
			__set_bit(TFW_HTTP_B_CHUNKED_APPLIED, msg->flags);
		}
		/* Fall through. */
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (c == ',')
			__FSM_I_MOVE_fixup(I_EoT, 1, 0);
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_EoT, 1, TFW_STR_OWS);
		if (IS_TOKEN(c)) {
			if (content)
				__FSM_I_JMP(I_EncodTok);

			__FSM_I_JMP(I_TransEncodTok);
		}

		if (IS_CRLF(c))
			return __data_off(p);

		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_transfer_encoding);

static int
__req_parse_transfer_encoding(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	return __parse_transfer_encoding(hm, data, len, true, false);
}

static int
__resp_parse_transfer_encoding(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	/*
	 * According to RFC 7230 section 3.3.1:
	 *
	 * A server MUST NOT send a Transfer-Encoding header field
	 * in any 2xx (Successful) response to a CONNECT request.
	 *
	 * TODO check CONNECT request.
	 */
	if (TFW_CONN_TYPE(hm->conn) & Conn_Srv) {
		unsigned int status = ((TfwHttpResp *)hm)->status;
		if (status - 100U < 100U || status == 204)
			return CSTR_NEQ;
	}

	return __parse_transfer_encoding(hm, data, len, false, false);
}

static int
__req_parse_content_encoding(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	return __parse_transfer_encoding(hm, data, len, true, true);
}

static int
__resp_parse_content_encoding(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	return __parse_transfer_encoding(hm, data, len, false, true);
}

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

	__FSM_STATE(Req_I_WSAccept) {
		if (IS_WS(c))
			__FSM_I_MOVE(Req_I_WSAccept);
		/* Fall through. */
	}

	__FSM_STATE(Req_I_Accept) {
		TRY_STR("text", Req_I_Accept, Req_I_AfterText);
		/*
		 * TRY_STR() compares the string with the substring at the
		 * beginning of the chunk sequence, but @c is the first
		 * non-matching character with the string of the previous
		 * TRY_STR(). If we will use @c to compare with "*", then we will
		 * catch matches not only with "*", but also with "t*", "te*",
		 * "tex*".
		 */
		TRY_STR("*", Req_I_Accept, Req_I_AfterStar);
		TRY_STR_INIT();
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_Type);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_AfterText) {
		if (c == '/')
			__FSM_I_MOVE(Req_I_AfterTextSlash);

		__FSM_I_MOVE(Req_I_Type);
	}

	__FSM_STATE(Req_I_AfterTextSlash) {
		if (c == '*')
			__FSM_I_MOVE(I_EoT);
		/* Fall through. */
	}

	__FSM_STATE(Req_I_AfterTextSlashToken) {
		TRY_STR("html", Req_I_AfterTextSlashToken, Req_I_AcceptHtml);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_Subtype);
	}

	__FSM_STATE(Req_I_AfterStar) {
		if (c == '/')
			__FSM_I_MOVE(Req_I_StarSlashStar);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_StarSlashStar) {
		if (c == '*')
			__FSM_I_MOVE(I_EoT);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_AcceptHtml) {
		if (IS_WS(c) || c == ',' || c == ';' || IS_CRLF(c)) {
			__set_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags);
			__FSM_I_JMP(I_EoT);
		}
		__FSM_I_JMP(Req_I_Subtype);
	}

	__FSM_STATE(Req_I_Type) {
		__FSM_I_MATCH_MOVE(token, Req_I_Type);
		c = *(p + __fsm_sz);
		if (c == '/')
			__FSM_I_MOVE_n(Req_I_Slash, __fsm_sz + 1);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Slash) {
		if (c == '*')
			__FSM_I_MOVE(I_EoT);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_Subtype);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Subtype) {
		__FSM_I_MATCH_MOVE(token, Req_I_Subtype);
		__FSM_I_MOVE_n(I_EoT, __fsm_sz);
	}

	/*
	 * RFC 7231 5.3.1
	 *
	 * Parser doesn't follow the RFC for qvalue, because it
	 * would introduce new states here (hence slower parsing),
	 * but an attack doesn't look likely.
	 *
	 * But it can validate just the first char "for free"
	 * (anyway empty qvalue validation is required), so it's validated.
	 */
	__FSM_REQUIRE(Req_I_QValueBeg, Req_I_QValue,
		      (c == '0' || c == '1'));


	__FSM_STATE(Req_I_QValue) {
		if (isdigit(c) || c == '.')
			__FSM_I_MOVE(Req_I_QValue);
		__FSM_I_JMP(I_EoT);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_WSAcceptOther) {
		if (IS_WS(c))
			__FSM_I_MOVE(Req_I_WSAcceptOther);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_AcceptOther);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_AcceptOther) {
		TRY_STR("q=", Req_I_AcceptOther, Req_I_QValueBeg);
		TRY_STR_INIT();
		__FSM_I_MATCH_MOVE(token, Req_I_AcceptOther);
		c = *(p + __fsm_sz);
		if (c == '=')
			__FSM_I_MOVE_n(Req_I_ParamValueBeg, __fsm_sz + 1);
		return CSTR_NEQ;
	}

	__FSM_REQUIRE(Req_I_ParamValueBeg, Req_I_ParamValue,
		      (IS_TOKEN(c) || c == '\"'));

	__FSM_STATE(Req_I_ParamValue) {
		if (c == '\"')
			__FSM_I_MOVE(Req_I_QuotedString);
		__FSM_I_MATCH_MOVE(token, Req_I_ParamValue);
		__FSM_I_MOVE_n(I_EoT, __fsm_sz);
	}

	__FSM_STATE(Req_I_QuotedString) {
		__FSM_I_MATCH_MOVE(token, Req_I_QuotedString);
		if (c != '"')
			__FSM_I_MOVE(Req_I_QuotedString);
		__FSM_I_MOVE(I_EoT);
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c))
			__FSM_I_MOVE(I_EoT);
		if (c == ',')
			__FSM_I_MOVE(Req_I_WSAccept);
		if (c == ';')
			/* Skip weight parameter. */
			__FSM_I_MOVE(Req_I_WSAcceptOther);
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
 * Parse request Cache-Control, RFC 2616 14.9.
 *
 * RFC 7234 1.2.1:
 *
 * If a cache receives a delta-seconds
 * value greater than the greatest integer it can represent, or if any
 * of its subsequent calculations overflows, the cache MUST consider the
 * value to be either 2147483648 (2^31) or the greatest positive integer
 * it can conveniently represent.
 * ...
 * What matters here is that an overflow
 * be detected and not treated as a negative value in later
 * calculations.
 *
 * Parser detects overflow when parsing delta-seconds,
 * but blocks such messages because it's a rare case.
 */
static int
__req_parse_cache_control(TfwHttpReq *req, unsigned char *data, size_t len)
{
	/* Very similar to __resp_parse_cache_control */
	int r = TFW_BLOCK;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	/*
	 * We cannot immediately modify req->cache_ctl.flags on smallest
	 * string match e.g. "Cache-Control: no-cache-me" should not lead to
	 * TFW_HTTP_CC_NO_CACHE being set, the whole directive should be matched
	 * exactly. That's why we remember the matched prefix with cc_dir_flag
	 * and set the flag after ensuring there's no suffix.
	 */
	parser->cc_dir_flag = 0;

	__FSM_STATE(Req_I_CC_start) {
		/* Spaces already skipped by RGen_LWS */
		/* Leading comma allowed per RFC 7230 Section 7 */
		if (c == ',')
			__FSM_I_MOVE(Req_I_CC_start_Comma);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_CC);
		/* Forbid empty header value */
		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Req_I_CC_start_Comma) {
		if (IS_WS(c))
			__FSM_I_MOVE(Req_I_CC_start_Comma);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_CC);
		/* Forbid empty header value and double commas */
		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Req_I_CC) {
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
		TRY_STR("max-age=", Req_I_CC_m, Req_I_CC_MaxAgeVBeg);
		TRY_STR("min-fresh=", Req_I_CC_m, Req_I_CC_MinFreshVBeg);
		TRY_STR("max-stale", Req_I_CC_m, Req_I_CC_MaxStale);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_n) {
		TRY_STR_LAMBDA("no-cache", {
			parser->cc_dir_flag = TFW_HTTP_CC_NO_CACHE;
		}, Req_I_CC_n, Req_I_CC_Flag);
		TRY_STR_LAMBDA("no-store", {
			parser->cc_dir_flag = TFW_HTTP_CC_NO_STORE;
		}, Req_I_CC_n, Req_I_CC_Flag);
		TRY_STR_LAMBDA("no-transform", {
			parser->cc_dir_flag = TFW_HTTP_CC_NO_TRANSFORM;
		}, Req_I_CC_n, Req_I_CC_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_o) {
		TRY_STR_LAMBDA("only-if-cached", {
			parser->cc_dir_flag = TFW_HTTP_CC_OIFCACHED;
		}, Req_I_CC_o, Req_I_CC_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_Flag) {
		/* A start of a standard directive successfully detected */
		if (IS_WS(c) || c == ',' || IS_CRLF(c)) {
			req->cache_ctl.flags |= parser->cc_dir_flag;
			__FSM_I_JMP(Req_I_EoT);
		}
		/* ...but the directive appears to have an unknown suffix */
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_REQUIRE_FIRST_DIGIT(Req_I_CC_MaxAgeVBeg, Req_I_CC_MaxAgeV);

	__FSM_STATE(Req_I_CC_MaxAgeV) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_uint_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			__FSM_EXIT(__fsm_n);
		req->cache_ctl.max_age = parser->_acc;
		req->cache_ctl.flags |= TFW_HTTP_CC_MAX_AGE;
		__FSM_I_MOVE_n(Req_I_EoT, __fsm_n);
	}

	__FSM_REQUIRE_FIRST_DIGIT(Req_I_CC_MinFreshVBeg, Req_I_CC_MinFreshV);

	__FSM_STATE(Req_I_CC_MinFreshV) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_uint_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			__FSM_EXIT(__fsm_n);
		req->cache_ctl.min_fresh = parser->_acc;
		req->cache_ctl.flags |= TFW_HTTP_CC_MIN_FRESH;
		__FSM_I_MOVE_n(Req_I_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_MaxStale) {
		if (c == '=')
			__FSM_I_MOVE(Req_I_CC_MaxStaleVBeg);
		if (IS_WS(c) || c == ',' || IS_CRLF(c)) {
			req->cache_ctl.max_stale = UINT_MAX;
			req->cache_ctl.flags |= TFW_HTTP_CC_MAX_STALE;
			__FSM_I_JMP(Req_I_EoT);
		}
		/* something like "max-staledfgh$!dgh" */
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_REQUIRE_FIRST_DIGIT(Req_I_CC_MaxStaleVBeg, Req_I_CC_MaxStaleV);

	__FSM_STATE(Req_I_CC_MaxStaleV) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_uint_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			__FSM_EXIT(__fsm_n);
		req->cache_ctl.max_stale = parser->_acc;
		req->cache_ctl.flags |= TFW_HTTP_CC_MAX_STALE;
		__FSM_I_MOVE_n(Req_I_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_Ext) {
		/* Any directive we don't understand.
		 * Here we just skip all the tokens, double quotes and equal signs.
		 */
		__FSM_I_MATCH_MOVE(qetoken, Req_I_CC_Ext);

		__FSM_I_MOVE_n(Req_I_EoT, __fsm_sz);
	}

	/* End of term. */
	__FSM_STATE(Req_I_EoT) {
		/*
		 * RFC 7234 uses RFC 7230 for token list definition.
		 * Per RFC 7230 Section 7 sender is required to send
		 * non-empty tokens i.e. no two consequtive commas allowed.
		 * However, this section also mentiones compatibility with
		 * older implementations that might send a limited amount of
		 * empty directives/consecutive commas as allowed, for example,
		 * by RFC 2616 HTTP/1.1 specification.
		 * Here we forbid consecutive commas completely.
		 */
		if (IS_WS(c))
			__FSM_I_MOVE(Req_I_EoT);
		if (c == ',')
			__FSM_I_MOVE(Req_I_After_Comma);
		if (IS_CRLF(c))
			__FSM_EXIT(__data_processed(p));
		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Req_I_After_Comma) {
		if (IS_WS(c))
			__FSM_I_MOVE(Req_I_After_Comma);

		parser->_acc = 0;
		if (IS_TOKEN(c)) {
			/* reinit for next token */
			parser->cc_dir_flag = 0;
			__FSM_I_JMP(Req_I_CC);
		}
		/* Trailing comma allowed per RFC 7230 Section 7. */
		if (IS_CRLF(c))
			__FSM_EXIT(__data_processed(p));

		__FSM_EXIT(TFW_BLOCK);
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
	 * Here we build a header value string manually to split it in chunks:
	 * chunk bounds are at least at name start, value start and value end.
	 * This simplifies the cookie search, http_sticky uses it.
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
	 * in a separate TfwStr chunk.
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
			/*
			 * No-fixup function with additional fixups above.
			 * This macro will never fixup the chunk, because
			 * we won't reach this branch with
			 * p + __fsm_sz == data + len.
			 */
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

void h2_set_hdr_if_nmatch(TfwHttpReq *req, const TfwCachedHeaderState *cstate)
{
	if (cstate->is_set && cstate->ifnmatch_etag_any)
		req->cond.flags |= TFW_HTTP_COND_ETAG_ANY;
}

/**
 * Parse ETag if message is a response or If-None-Match if it's a request.
 *
 * Function have extended behaviour when processing client connection.
 *
 * RFC 7232 2.3.
 */
static int
__parse_etag_or_if_nmatch(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int no_quotes, r = CSTR_NEQ;
	bool if_nmatch = TFW_CONN_TYPE(hm->conn) & Conn_Clnt;
	__FSM_DECLARE_VARS(hm);

	/*
	 * ETag value and closing DQUOTE is placed into separate chunks marked
	 * with flags TFW_STR_VALUE.
	 * Closing DQUOTE is used to support empty Etags. Opening is not added
	 * to simplify usage of tfw_stricmpspn()
	 *
	 * Note: Weak indicator is case-sensitive!
	 */

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_Etag) {
		TfwHttpReq *req = (TfwHttpReq *)hm; /* for If-None-Match. */

		/*
		* RFC 7232 3.3:
		*
		* A recipient MUST ignore If-Modified-Since if the request contains an
		* If-None-Match header field.
		*/
		if (if_nmatch
		    && req->cond.flags & TFW_HTTP_COND_IF_MSINCE) {
			req->cond.m_date = 0;
			req->cond.flags &= ~TFW_HTTP_COND_IF_MSINCE;
		}

		if (likely(c == '"')) {
			if (if_nmatch)
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

		if (if_nmatch && c == '*') {
			if (req->cond.flags & TFW_HTTP_COND_ETAG_LIST)
				return CSTR_NEQ;

			req->cond.flags |= TFW_HTTP_COND_ETAG_ANY;
			parser->cstate.is_set = 1;
			parser->cstate.ifnmatch_etag_any = 1;
			__FSM_I_MOVE_fixup(I_EoL, 1, 0);
		}

		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_Etag, 1, 0);

		/*
		 * According to RFC 9110 8.8.3:
		 * An entity-tag consists of an opaque quoted string, possibly
		 * prefixed by a weakness indicator.
		 * But unfortunately many do not follow RFC and send Etag
		 * without double quotes (wordpress for example), so we
		 * should process such Etag here.
		 */
		if (!if_nmatch) {
			__set_bit(TFW_HTTP_B_HDR_ETAG_HAS_NO_QOUTES, msg->flags);
			parser->_i_st = &&I_Etag_Val;
			goto I_Etag_Val;
		}
		return CSTR_NEQ;
	}

	__FSM_TX_ETAG(I_Etag_W, '/', I_Etag_We);
	__FSM_TX_ETAG(I_Etag_We, '"', I_Etag_Weak);

	__FSM_STATE(I_Etag_Weak) {
		__FSM_JMP(I_Etag_Val);
	}

	/*
	 * ETag-value can have zero length, but we still have to store it
	 * in separate TfwStr chunk.
	 */
	__FSM_STATE(I_Etag_Val) {
		no_quotes = test_bit(TFW_HTTP_B_HDR_ETAG_HAS_NO_QOUTES,
				     msg->flags);
		__FSM_I_MATCH_MOVE_fixup(etag, I_Etag_Val, TFW_STR_VALUE);
		c = *(p + __fsm_sz);
		/*
		 * Since we process Etags which are not enclosed in double
		 * quotes, we check that there is quote at the end of Etag
		 * only in case if it is in it's begin.
		 */
		if (likely(c == '"' && !no_quotes)) {
			__FSM_I_MOVE_fixup(I_EoT, __fsm_sz + 1, TFW_STR_VALUE);
		}
		if (unlikely(IS_CRLFWS(c)) && no_quotes) {
			__FSM_I_MOVE_fixup(I_EoT, __fsm_sz, __fsm_sz ?
					   TFW_STR_VALUE : 0);
		}
		return CSTR_NEQ;
	}

	/* End of ETag */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c)) {
			no_quotes = test_bit(TFW_HTTP_B_HDR_ETAG_HAS_NO_QOUTES,
					     msg->flags);
			if (!no_quotes)
				__FSM_I_MOVE_fixup(I_EoT, 1, TFW_STR_OWS);
			else
				__FSM_MOVE_nofixup(I_EoT);
		}
		if (IS_CRLF(c))
			return __data_off(p);
		if (if_nmatch && c == ',')
			__FSM_I_MOVE_fixup(I_Etag, 1, 0);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_EoL) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_EoL, 1, TFW_STR_OWS);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_etag_or_if_nmatch);

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
			__FSM_I_JMP(Req_I_H);
		if (likely(c == '['))
			__FSM_I_MOVE_flag(Req_I_H_v6, TFW_STR_VALUE);
		if (unlikely(IS_CRLFWS(c)))
			return 0; /* empty Host header */
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_H) {
		/* See Req_UriAuthority processing. */
		if (likely(isalnum(c) || c == '.' || c == '-'))
			__FSM_I_MOVE_flag(Req_I_H, TFW_STR_VALUE);
		if (p - data) {
			__msg_hdr_chunk_fixup(data, (p - data));
			__msg_chunk_flags(TFW_STR_VALUE);
		}
		parser->_i_st = &&Req_I_H_End;
		goto Req_I_H_End;
	}

	__FSM_STATE(Req_I_H_End) {
		if (c == ':') {
			parser->_acc = 0;
			__FSM_I_MOVE_fixup(Req_I_H_Port, 1, 0);
		}
		if (IS_CRLFWS(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_H_v6) {
		/* See Req_UriAuthorityIPv6 processing. */
		if (likely(isxdigit(c) || c == ':'))
			__FSM_I_MOVE_flag(Req_I_H_v6, TFW_STR_VALUE);
		if (likely(c == ']')) {
			__msg_hdr_chunk_fixup(data, (p - data + 1));
			__msg_chunk_flags(TFW_STR_VALUE);
			parser->_i_st = &&Req_I_H_End;
			p += 1;
			if (unlikely(__data_off(p) >= len))
				__FSM_EXIT(TFW_POSTPONE);
			goto Req_I_H_End;
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_H_Port) {
		/* See Req_UriPort processing. */
		if (unlikely(IS_CRLFWS(c))) {
			if (!req->host_port)
				/* Header ended before port was parsed. */
				return CSTR_NEQ;
			return __data_off(p);
		}
		__fsm_sz = __data_remain(p);
		__fsm_n = __parse_ulong_ws(p, __data_remain(p), &parser->_acc,
					   USHRT_MAX);
		switch (__fsm_n) {
		case CSTR_BADLEN:
		case CSTR_NEQ:
			return CSTR_NEQ;
		case CSTR_POSTPONE:
			req->host_port = parser->_acc;
			__FSM_I_MOVE_fixup(Req_I_H_Port, __fsm_sz, TFW_STR_VALUE);
		default:
			req->host_port = parser->_acc;
			if (!req->host_port)
				return CSTR_NEQ;
			parser->_acc = 0;
			__FSM_I_MOVE_fixup(Req_I_H_Port, __fsm_n, TFW_STR_VALUE);
		}
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

static int
__check_date(unsigned int year, unsigned int month, unsigned int day,
	     unsigned int hour, unsigned int min, unsigned int sec)
{
	static const unsigned mday[] = { 31, 28, 31, 30, 31, 30,
	                                 31, 31, 30, 31, 30, 31 };

	if (hour > 23 || min > 59 || sec > 59)
		return CSTR_NEQ;

	if (day == 29 && month == 2) {
		if ((year & 3) || ((year % 100 == 0) && (year % 400) != 0))
			return CSTR_NEQ;
	} else if (day > mday[month - 1]) {
		return CSTR_NEQ;
	}

	/*
	 * There is no such restriction in the RFC, but it's Nginx behaviour
	 * (we take it as standard de facto).
	 */
	if (year < 1970)
		return CSTR_NEQ;

	return 0;
}

#define SEC24H		(24 * 3600)
/* Number of days between March 1, 1 BC and March 1, 1970 */
#define EPOCH_DAYS	(1970 * 365 + 1970 / 4 - 1970 / 100 + 1970 / 400)

/*
 * Returns number of seconds since 1970-01-01.
 *
 * These algorithms internally assume that March 1 is the first day of the year.
 *
 * @return number of seconds since epoch in GMT.
 */
static long
__date_secs(unsigned int year, unsigned int month, unsigned int day,
	    unsigned int hour, unsigned int min, unsigned int sec)
{
	long days;

	if (__check_date(year, month, day, hour, min, sec) < 0)
		return CSTR_NEQ;

	year -= month <= 2;
	/* Days in the current year since March 1 */
	days = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	/* Days from March 1, 1 BC till March 1 of the current year */
	days += year * 365 + year / 4 - year / 100 + year / 400;
	/* 31 and 28 days were in January and February 1970 */
	return (days - EPOCH_DAYS + 31 + 28) * SEC24H +
	       hour * 3600 + min * 60 + sec;
}

static int
__parse_month(unsigned int month_int)
{
	switch (month_int) {
	case TFW_CHAR4_INT(' ', 'J', 'a', 'n'):
		return 1;
	case TFW_CHAR4_INT(' ', 'F', 'e', 'b'):
		return 2;
	case TFW_CHAR4_INT(' ', 'M', 'a', 'r'):
		return 3;
	case TFW_CHAR4_INT(' ', 'A', 'p', 'r'):
		return 4;
	case TFW_CHAR4_INT(' ', 'M', 'a', 'y'):
		return 5;
	case TFW_CHAR4_INT(' ', 'J', 'u', 'n'):
		return 6;
	case TFW_CHAR4_INT(' ', 'J', 'u', 'l'):
		return 7;
	case TFW_CHAR4_INT(' ', 'A', 'u', 'g'):
		return 8;
	case TFW_CHAR4_INT(' ', 'S', 'e', 'p'):
		return 9;
	case TFW_CHAR4_INT(' ', 'O', 'c', 't'):
		return 10;
	case TFW_CHAR4_INT(' ', 'N', 'o', 'v'):
		return 11;
	case TFW_CHAR4_INT(' ', 'D', 'e', 'c'):
		return 12;
	default:
		return CSTR_NEQ;
	}
}

typedef enum {
	RFC_822,
	RFC_850,
	ISOC,
} date_type_t;

static int
__parse_http_date(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	static const void * const st[][23] __annotate_jump_table = {
		[RFC_822] = {
			&&I_Day, &&I_Day, &&I_SP,
			&&I_MonthBeg, &&I_Month, &&I_Month, &&I_SP,
			&&I_Year, &&I_Year, &&I_Year, &&I_Year, &&I_SP,
			&&I_Hour, &&I_Hour, &&I_SC,
			&&I_Min, &&I_Min, &&I_SC,
			&&I_Sec, &&I_Sec, &&I_SP,
			&&I_GMT, /*&&I_Res*/
			/*
			 * The I_Res is omitted because the transition
			 * from I_GMT to I_Res is explicitly indicated
			 * in the code below
			 */
		},
		[RFC_850] = {
			&&I_Day, &&I_Day, &&I_Minus,
			&&I_MonthBeg, &&I_Month, &&I_Month, &&I_Minus,
			&&I_Year, &&I_Year, &&I_SP,
			&&I_Hour, &&I_Hour, &&I_SC,
			&&I_Min, &&I_Min, &&I_SC,
			&&I_Sec, &&I_Sec, &&I_SP,
			&&I_GMT, /*&&I_Res*/
			/*
			 * The I_Res is omitted because the transition
			 * from I_GMT to I_Res is explicitly indicated
			 * in the code below
			 */
		},
		[ISOC] = {
			&&I_MonthBeg, &&I_Month, &&I_Month, &&I_SP,
			&&I_SpaceOrDay, &&I_Day, &&I_SP,
			&&I_Hour, &&I_Hour, &&I_SC,
			&&I_Min, &&I_Min, &&I_SC,
			&&I_Sec, &&I_Sec, &&I_SP,
			&&I_Year, &&I_Year, &&I_Year, &&I_Year,
			&&I_Res
		}
	};
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START_ALT(parser->_i_st);

	/*
	 * Skip a weekday with comma (e.g. "Sun,") as redundant
	 * information.
	 */
	__FSM_STATE(I_WDate1) {
		if (likely('A' <= c && c <= 'Z'))
			__FSM_I_MOVE(I_WDate2);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_WDate2) {
		if (likely('a' <= c && c <= 'z'))
			__FSM_I_MOVE(I_WDate3);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_WDate3) {
		if (likely('a' <= c && c <= 'z'))
			__FSM_I_MOVE(I_WDate4);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_WDate4) {
		parser->_acc = 0;
		parser->month_int = ((size_t)' ') << 24;
		if (likely(c == ',')) {
			parser->date.type = RFC_822;
			__FSM_I_MOVE(I_WDaySP);
		}
		if ('a' <= c && c <= 'z') {
			parser->date.type = RFC_850;
			__FSM_I_MOVE(I_WDate5);
		}
		if (c == ' ') {
			parser->date.type = ISOC;
			__FSM_I_MOVE_BY_REF(
				st[parser->date.type][parser->date.pos]);
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_WDate5) {
		if ('a' <= c && c <= 'z')
			__FSM_I_MOVE(I_WDate5);
		if (c == ',')
			__FSM_I_MOVE(I_WDaySP);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_WDaySP) {
		if (likely(c == ' '))
			__FSM_I_MOVE_BY_REF(
				st[parser->date.type][parser->date.pos]);
		return CSTR_NEQ;
	}

#define __NEXT_TEMPL_STATE()						\
do {									\
	++parser->date.pos;						\
	__FSM_I_MOVE_BY_REF(st[parser->date.type][parser->date.pos]);	\
} while (0)

	__FSM_STATE(I_SP) {
		if (likely(c == ' '))
			__NEXT_TEMPL_STATE();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Minus) {
		if (likely(c == '-'))
			__NEXT_TEMPL_STATE();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_SC) {
		if (likely(c == ':'))
			__NEXT_TEMPL_STATE();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_SpaceOrDay) {
		if (c == ' ')
			__NEXT_TEMPL_STATE();
		if (isdigit(c)) {
			parser->date.day = parser->date.day * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Day) {
		if (isdigit(c)) {
			parser->date.day = parser->date.day * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_MonthBeg) {
		if ('A' <= c && c <= 'Z') {
			parser->month_int =
				((size_t)c) << 24 | (parser->month_int >> 8);
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Month) {
		if ('a' <= c && c <= 'z') {
			parser->month_int =
				((size_t)c) << 24 | (parser->month_int >> 8);
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Year) {
		if (isdigit(c)) {
			parser->date.year = parser->date.year * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Hour) {
		if (isdigit(c)) {
			parser->date.hour = parser->date.hour * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Min) {
		if (isdigit(c)) {
			parser->date.min = parser->date.min * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Sec) {
		if (isdigit(c)) {
			parser->date.sec = parser->date.sec * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}
#undef __NEXT_TEMPL_STATE

	__FSM_STATE(I_GMT) {

		TRY_STR_BY_REF("gmt", &&I_GMT,
			/*
			 * The st[][]-table is not used because it is known
			 * that I_GMT is followed by I_Res.
			 */
			&&I_Res);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Res) {
		int month;
		long date;

		if (parser->date.day == 0)
			return CSTR_NEQ;

		month = __parse_month(parser->month_int);
		if (month < 0)
			return CSTR_NEQ;

		/*
		 * RFC 7231 7.1.1.1:
		 *
		 * Recipients of a timestamp value in rfc850-date format,
		 * which uses a two-digit year, MUST interpret a timestamp
		 * that appears to be more than 50 years in the future as
		 * representing the most recent year in the past that had
		 * the same last two digits.
		 *
		 * Parser follows here to the simplified Nginx behaviour
		 * and doesn't satisfy the RFC.
		 */
		if (parser->date.year < 100 && parser->date.type == RFC_850)
			parser->date.year += (parser->date.year < 70) ? 2000
			                                              : 1900;

		date = __date_secs(parser->date.year, month,
		                   parser->date.day, parser->date.hour,
		                   parser->date.min, parser->date.sec);
		if (date < 0)
			return CSTR_NEQ;
		parser->_date = date;
		__FSM_JMP(I_EoL);
	}

	__FSM_STATE(I_EoL) {
		parser->_acc = 0;
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

	/*
	 * RFC 7230 3.2.2:
	 *
	 * A sender MUST NOT generate multiple header fields with the same field
	 * name in a message unless either the entire field value for that
	 * header field is defined as a comma-separated list [i.e., #(values)]
	 * or the header field is a well-known exception.
	 */
	if (unlikely(req->cond.flags & TFW_HTTP_COND_IF_MSINCE))
		return r;

	/*
	 * RFC 7232 3.3:
	 *
	 * A recipient MUST ignore If-Modified-Since if the request contains an
	 * If-None-Match header field.
	 *
	 * A recipient MUST ignore the If-Modified-Since header field if the
	 * received field-value is not a valid HTTP-date, or if the request
	 * method is neither GET nor HEAD.
	 */
	if (unlikely(TFW_STR_EMPTY(&req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH])
		    && (req->method == TFW_HTTP_METH_HEAD
	                || req->method == TFW_HTTP_METH_GET))) {
		r = __parse_http_date(msg, data, len);
	}

	if (r < 0 && r != CSTR_POSTPONE) {
		/* On error just swallow the rest of the line. */
		parser->_date = 0;
		parser->_acc = 0;
		parser->_i_st = __I_EoL;
		/* Use __parse_http_date just to go to the EoL. */
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
		TRY_STR_fixup(&TFW_STR_STRING("no-cache"), I_Pragma,
			      I_Pragma_NoCache);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Pragma_Ext);
	}

	__FSM_STATE(I_Pragma_NoCache) {
		if (IS_WS(c) || c == ',' || IS_CRLF(c))
			msg->cache_ctl.flags |= TFW_HTTP_CC_PRAGMA_NO_CACHE;
		/* Fall through. */
	}

	__FSM_STATE(I_Pragma_Ext) {
		/* Verify and just skip the extensions. */
		__FSM_I_MATCH_MOVE_fixup(qetoken, I_Pragma_Ext, 0);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',') {
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			p += __fsm_sz;
			__FSM_I_JMP(I_EoT);
		}
		if (IS_CRLF(c)) {
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			return __data_off(p + __fsm_sz);
		}

		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_EoT, 1, TFW_STR_OWS);
		if (c == ',')
			__FSM_I_MOVE_fixup(I_EoT, 1, 0);
		if (IS_CRLF(c))
			return __data_off(p);
		__FSM_I_JMP(I_Pragma_Ext);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_pragma);

/**
 * Parse Upgrade header field. Its semantics is described in RFC 7230 6.1.
 * For now only websocket protocol supported.
 */
static int
__parse_upgrade(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	parser->hdr.flags |= TFW_STR_HBH_HDR;

	/*
	 * Here we build a header value string manually to split it in chunks:
	 * next chunk starts after ',' or ' ' list delimiter and '/' delimiter.
	 * Optional protocol version chunk separate from protocol name chunk.
	 */
	__FSM_STATE(I_UpgradeProtocolStart) {
		static const TfwStr s_websocket = TFW_STR_STRING("websocket");
		TRY_STR_LAMBDA_fixup_flag(&s_websocket, &parser->hdr, {
			__set_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, &parser->_acc);
		}, I_UpgradeProtocolStart, I_UpgradeProtocol, TFW_STR_NAME);

		__FSM_I_MATCH_MOVE_fixup(token, I_UpgradeProtocol,
					 TFW_STR_NAME);
		if (__fsm_sz == 0) {
			if (test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET,
				     &parser->_acc))
			{
				__set_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET,
					  msg->flags);
				__FSM_I_JMP(I_UpgradeProtocolEnd);
			}

			/*
			 * Protocol name should contain at least 1 character.
			 */
			return CSTR_NEQ;
		}

		__set_bit(TFW_HTTP_B_UPGRADE_EXTRA, msg->flags);
		__FSM_I_JMP(I_UpgradeProtocolEnd);
	}

	/*
	 * At this state we know that we saw at least one character in
	 * protocol name and now we can pass zero length token.
	 */
	__FSM_STATE(I_UpgradeProtocol) {
		__FSM_I_MATCH_MOVE_fixup(token, I_UpgradeProtocol, TFW_STR_NAME);
		if (__fsm_sz == 0) {
			if (test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET,
				     &parser->_acc))
			{
				__set_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET,
					  msg->flags);
			}
		} else {
			__set_bit(TFW_HTTP_B_UPGRADE_EXTRA, msg->flags);
		}

		__FSM_I_JMP(I_UpgradeProtocolEnd);
	}

	__FSM_STATE(I_UpgradeProtocolEnd) {
		if (__fsm_sz) {
			/* Save protocol name */
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			__FSM_I_chunk_flags(TFW_STR_NAME);
		}

		p += __fsm_sz;
		if (likely(IS_CRLF(*(p)))) {
			__FSM_EXIT(__data_processed(p));
		}
		if (IS_WS(*p) || *p == ',')
			__FSM_I_MOVE_fixup(I_EoLE, 1, 0);
		if (*p == '/')
			__FSM_I_MOVE_fixup(I_UpgradeVersionStart, 1, 0);
		return CSTR_NEQ;
	}

	/*
	 * Protocol version stored in a separate value TfwStr chunk.
	 * May not be empty. '/' already matched.
	 */
	__FSM_STATE(I_UpgradeVersionStart) {
		__FSM_I_MATCH_MOVE_fixup(token, I_UpgradeVersion,
					 TFW_STR_VALUE);
		if (likely(__fsm_sz))
			__FSM_I_JMP(I_UpgradeVersionEnd);
		return CSTR_NEQ;
	}

	/*
	 * At this state we know that we saw at least one character in
	 * protocol version and now we can pass zero length token.
	 */
	__FSM_STATE(I_UpgradeVersion) {
		__FSM_I_MATCH_MOVE_fixup(token, I_UpgradeVersion,
					 TFW_STR_VALUE);
		__FSM_I_JMP(I_UpgradeVersionEnd);
	}

	__FSM_STATE(I_UpgradeVersionEnd) {
		if (likely(__fsm_sz)) {
			/* Save protocol version */
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			__FSM_I_chunk_flags(TFW_STR_VALUE);
		}

		p += __fsm_sz;
		if (likely(IS_CRLF(*(p)))) {
			__FSM_EXIT(__data_processed(p));
		}
		if (IS_WS(*p) || *p == ',')
			__FSM_I_MOVE_fixup(I_EoLE, 1, 0);
		return CSTR_NEQ;
	}

	/* End of list entry */
	__FSM_STATE(I_EoLE) {
		if (IS_WS(*p) || *p == ',')
			__FSM_I_MOVE_fixup(I_EoLE, 1, 0);

		if (IS_TOKEN(*p)) {
			parser->_acc = 0; /* reinit for next list entry */
			__FSM_I_JMP(I_UpgradeProtocolStart);
		}
		if (IS_CRLF(*p))
			__FSM_EXIT(__data_processed(p));
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_upgrade);

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

/**
 * Parse Forwarded header, RFC 7239.
 *
 * Defines logic to parse Forwarded header as set of unique pairs Param=Value
 * separated by semicolon. Also "Value" part can be in double quotes. Whole
 * field of header MUST be parsed. To have a handy way to process parsed string,
 * we can fixup these params as Key=Value. To achieve this we set flag
 * TFW_STR_NAME for "Param=" part and TFW_STR_VALUE for "Value" part. Semicolon
 * and quotes fixup without these flags.
 */
static int
__req_parse_forwarded(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

/* List of flags used to mark parameters as parsed. */
#define FWD_SET_FOR			0x00000001
#define FWD_SET_HOST			0x00000002
#define FWD_SET_PROTO			0x00000004
#define FWD_SET_BY			0x00000008

/*
 * Set of macroses which give possibility to explicitly open chunk and fixup
 * last opened chunk. It allocates new chunk in @parser->hdr which stay opened
 * and requires to fixup(update length) explicity.
 *
 * Open chunk in certain state, then move to another state and move @p pointer
 * without updating opened chunk, do some checks and then fixup the last opened
 * chunk. It allows us to fixup arbitrary length data as single chunk.
 *
 * In these macroses we are using:
 * 1. tfw_str_add_compound() for allocating new chunk in specified TfwStr.
 * 2. __msg_field_open() for chunk opening. Just inits @data and &skb of @str
 * but leaves length zeroed.
 * 3. tfw_str_updlen() for fixupping chunk. Simply updates length of the last
 * chunk and of whole @str. tfw_str_updlen() can't update length of chunk that
 * already have length. It means before call tfw_str_updlen() for @parser->hdr
 * we need ensure that last chunk isn't fixuped(length of chunk is zero). If
 * last chunk have already been fixuped, we need to use regular fixup functions.
 * e.g __msg_field_fixup_pos(). We can't use __msg_field_fixup_pos() with
 * opened chunk, because last chunk will be updated, but total length of TfwStr
 * (parser->header) will !not! be updated.
 *
 * Also, need be careful with fragmented data, before jump to next SKB need to
 * fixup current chunk.
 */

/* If last chunk of @parser->hdr is opened fixup it, otherwise do nothing. */
#define FWD_FIXUP_CURR()						\
do {									\
	TfwStr *ch = TFW_STR_CURR(&parser->hdr);			\
	if (TFW_STR_EMPTY(ch))						\
		tfw_str_updlen(&parser->hdr, p + 1);			\
} while(0)

/*
 * If last chunk of @parser->hdr is opened move by 1 to @to and fixup,
 * otherwise __FSM_I_MOVE_fixup.
 */
#define FWD_MOVE_FIXUP_CURR(to, flag)					\
do {									\
	TfwStr *ch = TFW_STR_CURR(&parser->hdr);			\
	if (TFW_STR_EMPTY(ch)) {					\
		p += 1;							\
		parser->_i_st = &&to;					\
		tfw_str_updlen(&parser->hdr, p);			\
		if (unlikely(__data_off(p) >= len))			\
			__FSM_EXIT(TFW_POSTPONE); 			\
		goto to; 						\
	}								\
	__FSM_I_MOVE_fixup(to, 1, flag);				\
} while (0)

/*
 * Allocate chunk and open it. Then inc @p and move to @to.
 * If data exhausted fixup current chunk.
 */
#define FWD_MOVE_OPEN_CHUNK(to, flag)					\
do {									\
	TfwStr *ch = tfw_str_add_compound(hm->pool, &parser->hdr);	\
	if (!ch) { 							\
		T_WARN("Cannot grow HTTP data string\n"); 		\
		return CSTR_NEQ; 					\
	} 								\
	__msg_field_open(ch, p); 					\
	__FSM_I_field_chunk_flags(ch, flag);				\
	p += 1;								\
	if (unlikely(__data_off(p) >= len)) {				\
		parser->_i_st = &&to;					\
		tfw_str_updlen(&parser->hdr, p);			\
		__FSM_EXIT(TFW_POSTPONE); 				\
	} 								\
	goto to; 							\
} while (0)

/* Fixup current @p + n before postpone without bounds check. */
#define __FSM_I_POSTPONE_fixup(to, n, flag)				\
do {									\
	BUG_ON(!&parser->hdr.data);					\
	BUG_ON(n < 0);							\
	__msg_field_fixup_pos(&parser->hdr, p, n);			\
	__FSM_I_field_chunk_flags(&parser->hdr, flag);			\
	parser->_i_st = &&to;						\
	__FSM_EXIT(TFW_POSTPONE);					\
} while (0)

/*
 * Tries to find parameter in header.
 * Parsing fails if parameter not a unique in current header.
 *
 * RFC 7239 section 4: 
 * Each parameter MUST NOT occur more than once per field-value.
 */
#define FWD_TRY_STR_NAME(name, curr_st, next_st, fwd_flag)		\
	TRY_STR_LAMBDA_fixup_flag(&TFW_STR_STRING(name),		\
				  &parser->hdr, { 			\
				  if (parser->flags & fwd_flag)		\
					return CSTR_NEQ;		\
				  parser->flags |= fwd_flag;		\
				  }, curr_st, next_st,			\
				  TFW_STR_NAME)

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_Fwd) {
		FWD_TRY_STR_NAME("for=", Req_I_Fwd, Req_I_Fwd_For_Start,
				 FWD_SET_FOR);
		FWD_TRY_STR_NAME("host=", Req_I_Fwd, Req_I_Fwd_Host_Start,
				 FWD_SET_HOST);
		FWD_TRY_STR_NAME("proto=", Req_I_Fwd, Req_I_Fwd_Proto_Start,
				 FWD_SET_PROTO);
		FWD_TRY_STR_NAME("by=", Req_I_Fwd, Req_I_Fwd_By_Start,
				 FWD_SET_BY);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_For_List) {
		/* Eat OWS before parameter. */
		if (unlikely(IS_WS(c)))
			__FSM_I_MOVE_fixup(Req_I_Fwd_For_List, 1, 0);
		/* Find next "for=" in list. */
		FWD_TRY_STR_NAME("for=", Req_I_Fwd_For_List,
				 Req_I_Fwd_For_Start,
				 0);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_For_Start) {
		if (likely(c == '"'))
			__FSM_I_MOVE_fixup(Req_I_Fwd_For_Quoted, 1, 0);
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_For_Unquoted) {
		/*
		 * Eat IP address or host name.
		 *
		 * TODO: parse/validate IP addresses and textual IDs.
		 * Currently we just validate separate characters, but the
		 * whole value may be invalid (e.g. "---[_..[[").
		 */
		__FSM_I_MATCH_MOVE_fixup(xff, Req_I_Fwd_For_Node_Id_Unquoted,
					 TFW_STR_VALUE);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_I_MOVE_fixup(Req_I_Fwd_For_Sep, __fsm_sz, TFW_STR_VALUE);
	}

	/*
	 * At this state we know that we saw at least one character as
	 * a host address and now we can pass zero length token.
	 */
	__FSM_STATE(Req_I_Fwd_For_Node_Id_Unquoted) {
		__FSM_I_MATCH_MOVE_fixup(xff, Req_I_Fwd_For_Node_Id_Unquoted,
					 TFW_STR_VALUE);
		__FSM_I_MOVE_fixup(Req_I_Fwd_For_Sep, __fsm_sz, TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_For_Quoted) {
		__FSM_I_MATCH_MOVE_fixup(xff, Req_I_Fwd_For_Node_Id_Quoted,
					 TFW_STR_VALUE);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_I_MOVE_fixup(Req_I_Fwd_For_Sep_Quoted, __fsm_sz,
				   TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_For_Node_Id_Quoted) {
		__FSM_I_MATCH_MOVE_fixup(xff, Req_I_Fwd_For_Node_Id_Quoted,
					 TFW_STR_VALUE);
		__FSM_I_MOVE_fixup(Req_I_Fwd_For_Sep_Quoted, __fsm_sz,
				   TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_For_Sep_Quoted) {
		if (unlikely(c != '"'))
			return CSTR_NEQ;
		FWD_MOVE_OPEN_CHUNK(Req_I_Fwd_For_Sep_Quoted_N, 0);
	}

	__FSM_STATE(Req_I_Fwd_For_Sep_Quoted_N) {
		/* At this point we try to fixup '"' with near symbol. */

		/* EOL after quote */
		if (likely(IS_CRLF(c))) {
			FWD_FIXUP_CURR();
			return __data_off(p);
		}
		/* ';' after quote */
		if (likely(c == ';'))
			FWD_MOVE_FIXUP_CURR(Req_I_Fwd, 0);
		/* ',' after quote */
		if (unlikely(c == ','))
			FWD_MOVE_FIXUP_CURR(Req_I_Fwd_For_List, 0);
		/* WS after quote */
		if (unlikely(IS_WS(c)))
			FWD_MOVE_FIXUP_CURR(Req_I_Fwd_For_Sep_End, 0);

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_For_Sep) {
		/* go to next param */
		if (likely(c == ';'))
			__FSM_I_MOVE_fixup(Req_I_Fwd, 1, 0);
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_For_Sep_End) {
		/*
		 * Proxy chains are rare, so we expect that the list will end
		 * after the first node and we get EOL here.
		 */
		if (likely(IS_CRLF(c)))
			return __data_off(p);
		/*
		 * "for=" can be represented as comma
		 * separated list, find next one.
		 */
		if (unlikely(c == ','))
			__FSM_I_MOVE_fixup(Req_I_Fwd_For_List, 1, 0);
	        /* OWS before comma or before EOL (is unusual). */
		if (unlikely(IS_WS(c)))
			__FSM_I_MOVE_fixup(Req_I_Fwd_For_Sep_End, 1, 0);

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_Host_Start) {
		if (unlikely(IS_CRLFWS(c)))
			return CSTR_NEQ;
		if (likely(c == '"'))
			__FSM_I_MOVE_fixup(Req_I_Fwd_Host_Start_Quoted, 1, 0);
		/* Fall through */
	}

	/* Parse host parameter as defined in RFC 7230 5.4. */
	__FSM_STATE(Req_I_Fwd_Host_Unquoted) {
		__fsm_sz = 0;

		while (likely(isalnum(c) || c == '.' || c == '-')) {
			__fsm_sz++;
			c = *(p + __fsm_sz);
			if (unlikely(__data_off(p + __fsm_sz) >= len))
				__FSM_I_POSTPONE_fixup(Req_I_Fwd_Host_Unquoted,
						       __fsm_sz,
						       TFW_STR_VALUE);
		}
		__FSM_I_MOVE_fixup(Req_I_Fwd_Host_End_Unquoted, __fsm_sz,
				   TFW_STR_VALUE);
	}

	/*
	 * Quoted version of parse host, this implies we must have been already
	 * fixed up dquote without flags in previous state.
	 */
	__FSM_STATE(Req_I_Fwd_Host_Start_Quoted) {
		if (likely(c == '['))
			__FSM_I_MOVE_fixup(Req_I_Fwd_Host_v6_Quoted_Start, 1,
					   TFW_STR_VALUE);
		/* Block empty quotes */
		if (unlikely(c == '"'))
			return CSTR_NEQ;
		/* Fall through */
	}

	/* Parse host parameter as defined in RFC 7230 5.4. */
	__FSM_STATE(Req_I_Fwd_Host_Quoted) {
		__fsm_sz = 0;

		while (likely(isalnum(c) || c == '.' || c == '-')) {
			__fsm_sz++;
			c = *(p + __fsm_sz);
			if (unlikely(__data_off(p + __fsm_sz) >= len))
				__FSM_I_POSTPONE_fixup(Req_I_Fwd_Host_Quoted,
						       __fsm_sz,
						       TFW_STR_VALUE);
		}
		__FSM_I_MOVE_fixup(Req_I_Fwd_Host_End_Quoted, __fsm_sz,
				   TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_Host_v6_Quoted_Start) {
		/* Block empty braces */
		if (unlikely(c == ']'))
			return CSTR_NEQ;
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_Host_v6_Quoted) {
		__fsm_sz = 0;

		while (likely(isxdigit(c) || c == ':')) {
			__fsm_sz++;
			c = *(p + __fsm_sz);
			if (unlikely(__data_off(p + __fsm_sz) >= len))
				__FSM_I_POSTPONE_fixup(Req_I_Fwd_Host_v6_Quoted,
						       __fsm_sz,
						       TFW_STR_VALUE);
		}
		if (likely(c == ']'))
			__FSM_I_MOVE_fixup(Req_I_Fwd_Host_End_Quoted,
					   __fsm_sz + 1, TFW_STR_VALUE);

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_Host_End_Quoted) {
		if (c == ':')
			__FSM_I_MOVE_fixup(Req_I_Fwd_Host_Port_Quoted, 1, 0);
		__FSM_I_JMP(Req_I_Fwd_Next_Or_Finish_Quoted);
	}

	__FSM_STATE(Req_I_Fwd_Host_End_Unquoted) {
		if (c == ':')
			__FSM_I_MOVE_fixup(Req_I_Fwd_Host_Port_Unquoted, 1, 0);
		__FSM_I_JMP(Req_I_Fwd_Next_Or_Finish);
	}

	__FSM_STATE(Req_I_Fwd_Host_Port_Unquoted) {
		__fsm_sz = __data_remain(p);
		__fsm_n = __parse_ulong_ws_delim(p, __fsm_sz,
						 (unsigned long*)&parser->port,
						 USHRT_MAX);
		switch (__fsm_n) {
		case CSTR_BADLEN:
		case CSTR_NEQ:
			return CSTR_NEQ;
		case CSTR_POSTPONE:
			if (parser->port == 0 || parser->port > 65535)
				return CSTR_NEQ;
			__FSM_I_MOVE_fixup(Req_I_Fwd_Host_Port_Unquoted,
					   __fsm_sz, TFW_STR_VALUE);
		default:
			if (parser->port == 0 || parser->port > 65535)
				return CSTR_NEQ;
			__FSM_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish, __fsm_n,
					   TFW_STR_VALUE);
		}

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_Host_Port_Quoted) {
		__fsm_sz = __data_remain(p);
		__fsm_n = __parse_ulong_ws_delim(p, __fsm_sz,
						 (unsigned long*)&parser->port,
						 USHRT_MAX);
		switch (__fsm_n) {
		case CSTR_BADLEN:
		case CSTR_NEQ:
			return CSTR_NEQ;
		case CSTR_POSTPONE:
			if (parser->port == 0 || parser->port > 65535)
				return CSTR_NEQ;
			__FSM_I_MOVE_fixup(Req_I_Fwd_Host_Port_Quoted,
					   __fsm_sz, TFW_STR_VALUE);
		default:
			if (parser->port == 0 || parser->port > 65535)
				return CSTR_NEQ;
			__FSM_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish_Quoted,
					   __fsm_n,
					   TFW_STR_VALUE);
		}

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_Proto_Start) {
		if (unlikely(IS_CRLFWS(c)))
			return CSTR_NEQ;
		if (likely(c == '"'))
			__FSM_I_MOVE_fixup(Req_I_Fwd_Proto_Quoted_Start, 1, 0);
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_Proto_Unquoted) {
		/* RFC 3986: 3.1 list of allowed characters */
		__fsm_sz = 0;

		while (likely(isalnum(c) || c == '+' || c == '-' || c == '.')) {
			__fsm_sz++;
			c = *(p + __fsm_sz);
			if (unlikely(__data_off(p + __fsm_sz) >= len))
				__FSM_I_POSTPONE_fixup(Req_I_Fwd_Proto_Unquoted,
						       __fsm_sz,
						       TFW_STR_VALUE);
		}
		__FSM_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish, __fsm_sz,
				   TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_Proto_Quoted_Start) {
		/* Block empty quotes */
		if (unlikely(c == '"'))
			return CSTR_NEQ;
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_Proto_Quoted) {
		/* RFC 3986: 3.1 list of allowed characters */
		__fsm_sz = 0;

		while (likely(isalnum(c) || c == '+' || c == '-' || c == '.')) {
			__fsm_sz++;
			c = *(p + __fsm_sz);
			if (unlikely(__data_off(p + __fsm_sz) >= len))
				__FSM_I_POSTPONE_fixup(Req_I_Fwd_Proto_Quoted,
						       __fsm_sz,
						       TFW_STR_VALUE);
		}
		__FSM_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish_Quoted,
				   __fsm_sz, TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_By_Start) {
		if (likely(c == '"'))
			__FSM_I_MOVE_fixup(Req_I_Fwd_By_Quoted, 1, 0);
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_By_Unquoted) {
		__FSM_I_MATCH_MOVE_fixup(xff,
					 Req_I_Fwd_By_Node_Id_Unquoted,
					 TFW_STR_VALUE);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish, __fsm_sz,
				   TFW_STR_VALUE);
	}

	/*
	 * At this state we know that we saw at least one character as
	 * a host address and now we can pass zero length token.
	 */
	__FSM_STATE(Req_I_Fwd_By_Node_Id_Unquoted) {
		__FSM_I_MATCH_MOVE_fixup(xff,
					 Req_I_Fwd_By_Node_Id_Unquoted,
					 TFW_STR_VALUE);
		__FSM_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish, __fsm_sz,
				   TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_By_Quoted) {
		__FSM_I_MATCH_MOVE_fixup(xff, Req_I_Fwd_By_Node_Id_Quoted,
					 TFW_STR_VALUE);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish_Quoted, __fsm_sz,
				   TFW_STR_VALUE);
	}

	/*
	 * At this state we know that we saw at least one character as
	 * a host address and now we can pass zero length token.
	 */
	__FSM_STATE(Req_I_Fwd_By_Node_Id_Quoted) {
		__FSM_I_MATCH_MOVE_fixup(xff, Req_I_Fwd_By_Node_Id_Quoted,
					 TFW_STR_VALUE);
		__FSM_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish_Quoted, __fsm_sz,
				   TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_Next_Or_Finish) {
		if (c == ';')
			FWD_MOVE_FIXUP_CURR(Req_I_Fwd, 0);
		if (IS_CRLFWS(c)) {
			FWD_FIXUP_CURR();
			return __data_off(p);
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_Next_Or_Finish_Quoted) {
		if (unlikely(c != '"'))
			return CSTR_NEQ;
		FWD_MOVE_OPEN_CHUNK(Req_I_Fwd_Next_Or_Finish, 0);
	}
done:
	return r;

#undef FWD_SET_FOR
#undef FWD_SET_HOST
#undef FWD_SET_PROTO
#undef FWD_SET_BY
#undef FWD_FIXUP_CURR
#undef FWD_MOVE_FIXUP_CURR
#undef FWD_MOVE_OPEN_CHUNK
#undef __FSM_I_POSTPONE_fixup
#undef FWD_TRY_STR_NAME
}
STACK_FRAME_NON_STANDARD(__req_parse_forwarded);

/*
 * Parse a non-standard "X-Tempesta-Cache" header which may be used in a PURGE
 * request.
 */
static int
__req_parse_x_tempesta_cache(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_X_Tempesta_Cache) {
		/* "X-Tempesta-Cache" ":" method */
		TRY_STR_fixup(&TFW_STR_STRING("get"), Req_I_X_Tempesta_Cache,
			      I_Tempesta_Cache_get);
		/* If the method is not "GET" just ignore the rest of the
		 * header line. */
		__FSM_I_JMP(I_Tempesta_Cache_skip);
	}

	__FSM_STATE(I_Tempesta_Cache_get) {
		if (likely(IS_CRLF(c) || IS_WS(c))) {
			__set_bit(TFW_HTTP_B_PURGE_GET, hm->flags);
			if (IS_CRLF(c))
				return __data_off(p);
		}
		__FSM_I_JMP(I_Tempesta_Cache_skip);
	}

	__FSM_STATE(I_Tempesta_Cache_skip) {
		/* Skip the rest of the line. */
		__FSM_I_MATCH_MOVE(nctl, I_Tempesta_Cache_skip);
		if (!IS_CRLF(*(p + __fsm_sz)))
			return CSTR_NEQ;
		return __data_off(p + __fsm_sz);
	}
done:
	return r;
}
STACK_FRAME_NON_STANDARD(__req_parse_x_tempesta_cache);

static int
__parse_keep_alive(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_KeepAlive) {
		TRY_STR_fixup(&TFW_STR_STRING("timeout="), I_KeepAlive,
			      I_KeepAliveTO);
		TRY_STR_INIT();
		__FSM_I_JMP(I_KeepAliveExt);
	}

	__FSM_STATE(I_KeepAliveTO) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_uint_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(p, __fsm_sz);
		if (__fsm_n < 0)
			return __fsm_n;
		hm->keep_alive = parser->_acc;
		parser->_acc = 0;
		__msg_hdr_chunk_fixup(p, __fsm_n);
		p += __fsm_n;
		__FSM_I_JMP(I_EoT);
	}

	/*
	 * Just ignore Keep-Alive extensions. Known extensions:
	 *	max=N
	 */
	__FSM_STATE(I_KeepAliveExt) {
		__FSM_I_MATCH_MOVE_fixup(qetoken, I_KeepAliveExt, 0);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',') {
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			p += __fsm_sz;
			__FSM_I_JMP(I_EoT);
		}
		if (IS_CRLF(c)) {
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			return __data_off(p + __fsm_sz);
		}
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (c == ',')
			__FSM_I_MOVE_fixup(I_EoT, 1, 0);
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(I_EoT, 1, TFW_STR_OWS);
		if (c == '=')
			__FSM_I_MOVE_fixup(I_KeepAliveExt, 1, 0);
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
	const TfwStr *str;
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

/* Parse method override request headers. */
static int
__parse_m_override(TfwHttpReq *req, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_Meth_Start) {
		switch (TFW_LC(c)) {
		case 'c':
			__FSM_I_JMP(I_Meth_C);
		case 'd':
			__FSM_I_JMP(I_Meth_D);
		case 'g':
			__FSM_I_JMP(I_Meth_G);
		case 'h':
			__FSM_I_JMP(I_Meth_H);
		case 'l':
			__FSM_I_JMP(I_Meth_L);
		case 'm':
			__FSM_I_JMP(I_Meth_M);
		case 'o':
			__FSM_I_JMP(I_Meth_O);
		case 'p':
			__FSM_I_JMP(I_Meth_P);
		case 't':
			__FSM_I_JMP(I_Meth_T);
		case 'u':
			__FSM_I_JMP(I_Meth_U);
		}
		__FSM_I_MOVE(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_C) {
		TRY_STR_LAMBDA("copy", {
			req->method_override = TFW_HTTP_METH_COPY;
		} , I_Meth_C, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_D) {
		TRY_STR_LAMBDA("delete", {
			req->method_override = TFW_HTTP_METH_DELETE;
		} , I_Meth_D, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_G) {
		TRY_STR_LAMBDA("get", {
			req->method_override = TFW_HTTP_METH_GET;
		} , I_Meth_G, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_H) {
		TRY_STR_LAMBDA("head", {
			req->method_override = TFW_HTTP_METH_HEAD;
		} , I_Meth_H, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_L) {
		TRY_STR_LAMBDA("lock", {
			req->method_override = TFW_HTTP_METH_LOCK;
		} , I_Meth_L, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_M) {
		TRY_STR_LAMBDA("mkcol", {
			req->method_override = TFW_HTTP_METH_MKCOL;
		} , I_Meth_M, I_EoT);
		TRY_STR_LAMBDA("move", {
			req->method_override = TFW_HTTP_METH_MOVE;
		} , I_Meth_M, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_O) {
		TRY_STR_LAMBDA("options", {
			req->method_override = TFW_HTTP_METH_OPTIONS;
		} , I_Meth_O, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_P) {
		TRY_STR_LAMBDA("patch", {
			req->method_override = TFW_HTTP_METH_PATCH;
		} , I_Meth_P, I_EoT);
		TRY_STR_LAMBDA("post", {
			req->method_override = TFW_HTTP_METH_POST;
		} , I_Meth_P, I_EoT);
		TRY_STR_LAMBDA("propfind", {
			req->method_override = TFW_HTTP_METH_PROPFIND;
		} , I_Meth_P, I_EoT);
		TRY_STR_LAMBDA("proppatch", {
			req->method_override = TFW_HTTP_METH_PROPPATCH;
		} , I_Meth_P, I_EoT);
		TRY_STR_LAMBDA("put", {
			req->method_override = TFW_HTTP_METH_PUT;
		} , I_Meth_P, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_T) {
		TRY_STR_LAMBDA("trace", {
			req->method_override = TFW_HTTP_METH_TRACE;
		} , I_Meth_T, I_EoT);
		TRY_STR_INIT();
	}

	__FSM_STATE(I_Meth_U) {
		TRY_STR_LAMBDA("unlock", {
			req->method_override = TFW_HTTP_METH_UNLOCK;
		} , I_Meth_U, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_Unknown) {
		__FSM_I_MATCH_MOVE(token, I_Meth_Unknown);
		req->method_override = _TFW_HTTP_METH_UNKNOWN;
		__FSM_I_MOVE_n(I_EoT, __fsm_sz);
	}

	__FSM_STATE(I_EoT) {
		if (IS_TOKEN(c))
			__FSM_I_MOVE(I_Meth_Unknown);
		if (IS_WS(c))
			__FSM_I_MOVE(I_EoT);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__parse_m_override);

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
	 * - raw:
	 *     none;
	 * - spec:
	 *     Connection: RFC 7230 6.1.
	 */
	hbh_hdrs->spec = 0x1 << TFW_HTTP_HDR_CONNECTION;
}


/**
 * Check h1/h2 request after all headers was parsed.
 *
 * According to RFC 7231 4.3.* a payload within GET, HEAD,
 * DELETE, TRACE and CONNECT requests has no defined semantics
 * and implementations can reject it. We do this respecting overrides.
 *
 * Return T_DROP if request contains Content-Length or Content-Type field
 * for bodyless method.
 */
int
tfw_http_parse_check_bodyless_meth(TfwHttpReq *req)
{
	TfwStr *tbl = req->h_tbl->tbl;

	if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_LENGTH])
	    || !TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_TYPE]))
	{
		/* Method override either honored or request message
		 * with method override header dropped later in processing */
		if ((req->method_override
			&& TFW_HTTP_IS_METH_BODYLESS(req->method_override))
		    || TFW_HTTP_IS_METH_BODYLESS(req->method))
		{
			T_WARN("Content-Length or Content-Type not allowed to"
			       " be used with such (overridden) method\n");
			return T_DROP;
		}
	}

	return T_OK;
}

int
tfw_http_parse_req(void *req_data, unsigned char *data, unsigned int len,
		   unsigned int *parsed)
{
	int r = TFW_BLOCK;
	TfwHttpReq *req = (TfwHttpReq *)req_data;
	__FSM_DECLARE_VARS(req);
	*parsed = 0;

	T_DBG("parse %u client data bytes (%.*s%s) on req=%p\n",
	      len, min(500, (int)len), data, len > 500 ? "..." : "", req);

	__FSM_START(parser->state);

	/* - Skipping and stripping leading CRLFs - */

	/* The parser accepts 1 optional CRLF or LF before the request line.
	 * The parser stores the fact of presense of it for subsequent
	 * stripping. The parser blocks the request if it contains additional
	 * CRLFs before the request line.
	 */
	__FSM_STATE(Req_0, hot) {
		if (unlikely(c == '\r')) {
			__set_bit(TFW_HTTP_B_NEED_STRIP_LEADING_CR,
				  req->flags);
			__FSM_MOVE_nofixup(Req_0_Wait_LF);
		}
		if (unlikely(c == '\n')) {
			__set_bit(TFW_HTTP_B_NEED_STRIP_LEADING_LF,
				  req->flags);
			__FSM_MOVE_nofixup(Req_Method);
		}
		__FSM_JMP(Req_Method);
	}
	__FSM_STATE(Req_0_Wait_LF) {
		if (likely(c == '\n')) 	{
			__set_bit(TFW_HTTP_B_NEED_STRIP_LEADING_LF,
				  req->flags);
			__FSM_MOVE_nofixup(Req_Method);
		}
		TFW_PARSER_BLOCK(Req_0_Wait_LF);
	}

	/* ----------------    Request Line    ---------------- */

	/* HTTP method. */
	__FSM_STATE(Req_Method, hot) {
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
			if (PI(p) == TFW_CHAR4_INT('G', 'E', 'T', ' ')) {
				req->method = TFW_HTTP_METH_GET;
				__FSM_MOVE_nofixup_n(Req_Uri, 4);
			}
			if (PI(p) == TFW_CHAR4_INT('P', 'O', 'S', 'T')) {
				req->method = TFW_HTTP_METH_POST;
				__FSM_MOVE_nofixup_n(Req_MUSpace, 4);
			}
			goto Req_Method_RareMethods;
		}
		goto Req_Method_1CharStep;
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

	__FSM_STATE(Req_Uri, hot) {
		if (likely(c == '/'))
			__FSM_JMP(Req_UriMark);
		__FSM_JMP(Req_UriRareForms);
	}

	__FSM_STATE(Req_UriMark, hot) {
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

	__FSM_STATE(Req_UriMarkEnd, hot) {
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
		__FSM_MATCH_MOVE_pos_f(uri, Req_UriAbsPath, &req->uri_path, 0);
		if (unlikely(*(p + __fsm_sz) != ' '))
			TFW_PARSER_BLOCK(Req_UriAbsPath);
		__msg_field_finish_pos(&req->uri_path, p, __fsm_sz);
		__FSM_MOVE_nofixup_n(Req_HttpVer, __fsm_sz + 1);
	}

	/* HTTP version */
	__FSM_STATE(Req_HttpVer, hot) {
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
	__FSM_STATE(RGen_Hdr, hot) {
		TFW_HTTP_PARSE_CRLF();

		tfw_http_msg_hdr_open(msg, p);

		switch (TFW_LC(c)) {
		case 'a':
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'c', 'c', 'e', 'p')
				   && TFW_LC(*(p + 5)) == 't'
				   && *(p + 6) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 6));
				parser->_i_st = &&Req_HdrAcceptV;
				p += 6;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 14)
				   && C8_INT_LCM(p + 1, 'u', 't', 'h', 'o',
							'r', 'i', 'z', 'a')
				   && C4_INT_LCM(p + 9, 't', 'i', 'o', 'n')
				   && *(p + 13) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 13));
				parser->_i_st = &&Req_HdrAuthorizationV;
				p += 13;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
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
					__msg_hdr_chunk_fixup(data,
							      __data_off(p + 13));
					parser->_i_st = &&Req_HdrCache_ControlV;
					p += 13;
					__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
				}
				__FSM_MOVE_n(RGen_HdrOtherN, 5);
			case TFW_CHAR4_INT('o', 'n', 'n', 'e'):
				if (likely(C4_INT_LCM(p + 5, 'c', 't', 'i', 'o')
					   && TFW_LC(*(p + 9)) == 'n'
					   && *(p + 10) == ':'))
				{
					__msg_hdr_chunk_fixup(data,
							      __data_off(p + 10));
					parser->_i_st = &&Req_HdrConnectionV;
					p += 10;
					__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
				}
				__FSM_MOVE_n(RGen_HdrOtherN, 5);
			case TFW_CHAR4_INT('o', 'n', 't', 'e'):
				if (likely(TFW_LC(*(p + 5)) == 'n'
					   && TFW_LC(*(p + 6)) == 't'
					   && *(p + 7) == '-'))
				{
					__FSM_MOVE_n(Req_HdrContent_, 8);
				}
				__FSM_MOVE_n(RGen_HdrOtherN, 5);
			case TFW_CHAR4_INT('o', 'o', 'k', 'i'):
				if (likely(TFW_LC(*(p + 5)) == 'e'
					   && *(p + 6) == ':'))
				{
					__msg_hdr_chunk_fixup(data,
							      __data_off(p + 6));
					parser->_i_st = &&Req_HdrCookieV;
					p += 6;
					__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
				}
				__FSM_MOVE_n(RGen_HdrOtherN, 5);
			default:
				__FSM_MOVE(RGen_HdrOtherN);
			}
		case 'f':
			if (likely(__data_available(p, 10)
				   && C8_INT_LCM(p + 1, 'o', 'r', 'w', 'a', 'r',
							'd', 'e', 'd')
				   && *(p + 9) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 9));
				parser->_i_st = &&Req_HdrForwardedV;
				p += 9;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Req_HdrF);
		case 'h':
			if (likely(__data_available(p, 5)
				   && C4_INT3_LCM(p + 1, 'o', 's', 't', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 4));
				parser->_i_st = &&Req_HdrHostV;
				parser->_hdr_tag = TFW_HTTP_HDR_HOST;
				p += 4;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
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
				__msg_hdr_chunk_fixup(data, __data_off(p + 17));
				parser->_i_st = &&Req_HdrIf_Modified_SinceV;
				p += 17;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
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
				__msg_hdr_chunk_fixup(data, __data_off(p + 13));
				parser->_i_st = &&Req_HdrIf_None_MatchV;
				p += 13;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
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
				__msg_hdr_chunk_fixup(data, __data_off(p + 10));
				parser->_i_st = &&Req_HdrKeep_AliveV;
				p += 10;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Req_HdrK);
		case 'p':
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'r', 'a', 'g', 'm')
				   && TFW_LC(*(p + 5)) == 'a'
				   && *(p + 6) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 6));
				parser->_i_st = &&Req_HdrPragmaV;
				p += 6;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Req_HdrP);
		case 'r':
			if (likely(__data_available(p, 8)
				   && C4_INT_LCM(p + 1, 'e', 'f', 'e', 'r')
				   && TFW_LC(*(p + 5)) == 'e'
				   && TFW_LC(*(p + 6)) == 'r'
				   && *(p + 7) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 7));
				parser->_i_st = &&Req_HdrRefererV;
				p += 7;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
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
				__msg_hdr_chunk_fixup(data, __data_off(p + 17));
				parser->_i_st = &&Req_HdrTransfer_EncodingV;
				p += 17;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Req_HdrT);
		case 'x':
			if (likely(__data_available(p, 16)
				   && *(p + 1) == '-'
				   && *(p + 11) == '-'
				   /* Safe match: '-' is checked above. */
				   && C8_INT_LCM(p, 'x', '-', 'f', 'o',
						 'r', 'w', 'a', 'r')
				   && C8_INT7_LCM(p + 8, 'd', 'e', 'd', '-',
						  'f', 'o', 'r', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 15));
				parser->_i_st = &&Req_HdrX_Forwarded_ForV;
				p += 15;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 14)
				   && *(p + 1) == '-'
				   && *(p + 7) == '-'
				   /* Safe match: '-' is checked above. */
				   && C8_INT_LCM(p, 'x', '-', 'h', 't',
						 't', 'p', '-', 'm')
				   && C4_INT_LCM(p + 8, 'e', 't', 'h', 'o')
				   && TFW_LC(*(p + 12) == 'd')
				   && *(p + 10) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 13));
				parser->_i_st = &&Req_HdrX_Method_OverrideV;
				p += 13;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 23)
				   && *(p + 1) == '-'
				   && *(p + 7) == '-'
				   && *(p + 14) == '-'
				   /* Safe match: '-' is checked above. */
				   && C8_INT_LCM(p, 'x', '-', 'h', 't',
						 't', 'p', '-', 'm')
				   && C8_INT_LCM(p + 8, 'e', 't', 'h', 'o',
						 'd', '-', 'o', 'v')
				   && C8_INT7_LCM(p + 16, 'v', 'e', 'r', 'r',
						  'i', 'd', 'e', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 22));
				parser->_i_st = &&Req_HdrX_Method_OverrideV;
				p += 22;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 18)
				   && *(p + 1) == '-'
				   && *(p + 9) == '-'
				   /* Safe match: '-' is checked above. */
				   && C8_INT_LCM(p + 2, 'm', 'e', 't', 'h',
						 'o', 'd', '-', 'o')
				   && C8_INT7_LCM(p + 10, 'v', 'e', 'r', 'r',
						 'i', 'd', 'e', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 17));
				parser->_i_st = &&Req_HdrX_Method_OverrideV;
				p += 17;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			/* match X-Tempesta-Cache */
			if (likely(__data_available(p, 17)
				   && *(p + 1) == '-'
				   && *(p + 10) == '-'
				   && C8_INT_LCM(p + 2, 't', 'e', 'm', 'p',
						 'e', 's', 't', 'a')
				   && C8_INT7_LCM(p + 9, 'a', '-', 'c', 'a',
						 'c', 'h', 'e', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 16));
				parser->_i_st = &&Req_HdrX_Tempesta_CacheV;
				p += 16;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
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
				__msg_hdr_chunk_fixup(data, __data_off(p + 10));
				parser->_i_st = &&Req_HdrUser_AgentV;
				p += 10;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 8)
				   && C4_INT_LCM(p, 'u', 'p', 'g', 'r')
				   && C4_INT3_LCM(p + 4, 'a', 'd', 'e', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 7));
				parser->_i_st = &&Req_HdrUpgradeV;
				p += 7;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Req_HdrU);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Content-* headers. */
	__FSM_STATE(Req_HdrContent_) {
		switch (TFW_LC(c)) {
		case 'e':
			if (likely(__data_available(p, 9)
				   && C8_INT7_LCM(p + 1, 'n', 'c', 'o', 'd',
						  'i', 'n', 'g', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 9));
				parser->_i_st = &&Req_HdrContent_EncodingV;
				p += 9;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Req_HdrContent_E);
		case 'l':
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'e', 'n', 'g', 't')
				   && TFW_LC(*(p + 5)) == 'h'
				   && *(p + 6) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 6));
				parser->_i_st = &&Req_HdrContent_LengthV;
				p += 6;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Req_HdrContent_L);
		case 't':
			if (likely(__data_available(p, 5)
				   && C4_INT3_LCM(p + 1, 'y', 'p', 'e', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 4));
				parser->_i_st = &&Req_HdrContent_TypeV;
				p += 4;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Req_HdrContent_T);
		default:
			__FSM_JMP(RGen_HdrOtherN);
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

	/* 'Content-Encding:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrContent_EncodingV, msg,
				     __req_parse_content_encoding,
				     TFW_HTTP_HDR_CONTENT_ENCODING, 0);

	/* 'Content-Length:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrContent_LengthV, msg,
				   __parse_content_length,
				   TFW_HTTP_HDR_CONTENT_LENGTH);

	/* 'Content-Type:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrContent_TypeV, msg,
				     __req_parse_content_type,
				     TFW_HTTP_HDR_CONTENT_TYPE, 0);

	/* 'Forwarded:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrForwardedV, msg,
				     __req_parse_forwarded,
				     TFW_HTTP_HDR_FORWARDED, 0);

	/* 'Host:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrHostV, req, __req_parse_host,
				     TFW_HTTP_HDR_HOST, 0);

	/* 'If-None-Match:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrIf_None_MatchV, msg, __parse_etag_or_if_nmatch,
				     TFW_HTTP_HDR_IF_NONE_MATCH, 0);

	/* 'If-Modified-Since:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrIf_Modified_SinceV, msg,
				  __req_parse_if_msince);

	/* 'Keep-Alive:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrKeep_AliveV, msg, __parse_keep_alive,
				     TFW_HTTP_HDR_KEEP_ALIVE, 0);

	/* 'Pragma:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrPragmaV, msg, __parse_pragma, 0);

	/* 'Referer:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrRefererV, msg, __req_parse_referer,
				   TFW_HTTP_HDR_REFERER);

	/* 'Transfer-Encoding:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrTransfer_EncodingV, msg,
				     __req_parse_transfer_encoding,
				     TFW_HTTP_HDR_TRANSFER_ENCODING, 0);

	/* 'X-Forwarded-For:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrX_Forwarded_ForV, msg,
				     __req_parse_x_forwarded_for,
				     TFW_HTTP_HDR_X_FORWARDED_FOR, 0);

	/* 'User-Agent:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrUser_AgentV, msg,
				   __req_parse_user_agent,
				   TFW_HTTP_HDR_USER_AGENT);

	/* 'Upgrade:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrUpgradeV, msg, __parse_upgrade,
				     TFW_HTTP_HDR_UPGRADE, 0);

	/* 'Cookie:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrCookieV, msg, __req_parse_cookie,
				     TFW_HTTP_HDR_COOKIE, 0);

	/*
	 * 'X-HTTP-Method:*OWS' OR 'X-HTTP-Method-Override:*OWS' OR
	 * 'X-Method-Override:*OWS' is read, process field-value.
	*/
	TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrX_Method_OverrideV, req,
				  __parse_m_override);

	/* 'X-Tempesta-Cache:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrX_Tempesta_CacheV, msg,
				     __req_parse_x_tempesta_cache,
				     TFW_HTTP_HDR_X_TEMPESTA_CACHE, 0);


	RGEN_HDR_OTHER();
	RGEN_OWS();
	RGEN_EOL();
	RGEN_CRLF();

	/* Normal end of the FSM. */
	__FSM_FINISH(req);
	return r;

	/*
	 * ----------------    Request body    ----------------
	 *
	 * Most requests do not have body, so move body parser after the end.
	 */
	TFW_HTTP_INIT_REQ_BODY_PARSING();
	TFW_HTTP_PARSE_BODY(cold);

	/*
	 * ----------------    Slow path    ----------------
	 *
	 * The code at the below is the slow path,
	 * so this is why it's at the end of the function.
	 */
	barrier();

	/*
	 * Process other (improbable) states here, on slow path.
	 * We're on state Req_Method.
	 *
	 * For most (or at least most frequent) methods @step_inc should be
	 * optimized out. The macro is used to reduce the FSM size, so there is
	 * no sense to use it's specific versions for the few states,
	 * e.g. for 'GET '.
	 *
	 * We already sure that there is enough data available from fast path
	 * of Req_Method.
	 */
Req_Method_RareMethods: __attribute__((cold))
#define __MATCH_METH(meth, step_inc)					\
do {									\
	req->method = TFW_HTTP_METH_##meth;				\
	__fsm_n += step_inc;						\
	goto match_meth;						\
} while (0)
#define __MK_METH_UNKNOWN()						\
do { req->method = _TFW_HTTP_METH_UNKNOWN; } while (0)

	__fsm_n = 4;
	switch (PI(p)) {
	case TFW_CHAR4_INT('H', 'E', 'A', 'D'):
		__MATCH_METH(HEAD, 0);
	/* PURGE Method for Tempesta Configuration: PURGE. */
	case TFW_CHAR4_INT('P', 'U', 'R', 'G'):
		if (likely(*(p + 4) == 'E'))
			__MATCH_METH(PURGE, 1);
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup_n(Req_MethPurg, 4);
	case TFW_CHAR4_INT('C', 'O', 'P', 'Y'):
		__MATCH_METH(COPY, 0);
	case TFW_CHAR4_INT('D', 'E', 'L', 'E'):
		if (likely(*(p + 4) == 'T' && *(p + 5) == 'E'))
			__MATCH_METH(DELETE, 2);
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup_n(Req_MethDele, 4);
	case TFW_CHAR4_INT('L', 'O', 'C', 'K'):
		__MATCH_METH(LOCK, 0);
	case TFW_CHAR4_INT('M', 'K', 'C', 'O'):
		if (likely(*(p + 4) == 'L'))
			__MATCH_METH(MKCOL, 1);
		__MK_METH_UNKNOWN();
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
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup_n(Req_MethOpti, 4);
	case TFW_CHAR4_INT('P', 'A', 'T', 'C'):
		if (likely(*(p + 4) == 'H'))
			__MATCH_METH(PATCH, 1);
		__MK_METH_UNKNOWN();
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
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup_n(Req_MethProp, 4);
	case TFW_CHAR4_INT('P', 'U', 'T', ' '):
		req->method = TFW_HTTP_METH_PUT;
		__FSM_MOVE_nofixup_n(Req_Uri, 4);
	case TFW_CHAR4_INT('T', 'R', 'A', 'C'):
		if (likely(*(p + 4) == 'E'))
			__MATCH_METH(TRACE, 1);
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup_n(Req_MethTrac, 4);
	case TFW_CHAR4_INT('U', 'N', 'L', 'O'):
		if (likely(*(p + 4) == 'C' && *(p + 5) == 'K'))
			__MATCH_METH(UNLOCK, 2);
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup_n(Req_MethUnlo, 4);
	default:
		__FSM_JMP(Req_MethodUnknown);
	}
match_meth:
	__FSM_MOVE_nofixup_n(Req_MUSpace, __fsm_n);
#undef __MATCH_METH

	/* Req_Method slow path: step char-by-char. */
Req_Method_1CharStep: __attribute__((cold))
	switch (c) {
	case 'G':
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup(Req_MethG);
	case 'H':
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup(Req_MethH);
	case 'P':
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup(Req_MethP);
	case 'C':
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup(Req_MethC);
	case 'D':
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup(Req_MethD);
	case 'L':
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup(Req_MethL);
	case 'M':
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup(Req_MethM);
	case 'O':
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup(Req_MethO);
	case 'T':
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup(Req_MethT);
	case 'U':
		__MK_METH_UNKNOWN();
		__FSM_MOVE_nofixup(Req_MethU);
	}
	__FSM_JMP(Req_MethodUnknown);
#undef __MK_METH_UNKNOWN						\

	/* ----------------    Improbable states    ---------------- */

	/* HTTP Method processing. */
	/* GET */
	__FSM_METH_MOVE(Req_MethG, 'E', Req_MethGe);
	__FSM_METH_MOVE_finish(Req_MethGe, 'T', TFW_HTTP_METH_GET);
	/* P* */
	__FSM_STATE(Req_MethP, cold) {
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
		__FSM_JMP(Req_MethodUnknown);
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
	__FSM_STATE(Req_MethProp, cold) {
		switch (c) {
		case 'F':
			__FSM_MOVE_nofixup(Req_MethPropf);
		case 'P':
			__FSM_MOVE_nofixup(Req_MethPropp);
		}
		__FSM_JMP(Req_MethodUnknown);
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
	__FSM_STATE(Req_MethPu, cold) {
		switch (c) {
		case 'R':
			__FSM_MOVE_nofixup(Req_MethPur);
		case 'T':
			/* PUT */
			req->method = TFW_HTTP_METH_PUT;
			__FSM_MOVE_nofixup(Req_MUSpace);
		}
		__FSM_JMP(Req_MethodUnknown);
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
	__FSM_STATE(Req_MethM, cold) {
		switch (c) {
		case 'K':
			__FSM_MOVE_nofixup(Req_MethMk);
		case 'O':
			__FSM_MOVE_nofixup(Req_MethMo);
		}
		__FSM_JMP(Req_MethodUnknown);
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

	__FSM_STATE(Req_MethodUnknown, cold) {
		__fsm_n = __data_remain(p);
		__fsm_sz = tfw_match_token(p, __fsm_n);
		if (likely(__fsm_sz)) {
			req->method = _TFW_HTTP_METH_UNKNOWN;
			p += __fsm_sz;
		}
		if (unlikely(__fsm_sz == __fsm_n)) {
			parser->state = &&Req_MethodUnknown;
			__FSM_EXIT(TFW_POSTPONE);
		}
		if (unlikely(req->method != _TFW_HTTP_METH_UNKNOWN))
			TFW_PARSER_BLOCK(Req_MethodUnknown);
			/* if neither here nor earlier we did not
			 * assign the _TFW_HTTP_METH_UNKNOWN
			 * then there is zero-length method name
			 * and the request must be blocked.
			 */
		__FSM_MOVE_nofixup_n(Req_MUSpace, 0);
	}

	__FSM_STATE(Req_UriRareForms, cold) {
		/* There is also authority form as in RFC7230#section-5.3.3,
		 * but it only used with CONNECT that is not supported */
		/* Asterisk form as in RFC7230#section-5.3.4 */
		if (req->method == TFW_HTTP_METH_OPTIONS && c == '*')
			__FSM_MOVE_nofixup(Req_UriMarkEnd);
		/* Absolute form as in RFC7230#section-5.3.2 */
		__FSM_JMP(Req_UriAbsoluteForm);
	}

	__FSM_STATE(Req_UriAbsoluteForm, cold) {
		/* Rare form so there is no need to speed-up matching with
		 * fast path prefixing */
		if (likely(TFW_LC(c) == 'h'))
			__FSM_MOVE_nofixup(Req_UriSchH);
		else if (TFW_LC(c) == 'w')
			__FSM_MOVE_nofixup(Req_UriSchW);

		TFW_PARSER_BLOCK(Req_UriAbsoluteForm);
	}

	/* process URI scheme */
	/* path for 'http://' and 'https://' */
	__FSM_TX_LC_nofixup(Req_UriSchH, 't', Req_UriSchHt, cold);
	__FSM_TX_LC_nofixup(Req_UriSchHt, 't', Req_UriSchHtt, cold);
	__FSM_TX_LC_nofixup(Req_UriSchHtt, 'p', Req_UriSchHttp, cold);
	__FSM_STATE(Req_UriSchHttp, cold) {
		switch (TFW_LC(c)) {
		case ':':
			__FSM_MOVE_nofixup(Req_UriSchHttpColon);
		case 's':
			__FSM_MOVE_nofixup(Req_UriSchHttps);
		}
		TFW_PARSER_BLOCK(Req_UriSchHttp);
	}
	/* http */
	__FSM_TX_nofixup(Req_UriSchHttpColon, '/', Req_UriSchHttpColonSlash,
			 cold);
	__FSM_TX_nofixup(Req_UriSchHttpColonSlash, '/', Req_UriAuthorityStart,
			 cold);
	/* https */
	__FSM_TX_nofixup(Req_UriSchHttps, ':', Req_UriSchHttpsColon, cold);
	__FSM_TX_nofixup(Req_UriSchHttpsColon, '/', Req_UriSchHttpsColonSlash,
			 cold);
	__FSM_TX_nofixup(Req_UriSchHttpsColonSlash, '/', Req_UriAuthorityStart,
			 cold);
	/* path for 'ws://' and 'wss://' */
	__FSM_TX_LC_nofixup(Req_UriSchW, 's', Req_UriSchWs, cold);
	__FSM_STATE(Req_UriSchWs, cold) {
		switch (TFW_LC(c)) {
		case ':':
			__FSM_MOVE_nofixup(Req_UriSchWsColon);
		case 's':
			__FSM_MOVE_nofixup(Req_UriSchWss);
		}
		TFW_PARSER_BLOCK(Req_UriSchWs);
	}
	/* ws */
	__FSM_TX_nofixup(Req_UriSchWsColon, '/', Req_UriSchWsColonSlash, cold);
	__FSM_TX_nofixup(Req_UriSchWsColonSlash, '/', Req_UriAuthorityStart,
			 cold);
	/* wss */
	__FSM_TX_nofixup(Req_UriSchWss, ':', Req_UriSchWssColon, cold);
	__FSM_TX_nofixup(Req_UriSchWssColon, '/', Req_UriSchWssColonSlash,
			 cold);
	__FSM_TX_nofixup(Req_UriSchWssColonSlash, '/', Req_UriAuthorityStart,
			 cold);

	/*
	 * URI host part.
	 * RFC 3986 chapter 3.2: authority = [userinfo@]host[:port]
	 *
	 * Authority parsing: it can be "host" or "userinfo@host" (port is
	 * parsed later). At the beginning we don't know, which of variants we
	 * have. So we fill req->host, and if we get '@', we copy host to
	 * req->userinfo, reset req->host and fill it.
	 */
	__FSM_STATE(Req_UriAuthorityStart, cold) {
		if (likely(isalnum(c) || c == '.' || c == '-')) {
			__set_bit(TFW_HTTP_B_ABSOLUTE_URI, req->flags);
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
			__set_bit(TFW_HTTP_B_ABSOLUTE_URI, req->flags);
			__msg_field_open(&req->host, p);
			__FSM_MOVE_f(Req_UriAuthorityIPv6, &req->host);
		}
		TFW_PARSER_BLOCK(Req_UriAuthorityStart);
	}

	__FSM_STATE(Req_UriAuthority, cold) {
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

	__FSM_STATE(Req_UriAuthorityIPv6, cold) {
		if (likely(isxdigit(c) || c == ':')) {
			__FSM_MOVE_f(Req_UriAuthorityIPv6, &req->host);
		} else if(c == ']') {
			__FSM_MOVE_f(Req_UriAuthorityEnd, &req->host);
		}
		TFW_PARSER_BLOCK(Req_UriAuthorityIPv6);
	}

	__FSM_STATE(Req_UriAuthorityResetHost, cold) {
		if (likely(isalnum(c) || c == '.' || c == '-')) {
			__msg_field_open(&req->host, p);
			__FSM_MOVE_f(Req_UriAuthority, &req->host);
		} else if (c == '[') {
			__msg_field_open(&req->host, p);
			__FSM_MOVE_f(Req_UriAuthorityIPv6, &req->host);
		}
		__FSM_JMP(Req_UriAuthorityEnd);
	}

	__FSM_STATE(Req_UriAuthorityEnd, cold) {
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
	__FSM_STATE(Req_UriPort, cold) {
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

	/* Parse HTTP version (1.1 and 1.0 are supported). */
	__FSM_TX_nofixup(Req_HttpVerT1, 'T', Req_HttpVerT2);
	__FSM_TX_nofixup(Req_HttpVerT2, 'T', Req_HttpVerP);
	__FSM_TX_nofixup(Req_HttpVerP, 'P', Req_HttpVerSlash);
	__FSM_TX_nofixup(Req_HttpVerSlash, '/', Req_HttpVer11);
	__FSM_TX_nofixup(Req_HttpVer11, '1', Req_HttpVerDot);
	__FSM_TX_nofixup(Req_HttpVerDot, '.', Req_HttpVer12);
	__FSM_STATE(Req_HttpVer12, cold) {
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

	__FSM_STATE(Req_HdrA, cold) {
		switch (TFW_LC(c)) {
		case 'c':
			__FSM_MOVE(Req_HdrAc);
		case 'u':
			__FSM_MOVE(Req_HdrAu);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Accept header processing. */
	__FSM_TX_AF(Req_HdrAc, 'c', Req_HdrAcc);
	__FSM_TX_AF(Req_HdrAcc, 'e', Req_HdrAcce);
	__FSM_TX_AF(Req_HdrAcce, 'p', Req_HdrAccep);
	__FSM_TX_AF(Req_HdrAccep, 't', Req_HdrAccept);
	__FSM_TX_AF_OWS(Req_HdrAccept, Req_HdrAcceptV);

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

	__FSM_STATE(Req_HdrC, cold) {
		switch (TFW_LC(c)) {
		case 'a':
			__FSM_MOVE(Req_HdrCa);
		case 'o':
			__FSM_MOVE(Req_HdrCo);
		default:
			__FSM_JMP(RGen_HdrOtherN);
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

	__FSM_STATE(Req_HdrCo, cold) {
		switch (TFW_LC(c)) {
		case 'n':
			__FSM_MOVE(Req_HdrCon);
		case 'o':
			__FSM_MOVE(Req_HdrCoo);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Connection header processing. */
	__FSM_STATE(Req_HdrCon, cold) {
		switch (TFW_LC(c)) {
		case 'n':
			__FSM_MOVE(Req_HdrConn);
		case 't':
			__FSM_MOVE(Req_HdrCont);
		default:
			__FSM_JMP(RGen_HdrOtherN);
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

	/* Content-Encoding header processing. */
	__FSM_TX_AF(Req_HdrContent_E, 'n', Req_HdrContent_En);
	__FSM_TX_AF(Req_HdrContent_En, 'c', Req_HdrContent_Enc);
	__FSM_TX_AF(Req_HdrContent_Enc, 'o', Req_HdrContent_Enco);
	__FSM_TX_AF(Req_HdrContent_Enco, 'd', Req_HdrContent_Encod);
	__FSM_TX_AF(Req_HdrContent_Encod, 'i', Req_HdrContent_Encodi);
	__FSM_TX_AF(Req_HdrContent_Encodi, 'n', Req_HdrContent_Encodin);
	__FSM_TX_AF(Req_HdrContent_Encodin, 'g', Req_HdrContent_Encoding);
	__FSM_TX_AF_OWS(Req_HdrContent_Encoding, Req_HdrContent_EncodingV);

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

	/* Forwarded header processing. */
	__FSM_TX_AF(Req_HdrF, 'o', Req_HdrFo);
	__FSM_TX_AF(Req_HdrFo, 'r', Req_HdrFor);
	__FSM_TX_AF(Req_HdrFor, 'w', Req_HdrForw);
	__FSM_TX_AF(Req_HdrForw, 'a', Req_HdrForwa);
	__FSM_TX_AF(Req_HdrForwa, 'r', Req_HdrForwar);
	__FSM_TX_AF(Req_HdrForwar, 'd', Req_HdrForward);
	__FSM_TX_AF(Req_HdrForward, 'e', Req_HdrForwarde);
	__FSM_TX_AF(Req_HdrForwarde, 'd', Req_HdrForwarded);
	__FSM_TX_AF_OWS(Req_HdrForwarded, Req_HdrForwardedV);

	/* Host header processing. */
	__FSM_TX_AF(Req_HdrH, 'o', Req_HdrHo);
	__FSM_TX_AF(Req_HdrHo, 's', Req_HdrHos);
	__FSM_TX_AF(Req_HdrHos, 't', Req_HdrHost);
	__FSM_TX_AF_OWS(Req_HdrHost, Req_HdrHostV);

	/* If-* header processing. */
	__FSM_TX_AF(Req_HdrI, 'f', Req_HdrIf);
	__FSM_TX_AF(Req_HdrIf, '-', Req_HdrIf_);
	__FSM_STATE(Req_HdrIf_, cold) {
		switch (TFW_LC(c)) {
		case 'm':
			__FSM_MOVE(Req_HdrIf_M);
		case 'n':
			__FSM_MOVE(Req_HdrIf_N);
		default:
			__FSM_JMP(RGen_HdrOtherN);
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

	__FSM_TX_AF(Req_HdrX, '-', Req_HdrX_);
	__FSM_STATE(Req_HdrX_, cold) {
		switch (TFW_LC(c)) {
		case 'f':
			__FSM_MOVE(Req_HdrX_F);
		case 'h':
			__FSM_MOVE(Req_HdrX_H);
		case 'm':
			__FSM_MOVE(Req_HdrX_M);
		case 't':
			__FSM_MOVE(Req_HdrX_T);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* X-Forwarded-For header processing. */
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

	/* X-Method-Override header processing. */
	__FSM_TX_AF(Req_HdrX_M, 'e', Req_HdrX_Me);
	__FSM_TX_AF(Req_HdrX_Me, 't', Req_HdrX_Met);
	__FSM_TX_AF(Req_HdrX_Met, 'h', Req_HdrX_Meth);
	__FSM_TX_AF(Req_HdrX_Meth, 'o', Req_HdrX_Metho);
	__FSM_TX_AF(Req_HdrX_Metho, 'd', Req_HdrX_Method);
	__FSM_TX_AF(Req_HdrX_Method, '-', Req_HdrX_Method_);
	__FSM_TX_AF(Req_HdrX_Method_, 'o', Req_HdrX_Method_O);
	__FSM_TX_AF(Req_HdrX_Method_O, 'v', Req_HdrX_Method_Ov);
	__FSM_TX_AF(Req_HdrX_Method_Ov, 'e', Req_HdrX_Method_Ove);
	__FSM_TX_AF(Req_HdrX_Method_Ove, 'r', Req_HdrX_Method_Over);
	__FSM_TX_AF(Req_HdrX_Method_Over, 'r', Req_HdrX_Method_Overr);
	__FSM_TX_AF(Req_HdrX_Method_Overr, 'i', Req_HdrX_Method_Overri);
	__FSM_TX_AF(Req_HdrX_Method_Overri, 'd', Req_HdrX_Method_Overrid);
	__FSM_TX_AF(Req_HdrX_Method_Overrid, 'e', Req_HdrX_Method_Override);
	__FSM_TX_AF_OWS(Req_HdrX_Method_Override, Req_HdrX_Method_OverrideV);

	/* X-Tempesta-Cache header processing */
	__FSM_TX_AF(Req_HdrX_T, 'e', Req_HdrX_Te);
	__FSM_TX_AF(Req_HdrX_Te, 'm', Req_HdrX_Tem);
	__FSM_TX_AF(Req_HdrX_Tem, 'p', Req_HdrX_Temp);
	__FSM_TX_AF(Req_HdrX_Temp, 'e', Req_HdrX_Tempe);
	__FSM_TX_AF(Req_HdrX_Tempe, 's', Req_HdrX_Tempes);
	__FSM_TX_AF(Req_HdrX_Tempes, 't', Req_HdrX_Tempest);
	__FSM_TX_AF(Req_HdrX_Tempest, 'a', Req_HdrX_Tempesta);
	__FSM_TX_AF(Req_HdrX_Tempesta, '-', Req_HdrX_Tempesta_);
	__FSM_TX_AF(Req_HdrX_Tempesta_, 'c', Req_HdrX_Tempesta_C);
	__FSM_TX_AF(Req_HdrX_Tempesta_C, 'a', Req_HdrX_Tempesta_Ca);
	__FSM_TX_AF(Req_HdrX_Tempesta_Ca, 'c', Req_HdrX_Tempesta_Cac);
	__FSM_TX_AF(Req_HdrX_Tempesta_Cac, 'h', Req_HdrX_Tempesta_Cach);
	__FSM_TX_AF(Req_HdrX_Tempesta_Cach, 'e', Req_HdrX_Tempesta_Cache);
	__FSM_TX_AF_OWS(Req_HdrX_Tempesta_Cache, Req_HdrX_Tempesta_CacheV);

	/* X-HTTP-Method header processing. */
	__FSM_TX_AF(Req_HdrX_H, 't', Req_HdrX_Ht);
	__FSM_TX_AF(Req_HdrX_Ht, 't', Req_HdrX_Htt);
	__FSM_TX_AF(Req_HdrX_Htt, 'p', Req_HdrX_Http);
	__FSM_TX_AF(Req_HdrX_Http, '-', Req_HdrX_Http_);
	__FSM_TX_AF(Req_HdrX_Http_, 'm', Req_HdrX_Http_M);
	__FSM_TX_AF(Req_HdrX_Http_M, 'e', Req_HdrX_Http_Me);
	__FSM_TX_AF(Req_HdrX_Http_Me, 't', Req_HdrX_Http_Met);
	__FSM_TX_AF(Req_HdrX_Http_Met, 'h', Req_HdrX_Http_Meth);
	__FSM_TX_AF(Req_HdrX_Http_Meth, 'o', Req_HdrX_Http_Metho);
	__FSM_TX_AF(Req_HdrX_Http_Metho, 'd', Req_HdrX_Http_Method);
	__FSM_STATE(Req_HdrX_Http_Method, cold) {
		switch (c) {
		case '-':
			__FSM_MOVE(Req_HdrX_Http_Method_);
		case ':':
			parser->_i_st = &&Req_HdrX_Method_OverrideV;
			__FSM_MOVE(RGen_LWS);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* X-HTTP-Method-Override processing. */
	__FSM_TX_AF(Req_HdrX_Http_Method_, 'o', Req_HdrX_Http_Method_O);
	__FSM_TX_AF(Req_HdrX_Http_Method_O, 'v', Req_HdrX_Http_Method_Ov);
	__FSM_TX_AF(Req_HdrX_Http_Method_Ov, 'e', Req_HdrX_Http_Method_Ove);
	__FSM_TX_AF(Req_HdrX_Http_Method_Ove, 'r', Req_HdrX_Http_Method_Over);
	__FSM_TX_AF(Req_HdrX_Http_Method_Over, 'r', Req_HdrX_Http_Method_Overr);
	__FSM_TX_AF(Req_HdrX_Http_Method_Overr, 'i', Req_HdrX_Http_Method_Overri);
	__FSM_TX_AF(Req_HdrX_Http_Method_Overri, 'd', Req_HdrX_Http_Method_Overrid);
	__FSM_TX_AF(Req_HdrX_Http_Method_Overrid, 'e', Req_HdrX_Http_Method_Override);
	__FSM_TX_AF_OWS(Req_HdrX_Http_Method_Override, Req_HdrX_Method_OverrideV);

	__FSM_STATE(Req_HdrU, cold) {
		switch (TFW_LC(c)) {
		case 's':
			__FSM_MOVE(Req_HdrUs);
		case 'p':
			__FSM_MOVE(Req_HdrUp);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* User-Agent header processing. */
	__FSM_TX_AF(Req_HdrUs, 'e', Req_HdrUse);
	__FSM_TX_AF(Req_HdrUse, 'r', Req_HdrUser);
	__FSM_TX_AF(Req_HdrUser, '-', Req_HdrUser_);
	__FSM_TX_AF(Req_HdrUser_, 'a', Req_HdrUser_A);
	__FSM_TX_AF(Req_HdrUser_A, 'g', Req_HdrUser_Ag);
	__FSM_TX_AF(Req_HdrUser_Ag, 'e', Req_HdrUser_Age);
	__FSM_TX_AF(Req_HdrUser_Age, 'n', Req_HdrUser_Agen);
	__FSM_TX_AF(Req_HdrUser_Agen, 't', Req_HdrUser_Agent);
	__FSM_TX_AF_OWS(Req_HdrUser_Agent, Req_HdrUser_AgentV);

	/* Upgrade header processing. */
	__FSM_TX_AF(Req_HdrUp, 'g', Req_HdrUpg);
	__FSM_TX_AF(Req_HdrUpg, 'r', Req_HdrUpgr);
	__FSM_TX_AF(Req_HdrUpgr, 'a', Req_HdrUpgra);
	__FSM_TX_AF(Req_HdrUpgra, 'd', Req_HdrUpgrad);
	__FSM_TX_AF(Req_HdrUpgrad, 'e', Req_HdrUpgrade);
	__FSM_TX_AF_OWS(Req_HdrUpgrade, Req_HdrUpgradeV);

	/* Cookie header processing. */
	__FSM_TX_AF(Req_HdrCoo, 'k', Req_HdrCook);
	__FSM_TX_AF(Req_HdrCook, 'i', Req_HdrCooki);
	__FSM_TX_AF(Req_HdrCooki, 'e', Req_HdrCookie);
	__FSM_TX_AF_OWS(Req_HdrCookie, Req_HdrCookieV);
}
STACK_FRAME_NON_STANDARD(tfw_http_parse_req);

/*
 * ------------------------------------------------------------------------
 *	 Special stuff for HTTP/2 parsing
 * ------------------------------------------------------------------------
 */
#define __FSM_H2_OK(st_next)						\
do {									\
	T_DBG3("%s: parsed, st_next=" #st_next ", input=%#x('%.*s'),"	\
	       " len=%lu, off=%lu\n", __func__, (char)c,		\
	       min(16U, (unsigned int)(data + len - p)), p, len,	\
	       p - data);						\
	parser->state = &&st_next;					\
	goto out;							\
} while (0)

#define __FSM_H2_POSTPONE(st_next)					\
do {									\
	T_DBG3("%s: postponed, state=" #st_next ", input=%#x('%.*s'),"	\
	       " len=%lu, off=%lu\n", __func__, (char)c,		\
	       min(16U, (unsigned int)(data + len - p)), p, len,	\
	       p - data);						\
	parser->state = &&st_next;					\
	ret = T_POSTPONE;						\
	goto out;							\
} while (0)

#define __FSM_H2_DROP(st)						\
do {									\
	T_WARN("HTTP/2 request dropped: state=" #st " input=%#x('%.*s')," \
	       " len=%lu, off=%lu\n", (char)c,				\
	       min(16U, (unsigned int)(data + len - p)), p,		\
	       len, p - data);						\
	ret = T_DROP;							\
	goto out;							\
} while (0)

#define H2_MSG_VERIFY(hid)						\
({									\
	bool ret = true;						\
	TfwStr *tbl = msg->h_tbl->tbl;					\
	if (unlikely(hid < TFW_HTTP_HDR_NONSINGULAR			\
		     && hid != TFW_HTTP_HDR_COOKIE			\
		     && !TFW_STR_EMPTY(&tbl[hid])))			\
	{								\
		ret = false;						\
	}								\
	/*								\
	 * Pseudo-headers must appear in the header block before	\
	 * regular headers; also, exactly one instance of ':method',	\
	 * ':scheme' and ':path' pseudo-headers must be contained in	\
	 * the request (see RFC 7540 section 8.1.2.1 and section	\
	 * 8.1.2.3 for details).					\
	 */								\
	if (test_bit(TFW_HTTP_B_H2_HDRS_FULL, req->flags)		\
	    && hid == TFW_HTTP_HDR_H2_AUTHORITY)			\
	{								\
		ret = false;						\
	}								\
	if (!test_bit(TFW_HTTP_B_H2_HDRS_FULL, req->flags)		\
	    && hid >= TFW_HTTP_HDR_REGULAR)				\
	{								\
		if (TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_H2_METHOD])		\
		    || TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_H2_SCHEME])	\
		    || TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_H2_PATH]))	\
		{							\
			ret = false;					\
		}							\
		else							\
		{							\
			__set_bit(TFW_HTTP_B_H2_HDRS_FULL, req->flags);	\
		}							\
	}								\
	ret;								\
})

#define __FSM_H2_FIN(to, n, h_tag)					\
do {									\
	p += n;								\
	T_DBG3("%s: name fin, h_tag=%d, to=" #to " len=%lu, off=%lu\n",	\
	       __func__, h_tag, len, __data_off(p));			\
	if (unlikely(__data_off(p) < len))				\
		goto RGen_HdrOtherN;					\
	__msg_hdr_chunk_fixup(data, len);				\
	if (unlikely(!fin))						\
		__FSM_H2_POSTPONE(RGen_HdrOtherN);			\
	it->tag = h_tag;						\
	__FSM_H2_OK(to);						\
} while (0)

#define __FSM_H2_NEXT_n(to, n)						\
do {									\
	p += n;								\
	T_DBG3("%s: name next, to=" #to " len=%lu, off=%lu\n", __func__, \
	       len, __data_off(p));					\
	if (likely(__data_off(p) < len))				\
		goto to;						\
	__msg_hdr_chunk_fixup(data, len);				\
	if (unlikely(!fin))						\
		__FSM_H2_POSTPONE(to);					\
	it->tag = TFW_TAG_HDR_RAW;					\
	__FSM_H2_OK(RGen_HdrOtherV);					\
} while (0)

#define __FSM_H2_NEXT(to)						\
	__FSM_H2_NEXT_n(to, 1)

#define __FSM_H2_OTHER_n(n)						\
	__FSM_H2_NEXT_n(RGen_HdrOtherN, n)

#define __FSM_H2_OTHER()						\
	__FSM_H2_OTHER_n(1)

#define __FSM_H2_HDR_COMPLETE(st_curr)					\
do {									\
	T_DBG3("%s: complete header, state=" #st_curr ", _hdr_tag=%u,"	\
	      " c=%#x, p='%.*s', len=%lu, off=%lu\n",			\
	      __func__, parser->_hdr_tag, (char)c,			\
	      min(16U, (unsigned int)(data + len - p)),			\
	      p, len, p - data);					\
	parser->state = NULL;						\
	goto out;							\
} while (0)

#define __FSM_H2_PSHDR_CHECK_lambda(pos, lambda)			\
do {									\
	if (__data_off(pos) >= len) {					\
		lambda;							\
	}								\
} while (0)

#define __FSM_H2_PSHDR_MOVE_FIN(st_curr, n, st_next)			\
do {									\
	p += n;								\
	__FSM_H2_PSHDR_CHECK_lambda(p, {				\
		__msg_hdr_chunk_fixup(data, len);			\
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);			\
		if (unlikely(!fin))					\
			__FSM_H2_POSTPONE(st_next);			\
		__FSM_H2_HDR_COMPLETE(st_curr);				\
	});								\
	goto st_next;							\
} while (0)

#define __FSM_H2_PSHDR_MOVE_FIN_fixup(st_curr, n, st_next)		\
do {									\
	__msg_hdr_chunk_fixup(p, n);					\
	__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);				\
	p += n;								\
	__FSM_H2_PSHDR_CHECK_lambda(p, {				\
		if (unlikely(!fin))					\
			__FSM_H2_POSTPONE(st_next);			\
		__FSM_H2_HDR_COMPLETE(st_curr);				\
	});								\
	goto st_next;							\
} while (0)

#define __FSM_H2_PSHDR_MOVE_DROP(st_curr, n, st_next)			\
do {									\
	p += n;								\
	__FSM_H2_PSHDR_CHECK_lambda(p, {				\
		if (unlikely(!fin)) {					\
			__msg_hdr_chunk_fixup(data, len);		\
			__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);		\
			__FSM_H2_POSTPONE(st_next);			\
		}							\
		__FSM_H2_DROP(st_curr);					\
	});								\
	goto st_next;							\
} while (0)

#define __FSM_H2_PSHDR_MOVE_DROP_nofixup(st_curr, n, st_next)		\
do {									\
	p += n;								\
	__FSM_H2_PSHDR_CHECK_lambda(p, {				\
		if (unlikely(!fin))					\
			__FSM_H2_POSTPONE(st_next);			\
		__FSM_H2_DROP(st_curr);					\
	});								\
	goto st_next;							\
} while (0)

#define __FSM_H2_PSHDR_COMPLETE(st, n)					\
do {									\
	p += n;								\
	__FSM_H2_PSHDR_CHECK_lambda(p, {				\
		if (unlikely(!fin))					\
			__FSM_H2_DROP(st);				\
		__msg_hdr_chunk_fixup(data, len);			\
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);			\
		__FSM_H2_HDR_COMPLETE(st);				\
	});								\
	__FSM_H2_DROP(st);						\
} while (0)

#define __FSM_H2_METHOD_MOVE(st_curr, n, st_next)			\
do {									\
	p += n;								\
	__FSM_H2_PSHDR_CHECK_lambda(p, {				\
		__msg_hdr_chunk_fixup(data, len);			\
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);			\
		if (unlikely(!fin))					\
			__FSM_H2_POSTPONE(st_next);			\
		req->method = _TFW_HTTP_METH_UNKNOWN;			\
		__FSM_H2_HDR_COMPLETE(st_curr);				\
	});								\
	goto st_next;							\
} while (0)

#define __FSM_H2_METHOD_COMPLETE(st_curr, n, mid)			\
do {									\
	p += n;								\
	__FSM_H2_PSHDR_CHECK_lambda(p, {				\
		__msg_hdr_chunk_fixup(data, len);			\
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);			\
		if (unlikely(!fin))					\
			__FSM_H2_POSTPONE(Req_MethodUnknown);		\
		req->method = mid;					\
		__FSM_H2_HDR_COMPLETE(st_curr);				\
	});								\
	goto Req_MethodUnknown;						\
} while (0)

/*
 * Special set of macros for slow-path parsing of pseudo-headers value
 * (char-by-char).
 */
#define __FSM_H2_SCHEME_STATE_MOVE(st, ch, st_next)			\
	__FSM_STATE(st, cold) {						\
		if (likely(TFW_LC(c) == (ch)))				\
			__FSM_H2_PSHDR_MOVE_DROP(st, 1, st_next);	\
		__FSM_H2_DROP(st);					\
	}

#define __FSM_H2_SCHEME_STATE_COMPLETE(st, ch)				\
	__FSM_STATE(st, cold) {						\
		if (likely(TFW_LC(c) == (ch)))				\
			__FSM_H2_PSHDR_COMPLETE(st, 1);			\
		__FSM_H2_DROP(st);					\
	}

#define __FSM_H2_METH_STATE_MOVE(st, ch, st_next)			\
	__FSM_STATE(st, cold) {						\
		if (likely(c == (ch)))					\
			__FSM_H2_METHOD_MOVE(st, 1, st_next);		\
		__FSM_JMP(Req_MethodUnknown);				\
	}

#define __FSM_H2_METH_STATE_COMPLETE(st, ch, mid)			\
	__FSM_STATE(st, cold) {						\
		if (likely(c == (ch)))					\
			__FSM_H2_METHOD_COMPLETE(st, 1,	mid);		\
		__FSM_JMP(Req_MethodUnknown);				\
	}

/*
 * @saveval = false for function with explicit chunking i.e.functions that
 * cal __FSM_H2_I_MOVE_fixup(), __FSM_H2_I_MATCH_MOVE_fixup(),
 * H2_TRY_STR_LAMBDA_fixup().
 */
#define TFW_H2_PARSE_HDR_VAL(st_curr, hm, func, hid, saveval)		\
__FSM_STATE(st_curr) {							\
	BUG_ON(p != data);						\
	if (!H2_MSG_VERIFY(hid))					\
		__FSM_H2_DROP(st_curr);					\
	if (!parser->_i_st)						\
		TRY_STR_INIT();						\
	__fsm_n = func(hm, p, len, fin);				\
	T_DBG3("%s: parse header value, " #func ": ret=%d data_len=%lu"	\
	       " hid=%d\n", __func__, __fsm_n, len, hid);		\
	switch (__fsm_n) {						\
	case CSTR_EQ:							\
		if (saveval) {						\
			__msg_hdr_chunk_fixup(data, len);		\
			__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);		\
		}							\
		parser->_i_st = NULL;					\
		parser->_hdr_tag = hid;					\
		parser->_acc = 0;					\
		__FSM_H2_HDR_COMPLETE(st_curr);				\
	case CSTR_POSTPONE:						\
		__FSM_H2_POSTPONE(st_curr);				\
	case CSTR_BADLEN:						\
	case CSTR_NEQ:							\
		__FSM_H2_DROP(st_curr);					\
	default:							\
		/* Unexpected values. */				\
		WARN_ON_ONCE(1);					\
		__FSM_H2_DROP(st_curr);					\
	}								\
}

/*
 * HTTP/2 automaton transition with alphabet checking for headers' name.
 * Improbable states only, so cold label.
 */
#define __FSM_H2_TX_AF(st, ch, st_next)					\
__FSM_STATE(st, cold) {							\
	if (likely(c == ch))						\
		__FSM_H2_NEXT(st_next);					\
	__FSM_JMP(RGen_HdrOtherN);					\
}

#define __FSM_H2_TX_AF_FIN(st, ch, st_next, tag)			\
__FSM_STATE(st, cold) {							\
	if (likely(c == ch))						\
		__FSM_H2_FIN(st_next, 1, tag);				\
	__FSM_JMP(RGen_HdrOtherN);					\
}

#define __FSM_H2_TX_AF_DROP(st, ch)					\
__FSM_STATE(st, cold) {							\
	if (likely(c == ch))						\
		__FSM_H2_DROP(st);					\
	__FSM_JMP(RGen_HdrOtherN);					\
}

/*
 * As above, but drops message if expected character is not matched;
 * applicable for HTTP/2 pseudo-header names, since only a limited
 * number of strictly defined pseudo-headers are allowed (see RFC 7540
 * section 8.1.2.3 and section 8.1.2.4 for details).
 */
#define __FSM_H2_TXD_AF(st, ch, st_next)				\
__FSM_STATE(st, cold) {							\
	if (likely(c == ch))						\
		__FSM_H2_NEXT(st_next);					\
	__FSM_H2_DROP(st);						\
}

#define __FSM_H2_TXD_AF_FIN(st, ch, st_next, tag)			\
__FSM_STATE(st, cold) {							\
	if (likely(c == ch))						\
		__FSM_H2_FIN(st_next, 1, tag);				\
	__FSM_H2_DROP(st);						\
}

#define	__FSM_H2_REQ_NEXT_STATE(v_stage)				\
	if (v_stage)							\
	{								\
		switch (it->tag) {					\
		case TFW_TAG_HDR_H2_METHOD:				\
			goto Req_HdrPsMethodV;				\
		case TFW_TAG_HDR_H2_SCHEME:				\
			goto Req_HdrPsSchemeV;				\
		case TFW_TAG_HDR_H2_AUTHORITY:				\
			goto Req_HdrPsAuthorityV;			\
		case TFW_TAG_HDR_H2_PATH:				\
			goto Req_HdrPsPathV;				\
		case TFW_TAG_HDR_ACCEPT:				\
			goto Req_HdrAcceptV;				\
		case TFW_TAG_HDR_AUTHORIZATION:				\
			goto Req_HdrAuthorizationV;			\
		case TFW_TAG_HDR_CACHE_CONTROL:				\
			goto Req_HdrCache_ControlV;			\
		case TFW_TAG_HDR_CONTENT_ENCODING:			\
			goto Req_HdrContent_EncodingV;			\
		case TFW_TAG_HDR_CONTENT_LENGTH:			\
			goto Req_HdrContent_LengthV;			\
		case TFW_TAG_HDR_CONTENT_TYPE:				\
			goto Req_HdrContent_TypeV;			\
		case TFW_TAG_HDR_COOKIE:				\
			goto Req_HdrCookieV;				\
		case TFW_TAG_HDR_HOST:					\
			goto Req_HdrHostV;				\
		case TFW_TAG_HDR_IF_MODIFIED_SINCE:			\
			goto Req_HdrIf_Modified_SinceV;			\
		case TFW_TAG_HDR_IF_NONE_MATCH:				\
			goto Req_HdrIf_None_MatchV;			\
		case TFW_TAG_HDR_PRAGMA:				\
			goto Req_HdrPragmaV;				\
		case TFW_TAG_HDR_REFERER:				\
			goto Req_HdrRefererV;				\
		case TFW_TAG_HDR_X_FORWARDED_FOR:			\
			goto Req_HdrX_Forwarded_ForV;			\
		case TFW_TAG_HDR_FORWARDED:				\
			goto Req_HdrForwardedV;				\
		case TFW_TAG_HDR_USER_AGENT:				\
			goto Req_HdrUser_AgentV;			\
		case TFW_TAG_HDR_RAW:					\
			goto RGen_HdrOtherV;				\
		default:						\
			__FSM_H2_DROP(Req_HdrForbidden);		\
		}							\
	}

/*
 * Auxiliary macros for parsing message header values (as @__FSM_I_*
 * macros, but intended for HTTP/2 messages parsing).
 */
#define __FSM_H2_I_MOVE_LAMBDA_n_flag_exit(to, n, lambda, flag, exit)	\
do {									\
	p += n;								\
	if (__data_off(p) < len)					\
		goto to;						\
	if (likely(fin)) {						\
		lambda;							\
		__FSM_EXIT(exit);					\
	}								\
	parser->_i_st = &&to;						\
	__msg_hdr_chunk_fixup(data, len);				\
	__FSM_I_chunk_flags(TFW_STR_HDR_VALUE | flag);			\
	__FSM_EXIT(CSTR_POSTPONE);					\
} while (0)

#define __FSM_H2_I_MOVE_LAMBDA_n_flag(to, n, lambda, flag)		\
	__FSM_H2_I_MOVE_LAMBDA_n_flag_exit(to, n, (lambda), flag, CSTR_EQ)

#define __FSM_H2_I_MOVE_LAMBDA_n(to, n, lambda)				\
	__FSM_H2_I_MOVE_LAMBDA_n_flag(to, n, lambda, 0)

#define __FSM_H2_I_MOVE_n(to, n)					\
	__FSM_H2_I_MOVE_LAMBDA_n(to, n, {})

#define __FSM_H2_I_MOVE(to)		__FSM_H2_I_MOVE_n(to, 1)

#define __FSM_H2_I_MOVE_NEQ_n_flag(to, n, flag)				\
	__FSM_H2_I_MOVE_LAMBDA_n_flag_exit(to, n, {}, flag, CSTR_NEQ)

#define __FSM_H2_I_MOVE_NEQ_n(to, n)					\
	__FSM_H2_I_MOVE_NEQ_n_flag(to, n, 0)

#define __FSM_H2_I_MOVE_NEQ(to)						\
	__FSM_H2_I_MOVE_NEQ_n(to, 1)

#define __FSM_H2_I_MOVE_BY_REF_NEQ(to)					\
do {									\
	parser->_i_st = to;						\
	p += 1;								\
	if (__data_off(p) < len)					\
		goto *to;						\
	if (likely(fin)) {						\
		__FSM_EXIT(CSTR_NEQ);					\
	}								\
	__msg_hdr_chunk_fixup(data, len);				\
	__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);				\
	__FSM_EXIT(CSTR_POSTPONE);					\
} while (0)

#define __FSM_H2_I_MATCH(alphabet)					\
do {									\
	__fsm_n = __data_remain(p);					\
	__fsm_sz = tfw_match_##alphabet(p, __fsm_n);			\
} while (0)

#define __FSM_H2_I_MATCH_MOVE_LAMBDA(alphabet, to, lambda)		\
do {									\
	__FSM_H2_I_MATCH(alphabet);					\
	if (__fsm_sz == __fsm_n) {					\
		if (likely(fin)) {					\
			lambda;						\
			__FSM_EXIT(CSTR_EQ);				\
		}							\
		__msg_hdr_chunk_fixup(data, len);			\
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);			\
		parser->_i_st = &&to;					\
		__FSM_EXIT(CSTR_POSTPONE);				\
	}								\
} while (0)

#define __FSM_H2_I_MATCH_MOVE(alphabet, to)				\
	__FSM_H2_I_MATCH_MOVE_LAMBDA(alphabet, to, {})

/*
 * The macros below control chunks within a string for HTTP/2 parsing (see
 * description for @__FSM_I_MOVE_LAMBDA_fixup_f() and others for details).
 */
#define __FSM_H2_I_MOVE_LAMBDA_fixup_f(to, n, field, lambda, flag)	\
do {									\
	BUG_ON(!(field)->data);						\
	__msg_field_fixup_pos(field, p, n);				\
	__FSM_I_field_chunk_flags(field, TFW_STR_HDR_VALUE | flag);	\
	if (__data_off(p + n) < len) {					\
		p += n;							\
		goto to;						\
	}								\
	if (likely(fin))						\
		lambda;							\
	parser->_i_st = &&to;						\
	__FSM_EXIT(CSTR_POSTPONE);					\
} while (0)

#define __FSM_H2_I_MOVE_LAMBDA_fixup(to, n, lambda, flag)		\
	__FSM_H2_I_MOVE_LAMBDA_fixup_f(to, n, &parser->hdr, lambda, flag)

#define __FSM_H2_I_MOVE_fixup(to, n, flag)				\
	__FSM_H2_I_MOVE_LAMBDA_fixup(to, n, {				\
		__FSM_EXIT(CSTR_EQ);					\
	}, flag)

#define __FSM_H2_I_MOVE_NEQ_fixup_f(to, n, field, flag)			\
do {									\
	BUG_ON(!(field)->data);						\
	if (likely(__data_off(p + n) < len)) {				\
		__msg_field_fixup_pos(field, p, n);			\
		__FSM_I_field_chunk_flags(field, TFW_STR_HDR_VALUE | flag); \
		p += n;							\
		goto to;						\
	}								\
	if (likely(fin))						\
		__FSM_EXIT(CSTR_NEQ);					\
	__msg_field_fixup_pos(field, p, n);				\
	__FSM_I_field_chunk_flags(field, TFW_STR_HDR_VALUE | flag);	\
	parser->_i_st = &&to;						\
	__FSM_EXIT(CSTR_POSTPONE);					\
} while (0)

#define __FSM_H2_I_MOVE_NEQ_fixup(to, n, flag)				\
	__FSM_H2_I_MOVE_NEQ_fixup_f(to, n, &parser->hdr, flag)

#define __FSM_H2_I_MATCH_MOVE_LAMBDA_fixup(alphabet, to, lambda, flag)	\
do {									\
	__FSM_H2_I_MATCH(alphabet);					\
	if (likely(__fsm_sz == __fsm_n)) {				\
		__msg_hdr_chunk_fixup(p, __fsm_sz);			\
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE | flag);		\
		if (likely(fin))					\
			lambda;						\
		parser->_i_st = &&to;					\
		__FSM_EXIT(CSTR_POSTPONE);				\
	}								\
} while (0)

#define __FSM_H2_I_MATCH_MOVE_fixup(alphabet, to, flag)			\
	__FSM_H2_I_MATCH_MOVE_LAMBDA_fixup(alphabet, to, {		\
		__FSM_EXIT(CSTR_EQ);					\
	}, flag)

#define __FSM_H2_I_MATCH_MOVE_NEQ_fixup(alphabet, to, flag)		\
do {									\
	__FSM_H2_I_MATCH(alphabet);					\
	if (unlikely(__fsm_sz == __fsm_n)) {				\
		if (likely(fin))					\
			__FSM_EXIT(CSTR_NEQ);				\
		__msg_hdr_chunk_fixup(p, __fsm_sz);			\
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE | flag);		\
		parser->_i_st = &&to;					\
		__FSM_EXIT(CSTR_POSTPONE);				\
	}								\
} while (0)

/**
 * Parsing helpers for HTTP/2 messages (same as @TRY_STR_* macros but
 * optimized for HTTP/2 parsing).
 */
#define H2_TRY_STR_2LAMBDA(str, lambda1, lambda2, curr_st, next_st)	\
	if (!chunk->data)						\
		chunk->data = p;					\
	__fsm_n = __try_str(&parser->hdr, chunk, p, __data_remain(p),	\
			    str, sizeof(str) - 1);			\
	if (__fsm_n > 0) {						\
		if (likely(chunk->len == sizeof(str) - 1)) {		\
			lambda1;					\
			TRY_STR_INIT();					\
			p += __fsm_n;					\
			if (__data_off(p) < len)			\
				goto next_st;				\
			if (likely(fin))				\
				lambda2;				\
			parser->_i_st = &&next_st;			\
			__msg_hdr_chunk_fixup(data, len);		\
			__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);		\
			__FSM_EXIT(CSTR_POSTPONE);			\
		}							\
		if (likely(fin))					\
			return CSTR_NEQ;				\
		parser->_i_st = &&curr_st;				\
		__msg_hdr_chunk_fixup(data, len);			\
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);			\
		__FSM_EXIT(CSTR_POSTPONE);				\
	}

#define H2_TRY_STR_LAMBDA(str, lambda, curr_st, next_st)		\
	H2_TRY_STR_2LAMBDA(str, {}, lambda, curr_st, next_st)

#define H2_TRY_STR(str, curr_st, next_st)				\
	H2_TRY_STR_LAMBDA(str, {					\
		__FSM_EXIT(CSTR_EQ);					\
	}, curr_st, next_st)

/**
 * The same as @H2_TRY_STR_2LAMBDA(), but with explicit chunks control;
 * besides, @str must be of plain @TfwStr{} type and variable @fld is
 * used (instead of hard coded header field).
 * The @lambda might interrupt process and return with an error. In such case
 * we don't need to fixup the current data chunk.
 */
#define H2_TRY_STR_FULL_OR_PART_MATCH_FIN_LAMBDA_fixup(str, fld,		\
						       lambda, fin1, fin2,	\
						       curr_st, next_st,	\
						       flag)			\
do {										\
	BUG_ON(!TFW_STR_PLAIN(str));						\
	if (!chunk->data)							\
		chunk->data = p;						\
	__fsm_n = __try_str(fld, chunk, p, __data_remain(p),			\
			    (str)->data, (str)->len);				\
	if (__fsm_n > 0) {							\
		if (likely(chunk->len == (str)->len)) {				\
			lambda;							\
			TRY_STR_INIT();						\
			__msg_field_fixup_pos(fld, p, __fsm_n);			\
			__FSM_I_field_chunk_flags(fld, 				\
						  TFW_STR_HDR_VALUE | flag);	\
			if (__data_off(p + __fsm_n) < len) {			\
				p += __fsm_n;					\
				goto next_st;					\
			}							\
			if (likely(fin))					\
				fin1;						\
			parser->_i_st = &&next_st;				\
			__FSM_EXIT(CSTR_POSTPONE);				\
		}								\
		__msg_field_fixup_pos(fld, p, __fsm_n);				\
		__FSM_I_field_chunk_flags(fld, TFW_STR_HDR_VALUE | flag);	\
		if (likely(fin))						\
			fin2;							\
		parser->_i_st = &&curr_st;					\
		__FSM_EXIT(CSTR_POSTPONE);					\
	}									\
} while (0)

#define H2_TRY_STR_FULL_MATCH_FIN_LAMBDA_fixup_name(str, fld, lambda, fin,	\
					       curr_st, next_st)		\
	H2_TRY_STR_FULL_OR_PART_MATCH_FIN_LAMBDA_fixup(				\
		str, fld, lambda, fin, {					\
			__FSM_EXIT(CSTR_NEQ);					\
		} , curr_st, next_st, TFW_STR_NAME)

#define H2_TRY_STR_FULL_MATCH_FIN_LAMBDA_fixup(str, fld, lambda, fin,		\
					       curr_st, next_st)		\
	H2_TRY_STR_FULL_OR_PART_MATCH_FIN_LAMBDA_fixup(				\
		str, fld, lambda, fin, {					\
			__FSM_EXIT(CSTR_NEQ);					\
		} , curr_st, next_st, 0)

#define H2_TRY_STR_FULL_OR_PART_MATCH_FIN_fixup(str, fld, fin1, fin2,		\
						curr_st, next_st)		\
	H2_TRY_STR_FULL_OR_PART_MATCH_FIN_LAMBDA_fixup(				\
		str, fld, {}, fin1, fin2, curr_st, next_st, 0)

/* Note: this method isn't called from __h2_req_parse_authority */
void
h2_set_hdr_authority(TfwHttpReq *req, const TfwCachedHeaderState *cstate)
{
	if (cstate->is_set)
		req->host_port = cstate->authority_port;
}

/*
 * ------------------------------------------------------------------------
 *	HTTP/2 request parsing
 * ------------------------------------------------------------------------
 */
static int
__h2_req_parse_authority(TfwHttpReq *req, unsigned char *data, size_t len,
			 bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_A_Start) {
		if (likely(isalnum(c) || c == '.' || c == '-'))
			__FSM_I_JMP(Req_I_A);
		if (likely(c == '['))
			__FSM_H2_I_MOVE_NEQ_n_flag(Req_I_A_v6, 1, TFW_STR_VALUE);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_A) {
		/* See Req_UriAuthority processing. */
		if (likely(isalnum(c) || c == '.' || c == '-')) {
			/* non-fixup function mimicking explicit fixups */
			__FSM_H2_I_MOVE_LAMBDA_n_flag(Req_I_A, 1, {
				__msg_hdr_chunk_fixup(data, (p - data));
				__msg_chunk_flags(TFW_STR_HDR_VALUE | TFW_STR_VALUE);
			}, TFW_STR_VALUE);
		}
		if (p - data) {
			__msg_hdr_chunk_fixup(data, (p - data));
			__msg_chunk_flags(TFW_STR_HDR_VALUE | TFW_STR_VALUE);
		}
		parser->_i_st = &&Req_I_A_End;
		goto Req_I_A_End;
	}

	__FSM_STATE(Req_I_A_End) {
		if (c == ':') {
			parser->_acc = 0;
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_A_Port, 1, 0);
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_A_v6) {
		/* See Req_UriAuthorityIPv6 processing. */
		if (likely(isxdigit(c) || c == ':'))
			__FSM_H2_I_MOVE_NEQ_n_flag(Req_I_A_v6, 1, TFW_STR_VALUE);
		if (likely(c == ']')) {
			__msg_hdr_chunk_fixup(data, (p - data + 1));
			__msg_chunk_flags(TFW_STR_HDR_VALUE | TFW_STR_VALUE);
			parser->_i_st = &&Req_I_A_End;
			p += 1;
			if (unlikely(__data_off(p) >= len)) {
				if (fin)
					__FSM_EXIT(CSTR_EQ);
				__FSM_EXIT(TFW_POSTPONE);
			}
			goto Req_I_A_End;
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_A_Port) {
		__fsm_sz = __data_remain(p);
		__fsm_n = __parse_ulong_ws(p, __data_remain(p), &parser->_acc,
					   USHRT_MAX);
		switch (__fsm_n) {
		case CSTR_BADLEN:
		case CSTR_NEQ:
			return CSTR_NEQ;
		case CSTR_POSTPONE:
			req->host_port = parser->_acc;
			parser->cstate.authority_port = parser->_acc;
			parser->cstate.is_set = 1;
			__FSM_H2_I_MOVE_LAMBDA_fixup(Req_I_A_Port, __fsm_sz, {
				if (req->host_port)
					__FSM_EXIT(CSTR_EQ);
				__FSM_EXIT(CSTR_NEQ);
			}, TFW_STR_VALUE);
		default:
			req->host_port = parser->_acc;
			parser->cstate.authority_port = parser->_acc;
			parser->cstate.is_set = 1;
			parser->_acc = 0;
			if (!req->host_port)
				return CSTR_NEQ;
			__FSM_H2_I_MOVE_LAMBDA_fixup(Req_I_A_Port, __fsm_sz, {
				if (req->host_port)
					__FSM_EXIT(CSTR_EQ);
				__FSM_EXIT(CSTR_NEQ);
			}, TFW_STR_VALUE);
		}
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_authority);

void
h2_set_hdr_accept(TfwHttpReq *req, const TfwCachedHeaderState *cstate)
{
	if (cstate->is_set && cstate->accept_text_html)
		__set_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags);
}

static int
__h2_req_parse_accept(TfwHttpReq *req, unsigned char *data, size_t len,
		      bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_WSAccept) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE_NEQ(Req_I_WSAccept);
		/* Fall through. */
	}

	__FSM_STATE(Req_I_Accept) {
		H2_TRY_STR_LAMBDA("text", {
			__FSM_EXIT(CSTR_NEQ);
		}, Req_I_Accept, Req_I_AfterText);
		/*
		 * TRY_STR() compares the string with the substring at the
		 * beginning of the chunk sequence, but @c is the first
		 * non-matching character with the string of the previous
		 * TRY_STR(). If we will use @c to compare with "*", then we will
		 * catch matches not only with "*", but also with "t*", "te*",
		 * "tex*".
		 */
		H2_TRY_STR_LAMBDA("*", {
			__FSM_EXIT(CSTR_NEQ);
		}, Req_I_Accept, Req_I_AfterStar);
		TRY_STR_INIT();
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_Type);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_AfterText) {
		if (c == '/')
			__FSM_H2_I_MOVE_NEQ(Req_I_AfterTextSlash);

		__FSM_H2_I_MOVE(Req_I_Type);
	}

	__FSM_STATE(Req_I_AfterTextSlash) {
		if (c == '*')
			__FSM_H2_I_MOVE(I_EoT);
		/* Fall through. */
	}

	__FSM_STATE(Req_I_AfterTextSlashToken) {
		H2_TRY_STR_LAMBDA("html", {
			parser->cstate.is_set = 1;
			parser->cstate.accept_text_html = 1;
			h2_set_hdr_accept(req, &parser->cstate);
			__FSM_EXIT(CSTR_EQ);
		},  Req_I_AfterTextSlashToken, Req_I_AcceptHtml);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_Subtype);
	}

	__FSM_STATE(Req_I_AfterStar) {
		if (c == '/')
			__FSM_H2_I_MOVE_NEQ(Req_I_StarSlashStar);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_StarSlashStar) {
		if (c == '*')
			__FSM_H2_I_MOVE(I_EoT);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_AcceptHtml) {
		if (IS_WS(c) || c == ',' || c == ';') {
			__set_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags);
			__FSM_I_JMP(I_EoT);
		}
		__FSM_I_JMP(Req_I_Subtype);
	}

	__FSM_STATE(Req_I_Type) {
		__FSM_H2_I_MATCH_MOVE_LAMBDA(token, Req_I_Type, {
			__FSM_EXIT(CSTR_NEQ);
		});
		c = *(p + __fsm_sz);
		if (c == '/')
			__FSM_H2_I_MOVE_NEQ_n(Req_I_Slash, __fsm_sz + 1);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Slash) {
		if (c == '*')
			__FSM_H2_I_MOVE(I_EoT);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_Subtype);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Subtype) {
		__FSM_H2_I_MATCH_MOVE(token, Req_I_Subtype);
		__FSM_H2_I_MOVE_n(I_EoT, __fsm_sz);
	}

	__FSM_REQUIRE(Req_I_QValueBeg, Req_I_QValue,
		      (c == '0' || c == '1'));

	__FSM_STATE(Req_I_QValue) {
		if (isdigit(c) || c == '.')
			__FSM_H2_I_MOVE(Req_I_QValue);
		__FSM_I_JMP(I_EoT);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_WSAcceptOther) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE(Req_I_WSAcceptOther);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_AcceptOther);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_AcceptOther) {
		H2_TRY_STR_LAMBDA("q=", {
			__FSM_EXIT(CSTR_NEQ);
		}, Req_I_AcceptOther, Req_I_QValueBeg);
		TRY_STR_INIT();
		__FSM_H2_I_MATCH_MOVE_LAMBDA(token, Req_I_AcceptOther, {
			__FSM_EXIT(CSTR_NEQ);
		});
		c = *(p + __fsm_sz);
		if (c == '=')
			__FSM_H2_I_MOVE_NEQ_n(Req_I_ParamValueBeg, __fsm_sz + 1);
		return CSTR_NEQ;
	}

	__FSM_REQUIRE(Req_I_ParamValueBeg, Req_I_ParamValue,
		      (IS_TOKEN(c) || c == '\"'));

	__FSM_STATE(Req_I_ParamValue) {
		if (c == '\"')
			__FSM_H2_I_MOVE_NEQ(Req_I_QuotedString);
		__FSM_H2_I_MATCH_MOVE(token, Req_I_ParamValue);
		__FSM_H2_I_MOVE_n(I_EoT, __fsm_sz);
	}

	__FSM_STATE(Req_I_QuotedString) {
		__FSM_H2_I_MATCH_MOVE_LAMBDA(token, Req_I_QuotedString, {
			__FSM_EXIT(CSTR_NEQ);
		});
		if (c != '"')
			__FSM_H2_I_MOVE_NEQ(Req_I_QuotedString);
		__FSM_H2_I_MOVE(I_EoT);
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE(I_EoT);
		if (c == ',')
			__FSM_H2_I_MOVE(Req_I_WSAccept);
		if (c == ';')
			/* Skip weight parameter. */
			__FSM_H2_I_MOVE_NEQ(Req_I_WSAcceptOther);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_accept);

static int
__h2_req_parse_authorization(TfwHttpReq *req, unsigned char *data, size_t len,
			     bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_Auth) {
		/*
		 * RFC 7235 requires handling quoted-string in auth-param,
		 * so almost any character can appear in the field.
		 */
		__FSM_H2_I_MATCH_MOVE_LAMBDA(ctext_vchar, Req_I_Auth, {
			req->cache_ctl.flags |=	TFW_HTTP_CC_HDR_AUTHORIZATION;
		});
		return CSTR_NEQ;
	}

done:
	return r;
}

static int
__h2_req_parse_cache_control(TfwHttpReq *req, unsigned char *data, size_t len,
			     bool fin)
{
	/* Mostly a copy of __req_parse_cache_control, see comments there */
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

#define __FSM_H2_I_MOVE_RESET_ACC(to, n)				\
	__FSM_H2_I_MOVE_LAMBDA_n(to, n, {				\
		parser->_acc = 0;					\
	})

	__FSM_START(parser->_i_st);

	parser->cc_dir_flag = 0;

	__FSM_STATE(Req_I_CC_start) {
		/* Spaces already skipped by RGen_LWS */
		if (c == ',')
			__FSM_H2_I_MOVE(Req_I_CC_start_Comma);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_CC);

		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Req_I_CC_start_Comma) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE(Req_I_CC_start_Comma);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Req_I_CC);
		/* Forbid empty header value and double commas */
		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Req_I_CC) {
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
		H2_TRY_STR_LAMBDA("max-age=", {
			__FSM_EXIT(CSTR_NEQ);
		}, Req_I_CC_m, Req_I_CC_MaxAgeVBeg);
		H2_TRY_STR_LAMBDA("min-fresh=", {
			__FSM_EXIT(CSTR_NEQ);
		}, Req_I_CC_m, Req_I_CC_MinFreshVBeg);
		H2_TRY_STR_LAMBDA("max-stale", {
			req->cache_ctl.max_stale = UINT_MAX;
			req->cache_ctl.flags |= TFW_HTTP_CC_MAX_STALE;
			__FSM_EXIT(CSTR_EQ);
		}, Req_I_CC_m, Req_I_CC_MaxStale);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_n) {
		H2_TRY_STR_2LAMBDA("no-cache", {
			parser->cc_dir_flag = TFW_HTTP_CC_NO_CACHE;
		}, {
			req->cache_ctl.flags |= TFW_HTTP_CC_NO_CACHE;
			__FSM_EXIT(CSTR_EQ);
		}, Req_I_CC_n, Req_I_CC_Flag);
		H2_TRY_STR_2LAMBDA("no-store", {
			parser->cc_dir_flag = TFW_HTTP_CC_NO_STORE;
		}, {
			req->cache_ctl.flags |= TFW_HTTP_CC_NO_STORE;
			__FSM_EXIT(CSTR_EQ);
		}, Req_I_CC_n, Req_I_CC_Flag);
		H2_TRY_STR_2LAMBDA("no-transform", {
			parser->cc_dir_flag = TFW_HTTP_CC_NO_TRANSFORM;
		}, {
			req->cache_ctl.flags |= TFW_HTTP_CC_NO_TRANSFORM;
			__FSM_EXIT(CSTR_EQ);
		}, Req_I_CC_n, Req_I_CC_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_o) {
		H2_TRY_STR_2LAMBDA("only-if-cached", {
			parser->_acc = TFW_HTTP_CC_OIFCACHED;
		}, {
			req->cache_ctl.flags |= TFW_HTTP_CC_OIFCACHED;
			__FSM_EXIT(CSTR_EQ);
		}, Req_I_CC_o, Req_I_CC_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_STATE(Req_I_CC_Flag) {
		if (IS_WS(c) || c == ',') {
			req->cache_ctl.flags |= parser->cc_dir_flag;
			__FSM_I_JMP(Req_I_EoT);
		}
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_REQUIRE_FIRST_DIGIT(Req_I_CC_MaxAgeVBeg, Req_I_CC_MaxAgeV);

	__FSM_STATE(Req_I_CC_MaxAgeV) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_uint_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE) {
			if (likely(fin)) {
				req->cache_ctl.max_age = parser->_acc;
				req->cache_ctl.flags |= TFW_HTTP_CC_MAX_AGE;
				parser->_acc = 0;
				return CSTR_EQ;
			}
			__msg_hdr_chunk_fixup(data, len);
			__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);
		}
		if (__fsm_n < 0)
			return __fsm_n;
		req->cache_ctl.max_age = parser->_acc;
		req->cache_ctl.flags |= TFW_HTTP_CC_MAX_AGE;
		__FSM_H2_I_MOVE_RESET_ACC(Req_I_EoT, __fsm_n);
	}

	__FSM_REQUIRE_FIRST_DIGIT(Req_I_CC_MinFreshVBeg, Req_I_CC_MinFreshV);

	__FSM_STATE(Req_I_CC_MinFreshV) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_uint_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE) {
			if (likely(fin)) {
				req->cache_ctl.min_fresh = parser->_acc;
				req->cache_ctl.flags |= TFW_HTTP_CC_MIN_FRESH;
				parser->_acc = 0;
				return CSTR_EQ;
			}
			__msg_hdr_chunk_fixup(data, len);
			__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);
		}
		if (__fsm_n < 0)
			return __fsm_n;
		req->cache_ctl.min_fresh = parser->_acc;
		req->cache_ctl.flags |= TFW_HTTP_CC_MIN_FRESH;
		__FSM_H2_I_MOVE_RESET_ACC(Req_I_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_MaxStale) {
		if (c == '=')
			__FSM_H2_I_MOVE_NEQ(Req_I_CC_MaxStaleVBeg);
		if (IS_WS(c) || c == ',') {
			req->cache_ctl.max_stale = UINT_MAX;
			req->cache_ctl.flags |= TFW_HTTP_CC_MAX_STALE;
			__FSM_I_JMP(Req_I_EoT);
		}
		__FSM_I_JMP(Req_I_CC_Ext);
	}

	__FSM_REQUIRE_FIRST_DIGIT(Req_I_CC_MaxStaleVBeg, Req_I_CC_MaxStaleV);

	__FSM_STATE(Req_I_CC_MaxStaleV) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_uint_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE) {
			if (likely(fin)) {
				req->cache_ctl.max_stale = parser->_acc;
				req->cache_ctl.flags |= TFW_HTTP_CC_MAX_STALE;
				parser->_acc = 0;
				return CSTR_EQ;
			}
			__msg_hdr_chunk_fixup(data, len);
			__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);
		}
		if (__fsm_n < 0)
			return __fsm_n;
		req->cache_ctl.max_stale = parser->_acc;
		req->cache_ctl.flags |= TFW_HTTP_CC_MAX_STALE;
		__FSM_H2_I_MOVE_RESET_ACC(Req_I_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_Ext) {
		__FSM_H2_I_MATCH_MOVE_LAMBDA(qetoken, Req_I_CC_Ext, {
			parser->_acc = 0;
		});

		__FSM_H2_I_MOVE_RESET_ACC(Req_I_EoT, __fsm_sz);
	}

	__FSM_STATE(Req_I_EoT) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE_RESET_ACC(Req_I_EoT, 1);
		if (c == ',')
			__FSM_H2_I_MOVE_RESET_ACC(Req_I_After_Comma, 1);

		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Req_I_After_Comma) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE(Req_I_After_Comma);

		parser->_acc = 0;
		if (IS_TOKEN(c)) {
			parser->cc_dir_flag = 0;
			__FSM_I_JMP(Req_I_CC);
		}
		__FSM_EXIT(TFW_BLOCK);
	}

done:
	return r;

#undef __FSM_H2_I_MOVE_RESET_ACC
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_cache_control);

/* Parse Content-Encoding header value, RFC 9110 8.4. */
static int
__h2_req_parse_content_encoding(TfwHttpMsg *hm, unsigned char *data,
				size_t len, bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_EncodTok) {
		__FSM_H2_I_MATCH_MOVE_fixup(token, I_EncodTok, 0);
		__FSM_H2_I_MOVE_fixup(I_EoT, __fsm_sz, 0);
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (c == ',')
			__FSM_H2_I_MOVE_fixup(I_EoT, 1, 0);
		if (IS_WS(c))
			__FSM_H2_I_MOVE_fixup(I_EoT, 1, TFW_STR_OWS);
		if (IS_TOKEN(c))
			__FSM_I_JMP(I_EncodTok);

		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_content_encoding);

static int
__h2_req_parse_content_length(TfwHttpMsg *msg, unsigned char *data, size_t len,
			      bool fin)
{
	int ret;

	ret = parse_long_ws(data, len, &msg->content_length);

	T_DBG3("%s: content_length=%lu, ret=%d\n", __func__,
	       msg->content_length, ret);

	if (ret == CSTR_POSTPONE) {
		if (fin)
			return CSTR_EQ;
		__msg_hdr_chunk_fixup(data, len);
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);
		return CSTR_POSTPONE;
	}

	return ret >= 0 ? CSTR_NEQ : ret;
}

static int
__h2_req_parse_content_type(TfwHttpMsg *hm, unsigned char *data, size_t len,
			    bool fin)
{
	int r = CSTR_NEQ;
	TfwHttpReq *req = (TfwHttpReq *)hm;
	__FSM_DECLARE_VARS(hm);

#define __FSM_H2_I_MOVE_FINALIZE_fixup(to, n)				\
	__FSM_H2_I_MOVE_LAMBDA_fixup(to, n, {				\
		goto finalize;						\
	}, 0)

#define __FSM_H2_I_MATCH_MOVE_FINALIZE_fixup(alphabet, to, flag)	\
	__FSM_H2_I_MATCH_MOVE_LAMBDA_fixup(alphabet, to, {		\
		p += __fsm_sz;						\
		goto finalize;						\
	}, flag)

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_ContType) {
		if (req->method != TFW_HTTP_METH_POST)
			__FSM_I_JMP(I_EoL);
		/* Fall through. */
	}

	__FSM_STATE(I_ContTypeMediaType) {
		static const TfwStr s_multipart_form_data =
			TFW_STR_STRING("multipart/form-data");
		H2_TRY_STR_FULL_OR_PART_MATCH_FIN_fixup(
			&s_multipart_form_data, &parser->hdr, {
				/*
				 * In that lambda (that corresponds to a full
				 * match) the parser do successful exit
				 * and it is no needed to apply p += __fsm_n.
				 */
				__set_bit(TFW_HTTP_B_CT_MULTIPART, req->flags);
				__FSM_EXIT(CSTR_EQ);
			}, {
				if (chunk->len == sizeof("multipart/") - 1)
					__FSM_EXIT(CSTR_NEQ);
				/* This lambda (that corresponds to a partial
				 * match) indicate that the parser will continue
				 * working in the next state
				 * (I_ContTypeOtherSubtype or I_ContTypeOtherType).
				 * The parser must continue working in the next
				 * state from position right after already
				 * processed bytes. So, it is needed
				 * to apply p += __fsm_n.
				 */
				p += __fsm_n;
				break;
			}, I_ContTypeMediaType, I_ContTypeMaybeMultipart);
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
			__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeParamOWS, 1);
		}
		if (IS_WS(c))
			__FSM_H2_I_MOVE_LAMBDA_fixup(I_ContTypeMultipartOWS, 1, {
			    __set_bit(TFW_HTTP_B_CT_MULTIPART, req->flags);
			    goto finalize;
			}, 0);
		__FSM_I_JMP(I_ContTypeOtherSubtype);
	}

	__FSM_STATE(I_ContTypeMultipartOWS) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE_LAMBDA_fixup(I_ContTypeMultipartOWS, 1, {
			    __set_bit(TFW_HTTP_B_CT_MULTIPART, req->flags);
			    goto finalize;
			}, 0);
		if (c == ';') {
			__set_bit(TFW_HTTP_B_CT_MULTIPART, req->flags);
			__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeParamOWS, 1);
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_ContTypeParamOWS) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeParamOWS, 1);
		/* Fall through. */
	}

	__FSM_STATE(I_ContTypeParam) {
		static const TfwStr s_boundary = TFW_STR_STRING("boundary=");
		if (!test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags))
			__FSM_I_JMP(I_ContTypeParamOther);

		H2_TRY_STR_FULL_MATCH_FIN_LAMBDA_fixup(&s_boundary, &parser->hdr, {
			/*
			 * Requests with multipart/form-data payload should have
			 * only one boundary parameter.
			 */
			if (__test_and_set_bit(
				    TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				    req->flags))
			{
				__FSM_EXIT(CSTR_NEQ);
			}
		}, {
			__FSM_EXIT(CSTR_EQ);
		}, I_ContTypeParam, I_ContTypeBoundaryValue);
		TRY_STR_INIT();
		/* Fall through. */
	}

	__FSM_STATE(I_ContTypeParamOther) {
		/*
		 * If the header value is finished here, that means that value
		 * is ended just after parameter name; thus, parameter value is
		 * missing, and the header is invalid.
		 */
		__FSM_H2_I_MATCH_MOVE_NEQ_fixup(token, I_ContTypeParamOther, 0);
		if (*(p + __fsm_sz) != '=')
			return CSTR_NEQ;
		__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeParamValue, __fsm_sz + 1);
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
			__FSM_H2_I_MOVE_NEQ_fixup(I_ContTypeBoundaryValueQuoted,
						  1, 0);
		}
		/* Fall through. */
	}

	__FSM_STATE(I_ContTypeBoundaryValueUnquoted) {
		__fsm_n = __data_remain(p);
		__fsm_sz = tfw_match_token(p, __fsm_n);
		if (__fsm_sz > 0) {
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			__FSM_I_chunk_flags(TFW_STR_HDR_VALUE | TFW_STR_VALUE);
			req->multipart_boundary_raw.len += __fsm_sz;
			req->multipart_boundary.len += __fsm_sz;
		}
		if (__fsm_sz == __fsm_n) {
			if (likely(fin)) {
				req->multipart_boundary_raw.nchunks =
					parser->hdr.nchunks -
					(size_t)req->multipart_boundary_raw.data;
				p += __fsm_sz;
				goto finalize;
			}
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
			__FSM_I_chunk_flags(TFW_STR_HDR_VALUE | TFW_STR_VALUE);
			req->multipart_boundary_raw.len += __fsm_sz;
			req->multipart_boundary.len += __fsm_sz;
		}
		if (unlikely(__fsm_sz == __fsm_n)) {
			if (likely(fin)) {
				/* Missing closing '"'. */
				return CSTR_NEQ;
			}
			parser->_i_st = &&I_ContTypeBoundaryValueQuoted;
			return CSTR_POSTPONE;
		}
		p += __fsm_sz;
		if (*p == '\\') {
			req->multipart_boundary_raw.len += 1;
			__FSM_H2_I_MOVE_NEQ_fixup(
				I_ContTypeBoundaryValueEscapedChar,
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
			__FSM_H2_I_MOVE_NEQ_fixup(I_ContTypeBoundaryValueQuoted,
						  1, TFW_STR_VALUE);
		}

		/* *p == '"' */
		__msg_hdr_chunk_fixup(p, 1);
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);
		p += 1;
		req->multipart_boundary_raw.len += 1;
		req->multipart_boundary_raw.nchunks = parser->hdr.nchunks -
			(size_t)req->multipart_boundary_raw.data;

		if (unlikely(__data_remain(p) == 0)) {
			if (fin)
				goto finalize;
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
		__FSM_H2_I_MOVE_NEQ_fixup(I_ContTypeBoundaryValueQuoted, 1,
					  TFW_STR_VALUE);
	}

	__FSM_STATE(I_ContTypeParamValue) {
		if (*p == '"')
			__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeParamValueQuoted, 1);
		/* Fall through. */
	}

	__FSM_STATE(I_ContTypeParamValueUnquoted) {
		__FSM_H2_I_MATCH_MOVE_FINALIZE_fixup(token,
						I_ContTypeParamValueUnquoted,
						TFW_STR_VALUE);
		__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeParamValueOWS, __fsm_sz);
	}

	__FSM_STATE(I_ContTypeParamValueOWS) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeParamValueOWS, 1);
		if (c == ';')
			__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeParamOWS, 1);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_ContTypeParamValueQuoted) {
		__FSM_H2_I_MATCH_MOVE_NEQ_fixup(token,
						I_ContTypeParamValueQuoted,
						TFW_STR_VALUE);
		if (__fsm_sz > 0) {
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			__FSM_I_chunk_flags(TFW_STR_HDR_VALUE | TFW_STR_VALUE);
		}
		p += __fsm_sz;
		if (*p == '\\')
			__FSM_H2_I_MOVE_NEQ_fixup(
				I_ContTypeParamValueEscapedChar,
				1, 0);
		if (*p == '"')
			__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeParamValueOWS, 1);
		if (IS_CRLF(*p)) {
			/* Missing closing '"'. */
			return CSTR_NEQ;
		}
		/* TODO: faster qdtext/quoted-pair matcher. */
		__FSM_H2_I_MOVE_NEQ_fixup(I_ContTypeParamValueQuoted, 1, 0);
	}

	__FSM_STATE(I_ContTypeParamValueEscapedChar) {
		if (IS_CRLF(*p))
			return CSTR_NEQ;
		__FSM_H2_I_MOVE_NEQ_fixup(I_ContTypeParamValueQuoted, 1,
					  TFW_STR_VALUE);
	}

	__FSM_STATE(I_ContTypeOtherType) {
		__FSM_H2_I_MATCH_MOVE_FINALIZE_fixup(token, I_ContTypeOtherType, 0);
		c = *(p + __fsm_sz);
		if (c != '/')
			return CSTR_NEQ;
		__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeOtherSubtype, __fsm_sz + 1);
	}

	__FSM_STATE(I_ContTypeOtherSubtype) {
		__FSM_H2_I_MATCH_MOVE_FINALIZE_fixup(token, I_ContTypeOtherSubtype, 0);
		__msg_hdr_chunk_fixup(p, __fsm_sz);
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);
		p += __fsm_sz;
		/* Fall through. */
	}

	__FSM_STATE(I_ContTypeOtherTypeOWS) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeOtherTypeOWS, 1);
		if (c == ';')
			__FSM_H2_I_MOVE_FINALIZE_fixup(I_ContTypeParamOWS, 1);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_EoL) {
		__FSM_H2_I_MATCH_MOVE_FINALIZE_fixup(ctext_vchar, I_EoL, 0);
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

	return CSTR_EQ;

#undef __FSM_H2_I_MOVE_FINALIZE_fixup
#undef __FSM_H2_I_MATCH_MOVE_FINALIZE_fixup
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_content_type);

static int
__h2_req_parse_cookie(TfwHttpMsg *hm, unsigned char *data, size_t len, bool fin)
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
		__FSM_H2_I_MATCH_MOVE_NEQ_fixup(token, Req_I_CookieName,
						TFW_STR_NAME);
		/*
		 * Name should contain at least 1 character.
		 * Store "=" with cookie parameter name.
		 */
		if (likely(__fsm_sz && *(p + __fsm_sz) == '='))
			__FSM_H2_I_MOVE_fixup(Req_I_CookieVal, __fsm_sz + 1,
					      TFW_STR_NAME);
		return CSTR_NEQ;
	}

	/*
	 * At this state we know that we saw at least one character as
	 * cookie-name and now we can pass zero length token. Cookie-value
	 * can have zero length.
	 */
	__FSM_STATE(Req_I_CookieName) {
		__FSM_H2_I_MATCH_MOVE_NEQ_fixup(token, Req_I_CookieName,
						TFW_STR_NAME);
		if (*(p + __fsm_sz) != '=')
			return CSTR_NEQ;
		/* Store "=" with cookie parameter name. */
		__FSM_H2_I_MOVE_fixup(Req_I_CookieVal, __fsm_sz + 1,
				      TFW_STR_NAME);
	}

	__FSM_STATE(Req_I_CookieVal) {
		__FSM_H2_I_MATCH_MOVE_fixup(cookie, Req_I_CookieVal,
					    TFW_STR_VALUE);
		c = *(p + __fsm_sz);
		if (c == ';') {
			if (likely(__fsm_sz)) {
				/* Save cookie-value w/o ';'. */
				__msg_hdr_chunk_fixup(p, __fsm_sz);
				__FSM_I_chunk_flags(TFW_STR_HDR_VALUE
						    | TFW_STR_VALUE);
			}
			p += __fsm_sz;
			__FSM_I_JMP(Req_I_CookieSemicolon);
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
				__FSM_H2_I_MOVE_NEQ_fixup(Req_I_CookieStart,
							  2, 0);
			return CSTR_NEQ;
		}
		/*
		 * After ';' must be SP and another cookie-pair. Thus, if this
		 * is the last parsed part of the header value, the header is
		 * invalid.
		 */
		if (likely(fin))
			__FSM_EXIT(CSTR_NEQ);
		/*
		 * Only ';' is available now: fixup ';' as independent chunk,
		 * SP will be fixed up at next enter to the FSM.
		 */
		__msg_hdr_chunk_fixup(p, 1);
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);
		parser->_i_st = &&Req_I_CookieSP;
		__FSM_EXIT(CSTR_POSTPONE);
	}

	__FSM_STATE(Req_I_CookieSP) {
		if (unlikely(c != ' '))
			return CSTR_NEQ;
		/* Fixup delimiters chunk and move to the next parameter. */
		__FSM_H2_I_MOVE_NEQ_fixup(Req_I_CookieStart, 1, 0);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_cookie);

#define __FSM_H2_TX_ETAG_fixup(st, ch, st_next)				\
__FSM_STATE(st) {							\
	if (likely(c == (ch)))						\
		__FSM_H2_I_MOVE_NEQ_fixup(st_next, 1, 0);		\
	return CSTR_NEQ;						\
}

static int
__h2_req_parse_if_nmatch(TfwHttpMsg *hm, unsigned char *data, size_t len,
			 bool fin)
{
	int r = CSTR_NEQ;
	TfwHttpReq *req = (TfwHttpReq *)hm;
	__FSM_DECLARE_VARS(hm);

	/*
	 * RFC 7232 3.3:
	 *
	 * A recipient MUST ignore If-Modified-Since if the request contains an
	 * If-None-Match header field.
	 */
	if (req->cond.flags & TFW_HTTP_COND_IF_MSINCE) {
		req->cond.m_date = 0;
		req->cond.flags &= ~TFW_HTTP_COND_IF_MSINCE;
	}

	/*
	 * ETag value and closing DQUOTE are placed into separate chunks (see
	 * comments in @__parse_etag_or_if_nmatch() for details).
	 */
	__FSM_START(parser->_i_st);

	__FSM_STATE(I_Etag) {
		if (likely(c == '"')) {
			req->cond.flags |= TFW_HTTP_COND_ETAG_LIST;
			__FSM_H2_I_MOVE_NEQ_fixup(I_Etag_Val, 1, 0);
		}

		if (likely(__data_available(p, 3))
		    && (*p == 'W') && (*(p + 1) == '/') && (*(p + 2) == '"'))
		{
			__FSM_H2_I_MOVE_NEQ_fixup(I_Etag_Weak, 3, 0);
		}
		if (c == 'W')
			__FSM_H2_I_MOVE_NEQ_fixup(I_Etag_W, 1, 0);

		if (c == '*') {
			if (req->cond.flags & TFW_HTTP_COND_ETAG_LIST)
				return CSTR_NEQ;

			req->cond.flags |= TFW_HTTP_COND_ETAG_ANY;
			parser->cstate.is_set = 1;
			parser->cstate.ifnmatch_etag_any = 1;
			__FSM_H2_I_MOVE_fixup(I_EoL, 1, 0);
		}

		if (IS_WS(c))
			__FSM_H2_I_MOVE_NEQ_fixup(I_Etag, 1, 0);
		return CSTR_NEQ;
	}

	__FSM_H2_TX_ETAG_fixup(I_Etag_W, '/', I_Etag_We);
	__FSM_H2_TX_ETAG_fixup(I_Etag_We, '"', I_Etag_Weak);

	__FSM_STATE(I_Etag_Weak) {
		__FSM_JMP(I_Etag_Val);
	}

	__FSM_STATE(I_Etag_Val) {
		__FSM_H2_I_MATCH_MOVE_NEQ_fixup(etag, I_Etag_Val, TFW_STR_VALUE);
		c = *(p + __fsm_sz);
		if (likely(c == '"')) {
			__FSM_H2_I_MOVE_fixup(I_EoT, __fsm_sz + 1, TFW_STR_VALUE);
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_EoT) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE_fixup(I_EoT, 1, 0);
		if (c == ',')
			__FSM_H2_I_MOVE_NEQ_fixup(I_Etag, 1, 0);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_EoL) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE_fixup(I_EoL, 1, 0);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_if_nmatch);

static int
__h2_req_parse_referer(TfwHttpMsg *hm, unsigned char *data, size_t len,
		       bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_Referer) {
		__FSM_H2_I_MATCH_MOVE(uri, Req_I_Referer);
		if (IS_WS(*(p + __fsm_sz)))
			__FSM_H2_I_MOVE_n(Req_I_EoT, __fsm_sz + 1);
		return CSTR_NEQ;
	}
	__FSM_STATE(Req_I_EoT) {
		if (IS_WS(c))
			__FSM_H2_I_MOVE(Req_I_EoT);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_referer);

static int
__h2_parse_http_date(TfwHttpMsg *hm, unsigned char *data, size_t len, bool fin)
{
	static const void * const st[][23] __annotate_jump_table = {
		[RFC_822] = {
			&&I_Day, &&I_Day, &&I_SP,
			&&I_MonthBeg, &&I_Month, &&I_Month, &&I_SP,
			&&I_Year, &&I_Year, &&I_Year, &&I_Year, &&I_SP,
			&&I_Hour, &&I_Hour, &&I_SC,
			&&I_Min, &&I_Min, &&I_SC,
			&&I_Sec, &&I_Sec, &&I_SP,
			&&I_GMT, /*&&I_Res*/
			/*
			 * The I_Res is omitted because the transition
			 * from I_GMT to I_Res is explicitly indicated
			 * in the code below
			 */
		},
		[RFC_850] = {
			&&I_Day, &&I_Day, &&I_Minus,
			&&I_MonthBeg, &&I_Month, &&I_Month, &&I_Minus,
			&&I_Year, &&I_Year, &&I_SP,
			&&I_Hour, &&I_Hour, &&I_SC,
			&&I_Min, &&I_Min, &&I_SC,
			&&I_Sec, &&I_Sec, &&I_SP,
			&&I_GMT, /*&&I_Res*/
			/*
			 * The I_Res is omitted because the transition
			 * from I_GMT to I_Res is explicitly indicated
			 * in the code below
			 */
		},
		[ISOC] = {
			&&I_MonthBeg, &&I_Month, &&I_Month, &&I_SP,
			&&I_SpaceOrDay, &&I_Day, &&I_SP,
			&&I_Hour, &&I_Hour, &&I_SC,
			&&I_Min, &&I_Min, &&I_SC,
			&&I_Sec, &&I_Sec, &&I_SP,
			&&I_Year, &&I_Year, &&I_Year, &&I_YearEnd,
			&&I_Res
		}
	};
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START_ALT(parser->_i_st);

	/*
	 * Skip a weekday with comma (e.g. "Sun,") as redundant
	 * information.
	 */
	__FSM_STATE(I_WDate1) {
		if (likely('A' <= c && c <= 'Z'))
			__FSM_H2_I_MOVE_NEQ(I_WDate2);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_WDate2) {
		if (likely('a' <= c && c <= 'z'))
			__FSM_H2_I_MOVE_NEQ(I_WDate3);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_WDate3) {
		if (likely('a' <= c && c <= 'z'))
			__FSM_H2_I_MOVE_NEQ(I_WDate4);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_WDate4) {
		parser->_acc = 0;
		parser->month_int = ((size_t)' ') << 24;
		if (likely(c == ',')) {
			parser->date.type = RFC_822;
			__FSM_H2_I_MOVE_NEQ(I_WDaySP);
		}
		if ('a' <= c && c <= 'z') {
			parser->date.type = RFC_850;
			__FSM_H2_I_MOVE_NEQ(I_WDate5);
		}
		if (c == ' ') {
			parser->date.type = ISOC;
			__FSM_H2_I_MOVE_BY_REF_NEQ(
				st[parser->date.type][parser->date.pos]);
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_WDate5) {
		if ('a' <= c && c <= 'z')
			__FSM_H2_I_MOVE_NEQ(I_WDate5);
		if (c == ',')
			__FSM_H2_I_MOVE_NEQ(I_WDaySP);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_WDaySP) {
		if (likely(c == ' '))
			__FSM_H2_I_MOVE_BY_REF_NEQ(
				st[parser->date.type][parser->date.pos]);
		return CSTR_NEQ;
	}

#define __NEXT_TEMPL_STATE()							\
do {										\
	++parser->date.pos;							\
	__FSM_H2_I_MOVE_BY_REF_NEQ(st[parser->date.type][parser->date.pos]);	\
} while (0)

	__FSM_STATE(I_SP) {
		if (likely(c == ' '))
			__NEXT_TEMPL_STATE();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Minus) {
		if (likely(c == '-'))
			__NEXT_TEMPL_STATE();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_SC) {
		if (likely(c == ':'))
			__NEXT_TEMPL_STATE();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_SpaceOrDay) {
		if (c == ' ')
			__NEXT_TEMPL_STATE();
		if (isdigit(c)) {
			parser->date.day = parser->date.day * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Day) {
		if (isdigit(c)) {
			parser->date.day = parser->date.day * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_MonthBeg) {
		if ('A' <= c && c <= 'Z') {
			parser->month_int =
				((size_t)c) << 24 | (parser->month_int >> 8);
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Month) {
		if ('a' <= c && c <= 'z') {
			parser->month_int =
				((size_t)c) << 24 | (parser->month_int >> 8);
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Year) {
		if (isdigit(c)) {
			parser->date.year = parser->date.year * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_YearEnd) {
		if (isdigit(c)) {
			p += 1;
			if (__data_off(p) == len && fin) {
				parser->date.year
					= parser->date.year * 10 + (c - '0');
				++parser->date.pos;
				__FSM_JMP(*st[parser->date.type][parser->date.pos]);
			}
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Hour) {
		if (isdigit(c)) {
			parser->date.hour = parser->date.hour * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Min) {
		if (isdigit(c)) {
			parser->date.min = parser->date.min * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Sec) {
		if (isdigit(c)) {
			parser->date.sec = parser->date.sec * 10 + (c - '0');
			__NEXT_TEMPL_STATE();
		}
		return CSTR_NEQ;
	}
#undef __NEXT_TEMPL_STATE

	__FSM_STATE(I_GMT) {
		H2_TRY_STR_LAMBDA("gmt", {
			/*
			 * The st[][]-table is not used because it is known
			 * that I_GMT is followed by I_Res.
			 */
			__FSM_I_JMP(I_Res);
		}, I_GMT, I_Res);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	__FSM_STATE(I_Res) {
		int month;
		long date;

		if (parser->date.day == 0)
			return CSTR_NEQ;

		month = __parse_month(parser->month_int);
		if (month < 0)
			return CSTR_NEQ;

		if (parser->date.year < 100 && parser->date.type == RFC_850)
			parser->date.year += (parser->date.year < 70) ? 2000
								      : 1900;

		date = __date_secs(parser->date.year, month,
				   parser->date.day, parser->date.hour,
				   parser->date.min, parser->date.sec);
		if (date < 0)
			return CSTR_NEQ;
		parser->_date = date;
		__FSM_JMP(I_EoL);
	}

	__FSM_STATE(I_EoL) {
		parser->_acc = 0;
		/* Skip the rest of the line. */
		__FSM_H2_I_MATCH_MOVE(nctl, I_EoL);
		if (!IS_CRLF(*(p + __fsm_sz)))
			return CSTR_NEQ;
		T_DBG3("%s: parsed date %lu", __func__, parser->_date);
		return __data_off(p + __fsm_sz);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_parse_http_date);

int
h2_set_hdr_if_mod_since(TfwHttpReq *req, const TfwCachedHeaderState *cstate)
{
	if (req->cond.flags & TFW_HTTP_COND_IF_MSINCE)
		return T_DROP;
	if (cstate->is_set) {
		req->cond.m_date = cstate->if_msince_date;
		req->cond.flags |= TFW_HTTP_COND_IF_MSINCE;
	}
	return T_OK;
}

static int
__h2_req_parse_if_msince(TfwHttpMsg *msg, unsigned char *data, size_t len,
			 bool fin)
{
	int r = CSTR_NEQ;
	TfwHttpReq *req = (TfwHttpReq *)msg;
	TfwHttpParser *parser = &msg->stream->parser;

	/*
	 * RFC 7230 3.2.2:
	 *
	 * A sender MUST NOT generate multiple header fields with the same field
	 * name in a message unless either the entire field value for that
	 * header field is defined as a comma-separated list [i.e., #(values)]
	 * or the header field is a well-known exception.
	 */
	if (unlikely(req->cond.flags & TFW_HTTP_COND_IF_MSINCE))
		return r;

	/*
	 * RFC 7232 3.3:
	 *
	 * A recipient MUST ignore If-Modified-Since if the request contains an
	 * If-None-Match header field.
	 *
	 * A recipient MUST ignore the If-Modified-Since header field if the
	 * received field-value is not a valid HTTP-date, or if the request
	 * method is neither GET nor HEAD.
	 */
	if (unlikely(TFW_STR_EMPTY(&req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH])
		     && (req->method == TFW_HTTP_METH_HEAD
	        	 || req->method == TFW_HTTP_METH_GET))) {
		r = __h2_parse_http_date(msg, data, len, fin);
	}

	if (r < 0 && r != CSTR_POSTPONE) {
		/* On error just swallow the rest of the line. */
		parser->_date = 0;
		parser->_acc = 0;
		parser->_i_st = __I_EoL;
		r = __h2_parse_http_date(msg, data, len, fin);
	}

	if (r >= 0) {
		parser->cstate.is_set = 1;
		parser->cstate.if_msince_date = parser->_date;
		h2_set_hdr_if_mod_since(req, &parser->cstate);

		return CSTR_EQ;
	}

	return r;
}

static int
__h2_req_parse_pragma(TfwHttpMsg *hm, unsigned char *data, size_t len, bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_Pragma) {
		H2_TRY_STR_LAMBDA("no-cache", {
			msg->cache_ctl.flags |= TFW_HTTP_CC_PRAGMA_NO_CACHE;
			__FSM_EXIT(CSTR_EQ);
		}, I_Pragma, I_Pragma_NoCache);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Pragma_Ext);
	}

	__FSM_STATE(I_Pragma_NoCache) {
		if (IS_WS(c) || c == ',')
			msg->cache_ctl.flags |= TFW_HTTP_CC_PRAGMA_NO_CACHE;
		__FSM_I_JMP(I_Pragma_Ext);
	}

	__FSM_STATE(I_Pragma_Ext) {
		__FSM_H2_I_MATCH_MOVE(qetoken, I_Pragma_Ext);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_H2_I_MOVE_n(I_EoT, __fsm_sz + 1);
		return CSTR_NEQ;
	}

	__FSM_STATE(I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_H2_I_MOVE(I_EoT);
		__FSM_I_JMP(I_Pragma_Ext);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_pragma);

static int
__h2_req_parse_user_agent(TfwHttpMsg *hm, unsigned char *data, size_t len,
			  bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_UserAgent) {
		__FSM_H2_I_MATCH_MOVE(ctext_vchar, Req_I_UserAgent);
		return CSTR_NEQ;
	}
done:
	return r;
}

static int
__h2_req_parse_x_forwarded_for(TfwHttpMsg *hm, unsigned char *data, size_t len,
			       bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_XFF) {
		/* Eat OWS before the node ID. */
		if (unlikely(IS_WS(c)))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_XFF, 1, 0);
		/*
		 * Eat IP address or host name.
		 *
		 * TODO: parse/validate IP addresses and textual IDs.
		 * Currently we just validate separate characters, but the
		 * whole value may be invalid (e.g. "---[_..[[").
		 */
		__FSM_H2_I_MATCH_MOVE_fixup(xff, Req_I_XFF_Node_Id, TFW_STR_VALUE);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_H2_I_MOVE_fixup(Req_I_XFF_Sep, __fsm_sz, TFW_STR_VALUE);
	}

	/*
	 * At this state we know that we saw at least one character as
	 * a host address and now we can pass zero length token.
	 */
	__FSM_STATE(Req_I_XFF_Node_Id) {
		__FSM_H2_I_MATCH_MOVE_fixup(xff, Req_I_XFF_Node_Id, TFW_STR_VALUE);
		__msg_hdr_chunk_fixup(p, __fsm_sz);
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE | TFW_STR_VALUE);
		p += __fsm_sz;
		__FSM_I_JMP(Req_I_XFF_Sep);
	}

	__FSM_STATE(Req_I_XFF_Sep) {
		/* OWS before comma is unusual. */
		if (unlikely(IS_WS(c)))
			__FSM_H2_I_MOVE_fixup(Req_I_XFF_Sep, 1, 0);
		/*
		 * Multiple subsequent commas look suspicious, so we don't
		 * stay in this state after the first comma is met.
		 */
		if (likely(c == ','))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_XFF, 1, 0);

		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_x_forwarded_for);

static int
__h2_req_parse_te(TfwHttpMsg *hm, unsigned char *data, size_t len,
			       bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_Te) {
		H2_TRY_STR_LAMBDA("trailers", {
			__FSM_EXIT(CSTR_EQ);
		}, I_Te, done);
		TRY_STR_INIT();
	}
done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_te);

/**
 * Parse Forwarded header, RFC 7239.
 *
 * Defines logic to parse Forwarded header as set of unique pairs Param=Value
 * separated by semicolon. Also "Value" part can be in double quotes. Whole
 * field of header MUST be parsed. To have a handy way to process parsed string,
 * we can fixup these params as Key=Value. To achieve this we set flag
 * TFW_STR_NAME for "Param=" part and TFW_STR_VALUE for "Value" part. Semicolon
 * and quotes fixup without these flags.
 */
static int
__h2_req_parse_forwarded(TfwHttpMsg *hm, unsigned char *data, size_t len,
			 bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

/* List of flags used to mark parameters as parsed. */
#define FWD_SET_FOR			0x00000001
#define FWD_SET_HOST			0x00000002
#define FWD_SET_PROTO			0x00000004
#define FWD_SET_BY			0x00000008

/* See comments to __req_parse_forwarded() */

/* If last chunk of @parser->hdr is opened fixup it, otherwise do nothing. */
#define H2_FWD_FIXUP_CURR()						   \
do {									   \
	TfwStr *ch = TFW_STR_CURR(&parser->hdr);			   \
	if (TFW_STR_EMPTY(ch))						   \
		tfw_str_updlen(&parser->hdr, p + 1);			   \
} while(0)

/*
 * If last chunk of @parser->hdr is opened move by 1 to @to and fixup,
 * otherwise __FSM_I_MOVE_fixup.
 */
#define H2_FWD_MOVE_FIXUP_CURR(to, flag, ret)				   \
do {									   \
	TfwStr *ch = TFW_STR_CURR(&parser->hdr);			   \
	if (TFW_STR_EMPTY(ch)) {					   \
		p += 1;							   \
		parser->_i_st = &&to;					   \
		tfw_str_updlen(&parser->hdr, p);			   \
		if (unlikely(__data_off(p) >= len)) {			   \
			if(likely(fin))					   \
				__FSM_EXIT(ret);			   \
			__FSM_EXIT(TFW_POSTPONE);			   \
		}							   \
		goto to; 						   \
	}								   \
	__FSM_H2_I_MOVE_LAMBDA_fixup(to, 1, {				   \
		__FSM_EXIT(ret);					   \
	}, flag);							   \
} while (0)

/*
 * Allocate chunk and open it. Then inc @p and move to @to.
 * If data exhausted fixup current chunk.
 */
#define H2_FWD_MOVE_OPEN_CHUNK(to, flag, ret)				   \
do {									   \
	TfwStr *ch = tfw_str_add_compound(hm->pool, &parser->hdr);	   \
	if (!ch) { 							   \
		T_WARN("Cannot grow HTTP data string\n"); 		   \
		return CSTR_NEQ; 					   \
	} 								   \
	__msg_field_open(ch, p); 					   \
	__FSM_I_field_chunk_flags(ch, TFW_STR_HDR_VALUE | flag);	   \
	p += 1;								   \
	if (unlikely(__data_off(p) >= len)) {				   \
		if(likely(fin))						   \
			__FSM_EXIT(ret);				   \
		parser->_i_st = &&to;					   \
		tfw_str_updlen(&parser->hdr, p);			   \
		__FSM_EXIT(TFW_POSTPONE); 				   \
	} 								   \
	goto to; 							   \
} while (0)

/* Fixup current @p + n before postpone without bounds check. */
#define __FSM_H2_I_POSTPONE_fixup(to, n, lambda, flag) 			   \
do {									   \
	BUG_ON(!&parser->hdr.data);					   \
	BUG_ON(n < 0);							   \
	__msg_field_fixup_pos(&parser->hdr, p, n);			   \
	__FSM_I_field_chunk_flags(&parser->hdr, TFW_STR_HDR_VALUE | flag); \
	parser->_i_st = &&to;						   \
	if (fin) 							   \
		lambda;							   \
	__FSM_EXIT(TFW_POSTPONE);					   \
} while (0)

#define __FSM_H2_I_FWD_EQ_fixup(to, n, flag)				   \
	__FSM_H2_I_POSTPONE_fixup(to, n, {				   \
		__FSM_EXIT(CSTR_EQ);					   \
	}, flag)

#define __FSM_H2_I_FWD_NEQ_fixup(to, n, flag)				   \
	__FSM_H2_I_POSTPONE_fixup(to, n, {				   \
		__FSM_EXIT(CSTR_NEQ);					   \
	}, flag)

#define FWD_SET_FLAG(flag) parser->flags |= flag

/* 
 * Tries to find parameter in header.
 * Parsing fails if parameter not a unique in current header.
 *
 * RFC 7239 section 4: 
 * Each parameter MUST NOT occur more than once per field-value.
 */
#define H2_FWD_TRY_STR_NAME(name, curr_st, next_st, fw_flag)		   \
	H2_TRY_STR_FULL_MATCH_FIN_LAMBDA_fixup_name(&TFW_STR_STRING(name), \
						    &parser->hdr, {	   \
						    if (parser->flags	   \
							& fw_flag)	   \
							return CSTR_NEQ;   \
						     FWD_SET_FLAG(fw_flag);\
						    }, {		   \
						    __FSM_EXIT(CSTR_NEQ);  \
						    }, curr_st,		   \
						    next_st)

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_Fwd) {
		H2_FWD_TRY_STR_NAME("for=", Req_I_Fwd, Req_I_Fwd_For_Start,
				    FWD_SET_FOR);
		H2_FWD_TRY_STR_NAME("host=", Req_I_Fwd, Req_I_Fwd_Host_Start,
				    FWD_SET_HOST);
		H2_FWD_TRY_STR_NAME("proto=", Req_I_Fwd, Req_I_Fwd_Proto_Start,
				    FWD_SET_PROTO);
		H2_FWD_TRY_STR_NAME("by=", Req_I_Fwd, Req_I_Fwd_By_Start,
				    FWD_SET_BY);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_For_List) {
		/* Eat OWS before parameter. */
		if (unlikely(IS_WS(c)))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_For_List, 1, 0);
		/* Find next "for=" in list. */
		H2_FWD_TRY_STR_NAME("for=", Req_I_Fwd_For_List,
				    Req_I_Fwd_For_Start,
				    0);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_For_Start) {
		if (likely(c == '"'))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_For_Quoted, 1, 0);
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_For_Unquoted) {
		/*
		 * Eat IP address or host name.
		 *
		 * TODO: parse/validate IP addresses and textual IDs.
		 * Currently we just validate separate characters, but the
		 * whole value may be invalid (e.g. "---[_..[[").
		 */
		__FSM_H2_I_MATCH_MOVE_fixup(xff, Req_I_Fwd_For_Node_Id_Unquoted,
					    TFW_STR_VALUE);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_H2_I_MOVE_fixup(Req_I_Fwd_For_Sep, __fsm_sz,
				      TFW_STR_VALUE);
	}

	/*
	 * At this state we know that we saw at least one character as
	 * a host address and now we can pass zero length token.
	 */
	__FSM_STATE(Req_I_Fwd_For_Node_Id_Unquoted) {
		__FSM_H2_I_MATCH_MOVE_fixup(xff, Req_I_Fwd_For_Node_Id_Unquoted,
					    TFW_STR_VALUE);
		__FSM_H2_I_MOVE_fixup(Req_I_Fwd_For_Sep, __fsm_sz,
				      TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_For_Quoted) {
		__FSM_H2_I_MATCH_MOVE_NEQ_fixup(xff,
						Req_I_Fwd_For_Node_Id_Quoted,
						TFW_STR_VALUE);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_H2_I_MOVE_fixup(Req_I_Fwd_For_Sep_Quoted, __fsm_sz,
				      TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_For_Node_Id_Quoted) {
		__FSM_H2_I_MATCH_MOVE_NEQ_fixup(xff,
						Req_I_Fwd_For_Node_Id_Quoted,
						TFW_STR_VALUE);
		__FSM_H2_I_MOVE_fixup(Req_I_Fwd_For_Sep_Quoted, __fsm_sz,
				      TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_For_Sep_Quoted) {
		if (unlikely(c != '"'))
			return CSTR_NEQ;
		H2_FWD_MOVE_OPEN_CHUNK(Req_I_Fwd_For_Sep_Quoted_N, 0, CSTR_EQ);
	}

	__FSM_STATE(Req_I_Fwd_For_Sep_Quoted_N) {
		/* At this point we try to fixup '"' with near symbol. */

		/* ';' after quote */
		if (likely(c == ';'))
			H2_FWD_MOVE_FIXUP_CURR(Req_I_Fwd, 0, CSTR_NEQ);
		/* ',' after quote */
		if (unlikely(c == ','))
			H2_FWD_MOVE_FIXUP_CURR(Req_I_Fwd_For_List, 0, CSTR_NEQ);
		/* WS after quote */
		if (unlikely(IS_WS(c)))
			H2_FWD_MOVE_FIXUP_CURR(Req_I_Fwd_For_Sep_End, 0,
					       CSTR_EQ);

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_For_Sep) {
		/* go to next param */
		if (likely(c == ';'))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd, 1, 0);
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_For_Sep_End) {
		/*
		 * "for=" can be represented as comma
		 * separated list, find next one.
		 */
		if (unlikely(c == ','))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_For_List, 1, 0);
	        /* OWS before comma or before EOL (is unusual). */
		if (unlikely(IS_WS(c)))
			__FSM_H2_I_MOVE_fixup(Req_I_Fwd_For_Sep_End, 1, 0);

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_Host_Start) {
		if (likely(c == '"'))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_Host_Start_Quoted,
						  1, 0);
		/* Fall through */
	}

	/* Parse host parameter as defined in RFC 7230 5.4. */
	__FSM_STATE(Req_I_Fwd_Host_Unquoted) {
		__fsm_sz = 0;

		while (likely(isalnum(c) || c == '.' || c == '-')) {
			__fsm_sz++;
			c = *(p + __fsm_sz);
			if (unlikely(__data_off(p + __fsm_sz) >= len))
				__FSM_H2_I_FWD_EQ_fixup(Req_I_Fwd_Host_Unquoted,
						        __fsm_sz,
						        TFW_STR_VALUE);
		}
		__FSM_H2_I_MOVE_fixup(Req_I_Fwd_Host_End_Unquoted, __fsm_sz,
				      TFW_STR_VALUE);
	}

	/*
	 * Quoted version of parse host, this implies we must have been already
	 * fixed up dquote without flags in previous state.
	 */
	__FSM_STATE(Req_I_Fwd_Host_Start_Quoted) {
		if (likely(c == '['))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_H_v6_Quoted_Start,
						  1, TFW_STR_VALUE);
		/* Block empty quotes */
		if (unlikely(c == '"'))
			return CSTR_NEQ;
		/* Fall through */
	}

	/* Parse host parameter as defined in RFC 7230 5.4. */
	__FSM_STATE(Req_I_Fwd_Host_Quoted) {
		__fsm_sz = 0;

		while (likely(isalnum(c) || c == '.' || c == '-')) {
			__fsm_sz++;
			c = *(p + __fsm_sz);
			if (unlikely(__data_off(p + __fsm_sz) >= len))
				__FSM_H2_I_FWD_NEQ_fixup(Req_I_Fwd_Host_Quoted,
							 __fsm_sz,
						         TFW_STR_VALUE);
		}
		__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_Host_End_Quoted, __fsm_sz,
					  TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_H_v6_Quoted_Start) {
		/* Block empty braces */
		if (unlikely(c == ']'))
			return CSTR_NEQ;
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_H_v6_Quoted) {
		__fsm_sz = 0;

		while (likely(isxdigit(c) || c == ':')) {
			__fsm_sz++;
			c = *(p + __fsm_sz);
			if (unlikely(__data_off(p + __fsm_sz) >= len))
				__FSM_H2_I_FWD_NEQ_fixup(Req_I_Fwd_H_v6_Quoted,
							 __fsm_sz,
						         TFW_STR_VALUE);
		}
		if (likely(c == ']'))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_Host_End_Quoted,
						  __fsm_sz + 1, TFW_STR_VALUE);

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_Host_End_Quoted) {
		if (c == ':')
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_Host_Port_Quoted,
						  1, 0);
		__FSM_I_JMP(Req_I_Fwd_Next_Or_End_Quoted);
	}

	__FSM_STATE(Req_I_Fwd_Host_End_Unquoted) {
		if (c == ':')
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_Host_Port_Unquoted,
						  1, 0);
		__FSM_I_JMP(Req_I_Fwd_Next_Or_Finish);
	}

	__FSM_STATE(Req_I_Fwd_Host_Port_Unquoted) {
		__fsm_sz = __data_remain(p);
		__fsm_n = __parse_ulong_ws_delim(p, __fsm_sz,
						 (unsigned long*)&parser->port,
						 USHRT_MAX);
		switch (__fsm_n) {
		case CSTR_BADLEN:
		case CSTR_NEQ:
			return CSTR_NEQ;
		case CSTR_POSTPONE:
			if (parser->port == 0 || parser->port > 65535)
				return CSTR_NEQ;
			__FSM_H2_I_MOVE_fixup(Req_I_Fwd_Host_Port_Unquoted,
					      __fsm_sz, TFW_STR_VALUE);
		default:
			if (parser->port == 0 || parser->port > 65535)
				return CSTR_NEQ;
			__FSM_H2_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish, __fsm_n,
					      TFW_STR_VALUE);
		}

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_Host_Port_Quoted) {
		__fsm_sz = __data_remain(p);
		__fsm_n = __parse_ulong_ws_delim(p, __fsm_sz,
						 (unsigned long*)&parser->port,
						 USHRT_MAX);
		switch (__fsm_n) {
		case CSTR_BADLEN:
		case CSTR_NEQ:
			return CSTR_NEQ;
		case CSTR_POSTPONE:
			if (parser->port == 0 || parser->port > 65535)
				return CSTR_NEQ;
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_Host_Port_Quoted,
						  __fsm_sz, TFW_STR_VALUE);
		default:
			if (parser->port == 0 || parser->port > 65535)
				return CSTR_NEQ;
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_Next_Or_End_Quoted,
						  __fsm_n,
						  TFW_STR_VALUE);
		}

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_Proto_Start) {
		if (likely(c == '"'))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_Proto_Quoted_Start,
						  1, 0);
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_Pto_Unquoted) {
		/* RFC 3986: 3.1 list of allowed characters */
		__fsm_sz = 0;

		while (likely(isalnum(c) || c == '+' || c == '-' || c == '.')) {
			__fsm_sz++;
			c = *(p + __fsm_sz);
			if (unlikely(__data_off(p + __fsm_sz) >= len))
				__FSM_H2_I_FWD_EQ_fixup(Req_I_Fwd_Pto_Unquoted,
						        __fsm_sz,
						        TFW_STR_VALUE);
		}
		__FSM_H2_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish, __fsm_sz,
				      TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_Proto_Quoted_Start) {
		/* Block empty quotes */
		if (unlikely(c == '"'))
			return CSTR_NEQ;
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_Proto_Quoted) {
		/* RFC 3986: 3.1 list of allowed characters */
		__fsm_sz = 0;

		while (likely(isalnum(c) || c == '+' || c == '-' || c == '.')) {
			__fsm_sz++;
			c = *(p + __fsm_sz);
			if (unlikely(__data_off(p + __fsm_sz) >= len))
				__FSM_H2_I_FWD_NEQ_fixup(Req_I_Fwd_Proto_Quoted,
							 __fsm_sz,
							 TFW_STR_VALUE);
		}
		__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_Next_Or_End_Quoted,
					  __fsm_sz, TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_By_Start) {
		if (likely(c == '"'))
			__FSM_H2_I_MOVE_NEQ_fixup(Req_I_Fwd_By_Quoted, 1, 0);
		/* Fall through */
	}

	__FSM_STATE(Req_I_Fwd_By_Unquoted) {
		__FSM_H2_I_MATCH_MOVE_fixup(xff, Req_I_Fwd_By_Node_Id_Unquoted,
					    TFW_STR_VALUE);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_H2_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish, __fsm_sz,
				      TFW_STR_VALUE);
	}

	/*
	 * At this state we know that we saw at least one character as
	 * a host address and now we can pass zero length token.
	 */
	__FSM_STATE(Req_I_Fwd_By_Node_Id_Unquoted) {
		__FSM_H2_I_MATCH_MOVE_fixup(xff, Req_I_Fwd_By_Node_Id_Unquoted,
					    TFW_STR_VALUE);
		__FSM_H2_I_MOVE_fixup(Req_I_Fwd_Next_Or_Finish, __fsm_sz,
				      TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_By_Quoted) {
		__FSM_H2_I_MATCH_MOVE_NEQ_fixup(xff,
						Req_I_Fwd_By_Node_Id_Quoted,
						TFW_STR_VALUE);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_H2_I_MOVE_fixup(Req_I_Fwd_Next_Or_End_Quoted, __fsm_sz,
				      TFW_STR_VALUE);
	}

	/*
	 * At this state we know that we saw at least one character as
	 * a host address and now we can pass zero length token.
	 */
	__FSM_STATE(Req_I_Fwd_By_Node_Id_Quoted) {
		__FSM_H2_I_MATCH_MOVE_NEQ_fixup(xff,
						Req_I_Fwd_By_Node_Id_Quoted,
						TFW_STR_VALUE);
		__FSM_H2_I_MOVE_fixup(Req_I_Fwd_Next_Or_End_Quoted, __fsm_sz,
				      TFW_STR_VALUE);
	}

	__FSM_STATE(Req_I_Fwd_Next_Or_Finish) {
		if (likely(c == ';'))
			H2_FWD_MOVE_FIXUP_CURR(Req_I_Fwd, 0, CSTR_NEQ);

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_Fwd_Next_Or_End_Quoted) {
		if (unlikely(c != '"'))
			return CSTR_NEQ;
		H2_FWD_MOVE_OPEN_CHUNK(Req_I_Fwd_Next_Or_Finish, 0, CSTR_EQ);

		return CSTR_NEQ;
	}

done:
	return r;

#undef FWD_SET_FOR
#undef FWD_SET_HOST
#undef FWD_SET_PROTO
#undef FWD_SET_BY
#undef H2_FWD_FIXUP_CURR
#undef H2_FWD_MOVE_FIXUP_CURR
#undef H2_FWD_MOVE_OPEN_CHUNK
#undef __FSM_H2_I_POSTPONE_fixup
#undef __FSM_H2_I_FWD_EQ_fixup
#undef __FSM_H2_I_FWD_NEQ_fixup
#undef FWD_SET_FLAG
#undef H2_FWD_TRY_STR_NAME
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_forwarded);

/* Parse method override request headers. */
static int
__h2_req_parse_m_override(TfwHttpReq *req, unsigned char *data, size_t len,
			  bool fin)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(I_Meth_Start) {
		switch (TFW_LC(c)) {
		case 'c':
			__FSM_I_JMP(I_Meth_C);
		case 'd':
			__FSM_I_JMP(I_Meth_D);
		case 'g':
			__FSM_I_JMP(I_Meth_G);
		case 'h':
			__FSM_I_JMP(I_Meth_H);
		case 'l':
			__FSM_I_JMP(I_Meth_L);
		case 'm':
			__FSM_I_JMP(I_Meth_M);
		case 'o':
			__FSM_I_JMP(I_Meth_O);
		case 'p':
			__FSM_I_JMP(I_Meth_P);
		case 't':
			__FSM_I_JMP(I_Meth_T);
		case 'u':
			__FSM_I_JMP(I_Meth_U);
		}
		__FSM_I_MOVE(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_C) {
		H2_TRY_STR_LAMBDA("copy", {
			req->method_override = TFW_HTTP_METH_COPY;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_C, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_D) {
		H2_TRY_STR_LAMBDA("delete", {
			req->method_override = TFW_HTTP_METH_DELETE;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_D, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_G) {
		H2_TRY_STR_LAMBDA("get", {
			req->method_override = TFW_HTTP_METH_GET;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_G, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_H) {
		H2_TRY_STR_LAMBDA("head", {
			req->method_override = TFW_HTTP_METH_HEAD;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_H, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_L) {
		H2_TRY_STR_LAMBDA("lock", {
			req->method_override = TFW_HTTP_METH_LOCK;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_L, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_M) {
		H2_TRY_STR_LAMBDA("mkcol", {
			req->method_override = TFW_HTTP_METH_MKCOL;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_M, I_EoT);
		H2_TRY_STR_LAMBDA("move", {
			req->method_override = TFW_HTTP_METH_MOVE;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_M, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_O) {
		H2_TRY_STR_LAMBDA("options", {
			req->method_override = TFW_HTTP_METH_OPTIONS;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_O, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_P) {
		H2_TRY_STR_LAMBDA("patch", {
			req->method_override = TFW_HTTP_METH_PATCH;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_P, I_EoT);
		H2_TRY_STR_LAMBDA("post", {
			req->method_override = TFW_HTTP_METH_POST;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_P, I_EoT);
		H2_TRY_STR_LAMBDA("propfind", {
			req->method_override = TFW_HTTP_METH_PROPFIND;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_P, I_EoT);
		H2_TRY_STR_LAMBDA("proppatch", {
			req->method_override = TFW_HTTP_METH_PROPPATCH;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_P, I_EoT);
		H2_TRY_STR_LAMBDA("put", {
			req->method_override = TFW_HTTP_METH_PUT;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_P, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_T) {
		H2_TRY_STR_LAMBDA("trace", {
			req->method_override = TFW_HTTP_METH_TRACE;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_T, I_EoT);
		TRY_STR_INIT();
	}

	__FSM_STATE(I_Meth_U) {
		H2_TRY_STR_LAMBDA("unlock", {
			req->method_override = TFW_HTTP_METH_UNLOCK;
			__FSM_EXIT(CSTR_EQ);
		} , I_Meth_U, I_EoT);
		TRY_STR_INIT();
		__FSM_I_JMP(I_Meth_Unknown);
	}

	__FSM_STATE(I_Meth_Unknown) {
		__FSM_I_MATCH_MOVE_finish(token, I_Meth_Unknown, {
			if (likely(fin))
				break;
		});
		req->method_override = _TFW_HTTP_METH_UNKNOWN;
		__FSM_H2_I_MOVE_n(I_EoT, __fsm_sz);
	}

	__FSM_STATE(I_EoT) {
		if (IS_TOKEN(c))
			__FSM_I_JMP(I_Meth_Unknown);
		if (IS_WS(c))
			__FSM_H2_I_MOVE(I_EoT);
		return CSTR_NEQ;
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_m_override);

/**
 * Parse Tempesta FW session redirection mark in URI into req->mark or
 * normal URI path to parser->hdr.
 */
static int
__h2_req_parse_mark(TfwHttpReq *req, unsigned char *data, size_t len, bool fin)
{
	const TfwStr *str;
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st);

	__FSM_STATE(Req_I_UriMarkStart) {
		if (WARN_ON_ONCE(c != '/'))
			__FSM_EXIT(CSTR_NEQ);

		__msg_field_open(&req->mark, p);
		/* Place initial slash into separate chunk. */
		__FSM_H2_I_MOVE_LAMBDA_fixup_f(Req_I_UriMarkName, 1, &req->mark,
		{
			/*
			 * The end of ':path' header has been met; thus, we can
			 * just go out, and the parsed '/' will be fixed up in
			 * the outside state Req_Path after returning.
			 */
			TFW_STR_INIT(&req->mark);
			return 0;
		}, 0);
	}

	__FSM_STATE(Req_I_UriMarkName) {
		/*
		 * Lookup for Tempesta FW URI marker.
		 * If there is no such marker, then there is zero matching and
		 * p remains the same. However a valid URI may have the same
		 * prefix with the Tempesta FW marker. In this case we move the
		 * whole matching perfix to parser->hdr.
		 */
		str = tfw_http_sess_mark_name();
		H2_TRY_STR_FULL_MATCH_FIN_LAMBDA_fixup(str, &req->mark, {
			parser->to_read = tfw_http_sess_mark_size();
		}, {
			/*
			 * __try_str() in H2_TRY_STR_FULL_MATCH_FIN_LAMBDA_fixup()
			 * didn't find a match, i.e. returned CSTR_NEQ.
			 */
			__FSM_EXIT(CSTR_NEQ);
		}, Req_I_UriMarkName, Req_I_UriMarkValue);
		/*
		 * In case of HTTP/2 processing we need not set @req->uri_path
		 * here; instead, the value of ':path' pseudo-header in
		 * @req->h_tbl (currently @parser->hdr) is used. If mark isn't
		 * matched here, concatenate descriptors accumulated in
		 * @req->mark with the descriptor of ':path' pseudo-header
		 * (that is @parser->hdr) - the latter will be finished in the
		 * 'Req_Path' state. Note, that if we are here, we must not be
		 * postponed in the outside state after returning.
		 */
		if (tfw_strcat(req->pool, &parser->hdr, &req->mark))
			__FSM_EXIT(CSTR_NEQ);

		TFW_STR_INIT(&req->mark);
		return __data_off(p);
	}

	__FSM_STATE(Req_I_UriMarkValue) {
		__fsm_n = min_t(long, parser->to_read, __data_remain(p));
		parser->to_read -= __fsm_n;
		if (parser->to_read) {
			if (fin)
				__FSM_EXIT(CSTR_NEQ);
			__msg_field_fixup_pos(&req->mark, p, __fsm_n);
			__FSM_I_field_chunk_flags(&req->mark, TFW_STR_VALUE);
			parser->_i_st = &&Req_I_UriMarkValue;
			__FSM_EXIT(CSTR_POSTPONE);
		}
		parser->to_read = -1;
		__msg_field_finish_pos(&req->mark, p, __fsm_n);
		__FSM_I_field_chunk_flags(&req->mark, TFW_STR_VALUE);
		return __data_off(p + __fsm_n);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__h2_req_parse_mark);

int
tfw_h2_parse_req_hdr(unsigned char *data, unsigned long len, TfwHttpReq *req,
		     bool fin, bool value_stage)
{
	int ret = T_OK;
	TfwMsgParseIter *it = &req->pit;
	__FSM_DECLARE_VARS(req);

	T_DBG("%s: fin=%d, len=%lu, data=%.*s%s, req=[%p]\n", __func__, fin, len,
	      min(500, (int)len), data, len > 500 ? "..." : "", req);

	__FSM_START(parser->state);

	/*
	 * If next state is not defined here, that means the name has not been
	 * parsed and is indexed, thus we should determine the state from the
	 * header tag.
	 */
	__FSM_H2_REQ_NEXT_STATE(value_stage);

	/* ----------------    (Pseudo-)headers name    ---------------- */

	__FSM_STATE(RGen_Hdr, hot) {

		tfw_http_msg_hdr_open(msg, p);

		/* Ensure we have enough data for largest match. */
		if (unlikely(!__data_available(p, 4)))
			__FSM_JMP(Req_Hdr);
		/*
		 * Some successful matches cause drop action instead of move:
		 * - All allowed pseudo headers are listed here, no need to
		 *   fallback to slow path on partial matches.
		 * - RFC 7540 Section 8.1.2.2: Messages with connection-specific
		 *   headers must be treated as malformed.
		 */

		switch (PI(p)) {

		/* :authority */
		case TFW_CHAR4_INT(':', 'a', 'u', 't'):
			if (unlikely(!__data_available(p, 10)))
				__FSM_H2_NEXT_n(Req_HdrPsAut, 4);
			if (C8_INT(p + 2, 'u', 't', 'h', 'o', 'r', 'i', 't', 'y'))
				__FSM_H2_FIN(Req_HdrPsAuthorityV, 10,
					     TFW_TAG_HDR_H2_AUTHORITY);
			__FSM_H2_DROP(RGen_Hdr);
		/* :method */
		case TFW_CHAR4_INT(':', 'm', 'e', 't'):
			if (unlikely(!__data_available(p, 7)))
				__FSM_H2_NEXT_n(Req_HdrPsMet, 4);
			if (C4_INT(p + 3, 't', 'h', 'o', 'd'))
				__FSM_H2_FIN(Req_HdrPsMethodV, 7,
					     TFW_TAG_HDR_H2_METHOD);
			__FSM_H2_DROP(RGen_Hdr);
		/* :scheme */
		case TFW_CHAR4_INT(':', 's', 'c', 'h'):
			if (unlikely(!__data_available(p, 7)))
				__FSM_H2_NEXT_n(Req_HdrPsSch, 4);
			if (C4_INT(p + 3, 'h', 'e', 'm', 'e'))
				__FSM_H2_FIN(Req_HdrPsSchemeV, 7,
					     TFW_TAG_HDR_H2_SCHEME);
			__FSM_H2_DROP(RGen_Hdr);
		/* :path */
		case TFW_CHAR4_INT(':', 'p', 'a', 't'):
			if (unlikely(!__data_available(p, 5)))
				__FSM_H2_NEXT_n(Req_HdrPsPat, 4);
			if (*(p + 4) == 'h')
				__FSM_H2_FIN(Req_HdrPsPathV, 5,
					     TFW_TAG_HDR_H2_PATH);
			__FSM_H2_DROP(RGen_Hdr);
		/* accept */
		case TFW_CHAR4_INT('a', 'c', 'c', 'e'):
			if (unlikely(!__data_available(p, 6)))
				__FSM_H2_NEXT_n(Req_HdrAcce, 4);
			if (C4_INT(p + 2, 'c', 'e', 'p', 't'))
				__FSM_H2_FIN(Req_HdrAcceptV, 6,
					     TFW_TAG_HDR_ACCEPT);
			__FSM_H2_OTHER_n(4);
		/* authorization */
		case TFW_CHAR4_INT('a', 'u', 't', 'h'):
			if (unlikely(!__data_available(p, 13)))
				__FSM_H2_NEXT_n(Req_HdrAuth, 4);
			if(C8_INT(p + 4, 'o', 'r', 'i', 'z', 'a', 't', 'i', 'o')
			   && *(p + 12) == 'n')
			{
				__FSM_H2_FIN(Req_HdrAuthorizationV, 13,
					     TFW_TAG_HDR_AUTHORIZATION);
			}
			__FSM_H2_OTHER_n(4);
		/* cache-control */
		case TFW_CHAR4_INT('c', 'a', 'c', 'h'):
			if (unlikely(!__data_available(p, 13)))
				__FSM_H2_NEXT_n(Req_HdrCach, 4);
			if (C8_INT(p + 4, 'e', '-', 'c', 'o', 'n', 't', 'r', 'o')
			    &&  *(p + 12) == 'l')
			{
				__FSM_H2_FIN(Req_HdrCache_ControlV, 13,
					     TFW_TAG_HDR_CACHE_CONTROL);
			}
			__FSM_H2_OTHER_n(4);
		/* connection */
		case TFW_CHAR4_INT('c', 'o', 'n', 'n'):
			if (unlikely(!__data_available(p, 10)))
				__FSM_H2_NEXT_n(Req_HdrConn, 4);
			if (C8_INT(p + 2, 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n'))
				__FSM_H2_DROP(Req_HdrConnection);
			__FSM_H2_OTHER_n(4);
		/* content-* */
		case TFW_CHAR4_INT('c', 'o', 'n', 't'):
			if (unlikely(!__data_available(p, 14)))
				__FSM_H2_NEXT_n(Req_HdrCont, 4);
			if (C8_INT(p + 4, 'e', 'n', 't', '-', 't', 'y', 'p', 'e'))
				__FSM_H2_FIN(Req_HdrContent_TypeV, 12,
					     TFW_TAG_HDR_CONTENT_TYPE);
			if (C8_INT(p + 4, 'e', 'n', 't', '-', 'e', 'n', 'c', 'o')
			    && C4_INT(p + 12,  'd', 'i', 'n', 'g'))
				__FSM_H2_FIN(Req_HdrContent_EncodingV, 16,
					     TFW_TAG_HDR_CONTENT_ENCODING);
			if (C8_INT(p + 4, 'e', 'n', 't', '-', 'l', 'e', 'n', 'g')
			    && C4_INT(p + 10,  'n', 'g', 't', 'h'))
				__FSM_H2_FIN(Req_HdrContent_LengthV, 14,
					     TFW_TAG_HDR_CONTENT_LENGTH);
			__FSM_H2_OTHER_n(4);
		/* cookie */
		case TFW_CHAR4_INT('c', 'o', 'o', 'k'):
			if (unlikely(!__data_available(p, 6)))
				__FSM_H2_NEXT_n(Req_HdrCook, 4);
			if (C4_INT(p + 2, 'o', 'k', 'i', 'e'))
				__FSM_H2_FIN(Req_HdrCookieV, 6,
					     TFW_TAG_HDR_COOKIE);
			__FSM_H2_OTHER_n(4);
		/* forwarded */
		case TFW_CHAR4_INT('f', 'o', 'r', 'w'):
			if (unlikely(!__data_available(p, 9)))
				__FSM_H2_NEXT_n(Req_HdrX_Fo, 4);
			if (C4_INT(p + 4,  'a', 'r', 'd', 'e')
			    && *(p + 8) == 'd')
			{
				__FSM_H2_FIN(Req_HdrForwardedV, 9,
					     TFW_TAG_HDR_FORWARDED);
			}
			__FSM_H2_OTHER_n(4);
		/* host */
		case TFW_CHAR4_INT('h', 'o', 's', 't'):
			__FSM_H2_FIN(Req_HdrHostV, 4, TFW_TAG_HDR_HOST);
		/* if-modified-since */
		case TFW_CHAR4_INT('i', 'f', '-', 'm'):
			if (unlikely(!__data_available(p, 17)))
				__FSM_H2_NEXT_n(Req_HdrIf_M, 4);
			if (C8_INT(p + 4, 'o', 'd', 'i', 'f', 'i', 'e', 'd', '-')
			    && C8_INT(p + 9, 'e', 'd', '-', 's', 'i', 'n', 'c',
				      'e'))
			{
				__FSM_H2_FIN(Req_HdrIf_Modified_SinceV, 17,
					     TFW_TAG_HDR_IF_MODIFIED_SINCE);
			}
			__FSM_H2_OTHER_n(4);
		/* if-none-match */
		case TFW_CHAR4_INT('i', 'f', '-', 'n'):
			if (unlikely(!__data_available(p, 13)))
				__FSM_H2_NEXT_n(Req_HdrIf_N, 4);
			if (C8_INT(p + 4, 'o', 'n', 'e', '-', 'm', 'a', 't', 'c')
			    && *(p + 12) == 'h')
			{
				__FSM_H2_FIN(Req_HdrIf_None_MatchV, 13,
					     TFW_TAG_HDR_IF_NONE_MATCH);
			}
			__FSM_H2_OTHER_n(4);
		/* keep-alive */
		case TFW_CHAR4_INT('k', 'e', 'e', 'p'):
			if (unlikely(!__data_available(p, 10)))
				__FSM_H2_NEXT_n(Req_HdrKeep, 4);
			if (C8_INT(p + 2, 'e', 'p', '-', 'a', 'l', 'i', 'v', 'e'))
				__FSM_H2_DROP(Req_HdrKeep_Alive);
			__FSM_H2_OTHER_n(4);
		/* pragma */
		case TFW_CHAR4_INT('p', 'r', 'a', 'g'):
			if (unlikely(!__data_available(p, 6)))
				__FSM_H2_NEXT_n(Req_HdrPrag, 4);
			if (C4_INT(p + 2, 'a', 'g', 'm', 'a'))
				__FSM_H2_FIN(Req_HdrPragmaV, 6,
					     TFW_TAG_HDR_PRAGMA);
			__FSM_H2_OTHER_n(4);
		/* proxy-connection */
		case TFW_CHAR4_INT('p', 'r', 'o', 'x'):
			if (unlikely(!__data_available(p, 16)))
				__FSM_H2_DROP(Req_HdrProxyConnection);
			if (C8_INT(p + 4, 'y', '-', 'c', 'o', 'n', 'n', 'e', 'c')
			    || C4_INT(p + 12, 't', 'i', 'o', 'n'))
				__FSM_H2_DROP(Req_HdrProxyConnection);
			__FSM_H2_OTHER_n(4);
		/* transfer-encoding */
		case TFW_CHAR4_INT('t', 'r', 'a', 'n'):
			if (unlikely(!__data_available(p, 17)))
				__FSM_H2_NEXT_n(Req_HdrTran, 4);
			if (C8_INT(p + 1,  'r', 'a', 'n', 's', 'f', 'e', 'r', '-')
			    &&  C8_INT(p + 9, 'e', 'n', 'c', 'o', 'd', 'i', 'n',
				       'g'))
			{
				__FSM_H2_DROP(Req_HdrTransfer_Encoding);
			}
			__FSM_H2_OTHER_n(4);
		/* referer */
		case TFW_CHAR4_INT('r', 'e', 'f', 'e'):
			if (unlikely(!__data_available(p, 7)))
				__FSM_H2_NEXT_n(Req_HdrRefe, 4);
			if (C4_INT(p + 3, 'e', 'r', 'e', 'r'))
				__FSM_H2_FIN(Req_HdrRefererV, 7,
					     TFW_TAG_HDR_REFERER);
			__FSM_H2_OTHER_n(4);
		/* user-agent */
		case TFW_CHAR4_INT('u', 's', 'e', 'r'):
			if (unlikely(!__data_available(p, 10)))
				__FSM_H2_NEXT_n(Req_HdrUser, 4);
			if (C8_INT(p + 2, 'e', 'r', '-', 'a', 'g', 'e', 'n', 't'))
				__FSM_H2_FIN(Req_HdrUser_AgentV, 10,
					     TFW_TAG_HDR_USER_AGENT);
			__FSM_H2_OTHER_n(4);
		/* upgrade */
		case TFW_CHAR4_INT('u', 'p', 'g', 'r'):
			if (unlikely(!__data_available(p, 7)))
				__FSM_H2_NEXT_n(Req_HdrUpgr, 4);
			if (C4_INT(p + 3, 'r', 'a', 'd', 'e'))
				__FSM_H2_DROP(Req_HdrUpgrade);
			__FSM_H2_OTHER_n(4);
		/* x-forwarded-for */
		case TFW_CHAR4_INT('x', '-', 'f', 'o'):
			if (unlikely(!__data_available(p, 15)))
				__FSM_H2_NEXT_n(Req_HdrX_Fo, 4);
			if (C8_INT(p + 4, 'r', 'w', 'a', 'r', 'd', 'e', 'd', '-')
			    && C4_INT(p + 11,  '-', 'f', 'o', 'r'))
			{
				__FSM_H2_FIN(Req_HdrX_Forwarded_ForV, 15,
					     TFW_TAG_HDR_X_FORWARDED_FOR);
			}
			__FSM_H2_OTHER_n(4);
		/* x-method-override family. */
		case TFW_CHAR4_INT('x', '-', 'h', 't'):
			if (unlikely(!__data_available(p, 22)))
				__FSM_H2_NEXT_n(Req_HdrX_Ht, 4);
			if (C8_INT(p + 4, 't', 'p', '-', 'm', 'e', 't', 'h', 'o')
			    && C8_INT(p + 12, 'd', '-', 'o', 'v','e', 'r', 'r',
				      'i')
			    && C4_INT(p + 18, 'r', 'i', 'd', 'e'))
			{
				__FSM_H2_FIN(Req_HdrX_Method_OverrideV, 22,
					     TFW_TAG_HDR_RAW);
			}
			if (C8_INT(p + 4, 't', 'p', '-', 'm', 'e', 't', 'h', 'o')
			    && *(p + 12) == 'd')
			{
				__FSM_H2_FIN(Req_HdrX_Method_OverrideV, 13,
					     TFW_TAG_HDR_RAW);
			}
			__FSM_H2_OTHER_n(4);
		case TFW_CHAR4_INT('x', '-', 'm', 'e'):
			if (unlikely(!__data_available(p, 17)))
				__FSM_H2_NEXT_n(Req_HdrX_Me, 4);
			if (C8_INT(p + 4, 't', 'h', 'o', 'd', '-', 'o', 'v', 'e')
			    &&  C8_INT(p + 9, 'o', 'v', 'e', 'r', 'r', 'i', 'd',
				       'e'))
			{
				__FSM_H2_FIN(Req_HdrX_Method_OverrideV, 17,
					     TFW_TAG_HDR_RAW);
			}
			__FSM_H2_OTHER_n(4);

		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	__FSM_STATE(RGen_HdrOtherN) {
		__fsm_n = __data_remain(p);
		/*
		 * TODO: RFC 7540, Section 8.1.2:
		 * A request or response containing uppercase header field
		 * names MUST be treated as malformed.
		 * We should use here lower-case matching function.
		 */
		__fsm_sz = tfw_match_token(p, __fsm_n);
		if (unlikely(__fsm_sz != __fsm_n))
			__FSM_H2_DROP(RGen_HdrOtherN);
		/*
		 * Use (data, len) instead of (p, __fsm_n) since we moved p in
		 * previous states trying known header names.
		 */
		__msg_hdr_chunk_fixup(data, len);
		if (unlikely(!fin))
			__FSM_H2_POSTPONE(RGen_HdrOtherN);
		it->tag = TFW_TAG_HDR_RAW;
		__FSM_H2_OK(RGen_HdrOtherV);
	}

	/* ----------------    Pseudo-header values    ---------------- */

	__FSM_STATE(Req_HdrPsMethodV, hot) {
		if (!H2_MSG_VERIFY(TFW_HTTP_HDR_H2_METHOD))
			__FSM_H2_DROP(Req_HdrPsMethodV);

		parser->_hdr_tag = TFW_HTTP_HDR_H2_METHOD;
		if (likely(__data_available(p, 3)
			   && *p == 'G'
			   && *(p + 1) == 'E'
			   && *(p + 2) == 'T'))
		{
			__FSM_H2_METHOD_COMPLETE(Req_HdrPsMethodV, 3,
						 TFW_HTTP_METH_GET);
		}
		if (likely(__data_available(p, 4)
			   && PI(p) == TFW_CHAR4_INT('P', 'O', 'S', 'T')))
		{
			__FSM_H2_METHOD_COMPLETE(Req_HdrPsMethodV, 4,
						 TFW_HTTP_METH_POST);
		}
		__FSM_JMP(Req_RareMethods_3);
	}

	__FSM_STATE(Req_HdrPsSchemeV, hot) {
		if (!H2_MSG_VERIFY(TFW_HTTP_HDR_H2_SCHEME))
			__FSM_H2_DROP(Req_HdrPsSchemeV);

		parser->_hdr_tag = TFW_HTTP_HDR_H2_SCHEME;
		if (likely(__data_available(p, 5)
			   && C4_INT_LCM(p, 'h', 't', 't', 'p')
			   && TFW_LC(*(p + 4)) == 's'))
		{
			__FSM_H2_PSHDR_COMPLETE(Req_HdrPsSchemeV, 5);
		}
		__FSM_JMP(Req_Scheme_1CharStep);
	}

	__FSM_STATE(Req_HdrPsPathV, hot) {
		if (!H2_MSG_VERIFY(TFW_HTTP_HDR_H2_PATH))
			__FSM_H2_DROP(Req_HdrPsPathV);

		parser->_hdr_tag = TFW_HTTP_HDR_H2_PATH;
		if (likely(c == '/'))
			__FSM_JMP(Req_Mark);

		if (unlikely(c == '*')) {
			__FSM_H2_PSHDR_CHECK_lambda(p + 1, {
				if ((req->method
				     && req->method != TFW_HTTP_METH_OPTIONS)
				    || !fin)
				{
					__FSM_H2_DROP(Req_HdrPsPathV);
				}
				__msg_hdr_chunk_fixup(data, len);
				__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);
				__FSM_H2_HDR_COMPLETE(Req_HdrPsPathV);
			});
		}
		__FSM_H2_DROP(Req_HdrPsPathV);
	}

	__FSM_STATE(Req_Mark, hot) {
		if (!tfw_http_sess_max_misses())
			__FSM_H2_PSHDR_MOVE_FIN_fixup(Req_Mark, 1, Req_Path);

		if (!parser->_i_st)
			TRY_STR_INIT();
		/* __fsm_n == CSTR_NEQ if the path doesn't start with '/'. */
		__fsm_n = __h2_req_parse_mark(req, p, __data_remain(p), fin);
		if (__fsm_n == CSTR_POSTPONE)
			__FSM_H2_POSTPONE(Req_Mark);
		if (__fsm_n < 0) {
			__FSM_H2_DROP(Req_Mark);
		}
		parser->_i_st = NULL;

		/*
		 * All data is already fixed up in __h2_req_parse_mark()
		 * into parser->hdr.
		 */
		if (!__fsm_n)
			__FSM_JMP(Req_Path);
		if (TFW_STR_EMPTY(&req->mark)) {
			/* Common path prefix with the redirection mark. */
			__FSM_H2_PSHDR_MOVE_DROP_nofixup(Req_Mark, __fsm_n, Req_Path);
		}
		/* Found Tempest FW redirection marker. */
		__FSM_H2_PSHDR_MOVE_DROP_nofixup(Req_Mark, __fsm_n, Req_MarkEnd);
	}

	__FSM_STATE(Req_MarkEnd, hot) {
		if (likely(c == '/'))
			__FSM_H2_PSHDR_MOVE_FIN_fixup(Req_MarkEnd, 1, Req_Path);
		__FSM_H2_DROP(Req_MarkEnd);
	}

	__FSM_STATE(Req_Path) {
		__fsm_n = __data_remain(p);
		__fsm_sz = tfw_match_uri(p, __fsm_n);
		if (likely(__fsm_sz != __fsm_n))
			__FSM_H2_DROP(Req_Path);
		__msg_hdr_chunk_fixup(p, __fsm_sz);
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);
		if (unlikely(!fin))
			__FSM_H2_POSTPONE(Req_Path);
		__FSM_H2_HDR_COMPLETE(Req_Path);
	}

	/* ':authority' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrPsAuthorityV, req, __h2_req_parse_authority,
			     TFW_HTTP_HDR_H2_AUTHORITY, 0);

	/* ----------------    Header values    ---------------- */

	/* 'accept' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrAcceptV, req, __h2_req_parse_accept,
			     TFW_HTTP_HDR_RAW, 1);

	/* 'authorization' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrAuthorizationV, req,
			     __h2_req_parse_authorization, TFW_HTTP_HDR_RAW, 1);

	/* 'cache-control' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrCache_ControlV, req,
			     __h2_req_parse_cache_control, TFW_HTTP_HDR_RAW, 1);

	/* 'content-encoding' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrContent_EncodingV, msg,
			     __h2_req_parse_content_encoding,
			     TFW_HTTP_HDR_CONTENT_ENCODING, 1);

	/* 'content-length' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrContent_LengthV, msg,
			     __h2_req_parse_content_length,
			     TFW_HTTP_HDR_CONTENT_LENGTH, 1);

	/* 'content-type' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrContent_TypeV, msg,
			     __h2_req_parse_content_type,
			     TFW_HTTP_HDR_CONTENT_TYPE, 0);

	/*
	 * 'host' is read, process field-value. Semantically equals to
	 * :authority header, use the same parsing functions.
	 */
	TFW_H2_PARSE_HDR_VAL(Req_HdrHostV, req, __h2_req_parse_authority,
			     TFW_HTTP_HDR_HOST, 0);

	/* 'if-none-match' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrIf_None_MatchV, msg,
			     __h2_req_parse_if_nmatch,
			     TFW_HTTP_HDR_IF_NONE_MATCH, 0);

	/* 'if-modified-since' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrIf_Modified_SinceV, msg,
			     __h2_req_parse_if_msince,
			     TFW_HTTP_HDR_RAW, 1);

	/* 'pragma' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrPragmaV, msg, __h2_req_parse_pragma,
			     TFW_HTTP_HDR_RAW, 1);

	/* 'referer' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrRefererV, msg, __h2_req_parse_referer,
			     TFW_HTTP_HDR_REFERER, 1);

	/* 'user-agent' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrUser_AgentV, msg, __h2_req_parse_user_agent,
			     TFW_HTTP_HDR_USER_AGENT, 1);

	/* 'cookie' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrCookieV, msg, __h2_req_parse_cookie,
			     TFW_HTTP_HDR_COOKIE, 0);

	/* 'x-forwarded-for' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrX_Forwarded_ForV, msg,
			     __h2_req_parse_x_forwarded_for,
			     TFW_HTTP_HDR_X_FORWARDED_FOR, 0);

	/* 'te' is read, process field-value */
	TFW_H2_PARSE_HDR_VAL(Req_HdrTeV, msg,
			     __h2_req_parse_te,
			     TFW_HTTP_HDR_RAW, 1);

	/* 'forwarded' is read, process field-value. */
	TFW_H2_PARSE_HDR_VAL(Req_HdrForwardedV, msg,
			     __h2_req_parse_forwarded,
			     TFW_HTTP_HDR_FORWARDED, 0);
	/*
	 * 'X-HTTP-Method:*OWS' OR 'X-HTTP-Method-Override:*OWS' OR
	 * 'X-Method-Override:*OWS' is read, process field-value.
	*/
	TFW_H2_PARSE_HDR_VAL(Req_HdrX_Method_OverrideV, req,
			     __h2_req_parse_m_override, TFW_HTTP_HDR_RAW, 1);

	__FSM_STATE(RGen_HdrOtherV) {
		if (!H2_MSG_VERIFY(TFW_HTTP_HDR_RAW))
			__FSM_H2_DROP(RGen_HdrOtherV);

		__fsm_n = __data_remain(p);
		__fsm_sz = tfw_match_ctext_vchar(p, __fsm_n);
		if (unlikely(__fsm_sz != __fsm_n))
			__FSM_H2_DROP(RGen_HdrOtherV);

		__msg_hdr_chunk_fixup(data, len);
		__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);

		if (unlikely(!fin))
			__FSM_H2_POSTPONE(RGen_HdrOtherV);

		parser->_hdr_tag = TFW_HTTP_HDR_RAW;
		__FSM_H2_HDR_COMPLETE(RGen_HdrOtherV);
	}

	/* ----------------    Slow path    ---------------- */

	barrier();

	/* Improbable states of (pseudo-)header names processing. */

	__FSM_STATE(Req_Hdr, cold) {
		switch (c) {
		case ':':
			p += 1;
			if (likely(__data_off(p) < len)) {
				T_DBG3("%s: name next, to=Req_HdrPseudo"
				       " len=%lu, off=%lu\n", __func__,
				       len, __data_off(p));
				__FSM_JMP(Req_HdrPseudo);
			}
			if (likely(!fin)) {
				__msg_hdr_chunk_fixup(data, len);
				__FSM_H2_POSTPONE(Req_HdrPseudo);
			}
			__FSM_H2_DROP(Req_Hdr);
		case 'a':
			__FSM_H2_NEXT(Req_HdrA);
		case 'c':
			__FSM_H2_NEXT(Req_HdrC);
		case 'f':
			__FSM_H2_NEXT(Req_HdrF);
		case 'h':
			__FSM_H2_NEXT(Req_HdrH);
		case 'i':
			__FSM_H2_NEXT(Req_HdrI);
		case 'k':
			__FSM_H2_NEXT(Req_HdrK);
		case 'p':
			__FSM_H2_NEXT(Req_HdrP);
		case 'r':
			__FSM_H2_NEXT(Req_HdrR);
		case 't':
			__FSM_H2_NEXT(Req_HdrT);
		case 'u':
			__FSM_H2_NEXT(Req_HdrU);
		case 'x':
			__FSM_H2_NEXT(Req_HdrX);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	__FSM_STATE(Req_HdrPseudo, cold) {
		switch (c) {
		case 'a':
			__FSM_H2_NEXT(Req_HdrPsA);
		case 'm':
			__FSM_H2_NEXT(Req_HdrPsM);
		case 'p':
			__FSM_H2_NEXT(Req_HdrPsP);
		case 's':
			__FSM_H2_NEXT(Req_HdrPsS);
		default:
			__FSM_H2_DROP(Req_HdrPseudo);
		}
	}

	__FSM_H2_TXD_AF(Req_HdrPsA, 'u', Req_HdrPsAu);
	__FSM_H2_TXD_AF(Req_HdrPsAu, 't', Req_HdrPsAut);
	__FSM_H2_TXD_AF(Req_HdrPsAut, 'h', Req_HdrPsAuth);
	__FSM_H2_TXD_AF(Req_HdrPsAuth, 'o', Req_HdrPsAutho);
	__FSM_H2_TXD_AF(Req_HdrPsAutho, 'r', Req_HdrPsAuthor);
	__FSM_H2_TXD_AF(Req_HdrPsAuthor, 'i', Req_HdrPsAuthori);
	__FSM_H2_TXD_AF(Req_HdrPsAuthori, 't', Req_HdrPsAuthorit);
	__FSM_H2_TXD_AF_FIN(Req_HdrPsAuthorit, 'y', Req_HdrPsAuthorityV,
			    TFW_TAG_HDR_H2_AUTHORITY);

	__FSM_H2_TXD_AF(Req_HdrPsM, 'e', Req_HdrPsMe);
	__FSM_H2_TXD_AF(Req_HdrPsMe, 't', Req_HdrPsMet);
	__FSM_H2_TXD_AF(Req_HdrPsMet, 'h', Req_HdrPsMeth);
	__FSM_H2_TXD_AF(Req_HdrPsMeth, 'o', Req_HdrPsMetho);
	__FSM_H2_TXD_AF_FIN(Req_HdrPsMetho, 'd', Req_HdrPsMethodV,
			    TFW_TAG_HDR_H2_METHOD);

	__FSM_H2_TXD_AF(Req_HdrPsP, 'a', Req_HdrPsPa);
	__FSM_H2_TXD_AF(Req_HdrPsPa, 't', Req_HdrPsPat);
	__FSM_H2_TXD_AF_FIN(Req_HdrPsPat, 'h', Req_HdrPsPathV,
			    TFW_TAG_HDR_H2_PATH);

	__FSM_H2_TXD_AF(Req_HdrPsS, 'c', Req_HdrPsSc);
	__FSM_H2_TXD_AF(Req_HdrPsSc, 'h', Req_HdrPsSch);
	__FSM_H2_TXD_AF(Req_HdrPsSch, 'e', Req_HdrPsSche);
	__FSM_H2_TXD_AF(Req_HdrPsSche, 'm', Req_HdrPsSchem);
	__FSM_H2_TXD_AF_FIN(Req_HdrPsSchem, 'e', Req_HdrPsSchemeV,
			    TFW_TAG_HDR_H2_SCHEME);

	__FSM_STATE(Req_HdrA, cold) {
		switch (c) {
		case 'c':
			__FSM_H2_NEXT(Req_HdrAc);
		case 'u':
			__FSM_H2_NEXT(Req_HdrAu);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	__FSM_H2_TX_AF(Req_HdrAc, 'c', Req_HdrAcc);
	__FSM_H2_TX_AF(Req_HdrAcc, 'e', Req_HdrAcce);
	__FSM_H2_TX_AF(Req_HdrAcce, 'p', Req_HdrAccep);
	__FSM_H2_TX_AF_FIN(Req_HdrAccep, 't', Req_HdrAcceptV,
			   TFW_TAG_HDR_ACCEPT);

	__FSM_H2_TX_AF(Req_HdrAu, 't', Req_HdrAut);
	__FSM_H2_TX_AF(Req_HdrAut, 'h', Req_HdrAuth);
	__FSM_H2_TX_AF(Req_HdrAuth, 'o', Req_HdrAutho);
	__FSM_H2_TX_AF(Req_HdrAutho, 'r', Req_HdrAuthor);
	__FSM_H2_TX_AF(Req_HdrAuthor, 'i', Req_HdrAuthori);
	__FSM_H2_TX_AF(Req_HdrAuthori, 'z', Req_HdrAuthoriz);
	__FSM_H2_TX_AF(Req_HdrAuthoriz, 'a', Req_HdrAuthoriza);
	__FSM_H2_TX_AF(Req_HdrAuthoriza, 't', Req_HdrAuthorizat);
	__FSM_H2_TX_AF(Req_HdrAuthorizat, 'i', Req_HdrAuthorizati);
	__FSM_H2_TX_AF(Req_HdrAuthorizati, 'o', Req_HdrAuthorizatio);
	__FSM_H2_TX_AF_FIN(Req_HdrAuthorizatio, 'n', Req_HdrAuthorizationV,
			   TFW_TAG_HDR_AUTHORIZATION);

	__FSM_STATE(Req_HdrC, cold) {
		switch (c) {
		case 'a':
			__FSM_H2_NEXT(Req_HdrCa);
		case 'o':
			__FSM_H2_NEXT(Req_HdrCo);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	__FSM_H2_TX_AF(Req_HdrCa, 'c', Req_HdrCac);
	__FSM_H2_TX_AF(Req_HdrCac, 'h', Req_HdrCach);
	__FSM_H2_TX_AF(Req_HdrCach, 'e', Req_HdrCache);
	__FSM_H2_TX_AF(Req_HdrCache, '-', Req_HdrCache_);
	__FSM_H2_TX_AF(Req_HdrCache_, 'c', Req_HdrCache_C);
	__FSM_H2_TX_AF(Req_HdrCache_C, 'o', Req_HdrCache_Co);
	__FSM_H2_TX_AF(Req_HdrCache_Co, 'n', Req_HdrCache_Con);
	__FSM_H2_TX_AF(Req_HdrCache_Con, 't', Req_HdrCache_Cont);
	__FSM_H2_TX_AF(Req_HdrCache_Cont, 'r', Req_HdrCache_Contr);
	__FSM_H2_TX_AF(Req_HdrCache_Contr, 'o', Req_HdrCache_Contro);
	__FSM_H2_TX_AF_FIN(Req_HdrCache_Contro, 'l', Req_HdrCache_ControlV,
			   TFW_TAG_HDR_CACHE_CONTROL);

	__FSM_STATE(Req_HdrCo, cold) {
		switch (c) {
		case 'n':
			__FSM_H2_NEXT(Req_HdrCon);
		case 'o':
			__FSM_H2_NEXT(Req_HdrCoo);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	__FSM_STATE(Req_HdrCon, cold) {
		switch (c) {
		case 'n':
			__FSM_H2_NEXT(Req_HdrConn);
		case 't':
			__FSM_H2_NEXT(Req_HdrCont);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}
	__FSM_H2_TX_AF(Req_HdrConn, 'e', Req_HdrConne);
	__FSM_H2_TX_AF(Req_HdrConne, 'c', Req_HdrConnec);
	__FSM_H2_TX_AF(Req_HdrConnec, 't', Req_HdrConnect);
	__FSM_H2_TX_AF(Req_HdrConnect, 'i', Req_HdrConnecti);
	__FSM_H2_TX_AF(Req_HdrConnecti, 'o', Req_HdrConnectio);
	__FSM_H2_TX_AF_DROP(Req_HdrConnectio, 'n');

	__FSM_H2_TX_AF(Req_HdrCont, 'e', Req_HdrConte);
	__FSM_H2_TX_AF(Req_HdrConte, 'n', Req_HdrConten);
	__FSM_H2_TX_AF(Req_HdrConten, 't', Req_HdrContent);
	__FSM_H2_TX_AF(Req_HdrContent, '-', Req_HdrContent_);

	__FSM_STATE(Req_HdrContent_, cold) {
		switch (c) {
		case 'e':
			__FSM_H2_NEXT(Req_HdrContent_E);
		case 'l':
			__FSM_H2_NEXT(Req_HdrContent_L);
		case 't':
			__FSM_H2_NEXT(Req_HdrContent_T);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	__FSM_H2_TX_AF(Req_HdrContent_E, 'n', Req_HdrContent_En);
	__FSM_H2_TX_AF(Req_HdrContent_En, 'c', Req_HdrContent_Enc);
	__FSM_H2_TX_AF(Req_HdrContent_Enc, 'o', Req_HdrContent_Enco);
	__FSM_H2_TX_AF(Req_HdrContent_Enco, 'd', Req_HdrContent_Encod);
	__FSM_H2_TX_AF(Req_HdrContent_Encod, 'i', Req_HdrContent_Encodi);
	__FSM_H2_TX_AF(Req_HdrContent_Encodi, 'n', Req_HdrContent_Encodin);
	__FSM_H2_TX_AF_FIN(Req_HdrContent_Encodin, 'g',
			   Req_HdrContent_EncodingV,
			   TFW_TAG_HDR_CONTENT_ENCODING);

	__FSM_H2_TX_AF(Req_HdrContent_L, 'e', Req_HdrContent_Le);
	__FSM_H2_TX_AF(Req_HdrContent_Le, 'n', Req_HdrContent_Len);
	__FSM_H2_TX_AF(Req_HdrContent_Len, 'g', Req_HdrContent_Leng);
	__FSM_H2_TX_AF(Req_HdrContent_Leng, 't', Req_HdrContent_Lengt);
	__FSM_H2_TX_AF_FIN(Req_HdrContent_Lengt, 'h', Req_HdrContent_LengthV,
			   TFW_TAG_HDR_CONTENT_LENGTH);

	__FSM_H2_TX_AF(Req_HdrContent_T, 'y', Req_HdrContent_Ty);
	__FSM_H2_TX_AF(Req_HdrContent_Ty, 'p', Req_HdrContent_Typ);
	__FSM_H2_TX_AF_FIN(Req_HdrContent_Typ, 'e', Req_HdrContent_TypeV,
			   TFW_TAG_HDR_CONTENT_TYPE);

	__FSM_H2_TX_AF(Req_HdrF, 'o', Req_HdrFo);
	__FSM_H2_TX_AF(Req_HdrFo, 'r', Req_HdrFor);
	__FSM_H2_TX_AF(Req_HdrFor, 'w', Req_HdrForw);
	__FSM_H2_TX_AF(Req_HdrForw, 'a', Req_HdrForwa);
	__FSM_H2_TX_AF(Req_HdrForwa, 'r', Req_HdrForwar);
	__FSM_H2_TX_AF(Req_HdrForwar, 'd', Req_HdrForward);
	__FSM_H2_TX_AF(Req_HdrForward, 'e', Req_HdrForwarde);
	__FSM_H2_TX_AF_FIN(Req_HdrForwarde, 'd', Req_HdrForwardedV, TFW_TAG_HDR_FORWARDED);

	__FSM_H2_TX_AF(Req_HdrH, 'o', Req_HdrHo);
	__FSM_H2_TX_AF(Req_HdrHo, 's', Req_HdrHos);
	__FSM_H2_TX_AF_FIN(Req_HdrHos, 't', Req_HdrHostV, TFW_TAG_HDR_HOST);

	__FSM_H2_TX_AF(Req_HdrI, 'f', Req_HdrIf);
	__FSM_H2_TX_AF(Req_HdrIf, '-', Req_HdrIf_);
	__FSM_STATE(Req_HdrIf_, cold) {
		switch (c) {
		case 'm':
			__FSM_H2_NEXT(Req_HdrIf_M);
		case 'n':
			__FSM_H2_NEXT(Req_HdrIf_N);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	__FSM_H2_TX_AF(Req_HdrIf_M, 'o', Req_HdrIf_Mo);
	__FSM_H2_TX_AF(Req_HdrIf_Mo, 'd', Req_HdrIf_Mod);
	__FSM_H2_TX_AF(Req_HdrIf_Mod, 'i', Req_HdrIf_Modi);
	__FSM_H2_TX_AF(Req_HdrIf_Modi, 'f', Req_HdrIf_Modif);
	__FSM_H2_TX_AF(Req_HdrIf_Modif, 'i', Req_HdrIf_Modifi);
	__FSM_H2_TX_AF(Req_HdrIf_Modifi, 'e', Req_HdrIf_Modifie);
	__FSM_H2_TX_AF(Req_HdrIf_Modifie, 'd', Req_HdrIf_Modified);
	__FSM_H2_TX_AF(Req_HdrIf_Modified, '-', Req_HdrIf_Modified_);
	__FSM_H2_TX_AF(Req_HdrIf_Modified_, 's', Req_HdrIf_Modified_S);
	__FSM_H2_TX_AF(Req_HdrIf_Modified_S, 'i', Req_HdrIf_Modified_Si);
	__FSM_H2_TX_AF(Req_HdrIf_Modified_Si, 'n', Req_HdrIf_Modified_Sin);
	__FSM_H2_TX_AF(Req_HdrIf_Modified_Sin, 'c', Req_HdrIf_Modified_Sinc);
	__FSM_H2_TX_AF_FIN(Req_HdrIf_Modified_Sinc, 'e',
			   Req_HdrIf_Modified_SinceV,
			   TFW_TAG_HDR_IF_MODIFIED_SINCE);

	__FSM_H2_TX_AF(Req_HdrIf_N, 'o', Req_HdrIf_No);
	__FSM_H2_TX_AF(Req_HdrIf_No, 'n', Req_HdrIf_Non);
	__FSM_H2_TX_AF(Req_HdrIf_Non, 'e', Req_HdrIf_None);
	__FSM_H2_TX_AF(Req_HdrIf_None, '-', Req_HdrIf_None_);
	__FSM_H2_TX_AF(Req_HdrIf_None_, 'm', Req_HdrIf_None_M);
	__FSM_H2_TX_AF(Req_HdrIf_None_M, 'a', Req_HdrIf_None_Ma);
	__FSM_H2_TX_AF(Req_HdrIf_None_Ma, 't', Req_HdrIf_None_Mat);
	__FSM_H2_TX_AF(Req_HdrIf_None_Mat, 'c', Req_HdrIf_None_Matc);
	__FSM_H2_TX_AF_FIN(Req_HdrIf_None_Matc, 'h', Req_HdrIf_None_MatchV,
			   TFW_TAG_HDR_IF_NONE_MATCH);

	__FSM_H2_TX_AF(Req_HdrK, 'e', Req_HdrKe);
	__FSM_H2_TX_AF(Req_HdrKe, 'e', Req_HdrKee);
	__FSM_H2_TX_AF(Req_HdrKee, 'p', Req_HdrKeep);
	__FSM_H2_TX_AF(Req_HdrKeep, '-', Req_HdrKeep_);
	__FSM_H2_TX_AF(Req_HdrKeep_, 'a', Req_HdrKeep_A);
	__FSM_H2_TX_AF(Req_HdrKeep_A, 'l', Req_HdrKeep_Al);
	__FSM_H2_TX_AF(Req_HdrKeep_Al, 'i', Req_HdrKeep_Ali);
	__FSM_H2_TX_AF(Req_HdrKeep_Ali, 'v', Req_HdrKeep_Aliv);
	__FSM_H2_TX_AF_DROP(Req_HdrKeep_Aliv, 'e');

	__FSM_H2_TX_AF(Req_HdrP, 'r', Req_HdrPr);
	__FSM_STATE(Req_HdrPr, cold) {
		switch (c) {
		case 'a':
			__FSM_H2_NEXT(Req_HdrPra);
		case 'o':
			__FSM_H2_NEXT(Req_HdrPro);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	__FSM_H2_TX_AF(Req_HdrPra, 'g', Req_HdrPrag);
	__FSM_H2_TX_AF(Req_HdrPrag, 'm', Req_HdrPragm);
	__FSM_H2_TX_AF_FIN(Req_HdrPragm, 'a', Req_HdrPragmaV,
			   TFW_TAG_HDR_PRAGMA);

	__FSM_H2_TX_AF(Req_HdrPro, 'x', Req_HdrProx);
	__FSM_H2_TX_AF(Req_HdrProx, 'y', Req_HdrProxy);
	__FSM_H2_TX_AF(Req_HdrProxy, '_', Req_HdrProxy_);
	__FSM_H2_TX_AF(Req_HdrProxy_, 'c', Req_HdrProxy_C);
	__FSM_H2_TX_AF(Req_HdrProxy_C, 'o', Req_HdrProxy_Co);
	__FSM_H2_TX_AF(Req_HdrProxy_Co, 'n', Req_HdrProxy_Con);
	__FSM_H2_TX_AF(Req_HdrProxy_Con, 'n', Req_HdrProxy_Conn);
	__FSM_H2_TX_AF(Req_HdrProxy_Conn, 'e', Req_HdrProxy_Conne);
	__FSM_H2_TX_AF(Req_HdrProxy_Conne, 'c', Req_HdrProxy_Connec);
	__FSM_H2_TX_AF(Req_HdrProxy_Connec, 't', Req_HdrProxy_Connect);
	__FSM_H2_TX_AF(Req_HdrProxy_Connect, 'i', Req_HdrProxy_Connecti);
	__FSM_H2_TX_AF(Req_HdrProxy_Connecti, 'o', Req_HdrProxy_Connectio);
	__FSM_H2_TX_AF_DROP(Req_HdrProxy_Connectio, 'n');

	__FSM_H2_TX_AF(Req_HdrR, 'e', Req_HdrRe);
	__FSM_H2_TX_AF(Req_HdrRe, 'f', Req_HdrRef);
	__FSM_H2_TX_AF(Req_HdrRef, 'e', Req_HdrRefe);
	__FSM_H2_TX_AF(Req_HdrRefe, 'r', Req_HdrRefer);
	__FSM_H2_TX_AF(Req_HdrRefer, 'e', Req_HdrRefere);
	__FSM_H2_TX_AF_FIN(Req_HdrRefere, 'r', Req_HdrRefererV,
			   TFW_TAG_HDR_REFERER);

	__FSM_STATE(Req_HdrT, cold) {
		switch (c) {
		case 'r':
			__FSM_H2_NEXT(Req_HdrTr);
		case 'e':
			 __FSM_H2_FIN(Req_HdrTeV, 1, TFW_TAG_HDR_RAW);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}
	__FSM_H2_TX_AF(Req_HdrTr, 'a', Req_HdrTra);
	__FSM_H2_TX_AF(Req_HdrTra, 'n', Req_HdrTran);
	__FSM_H2_TX_AF(Req_HdrTran, 's', Req_HdrTrans);
	__FSM_H2_TX_AF(Req_HdrTrans, 'f', Req_HdrTransf);
	__FSM_H2_TX_AF(Req_HdrTransf, 'e', Req_HdrTransfe);
	__FSM_H2_TX_AF(Req_HdrTransfe, 'r', Req_HdrTransfer);
	__FSM_H2_TX_AF(Req_HdrTransfer, '-', Req_HdrTransfer_);
	__FSM_H2_TX_AF(Req_HdrTransfer_, 'e', Req_HdrTransfer_E);
	__FSM_H2_TX_AF(Req_HdrTransfer_E, 'n', Req_HdrTransfer_En);
	__FSM_H2_TX_AF(Req_HdrTransfer_En, 'c', Req_HdrTransfer_Enc);
	__FSM_H2_TX_AF(Req_HdrTransfer_Enc, 'o', Req_HdrTransfer_Enco);
	__FSM_H2_TX_AF(Req_HdrTransfer_Enco, 'd', Req_HdrTransfer_Encod);
	__FSM_H2_TX_AF(Req_HdrTransfer_Encod, 'i', Req_HdrTransfer_Encodi);
	__FSM_H2_TX_AF(Req_HdrTransfer_Encodi, 'n', Req_HdrTransfer_Encodin);
	__FSM_H2_TX_AF_DROP(Req_HdrTransfer_Encodin, 'g');

	__FSM_H2_TX_AF(Req_HdrX, '-', Req_HdrX_);
	__FSM_STATE(Req_HdrX_, cold) {
		switch (c) {
		case 'f':
			__FSM_H2_NEXT(Req_HdrX_F);
		case 'h':
			__FSM_H2_NEXT(Req_HdrX_H);
		case 'm':
			__FSM_H2_NEXT(Req_HdrX_M);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* X-Forwarded-For header processing. */
	__FSM_H2_TX_AF(Req_HdrX_F, 'o', Req_HdrX_Fo);
	__FSM_H2_TX_AF(Req_HdrX_Fo, 'r', Req_HdrX_For);
	__FSM_H2_TX_AF(Req_HdrX_For, 'w', Req_HdrX_Forw);
	__FSM_H2_TX_AF(Req_HdrX_Forw, 'a', Req_HdrX_Forwa);
	__FSM_H2_TX_AF(Req_HdrX_Forwa, 'r', Req_HdrX_Forwar);
	__FSM_H2_TX_AF(Req_HdrX_Forwar, 'd', Req_HdrX_Forward);
	__FSM_H2_TX_AF(Req_HdrX_Forward, 'e', Req_HdrX_Forwarde);
	__FSM_H2_TX_AF(Req_HdrX_Forwarde, 'd', Req_HdrX_Forwarded);
	__FSM_H2_TX_AF(Req_HdrX_Forwarded, '-', Req_HdrX_Forwarded_);
	__FSM_H2_TX_AF(Req_HdrX_Forwarded_, 'f', Req_HdrX_Forwarded_F);
	__FSM_H2_TX_AF(Req_HdrX_Forwarded_F, 'o', Req_HdrX_Forwarded_Fo);
	__FSM_H2_TX_AF_FIN(Req_HdrX_Forwarded_Fo, 'r', Req_HdrX_Forwarded_ForV,
			   TFW_TAG_HDR_X_FORWARDED_FOR);

	/* X-Method-Override header processing. */
	__FSM_H2_TX_AF(Req_HdrX_M, 'e', Req_HdrX_Me);
	__FSM_H2_TX_AF(Req_HdrX_Me, 't', Req_HdrX_Met);
	__FSM_H2_TX_AF(Req_HdrX_Met, 'h', Req_HdrX_Meth);
	__FSM_H2_TX_AF(Req_HdrX_Meth, 'o', Req_HdrX_Metho);
	__FSM_H2_TX_AF(Req_HdrX_Metho, 'd', Req_HdrX_Method);
	__FSM_H2_TX_AF(Req_HdrX_Method, '-', Req_HdrX_Method_);
	__FSM_H2_TX_AF(Req_HdrX_Method_, 'o', Req_HdrX_Method_O);
	__FSM_H2_TX_AF(Req_HdrX_Method_O, 'v', Req_HdrX_Method_Ov);
	__FSM_H2_TX_AF(Req_HdrX_Method_Ov, 'e', Req_HdrX_Method_Ove);
	__FSM_H2_TX_AF(Req_HdrX_Method_Ove, 'r', Req_HdrX_Method_Over);
	__FSM_H2_TX_AF(Req_HdrX_Method_Over, 'r', Req_HdrX_Method_Overr);
	__FSM_H2_TX_AF(Req_HdrX_Method_Overr, 'i', Req_HdrX_Method_Overri);
	__FSM_H2_TX_AF(Req_HdrX_Method_Overri, 'd', Req_HdrX_Method_Overrid);
	__FSM_H2_TX_AF_FIN(Req_HdrX_Method_Overrid, 'e', Req_HdrX_Method_OverrideV,
			   TFW_TAG_HDR_RAW);

	/* X-HTTP-Method header processing */
	__FSM_H2_TX_AF(Req_HdrX_H, 't', Req_HdrX_Ht);
	__FSM_H2_TX_AF(Req_HdrX_Ht, 't', Req_HdrX_Htt);
	__FSM_H2_TX_AF(Req_HdrX_Htt, 'p', Req_HdrX_Http);
	__FSM_H2_TX_AF(Req_HdrX_Http, '-', Req_HdrX_Http_);
	__FSM_H2_TX_AF(Req_HdrX_Http_, 'm', Req_HdrX_Http_M);
	__FSM_H2_TX_AF(Req_HdrX_Http_M, 'e', Req_HdrX_Http_Me);
	__FSM_H2_TX_AF(Req_HdrX_Http_Me, 't', Req_HdrX_Http_Met);
	__FSM_H2_TX_AF(Req_HdrX_Http_Met, 'h', Req_HdrX_Http_Meth);
	__FSM_H2_TX_AF(Req_HdrX_Http_Meth, 'o', Req_HdrX_Http_Metho);
	/*
	 * Same as __FSM_H2_TX_AF_FIN, but jump to X-HTTP-Method-Override
	 * header if more data is found afer 'd'
	 */
	__FSM_STATE(Req_HdrX_Http_Metho, cold) {
		if (unlikely(c != 'd'))
			__FSM_JMP(RGen_HdrOtherN);

		p += 1;
		T_DBG3("%s: name next, to=Req_HdrX_Http_Method len=%lu,"
		       " off=%lu\n", __func__, len, __data_off(p));
		if (__data_off(p) < len)
			__FSM_JMP(Req_HdrX_Http_Method);

		__msg_hdr_chunk_fixup(data, len);
		if (likely(!fin))
			__FSM_H2_POSTPONE(Req_HdrX_Http_Method);

		it->tag = TFW_TAG_HDR_RAW;
		__FSM_H2_OK(Req_HdrX_Method_OverrideV);
	}

	/* X-HTTP-Method-Override processing */
	__FSM_H2_TX_AF(Req_HdrX_Http_Method, '-', Req_HdrX_Http_Method_);
	__FSM_H2_TX_AF(Req_HdrX_Http_Method_, 'o', Req_HdrX_Http_Method_O);
	__FSM_H2_TX_AF(Req_HdrX_Http_Method_O, 'v', Req_HdrX_Http_Method_Ov);
	__FSM_H2_TX_AF(Req_HdrX_Http_Method_Ov, 'e', Req_HdrX_Http_Method_Ove);
	__FSM_H2_TX_AF(Req_HdrX_Http_Method_Ove, 'r', Req_HdrX_Http_Method_Over);
	__FSM_H2_TX_AF(Req_HdrX_Http_Method_Over, 'r', Req_HdrX_Http_Method_Overr);
	__FSM_H2_TX_AF(Req_HdrX_Http_Method_Overr, 'i', Req_HdrX_Http_Method_Overri);
	__FSM_H2_TX_AF(Req_HdrX_Http_Method_Overri, 'd', Req_HdrX_Http_Method_Overrid);
	__FSM_H2_TX_AF_FIN(Req_HdrX_Http_Method_Overrid, 'e', Req_HdrX_Method_OverrideV,
			   TFW_TAG_HDR_RAW);

	__FSM_STATE(Req_HdrU, cold) {
		switch (c) {
		case 's':
			__FSM_H2_NEXT(Req_HdrUs);
		case 'p':
			__FSM_H2_NEXT(Req_HdrUp);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}
	__FSM_H2_TX_AF(Req_HdrUs, 'e', Req_HdrUse);
	__FSM_H2_TX_AF(Req_HdrUse, 'r', Req_HdrUser);
	__FSM_H2_TX_AF(Req_HdrUser, '-', Req_HdrUser_);
	__FSM_H2_TX_AF(Req_HdrUser_, 'a', Req_HdrUser_A);
	__FSM_H2_TX_AF(Req_HdrUser_A, 'g', Req_HdrUser_Ag);
	__FSM_H2_TX_AF(Req_HdrUser_Ag, 'e', Req_HdrUser_Age);
	__FSM_H2_TX_AF(Req_HdrUser_Age, 'n', Req_HdrUser_Agen);
	__FSM_H2_TX_AF_FIN(Req_HdrUser_Agen, 't', Req_HdrUser_AgentV,
			   TFW_TAG_HDR_USER_AGENT);

	__FSM_H2_TX_AF(Req_HdrUp, 'g', Req_HdrUpg);
	__FSM_H2_TX_AF(Req_HdrUpg, 'r', Req_HdrUpgr);
	__FSM_H2_TX_AF(Req_HdrUpgr, 'a', Req_HdrUpgra);
	__FSM_H2_TX_AF(Req_HdrUpgra, 'd', Req_HdrUpgrad);
	__FSM_H2_TX_AF_DROP(Req_HdrUpgrad, 'e');

	__FSM_H2_TX_AF(Req_HdrCoo, 'k', Req_HdrCook);
	__FSM_H2_TX_AF(Req_HdrCook, 'i', Req_HdrCooki);
	__FSM_H2_TX_AF_FIN(Req_HdrCooki, 'e', Req_HdrCookieV,
			   TFW_TAG_HDR_COOKIE);

	/* Improbable states of method values processing. */

	__FSM_STATE(Req_RareMethods_3, cold) {
		if (__data_available(p, 3)) {
			if (*p == 'P' && *(p + 1) == 'U' && *(p + 2) == 'T') {
				__FSM_H2_METHOD_COMPLETE(Req_HdrPsMethodV, 3,
							 TFW_HTTP_METH_PUT);
			}
			__FSM_JMP(Req_RareMethods_4);
		}
		__FSM_JMP(Req_Method_1CharStep);
	}

	__FSM_STATE(Req_RareMethods_4, cold) {
		if (__data_available(p, 4)) {
			if (C4_INT(p, 'H', 'E', 'A', 'D'))
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_4, 4,
							 TFW_HTTP_METH_HEAD);
			if (C4_INT(p, 'C', 'O', 'P', 'Y'))
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_4, 4,
							 TFW_HTTP_METH_COPY);
			if (C4_INT(p, 'L', 'O', 'C', 'K'))
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_4, 4,
							 TFW_HTTP_METH_LOCK);
			if (C4_INT(p, 'M', 'O', 'V', 'E'))
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_4, 4,
							 TFW_HTTP_METH_MOVE);
			__FSM_JMP(Req_RareMethods_5);
		}
		__FSM_JMP(Req_Method_1CharStep);
	}

	__FSM_STATE(Req_RareMethods_5, cold) {
		if (__data_available(p, 5)) {
			if (C4_INT(p, 'P', 'U', 'R', 'G') && *(p + 4) == 'E')
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_5, 5,
							 TFW_HTTP_METH_PURGE);
			if (C4_INT(p, 'M', 'K', 'C', 'O') && *(p + 4) == 'L')
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_5, 5,
							 TFW_HTTP_METH_MKCOL);
			if (C4_INT(p, 'P', 'A', 'T', 'C') && *(p + 4) == 'H')
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_5, 5,
							 TFW_HTTP_METH_PATCH);
			if (C4_INT(p, 'T', 'R', 'A', 'C') && *(p + 4) == 'E')
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_5, 5,
							 TFW_HTTP_METH_TRACE);
			__FSM_JMP(Req_RareMethods_6);
		}
		__FSM_JMP(Req_Method_1CharStep);
	}

	__FSM_STATE(Req_RareMethods_6, cold) {
		if (__data_available(p, 6)) {
			if (C4_INT(p, 'D', 'E', 'L', 'E')
			    && *(p + 4) == 'T'
			    && *(p + 5) == 'E')
			{
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_6, 6,
							 TFW_HTTP_METH_DELETE);
			}
			if (C4_INT(p, 'U', 'N', 'L', 'O')
			    && *(p + 4) == 'C'
			    && *(p + 5) == 'K')
			{
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_6, 6,
							 TFW_HTTP_METH_UNLOCK);
			}
			__FSM_JMP(Req_RareMethods_7);
		}
		__FSM_JMP(Req_Method_1CharStep);
	}

	__FSM_STATE(Req_RareMethods_7, cold) {
		if (__data_available(p, 7)) {
			if (C4_INT(p, 'O', 'P', 'T', 'I')
			    && *(p + 4) == 'O'
			    && *(p + 5) == 'N'
			    && *(p + 6) == 'S')
			{
				__FSM_H2_METHOD_COMPLETE(Req_RareMethods_7, 7,
							 TFW_HTTP_METH_OPTIONS);
			}
			__FSM_JMP(Req_RareMethods);
		}
		__FSM_JMP(Req_Method_1CharStep);
	}

	__FSM_STATE(Req_RareMethods, cold) {
		if (!__data_available(p, 8))
			__FSM_JMP(Req_Method_1CharStep);
		if (!C4_INT(p, 'P', 'R', 'O', 'P'))
			__FSM_JMP(Req_MethodUnknown);
		p += 4;
		if(C4_INT(p, 'F', 'I', 'N', 'D'))
			__FSM_H2_METHOD_COMPLETE(Req_RareMethods, 4,
						 TFW_HTTP_METH_PROPFIND);
		if (!__data_available(p, 5))
			__FSM_JMP(Req_MethodUnknown);
		if (C4_INT(p, 'P', 'A', 'T', 'C') && *(p + 4) == 'H')
			__FSM_H2_METHOD_COMPLETE(Req_RareMethods, 5,
						 TFW_HTTP_METH_PROPPATCH);
		__FSM_JMP(Req_MethodUnknown);
	}

	__FSM_STATE(Req_Method_1CharStep, cold) {
		switch (c) {
		case 'G':
			__FSM_H2_METHOD_MOVE(Req_Method_1CharStep, 1,
					     Req_MethG);
		case 'H':
			__FSM_H2_METHOD_MOVE(Req_Method_1CharStep, 1,
					     Req_MethH);
		case 'P':
			__FSM_H2_METHOD_MOVE(Req_Method_1CharStep, 1,
					     Req_MethP);
		case 'C':
			__FSM_H2_METHOD_MOVE(Req_Method_1CharStep, 1,
					     Req_MethC);
		case 'D':
			__FSM_H2_METHOD_MOVE(Req_Method_1CharStep, 1,
					     Req_MethD);
		case 'L':
			__FSM_H2_METHOD_MOVE(Req_Method_1CharStep, 1,
					     Req_MethL);
		case 'M':
			__FSM_H2_METHOD_MOVE(Req_Method_1CharStep, 1,
					     Req_MethM);
		case 'O':
			__FSM_H2_METHOD_MOVE(Req_Method_1CharStep, 1,
					     Req_MethO);
		case 'T':
			__FSM_H2_METHOD_MOVE(Req_Method_1CharStep, 1,
					     Req_MethT);
		case 'U':
			__FSM_H2_METHOD_MOVE(Req_Method_1CharStep, 1,
					     Req_MethU);
		}
		__FSM_JMP(Req_MethodUnknown);
	}
	/* GET */
	__FSM_H2_METH_STATE_MOVE(Req_MethG, 'E', Req_MethGe);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethGe, 'T', TFW_HTTP_METH_GET);
	/* P* */
	__FSM_STATE(Req_MethP, cold) {
		switch (c) {
		case 'O':
			__FSM_H2_METHOD_MOVE(Req_MethP, 1, Req_MethPo);
		case 'A':
			__FSM_H2_METHOD_MOVE(Req_MethP, 1, Req_MethPa);
		case 'R':
			__FSM_H2_METHOD_MOVE(Req_MethP, 1, Req_MethPr);
		case 'U':
			__FSM_H2_METHOD_MOVE(Req_MethP, 1, Req_MethPu);
		}
		__FSM_JMP(Req_MethodUnknown);
	}
	/* POST */
	__FSM_H2_METH_STATE_MOVE(Req_MethPo, 'S', Req_MethPos);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethPos, 'T', TFW_HTTP_METH_POST);
	/* PATCH */
	__FSM_H2_METH_STATE_MOVE(Req_MethPa, 'T', Req_MethPat);
	__FSM_H2_METH_STATE_MOVE(Req_MethPat, 'C', Req_MethPatc);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethPatc, 'H', TFW_HTTP_METH_PATCH);
	/* PROP* */
	__FSM_H2_METH_STATE_MOVE(Req_MethPr, 'O', Req_MethPro);
	__FSM_H2_METH_STATE_MOVE(Req_MethPro, 'P', Req_MethProp);
	__FSM_STATE(Req_MethProp, cold) {
		switch (c) {
		case 'F':
			__FSM_H2_METHOD_MOVE(Req_MethProp, 1, Req_MethPropf);
		case 'P':
			__FSM_H2_METHOD_MOVE(Req_MethProp, 1, Req_MethPropp);
		}
		__FSM_JMP(Req_MethodUnknown);
	}
	/* PROPFIND */
	__FSM_H2_METH_STATE_MOVE(Req_MethPropf, 'I', Req_MethPropfi);
	__FSM_H2_METH_STATE_MOVE(Req_MethPropfi, 'N', Req_MethPropfin);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethPropfin, 'D',
				     TFW_HTTP_METH_PROPFIND);
	/* PROPPATCH */
	__FSM_H2_METH_STATE_MOVE(Req_MethPropp, 'A', Req_MethProppa);
	__FSM_H2_METH_STATE_MOVE(Req_MethProppa, 'T', Req_MethProppat);
	__FSM_H2_METH_STATE_MOVE(Req_MethProppat, 'C', Req_MethProppatc);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethProppatc, 'H',
				     TFW_HTTP_METH_PROPPATCH);
	/* PU* */
	__FSM_STATE(Req_MethPu, cold) {
		switch (c) {
		case 'R':
			__FSM_H2_METHOD_MOVE(Req_MethPu, 1, Req_MethPur);
		case 'T':
			/* PUT */
			__FSM_H2_METHOD_COMPLETE(Req_MethPu, 1,
						 TFW_HTTP_METH_PUT);
		}
		__FSM_JMP(Req_MethodUnknown);
	}
	/* PURGE */
	__FSM_H2_METH_STATE_MOVE(Req_MethPur, 'G', Req_MethPurg);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethPurg, 'E', TFW_HTTP_METH_PURGE);
	/* HEAD */
	__FSM_H2_METH_STATE_MOVE(Req_MethH, 'E', Req_MethHe);
	__FSM_H2_METH_STATE_MOVE(Req_MethHe, 'A', Req_MethHea);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethHea, 'D', TFW_HTTP_METH_HEAD);
	/* COPY */
	__FSM_H2_METH_STATE_MOVE(Req_MethC, 'O', Req_MethCo);
	__FSM_H2_METH_STATE_MOVE(Req_MethCo, 'P', Req_MethCop);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethCop, 'Y', TFW_HTTP_METH_COPY);
	/* DELETE */
	__FSM_H2_METH_STATE_MOVE(Req_MethD, 'E', Req_MethDe);
	__FSM_H2_METH_STATE_MOVE(Req_MethDe, 'L', Req_MethDel);
	__FSM_H2_METH_STATE_MOVE(Req_MethDel, 'E', Req_MethDele);
	__FSM_H2_METH_STATE_MOVE(Req_MethDele, 'T', Req_MethDelet);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethDelet, 'E', TFW_HTTP_METH_DELETE);
	/* LOCK */
	__FSM_H2_METH_STATE_MOVE(Req_MethL, 'O', Req_MethLo);
	__FSM_H2_METH_STATE_MOVE(Req_MethLo, 'C', Req_MethLoc);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethLoc, 'K', TFW_HTTP_METH_LOCK);
	/* M* */
	__FSM_STATE(Req_MethM, cold) {
		switch (c) {
		case 'K':
			__FSM_H2_METHOD_MOVE(Req_MethM, 1, Req_MethMk);
		case 'O':
			__FSM_H2_METHOD_MOVE(Req_MethM, 1, Req_MethMo);
		}
		__FSM_JMP(Req_MethodUnknown);
	}
	/* MKCOL */
	__FSM_H2_METH_STATE_MOVE(Req_MethMk, 'C', Req_MethMkc);
	__FSM_H2_METH_STATE_MOVE(Req_MethMkc, 'O', Req_MethMkco);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethMkco, 'L', TFW_HTTP_METH_MKCOL);
	/* MOVE */
	__FSM_H2_METH_STATE_MOVE(Req_MethMo, 'V', Req_MethMov);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethMov, 'E', TFW_HTTP_METH_MOVE);
	/* OPTIONS */
	__FSM_H2_METH_STATE_MOVE(Req_MethO, 'P', Req_MethOp);
	__FSM_H2_METH_STATE_MOVE(Req_MethOp, 'T', Req_MethOpt);
	__FSM_H2_METH_STATE_MOVE(Req_MethOpt, 'I', Req_MethOpti);
	__FSM_H2_METH_STATE_MOVE(Req_MethOpti, 'O', Req_MethOptio);
	__FSM_H2_METH_STATE_MOVE(Req_MethOptio, 'N', Req_MethOption);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethOption, 'S', TFW_HTTP_METH_OPTIONS);
	/* TRACE */
	__FSM_H2_METH_STATE_MOVE(Req_MethT, 'R', Req_MethTr);
	__FSM_H2_METH_STATE_MOVE(Req_MethTr, 'A', Req_MethTra);
	__FSM_H2_METH_STATE_MOVE(Req_MethTra, 'C', Req_MethTrac);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethTrac, 'E', TFW_HTTP_METH_TRACE);
	/* UNLOCK */
	__FSM_H2_METH_STATE_MOVE(Req_MethU, 'N', Req_MethUn);
	__FSM_H2_METH_STATE_MOVE(Req_MethUn, 'L', Req_MethUnl);
	__FSM_H2_METH_STATE_MOVE(Req_MethUnl, 'O', Req_MethUnlo);
	__FSM_H2_METH_STATE_MOVE(Req_MethUnlo, 'C', Req_MethUnloc);
	__FSM_H2_METH_STATE_COMPLETE(Req_MethUnloc, 'K', TFW_HTTP_METH_UNLOCK);

	__FSM_STATE(Req_MethodUnknown, cold) {
		__fsm_n = __data_remain(p);
		__fsm_sz = tfw_match_token(p, __fsm_n);
		if (likely(__fsm_sz == __fsm_n)) {
			__msg_hdr_chunk_fixup(data, len);
			__FSM_I_chunk_flags(TFW_STR_HDR_VALUE);
			if (unlikely(!fin))
				__FSM_H2_POSTPONE(Req_MethodUnknown);
			req->method = _TFW_HTTP_METH_UNKNOWN;
			__FSM_H2_HDR_COMPLETE(Req_MethodUnknown);
		}
		__FSM_H2_DROP(Req_MethodUnknown);
	}

	/* Improbable states of scheme value processing. */

	__FSM_H2_SCHEME_STATE_MOVE(Req_Scheme_1CharStep, 'h', Req_SchemeH);
	__FSM_H2_SCHEME_STATE_MOVE(Req_SchemeH, 't', Req_SchemeHt);
	__FSM_H2_SCHEME_STATE_MOVE(Req_SchemeHt, 't', Req_SchemeHtt);
	__FSM_H2_SCHEME_STATE_MOVE(Req_SchemeHtt, 'p', Req_SchemeHttp);
	__FSM_H2_SCHEME_STATE_COMPLETE(Req_SchemeHttp, 's');

out:
	return ret;
}
STACK_FRAME_NON_STANDARD(tfw_h2_parse_req_hdr);

static int
tfw_h2_parse_body(char *data, unsigned int len, TfwHttpReq *req,
		  unsigned int *parsed)
{
	unsigned int m_len;
	TfwH2Ctx *ctx = tfw_h2_context(req->conn);
	TfwHttpMsg *msg = (TfwHttpMsg *)req;
	TfwHttpParser *parser = &msg->stream->parser;
	int ret = T_POSTPONE;

	if (parser->to_read == -1) {
		if (WARN_ON_ONCE(!ctx->plen))
			return T_DROP;

		parser->to_read = ctx->plen;

		T_DBG3("%s: init, content_length=%lu, to_read=%ld\n", __func__,
		       req->content_length, parser->to_read);

		if (!req->body.data)
			tfw_http_msg_set_str_data(msg, &req->body, data);
	}

	BUG_ON(parser->to_read < 0);
	m_len = min_t(long, parser->to_read, len);
	parser->to_read -= m_len;

	if (parser->to_read) {
		T_DBG3("%s: postpone, to_read=%ld, m_len=%u, len=%u\n",
		       __func__, parser->to_read, m_len, len);
		__msg_field_fixup(&req->body, data + len);
		goto out;
	}

	WARN_ON_ONCE(m_len != len);
	T_DBG3("%s: to_read=%ld, m_len=%u, len=%u\n", __func__,
	       parser->to_read, m_len, len);

	if (tfw_http_msg_add_str_data(msg, &req->body, data, m_len))
		return T_DROP;

	parser->to_read = -1;
	ret = T_OK;

out:
	*parsed += m_len;
	return ret;
}

/**
 * Parse h2 request.
 *
 * Parsing of HTTP/2 frames' payload never gives T_OK result since request
 * can be assembled from different number of frames; only stream's state can
 * indicate the moment when request is completed. After all parts of request are
 * fully received and parsed, call the @tfw_h2_parse_req_finish() to check the
 * parser state.
 */
int
tfw_h2_parse_req(void *req_data, unsigned char *data, unsigned int len,
		 unsigned int *parsed)
{
	int r;
	TfwHttpReq *req = (TfwHttpReq *)req_data;
	TfwH2Ctx *ctx = tfw_h2_context(req->conn);

	WARN_ON_ONCE(!len);
	*parsed = 0;

	switch(ctx->hdr.type) {
	case HTTP2_HEADERS:
	case HTTP2_CONTINUATION:
		/* Receiving END_HEADERS flags second time
		 * means that we're processing trailer
		 * HEADERS/CONTINUATION frame.
		 *
		 * RFC 9113 8.1: Trailer HEADERS frame must
		 * contain END_STREAM flag.
		 */

		if (ctx->hdr.flags & HTTP2_F_END_HEADERS &&
		    test_bit(TFW_HTTP_B_HEADERS_PARSED, req->flags) &&
		    !(ctx->hdr.flags & HTTP2_F_END_STREAM))
		{
			return T_DROP;
		}

		r = tfw_hpack_decode(&ctx->hpack, data, len, req, parsed);
		break;
	case HTTP2_DATA:
		if ((req->method_override &&
		     TFW_HTTP_IS_METH_BODYLESS(req->method_override))
		    || TFW_HTTP_IS_METH_BODYLESS(req->method))
		{
			return T_DROP;
		}

		r = tfw_h2_parse_body(data, len, req, parsed);
		break;
	default:
		WARN(1, "%s: h2 ctx %p req %p, illegal frame type %d(%s)\n", __func__, ctx,
		     req, ctx->hdr.type, __h2_frm_type_n(ctx->hdr.type));
		return T_DROP;
	}

	return (r == T_OK) ? T_POSTPONE : r;
}

/**
 * Finish parsing h2 request. The request may consist of multiple skbs and
 * multiple h2 frames. Last frame is marked with End Stream flag, it's the
 * only way to indicate message end.
 */
int
tfw_h2_parse_req_finish(TfwHttpReq *req)
{
	TfwHttpHdrTbl *ht = req->h_tbl;

	if (unlikely(!test_bit(TFW_HTTP_B_HEADERS_PARSED, req->flags)))
		return T_DROP;

	/*
	 * TFW_HTTP_B_H2_HDRS_FULL flag is set on first TFW_HTTP_HDR_REGULAR
	 * header, if no present, need to check mandatory pseudo headers.
	 */
	if (unlikely(!test_bit(TFW_HTTP_B_H2_HDRS_FULL, req->flags)
		     && (TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_H2_METHOD])
			 || TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_H2_SCHEME])
			 || TFW_STR_EMPTY(&ht->tbl[TFW_HTTP_HDR_H2_PATH]))))
	{
		return T_DROP;
	}

	if (req->content_length
	    && req->content_length != req->body.len)
	{
		return T_DROP;
	}
	/*
	 * RFC 7540 8.1.2.6: A request or response that includes a payload
	 * body can include a content-length header field.
	 *
	 * Since the h2 provides explicit message framing, the content-length
	 * header is not required at all. But our code may rely on
	 * req->content_length field value, fill it.
	 */
	req->content_length = req->body.len;
	req->body.flags |= TFW_STR_COMPLETE;
	__set_bit(TFW_HTTP_B_FULLY_PARSED, req->flags);

	__h2_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_H2_PATH],
			 &req->uri_path);

	return T_OK;
}

void
tfw_idx_hdr_parse_host_port(TfwHttpReq *req, TfwStr *hdr)
{
	TfwStr *c, *end;
	bool has_exp_port = false;

	TFW_STR_FOR_EACH_CHUNK(c, hdr, end) {
		if (!(c->flags & TFW_STR_VALUE) && c->len == 1 &&
			c->data[0] == ':') {
			has_exp_port = true;
			break;
		}
	}

	if (has_exp_port) {
		/* chunk containing the port should always be the last one */
		TfwStr p_chunk = hdr->chunks[hdr->nchunks - 1];
		unsigned long host_port = 0;
		__parse_ulong_ws(p_chunk.data, p_chunk.len, &host_port, USHRT_MAX);
		T_DBG3("%s: got port: %lu\n", __func__, host_port);
		req->host_port = host_port;
	}
}

enum {
	TFW_HTTP_MLEN_3C = 3,
	TFW_HTTP_MLEN_4C,
	TFW_HTTP_MLEN_5C,
	TFW_HTTP_MLEN_6C,
	TFW_HTTP_MLEN_7C,
	TFW_HTTP_MLEN_8C,
	TFW_HTTP_MLEN_9C,
};
#define H2_METH_HDR_VLEN    7

/**
 * Obtain HTTP method id from TfwStr chunked string.
 * Code here relies on http parser, which should
 * filter out illegal 'method' headers.
 * Used exclusively by HPACK related code.
 */
unsigned char
tfw_http_meth_str2id(const TfwStr *m_hdr)
{
	unsigned long mv_len;
	unsigned char *p;
	const TfwStr *chunk;

	BUG_ON(TFW_STR_PLAIN(m_hdr));

	mv_len = m_hdr->len - H2_METH_HDR_VLEN;
	/* ':method' name should always be in a single chunk */
	chunk = TFW_STR_CHUNK(m_hdr, 1);
	p = chunk->data;

	switch (mv_len) {
	case TFW_HTTP_MLEN_3C:
		return *p == 'P' ? TFW_HTTP_METH_PUT : TFW_HTTP_METH_GET;
	case TFW_HTTP_MLEN_4C:
		switch (*p) {
		case 'C':
			return TFW_HTTP_METH_COPY;
		case 'H':
			return TFW_HTTP_METH_HEAD;
		case 'L':
			return TFW_HTTP_METH_LOCK;
		case 'M':
			return TFW_HTTP_METH_MOVE;
		case 'P':
			return TFW_HTTP_METH_POST;
		default:
			WARN_ON(1);
			return _TFW_HTTP_METH_UNKNOWN;
		}
	case TFW_HTTP_MLEN_5C:
		switch (*p) {
		case 'M':
			return TFW_HTTP_METH_MKCOL;
		case 'T':
			return TFW_HTTP_METH_TRACE;
		case 'P':
			if (chunk->len == 1)
				p = TFW_STR_CHUNK(m_hdr, 2)->data;
			else
				p++;

			return *p  == 'A'
				? TFW_HTTP_METH_PATCH
				: TFW_HTTP_METH_PURGE;
		default:
			WARN_ON(1);
			return _TFW_HTTP_METH_UNKNOWN;
		}
	case TFW_HTTP_MLEN_6C:
		return *p == 'D' ? TFW_HTTP_METH_DELETE
				 : TFW_HTTP_METH_UNLOCK;
	case TFW_HTTP_MLEN_7C:
		/* TODO: add CONNECT method */
		return TFW_HTTP_METH_OPTIONS;
	case TFW_HTTP_MLEN_8C:
		return TFW_HTTP_METH_PROPFIND;
	case TFW_HTTP_MLEN_9C:
		return TFW_HTTP_METH_PROPPATCH;
	default:
		return _TFW_HTTP_METH_UNKNOWN;
	}
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

	__FSM_REQUIRE_FIRST_DIGIT(Resp_I_AgeBeg, Resp_I_Age);

	__FSM_STATE(Resp_I_Age) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_ws(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(p, __fsm_sz);
		/*
		 * RFC 7234 1.2.1:
		 *
		 * If a cache receives a delta-seconds
		 * value greater than the greatest integer it can represent, or if any
		 * of its subsequent calculations overflows, the cache MUST consider the
		 * value to be either 2147483648 (2^31) or the greatest positive integer
		 * it can conveniently represent.
		 * ...
		 * What matters here is that an overflow
		 * be detected and not treated as a negative value in later
		 * calculations.
		 *
		 * Parser detects overflow when parsing delta-seconds,
		 * but blocks such messages because it's a rare case.
		 */
		if (__fsm_n < 0)
			return __fsm_n;
		resp->cache_ctl.age = parser->_acc;
		parser->_acc = 0;
		__msg_hdr_chunk_fixup(p, __fsm_n);
		p += __fsm_n;
		/* Fall through. */
	}

	__FSM_STATE(Resp_I_EoL) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(Resp_I_EoL, 1, TFW_STR_OWS);
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
 * Parse response Cache-Control, RFC 2616 14.9.
 */
static int
__resp_parse_cache_control(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	/*
	 * Very similar to __req_parse_cache_control,
	 * but requires explicit fixups due to the parent's
	 * __TFW_HTTP_PARSE_RAWHDR_VAL(saveval = false)
	 */
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

	__FSM_START(parser->_i_st);

	parser->cc_dir_flag = 0;

	__FSM_STATE(Resp_I_CC_start) {
		/* Spaces already skipped by RGen_LWS */
		/* Leading comma allowed per RFC 7230 Section 7 */
		if (c == ',')
			__FSM_I_MOVE_fixup(Resp_I_CC_start_Comma, 1, 0);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Resp_I_CC);
		/* Forbid empty header value */
		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Resp_I_CC_start_Comma) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(Resp_I_CC_start_Comma, 1,
					   TFW_STR_OWS);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Resp_I_CC);
		/* Forbid empty header value and double commas */
		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Resp_I_CC) {
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
		TRY_STR_fixup(&TFW_STR_STRING("max-age="), Resp_I_CC_m,
			      Resp_I_CC_MaxAgeVBeg);
		TRY_STR_LAMBDA_fixup(&TFW_STR_STRING("must-revalidate"),
			&parser->hdr, {
			parser->cc_dir_flag = TFW_HTTP_CC_MUST_REVAL;
		}, Resp_I_CC_m, Resp_I_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Resp_I_Ext);
	}

	__FSM_STATE(Resp_I_CC_n) {
		TRY_STR_LAMBDA_fixup(&TFW_STR_STRING("no-cache"),
			&parser->hdr, {
			parser->cc_dir_flag = TFW_HTTP_CC_NO_CACHE;
		}, Resp_I_CC_n, Resp_I_Dir_Eq);
		TRY_STR_LAMBDA_fixup(&TFW_STR_STRING("no-store"),
			&parser->hdr, {
			parser->cc_dir_flag = TFW_HTTP_CC_NO_STORE;
		}, Resp_I_CC_n, Resp_I_Flag);
		TRY_STR_LAMBDA_fixup(&TFW_STR_STRING("no-transform"),
			&parser->hdr, {
			parser->cc_dir_flag = TFW_HTTP_CC_NO_TRANSFORM;
		}, Resp_I_CC_n, Resp_I_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Resp_I_Ext);
	}

	__FSM_STATE(Resp_I_CC_p) {
		TRY_STR_LAMBDA_fixup(&TFW_STR_STRING("public"), &parser->hdr, {
			parser->cc_dir_flag = TFW_HTTP_CC_PUBLIC;
		}, Resp_I_CC_p, Resp_I_Flag);
		TRY_STR_LAMBDA_fixup(&TFW_STR_STRING("private"), &parser->hdr, {
			parser->cc_dir_flag = TFW_HTTP_CC_PRIVATE;
		}, Resp_I_CC_p, Resp_I_Dir_Eq);
		TRY_STR_LAMBDA_fixup(&TFW_STR_STRING("proxy-revalidate"),
			&parser->hdr, {
			parser->cc_dir_flag = TFW_HTTP_CC_PROXY_REVAL;
		}, Resp_I_CC_p, Resp_I_Flag);
		TRY_STR_INIT();
		__FSM_I_JMP(Resp_I_Ext);
	}

	/*
	 * no-cache or private with arguments as defined by rfc7234
	 * sections 5.2.2.2 and 5.2.2.6
	 */
	__FSM_STATE(Resp_I_Dir_Eq) {
		if (c == '=') {
			/* Qualified form cancels out the general flag */
			/*
			 * Resp_I_CC_Dir_Opening_Quote =>
			 * => Resp_I_CC_Dir_Arg_Token =>
			 * => Resp_I_CC_Dir_Arg_EoT
			 */
			__FSM_I_MOVE_fixup(Resp_I_CC_Dir_Opening_Quote, 1, 0);
		}
		__FSM_I_JMP(Resp_I_Flag);
	}

	__FSM_STATE(Resp_I_Flag) {
		/* A start of a standard directive successfully detected */
		if (IS_WS(c) || c == ',' || IS_CRLF(c)) {
			resp->cache_ctl.flags |= parser->cc_dir_flag;
			__FSM_I_JMP(Resp_I_EoT);
		}
		/* ...but the flag appears to have an unknown suffix */
		__FSM_I_JMP(Resp_I_Ext);
	}

	__FSM_STATE(Resp_I_CC_Dir_Opening_Quote) {
		if (c != '"')
			__FSM_EXIT(TFW_BLOCK);

		__FSM_I_MOVE_fixup(Resp_I_CC_Dir_Arg_Token, 1, 0);
	}

	__FSM_STATE(Resp_I_CC_Dir_Arg_Token) {
		/* Comma-separated field list (field-name/token) with optional
		 * linear white space.
		 * We do not set TfwStr->skb for tokens, since the tokens are
		 * used in read-only fashion to compare strings and are never
		 * rewriten (TfwStr->skb is used for rewriting raw data only).
		 */
#define __APPEND_CC_DIR(complete_current)					\
do {										\
	int ret = tfw_str_array_append_chunk(msg->pool, tokens, p, __fsm_sz,	\
					     complete_current);			\
	if (unlikely(ret)) {							\
		if (ret == -E2BIG)						\
			T_WARN_ADDR_STATUS(					\
				"Trying to allocate too many cache-control"	\
				" no-cache/private directives",			\
				&resp->conn->peer->addr,			\
				TFW_WITH_PORT, resp->status);			\
		__FSM_EXIT(TFW_BLOCK);						\
	}									\
} while (0)
		TfwStr *tokens;
		tokens = parser->cc_dir_flag == TFW_HTTP_CC_PRIVATE ?
			 &resp->private_tokens : &resp->no_cache_tokens;

		__FSM_I_MATCH_MOVE_fixup_finish(token, Resp_I_CC_Dir_Arg_Token,
						0, {
			__APPEND_CC_DIR(false);
		});

		/* Completing the current item */
		__APPEND_CC_DIR(true);
#undef __APPEND_CC_DIR

		__FSM_I_MOVE_fixup(Resp_I_CC_Dir_Arg_EoT, __fsm_sz, 0);
	}

	__FSM_STATE(Resp_I_CC_Dir_Arg_EoT) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(Resp_I_CC_Dir_Arg_EoT, 1,
					   TFW_STR_OWS);
		if (c == ',')
			__FSM_I_MOVE_fixup(Resp_I_CC_Dir_Arg_Comma, 1, 0);
		if (c == '"')
			__FSM_I_MOVE_fixup(Resp_I_EoT, 1, 0);
		/*
		 * if (IS_TOKEN(c)) then block too, because tokens should be
		 * separated by commas.
		 * Block on CRLF, because the double-quote should be closed.
		 */
		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Resp_I_CC_Dir_Arg_Comma) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(Resp_I_CC_Dir_Arg_Comma, 1,
					   TFW_STR_OWS);
		if (c == '"')
			__FSM_I_MOVE_fixup(Resp_I_EoT, 1, 0);
		if (IS_TOKEN(c))
			__FSM_I_JMP(Resp_I_CC_Dir_Arg_Token);
		/*
		 * Two consecutive commas in arguments not allowed,
		 * just like in Cache-Control directives.
		 */
		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Resp_I_CC_s) {
		TRY_STR_fixup(&TFW_STR_STRING("s-maxage="), Resp_I_CC_s,
			      Resp_I_CC_SMaxAgeVBeg);
		TRY_STR_INIT();
		__FSM_I_JMP(Resp_I_Ext);
	}

	__FSM_REQUIRE_FIRST_DIGIT(Resp_I_CC_MaxAgeVBeg, Resp_I_CC_MaxAgeV);

	__FSM_STATE(Resp_I_CC_MaxAgeV) {
		/*
		 * RFC 7234 4.2.1:
		 *
		 * When there is more than one value present for a given directive
		 * (e.g., two Expires header fields, multiple Cache-Control: max-age
		 * directives), the directive's value is considered invalid.
		 */
		if (unlikely(resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE))
			__FSM_EXIT(TFW_BLOCK);

		__fsm_sz = __data_remain(p);
		__fsm_n = parse_uint_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(p, __fsm_sz);
		if (__fsm_n < 0)
			__FSM_EXIT(__fsm_n);
		resp->cache_ctl.max_age = parser->_acc;
		resp->cache_ctl.flags |= TFW_HTTP_CC_MAX_AGE;
		__FSM_I_MOVE_fixup(Resp_I_EoT, __fsm_n, 0);
	}

	__FSM_REQUIRE_FIRST_DIGIT(Resp_I_CC_SMaxAgeVBeg, Resp_I_CC_SMaxAgeV);

	__FSM_STATE(Resp_I_CC_SMaxAgeV) {
		/*
		 * RFC 7234 4.2.1:
		 *
		 * When there is more than one value present for a given directive
		 * (e.g., two Expires header fields, multiple Cache-Control: max-age
		 * directives), the directive's value is considered invalid.
		 */
		if (unlikely(resp->cache_ctl.flags & TFW_HTTP_CC_S_MAXAGE))
			__FSM_EXIT(TFW_BLOCK);

		__fsm_sz = __data_remain(p);
		__fsm_n = parse_uint_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(p, __fsm_sz);
		if (__fsm_n < 0)
			__FSM_EXIT(__fsm_n);
		resp->cache_ctl.s_maxage = parser->_acc;
		resp->cache_ctl.flags |= TFW_HTTP_CC_S_MAXAGE;
		__FSM_I_MOVE_fixup(Resp_I_EoT, __fsm_n, 0);
	}

	__FSM_STATE(Resp_I_Ext) {
		/*
		 * Any directive we don't understand.
		 * Here we just skip all the tokens, double quotes and
		 * equality signs.
		 */
		__FSM_I_MATCH_MOVE_fixup(qetoken, Resp_I_Ext, 0);

		__FSM_I_MOVE_fixup(Resp_I_EoT, __fsm_sz, 0);
	}

	/* End of term. */
	__FSM_STATE(Resp_I_EoT) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(Resp_I_EoT, 1, TFW_STR_OWS);

		if (c == ',')
			__FSM_I_MOVE_fixup(Resp_I_After_Comma, 1, 0);

		if (IS_CRLF(c))
			__FSM_EXIT(__data_processed(p));

		__FSM_EXIT(TFW_BLOCK);
	}

	__FSM_STATE(Resp_I_After_Comma) {
		if (IS_WS(c))
			__FSM_I_MOVE_fixup(Resp_I_After_Comma, 1, TFW_STR_OWS);

		parser->_acc = 0;
		if (IS_TOKEN(c)) {
			/* reinit for next token */
			parser->cc_dir_flag = 0;
			__FSM_I_JMP(Resp_I_CC);
		}
		if (IS_CRLF(c))
			__FSM_EXIT(__data_processed(p));
		/* Two consecutive commas not allowed */
		__FSM_EXIT(TFW_BLOCK);
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
	int r = CSTR_NEQ;
	TfwHttpResp *resp = (TfwHttpResp *)msg;
	TfwHttpParser *parser = &msg->stream->parser;

	/*
	 * RFC 7234 4.2.1:
	 *
	 * When there is more than one value present for a given directive
	 * (e.g., two Expires header fields, multiple Cache-Control: max-age
	 * directives), the directive's value is considered invalid.
	 */
	if (unlikely(resp->cache_ctl.flags & TFW_HTTP_CC_HDR_EXPIRES))
		return r;

	r = __parse_http_date(msg, data, len);
	if (r < 0 && r != CSTR_POSTPONE) {
		/*
		 * On error just swallow the rest of the line.
		 * @resp->cache_ctl.expires is set to zero - already expired.
		 */
		parser->_date = 0;
		parser->_acc = 0;
		parser->_i_st = __I_EoL;
		/* Use __parse_http_date just to go to the EoL. */
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

	/*
	 * RFC 7230 3.2.2:
	 *
	 * A sender MUST NOT generate multiple header fields with the same field
	 * name in a message unless either the entire field value for that
	 * header field is defined as a comma-separated list [i.e., #(values)]
	 * or the header field is a well-known exception.
	 */
	if (unlikely(test_bit(TFW_HTTP_B_HDR_DATE, resp->flags)))
		return r;

	r = __parse_http_date(msg, data, len);
	if (r < 0 && r != CSTR_POSTPONE) {
		/* On error just swallow the rest of the line. */
		parser->_date = 0;
		parser->_acc = 0;
		parser->_i_st = __I_EoL;
		/* Use __parse_http_date just to go to the EoL. */
		r = __parse_http_date(msg, data, len);
	}

	if (r >= 0) {
		resp->date = parser->_date;
		__set_bit(TFW_HTTP_B_HDR_DATE, resp->flags);
	}

	return r;
}

static int
__resp_parse_last_modified(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpResp *resp = (TfwHttpResp *)msg;
	TfwHttpParser *parser = &msg->stream->parser;

	/*
	 * RFC 7230 3.2.2:
	 *
	 * A sender MUST NOT generate multiple header fields with the same field
	 * name in a message unless either the entire field value for that
	 * header field is defined as a comma-separated list [i.e., #(values)]
	 * or the header field is a well-known exception.
	 */
	if (unlikely(test_bit(TFW_HTTP_B_HDR_LMODIFIED, resp->flags)))
		return r;

	r = __parse_http_date(msg, data, len);
	if (r < 0 && r != CSTR_POSTPONE) {
		/* On error just swallow the rest of the line. */
		parser->_date = 0;
		parser->_acc = 0;
		parser->_i_st = __I_EoL;
		/* Use __parse_http_date just to go to the EoL. */
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

static int
__resp_parse_set_cookie(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

	/*
	 * Set-Cookie header is parsed according to RFC 6265 4.1.1.
	 *
	 * Here we build a header value string manually to split it in chunks:
	 * chunk bounds are at least at name start, value start and value end.
	 * This simplifies the cookie search, http_sticky uses it.
	 */
	__FSM_START(parser->_i_st);

	__FSM_STATE(Resp_I_CookieStart) {
		__FSM_I_MATCH_MOVE_fixup(token, Resp_I_CookieName, TFW_STR_NAME);
		/*
		 * Name should contain at least 1 character.
		 * Store "=" with cookie parameter name.
		 */
		if (likely(__fsm_sz && *(p + __fsm_sz) == '='))
			__FSM_I_MOVE_fixup(Resp_I_CookieVal, __fsm_sz + 1,
					   TFW_STR_NAME);
		return CSTR_NEQ;
	}

	/*
	 * At this state we know that we saw at least one character as
	 * cookie-name and now we can pass zero length token.
	 */
	__FSM_STATE(Resp_I_CookieName) {
		__FSM_I_MATCH_MOVE_fixup(token, Resp_I_CookieName, TFW_STR_NAME);
		if (*(p + __fsm_sz) != '=')
			return CSTR_NEQ;
		/* Store "=" with cookie parameter name. */
		__FSM_I_MOVE_fixup(Resp_I_CookieVal, __fsm_sz + 1, TFW_STR_NAME);
	}

	/*
	 * Cookie-value can have zero length, but we still have to store it
	 * in a separate TfwStr chunk.
	 */
	__FSM_STATE(Resp_I_CookieVal) {
		__FSM_I_MATCH_MOVE_fixup(cookie, Resp_I_CookieVal, TFW_STR_VALUE);
		c = *(p + __fsm_sz);
		if (c == ';') {
			if (likely(__fsm_sz)) {
				/* Save cookie-value w/o ';'. */
				__msg_hdr_chunk_fixup(p, __fsm_sz);
				__FSM_I_chunk_flags(TFW_STR_VALUE);
			}
			/* No-fixup function with additional fixups above. */
			__FSM_I_MOVE_n(Resp_I_CookieSemicolon, __fsm_sz);
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
	__FSM_STATE(Resp_I_CookieSemicolon) {
		/*
		 * Fixup current delimiters chunk and move to next parameter
		 * if we can eat ';' and SP at once.
		 */
		if (likely(__data_available(p, 2))) {
			if (likely(*(p + 1) == ' '))
				__FSM_I_MOVE_fixup(Resp_I_CookieExtension, 2, 0);
			return CSTR_NEQ;
		}
		/*
		 * Only ';' is available now: fixup ';' as independent chunk,
		 * SP will be fixed up at next enter to the FSM.
		 */
		__FSM_I_MOVE_fixup(Resp_I_CookieSP, 1, 0);
	}

	/*
	 * We don't strictly validate the extensions, eat them as is. Hope
	 * a backend doesn't try to trick us.
	 */
	__FSM_STATE(Resp_I_CookieExtension) {
		__FSM_I_MATCH_MOVE_fixup(ctext_vchar, Resp_I_CookieExtension, 0);
		c = *(p + __fsm_sz);
		if (unlikely(IS_CRLF(c))) {
			if (likely(__fsm_sz))
				__msg_hdr_chunk_fixup(p, __fsm_sz);

			return __data_off(p + __fsm_sz);
		}
		return CSTR_NEQ;
	}

	__FSM_STATE(Resp_I_CookieSP) {
		if (unlikely(c != ' '))
			return CSTR_NEQ;
		/* Fixup current delimiters chunk and move to next parameter. */
		__FSM_I_MOVE_fixup(Resp_I_CookieExtension, 1, 0);
	}

done:
	return r;
}
STACK_FRAME_NON_STANDARD(__resp_parse_set_cookie);

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
	 * - raw:
	 *     none;
	 * - spec:
	 *     Connection: RFC 7230 6.1.
	 *     Server: Server header isn't defined as hop-by-hop by the RFC,
	 *	       but we don't show protected server to world.
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
tfw_http_parse_resp(void *resp_data, unsigned char *data, unsigned int len,
		    unsigned int *parsed)
{
	int r = TFW_BLOCK;
	TfwHttpResp *resp = (TfwHttpResp *)resp_data;
	__FSM_DECLARE_VARS(resp);
	*parsed = 0;

	T_DBG("parse %u server data bytes (%.*s%s) on resp=%p\n",
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
				tfw_http_msg_hdr_open(msg, p);
				__FSM_MOVE(Resp_HttpVerT1);
			}
			TFW_PARSER_BLOCK(Resp_HttpVer);
		}
		/* Fast path. */
		switch (*(unsigned long *)p) {
		case TFW_CHAR8_INT('H', 'T', 'T', 'P', '/', '1', '.', '1'):
			resp->version = TFW_HTTP_VER_11;
			if (*(p + 8) == ' ') {
				tfw_http_msg_hdr_open(msg, p);
				__FSM_MOVE_n(Resp_StatusCodeBeg, 9);
			}
			TFW_PARSER_BLOCK(Resp_HttpVer);
		case TFW_CHAR8_INT('H', 'T', 'T', 'P', '/', '1', '.', '0'):
			resp->version = TFW_HTTP_VER_10;
			if (*(p + 8) == ' ') {
				tfw_http_msg_hdr_open(msg, p);
				__FSM_MOVE_n(Resp_StatusCodeBeg, 9);
			}
			/* fall through */
		default:
			TFW_PARSER_BLOCK(Resp_HttpVer);
		}
	}

	__FSM_REQUIRE_FIRST_DIGIT(Resp_StatusCodeBeg, Resp_StatusCode);

	/* Response Status-Code. */
	__FSM_STATE(Resp_StatusCode) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_ulong_list(p, __fsm_sz, &parser->_acc, USHRT_MAX);
		switch (__fsm_n) {
		case CSTR_POSTPONE:
			/* Not all the header data is parsed. */
			__FSM_MOVE_n(Resp_StatusCode, __fsm_sz);
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

			if (resp->status < 100 || resp->status > 599)
				T_WARN("Unknown response code: %hu", resp->status);

			__FSM_MOVE_n(Resp_ReasonPhrase, __fsm_n);
		}
	}

	/*
	 * Reason-Phrase: just skip. RFC 7230 3.1.2:
	 *
	 *	reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
	 */
	__FSM_STATE(Resp_ReasonPhrase) {
		/* Store reason-phrase in separate chunk(s). */
		__msg_hdr_chunk_fixup(data, p - data);
		__FSM_MATCH_MOVE_pos_f(ctext_vchar, Resp_ReasonPhrase,
				       &parser->hdr, TFW_STR_VALUE);
		if (IS_CRLF(*(p + __fsm_sz))) {
			parser->_hdr_tag = TFW_HTTP_STATUS_LINE;
			__msg_hdr_chunk_fixup(p, __fsm_sz);
			__msg_chunk_flags(TFW_STR_VALUE);
			p += __fsm_sz;
			__FSM_JMP(RGen_EoL);
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
			if (likely(__data_available(p, 28)
				   && C8_INT_LCM(p, 'a', 'c', 'c', 'e',
						 's', 's', '-', 'c')
				   && C8_INT_LCM(p + 8, 'o', 'n', 't', 'r',
						 'o', 'l', '-', 'a')
				   && C8_INT_LCM(p + 16, 'l', 'l', 'o', 'w',
						 '-', 'o', 'r', 'i')
				   && C4_INT3_LCM(p + 24, 'g', 'i', 'n', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 27));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(20);
				p += 27;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 14)
				   && C8_INT_LCM(p + 1, 'c', 'c', 'e', 'p',
						 't', '-', 'r', 'a')
				   && C4_INT_LCM(p + 9, 'n', 'g', 'e', 's')
				   && *(p + 13) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 13));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(18);
				p += 13;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 6)
				   && C4_INT_LCM(p + 1, 'l', 'l', 'o', 'w')
				   && *(p + 5) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 5));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(22);
				p += 5;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 4)
				   && C4_INT3_LCM(p, 'a', 'g', 'e', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 3));
				parser->_i_st = &&Resp_HdrAgeV;
				__msg_hdr_set_hpack_index(21);
				p += 3;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
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
					__msg_hdr_chunk_fixup(data,
							      __data_off(p + 13));
					parser->_i_st = &&Resp_HdrCache_CtrlV;
					__msg_hdr_set_hpack_index(24);
					p += 13;
					__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
				}
				__FSM_MOVE_n(RGen_HdrOtherN, 5);
			case TFW_CHAR4_INT('o', 'n', 'n', 'e'):
				if (likely(C4_INT_LCM(p + 5, 'c', 't', 'i', 'o')
					   && TFW_LC(*(p + 9)) == 'n'
					   && *(p + 10) == ':'))
				{
					__msg_hdr_chunk_fixup(data,
							      __data_off(p + 10));
					parser->_i_st = &&Resp_HdrConnectionV;
					p += 10;
					__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
				}
				__FSM_MOVE_n(RGen_HdrOtherN, 5);
			case TFW_CHAR4_INT('o', 'n', 't', 'e'):
				if (likely(TFW_LC(*(p + 5)) == 'n'
					   && TFW_LC(*(p + 6)) == 't'
					   && *(p + 7) == '-'))
				{
					__FSM_MOVE_n(Resp_HdrContent_, 8);
				}
				__FSM_MOVE_n(RGen_HdrOtherN, 5);
			default:
				__FSM_MOVE(RGen_HdrOtherN);
			}
		case 'd':
			if (likely(__data_available(p, 5)
				   && C4_INT3_LCM(p + 1, 'a', 't', 'e', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 4));
				parser->_i_st = &&Resp_HdrDateV;
				__msg_hdr_set_hpack_index(33);
				p += 4;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrD);
		case 'e':
			if (likely(__data_available(p, 5)
				   && C4_INT3_LCM(p + 1, 't', 'a', 'g', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 4));
				parser->_i_st = &&Resp_HdrEtagV;
				__msg_hdr_set_hpack_index(34);
				p += 4;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 8)
				   && C8_INT7_LCM(p, 'e', 'x', 'p', 'i',
						  'r', 'e', 's', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 7));
				parser->_i_st = &&Resp_HdrExpiresV;
				__msg_hdr_set_hpack_index(36);
				p += 7;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
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
				__msg_hdr_chunk_fixup(data, __data_off(p + 10));
				parser->_i_st = &&Resp_HdrKeep_AliveV;
				p += 10;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
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
				__msg_hdr_chunk_fixup(data, __data_off(p + 13));
				parser->_i_st = &&Resp_HdrLast_ModifiedV;
				__msg_hdr_set_hpack_index(44);
				p += 13;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 9)
			           && C8_INT7_LCM(p + 1, 'o', 'c', 'a', 't',
						  'i', 'o', 'n', ':')))
			{
				__msg_hdr_chunk_fixup(data,__data_off(p + 8));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(46);
				p += 8;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 5)
			           && C4_INT3_LCM(p + 1, 'i', 'n', 'k', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 4));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(45);
				p += 4;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrL);
		case 'p':
			if (likely(__data_available(p, 17)
			           && C4_INT_LCM(p + 1, 'r', 'o', 'x', 'y')))
			{
				if (C8_INT_LCM(p + 5, '-', 'c', 'o', 'n', 'n',
					       'e', 'c', 't')
					&& C4_INT3_LCM(p + 13, 'i', 'o', 'n', ':'))
				{
					/* Proxy-Connection */
					__msg_hdr_chunk_fixup(data,
							      __data_off(p + 16));
					parser->_i_st = &&RGen_HdrOtherV;
					parser->hdr.flags |= TFW_STR_HBH_HDR;
					p += 16;
					__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
				}
				if (__data_available(p, 19)
					&& C8_INT_LCM(p + 5, '-', 'a', 'u', 't',
						      'h', 'e', 'n', 't')
					&& C8_INT7_LCM(p + 11, 'n', 't', 'i',
						       'c', 'a', 't', 'e', ':'))
				{
					__msg_hdr_chunk_fixup(data,
							      __data_off(p + 18));
					parser->_i_st = &&RGen_HdrOtherV;
					__msg_hdr_set_hpack_index(48);
					p += 18;
					__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
				}
			}
			if (likely(__data_available(p, 7))
			           && C4_INT_LCM(p + 1, 'r', 'a', 'g', 'm')
			           && TFW_LC(*(p + 5)) == 'a'
			           && *(p + 6) == ':')
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 6));
				parser->_i_st = &&Resp_HdrPragmaV;
				p += 6;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrP);
		case 'r':
			if (likely(__data_available(p, 12)
			           && C8_INT_LCM(p, 'r', 'e', 't', 'r',
						 'y', '-', 'a', 'f')
				   && C4_INT3_LCM(p + 8, 't', 'e', 'r', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 11));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(53);
				p += 11;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrR);
		case 's':
			if (likely(__data_available(p, 26)
			           && C8_INT_LCM(p + 1, 't', 'r', 'i', 'c',
						  't', '-', 't', 'r')
				   && C8_INT_LCM(p + 9, 'a', 'n', 's', 'p',
						 'o', 'r', 't', '-')
				   && C8_INT_LCM(p + 17, 's', 'e', 'c', 'u',
						 'r', 'i', 't', 'y')
				   && *(p + 25) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 25));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(56);
				p += 25;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 11)
			           && C8_INT_LCM(p + 1, 'e', 't', '-', 'c',
						 'o', 'o', 'k', 'i')
				   && *(p + 3) == '-'
				   && TFW_LC(*(p + 9)) == 'e'
				   && *(p + 10) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 10));
				parser->_i_st = &&Resp_HdrSet_CookieV;
				__msg_hdr_set_hpack_index(55);
				p += 10;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'e', 'r', 'v', 'e')
				   && TFW_LC(*(p + 5)) == 'r'
				   && *(p + 6) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 6));
				parser->_i_st = &&Resp_HdrServerV;
				__msg_hdr_set_hpack_index(54);
				p += 6;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
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
				__msg_hdr_chunk_fixup(data, __data_off(p + 17));
				parser->_i_st = &&Resp_HdrTransfer_EncodingV;
				p += 17;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrT);
		case 'u':
			if (likely(__data_available(p, 8)
				   && C4_INT_LCM(p, 'u', 'p', 'g', 'r')
				   && C4_INT3_LCM(p + 4, 'a', 'd', 'e', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 7));
				parser->_i_st = &&Resp_HdrUpgradeV;
				p += 7;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrU);
		case 'v':
			if (likely(__data_available(p, 5)
			           && C4_INT3_LCM(p + 1, 'a', 'r', 'y', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 4));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(59);
				p += 4;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			if (likely(__data_available(p, 4)
			           && C4_INT3_LCM(p, 'v', 'i', 'a', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 3));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(60);
				p += 3;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrV);
		case 'w':
			if (likely(__data_available(p, 17)
				   && C8_INT_LCM(p + 1, 'w', 'w', '-', 'a',
						 'u', 't', 'h', 'e')
				   && C8_INT7_LCM(p + 9, 'n', 't', 'i', 'c',
						  'a', 't', 'e', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 16));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(61);
				p += 16;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrW);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Content-* headers. */
	__FSM_STATE(Resp_HdrContent_) {
		switch (TFW_LC(c)) {
		case 'd':
			if (likely(__data_available(p, 12)
				   && C8_INT_LCM(p, 'd', 'i', 's', 'p',
						 'o', 's', 'i', 't')
				   && C4_INT3_LCM(p + 8, 'i', 'o', 'n', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 11));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(25);
				p += 11;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrContent_D);
		case 'e':
			if (likely(__data_available(p, 9)
				   && C8_INT7_LCM(p + 1, 'n', 'c', 'o', 'd',
						  'i', 'n', 'g', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 8));
				parser->_i_st = &&Resp_HdrContent_EncodingV;
				__msg_hdr_set_hpack_index(26);
				p += 8;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrContent_E);
		case 'l':
			if (likely(__data_available(p, 9))) {
				if (C8_INT7_LCM(p + 1, 'a', 'n', 'g', 'u',
						'a', 'g', 'e', ':'))
				{
					__msg_hdr_chunk_fixup(data,
							      __data_off(p + 8));
					parser->_i_st = &&RGen_HdrOtherV;
					__msg_hdr_set_hpack_index(27);
					p += 8;
					__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
				}
				if (C8_INT7_LCM(p + 1, 'o', 'c', 'a', 't',
						'i', 'o', 'n', ':'))
				{
					__msg_hdr_chunk_fixup(data,
							      __data_off(p + 8));
					parser->_i_st = &&RGen_HdrOtherV;
					__msg_hdr_set_hpack_index(29);
					p += 8;
					__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
				}
			}
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'e', 'n', 'g', 't')
				   && TFW_LC(*(p + 5)) == 'h'
				   && *(p + 6) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 6));
				parser->_i_st = &&Resp_HdrContent_LengthV;
				__msg_hdr_set_hpack_index(28);
				p += 6;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrContent_L);
		case 'r':
			if (likely(__data_available(p, 6)
				   && C4_INT_LCM(p + 1, 'a', 'n', 'g', 'e')
				   && *(p + 5) == ':'))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 5));
				parser->_i_st = &&RGen_HdrOtherV;
				__msg_hdr_set_hpack_index(30);
				p += 5;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrContent_R);
		case 't':
			if (likely(__data_available(p, 5)
				   && C4_INT3_LCM(p + 1, 'y', 'p', 'e', ':')))
			{
				__msg_hdr_chunk_fixup(data, __data_off(p + 4));
				parser->_i_st = &&Resp_HdrContent_TypeV;
				__msg_hdr_set_hpack_index(31);
				p += 4;
				__FSM_MOVE_hdr_fixup(RGen_LWS, 1);
			}
			__FSM_MOVE(Resp_HdrContent_T);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* 'Age:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrAgeV, resp, __resp_parse_age, 0);

	/* 'Cache-Control:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrCache_CtrlV, resp,
				    __resp_parse_cache_control, 0);

	/* 'Connection:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrConnectionV, msg, __parse_connection,
				   TFW_HTTP_HDR_CONNECTION);

	/* 'Content-Encoding:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrContent_EncodingV, msg,
				     __resp_parse_content_encoding,
				     TFW_HTTP_HDR_CONTENT_ENCODING, 0);

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
	__TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrEtagV, msg, __parse_etag_or_if_nmatch,
				     TFW_HTTP_HDR_ETAG, 0);

	/* 'Expires:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrExpiresV, msg, __resp_parse_expires);

	/* 'Keep-Alive:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrKeep_AliveV, msg, __parse_keep_alive,
				     TFW_HTTP_HDR_KEEP_ALIVE, 0);

	/* 'Last-Modified:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrLast_ModifiedV, msg,
				  __resp_parse_last_modified);

	/* 'Pragma:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrPragmaV, msg, __parse_pragma, 0);

	/* 'Upgrade:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrUpgradeV, msg, __parse_upgrade,
				     TFW_HTTP_HDR_UPGRADE, 0);

	/* 'Server:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrServerV, resp, __resp_parse_server,
				   TFW_HTTP_HDR_SERVER);

	/* 'Transfer-Encoding:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrTransfer_EncodingV, msg,
				     __resp_parse_transfer_encoding,
				     TFW_HTTP_HDR_TRANSFER_ENCODING, 0);

	/* 'Set-Cookie:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrSet_CookieV, resp,
				     __resp_parse_set_cookie,
				     TFW_HTTP_HDR_SET_COOKIE, 0);

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
	__FSM_TX(Resp_HttpVerT1, 'T', Resp_HttpVerT2);
	__FSM_TX(Resp_HttpVerT2, 'T', Resp_HttpVerP);
	__FSM_TX(Resp_HttpVerP, 'P', Resp_HttpVerSlash);
	__FSM_TX(Resp_HttpVerSlash, '/', Resp_HttpVer11);
	__FSM_TX(Resp_HttpVer11, '1', Resp_HttpVerDot);
	__FSM_TX(Resp_HttpVerDot, '.', Resp_HttpVer12);
	__FSM_STATE(Resp_HttpVer12) {
		switch (c) {
		case '1':
			resp->version = TFW_HTTP_VER_11;
			__FSM_MOVE(Resp_SSpace);
		case '0':
			resp->version = TFW_HTTP_VER_10;
			__FSM_MOVE(Resp_SSpace);
		default:
			TFW_PARSER_BLOCK(Resp_HttpVer12);
		}
	}
	__FSM_TX(Resp_SSpace, ' ', Resp_StatusCodeBeg);

	__FSM_STATE(Resp_HdrA) {
		switch (TFW_LC(c)) {
		case 'c':
			__FSM_MOVE(Resp_HdrAc);
		case 'l':
			__FSM_MOVE(Resp_HdrAl);
		case 'g':
			__FSM_MOVE(Resp_HdrAg);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}
	__FSM_TX_AF(Resp_HdrAc, 'c', Resp_HdrAcc);
	__FSM_TX_AF(Resp_HdrAcc, 'e', Resp_HdrAcce);

	__FSM_STATE(Resp_HdrAcce) {
		switch (TFW_LC(c)) {
		case 'p':
			__FSM_MOVE(Resp_HdrAccep);
		case 's':
			__FSM_MOVE(Resp_HdrAcces);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Access-Control-Allow-Origin header processing. */
	__FSM_TX_AF(Resp_HdrAcces, 's', Resp_HdrAccess);
	__FSM_TX_AF(Resp_HdrAccess, '-', Resp_HdrAccess_);
	__FSM_TX_AF(Resp_HdrAccess_, 'c', Resp_HdrAccess_C);
	__FSM_TX_AF(Resp_HdrAccess_C, 'o', Resp_HdrAccess_Co);
	__FSM_TX_AF(Resp_HdrAccess_Co, 'n', Resp_HdrAccess_Con);
	__FSM_TX_AF(Resp_HdrAccess_Con, 't', Resp_HdrAccess_Cont);
	__FSM_TX_AF(Resp_HdrAccess_Cont, 'r', Resp_HdrAccess_Contr);
	__FSM_TX_AF(Resp_HdrAccess_Contr, 'o', Resp_HdrAccess_Contro);
	__FSM_TX_AF(Resp_HdrAccess_Contro, 'l', Resp_HdrAccess_Control);
	__FSM_TX_AF(Resp_HdrAccess_Control, '-', Resp_HdrAccess_Control_);
	__FSM_TX_AF(Resp_HdrAccess_Control_, 'a', Resp_HdrAccess_Control_A);
	__FSM_TX_AF(Resp_HdrAccess_Control_A, 'l', Resp_HdrAccess_Control_Al);
	__FSM_TX_AF(Resp_HdrAccess_Control_Al, 'l', Resp_HdrAccess_Control_All);
	__FSM_TX_AF(Resp_HdrAccess_Control_All, 'o',
		    Resp_HdrAccess_Control_Allo);
	__FSM_TX_AF(Resp_HdrAccess_Control_Allo, 'w',
		    Resp_HdrAccess_Control_Allow);
	__FSM_TX_AF(Resp_HdrAccess_Control_Allow, '-',
		    Resp_HdrAccess_Control_Allow_);
	__FSM_TX_AF(Resp_HdrAccess_Control_Allow_, 'o',
		    Resp_HdrAccess_Control_Allow_O);
	__FSM_TX_AF(Resp_HdrAccess_Control_Allow_O, 'r',
		    Resp_HdrAccess_Control_Allow_Or);
	__FSM_TX_AF(Resp_HdrAccess_Control_Allow_Or, 'i',
		    Resp_HdrAccess_Control_Allow_Ori);
	__FSM_TX_AF(Resp_HdrAccess_Control_Allow_Ori, 'g',
		    Resp_HdrAccess_Control_Allow_Orig);
	__FSM_TX_AF(Resp_HdrAccess_Control_Allow_Orig, 'i',
		    Resp_HdrAccess_Control_Allow_Origi);
	__FSM_TX_AF(Resp_HdrAccess_Control_Allow_Origi, 'n',
		    Resp_HdrAccess_Control_Allow_Origin);
	__FSM_TX_AF_OWS_HP(Resp_HdrAccess_Control_Allow_Origin,
			   RGen_HdrOtherV, 20);

	/* Accept-Ranges header processing. */
	__FSM_TX_AF(Resp_HdrAccep, 't', Resp_HdrAccept);
	__FSM_TX_AF(Resp_HdrAccept, '-', Resp_HdrAccept_);
	__FSM_TX_AF(Resp_HdrAccept_, 'r', Resp_HdrAccept_R);
	__FSM_TX_AF(Resp_HdrAccept_R, 'a', Resp_HdrAccept_Ra);
	__FSM_TX_AF(Resp_HdrAccept_Ra, 'n', Resp_HdrAccept_Ran);
	__FSM_TX_AF(Resp_HdrAccept_Ran, 'g', Resp_HdrAccept_Rang);
	__FSM_TX_AF(Resp_HdrAccept_Rang, 'e', Resp_HdrAccept_Range);
	__FSM_TX_AF(Resp_HdrAccept_Range, 's', Resp_HdrAccept_Ranges);
	__FSM_TX_AF_OWS_HP(Resp_HdrAccept_Ranges, RGen_HdrOtherV, 18);

	/* Allow header processing. */
	__FSM_TX_AF(Resp_HdrAl, 'l', Resp_HdrAll);
	__FSM_TX_AF(Resp_HdrAll, 'o', Resp_HdrAllo);
	__FSM_TX_AF(Resp_HdrAllo, 'w', Resp_HdrAllow);
	__FSM_TX_AF_OWS_HP(Resp_HdrAllow, RGen_HdrOtherV, 22);

	/* Age header processing. */
	__FSM_TX_AF(Resp_HdrAg, 'e', Resp_HdrAge);
	__FSM_TX_AF_OWS_HP(Resp_HdrAge, Resp_HdrAgeV, 21);

	__FSM_STATE(Resp_HdrC) {
		switch (TFW_LC(c)) {
		case 'a':
			__FSM_MOVE(Resp_HdrCa);
		case 'o':
			__FSM_MOVE(Resp_HdrCo);
		default:
			__FSM_JMP(RGen_HdrOtherN);
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
	__FSM_TX_AF_OWS_HP(Resp_HdrCache_Control, Resp_HdrCache_CtrlV, 24);

	/* Connection header processing. */
	__FSM_TX_AF(Resp_HdrCo, 'n', Resp_HdrCon);
	__FSM_STATE(Resp_HdrCon) {
		switch (TFW_LC(c)) {
		case 'n':
			__FSM_MOVE(Resp_HdrConn);
		case 't':
			__FSM_MOVE(Resp_HdrCont);
		default:
			__FSM_JMP(RGen_HdrOtherN);
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

	/* Content-Disposition header processing. */
	__FSM_TX_AF(Resp_HdrContent_D, 'i', Resp_HdrContent_Di);
	__FSM_TX_AF(Resp_HdrContent_Di, 's', Resp_HdrContent_Dis);
	__FSM_TX_AF(Resp_HdrContent_Dis, 'p', Resp_HdrContent_Disp);
	__FSM_TX_AF(Resp_HdrContent_Disp, 'o', Resp_HdrContent_Dispo);
	__FSM_TX_AF(Resp_HdrContent_Dispo, 's', Resp_HdrContent_Dispos);
	__FSM_TX_AF(Resp_HdrContent_Dispos, 'i', Resp_HdrContent_Disposi);
	__FSM_TX_AF(Resp_HdrContent_Disposi, 't', Resp_HdrContent_Disposit);
	__FSM_TX_AF(Resp_HdrContent_Disposit, 'i', Resp_HdrContent_Dispositi);
	__FSM_TX_AF(Resp_HdrContent_Dispositi, 'o', Resp_HdrContent_Dispositio);
	__FSM_TX_AF(Resp_HdrContent_Dispositio, 'n', Resp_HdrContent_Disposition);
	__FSM_TX_AF_OWS_HP(Resp_HdrContent_Disposition, RGen_HdrOtherV, 25);

	/* Content-Encoding header processing. */
	__FSM_TX_AF(Resp_HdrContent_E, 'n', Resp_HdrContent_En);
	__FSM_TX_AF(Resp_HdrContent_En, 'c', Resp_HdrContent_Enc);
	__FSM_TX_AF(Resp_HdrContent_Enc, 'o', Resp_HdrContent_Enco);
	__FSM_TX_AF(Resp_HdrContent_Enco, 'd', Resp_HdrContent_Encod);
	__FSM_TX_AF(Resp_HdrContent_Encod, 'i', Resp_HdrContent_Encodi);
	__FSM_TX_AF(Resp_HdrContent_Encodi, 'n', Resp_HdrContent_Encodin);
	__FSM_TX_AF(Resp_HdrContent_Encodin, 'g', Resp_HdrContent_Encoding);
	__FSM_TX_AF_OWS_HP(Resp_HdrContent_Encoding, Resp_HdrContent_EncodingV,
			   26);

	__FSM_STATE(Resp_HdrContent_L) {
		switch (TFW_LC(c)) {
		case 'a':
			__FSM_MOVE(Resp_HdrContent_La);
		case 'e':
			__FSM_MOVE(Resp_HdrContent_Le);
		case 'o':
			__FSM_MOVE(Resp_HdrContent_Lo);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Content-Language header processing. */
	__FSM_TX_AF(Resp_HdrContent_La, 'n', Resp_HdrContent_Lan);
	__FSM_TX_AF(Resp_HdrContent_Lan, 'g', Resp_HdrContent_Lang);
	__FSM_TX_AF(Resp_HdrContent_Lang, 'u', Resp_HdrContent_Langu);
	__FSM_TX_AF(Resp_HdrContent_Langu, 'a', Resp_HdrContent_Langua);
	__FSM_TX_AF(Resp_HdrContent_Langua, 'g', Resp_HdrContent_Languag);
	__FSM_TX_AF(Resp_HdrContent_Languag, 'e', Resp_HdrContent_Language);
	__FSM_TX_AF_OWS_HP(Resp_HdrContent_Language, RGen_HdrOtherV, 27);

	/* Content-Length header processing. */
	__FSM_TX_AF(Resp_HdrContent_Le, 'n', Resp_HdrContent_Len);
	__FSM_TX_AF(Resp_HdrContent_Len, 'g', Resp_HdrContent_Leng);
	__FSM_TX_AF(Resp_HdrContent_Leng, 't', Resp_HdrContent_Lengt);
	__FSM_TX_AF(Resp_HdrContent_Lengt, 'h', Resp_HdrContent_Length);
	__FSM_TX_AF_OWS_HP(Resp_HdrContent_Length, Resp_HdrContent_LengthV, 28);

	/* Content-Location header processing. */
	__FSM_TX_AF(Resp_HdrContent_Lo, 'c', Resp_HdrContent_Loc);
	__FSM_TX_AF(Resp_HdrContent_Loc, 'a', Resp_HdrContent_Loca);
	__FSM_TX_AF(Resp_HdrContent_Loca, 't', Resp_HdrContent_Locat);
	__FSM_TX_AF(Resp_HdrContent_Locat, 'i', Resp_HdrContent_Locati);
	__FSM_TX_AF(Resp_HdrContent_Locati, 'o', Resp_HdrContent_Locatio);
	__FSM_TX_AF(Resp_HdrContent_Locatio, 'n', Resp_HdrContent_Location);
	__FSM_TX_AF_OWS_HP(Resp_HdrContent_Location, RGen_HdrOtherV, 29);

	/* Content-Range header processing. */
	__FSM_TX_AF(Resp_HdrContent_R, 'a', Resp_HdrContent_Ra);
	__FSM_TX_AF(Resp_HdrContent_Ra, 'n', Resp_HdrContent_Ran);
	__FSM_TX_AF(Resp_HdrContent_Ran, 'g', Resp_HdrContent_Rang);
	__FSM_TX_AF(Resp_HdrContent_Rang, 'e', Resp_HdrContent_Range);
	__FSM_TX_AF_OWS_HP(Resp_HdrContent_Range, RGen_HdrOtherV, 30);

	/* Content-Type header processing. */
	__FSM_TX_AF(Resp_HdrContent_T, 'y', Resp_HdrContent_Ty);
	__FSM_TX_AF(Resp_HdrContent_Ty, 'p', Resp_HdrContent_Typ);
	__FSM_TX_AF(Resp_HdrContent_Typ, 'e', Resp_HdrContent_Type);
	__FSM_TX_AF_OWS_HP(Resp_HdrContent_Type, Resp_HdrContent_TypeV, 31);

	/* Date header processing. */
	__FSM_TX_AF(Resp_HdrD, 'a', Resp_HdrDa);
	__FSM_TX_AF(Resp_HdrDa, 't', Resp_HdrDat);
	__FSM_TX_AF(Resp_HdrDat, 'e', Resp_HdrDate);
	__FSM_TX_AF_OWS_HP(Resp_HdrDate, Resp_HdrDateV, 33);

	__FSM_STATE(Resp_HdrE) {
		switch (TFW_LC(c)) {
		case 't':
			__FSM_MOVE(Resp_HdrEt);
		case 'x':
			__FSM_MOVE(Resp_HdrEx);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}
	/* ETag header processing. */
	__FSM_TX_AF(Resp_HdrEt, 'a', Resp_HdrEta);
	__FSM_TX_AF(Resp_HdrEta, 'g', Resp_HdrEtag);
	__FSM_TX_AF_OWS_HP(Resp_HdrEtag, Resp_HdrEtagV, 34);

	/* Expires header processing. */
	__FSM_TX_AF(Resp_HdrEx, 'p', Resp_HdrExp);
	__FSM_TX_AF(Resp_HdrExp, 'i', Resp_HdrExpi);
	__FSM_TX_AF(Resp_HdrExpi, 'r', Resp_HdrExpir);
	__FSM_TX_AF(Resp_HdrExpir, 'e', Resp_HdrExpire);
	__FSM_TX_AF(Resp_HdrExpire, 's', Resp_HdrExpires);
	__FSM_TX_AF_OWS_HP(Resp_HdrExpires, Resp_HdrExpiresV, 36);

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

	__FSM_STATE(Resp_HdrL) {
		switch (TFW_LC(c)) {
		case 'a':
			__FSM_MOVE(Resp_HdrLa);
		case 'i':
			__FSM_MOVE(Resp_HdrLi);
		case 'o':
			__FSM_MOVE(Resp_HdrLo);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Last-Modified header processing. */
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
	__FSM_TX_AF_OWS_HP(Resp_HdrLast_Modified, Resp_HdrLast_ModifiedV, 44);

	/* Link header processing. */
	__FSM_TX_AF(Resp_HdrLi, 'n', Resp_HdrLin);
	__FSM_TX_AF(Resp_HdrLin, 'k', Resp_HdrLink);
	__FSM_TX_AF_OWS_HP(Resp_HdrLink, RGen_HdrOtherV, 45);

	/* Location header processing. */
	__FSM_TX_AF(Resp_HdrLo, 'c', Resp_HdrLoc);
	__FSM_TX_AF(Resp_HdrLoc, 'a', Resp_HdrLoca);
	__FSM_TX_AF(Resp_HdrLoca, 't', Resp_HdrLocat);
	__FSM_TX_AF(Resp_HdrLocat, 'i', Resp_HdrLocati);
	__FSM_TX_AF(Resp_HdrLocati, 'o', Resp_HdrLocatio);
	__FSM_TX_AF(Resp_HdrLocatio, 'n', Resp_HdrLocation);
	__FSM_TX_AF_OWS_HP(Resp_HdrLocation, RGen_HdrOtherV, 46);

	__FSM_TX_AF(Resp_HdrP, 'r', Resp_HdrPr);
	__FSM_STATE(Resp_HdrPr) {
		switch (TFW_LC(c)) {
		case 'a':
			__FSM_MOVE(Resp_HdrPra);
		case 'o':
			__FSM_MOVE(Resp_HdrPro);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Proxy-Authenticate header processing. */
	__FSM_TX_AF(Resp_HdrPro, 'x', Resp_HdrProx);
	__FSM_TX_AF(Resp_HdrProx, 'y', Resp_HdrProxy);
	__FSM_TX_AF(Resp_HdrProxy, '-', Resp_HdrProxy_);
	__FSM_STATE(Resp_HdrProxy_) {
		switch (TFW_LC(c)) {
		case 'a':
			__FSM_MOVE(Resp_HdrProxy_A);
		case 'c':
			__FSM_MOVE(Resp_HdrProxy_C);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	__FSM_TX_AF(Resp_HdrProxy_A, 'u', Resp_HdrProxy_Au);
	__FSM_TX_AF(Resp_HdrProxy_Au, 't', Resp_HdrProxy_Aut);
	__FSM_TX_AF(Resp_HdrProxy_Aut, 'h', Resp_HdrProxy_Auth);
	__FSM_TX_AF(Resp_HdrProxy_Auth, 'e', Resp_HdrProxy_Authe);
	__FSM_TX_AF(Resp_HdrProxy_Authe, 'n', Resp_HdrProxy_Authen);
	__FSM_TX_AF(Resp_HdrProxy_Authen, 't', Resp_HdrProxy_Authent);
	__FSM_TX_AF(Resp_HdrProxy_Authent, 'i', Resp_HdrProxy_Authenti);
	__FSM_TX_AF(Resp_HdrProxy_Authenti, 'c', Resp_HdrProxy_Authentic);
	__FSM_TX_AF(Resp_HdrProxy_Authentic, 'a', Resp_HdrProxy_Authentica);
	__FSM_TX_AF(Resp_HdrProxy_Authentica, 't', Resp_HdrProxy_Authenticat);
	__FSM_TX_AF(Resp_HdrProxy_Authenticat, 'e', Resp_HdrProxy_Authenticate);
	__FSM_TX_AF_OWS_HP(Resp_HdrProxy_Authenticate, RGen_HdrOtherV, 48);

	__FSM_TX_AF(Resp_HdrProxy_C, 'o', Resp_HdrProxy_Co);
	__FSM_TX_AF(Resp_HdrProxy_Co, 'n', Resp_HdrProxy_Con);
	__FSM_TX_AF(Resp_HdrProxy_Con, 'n', Resp_HdrProxy_Conn);
	__FSM_TX_AF(Resp_HdrProxy_Conn, 'e', Resp_HdrProxy_Conne);
	__FSM_TX_AF(Resp_HdrProxy_Conne, 'c', Resp_HdrProxy_Connec);
	__FSM_TX_AF(Resp_HdrProxy_Connec, 't', Resp_HdrProxy_Connect);
	__FSM_TX_AF(Resp_HdrProxy_Connect, 'i', Resp_HdrProxy_Connecti);
	__FSM_TX_AF(Resp_HdrProxy_Connecti, 'o', Resp_HdrProxy_Connectio);
	__FSM_TX_AF(Resp_HdrProxy_Connectio, 'n', Resp_HdrProxy_Connection);
	__FSM_TX_AF_OWS(Resp_HdrProxy_Connection, RGen_HdrOtherV);

	/* Pragma header processing. */
	__FSM_TX_AF(Resp_HdrPra, 'g', Resp_HdrPrag);
	__FSM_TX_AF(Resp_HdrPrag, 'm', Resp_HdrPragm);
	__FSM_TX_AF(Resp_HdrPragm, 'a', Resp_HdrPragma);
	__FSM_TX_AF_OWS(Resp_HdrPragma, Resp_HdrPragmaV);

	/* Retry-After header processing. */
	__FSM_TX_AF(Resp_HdrR, 'e', Resp_HdrRe);
	__FSM_TX_AF(Resp_HdrRe, 't', Resp_HdrRet);
	__FSM_TX_AF(Resp_HdrRet, 'r', Resp_HdrRetr);
	__FSM_TX_AF(Resp_HdrRetr, 'y', Resp_HdrRetry);
	__FSM_TX_AF(Resp_HdrRetry, '-', Resp_HdrRetry_);
	__FSM_TX_AF(Resp_HdrRetry_, 'a', Resp_HdrRetry_A);
	__FSM_TX_AF(Resp_HdrRetry_A, 'f', Resp_HdrRetry_Af);
	__FSM_TX_AF(Resp_HdrRetry_Af, 't', Resp_HdrRetry_Aft);
	__FSM_TX_AF(Resp_HdrRetry_Aft, 'e', Resp_HdrRetry_Afte);
	__FSM_TX_AF(Resp_HdrRetry_Afte, 'r', Resp_HdrRetry_After);
	__FSM_TX_AF_OWS_HP(Resp_HdrRetry_After, RGen_HdrOtherV, 53);

	__FSM_STATE(Resp_HdrS) {
		switch (TFW_LC(c)) {
		case 'e':
			__FSM_MOVE(Resp_HdrSe);
		case 't':
			__FSM_MOVE(Resp_HdrSt);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Strict-Transport-Security header processing. */
	__FSM_TX_AF(Resp_HdrSt, 'r', Resp_HdrStr);
	__FSM_TX_AF(Resp_HdrStr, 'i', Resp_HdrStri);
	__FSM_TX_AF(Resp_HdrStri, 'c', Resp_HdrStric);
	__FSM_TX_AF(Resp_HdrStric, 't', Resp_HdrStrict);
	__FSM_TX_AF(Resp_HdrStrict, '-', Resp_HdrStrict_);
	__FSM_TX_AF(Resp_HdrStrict_, 't', Resp_HdrStrict_T);
	__FSM_TX_AF(Resp_HdrStrict_T, 'r', Resp_HdrStrict_Tr);
	__FSM_TX_AF(Resp_HdrStrict_Tr, 'a', Resp_HdrStrict_Tra);
	__FSM_TX_AF(Resp_HdrStrict_Tra, 'n', Resp_HdrStrict_Tran);
	__FSM_TX_AF(Resp_HdrStrict_Tran, 's', Resp_HdrStrict_Trans);
	__FSM_TX_AF(Resp_HdrStrict_Trans, 'p', Resp_HdrStrict_Transp);
	__FSM_TX_AF(Resp_HdrStrict_Transp, 'o', Resp_HdrStrict_Transpo);
	__FSM_TX_AF(Resp_HdrStrict_Transpo, 'r', Resp_HdrStrict_Transpor);
	__FSM_TX_AF(Resp_HdrStrict_Transpor, 't', Resp_HdrStrict_Transport);
	__FSM_TX_AF(Resp_HdrStrict_Transport, '-', Resp_HdrStrict_Transport_);
	__FSM_TX_AF(Resp_HdrStrict_Transport_, 's', Resp_HdrStrict_Transport_S);
	__FSM_TX_AF(Resp_HdrStrict_Transport_S, 'e',
		    Resp_HdrStrict_Transport_Se);
	__FSM_TX_AF(Resp_HdrStrict_Transport_Se, 'c',
		    Resp_HdrStrict_Transport_Sec);
	__FSM_TX_AF(Resp_HdrStrict_Transport_Sec, 'u',
		    Resp_HdrStrict_Transport_Secu);
	__FSM_TX_AF(Resp_HdrStrict_Transport_Secu, 'r',
		    Resp_HdrStrict_Transport_Secur);
	__FSM_TX_AF(Resp_HdrStrict_Transport_Secur, 'i',
		    Resp_HdrStrict_Transport_Securi);
	__FSM_TX_AF(Resp_HdrStrict_Transport_Securi, 't',
		    Resp_HdrStrict_Transport_Securit);
	__FSM_TX_AF(Resp_HdrStrict_Transport_Securit, 'y',
		    Resp_HdrStrict_Transport_Security);
	__FSM_TX_AF_OWS_HP(Resp_HdrStrict_Transport_Security,
			   RGen_HdrOtherV, 56);

	__FSM_STATE(Resp_HdrSe) {
		switch (TFW_LC(c)) {
		case 'r':
			__FSM_MOVE(Resp_HdrSer);
		case 't':
			__FSM_MOVE(Resp_HdrSet);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Server header processing. */
	__FSM_TX_AF(Resp_HdrSer, 'v', Resp_HdrServ);
	__FSM_TX_AF(Resp_HdrServ, 'e', Resp_HdrServe);
	__FSM_TX_AF(Resp_HdrServe, 'r', Resp_HdrServer);
	__FSM_TX_AF_OWS_HP(Resp_HdrServer, Resp_HdrServerV, 54);

	/* Set-Cookie header processing. */
	__FSM_TX_AF(Resp_HdrSet, '-', Resp_HdrSet_);
	__FSM_TX_AF(Resp_HdrSet_, 'c', Resp_HdrSet_C);
	__FSM_TX_AF(Resp_HdrSet_C, 'o', Resp_HdrSet_Co);
	__FSM_TX_AF(Resp_HdrSet_Co, 'o', Resp_HdrSet_Coo);
	__FSM_TX_AF(Resp_HdrSet_Coo, 'k', Resp_HdrSet_Cook);
	__FSM_TX_AF(Resp_HdrSet_Cook, 'i', Resp_HdrSet_Cooki);
	__FSM_TX_AF(Resp_HdrSet_Cooki, 'e', Resp_HdrSet_Cookie);
	__FSM_TX_AF_OWS_HP(Resp_HdrSet_Cookie, Resp_HdrSet_CookieV, 55);

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

	__FSM_STATE(Resp_HdrV) {
		switch (TFW_LC(c)) {
		case 'a':
			__FSM_MOVE(Resp_HdrVa);
		case 'i':
			__FSM_MOVE(Resp_HdrVi);
		default:
			__FSM_JMP(RGen_HdrOtherN);
		}
	}

	/* Vary header processing. */
	__FSM_TX_AF(Resp_HdrVa, 'r', Resp_HdrVar);
	__FSM_TX_AF(Resp_HdrVar, 'y', Resp_HdrVary);
	__FSM_TX_AF_OWS_HP(Resp_HdrVary, RGen_HdrOtherV, 59);

	/* Via header processing. */
	__FSM_TX_AF(Resp_HdrVi, 'a', Resp_HdrVia);
	__FSM_TX_AF_OWS_HP(Resp_HdrVia, RGen_HdrOtherV, 60);

	/* WWW-Authenticate header processing. */
	__FSM_TX_AF(Resp_HdrW, 'w', Resp_HdrWW);
	__FSM_TX_AF(Resp_HdrWW, 'w', Resp_HdrWWW);
	__FSM_TX_AF(Resp_HdrWWW, '-', Resp_HdrWWW_);
	__FSM_TX_AF(Resp_HdrWWW_, 'a', Resp_HdrWWW_A);
	__FSM_TX_AF(Resp_HdrWWW_A, 'u', Resp_HdrWWW_Au);
	__FSM_TX_AF(Resp_HdrWWW_Au, 't', Resp_HdrWWW_Aut);
	__FSM_TX_AF(Resp_HdrWWW_Aut, 'h', Resp_HdrWWW_Auth);
	__FSM_TX_AF(Resp_HdrWWW_Auth, 'e', Resp_HdrWWW_Authe);
	__FSM_TX_AF(Resp_HdrWWW_Authe, 'n', Resp_HdrWWW_Authen);
	__FSM_TX_AF(Resp_HdrWWW_Authen, 't', Resp_HdrWWW_Authent);
	__FSM_TX_AF(Resp_HdrWWW_Authent, 'i', Resp_HdrWWW_Authenti);
	__FSM_TX_AF(Resp_HdrWWW_Authenti, 'c', Resp_HdrWWW_Authentic);
	__FSM_TX_AF(Resp_HdrWWW_Authentic, 'a', Resp_HdrWWW_Authentica);
	__FSM_TX_AF(Resp_HdrWWW_Authentica, 't', Resp_HdrWWW_Authenticat);
	__FSM_TX_AF(Resp_HdrWWW_Authenticat, 'e', Resp_HdrWWW_Authenticate);
	__FSM_TX_AF_OWS_HP(Resp_HdrWWW_Authenticate, RGen_HdrOtherV, 61);

	/* Upgrade header processing. */
	__FSM_TX_AF(Resp_HdrU, 'p', Resp_HdrUp);
	__FSM_TX_AF(Resp_HdrUp, 'g', Resp_HdrUpg);
	__FSM_TX_AF(Resp_HdrUpg, 'r', Resp_HdrUpgr);
	__FSM_TX_AF(Resp_HdrUpgr, 'a', Resp_HdrUpgra);
	__FSM_TX_AF(Resp_HdrUpgra, 'd', Resp_HdrUpgrad);
	__FSM_TX_AF(Resp_HdrUpgrad, 'e', Resp_HdrUpgrade);
	__FSM_TX_AF_OWS(Resp_HdrUpgrade, Resp_HdrUpgradeV);

	__FSM_FINISH(resp);

	return r;
}
STACK_FRAME_NON_STANDARD(tfw_http_parse_resp);

bool
tfw_http_parse_is_done(TfwHttpMsg *hm)
{
	return test_bit(TFW_HTTP_B_FULLY_PARSED, hm->flags);
}
