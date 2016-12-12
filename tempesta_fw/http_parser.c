/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#include <linux/kernel.h>

#include "gfsm.h"
#include "http_msg.h"
#include "htype.h"

/*
 * ------------------------------------------------------------------------
 *	Common HTTP parsing routines
 * ------------------------------------------------------------------------
 */

/* Common states. */
enum {
	RGen_OWS = 10000,

	RGen_EoL,
	RGen_CR,
	RGen_CRLFCR,

	RGen_Hdr,
	RGen_HdrOther,
	RGen_HdrOtherN,
	RGen_HdrOtherV,

	RGen_BodyInit,
	RGen_BodyStart,
	RGen_BodyChunk,
	RGen_BodyChunkLen,
	RGen_BodyChunkExt,
	RGen_BodyReadChunk,
	RGen_BodyEoL,
	RGen_BodyCR,
};

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
 * must be raised.
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

#define __msg_hdr_chunk_fixup(data, len)				\
	tfw_http_msg_add_str_data(msg, &msg->parser.hdr, data, len)

/**
 * GCC 4.8 (CentOS 7) does a poor work on memory reusage of automatic local
 * variables in nested blocks, so we declare all required temporal variables
 * used in the defines below here to reduce stack frame usage.
 * Since the variables are global now, be careful with them.
 */
#define __FSM_DECLARE_VARS(ptr)						\
	TfwHttpMsg	*msg = (TfwHttpMsg *)(ptr);			\
	TfwHttpParser	*parser = &msg->parser;				\
	unsigned char	*p = data;					\
	unsigned char	c = *p;						\
	int		__fsm_const_state;				\
	int		__maybe_unused __fsm_n;				\
	size_t		__maybe_unused __fsm_sz;			\
	TfwStr		__maybe_unused *chunk = &parser->_tmp_chunk;	\

#define TFW_PARSER_BLOCK(st)						\
do {									\
	TFW_WARN("Parser error: state=" #st " input=%#x('%.*s')"	\
		 " data_len=%lu off=%lu\n",				\
		 (char)c, min(16U, (unsigned int)(data + len - p)), p,	\
		 len, p - data);					\
	return TFW_BLOCK;						\
} while (0)

#define __FSM_START(s)							\
fsm_reenter: __attribute__((unused))					\
	TFW_DBG3("enter FSM at state %d\n", s);				\
switch (s)

#define __FSM_STATE(st)							\
case st:								\
st: __attribute__((unused)) 						\
 	__fsm_const_state = st; /* optimized out to constant */		\
	c = *p;								\
	TFW_DBG3("parser: " #st "(%d:%d): c=%#x(%c), p_off=%ld\n",	\
		 st, parser->_i_st, c, isprint(c) ? c : '.', p - data);

#define __FSM_EXIT()			goto done;

#define FSM_EXIT()							\
do {									\
	p += 1; /* eat current character */				\
	__FSM_EXIT();							\
} while (0)

#define __FSM_FINISH(m)							\
done:									\
	parser->state = __fsm_const_state;				\
	/* Remaining number of bytes to process in the data chunk. */	\
	parser->to_go = __data_remain(p);

#define __FSM_MOVE_nofixup_n(to, n)					\
do {									\
	p += n;								\
	if (unlikely(__data_off(p) >= len)) {				\
		r = TFW_POSTPONE; /* postpone to more data available */	\
		__fsm_const_state = to; /* start from state @to next time */\
		__FSM_EXIT()						\
	}								\
	goto to;							\
} while (0)

#define __FSM_MOVE_nf(to, n, field)					\
do {									\
	p += n;								\
	if (unlikely(__data_off(p) >= len)) {				\
		r = TFW_POSTPONE; /* postpone to more data available */	\
		__fsm_const_state = to; /* start from state @to next time */\
		/* Close currently parsed field chunk. */		\
		BUG_ON(!(field)->ptr);					\
		__msg_field_fixup(field, data + len);			\
		__FSM_EXIT()						\
	}								\
	goto to;							\
} while (0)

#define __FSM_MOVE_nofixup(to)		__FSM_MOVE_nofixup_n(to, 1)
#define __FSM_MOVE_n(to, n)		__FSM_MOVE_nf(to, n, &msg->parser.hdr)
#define __FSM_MOVE_f(to, field)		__FSM_MOVE_nf(to, 1, field)
#define __FSM_MOVE(to)			__FSM_MOVE_nf(to, 1, &msg->parser.hdr)
/* The same as __FSM_MOVE_n(), but exactly for jumps w/o data moving. */
#define __FSM_JMP(to)			do { goto to; } while (0)

#define __FSM_MATCH_MOVE_f(alphabet, to, field)				\
do {									\
	__fsm_n = __data_remain(p);					\
	__fsm_sz = tfw_match_##alphabet(p, __fsm_n);			\
	if (unlikely(__fsm_sz == __fsm_n)) {				\
		/* Continue field processing on next skb. */		\
		BUG_ON(!(field)->ptr);					\
		__msg_field_fixup(field, data + len);			\
		__fsm_const_state = to;					\
		r = TFW_POSTPONE;					\
		p += __fsm_sz;						\
		__FSM_EXIT()						\
	}								\
} while (0)

#define __FSM_MATCH_MOVE(alphabet, to)	__FSM_MATCH_MOVE_f(alphabet, to, \
							   &msg->parser.hdr)

/*
 * __FSM_I_* macros are intended to help with parsing of message
 * header values. That is done with separate, nested, or interior
 * FSMs, and so _I_ in the name means "interior" FSM.
 */

#define __FSM_I_chunk_flags(flag)					\
do {									\
	TFW_DBG3("parser: add chunk flags: %u\n", flag);		\
	TFW_STR_CURR(&msg->parser.hdr)->flags |= flag;		  	\
} while (0)

#define __FSM_I_MOVE_finish_n(to, n, finish)				\
do {									\
	parser->_i_st = to;						\
	p += n;								\
	if (unlikely(__data_off(p) >= len)) {				\
		r = TFW_POSTPONE; /* postpone to more data available */	\
		__fsm_const_state = to; /* start from state @to nest time */\
		/* Close currently parsed field chunk. */		\
		__msg_hdr_chunk_fixup(data, len);			\
		finish;							\
		__FSM_EXIT()						\
	}								\
	goto to;							\
} while (0)

#define __FSM_I_MOVE_n(to, n)  		__FSM_I_MOVE_finish_n(to, n, {})
#define __FSM_I_MOVE(to)		__FSM_I_MOVE_n(to, 1)
/* The same as __FSM_I_MOVE_n(), but exactly for jumps w/o data moving. */
#define __FSM_I_JMP(to)			do { goto to; } while (0)

#define __FSM_I_MATCH_MOVE(alphabet, to)				\
do {									\
	__fsm_n = __data_remain(p);					\
	__fsm_sz = tfw_match_##alphabet(p, __fsm_n);			\
	if (unlikely(__fsm_sz == __fsm_n)) {				\
		__msg_hdr_chunk_fixup(data, len);			\
		parser->_i_st = to;					\
		__fsm_const_state = to;					\
		r = TFW_POSTPONE;					\
		__FSM_EXIT()						\
	}								\
} while (0)

/*
 * The macros below control chunks within a string:
 * i.e. a caller can explicitly chop an ingress contiguous string
 * into multiple chunks thus generating efficient key/value pairs.
 *
 * Fixup the current chunk that starts at the current data pointer
 * @p and has the size @n. Move forward to just after the chunk.
 * We have at least @n bytes as we parsed them before the fixup.
 */
#define __FSM_I_MOVE_fixup(to, n, flag)					\
do {									\
	__msg_hdr_chunk_fixup(p, n);					\
	__FSM_I_chunk_flags(flag);					\
	parser->_i_st = to;						\
	p += n;								\
	if (unlikely(__data_off(p) >= len)) {				\
		r = TFW_POSTPONE;					\
		__fsm_const_state = to;					\
		__FSM_EXIT()						\
	}								\
	goto to;							\
} while (0)

#define __FSM_I_MATCH_MOVE_fixup(alphabet, to, flag)			\
do {									\
	__fsm_n = __data_remain(p);					\
	__fsm_sz = tfw_match_##alphabet(p, __fsm_n);			\
	if (unlikely(__fsm_sz == __fsm_n)) {				\
		__msg_hdr_chunk_fixup(p, __fsm_sz);			\
		__FSM_I_chunk_flags(flag);				\
		parser->_i_st = to;					\
		__fsm_const_state = to;					\
		r = TFW_POSTPONE;					\
		__FSM_EXIT()						\
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
#define __FSM_TX_AF(st, ch, st_next, st_fallback)			\
__FSM_STATE(st) {							\
	if (likely(TFW_LC(c) == ch))					\
		__FSM_MOVE(st_next);					\
	/* It should be checked in st_fallback if `c` is allowed */	\
	__FSM_JMP(st_fallback);						\
}

/* As above, but reads OWS through transitional state. */
#define __FSM_TX_AF_OWS(st, ch, st_next, st_fallback)			\
__FSM_STATE(st) {							\
	if (likely(TFW_LC(c) == ch)) {					\
		parser->_i_st = st_next;				\
		__FSM_MOVE(RGen_OWS);					\
	}								\
	/* It should be checked in st_fallback if `c` is allowed */	\
	__FSM_JMP(st_fallback);						\
}

/**
 * Little endian.
 * These two at the below can be used for characters only.
 */
#define TFW_LC_INT	0x20202020
#define TFW_LC_LONG	0x2020202020202020UL
#define TFW_CHAR4_INT(a, b, c, d)					\
	 ((d << 24) | (c << 16) | (b << 8) | a)
#define TFW_CHAR8_INT(a, b, c, d, e, f, g, h)				\
	 (((long)h << 56) | ((long)g << 48) | ((long)f << 40)		\
	  | ((long)e << 32) | (d << 24) | (c << 16) | (b << 8) | a)
#define TFW_P2LCINT(p)	((*(unsigned int *)(p)) | TFW_LC_INT)
/*
 * Match 4 or 8 characters with conversion to lower case
 * and type conversion to int or long type.
 */
#define C4_INT_LCM(p, a, b, c, d)					\
	 !((*(unsigned int *)(p) | TFW_LC_INT) ^ TFW_CHAR4_INT(a, b, c, d))
#define C8_INT_LCM(p, a, b, c, d, e, f, g, h)				\
	 !((*(unsigned long *)(p) | TFW_LC_LONG)			\
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
 * @chunk->ptr is used to refer to the start of the first string within the
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

	if (unlikely(offset > str_len ||
	    (TFW_LC(*p) != TFW_LC(*(str + offset)))))
		return CSTR_NEQ;

	len = min(len, str_len - offset);
	if (tfw_stricmp_2lc(p, str + offset, len) ||
	    (chunk->len && !tfw_str_eq_cstr_pos(hdr, chunk->ptr, str,
						chunk->len, TFW_STR_EQ_CASEI)))
		return CSTR_NEQ;

	chunk->len += len;
	return len;
}

/**
 * Parse probably chunked string representation of an decimal integer.
 * @return number of parsed bytes.
 */
static int
parse_int_a(unsigned char *data, size_t len, const unsigned long *delimiter_a,
	    unsigned long *acc)
{
	unsigned char *p;

	for (p = data; p - data < len; ++p) {
		if (unlikely(IN_ALPHABET(*p, delimiter_a)))
			return p - data;
		if (unlikely(!isdigit(*p)))
			return CSTR_NEQ;
		if (unlikely(*acc > (UINT_MAX - 10) / 10))
			return CSTR_BADLEN;
		*acc = *acc * 10 + *p - '0';
	}

	return CSTR_POSTPONE;
}

/**
 * Parse an integer followed by a white space.
 */
static inline int
parse_int_ws(unsigned char *data, size_t len, unsigned long *acc)
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
	return parse_int_a(data, len, whitespace_a, acc);
}

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
parse_int_hex(unsigned char *data, size_t len, unsigned long *acc)
{
	unsigned char *p;

	for (p = data; p - data < len; ++p) {
		if (unlikely(IS_CRLF(*p) || (*p == ';')))
			return p - data;
		if (unlikely(!isxdigit(*p)))
			return CSTR_NEQ;
		if (unlikely(*acc > (UINT_MAX - 16) / 16))
			return CSTR_BADLEN;
		*acc = (*acc << 4) + (*p & 0xf) + (*p >> 6) * 9;
	}

	return CSTR_POSTPONE;
}

/* Helping (inferior) states to process particular parts of HTTP message. */
enum {
	I_0, /* initial state */

	I_Conn, /* Connection */
	I_ConnOther,
	I_ContLen, /* Content-Length */
	I_ContType, /* Content-Type */
	I_TransEncod, /* Transfer-Encoding */
	I_TransEncodChunked,
	I_TransEncodOther,

	I_EoT, /* end of term */
};

/* Initialize TRY_STR parsing context */
#define TRY_STR_INIT()							\
	TFW_STR_INIT(chunk)

/**
 * Parsing helpers.
 * @str in TRY_STR_LAMBDA must be in lower case.
 */
#define TRY_STR_LAMBDA(str, lambda, state)				\
	if (!chunk->ptr)						\
		chunk->ptr = p;						\
	__fsm_n = __try_str(&parser->hdr, chunk, p, __data_remain(p),	\
			    str, sizeof(str) - 1);			\
	if (__fsm_n > 0) {						\
		if (chunk->len == (sizeof(str) - 1)) {			\
			lambda;						\
			TRY_STR_INIT();					\
			__FSM_I_MOVE_n(state, __fsm_n);			\
		}							\
		__msg_hdr_chunk_fixup(data, len);			\
		return CSTR_POSTPONE;					\
	}

#define TRY_STR(str, state)						\
	TRY_STR_LAMBDA(str, { }, state)

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
		if (parser->hdr.ptr) {					\
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
	if (parser->hdr.ptr) {						\
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
		if (!msg->crlf.ptr)					\
			/* The end of the headers part. */		\
			tfw_http_msg_set_str_data(msg, &msg->crlf, p);	\
		__FSM_MOVE_f(RGen_CRLFCR, &msg->crlf);			\
	}								\
	if (c == '\n') {						\
		if (!msg->crlf.ptr) {					\
			/*						\
			 * Set data and length explicitly for a single	\
			 * LF w/o calling complex __msg_field_fixup().	\
			 */						\
			tfw_http_msg_set_str_data(msg, &msg->crlf, p);	\
			msg->crlf.len = 1;				\
			msg->crlf.flags |= TFW_STR_COMPLETE;		\
			__FSM_JMP(RGen_BodyInit);			\
		}							\
		r = TFW_PASS;						\
		FSM_EXIT();						\
	}								\
} while (0)

/*
 * State processing a character just after CRLFCR, i.e. the final LF.
 */
#define RGEN_CRLF()							\
__FSM_STATE(RGen_CRLFCR) {						\
	if (unlikely(c != '\n'))					\
		TFW_PARSER_BLOCK(RGen_CRLFCR);				\
	if (!(msg->crlf.flags & TFW_STR_COMPLETE)) {			\
		BUG_ON(!msg->crlf.ptr);					\
		__msg_field_finish(&msg->crlf, p + 1);			\
		__FSM_JMP(RGen_BodyInit);				\
	}								\
	r = TFW_PASS;							\
	FSM_EXIT();							\
}

/*
 * We have HTTP message descriptors and special headers,
 * however we still need to store full headers (instead of just their values)
 * as well as store headers which aren't need in further processing
 * (e.g. Content-Length which is doubled by TfwHttpMsg.conent_length)
 * to mangle row skb data.
 */
#define __TFW_HTTP_PARSE_SPECHDR_VAL(st_curr, st_i, hm, func, id, saveval) \
__FSM_STATE(st_curr) {							\
	BUG_ON(__data_off(p) > len);					\
	__fsm_sz = __data_remain(p);					\
	if (parser->_i_st == I_0) {					\
		TRY_STR_INIT();						\
		parser->_i_st = st_i;					\
	}								\
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
	TFW_DBG3("parse special header " #func ": ret=%d data_len=%lu"	\
		 " id=%d\n", __fsm_n, __fsm_sz, id);			\
	switch (__fsm_n) {						\
	case CSTR_POSTPONE:						\
		/* The automaton state keeping is handled in @func. */	\
		r = TFW_POSTPONE;					\
		p += __fsm_sz;						\
		goto done;						\
	case CSTR_BADLEN: /* bad header length */			\
	case CSTR_NEQ: /* bad header value */				\
		TFW_PARSER_BLOCK(st_curr);				\
	default:							\
		BUG_ON(__fsm_n < 0);					\
		/* The header value is fully parsed, move forward. */	\
		if (saveval)						\
			__msg_hdr_chunk_fixup(p, __fsm_n);		\
		parser->_i_st = RGen_EoL;				\
		parser->_hdr_tag = id;					\
		__FSM_MOVE_n(RGen_OWS, __fsm_n); /* skip OWS */		\
	}								\
}

#define TFW_HTTP_PARSE_SPECHDR_VAL(st_curr, st_i, hm, func, id) \
	__TFW_HTTP_PARSE_SPECHDR_VAL(st_curr, st_i, hm, func, id, 1)

#define TFW_HTTP_PARSE_RAWHDR_VAL(st_curr, st_i, hm, func)		\
__FSM_STATE(st_curr) {							\
	BUG_ON(__data_off(p) > len);					\
	__fsm_sz = __data_remain(p);					\
	if (parser->_i_st == I_0) {					\
		TRY_STR_INIT();						\
		parser->_i_st = st_i;					\
	}								\
	/* In 'func' the  pointer at the beginning of this piece of the request
	 * is not available to us. If the request ends in 'func', we can not
	 * correctly create a new chunk, which includes part of the request
	 * before the header-value, and we lose this part. It should be forced
	 * to save it.*/						\
	__msg_hdr_chunk_fixup(data, p - data);				\
	__fsm_n = func(hm, p, __fsm_sz);				\
	TFW_DBG3("parse raw header " #func ": ret=%d data_len=%lu\n",	\
		 __fsm_n, __fsm_sz);					\
	switch (__fsm_n) {						\
	case CSTR_POSTPONE:						\
		/* The automaton state keeping is handled in @func. */	\
		r = TFW_POSTPONE;					\
		p += __fsm_sz;						\
		goto done;						\
	case CSTR_BADLEN: /* bad header length */			\
	case CSTR_NEQ: /* bad header value */				\
		TFW_PARSER_BLOCK(st_curr);				\
	default:							\
		BUG_ON(__fsm_n < 0);					\
		/* The header value is fully parsed, move forward. */	\
		__msg_hdr_chunk_fixup(p, __fsm_n);			\
		parser->_i_st = RGen_EoL;				\
		parser->_hdr_tag = TFW_HTTP_HDR_RAW;			\
		__FSM_MOVE_n(RGen_OWS, __fsm_n); /* skip OWS */	\
	}								\
}

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
		parser->_i_st = RGen_HdrOtherV;				\
		__FSM_MOVE_n(RGen_OWS, __fsm_sz + 1);			\
	}								\
	TFW_PARSER_BLOCK(RGen_HdrOtherN);				\
}									\
__FSM_STATE(RGen_HdrOtherV) {						\
	/*								\
	 * The header content is opaqueue for us,			\
	 * so pass ctext and VCHAR.					\
	 */								\
	__FSM_MATCH_MOVE(ctext_vchar, RGen_HdrOtherV);			\
	if (!IS_CRLF(*(p + __fsm_sz)))					\
		TFW_PARSER_BLOCK(RGen_HdrOtherV);			\
	__msg_hdr_chunk_fixup(data, __data_off(p + __fsm_sz)); 		\
	__FSM_MOVE_n(RGen_EoL, __fsm_sz);				\
}

/* Process according RFC 7230 3.3.3 */
#define TFW_HTTP_INIT_REQ_BODY_PARSING()				\
__FSM_STATE(RGen_BodyInit) {						\
	TfwStr *tbl = msg->h_tbl->tbl;					\
									\
	TFW_DBG3("parse request body: flags=%#x content_length=%lu\n",	\
		 msg->flags, msg->content_length);			\
									\
	if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_TRANSFER_ENCODING])) {	\
		/* The alternative: remove "Content-Length" header. */	\
		if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_LENGTH]))	\
			TFW_PARSER_BLOCK(RGen_BodyInit);		\
		if (msg->flags & TFW_HTTP_CHUNKED)			\
			__FSM_MOVE_nofixup(RGen_BodyStart);		\
		/*							\
		 * TODO: If "Transfer-Encoding:" header is present and	\
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
	r = TFW_PASS;							\
	FSM_EXIT();							\
}

/* Process according RFC 7230 3.3.3 */
#define TFW_HTTP_INIT_RESP_BODY_PARSING()				\
__FSM_STATE(RGen_BodyInit) {						\
	TfwStr *tbl = msg->h_tbl->tbl;					\
	TfwHttpResp *resp = (TfwHttpResp *)msg;				\
									\
	TFW_DBG3("parse response body: flags=%#x content_length=%lu\n",	\
		 msg->flags, msg->content_length);			\
									\
	/* There's no body. */						\
	/* TODO: Add (req == CONNECT && resp == 2xx) */			\
	if (resp->status - 100U < 100U || resp->status == 204		\
	    || resp->status == 304 || msg->flags & TFW_HTTP_VOID_BODY)	\
	{								\
		/* There is no body. */					\
		msg->body.flags |= TFW_STR_COMPLETE;			\
		r = TFW_PASS;						\
		FSM_EXIT();						\
	}								\
	if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_TRANSFER_ENCODING])) {	\
		/* The alternative: remove "Content-Length" header. */	\
		if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_LENGTH]))	\
			TFW_PARSER_BLOCK(RGen_BodyInit);		\
		if (msg->flags & TFW_HTTP_CHUNKED)			\
			__FSM_MOVE_nofixup(RGen_BodyStart);		\
		__FSM_MOVE_nofixup(Resp_BodyUnlimStart);		\
	}								\
	if (!TFW_STR_EMPTY(&tbl[TFW_HTTP_HDR_CONTENT_LENGTH]))		\
	{								\
		if (msg->content_length) {				\
			parser->to_read = msg->content_length;		\
			__FSM_MOVE_nofixup(RGen_BodyStart);		\
		}							\
		/* There is no body. */					\
		msg->body.flags |= TFW_STR_COMPLETE;			\
		r = TFW_PASS;						\
		FSM_EXIT();						\
	}								\
	/* Process the body until the connection is closed. */		\
	/*								\
	 * TODO: Currently Tempesta fully assembles response before	\
	 * transmitting it to a client. This behaviour is considered	\
	 * dangerous and the issue must be solved in generic way:	\
	 * Tempesta must use chunked transfer encoding for proxied	\
	 * responses w/o lengths. Refer issue #534 for more information	\
	 */								\
	__FSM_MOVE_nofixup(Resp_BodyUnlimStart);			\
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
	TFW_DBG3("read body: to_read=%d\n", parser->to_read);		\
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
	__fsm_sz = min_t(int, parser->to_read, __data_remain(p));	\
	parser->to_read -= __fsm_sz;					\
	if (parser->to_read)						\
		__FSM_MOVE_nf(RGen_BodyReadChunk, __fsm_sz, &msg->body); \
	if (msg->flags & TFW_HTTP_CHUNKED) {				\
		parser->to_read = -1;					\
		__FSM_MOVE_nf(RGen_BodyEoL, __fsm_sz, &msg->body);	\
	}								\
	/* We've fully read Content-Length bytes. */			\
	if (tfw_http_msg_add_str_data(msg, &msg->body, p, __fsm_sz))	\
		TFW_PARSER_BLOCK(RGen_BodyReadChunk);			\
	msg->body.flags |= TFW_STR_COMPLETE;				\
	p += __fsm_sz;							\
	r = TFW_PASS;							\
	goto done;							\
}									\
__FSM_STATE(RGen_BodyChunkLen) {					\
	__fsm_sz = __data_remain(p);					\
	/* Read next chunk length. */					\
	__fsm_n = parse_int_hex(p, __fsm_sz, &parser->_acc);		\
	TFW_DBG3("data chunk: remain_len=%zu ret=%d to_read=%lu\n",	\
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
	parser->_i_st = 0;						\
	BUG_ON(unlikely(__data_off(p) >= len));				\
	goto fsm_reenter;						\
}

/**
 * Parse Connection header value, RFC 2616 14.10.
 */
static int
__parse_connection(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st) {

	__FSM_STATE(I_Conn) {
		TRY_STR_LAMBDA("close", {
			if (msg->flags & TFW_HTTP_CONN_KA)
				return CSTR_NEQ;
			msg->flags |= TFW_HTTP_CONN_CLOSE;
		}, I_EoT);
		TRY_STR_LAMBDA("keep-alive", {
			if (msg->flags & TFW_HTTP_CONN_CLOSE)
				return CSTR_NEQ;
			msg->flags |= TFW_HTTP_CONN_KA;
		}, I_EoT);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(I_ConnOther, 0);
	}

	/*
	 * Other connection tokens. Popular examples of the "Connection:"
	 * header value are "Keep-Alive, TE" or "TE, close". However,
	 * it could be names of any headers, including custom headers.
	 */
	__FSM_STATE(I_ConnOther) {
		__FSM_I_MATCH_MOVE(token, I_ConnOther);
		c = *(p + __fsm_sz);
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
		if (IS_TOKEN(c))
			__FSM_I_MOVE_n(I_Conn, 0);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

	} /* FSM END */
done:
	TFW_DBG3("parser: Connection parsed: flags %#x\n", msg->flags);

	return r;
}

/**
 * Parse Content-Length header value, RFC 2616 14.13.
 */
static int
__parse_content_length(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	int r;

	/*
	 * According to RFC 7230 section 3.3.2:
	 *
	 * TODO: If a message is received that has multiple Content-Length
	 * header fields with field-values consisting of the same decimal
	 * value, or a single Content-Length header field with a field
	 * value containing a list of identical decimal values (e.g.,
	 * "Content-Length: 42, 42"), indicating that duplicate
	 * Content-Length header fields have been generated or combined by
	 * an upstream message processor, then the recipient MUST either
	 * reject the message as invalid or replace the duplicated
	 * field-values with a single valid Content-Length field containing
	 * that decimal value prior to determining the message body length
	 * or forwarding the message.
	 */
	r = parse_int_ws(data, len, &msg->content_length);
	if (r == CSTR_POSTPONE)
		__msg_hdr_chunk_fixup(data, len);

	TFW_DBG3("%s: content_length=%lu\n", __func__, msg->content_length);

	return r;
}

/**
 * Parse Content-Type header value, RFC 7231 3.1.1.5.
 */
static int
__parse_content_type(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st) {

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

	} /* FSM END */
done:
	return r;
}

/**
 * Parse Transfer-Encoding header value, RFC 2616 14.41 and 3.6.
 */
static int
__parse_transfer_encoding(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st) {

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
			if ((status - 100U < 100U) || (status == 204))
				return CSTR_NEQ;
		}
		__FSM_I_JMP(I_TransEncodChunked);
	}

	__FSM_STATE(I_TransEncodChunked) {
		/*
		 * A sender MUST NOT apply chunked more than once
		 * to a message body (i.e., chunking an already
		 * chunked message is not allowed). RFC 7230 3.3.1.
		 */
		TRY_STR_LAMBDA("chunked", {
			if (unlikely(msg->flags & TFW_HTTP_CHUNKED))
				return CSTR_NEQ;
			msg->flags |= TFW_HTTP_CHUNKED;
		}, I_EoT);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(I_TransEncodOther, 0);
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
			if (unlikely(msg->flags & TFW_HTTP_CHUNKED))
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
			__FSM_I_MOVE_n(I_TransEncodChunked, 0);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

	} /* FSM END */
done:
	return r;
}

/*
 * ------------------------------------------------------------------------
 *	HTTP request parsing
 * ------------------------------------------------------------------------
 */
/* Main (parent) HTTP request processing states. */
enum {
	Req_0,
	/* Request line. */
	Req_Method,
	Req_MethG,
	Req_MethGe,
	Req_MethH,
	Req_MethHe,
	Req_MethHea,
	Req_MethP,
	Req_MethPo,
	Req_MethPos,
	Req_MUSpace,
	Req_Uri,
	Req_UriSchH,
	Req_UriSchHt,
	Req_UriSchHtt,
	Req_UriSchHttp,
	Req_UriSchHttpColon,
	Req_UriSchHttpColonSlash,
	/* RFC 3986, 3.2:
	 * authority = [userinfo@]host[:port]
	 * We have a special state for parsing :port, so
	 * in Req_UriAuthority* we parse [userinfo@]host.
	 */
	Req_UriAuthorityStart,
	Req_UriAuthority,
	Req_UriAuthorityResetHost,
	Req_UriAuthorityIPv6,
	Req_UriAuthorityEnd,
	Req_UriPort,
	Req_UriAbsPath,
	Req_HttpVer,
	Req_HttpVerT1,
	Req_HttpVerT2,
	Req_HttpVerP,
	Req_HttpVerSlash,
	Req_HttpVer11,
	Req_HttpVerDot,
	Req_HttpVer12,
	/* Headers. */
	Req_Hdr,
	Req_HdrA,
	Req_HdrAu,
	Req_HdrAut,
	Req_HdrAuth,
	Req_HdrAutho,
	Req_HdrAuthor,
	Req_HdrAuthori,
	Req_HdrAuthoriz,
	Req_HdrAuthoriza,
	Req_HdrAuthorizat,
	Req_HdrAuthorizati,
	Req_HdrAuthorizatio,
	Req_HdrAuthorization,
	Req_HdrAuthorizationV,
	Req_HdrC,
	Req_HdrCa,
	Req_HdrCac,
	Req_HdrCach,
	Req_HdrCache,
	Req_HdrCache_,
	Req_HdrCache_C,
	Req_HdrCache_Co,
	Req_HdrCache_Con,
	Req_HdrCache_Cont,
	Req_HdrCache_Contr,
	Req_HdrCache_Contro,
	Req_HdrCache_Control,
	Req_HdrCache_ControlV,
	Req_HdrCo,
	Req_HdrCon,
	Req_HdrConn,
	Req_HdrConne,
	Req_HdrConnec,
	Req_HdrConnect,
	Req_HdrConnecti,
	Req_HdrConnectio,
	Req_HdrConnection,
	Req_HdrConnectionV,
	Req_HdrCont,
	Req_HdrConte,
	Req_HdrConten,
	Req_HdrContent,
	Req_HdrContent_,
	Req_HdrContent_L,
	Req_HdrContent_Le,
	Req_HdrContent_Len,
	Req_HdrContent_Leng,
	Req_HdrContent_Lengt,
	Req_HdrContent_Length,
	Req_HdrContent_LengthV,
	Req_HdrContent_T,
	Req_HdrContent_Ty,
	Req_HdrContent_Typ,
	Req_HdrContent_Type,
	Req_HdrContent_TypeV,
	Req_HdrCoo,
	Req_HdrCook,
	Req_HdrCooki,
	Req_HdrCookie,
	Req_HdrCookieV,
	Req_HdrH,
	Req_HdrHo,
	Req_HdrHos,
	Req_HdrHost,
	Req_HdrHostV,
	Req_HdrP,
	Req_HdrPr,
	Req_HdrPra,
	Req_HdrPrag,
	Req_HdrPragm,
	Req_HdrPragma,
	Req_HdrPragmaV,
	Req_HdrT,
	Req_HdrTr,
	Req_HdrTra,
	Req_HdrTran,
	Req_HdrTrans,
	Req_HdrTransf,
	Req_HdrTransfe,
	Req_HdrTransfer,
	Req_HdrTransfer_,
	Req_HdrTransfer_E,
	Req_HdrTransfer_En,
	Req_HdrTransfer_Enc,
	Req_HdrTransfer_Enco,
	Req_HdrTransfer_Encod,
	Req_HdrTransfer_Encodi,
	Req_HdrTransfer_Encodin,
	Req_HdrTransfer_Encoding,
	Req_HdrTransfer_EncodingV,
	Req_HdrU,
	Req_HdrUs,
	Req_HdrUse,
	Req_HdrUser,
	Req_HdrUser_,
	Req_HdrUser_A,
	Req_HdrUser_Ag,
	Req_HdrUser_Age,
	Req_HdrUser_Agen,
	Req_HdrUser_Agent,
	Req_HdrUser_AgentV,
	Req_HdrX,
	Req_HdrX_,
	Req_HdrX_F,
	Req_HdrX_Fo,
	Req_HdrX_For,
	Req_HdrX_Forw,
	Req_HdrX_Forwa,
	Req_HdrX_Forwar,
	Req_HdrX_Forward,
	Req_HdrX_Forwarde,
	Req_HdrX_Forwarded,
	Req_HdrX_Forwarded_,
	Req_HdrX_Forwarded_F,
	Req_HdrX_Forwarded_Fo,
	Req_HdrX_Forwarded_For,
	Req_HdrX_Forwarded_ForV,
	/* Body */
	/* URI normalization. */
	Req_UriNorm,
};

#ifdef TFW_HTTP_NORMALIZATION
#define TFW_HTTP_URI_HOOK	Req_UriNorm
#else
#define TFW_HTTP_URI_HOOK	Req_UriAbsPath
#endif

/*
 * Helping (interior) FSM states
 * for processing specific parts of an HTTP request.
 */
enum {
	Req_I_0,

	/* Host header */
	Req_I_H_Start,
	Req_I_H,
	Req_I_H_v6,
	Req_I_H_v6_End,
	Req_I_H_Port,
	/* Cache-Control header */
	Req_I_Auth,
	Req_I_CC,
	Req_I_CC_m,
	Req_I_CC_n,
	Req_I_CC_o,
	Req_I_CC_MaxAgeV,
	Req_I_CC_MinFreshV,
	Req_I_CC_MaxStale,
	Req_I_CC_MaxStaleV,
	Req_I_CC_Ext,
	/* Pragma header */
	Req_I_Pragma,
	Req_I_Pragma_Ext,
	/* X-Forwarded-For header */
	Req_I_XFF,
	Req_I_XFF_Node_Id,
	Req_I_XFF_Sep,
	/* User-Agent */
	Req_I_UserAgent,
	/* Cookie header */
	Req_I_CookieStart,
	Req_I_CookieName,
	Req_I_CookieVal,
	Req_I_CookieSemicolon,
	Req_I_CookieSP,

	Req_I_EoT,
};

static int
__req_parse_authorization(TfwHttpReq *req, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st) {

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

	} /* FSM END */

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

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Req_I_CC) {
		switch (TFW_LC(c)) {
		case 'm':
			__FSM_I_MOVE_n(Req_I_CC_m, 0);
		case 'n':
			__FSM_I_MOVE_n(Req_I_CC_n, 0);
		case 'o':
			__FSM_I_MOVE_n(Req_I_CC_o, 0);
		}
		__FSM_I_MOVE_n(Req_I_CC_Ext, 0);
	}

	__FSM_STATE(Req_I_CC_m) {
		TRY_STR("max-age=", Req_I_CC_MaxAgeV);
		TRY_STR("min-fresh=", Req_I_CC_MinFreshV);
		TRY_STR("max-stale", Req_I_CC_MaxStale);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(Req_I_CC_Ext, 0);
	}

	__FSM_STATE(Req_I_CC_n) {
		TRY_STR_LAMBDA("no-cache", {
			req->cache_ctl.flags |= TFW_HTTP_CC_NO_CACHE;
		}, Req_I_EoT);
		TRY_STR_LAMBDA("no-store", {
			req->cache_ctl.flags |= TFW_HTTP_CC_NO_STORE;
		}, Req_I_EoT);
		TRY_STR_LAMBDA("no-transform", {
			req->cache_ctl.flags |= TFW_HTTP_CC_NO_TRANSFORM;
		}, Req_I_EoT);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(Req_I_CC_Ext, 0);
	}

	__FSM_STATE(Req_I_CC_o) {
		TRY_STR_LAMBDA("only-if-cached", {
			req->cache_ctl.flags |= TFW_HTTP_CC_OIFCACHED;
		}, Req_I_EoT);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(Req_I_CC_Ext, 0);
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
		parser->_acc = 0;
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
		parser->_acc = 0;
		__FSM_I_MOVE_n(Req_I_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_MaxStale) {
		if (c == '=')
			__FSM_I_MOVE(Req_I_CC_MaxStaleV);
		req->cache_ctl.max_stale = UINT_MAX;
		req->cache_ctl.flags |= TFW_HTTP_CC_MAX_STALE;
		__FSM_I_MOVE_n(Req_I_EoT, 0);
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
		parser->_acc = 0;
		__FSM_I_MOVE_n(Req_I_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_Ext) {
		/* TODO: process cache extensions. */
		__FSM_I_MATCH_MOVE(qetoken, Req_I_CC_Ext);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(Req_I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(Req_I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(Req_I_EoT);
		if (IS_TOKEN(c))
			__FSM_I_MOVE_n(Req_I_CC, 0);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

	} /* FSM END */
done:
	return r;
}

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
	__FSM_START(parser->_i_st) {

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
		 * Fixup current delimeters chunk and move to next parameter
		 * if we can eat ';' and SP at once.
		 */
		if (likely(__data_available(p, 2))) {
			if (likely(*(p + 1) == ' '))
				__FSM_I_MOVE_fixup(Req_I_CookieStart, 2, 0);
			return CSTR_NEQ;
		}
		/*
		 * Only ';' is available now: fixup ';' as independent chunk,
		 * SP willbe fixed up at next enter to the FSM.
		 */
		__FSM_I_MOVE_fixup(Req_I_CookieSP, 1, 0);
	}

	__FSM_STATE(Req_I_CookieSP) {
		if (unlikely(c != ' '))
			return CSTR_NEQ;
		/* Fixup current delimeters chunk and move to next parameter. */
		__FSM_I_MOVE_fixup(Req_I_CookieStart, 1, 0);
	}

	} /* FSM END */
done:
	return r;
}

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

	__FSM_START(parser->_i_st) {

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

	} /* FSM END */
done:
	return r;
}

/**
 * Parse request Pragma header field, RFC 7234 5.4.
 * The meaning of "Pragma: no-cache" in responses is not specified.
 */
static int
__req_parse_pragma(TfwHttpReq *req, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(req);

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Req_I_Pragma) {
		TRY_STR_LAMBDA("no-cache", {
			req->cache_ctl.flags |= TFW_HTTP_CC_PRAGMA_NO_CACHE;
		}, Req_I_Pragma_Ext);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(Req_I_Pragma_Ext, 0);
	}

	__FSM_STATE(Req_I_Pragma_Ext) {
		/* Verify and just skip the extensions. */
		__FSM_I_MATCH_MOVE(qetoken, Req_I_Pragma_Ext);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(Req_I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(Req_I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(Req_I_EoT);
		if (IS_CRLF(c))
			return __data_off(p);
		__FSM_I_MOVE_n(Req_I_Pragma_Ext, 0);
	}

	} /* FSM END */
done:
	return r;
}

static int
__req_parse_user_agent(TfwHttpMsg *hm, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(hm);

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Req_I_UserAgent) {
		__FSM_I_MATCH_MOVE(ctext_vchar, Req_I_UserAgent);
		if (IS_CRLF(*(p + __fsm_sz)))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

	} /* FSM END */

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

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Req_I_XFF) {
		/* Eat OWS before the node ID. */
		if (unlikely(IS_WS(c)))
			__FSM_I_MOVE(Req_I_XFF);
		/*
		 * Eat IP address or host name.
		 *
		 * TODO: parse/validate IP addresses and textual IDs.
		 * Currently we just validate separate characters, but the
		 * whole value may be invalid (e.g. "---[_..[[").
		 */
		__FSM_I_MATCH_MOVE(xff, Req_I_XFF_Node_Id);
		if (unlikely(!__fsm_sz))
			return CSTR_NEQ;
		__FSM_I_MOVE_n(Req_I_XFF_Sep, __fsm_sz);
	}

	/*
	 * At this state we know that we saw at least one character as
	 * a host address and now we can pass zero length token.
	 */
	__FSM_STATE(Req_I_XFF_Node_Id) {
		__FSM_I_MATCH_MOVE(xff, Req_I_XFF_Node_Id);
		__FSM_I_MOVE_n(Req_I_XFF_Sep, __fsm_sz);
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
			__FSM_I_MOVE(Req_I_XFF_Sep);

		/*
		 * Multiple subsequent commas look suspicious, so we don't
		 * stay in this state after the first comma is met.
		 */
		if (likely(c == ','))
			__FSM_I_MOVE(Req_I_XFF);

		return CSTR_NEQ;
	}

	} /* FSM END */
done:
	return r;
}

int
tfw_http_parse_req(void *req_data, unsigned char *data, size_t len)
{
	int r = TFW_BLOCK;
	TfwHttpReq *req = (TfwHttpReq *)req_data;
	__FSM_DECLARE_VARS(req);

	TFW_DBG("parse %lu client data bytes (%.*s%s) on req=%p\n",
		len, min(500, (int)len), data, len > 500 ? "..." : "", req);

	__FSM_START(parser->state) {

	/* ----------------    Request Line    ---------------- */

	__FSM_STATE(Req_0) {
		if (unlikely(IS_CRLF(c)))
			__FSM_MOVE_nofixup(Req_0);
		/* fall through */
	}

	/* HTTP method. */
	__FSM_STATE(Req_Method) {
		/* Fast path: compare 4 characters at once. */
		if (likely(__data_available(p, 4))) {
			switch (*(unsigned int *)p) {
			case TFW_CHAR4_INT('G', 'E', 'T', ' '):
				req->method = TFW_HTTP_METH_GET;
				__FSM_MOVE_nofixup_n(Req_Uri, 4);
			case TFW_CHAR4_INT('H', 'E', 'A', 'D'):
				req->method = TFW_HTTP_METH_HEAD;
				__FSM_MOVE_nofixup_n(Req_MUSpace, 4);
			case TFW_CHAR4_INT('P', 'O', 'S', 'T'):
				req->method = TFW_HTTP_METH_POST;
				__FSM_MOVE_nofixup_n(Req_MUSpace, 4);
			case TFW_CHAR4_INT('P', 'U', 'R', 'G'):
				if (likely(__data_available(p, 5))
				    && (*(p + 4) == 'E'))
				{
					req->method = TFW_HTTP_METH_PURGE;
					__FSM_MOVE_nofixup_n(Req_MUSpace, 5);
				}
			}
			TFW_PARSER_BLOCK(Req_Method); /* Unsupported method */
		}
		/* Slow path: step char-by-char. */
		switch (c) {
		case 'G':
			__FSM_MOVE_nofixup(Req_MethG);
		case 'H':
			__FSM_MOVE_nofixup(Req_MethH);
		case 'P':
			__FSM_MOVE_nofixup(Req_MethP);
		}
		TFW_PARSER_BLOCK(Req_Method); /* Unsupported method */
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
		if (likely(c == '/')) {
			__msg_field_open(&req->uri_path, p);
			__FSM_MOVE_f(Req_UriAbsPath, &req->uri_path);
		}
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
	 * parsed later). At the begining we don't know, which of variants we
	 * have. So we fill req->host, and if we get '@', we copy host to
	 * req->userinfo, reset req->host and fill it.
	 */
	__FSM_STATE(Req_UriAuthorityStart) {
		req->flags |= TFW_HTTP_URI_FULL;
		if (likely(isalnum(c) || c == '.' || c == '-')) {
			__msg_field_open(&req->host, p);
			__FSM_MOVE_f(Req_UriAuthority, &req->host);
		} else if (likely(c == '/')) {
			/*
			 * The case where "Host:" header value is empty.
			 * A special TfwStr{} string is created that has
			 * a valid pointer and the length of zero.
			 */
			TFW_DBG3("Handling http:///path\n");
			tfw_http_msg_set_str_data(msg, &req->host, p);
			req->host.flags |= TFW_STR_COMPLETE;
			__FSM_MOVE_f(Req_UriAbsPath, &req->uri_path);
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
					TFW_DBG("Second '@' in authority\n");
					TFW_PARSER_BLOCK(Req_UriAuthority);
				}
				TFW_DBG3("Authority contains userinfo\n");
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
		/* Authority End */
		__msg_field_finish(&req->host, p);
		TFW_DBG3("Userinfo len = %i, host len = %i\n",
			 (int)req->userinfo.len, (int)req->host.len);
		if (likely(c == '/')) {
			__msg_field_open(&req->uri_path, p);
			__FSM_MOVE_f(Req_UriAbsPath, &req->uri_path);
		}
		else if (c == ' ') {
			__FSM_MOVE_nofixup(Req_HttpVer);
		}
		else if (c == ':') {
			__FSM_MOVE_nofixup(Req_UriPort);
		}
		else {
			TFW_PARSER_BLOCK(Req_UriAuthorityEnd);
		}
	}

	/* Host port in URI */
	__FSM_STATE(Req_UriPort) {
		if (likely(isdigit(c)))
			__FSM_MOVE_nofixup(Req_UriPort);
		else if (likely(c == '/')) {
			__msg_field_open(&req->uri_path, p);
			__FSM_MOVE_f(Req_UriAbsPath, &req->uri_path);
		}
		else if (c == ' ') {
			__FSM_MOVE_nofixup(Req_HttpVer);
		}
		else {
			TFW_PARSER_BLOCK(Req_UriPort);
		}
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
			__msg_field_finish(&req->uri_path, p);
			__FSM_MOVE_nofixup(Req_HttpVer);
		}
		__FSM_MATCH_MOVE_f(uri, TFW_HTTP_URI_HOOK, &req->uri_path);
		if (unlikely(*(p + __fsm_sz) != ' '))
			TFW_PARSER_BLOCK(Req_UriAbsPath);
		__msg_field_finish(&req->uri_path, p + __fsm_sz);
		__FSM_MOVE_nofixup_n(Req_HttpVer, __fsm_sz + 1);
	}

	/* URI normalization if enabled. */
	#define TFW_HTTP_NORM_URI
	#include "http_norm.h"
	#undef TFW_HTTP_NORM_URI

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
			if (likely(__data_available(p, 14)
				   && C8_INT_LCM(p + 1, 'u', 't', 'h', 'o',
							'r', 'i', 'z', 'a')
				   && C4_INT_LCM(p + 9, 't', 'i', 'o', 'n')
				   && *(p + 13) == ':'))
			{
				parser->_i_st = Req_HdrAuthorizationV;
				__FSM_MOVE_n(RGen_OWS, 14);
			}
			__FSM_MOVE(Req_HdrA);
		case 'c':
			/* Ensure we have enough data for largest match. */
			if (unlikely(!__data_available(p, 14)))
				__FSM_MOVE(Req_HdrC);
			/* Qick switch for HTTP headers with the same prefix. */
			switch (TFW_P2LCINT(p + 1)) {
			case TFW_CHAR4_INT('a', 'c', 'h', 'e'):
				if (likely(*(p + 5) == '-'
					   && C8_INT_LCM(p + 6, 'c', 'o', 'n',
						                't', 'r', 'o',
								'l', ':')))
				{
					parser->_i_st = Req_HdrCache_ControlV;
					__FSM_MOVE_n(RGen_OWS, 14);
				}
				__FSM_MOVE_n(RGen_HdrOther, 5);
			case TFW_CHAR4_INT('o', 'n', 'n', 'e'):
				if (likely(C4_INT_LCM(p + 5, 'c', 't', 'i', 'o')
					   && TFW_LC(*(p + 9)) == 'n'
					   && *(p + 10) == ':'))
				{
					parser->_i_st = Req_HdrConnectionV;
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
					parser->_i_st = Req_HdrCookieV;
					__FSM_MOVE_n(RGen_OWS, 7);
				}
				__FSM_MOVE_n(RGen_HdrOther, 5);
			default:
				__FSM_MOVE(RGen_HdrOther);
			}
		case 'h':
			if (likely(__data_available(p, 5)
				   && C4_INT_LCM(p + 1, 'o', 's', 't', ':'))) {
				parser->_i_st = Req_HdrHostV;
				parser->_hdr_tag = TFW_HTTP_HDR_HOST;
				__FSM_MOVE_n(RGen_OWS, 5);
			}
			__FSM_MOVE(Req_HdrH);
		case 'p':
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'r', 'a', 'g', 'm')
				   && TFW_LC(*(p + 5)) == 'a'
				   && *(p + 6) == ':'))
			{
				parser->_i_st = Req_HdrPragmaV;
				__FSM_MOVE_n(RGen_OWS, 7);
			}
			__FSM_MOVE(Req_HdrP);
		case 't':
			if (likely(__data_available(p, 18)
				   && C8_INT_LCM(p, 't', 'r', 'a', 'n',
						    's', 'f', 'e', 'r')
				   && *(p + 8) == '-'
				   && C8_INT_LCM(p + 9, 'e', 'n', 'c', 'o',
							'd', 'i', 'n', 'g')
				   && *(p + 17) == ':'))
			{
				parser->_i_st = Req_HdrTransfer_EncodingV;
				__FSM_MOVE_n(RGen_OWS, 18);
			}
			__FSM_MOVE(Req_HdrT);
		case 'x':
			if (likely(__data_available(p, 16)
				   && *(p + 1) == '-'
				   && *(p + 11) == '-'
				   && C8_INT_LCM(p, 'x', '-', 'f', 'o',
						    'r', 'w', 'a', 'r')
				   && C8_INT_LCM(p + 8, 'd', 'e', 'd', '-',
							'f', 'o', 'r', ':')))
			{
				parser->_i_st = Req_HdrX_Forwarded_ForV;
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
				parser->_i_st = Req_HdrUser_AgentV;
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
				parser->_i_st = Req_HdrContent_LengthV;
				__FSM_MOVE_n(RGen_OWS, 7);
			}
			__FSM_MOVE(Req_HdrContent_L);
		case 't':
			if (likely(__data_available(p, 5)
				   && C4_INT_LCM(p + 1, 'y', 'p', 'e', ':')))
			{
				parser->_i_st = Req_HdrContent_TypeV;
				__FSM_MOVE_n(RGen_OWS, 5);
			}
			__FSM_MOVE(Req_HdrContent_T);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* 'Authorization:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrAuthorizationV, Req_I_Auth,
				  req, __req_parse_authorization);

	/* 'Cache-Control:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrCache_ControlV, Req_I_CC, req,
				  __req_parse_cache_control);

	/* 'Connection:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrConnectionV, I_Conn, msg,
				   __parse_connection, TFW_HTTP_HDR_CONNECTION);

	/* 'Content-Length:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrContent_LengthV, I_ContLen,
				   msg, __parse_content_length,
				   TFW_HTTP_HDR_CONTENT_LENGTH);

	/* 'Content-Type:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrContent_TypeV, I_ContType,
				   msg, __parse_content_type,
				   TFW_HTTP_HDR_CONTENT_TYPE);

	/* 'Host:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrHostV, Req_I_H_Start, req,
				   __req_parse_host, TFW_HTTP_HDR_HOST);

	/* 'Pragma:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Req_HdrPragmaV, Req_I_Pragma,
				  req, __req_parse_pragma);

	/* 'Transfer-Encoding:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrTransfer_EncodingV, I_TransEncod,
				  msg, __parse_transfer_encoding,
				  TFW_HTTP_HDR_TRANSFER_ENCODING);

	/* 'X-Forwarded-For:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrX_Forwarded_ForV, Req_I_XFF,
				   msg, __req_parse_x_forwarded_for,
				   TFW_HTTP_HDR_X_FORWARDED_FOR);

	/* 'User-Agent:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrUser_AgentV, Req_I_UserAgent,
				   msg, __req_parse_user_agent,
				   TFW_HTTP_HDR_USER_AGENT);

	/* 'Cookie:*OWS' is read, process field-value. */
	__TFW_HTTP_PARSE_SPECHDR_VAL(Req_HdrCookieV, Req_I_CookieStart,
				     msg, __req_parse_cookie,
				     TFW_HTTP_HDR_COOKIE, 0);

	RGEN_HDR_OTHER();
	RGEN_OWS();
	RGEN_EOL();
	RGEN_CRLF();


	/* ----------------    Request body    ---------------- */

	TFW_HTTP_INIT_REQ_BODY_PARSING();
	TFW_HTTP_PARSE_BODY();

	/* ----------------    Improbable states    ---------------- */

	/*
	 * HTTP Method processing.
	 *
	 * GET
	 */
	__FSM_TX_nofixup(Req_MethG, 'E', Req_MethGe);
	__FSM_STATE(Req_MethGe) {
		if (unlikely(c != 'T'))
			TFW_PARSER_BLOCK(Req_MethGe);
		req->method = TFW_HTTP_METH_GET;
		__FSM_MOVE_nofixup(Req_MUSpace);
	}
	/* POST */
	__FSM_TX_nofixup(Req_MethP, 'O', Req_MethPo);
	__FSM_TX_nofixup(Req_MethPo, 'S', Req_MethPos);
	__FSM_STATE(Req_MethPos) {
		if (unlikely(c != 'T'))
			TFW_PARSER_BLOCK(Req_MethPos);
		req->method = TFW_HTTP_METH_POST;
		__FSM_MOVE_nofixup(Req_MUSpace);
	}
	/* HEAD */
	__FSM_TX_nofixup(Req_MethH, 'E', Req_MethHe);
	__FSM_TX_nofixup(Req_MethHe, 'A', Req_MethHea);
	__FSM_STATE(Req_MethHea) {
		if (unlikely(c != 'D'))
			TFW_PARSER_BLOCK(Req_MethHea);
		req->method = TFW_HTTP_METH_HEAD;
		__FSM_MOVE_nofixup(Req_MUSpace);
	}

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

	/* Authorization header processing. */
	__FSM_TX_AF(Req_HdrA, 'u', Req_HdrAu, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAu, 't', Req_HdrAut, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAut, 'h', Req_HdrAuth, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAuth, 'o', Req_HdrAutho, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAutho, 'r', Req_HdrAuthor, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAuthor, 'i', Req_HdrAuthori, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAuthori, 'z', Req_HdrAuthoriz, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAuthoriz, 'a', Req_HdrAuthoriza, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAuthoriza, 't', Req_HdrAuthorizat, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAuthorizat, 'i', Req_HdrAuthorizati, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAuthorizati, 'o', Req_HdrAuthorizatio, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrAuthorizatio, 'n', Req_HdrAuthorization, RGen_HdrOther);
	__FSM_TX_AF_OWS(Req_HdrAuthorization, ':', Req_HdrAuthorizationV, RGen_HdrOther);

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
	__FSM_TX_AF(Req_HdrCa, 'c', Req_HdrCac, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCac, 'h', Req_HdrCach, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCach, 'e', Req_HdrCache, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCache, '-', Req_HdrCache_, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCache_, 'c', Req_HdrCache_C, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCache_C, 'o', Req_HdrCache_Co, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCache_Co, 'n', Req_HdrCache_Con, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCache_Con, 't', Req_HdrCache_Cont, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCache_Cont, 'r', Req_HdrCache_Contr, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCache_Contr, 'o', Req_HdrCache_Contro, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCache_Contro, 'l', Req_HdrCache_Control, RGen_HdrOther);
	__FSM_TX_AF_OWS(Req_HdrCache_Control, ':', Req_HdrCache_ControlV, RGen_HdrOther);

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
	__FSM_TX_AF(Req_HdrConn, 'e', Req_HdrConne, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrConne, 'c', Req_HdrConnec, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrConnec, 't', Req_HdrConnect, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrConnect, 'i', Req_HdrConnecti, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrConnecti, 'o', Req_HdrConnectio, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrConnectio, 'n', Req_HdrConnection, RGen_HdrOther);
	__FSM_TX_AF_OWS(Req_HdrConnection, ':', Req_HdrConnectionV, RGen_HdrOther);

	/* Content-* headers processing. */
	__FSM_TX_AF(Req_HdrCont, 'e', Req_HdrConte, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrConte, 'n', Req_HdrConten, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrConten, 't', Req_HdrContent, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrContent, '-', Req_HdrContent_, RGen_HdrOther);

	/* Content-Length header processing. */
	__FSM_TX_AF(Req_HdrContent_L, 'e', Req_HdrContent_Le, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrContent_Le, 'n', Req_HdrContent_Len, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrContent_Len, 'g', Req_HdrContent_Leng, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrContent_Leng, 't', Req_HdrContent_Lengt, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrContent_Lengt, 'h', Req_HdrContent_Length, RGen_HdrOther);
	__FSM_TX_AF_OWS(Req_HdrContent_Length, ':', Req_HdrContent_LengthV, RGen_HdrOther);

	/* Content-Type header processing. */
	__FSM_TX_AF(Req_HdrContent_T, 'y', Req_HdrContent_Ty, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrContent_Ty, 'p', Req_HdrContent_Typ, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrContent_Typ, 'e', Req_HdrContent_Type, RGen_HdrOther);
	__FSM_TX_AF_OWS(Req_HdrContent_Type, ':', Req_HdrContent_TypeV, RGen_HdrOther);

	/* Host header processing. */
	__FSM_TX_AF(Req_HdrH, 'o', Req_HdrHo, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrHo, 's', Req_HdrHos, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrHos, 't', Req_HdrHost, RGen_HdrOther);
	/* NOTE: Allow empty host field-value there. RFC 7230 5.4. */
	__FSM_STATE(Req_HdrHost) {
		if (likely(c == ':')) {
			parser->_i_st = Req_HdrHostV;
			__FSM_MOVE(RGen_OWS);
		}
		__FSM_JMP(RGen_HdrOther);
	}

	/* Pragma header processing. */
	__FSM_TX_AF(Req_HdrP, 'r', Req_HdrPr, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrPr, 'a', Req_HdrPra, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrPra, 'g', Req_HdrPrag, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrPrag, 'm', Req_HdrPragm, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrPragm, 'a', Req_HdrPragma, RGen_HdrOther);
	__FSM_TX_AF_OWS(Req_HdrPragma, ':', Req_HdrPragmaV, RGen_HdrOther);

	/* Transfer-Encoding header processing. */
	__FSM_TX_AF(Req_HdrT, 'r', Req_HdrTr, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTr, 'a', Req_HdrTra, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTra, 'n', Req_HdrTran, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTran, 's', Req_HdrTrans, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTrans, 'f', Req_HdrTransf, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransf, 'e', Req_HdrTransfe, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransfe, 'r', Req_HdrTransfer, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer, '-', Req_HdrTransfer_, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_, 'e', Req_HdrTransfer_E, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_E, 'n', Req_HdrTransfer_En, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_En, 'c', Req_HdrTransfer_Enc, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_Enc, 'o', Req_HdrTransfer_Enco, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_Enco, 'd', Req_HdrTransfer_Encod, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_Encod, 'i', Req_HdrTransfer_Encodi, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_Encodi, 'n', Req_HdrTransfer_Encodin, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_Encodin, 'g', Req_HdrTransfer_Encoding, RGen_HdrOther);
	__FSM_TX_AF_OWS(Req_HdrTransfer_Encoding, ':', Req_HdrTransfer_EncodingV, RGen_HdrOther);

	/* X-Forwarded-For header processing. */
	__FSM_TX_AF(Req_HdrX, '-', Req_HdrX_, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_, 'f', Req_HdrX_F, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_F, 'o', Req_HdrX_Fo, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_Fo, 'r', Req_HdrX_For, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_For, 'w', Req_HdrX_Forw, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forw, 'a', Req_HdrX_Forwa, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwa, 'r', Req_HdrX_Forwar, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwar, 'd', Req_HdrX_Forward, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forward, 'e', Req_HdrX_Forwarde, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwarde, 'd', Req_HdrX_Forwarded, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwarded, '-', Req_HdrX_Forwarded_, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwarded_, 'f', Req_HdrX_Forwarded_F, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwarded_F, 'o', Req_HdrX_Forwarded_Fo, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwarded_Fo, 'r', Req_HdrX_Forwarded_For, RGen_HdrOther);
	/* NOTE: we don't eat OWS here because RGEN_OWS() doesn't allow '[' after OWS. */
	__FSM_TX_AF_OWS(Req_HdrX_Forwarded_For, ':', Req_HdrX_Forwarded_ForV, RGen_HdrOther);

	/* User-Agent header processing. */
	__FSM_TX_AF(Req_HdrU, 's', Req_HdrUs, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrUs, 'e', Req_HdrUse, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrUse, 'r', Req_HdrUser, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrUser, '-', Req_HdrUser_, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrUser_, 'a', Req_HdrUser_A, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrUser_A, 'g', Req_HdrUser_Ag, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrUser_Ag, 'e', Req_HdrUser_Age, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrUser_Age, 'n', Req_HdrUser_Agen, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrUser_Agen, 't', Req_HdrUser_Agent, RGen_HdrOther);
	__FSM_TX_AF_OWS(Req_HdrUser_Agent, ':', Req_HdrUser_AgentV, RGen_HdrOther);

	/* Cookie header processing. */
	__FSM_TX_AF(Req_HdrCoo, 'k', Req_HdrCook, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCook, 'i', Req_HdrCooki, RGen_HdrOther);
	__FSM_TX_AF(Req_HdrCooki, 'e', Req_HdrCookie, RGen_HdrOther);
	__FSM_TX_AF_OWS(Req_HdrCookie, ':', Req_HdrCookieV, RGen_HdrOther);

	}
	__FSM_FINISH(req);

	return r;
}

/*
 * ------------------------------------------------------------------------
 *	HTTP response parsing
 * ------------------------------------------------------------------------
 */
/* Main (parent) HTTP response processing states. */
enum {
	Resp_0,
	Resp_HttpVer,
	Resp_HttpVerT1,
	Resp_HttpVerT2,
	Resp_HttpVerP,
	Resp_HttpVerSlash,
	Resp_HttpVer11,
	Resp_HttpVerDot,
	Resp_HttpVer12,
	Resp_SSpace,
	Resp_StatusCode,
	Resp_ReasonPhrase,
	/* Headers. */
	Resp_Hdr,
	Resp_HdrA,
	Resp_HdrAg,
	Resp_HdrAge,
	Resp_HdrAgeV,
	Resp_HdrC,
	Resp_HdrCa,
	Resp_HdrCac,
	Resp_HdrCach,
	Resp_HdrCache,
	Resp_HdrCache_,
	Resp_HdrCache_C,
	Resp_HdrCache_Co,
	Resp_HdrCache_Con,
	Resp_HdrCache_Cont,
	Resp_HdrCache_Contr,
	Resp_HdrCache_Contro,
	Resp_HdrCache_Control,
	Resp_HdrCache_ControlV,
	Resp_HdrCo,
	Resp_HdrCon,
	Resp_HdrConn,
	Resp_HdrConne,
	Resp_HdrConnec,
	Resp_HdrConnect,
	Resp_HdrConnecti,
	Resp_HdrConnectio,
	Resp_HdrConnection,
	Resp_HdrConnectionV,
	Resp_HdrCont,
	Resp_HdrConte,
	Resp_HdrConten,
	Resp_HdrContent,
	Resp_HdrContent_,
	Resp_HdrContent_L,
	Resp_HdrContent_Le,
	Resp_HdrContent_Len,
	Resp_HdrContent_Leng,
	Resp_HdrContent_Lengt,
	Resp_HdrContent_Length,
	Resp_HdrContent_LengthV,
	Resp_HdrContent_T,
	Resp_HdrContent_Ty,
	Resp_HdrContent_Typ,
	Resp_HdrContent_Type,
	Resp_HdrContent_TypeV,
	Resp_HdrD,
	Resp_HdrDa,
	Resp_HdrDat,
	Resp_HdrDate,
	Resp_HdrDateV,
	Resp_HdrE,
	Resp_HdrEx,
	Resp_HdrExp,
	Resp_HdrExpi,
	Resp_HdrExpir,
	Resp_HdrExpire,
	Resp_HdrExpires,
	Resp_HdrExpiresV,
	Resp_HdrK,
	Resp_HdrKe,
	Resp_HdrKee,
	Resp_HdrKeep,
	Resp_HdrKeep_,
	Resp_HdrKeep_A,
	Resp_HdrKeep_Al,
	Resp_HdrKeep_Ali,
	Resp_HdrKeep_Aliv,
	Resp_HdrKeep_Alive,
	Resp_HdrKeep_AliveV,
	Resp_HdrS,
	Resp_HdrSe,
	Resp_HdrSer,
	Resp_HdrServ,
	Resp_HdrServe,
	Resp_HdrServer,
	Resp_HdrServerV,
	Resp_HdrT,
	Resp_HdrTr,
	Resp_HdrTra,
	Resp_HdrTran,
	Resp_HdrTrans,
	Resp_HdrTransf,
	Resp_HdrTransfe,
	Resp_HdrTransfer,
	Resp_HdrTransfer_,
	Resp_HdrTransfer_E,
	Resp_HdrTransfer_En,
	Resp_HdrTransfer_Enc,
	Resp_HdrTransfer_Enco,
	Resp_HdrTransfer_Encod,
	Resp_HdrTransfer_Encodi,
	Resp_HdrTransfer_Encodin,
	Resp_HdrTransfer_Encoding,
	Resp_HdrTransfer_EncodingV,
	Resp_HdrDone,

	Resp_BodyUnlimStart,
	Resp_BodyUnlimRead,
};

/*
 * Helping (interior) FSM states
 * for processing specific parts of an HTTP request.
 */
enum {
	Resp_I_0,

	/* Age header */
	Resp_I_Age,
	Resp_I_AgeVal,
	/* Cache-Control header */
	Resp_I_CC,
	Resp_I_CC_m,
	Resp_I_CC_n,
	Resp_I_CC_p,
	Resp_I_CC_s,
	Resp_I_CC_MaxAgeV,
	Resp_I_CC_SMaxAgeV,
	/* Http-Date */
	Resp_I_Date,
	Resp_I_DateDay,
	Resp_I_DateMonthSP,
	Resp_I_DateMonth,
	Resp_I_DateMonth_A,
	Resp_I_DateMonth_J,
	Resp_I_DateMonth_M,
	Resp_I_DateMonth_Other,
	Resp_I_DateYearSP,
	Resp_I_DateYear,
	Resp_I_DateHourSP,
	Resp_I_DateHour,
	Resp_I_DateMinCln,
	Resp_I_DateMin,
	Resp_I_DateSecCln,
	Resp_I_DateSec,
	Resp_I_DateSecSP,
	Resp_I_DateZone,
	/* Keep-Alive header. */
	Resp_I_KeepAlive,
	Resp_I_KeepAliveTO,
	/* Server header. */
	Resp_I_Server,

	Resp_I_Ext,
	Resp_I_EoT,
	Resp_I_EoL,
};

static int
__resp_parse_age(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

	__FSM_START(parser->_i_st) {

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

	} /* FSM END */
done:
	return r;
}

/**
 * Parse response Cache-Control, RFC 2616 14.9
 */
static int
__resp_parse_cache_control(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Resp_I_CC) {
		switch (TFW_LC(c)) {
		case 'm':
			__FSM_I_MOVE_n(Resp_I_CC_m, 0);
		case 'n':
			__FSM_I_MOVE_n(Resp_I_CC_n, 0);
		case 'p':
			__FSM_I_MOVE_n(Resp_I_CC_p, 0);
		case 's':
			__FSM_I_MOVE_n(Resp_I_CC_s, 0);
		}
		__FSM_I_MOVE_n(Resp_I_Ext, 0);
	}

	__FSM_STATE(Resp_I_CC_m) {
		TRY_STR("max-age=", Resp_I_CC_MaxAgeV);
		TRY_STR_LAMBDA("must-revalidate", {
			resp->cache_ctl.flags |= TFW_HTTP_CC_MUST_REVAL;
		}, Resp_I_EoT);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(Resp_I_Ext, 0);
	}

	__FSM_STATE(Resp_I_CC_n) {
		TRY_STR_LAMBDA("no-cache", {
			resp->cache_ctl.flags |= TFW_HTTP_CC_NO_CACHE;
		}, Resp_I_EoT);
		TRY_STR_LAMBDA("no-store", {
			resp->cache_ctl.flags |= TFW_HTTP_CC_NO_STORE;
		}, Resp_I_EoT);
		TRY_STR_LAMBDA("no-transform", {
			resp->cache_ctl.flags |= TFW_HTTP_CC_NO_TRANSFORM;
		}, Resp_I_EoT);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(Resp_I_Ext, 0);
	}

	__FSM_STATE(Resp_I_CC_p) {
		TRY_STR_LAMBDA("public", {
			resp->cache_ctl.flags |= TFW_HTTP_CC_PUBLIC;
		}, Resp_I_EoT);
		TRY_STR_LAMBDA("private", {
			resp->cache_ctl.flags |= TFW_HTTP_CC_PRIVATE;
		}, Resp_I_EoT);
		TRY_STR_LAMBDA("proxy-revalidate", {
			resp->cache_ctl.flags |= TFW_HTTP_CC_PROXY_REVAL;
		}, Resp_I_EoT);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(Resp_I_Ext, 0);
	}

	__FSM_STATE(Resp_I_CC_s) {
		TRY_STR("s-maxage=", Resp_I_CC_SMaxAgeV);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(Resp_I_Ext, 0);
	}

	__FSM_STATE(Resp_I_CC_MaxAgeV) {
		if (unlikely(resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE)) {
			resp->cache_ctl.max_age = 0;
			__FSM_I_MOVE_n(Resp_I_Ext, 0);
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
		parser->_acc = 0;
		__FSM_I_MOVE_n(Resp_I_EoT, __fsm_n);
	}

	__FSM_STATE(Resp_I_CC_SMaxAgeV) {
		if (unlikely(resp->cache_ctl.flags & TFW_HTTP_CC_S_MAXAGE)) {
			resp->cache_ctl.s_maxage = 0;
			__FSM_I_MOVE_n(Resp_I_Ext, 0);
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
		parser->_acc = 0;
		__FSM_I_MOVE_n(Resp_I_EoT, __fsm_n);
	}

	__FSM_STATE(Resp_I_Ext) {
		/* TODO: process cache extensions. */
		__FSM_I_MATCH_MOVE(qetoken, Resp_I_Ext);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(Resp_I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(Resp_I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(Resp_I_EoT);
		/*
		 * TODO
		 * - For the time being we don't support field values for
		 *   no-cache and private fields, so just skip '=[token]*'.
		 */
		if (c == '=')
			__FSM_I_MOVE(Resp_I_Ext);
		if (IS_TOKEN(c))
			__FSM_I_MOVE_n(Resp_I_CC, 0);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

	} /* FSM END */
done:
	return r;
}

/**
 * Parse response Expires, RFC 2616 14.21.
 *
 * We support only RFC 1123 date as it's most usable by modern software.
 * However RFC 2616 reuires that all server and client software MUST support
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
__resp_parse_http_date(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	static const unsigned long colon_a[] ____cacheline_aligned = {
		/* ':' (0x3a)(58) Colon */
		0x0400000000000000UL, 0, 0, 0
	};
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Resp_I_Date) {
		switch (parser->state) {
		case Resp_HdrExpiresV:
			/*
			 * A duplicate invalidates the header's value.
			 * @resp->expires is set to zero - already expired.
			 */
			if (resp->cache_ctl.flags & TFW_HTTP_CC_HDR_EXPIRES)
				__FSM_I_MOVE_n(Resp_I_EoL, 0);
			break;
		case Resp_HdrDateV:
			if (resp->flags & TFW_HTTP_HAS_HDR_DATE)
				return CSTR_NEQ;
			break;
		default:
			TFW_DBG2("%s: Unknown caller's FSM state: [%d]\n",
				 __func__, parser->state);
			BUG();
			return CSTR_NEQ;
		}
		/*
		 * Skip a weekday with comma (e.g. "Sun,") as redundant
		 * information.
		 */
		__fsm_sz = __data_remain(p);
		__fsm_n = __skip_weekday(p, __fsm_sz);
		if (__fsm_sz == __fsm_n)
			__FSM_I_MOVE_n(Resp_I_Date, __fsm_sz);
		if (unlikely(__fsm_n == CSTR_NEQ))
			return CSTR_NEQ;
		__FSM_I_MOVE_n(Resp_I_DateDay, __fsm_n + 1);
	}

	__FSM_STATE(Resp_I_DateDay) {
		__fsm_sz = __data_remain(p);
		/* Parse a 2-digit day. */
		__fsm_n = parse_int_ws(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			return __fsm_n;
		if (parser->_acc < 1 || parser->_acc > 31)
			return CSTR_BADLEN;
		/* Add seconds in full passed days. */
		parser->_date = (parser->_acc - 1) * SEC24H;
		parser->_acc = 0;
		__FSM_I_MOVE_n(Resp_I_DateMonthSP, __fsm_n);
	}

	__FSM_STATE(Resp_I_DateMonthSP) {
		if (likely(c == ' '))
			__FSM_I_MOVE(Resp_I_DateMonth);
		return CSTR_NEQ;
	}

	__FSM_STATE(Resp_I_DateMonth) {
		switch (c) {
		case 'A':
			__FSM_I_MOVE_n(Resp_I_DateMonth_A, 0);
		case 'J':
			__FSM_I_MOVE_n(Resp_I_DateMonth_J, 0);
		case 'M':
			__FSM_I_MOVE_n(Resp_I_DateMonth_M, 0);
		}
		__FSM_I_MOVE_n(Resp_I_DateMonth_Other, 0);
	}

	__FSM_STATE(Resp_I_DateMonth_A) {
		TRY_STR_LAMBDA("apr", {
			parser->_date += SB_APR;
		}, Resp_I_DateYearSP);
		TRY_STR_LAMBDA("aug", {
			parser->_date += SB_AUG;
		}, Resp_I_DateYearSP);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	__FSM_STATE(Resp_I_DateMonth_J) {
		TRY_STR("jan", Resp_I_DateYearSP);
		TRY_STR_LAMBDA("jun", {
			parser->_date += SB_JUN;
		}, Resp_I_DateYearSP);
		TRY_STR_LAMBDA("jul", {
			parser->_date += SB_JUL;
		}, Resp_I_DateYearSP);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	__FSM_STATE(Resp_I_DateMonth_M) {
		TRY_STR_LAMBDA("mar", {
			/* Add SEC24H for leap year on year parsing. */
			parser->_date += SB_MAR;
		}, Resp_I_DateYearSP);
		TRY_STR_LAMBDA("may", {
			parser->_date += SB_MAY;
		}, Resp_I_DateYearSP);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	__FSM_STATE(Resp_I_DateMonth_Other) {
		TRY_STR_LAMBDA("feb", {
			parser->_date += SB_FEB;
		}, Resp_I_DateYearSP);
		TRY_STR_LAMBDA("sep", {
			parser->_date += SB_SEP;
		}, Resp_I_DateYearSP);
		TRY_STR_LAMBDA("oct", {
			parser->_date += SB_OCT;
		}, Resp_I_DateYearSP);
		TRY_STR_LAMBDA("nov", {
			parser->_date += SB_NOV;
		}, Resp_I_DateYearSP);
		TRY_STR_LAMBDA("dec", {
			parser->_date += SB_DEC;
		}, Resp_I_DateYearSP);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	/* Eat SP between Month and Year. */
	__FSM_STATE(Resp_I_DateYearSP) {
		if (c == ' ')
			__FSM_I_MOVE(Resp_I_DateYear);
		return CSTR_NEQ;
	}

	/* 4-digit year. */
	__FSM_STATE(Resp_I_DateYear) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_ws(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			return __fsm_n;
		parser->_date = __year_day_secs(parser->_acc, parser->_date);
		if (parser->_date < 0)
			return CSTR_NEQ;
		parser->_acc = 0;
		__FSM_I_MOVE_n(Resp_I_DateHourSP, __fsm_n);
	}

	__FSM_STATE(Resp_I_DateHourSP) {
		if (likely(c == ' '))
			__FSM_I_MOVE(Resp_I_DateHour);
		return CSTR_NEQ;
	}

	__FSM_STATE(Resp_I_DateHour) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_a(p, __fsm_sz, colon_a, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			return __fsm_n;
		parser->_date += parser->_acc * 3600;
		parser->_acc = 0;
		__FSM_I_MOVE_n(Resp_I_DateMinCln, __fsm_n);
	}

	__FSM_STATE(Resp_I_DateMinCln) {
		if (likely(c == ':'))
			__FSM_I_MOVE(Resp_I_DateMin);
		return CSTR_NEQ;
	}

	__FSM_STATE(Resp_I_DateMin) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_a(p, __fsm_sz, colon_a, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			return __fsm_n;
		parser->_date += parser->_acc * 60;
		parser->_acc = 0;
		__FSM_I_MOVE_n(Resp_I_DateSecCln, __fsm_n);
	}

	__FSM_STATE(Resp_I_DateSecCln) {
		if (likely(c == ':'))
			__FSM_I_MOVE(Resp_I_DateSec);
		return CSTR_NEQ;
	}

	__FSM_STATE(Resp_I_DateSec) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_ws(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			return __fsm_n;
		parser->_date += parser->_acc;
		parser->_acc = 0;
		__FSM_I_MOVE_n(Resp_I_DateSecSP, __fsm_n);
	}

	__FSM_STATE(Resp_I_DateSecSP) {
		if (likely(c == ' '))
			__FSM_I_MOVE(Resp_I_DateZone);
		return CSTR_NEQ;
	}

	__FSM_STATE(Resp_I_DateZone) {
		TRY_STR("gmt", Resp_I_EoL);
		TRY_STR_INIT();
		return CSTR_NEQ;
	}

	__FSM_STATE(Resp_I_EoL) {
		/* Skip the rest of the line. */
		__FSM_I_MATCH_MOVE(nctl, Resp_I_EoL);
		if (!IS_CRLF(*(p + __fsm_sz)))
			return CSTR_NEQ;
		TFW_DBG3("%s: parsed date %lu", __func__, parser->_date);
		switch (parser->state) {
		case Resp_HdrExpiresV:
			resp->cache_ctl.expires = parser->_date;
			resp->cache_ctl.flags |= TFW_HTTP_CC_HDR_EXPIRES;
			break;
		case Resp_HdrDateV:
			resp->date = parser->_date;
			resp->flags |= TFW_HTTP_HAS_HDR_DATE;
			break;
		}
		return __data_off(p + __fsm_sz);
	}

	} /* FSM END */
done:
	return r;
}

/*
 * The value of "Expires:" header field is a date in HTTP-Date format.
 * However, if the format of a date is invalid, that is interpreted
 * as representing a time in the past (i.e., "already expired").
 * See RFC 7234 5.3.
 */
static int
__resp_parse_expires(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int ret = __resp_parse_http_date(resp, data, len);
	if (ret < CSTR_POSTPONE) {  /* (ret < 0) && (ret != POSTPONE) */
		/*
		 * On error just swallow the rest of the line.
		 * @resp->expires is set to zero - already expired.
		 */
		BUG_ON(resp->parser.state != Resp_HdrExpiresV);
		resp->parser._date = 0;
		resp->parser._i_st = Resp_I_EoL;
		ret = __resp_parse_http_date(resp, data, len);
	}
	return ret;
}

static int
__resp_parse_keep_alive(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Resp_I_KeepAlive) {
		TRY_STR("timeout=", Resp_I_KeepAliveTO);
		TRY_STR_INIT();
		__FSM_I_MOVE_n(Resp_I_Ext, 0);
	}

	__FSM_STATE(Resp_I_KeepAliveTO) {
		__fsm_sz = __data_remain(p);
		__fsm_n = parse_int_list(p, __fsm_sz, &parser->_acc);
		if (__fsm_n == CSTR_POSTPONE)
			__msg_hdr_chunk_fixup(data, len);
		if (__fsm_n < 0)
			return __fsm_n;
		resp->keep_alive = parser->_acc;
		parser->_acc = 0;
		__FSM_I_MOVE_n(Resp_I_EoT, __fsm_n);
	}

	/*
	 * Just ignore Keep-Alive extensions. Known extensions:
	 *	max=N
	 */
	__FSM_STATE(Resp_I_Ext) {
		__FSM_I_MATCH_MOVE(qetoken, Resp_I_Ext);
		c = *(p + __fsm_sz);
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE_n(Resp_I_EoT, __fsm_sz + 1);
		if (IS_CRLF(c))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

	/* End of term. */
	__FSM_STATE(Resp_I_EoT) {
		if (IS_WS(c) || c == ',')
			__FSM_I_MOVE(Resp_I_EoT);
		if (c == '=')
			__FSM_I_MOVE(Resp_I_Ext);
		if (IS_TOKEN(c))
			__FSM_I_MOVE_n(Resp_I_KeepAlive, 0);
		if (IS_CRLF(c))
			return __data_off(p);
		return CSTR_NEQ;
	}

	} /* FSM END */
done:
	return r;
}

static int
__resp_parse_server(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	__FSM_DECLARE_VARS(resp);

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Resp_I_Server) {
		/*
		 * Just eat the header value: usually we just replace
		 * the header value.
		 */
		__FSM_I_MATCH_MOVE(ctext_vchar, Resp_I_Server);
		if (IS_CRLF(*(p + __fsm_sz)))
			return __data_off(p + __fsm_sz);
		return CSTR_NEQ;
	}

	} /* FSM END */
done:
	return r;
}

/*
 * The connection is being closed. Terminate the current message.
 * Note that eolen is not set on the body string.
 */
bool
tfw_http_parse_terminate(TfwHttpMsg *hm)
{
	BUG_ON(!hm);
	BUG_ON(!(TFW_CONN_TYPE(hm->conn) & Conn_Srv));

	/*
	 * Set Content-Length header to warn client about end of message.
	 * Other option is to close connection to client. All the situations
	 * when Content-Length header must not present in responce were
	 * checked earlier. Refer to RFC 7230 3.3.3
	 */
	if (hm->parser.state == Resp_BodyUnlimRead
	    || hm->parser.state == Resp_BodyUnlimStart)
	{
		char c_len[TFW_ULTOA_BUF_SIZ] = {0};
		size_t digs;
		int r;

		BUG_ON(hm->body.flags & TFW_STR_COMPLETE);
		hm->body.flags |= TFW_STR_COMPLETE;
		hm->content_length = hm->body.len;
		if (!(digs = tfw_ultoa(hm->content_length, c_len,
				       TFW_ULTOA_BUF_SIZ)))
			return false;
		r = tfw_http_msg_hdr_xfrm(hm, "Content-Length",
					  sizeof("Content-Length") - 1,
					  c_len, digs,
					  TFW_HTTP_HDR_CONTENT_LENGTH, 0);
		return (r == 0);
	}
	return false;
}

int
tfw_http_parse_resp(void *resp_data, unsigned char *data, size_t len)
{
	int r = TFW_BLOCK;
	TfwHttpResp *resp = (TfwHttpResp *)resp_data;
	__FSM_DECLARE_VARS(resp);

	TFW_DBG("parse %lu server data bytes (%.*s%s) on resp=%p\n",
		len, min(500, (int)len), data, len > 500 ? "..." : "", resp);

	__FSM_START(parser->state) {

	/* ----------------    Status Line    ---------------- */

	__FSM_STATE(Resp_0) {
		if (unlikely(IS_CRLF(c)))
			__FSM_MOVE_nofixup(Resp_0);
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
		parser->_i_st = I_Conn;
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
			__FSM_MOVE_nf(Resp_ReasonPhrase, __fsm_n,
				      &resp->s_line);
		}
	}

	/* Reason-Phrase: just skip. */
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
				   && C4_INT_LCM(p, 'a', 'g', 'e', ':')))
			{
				parser->_i_st = Resp_HdrAgeV;
				__FSM_MOVE_n(RGen_OWS, 4);
			}
			__FSM_MOVE(Resp_HdrA);
		case 'c':
			/* Ensure we have enough data for largest match. */
			if (unlikely(!__data_available(p, 14)))
				__FSM_MOVE(Resp_HdrC);
			/* Qick switch for HTTP headers with the same prefix. */
			switch (TFW_P2LCINT(p + 1)) {
			case TFW_CHAR4_INT('a', 'c', 'h', 'e'):
				if (likely(*(p + 5) == '-'
					   && C8_INT_LCM(p + 6, 'c', 'o', 'n',
						                't', 'r', 'o',
								'l', ':')))
				{
					parser->_i_st = Resp_HdrCache_ControlV;
					__FSM_MOVE_n(RGen_OWS, 14);
				}
				__FSM_MOVE_n(RGen_HdrOther, 5);
			case TFW_CHAR4_INT('o', 'n', 'n', 'e'):
				if (likely(C4_INT_LCM(p + 5, 'c', 't', 'i', 'o')
					   && TFW_LC(*(p + 9)) == 'n'
					   && *(p + 10) == ':'))
				{
					parser->_i_st = Resp_HdrConnectionV;
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
				   && C4_INT_LCM(p + 1, 'a', 't', 'e', ':')))
			{
				parser->_i_st = Resp_HdrDateV;
				__FSM_MOVE_n(RGen_OWS, 5);
			}
			__FSM_MOVE(Resp_HdrD);
		case 'e':
			if (likely(__data_available(p, 8)
				   && C8_INT_LCM(p, 'e', 'x', 'p', 'i',
						    'r', 'e', 's', ':')))
			{
				parser->_i_st = Resp_HdrExpiresV;
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
				parser->_i_st = Resp_HdrKeep_AliveV;
				__FSM_MOVE_n(RGen_OWS, 11);
			}
			__FSM_MOVE(Resp_HdrK);
		case 's':
			if (likely(__data_available(p, 7)
				   && C4_INT_LCM(p + 1, 'e', 'r', 'v', 'e')
				   && *(p + 5) == 'r' && *(p + 6) == ':'))
			{
				parser->_i_st = Resp_HdrServerV;
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
				parser->_i_st = Resp_HdrTransfer_EncodingV;
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
				parser->_i_st = Resp_HdrContent_LengthV;
				__FSM_MOVE_n(RGen_OWS, 7);
			}
			__FSM_MOVE(Resp_HdrContent_L);
		case 't':
			if (likely(__data_available(p, 5)
				   && C4_INT_LCM(p + 1, 'y', 'p', 'e', ':')))
			{
				parser->_i_st = Resp_HdrContent_TypeV;
				__FSM_MOVE_n(RGen_OWS, 5);
			}
			__FSM_MOVE(Resp_HdrContent_T);
		default:
			__FSM_JMP(RGen_HdrOther);
		}
	}

	/* 'Age:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrAgeV, Resp_I_Age, resp,
				  __resp_parse_age);

	/* 'Cache-Control:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrCache_ControlV, Resp_I_CC, resp,
				  __resp_parse_cache_control);

	/* 'Connection:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrConnectionV, I_Conn, msg,
				   __parse_connection, TFW_HTTP_HDR_CONNECTION);

	/* 'Content-Length:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrContent_LengthV, I_ContLen,
				   msg, __parse_content_length,
				   TFW_HTTP_HDR_CONTENT_LENGTH);

	/* 'Content-Type:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrContent_TypeV, I_ContType,
				   msg, __parse_content_type,
				   TFW_HTTP_HDR_CONTENT_TYPE);

	/* 'Date:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrDateV, Resp_I_Date, resp,
				  __resp_parse_http_date);

	/* 'Expires:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrExpiresV, Resp_I_Date, resp,
				  __resp_parse_expires);

	/* 'Keep-Alive:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_RAWHDR_VAL(Resp_HdrKeep_AliveV, Resp_I_KeepAlive, resp,
				  __resp_parse_keep_alive);

	/* 'Server:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrServerV, Resp_I_Server, resp,
				   __resp_parse_server, TFW_HTTP_HDR_SERVER);

	/* 'Transfer-Encoding:*OWS' is read, process field-value. */
	TFW_HTTP_PARSE_SPECHDR_VAL(Resp_HdrTransfer_EncodingV, I_TransEncod,
				   msg, __parse_transfer_encoding,
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
	__FSM_TX_AF(Resp_HdrA, 'g', Resp_HdrAg, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrAg, 'e', Resp_HdrAge, RGen_HdrOther);
	__FSM_TX_AF_OWS(Resp_HdrAge, ':', Resp_HdrAgeV, RGen_HdrOther);

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
	__FSM_TX_AF(Resp_HdrCa, 'c', Resp_HdrCac, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrCac, 'h', Resp_HdrCach, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrCach, 'e', Resp_HdrCache, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrCache, '-', Resp_HdrCache_, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_, 'c', Resp_HdrCache_C, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_C, 'o', Resp_HdrCache_Co, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_Co, 'n', Resp_HdrCache_Con, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_Con, 't', Resp_HdrCache_Cont, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_Cont, 'r', Resp_HdrCache_Contr, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_Contr, 'o', Resp_HdrCache_Contro, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_Contro, 'l', Resp_HdrCache_Control, RGen_HdrOther);
	__FSM_TX_AF_OWS(Resp_HdrCache_Control, ':', Resp_HdrCache_ControlV, RGen_HdrOther);

	/* Connection header processing. */
	__FSM_TX_AF(Resp_HdrCo, 'n', Resp_HdrCon, RGen_HdrOther);
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
	__FSM_TX_AF(Resp_HdrConn, 'e', Resp_HdrConne, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrConne, 'c', Resp_HdrConnec, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrConnec, 't', Resp_HdrConnect, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrConnect, 'i', Resp_HdrConnecti, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrConnecti, 'o', Resp_HdrConnectio, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrConnectio, 'n', Resp_HdrConnection, RGen_HdrOther);
	__FSM_TX_AF_OWS(Resp_HdrConnection, ':', Resp_HdrConnectionV, RGen_HdrOther);

	/* Content-* headers processing. */
	__FSM_TX_AF(Resp_HdrCont, 'e', Resp_HdrConte, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrConte, 'n', Resp_HdrConten, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrConten, 't', Resp_HdrContent, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrContent, '-', Resp_HdrContent_, RGen_HdrOther);

	/* Content-Length header processing. */
	__FSM_TX_AF(Resp_HdrContent_L, 'e', Resp_HdrContent_Le, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_Le, 'n', Resp_HdrContent_Len, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_Len, 'g', Resp_HdrContent_Leng, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_Leng, 't', Resp_HdrContent_Lengt, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_Lengt, 'h', Resp_HdrContent_Length, RGen_HdrOther);
	__FSM_TX_AF_OWS(Resp_HdrContent_Length, ':', Resp_HdrContent_LengthV, RGen_HdrOther);

	/* Content-Type header processing. */
	__FSM_TX_AF(Resp_HdrContent_T, 'y', Resp_HdrContent_Ty, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_Ty, 'p', Resp_HdrContent_Typ, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_Typ, 'e', Resp_HdrContent_Type, RGen_HdrOther);
	__FSM_TX_AF_OWS(Resp_HdrContent_Type, ':', Resp_HdrContent_TypeV, RGen_HdrOther);

	/* Date header processing. */
	__FSM_TX_AF(Resp_HdrD, 'a', Resp_HdrDa, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrDa, 't', Resp_HdrDat, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrDat, 'e', Resp_HdrDate, RGen_HdrOther);
	__FSM_TX_AF_OWS(Resp_HdrDate, ':', Resp_HdrDateV, RGen_HdrOther);

	/* Expires header processing. */
	__FSM_TX_AF(Resp_HdrE, 'x', Resp_HdrEx, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrEx, 'p', Resp_HdrExp, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrExp, 'i', Resp_HdrExpi, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrExpi, 'r', Resp_HdrExpir, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrExpir, 'e', Resp_HdrExpire, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrExpire, 's', Resp_HdrExpires, RGen_HdrOther);
	__FSM_TX_AF_OWS(Resp_HdrExpires, ':', Resp_HdrExpiresV, RGen_HdrOther);

	/* Keep-Alive header processing. */
	__FSM_TX_AF(Resp_HdrK, 'e', Resp_HdrKe, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrKe, 'e', Resp_HdrKee, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrKee, 'p', Resp_HdrKeep, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep, '-', Resp_HdrKeep_, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep_, 'a', Resp_HdrKeep_A, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep_A, 'l', Resp_HdrKeep_Al, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep_Al, 'i', Resp_HdrKeep_Ali, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep_Ali, 'v', Resp_HdrKeep_Aliv, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep_Aliv, 'e', Resp_HdrKeep_Alive, RGen_HdrOther);
	__FSM_TX_AF_OWS(Resp_HdrKeep_Alive, ':', Resp_HdrKeep_AliveV, RGen_HdrOther);

	/* Server header processing. */
	__FSM_TX_AF(Resp_HdrS, 'e', Resp_HdrSe, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrSe, 'r', Resp_HdrSer, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrSer, 'v', Resp_HdrServ, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrServ, 'e', Resp_HdrServe, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrServe, 'r', Resp_HdrServer, RGen_HdrOther);
	__FSM_TX_AF_OWS(Resp_HdrServer, ':', Resp_HdrServerV, RGen_HdrOther);

	/* Transfer-Encoding header processing. */
	__FSM_TX_AF(Resp_HdrT, 'r', Resp_HdrTr, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTr, 'a', Resp_HdrTra, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTra, 'n', Resp_HdrTran, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTran, 's', Resp_HdrTrans, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTrans, 'f', Resp_HdrTransf, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransf, 'e', Resp_HdrTransfe, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfe, 'r', Resp_HdrTransfer, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer, '-', Resp_HdrTransfer_, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_, 'e', Resp_HdrTransfer_E, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_E, 'n', Resp_HdrTransfer_En, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_En, 'c', Resp_HdrTransfer_Enc, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_Enc, 'o', Resp_HdrTransfer_Enco, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_Enco, 'd', Resp_HdrTransfer_Encod, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_Encod, 'i', Resp_HdrTransfer_Encodi, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_Encodi, 'n', Resp_HdrTransfer_Encodin, RGen_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_Encodin, 'g', Resp_HdrTransfer_Encoding, RGen_HdrOther);
	__FSM_TX_AF_OWS(Resp_HdrTransfer_Encoding, ':', Resp_HdrTransfer_EncodingV, RGen_HdrOther);

	}
	__FSM_FINISH(resp);

	return r;
}
