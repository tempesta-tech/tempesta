/**
 *		Tempesta FW
 *
 * HTTP Parser.
 *
 * Table-based FSM is greedy for memory (the state table can require number
 * of pages) and randomly accesses cells of the table, so it is hard to make
 * table-based FSM work quickly due to poor L1d cache hit.
 * However, if FSM has many branches at the many states (i.e. many input
 * characters at the many states generate many branches) then table-based
 * approach can get solid performance. But HTTP's one isn't kind of such FSMs.
 * Also during FSM processing we need to do some custom actions, so we need
 * switch statement anyhow.
 *
 * The most popular approach (widely used in HTTP servers) is switch-driven
 * automaton. If logging is switched off and an HTTP server (tested on Nginx) is
 * loaded only by requests to the same content, then all content is cached and
 * HTTP parser becomes the most hot spot. The problem is that HTTP parsing code
 * is comparable in size with L1i cache and processes one character at a time
 * with significant number of branches. Modern compilers optimize large switch
 * statements to lookup tables that minimizes number of conditional jumps, but
 * branch misprediction and instruction cache misses still hurt performance of
 * the state machine. So the approach is also could be considered as inefficient.
 *
 * The first obvious alternative for the state machine is to use Hybrid State
 * Machine (HSM), which combines very small table with also small switch
 * statement. In our case we tried to encode outgoing transitions from a state
 * with at most 4 ranges. If the state has more outgoing transitions, then all
 * transitions over that 4 must be encoded in switch. All actions (like storing
 * HTTP header names and values) must be performed in switch. Using this
 * technique we can encode each state with only 16 bytes, i.e. one cache line
 * can contain 4 states. Giving this the approach should have significantly
 * improve data cache hit.
 *
 * We also know that Ragel generates perfect automatons and combines case labels
 * in switch statement with direct goto labels (it seems switch is used to be
 * able to enter FSM from any state, i.e. to be able to process chunked data).
 * Such automatons has lower number of loop cycle and bit faster than
 * traditional a-loop-cycle-for-each-transition approach. There was successful
 * attempt to generate simple HTTP parsers using Ragel, but the parsers are
 * limited in functionality.
 *
 * However there are also several research papers which says that an automaton
 * states is just auxiliary information and an automaton can be significantly
 * accelerated if state information is declined.
 *
 * So the second interesting opportunity to generate the fastest HTTP parser is
 * just to encode the automaton directly using simple goto statements, ever w/o
 * any explicit loop.
 *
 * Basically HTTP parsers just matches a string against set of characters
 * (e.g. [A-Za-z_-] for header names), what strspn(3) does. SSE 4.2 provides
 * PCMPSTR instructions family for this purpose (GLIBC since 2.16 uses
 * SSE 4.2 impemenetation for strspn()). However, this is vector instruction
 * which doesn't support accepr ot reject sets more than 16 characters, so it's
 * not too usable for HTTP parsers.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * TODO:
 *
 * 1.	Currently we parse only limited number of HTTP headers.
 * 	Store all other headers in strings array allocated using pool.
 */
#include <linux/ctype.h>
#include <linux/kernel.h>

#include "gfsm.h"
#include "http.h"

/*
 * ------------------------------------------------------------------------
 *	Common HTTP routines
 * ------------------------------------------------------------------------
 */
/**
 * Set final field length and mark it as finished.
 */
static inline void
__field_finish(TfwStr *field, unsigned char *begin, unsigned char *end)
{
	if (unlikely(field->flags & TFW_STR_COMPOUND)) {
		TfwStr *last = (TfwStr *)field->ptr + field->len - 1;
		if (unlikely(begin == end)) {
			BUG_ON(field->len >= 2);
			if (--field->len == 1)
				/*
				 * Last/second chunk is empty
				 * - back to plain string.
				 */
				memcpy(field, field->ptr, sizeof(*field));
		} else {
			/*
			 * This is not the first data segment,
			 * so current data starts at @begin.
			 */
			last->ptr = begin;
			last->len = end - begin;
		}
	} else {
		/* field->ptr must be set before reaching current state. */
		BUG_ON(!field->ptr);
		field->len = end - (unsigned char *)field->ptr;
	}
}

#define __FSM_START(s)							\
int __fsm_const_state;							\
parser->data_off = 0; /* new data chunk */				\
fsm_reenter: __attribute__((unused))					\
	TFW_DBG("enter FSM at state %d\n", s);				\
switch (s)

#define __FSM_STATE(st)							\
case st:								\
st: __attribute__((unused)) 						\
 	__fsm_const_state = st; /* optimized out to constant */		\
	c = *p;								\
	TFW_DBG("parser: " #st "(%d:%d): c=%#x(%c)\n",			\
		st, parser->_i_st, c, isprint(c) ? c : '.');

#define __FSM_EXIT(field)						\
do {									\
	if (field) /* staticaly resolved */				\
		if (unlikely(!tfw_str_add_compound(msg->pool, field)))	\
			return TFW_BLOCK;				\
	goto done;							\
} while (0)

#define __FSM_I_EXIT()			goto done

#define __FSM_FINISH(m)							\
done:									\
	parser->state = __fsm_const_state;				\
	parser->data_off = p - data;					\
	m->msg.len += parser->data_off;					\

#define ____FSM_MOVE_LAMBDA(to, n, code)				\
do {									\
	p += n;								\
	if (unlikely(p >= data + len || !*p)) {				\
		r = TFW_POSTPONE; /* postpone to more data available */	\
		if (parser->hdr.ptr) {					\
			TfwStr *h = TFW_STR_CURR(&parser->hdr);		\
			h->len += data + len - (unsigned char *)h->ptr;	\
		}							\
		code;							\
	}								\
	c = *p;								\
	goto to;							\
} while (0)

#define __FSM_I_MOVE_n(to, n)						\
	____FSM_MOVE_LAMBDA(to, n, __FSM_I_EXIT())

#define __FSM_MOVE_n(to, n)						\
	____FSM_MOVE_LAMBDA(to, n, __FSM_EXIT(NULL))
#define __FSM_MOVE(to)			__FSM_MOVE_n(to, 1)
/* The same as __FSM_MOVE_n(), but exactly for jumps w/o data moving. */
#define __FSM_JMP(to)			do { goto to; } while (0)

#define __FSM_I_MOVE(to)		__FSM_I_MOVE_n(to, 1)
#define __FSM_I_MOVE_str(to, str)	__FSM_I_MOVE_n(to, sizeof(str) - 1)
/* The same as __FSM_I_MOVE_n(), but exactly for jumps w/o data moving. */
#define __FSM_I_JMP(to)			do { goto to; } while (0)

/* Automaton transition from state @st to @st_next on character @ch. */
#define __FSM_TX(st, ch, st_next)					\
__FSM_STATE(st) {							\
	if (likely(c == ch))						\
		__FSM_MOVE(st_next);					\
	return TFW_BLOCK;						\
}

/* Automaton transition with alphabet checking and fallback state. */
#define __FSM_TX_AF(st, ch, st_next, a, st_fallback)			\
__FSM_STATE(st) {							\
	if (likely(tolower(c) == ch))					\
		__FSM_MOVE(st_next);					\
	if (likely(IN_ALPHABET(c, a)))					\
		__FSM_MOVE(st_fallback);				\
	return TFW_BLOCK;						\
}

/* As above, but reads LWS through transitional state. */
enum { RGen_LWS = 10000 };
#define __FSM_TX_AF_LWS(st, ch, st_next, a, st_fallback)		\
__FSM_STATE(st) {							\
	if (likely(tolower(c) == ch)) {					\
		parser->_i_st = st_next;				\
		__FSM_MOVE(RGen_LWS);					\
	}								\
	if (likely(IN_ALPHABET(c, a)))					\
		__FSM_MOVE(st_fallback);				\
	return TFW_BLOCK;						\
}

/* Little endian. */
#define LC(c)		((c) | 0x20)
#define TFW_LC_INT	0x20202020
#define TFW_LC_LONG	0x2020202020202020UL
#define TFW_CHAR4_INT(a, b, c, d)					\
	 ((d << 24) | (c << 16) | (b << 8) | a)
#define TFW_CHAR8_INT(a, b, c, d, e, f, g, h)				\
	 (((long)h << 56) | ((long)g << 48) | ((long)f << 40)		\
	  | ((long)e << 32) | (d << 24) | (c << 16) | (b << 8) | a)
/*
 * Match 4 or 8 characters with type conversion to int with lower-case
 * conversion.
 */
#define C4_INT_LCM(p, a, b, c, d)					\
	 (p + 4 <= data + len) &&					\
	 !((*(unsigned int *)(p) | TFW_LC_INT) ^ TFW_CHAR4_INT(a, b, c, d))
#define C8_INT_LCM(p, a, b, c, d, e, f, g, h)				\
	 (p + 8 <= data + len) &&					\
	 !((*(unsigned long *)(p) | TFW_LC_LONG)			\
	   ^ TFW_CHAR8_INT(a, b, c, d, e, f, g, h))

/*
 * Alphabet for HTTP message header field-name (RFC 2616 4.2).
 * Computed as the above for
 *
 * 	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
 * 	"!#$%&'*+-.^_`|~0123456789"
 */
static const unsigned long hdr_a[] ____cacheline_aligned = {
	0x3ff6cfa00000000UL, 0x57ffffffc7fffffeUL, 0, 0
};

#define IN_ALPHABET(c, a)	(a[c >> 6] & (1UL << (c & 0x3f)))

/**
 * Prepare the parser to process a new message in the same data chunk.
 */
void
tfw_http_parser_msg_inherit(TfwHttpMsg *hm, TfwHttpMsg *hm_new)
{
	hm_new->parser.data_off = hm->parser.data_off;
}

#define CSTR_EQ			0
#define CSTR_POSTPONE		TFW_POSTPONE	/* -1 */
#define CSTR_NEQ		TFW_BLOCK	/* -2 */
#define CSTR_BADLEN		-3
/**
 * Compare two chunks of data with const pattern @str.
 * If two chunks are less than @tot_len in length and if @chunk is empty,
 * then store @p in @chunk and postpone the comparison util next piece of data.
 *
 * @return
 * 	CSTR_EQ:		equal
 * 	CSTR_NEW:		not equal
 * 	CSTR_POSTPONE:		need to postpone the comparison to next chunk
 * 	CSTR_BADLEN:		bad length (2 chunks are not enough)
 *
 * Beware! The function has side effect unlike standard strncasecmp().
 * Maybe it's better to rename it...
 */
static int
__chunk_strncasecmp(TfwStr *chunk, unsigned char *p, size_t len, const char *str,
	       size_t tot_len)
{
	int r = CSTR_EQ, cn = chunk->len;

	if (unlikely(tot_len > cn + len)) {
		if (cn) {
			r = CSTR_BADLEN;
			goto out;
		}
		chunk->ptr = p;
		chunk->len = len;
		return CSTR_POSTPONE;
	}

	/*
	 * TODO kernel has dummy C strcasecmp() implementation which converts
	 * both the strings to low case while @str is always in lower case.
	 * Also GLIBC has assembly implementation of the functions, so
	 * implement our own strcasecmp() if it becomes a bottle neck.
	 */
	if ((cn && strncasecmp(chunk->ptr, str, cn))
	    || strncasecmp(p, str + cn, tot_len - cn))
		r = CSTR_NEQ;

out:
	chunk->len = 0;
	chunk->ptr = NULL;

	return r;
}
#define CHUNK_STRNCASECMP(c, p, n, s)					\
	__chunk_strncasecmp(c, p, n, s, sizeof(s) - 1)

/**
 * Parse probably chunked string representation of an decimal integer.
 * Returns number of parsed bytes (in data, w/o stored chunk) on success
 * or negative value otherwise.
 */
static int
__parse_int(TfwStr *chunk, unsigned char *data, size_t len, unsigned int *acc)
{
	unsigned char *p;
	int r;

#define PROCESS_ACC()							\
do {									\
	if (unlikely(!isdigit(*p)))					\
		return CSTR_NEQ;					\
	if (unlikely(*acc > (UINT_MAX - 10) / 10))			\
		return CSTR_BADLEN;					\
	*acc = *acc * 10 + *p - '0';					\
} while (0)

	/* Parse stored chunk. */
	for (p = chunk->ptr; chunk->len; ++chunk->ptr, --chunk->len)
		PROCESS_ACC();

	/* Parse current chunk. */
	for (p = data; !isspace(*p); ++p) {
		if (unlikely(p - data == len)) {
			if (chunk->ptr) {
				r = CSTR_BADLEN;
				goto err;
			} else {
				chunk->ptr = data;
				chunk->len = len;
				return CSTR_POSTPONE;
			}
		}
		PROCESS_ACC();
	}

	r = (p - data > 0) ? p - data : CSTR_BADLEN;
err:
	/* Initialized chunk, chunk->len is already zero. */
	chunk->ptr = NULL;
	return r;
#undef PROCESS_ACC
}

/**
 * Parse probably chunked string representation of an hexadecimal integer.
 * Returns number of parsed bytes (in data, w/o stored chunk) on success
 * or negative value otherwise.
 */
static int
__parse_hex(TfwStr *chunk, unsigned char *data, size_t len, unsigned int *acc)
{
	unsigned char *p;
	int r;

#define PROCESS_ACC()							\
do {									\
	if (unlikely(*acc > (UINT_MAX - 10) / 10))			\
		return CSTR_BADLEN;					\
	if (!isxdigit(*p))						\
		return CSTR_NEQ;					\
	*acc = (*acc << 4) + (*p & 0xf) + (*p >> 6) * 9;		\
} while (0)

	/* Parse stored chunk. */
	for (p = chunk->ptr; chunk->len; ++chunk->ptr, --chunk->len)
		PROCESS_ACC();

	/* Parse current chunk. */
	for (p = data; !isspace(*p) || *p == ';'; ++p) {
		if (unlikely(p - data == len)) {
			if (chunk->ptr) {
				r = CSTR_BADLEN;
				goto err;
			} else {
				chunk->ptr = data;
				chunk->len = len;
				return CSTR_POSTPONE;
			}
		}
		PROCESS_ACC();
	}

	r = (p - data > 0) ? p - data : CSTR_BADLEN;
err:
	/* Initialized chunk, chunk->len is already zero. */
	chunk->ptr = NULL;
	return r;
#undef PROCESS_ACC
}

/* Helping (inferior) states to process particular parts of HTTP message. */
enum {
	I_0, /* initial state */

	I_Conn, /* Connection */
	I_ContLen, /* Content-Length */
	I_TransEncod, /* Transfer-Encoding */
	I_TransEncodExt,

	I_EoT, /* end of term */
	I_EoL, /* end of line */
};

/* Parsing helpers. */
#define TRY_STR_LAMBDA(str, lambda)					\
	r = CHUNK_STRNCASECMP(chunk, p, len, str);			\
	switch (r) {							\
	case CSTR_EQ:							\
		lambda;							\
	case CSTR_POSTPONE:						\
	case CSTR_BADLEN:						\
		return r;						\
	case CSTR_NEQ: /* fall through */				\
		;							\
	}
#define TRY_STR(str, state)						\
	TRY_STR_LAMBDA(str, __FSM_I_MOVE_str(state, str))

#define __TFW_HTTP_PARSE_HDR_VAL(st_curr, st_next, st_i, msg, func, id)	\
__FSM_STATE(st_curr) {							\
	long n = data + len - p;					\
	BUG_ON(n < 0);							\
	parser->_i_st = st_i;						\
	/* @n - header length, @r - next shift (@n + *CR + LF). */	\
	r = func(msg, p, &n);						\
	TFW_DBG("parse header " #func ": return %d\n", r);		\
	switch (r) {							\
	case CSTR_POSTPONE:						\
		/* Not all the header data is parsed. */		\
		STORE_HEADER(msg, id, n);				\
		__FSM_MOVE_n(st_curr, n);				\
	case CSTR_BADLEN: /* bad header length */			\
	case CSTR_NEQ: /* bad header value */				\
		return TFW_BLOCK;					\
	default:							\
		BUG_ON(r <= 0);						\
		/* The header value is fully parsed, move forward. */	\
		CLOSE_HEADER(msg, id, n);				\
		__FSM_MOVE_n(st_next, r);				\
	}								\
}

#define TFW_HTTP_PARSE_HDR_VAL(st_curr, st_next, st_i, msg, func)	\
	__TFW_HTTP_PARSE_HDR_VAL(st_curr, st_next, st_i, msg, func,	\
				 TFW_HTTP_HDR_RAW)

#define TFW_HTTP_INIT_BODY_PARSING(msg, to_state)			\
do {									\
	/* RFC 2616 4.4: firstly check chunked transfer encoding. */	\
	if (msg->flags & TFW_HTTP_CHUNKED)				\
		__FSM_MOVE(to_state);					\
	/* Next we chek content length. */				\
	if (msg->content_length) {					\
		parser->to_read = msg->content_length;			\
		__FSM_MOVE(to_state);					\
	}								\
	/* There is no body at all. */					\
	goto done;							\
} while (0)

#define TFW_HTTP_PARSE_BODY(prefix, msg)				\
/* Read request|response body. */					\
__FSM_STATE(prefix ## _Body) {						\
	if (!parser->to_read) {						\
		int r;							\
		unsigned int to_read = 0;				\
		long n = data + len - p;				\
		if (!(msg->flags & TFW_HTTP_CHUNKED)) {			\
			/* We've fully read Content-Length bytes. */	\
			r = TFW_PASS;					\
			goto done;					\
		}							\
		/* Read next chunk length. */				\
		r = __parse_hex(&parser->_tmp_chunk, p, n, &to_read);	\
		switch (r) {						\
		case CSTR_POSTPONE:					\
			/* Not all the header data is parsed. */	\
			__FSM_MOVE_n(prefix ## _Body, n);		\
		case CSTR_BADLEN: /* bad header length */		\
		case CSTR_NEQ: /* bad header value */			\
			return TFW_BLOCK;				\
		default:						\
			BUG_ON(r <= 0);					\
			parser->to_read = to_read;			\
			__FSM_MOVE_n(prefix ## _BodyChunkEoL, r);	\
		}							\
	}								\
	/* fall through */						\
}									\
/* Read parser->to_read bytes of message body. */			\
__FSM_STATE(prefix ## _BodyReadChunk) {					\
	if (!msg->body.ptr)						\
		msg->body.ptr = p;					\
	msg->body.len += min(parser->to_read, (int)(data + len - p));	\
	/* Just skip required number of bytes. */			\
	__FSM_MOVE_n(prefix ## _Body, parser->to_read);			\
}									\
__FSM_STATE(prefix ## _BodyChunkEoL) {					\
	if (c == '\n') {						\
		if (parser->to_read)					\
			__FSM_MOVE(prefix ## _BodyReadChunk);		\
		else							\
			/* Read trailing headers, RFC 2616 3.6.1. */	\
			__FSM_MOVE(prefix ## _Hdr);			\
	}								\
	if (c == '\r' || c == '=' || IN_ALPHABET(*p, hdr_a) || c == ';') \
		__FSM_MOVE(prefix ## _BodyChunkEoL);			\
	return TFW_BLOCK;						\
}									\
/* Request|Response is fully read. */					\
__FSM_STATE(prefix ## _Done) {						\
	if (c == '\n') {						\
		r = TFW_PASS;						\
		goto done;						\
	}								\
	return TFW_BLOCK;						\
}

/**
 * Parse Connection header value, RFC 2616 14.10.
 */
static int
__parse_connection(TfwHttpMsg *msg, unsigned char *data, size_t *lenrval)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &msg->parser;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	size_t len = *lenrval;
	unsigned char c = *p;
	bool hlen_set = false;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(I_Conn) {
		TRY_STR_LAMBDA("close", {
			msg->flags |= TFW_HTTP_CONN_CLOSE;
			__FSM_I_MOVE_str(I_EoL, "close");
		});
		TRY_STR_LAMBDA("keep-alive", {
			msg->flags |= TFW_HTTP_CONN_KA;
			__FSM_I_MOVE_str(I_EoL, "keep-alive");
		});
		return CSTR_NEQ;
	}

	__FSM_STATE(I_EoL) {
		if (!hlen_set) {
			*lenrval = p - data; /* set header length */
			hlen_set = true;
		}
		if (c == '\n') {
			r = p - data + 1;
			goto done;
		}
		if (isspace(c))
			/* Eat all spaces including '\r'. */
			__FSM_I_MOVE(I_EoL);

		return CSTR_NEQ;
	}

	} // FSM END
done:
	TFW_DBG("parser: Connection parsed: flags %#x\n", msg->flags);
	parser->_i_st = I_0;

	return r;
}

/**
 * Parse Content-Length header value, RFC 2616 14.13.
 */
static int
__parse_content_length(TfwHttpMsg *msg, unsigned char *data, size_t *lenrval)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &msg->parser;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	size_t len = *lenrval;
	unsigned char c = *p;
	bool hlen_set = false;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(I_ContLen) {
		unsigned int acc = 0;
		int n = __parse_int(chunk, p, len, &acc);
		if (n < 0)
			return n;
		msg->content_length = acc;
		__FSM_I_MOVE_n(I_EoL, n);
	}

	__FSM_STATE(I_EoL) {
		if (!hlen_set) {
			*lenrval = p - data; /* set header length */
			hlen_set = true;
		}
		if (c == '\n') {
			r = p - data + 1;
			goto done;
		}
		if (isspace(c))
			/* Eat all spaces including '\r'. */
			__FSM_I_MOVE(I_EoL);

		return CSTR_NEQ;
	}

	} // FSM END
done:
	parser->_i_st = I_0;
	return r;
}

/**
 * Parse Transfer-Encoding header value, RFC 2616 14.41 and 3.6.
 */
static int
__parse_transfer_encoding(TfwHttpMsg *msg, unsigned char *data, size_t *lenrval)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &msg->parser;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	size_t len = *lenrval;
	unsigned char c = *p;
	bool hlen_set = false;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(I_TransEncod) {
		TRY_STR_LAMBDA("chunked", {
			msg->flags |= TFW_HTTP_CHUNKED;
			__FSM_I_MOVE_str(I_EoL, "chunked");
		});
		__FSM_I_MOVE_n(I_TransEncodExt, 0);
	}

	__FSM_STATE(I_TransEncodExt) {
		/*
		 * TODO
		 * - process transfer encodings: gzip, deflate, identity,
		 *   				 compress;
		 * - replace double memchr() below by strspn() analog which
		 *   accepts string length instead of processing null-terminated
		 *   strings.
		 */
		unsigned char *lf = memchr(p, '\n', len);
		unsigned char *comma = memchr(p, ',', len);
		if (comma && comma < lf)
			__FSM_I_MOVE_n(I_EoT, comma - p);
		if (lf)
			__FSM_I_MOVE_n(I_EoL, lf - p);
		return CSTR_POSTPONE;
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (c == ' ' || c == ',')
			__FSM_I_MOVE(I_EoT);
		if (IN_ALPHABET(c, hdr_a))
			__FSM_I_MOVE(I_TransEncod);
		if (!isspace(c))
			return CSTR_NEQ;
		/* fall through */
	}

	__FSM_STATE(I_EoL) {
		if (!hlen_set) {
			*lenrval = p - data; /* set header length */
			hlen_set = true;
		}
		if (c == '\n') {
			r = p - data;
			goto done;
		}
		if (isspace(c))
			/* Eat all spaces including '\r'. */
			__FSM_I_MOVE(I_EoL);

		return CSTR_NEQ;
	}

	} // FSM END
done:
	parser->_i_st = I_0;
	return r;
}

/**
 * TODO process duplicate _generic_ (TFW_HTT_HDR_RAW) headers like:
 *
 * 	Foo: bar value\r\n
 * 	Bar: other value\r\n
 * 	Foo: processed as a new header - no collision!
 *
 * Note that both the headers can already be compound (i.e. consist from
 * few data chunks/fragments), so we should handle string tree of heigh 2.
 */
static void
__store_header(TfwHttpMsg *hm, unsigned char *data, long len, int id,
	       bool close)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *h;

	if (unlikely(id == TFW_HTTP_HDR_RAW
		     && hm->h_tbl->off == hm->h_tbl->size))
	{
		/* Allocate some more room if not enough to store the header. */
		size_t order = hm->h_tbl->size / TFW_HTTP_HDR_NUM;
		ht = tfw_pool_realloc(hm->pool, hm->h_tbl, TFW_HHTBL_SZ(order),
				      TFW_HHTBL_SZ(order + 1));
		if (!ht)
			return;
		hm->h_tbl = ht;
		ht->size = __HHTBL_SZ(order + 1);
	}

	if (id == TFW_HTTP_HDR_RAW)
		id = ht->off;

	h = &ht->tbl[id].field;
	if (h->ptr) {
		/*
		 * The header consists from many fragments - use compound string
		 * to aggregate the fragments in one string.
		 */
		h = tfw_str_add_compound(hm->pool, &ht->tbl[id].field);
		if (!h)
			return;
	}

	TFW_STR_COPY(h, &hm->parser.hdr);
	h->len = len;
	TFW_STR_INIT(&hm->parser.hdr);
	TFW_DBG("store header w/ ptr=%p len=%d flags=%x\n",
		h->ptr, h->len, h->flags);

	/* Move the offset forward if current header is fully read. */
	if (close)
		ht->off++;
}

#define STORE_HEADER(rmsg, id, len)	__store_header((TfwHttpMsg *)rmsg, \
						       data, len, id, false)
#define CLOSE_HEADER(rmsg, id, len)	__store_header((TfwHttpMsg *)rmsg, \
						       data, len, id, true)

/*
 * ------------------------------------------------------------------------
 *	HTTP request parsing
 * ------------------------------------------------------------------------
 */
/*
 * Alphabet for URI abs_path (RFC 3986).
 * The bitmap is generated by:
 *
 *	unsigned char *u = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
 *			   "abcdefghijklmnopqrstuvwxyz"
 *			   "0123456789-_.~!*'();:@&=+$,/?%#[]";
 * 	for ( ; *u; ++u)
 * 		uap_a[*u >> 6] |= 1UL << (*u & 0x3f);
 */
static const unsigned long uap_a[] ____cacheline_aligned = {
	0xaffffffa00000000UL, 0x47fffffeafffffffUL, 0, 0
};

/* Main (parent) HTTP request processing states. */
enum {
	Req_0,
	/* Request line. */
	Req_Method,
	Req_MUSpace,
	Req_UriHost,
	Req_UriHostEnd,
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
	Req_EoL,
	/* Headers. */
	Req_Hdr,
	Req_HdrH,
	Req_HdrHo,
	Req_HdrHos,
	Req_HdrHost,
	Req_HdrHostV,
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
	Req_HdrOther,
	Req_HdrDone,
	/* Body */
	Req_Body,
	Req_BodyChunkEoL,
	Req_BodyReadChunk,
	/* URI normalization. */
	Req_UriNorm,
	/* Request parsing done. */
	Req_Done
};
#ifdef TFW_HTTP_NORMALIZATION
#define TFW_HTTP_URI_HOOK	Req_UriNorm
#else
#define TFW_HTTP_URI_HOOK	Req_UriAbsPath
#endif

/* Helping (inferior) states to process particular parts of HTTP request. */
enum {
	Req_I_0,

	/* Host header */
	Req_I_H,
	Req_I_H_Port,
	Req_I_H_EoL,
	/* Cache-Control header */
	Req_I_CC,
	Req_I_CC_MaxAgeV,
	Req_I_CC_MinFreshV,
	Req_I_CC_Ext,
	Req_I_CC_EoT,
	Req_I_CC_EoL,
};

/**
 * Parse request Cache-Control, RFC 2616 14.9
 */
static int
__req_parse_cache_control(TfwHttpReq *req, unsigned char *data, size_t *lenrval)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &req->parser;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	size_t len = *lenrval;
	unsigned char c = *p;
	bool hlen_set = false;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Req_I_CC) {
		switch (tolower(c)) {
		case 'm':
			TRY_STR("max-age=", Req_I_CC_MaxAgeV);
			TRY_STR("min-fresh=", Req_I_CC_MinFreshV);
			TRY_STR_LAMBDA("max-stale", {
				req->cache_ctl.flags |= TFW_HTTP_CC_MAX_STALE;
				__FSM_I_MOVE_str(Req_I_CC_EoT, "max-stale");
			});
			goto cache_extension;
		case 'n':
			TRY_STR_LAMBDA("no-cache", {
				req->cache_ctl.flags |= TFW_HTTP_CC_NO_CACHE;
				__FSM_I_MOVE_str(Req_I_CC_EoT, "no-cache");
			});
			TRY_STR_LAMBDA("no-store", {
				req->cache_ctl.flags |= TFW_HTTP_CC_NO_STORE;
				__FSM_I_MOVE_str(Req_I_CC_EoT, "no-store");
			});
			TRY_STR_LAMBDA("no-transform", {
				req->cache_ctl.flags |= TFW_HTTP_CC_NO_TRANS;
				__FSM_I_MOVE_str(Req_I_CC_EoT, "no-transform");
			});
			goto cache_extension;
		case 'o':
			TRY_STR_LAMBDA("only-if-cached", {
				req->cache_ctl.flags |= TFW_HTTP_CC_NO_OIC;
				__FSM_I_MOVE_str(Req_I_CC_EoT,
						 "only-if-cached");
			});
		default:
		cache_extension:
			__FSM_I_MOVE_n(Req_I_CC_Ext, 0);
		}
	}

	__FSM_STATE(Req_I_CC_MaxAgeV) {
		unsigned int acc = 0;
		int n = __parse_int(chunk, p, len, &acc);
		if (n < 0)
			return n;
		req->cache_ctl.max_age = acc;
		__FSM_I_MOVE_n(Req_I_CC_EoT, n);
	}

	__FSM_STATE(Req_I_CC_MinFreshV) {
		unsigned int acc = 0;
		int n = __parse_int(chunk, p, len, &acc);
		if (n < 0)
			return n;
		req->cache_ctl.max_fresh = acc;
		__FSM_I_MOVE_n(Req_I_CC_EoT, n);
	}

	__FSM_STATE(Req_I_CC_Ext) {
		/*
		 * TODO
		 * - process cache extensions;
		 * - replace double memchr() below by strspn() analog which
		 *   accepts string length instead of processing null-terminated
		 *   strings.
		 */
		unsigned char *lf = memchr(p, '\n', len);
		unsigned char *comma = memchr(p, ',', len);
		if (comma && comma < lf)
			__FSM_I_MOVE_n(Req_I_CC_EoT, comma - p);
		if (lf)
			__FSM_I_MOVE_n(Req_I_CC_EoL, lf - p);
		return CSTR_POSTPONE;
	}

	/* End of term. */
	__FSM_STATE(Req_I_CC_EoT) {
		if (c == ' ' || c == ',')
			__FSM_I_MOVE(Req_I_CC_EoT);
		/*
		 * TODO: we're don't support for now field values for max-stale,
		 * so just skip '=[hdr_a]*' for now.
		 */
		if (c == '=')
			__FSM_I_MOVE(Req_I_CC_Ext);
		if (IN_ALPHABET(c, hdr_a))
			__FSM_I_MOVE(Req_I_CC);
		if (!isspace(c))
			return CSTR_NEQ;
		/* fall through */
	}

	__FSM_STATE(Req_I_CC_EoL) {
		if (!hlen_set) {
			*lenrval = p - data; /* set header length */
			hlen_set = true;
		}
		if (c == '\n') {
			r = p - data + 1;
			goto done;
		}
		if (isspace(c))
			/* Eat all spaces including '\r'. */
			__FSM_I_MOVE(Req_I_CC_EoL);

		return CSTR_NEQ;
	}

	} // FSM END
done:
	parser->_i_st = Req_I_0;
	return r;
}

/**
 * Parse request Host header, RFC 2616 14.23
 */
static int
__req_parse_host(TfwHttpReq *req, unsigned char *data, size_t *lenrval)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &req->parser;
	unsigned char *p = data;
	size_t len = *lenrval;
	unsigned char c = *p;
	bool hlen_set = false;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Req_I_H) {
		/* See Req_UriHost processing. */
		if (likely(isalnum(c) || c == '.' || c == '-'))
			__FSM_I_MOVE(Req_I_H);
		if (c == ':')
			__FSM_I_MOVE(Req_I_H_Port);
		if (isspace(c))
			__FSM_I_JMP(Req_I_H_EoL);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_H_Port) {
		/* See Req_UriPort processing. */
		if (likely(isdigit(c)))
			__FSM_I_MOVE(Req_I_H_Port);
		if (isspace(c))
			__FSM_I_JMP(Req_I_H_EoL);
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_H_EoL) {
		if (!hlen_set) {
			*lenrval = p - data; /* set header length */
			hlen_set = true;
		}
		if (c == '\n') {
			r = p - data + 1;
			goto done;
		}
		if (isspace(c))
			/* Eat all spaces including '\r'. */
			__FSM_I_MOVE(Req_I_H_EoL);

		return CSTR_NEQ;
	}

	} // FSM END
done:
	parser->_i_st = Req_I_0;
	return r;
}

int
tfw_http_parse_req(TfwHttpReq *req, unsigned char *data, size_t len)
{
	TfwHttpParser *parser = &req->parser;
	TfwHttpMsg *msg = (TfwHttpMsg *)req;
	int r = TFW_BLOCK;
	unsigned char *p = data;
	unsigned char c = *p;

	__FSM_START(parser->state) {

	/* ----------------    Request Line    ---------------- */

	__FSM_STATE(Req_0) {
		if (unlikely(c == '\r' || c == '\n'))
			__FSM_MOVE(Req_0);
		/* fall through */
	}

	/* HTTP method. */
	__FSM_STATE(Req_Method) {
		if (unlikely(p + 4 >= data + len))
			return TFW_BLOCK;

		switch (*(unsigned int *)p) {
		case TFW_CHAR4_INT('G', 'E', 'T', ' '):
			req->method = TFW_HTTP_METH_GET;
			__FSM_MOVE_n(Req_MUSpace, 4);
		case TFW_CHAR4_INT('H', 'E', 'A', 'D'):
			req->method = TFW_HTTP_METH_HEAD;
			__FSM_MOVE_n(Req_MUSpace, 4);
		case TFW_CHAR4_INT('P', 'O', 'S', 'T'):
			req->method = TFW_HTTP_METH_POST;
			__FSM_MOVE_n(Req_MUSpace, 4);
		}

		return TFW_BLOCK; /* Unsupported method */
	}

	/* Eat spaces before URI and HTTP (only) scheme. */
	__FSM_STATE(Req_MUSpace) {
		if (likely(c == ' '))
			__FSM_MOVE(Req_MUSpace);
		if (likely(c == '/')) {
			req->uri.ptr = p;
			__FSM_MOVE(Req_UriAbsPath);
		}
		if (likely(C4_INT_LCM(p, 'h', 't', 't', 'p')))
			if (likely(*(p + 4) == ':' && *(p + 5) == '/'
				   && *(p + 6) == '/'))
			{
				/*
				 * Set req->host here making Host header value
				 * ignored according to RFC2616 5.2.
				 */
				req->host.ptr = p + 7;
				__FSM_MOVE_n(Req_UriHost, 7);
			}

		return TFW_BLOCK;
	}

	/*
	 * URI host part.
	 *
	 * We must not rewrite abs_path, but still can cast host part
	 * to lower case.
	 */
	__FSM_STATE(Req_UriHost) {
		*p = LC(*p);
		if (likely(isalnum(c) || c == '.' || c == '-'))
			__FSM_MOVE(Req_UriHost);
		__FSM_MOVE(Req_UriHostEnd);
	}

	/* Host is read, start to read port or abs_path. */
	__FSM_STATE(Req_UriHostEnd) {
		req->host.len = p - (unsigned char *)req->host.ptr;

		if (likely(c == '/')) {
			req->uri.ptr = p;
			__FSM_MOVE(Req_UriAbsPath);
		}
		else if (c == ':') {
			__FSM_MOVE(Req_UriPort);
		}
		else
			return TFW_BLOCK;
	}

	/* Host port in URI */
	__FSM_STATE(Req_UriPort) {
		if (likely(isdigit(c)))
			__FSM_MOVE(Req_UriPort);

		if (unlikely(c != '/'))
			return TFW_BLOCK;

		req->uri.ptr = p;
		__FSM_MOVE(Req_UriAbsPath);
	}

	/* URI abs_path */
	__FSM_STATE(Req_UriAbsPath) {
		if (likely(IN_ALPHABET(c, uap_a)))
			/* Move forward through possibly segmented data. */
			____FSM_MOVE_LAMBDA(TFW_HTTP_URI_HOOK, 1,
					    __FSM_EXIT(&req->uri));

		if (likely(c == ' ')) {
			__field_finish(&req->uri, data, p);
			__FSM_MOVE(Req_HttpVer);
		}

		return TFW_BLOCK;
	}

	/* URI normalization if enabled. */
	#define TFW_HTTP_NORM_URI
	#include "http_norm.h"
	#undef TFW_HTTP_NORM_URI

	/* HTTP version */
	__FSM_STATE(Req_HttpVer) {
		if (likely(p + 8 <= data + len)) {
			/* Quick path. */
			if (*(unsigned long *)p
			    == TFW_CHAR8_INT('H', 'T', 'T', 'P',
					     '/', '1', '.', '1'))
				__FSM_MOVE_n(Req_EoL, 8);
			else
				return TFW_BLOCK;
		}

		/* Slow path. */
		if (c == 'H')
			__FSM_MOVE(Req_HttpVerT1);
		return TFW_BLOCK;
	}

	/* End of HTTP line (request or header). */
	__FSM_STATE(Req_EoL) {
		switch (c) {
		case '\r':
			__FSM_MOVE(Req_EoL);
		case '\n':
			__FSM_MOVE(Req_Hdr);
		default:
			return TFW_BLOCK;
		}
	}

	/* ----------------    Header Lines    ---------------- */

	/*
	 * Start of HTTP header or end of header part of the request.
	 * There is a switch for first character of a header name.
	 */
	__FSM_STATE(Req_Hdr) {
		if (parser->hdr.ptr)
			tfw_str_add_compound(req->pool, &parser->hdr);

		if (unlikely(c == '\r')) {
			if (!req->body.ptr) {
				req->crlf = p;
				__FSM_MOVE(Req_HdrDone);
			} else
				__FSM_MOVE(Req_Done);
		}
		if (unlikely(c == '\n')) {
			if (!req->body.ptr) {
				TFW_HTTP_INIT_BODY_PARSING(req, Req_Body);
			} else {
				r = TFW_PASS;
				goto done;
			}
		}

		if (unlikely(!IN_ALPHABET(c, hdr_a)))
			return TFW_BLOCK;

		/* We're going to read new header, remember it. */
		TFW_STR_CURR(&parser->hdr)->ptr = p;

		switch (LC(c)) {
		case 'c':
			__FSM_MOVE(Req_HdrC);
		case 'h':
			if (likely(C4_INT_LCM(p + 1, 'o', 's', 't', ':'))) {
				parser->_i_st = Req_HdrHostV;
				__FSM_MOVE_n(RGen_LWS, 5);
			}
			__FSM_MOVE(Req_HdrH);
		case 't':
			if (likely(p + 17 <= data + len
				   && C8_INT_LCM(p, 't', 'r', 'a', 'n',
					   	    's', 'f', 'e', 'r')
				   && *(p + 8) == '-'
				   && C8_INT_LCM(p + 9, 'e', 'n', 'c', 'o',
							'd', 'i', 'n', 'g')
				   && *(p + 17) == ':'))
			{
				parser->_i_st = Req_HdrTransfer_EncodingV;
				__FSM_MOVE_n(RGen_LWS, 18);
			}
			__FSM_MOVE(Req_HdrT);
		default:
			__FSM_JMP(Req_HdrOther);
		}
	}

	/*
	 * Read LWS at arbitrary position and move to stashed state.
	 * This is bit complicated (however you can think about this as
	 * a plain pushdown automaton), but reduces FSM code size.
	 */
	__FSM_STATE(RGen_LWS) {
		switch (c) {
		case '\r':
			if (likely(!(parser->flags & TFW_HTTP_PF_CRLF))) {
				parser->flags |= TFW_HTTP_PF_CR;
				__FSM_MOVE(RGen_LWS);
			}
			return TFW_BLOCK;
		case '\n':
			if (likely(!(parser->flags & TFW_HTTP_PF_LF))) {
				parser->flags |= TFW_HTTP_PF_LF;
				__FSM_MOVE(RGen_LWS);
			}
			return TFW_BLOCK;
		case ' ':
		case '\t':
			__FSM_MOVE(RGen_LWS);
		default:
			/* Field values should start from ALNUM. */
			if (unlikely(!isalnum(c)))
				return TFW_BLOCK;
			parser->flags &= ~TFW_HTTP_PF_CRLF;
			parser->state = parser->_i_st;
			parser->_i_st = 0;
			____FSM_MOVE_LAMBDA(fsm_reenter, 0, goto done);
		}
	}

	/* Parse headers starting from 'C'. */
	__FSM_STATE(Req_HdrC) {
		if (unlikely(!IN_ALPHABET(c, hdr_a)))
			return TFW_BLOCK;

		switch (LC(c)) {
		case 'a':
			if (likely(p + 12 <= data + len
				   && C4_INT_LCM(p, 'a', 'c', 'h', 'e')
				   && *(p + 4) == '-'
				   && C8_INT_LCM(p + 5, 'c', 'o', 'n', 't',
							'r', 'o', 'l', ':')))
			{
				parser->_i_st = Req_HdrCache_ControlV;
				__FSM_MOVE_n(RGen_LWS, 13);
			}
			__FSM_MOVE(Req_HdrCa);
		case 'o':
			if (likely(p + 13 <= data + len
				   && C4_INT_LCM(p + 1, 'n', 't', 'e', 'n')
				   && tolower(*(p + 5)) == 't'
				   && *(p + 6) == '-'
				   && C4_INT_LCM(p + 7, 'l', 'e', 'n', 'g')
				   && tolower(*(p + 11)) == 't'
				   && tolower(*(p + 12)) == 'h'
				   && *(p + 13) == ':'))
			{
				parser->_i_st = Req_HdrContent_Length;
				__FSM_MOVE_n(RGen_LWS, 14);
			}
			if (likely(C8_INT_LCM(p + 1, 'n', 'n', 'e', 'c',
						     't', 'i', 'o', 'n')))
				__FSM_MOVE_n(Req_HdrConnection, 9);
			__FSM_MOVE(Req_HdrCo);
		default:
			__FSM_JMP(Req_HdrOther);
		}
	}

	/* 'Host:*LWS' is read, process field-value. */
	__TFW_HTTP_PARSE_HDR_VAL(Req_HdrHostV, Req_Hdr, Req_I_H, req,
				 __req_parse_host, TFW_HTTP_HDR_HOST);

	/* 'Cache-Control:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Req_HdrCache_ControlV, Req_Hdr, Req_I_CC, req,
			       __req_parse_cache_control);

	/* 'Connection:*LWS' is read, process field-value. */
	__TFW_HTTP_PARSE_HDR_VAL(Req_HdrConnectionV, Req_Hdr, I_Conn,
				 (TfwHttpMsg *)req, __parse_connection,
				 TFW_HTTP_HDR_CONNECTION);

	/* 'Content-Length:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Req_HdrContent_LengthV, Req_Hdr, I_ContLen,
			       (TfwHttpMsg *)req, __parse_content_length);

	/* 'Transfer-Encoding:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Req_HdrTransfer_EncodingV, Req_Hdr, I_TransEncod,
			       (TfwHttpMsg *)req, __parse_transfer_encoding);

	/*
	 * Other (non interesting HTTP headers).
	 * Note that some of them (like Cookie or User-Agent can be
	 * extremely large).
	 */
	__FSM_STATE(Req_HdrOther) {
		/* Just eat the header until LF. */
		char *p1 = memchr(p, '\n', len);
		if (p1) {
			/* Get length of the header. */
			unsigned char *cr = p1 - 1;
			while (cr != p && *cr == '\r')
				--cr;
			CLOSE_HEADER(req, TFW_HTTP_HDR_RAW, cr - p);
			p = p1; /* move to just after LF */
			__FSM_MOVE(Req_Hdr);
		}
		STORE_HEADER(req, TFW_HTTP_HDR_RAW, len);
		__FSM_MOVE_n(Req_HdrOther, len);
	}

	/* Request headers are fully read. */
	__FSM_STATE(Req_HdrDone) {
		if (c == '\n')
			TFW_HTTP_INIT_BODY_PARSING(req, Req_Body);
		return TFW_BLOCK;
	}

	/* ----------------    Request body    ---------------- */

	TFW_HTTP_PARSE_BODY(Req, req);

	/* ----------------    Improbable states    ---------------- */

	/* Parse HTTP version (only 1.1 is supported). */
	__FSM_TX(Req_HttpVerT1, 'T', Req_HttpVerT2);
	__FSM_TX(Req_HttpVerT2, 'T', Req_HttpVerP);
	__FSM_TX(Req_HttpVerP, 'P', Req_HttpVerSlash);
	__FSM_TX(Req_HttpVerSlash, '/', Req_HttpVer11);
	__FSM_TX(Req_HttpVer11, '1', Req_HttpVerDot);
	__FSM_TX(Req_HttpVerDot, '.', Req_HttpVer12);
	__FSM_TX(Req_HttpVer12, '1', Req_EoL);

	/* Cache-Control header processing. */
	__FSM_TX_AF(Req_HdrCa, 'c', Req_HdrCac, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrCac, 'h', Req_HdrCach, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrCach, 'e', Req_HdrCache, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrCache, '-', Req_HdrCache_, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrCache_, 'c', Req_HdrCache_C, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrCache_C, 'o', Req_HdrCache_Co, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrCache_Co, 'n', Req_HdrCache_Con, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrCache_Con, 't', Req_HdrCache_Cont, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrCache_Cont, 'r', Req_HdrCache_Contr, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrCache_Contr, 'o', Req_HdrCache_Contro, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrCache_Contro, 'l', Req_HdrCache_Control, hdr_a, Req_HdrOther);
	__FSM_TX_AF_LWS(Req_HdrCache_Control, ':', Req_HdrCache_ControlV, hdr_a, Req_HdrOther);

	/* Connection header processing. */
	__FSM_TX_AF(Req_HdrCo, 'n', Req_HdrCon, hdr_a, Req_HdrOther);
	__FSM_STATE(Req_HdrCon) {
		if (unlikely(!IN_ALPHABET(c, hdr_a)))
			return TFW_BLOCK;

		switch (LC(c)) {
		case 'n':
			__FSM_MOVE(Req_HdrConn);
		case 't':
			__FSM_MOVE(Req_HdrCont);
		default:
			__FSM_MOVE(Req_HdrOther);
		}
	}
	__FSM_TX_AF(Req_HdrConn, 'e', Req_HdrConne, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrConne, 'c', Req_HdrConnec, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrConnec, 't', Req_HdrConnect, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrConnect, 'i', Req_HdrConnecti, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrConnecti, 'o', Req_HdrConnectio, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrConnectio, 'n', Req_HdrConnection, hdr_a, Req_HdrOther);
	__FSM_TX_AF_LWS(Req_HdrConnection, ':', Req_HdrConnectionV, hdr_a, Req_HdrOther);

	/* Content-Length header processing. */
	__FSM_TX_AF(Req_HdrCont, 'e', Req_HdrConte, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrConte, 'n', Req_HdrConten, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrConten, 't', Req_HdrContent, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrContent, '-', Req_HdrContent_, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrContent_, 'l', Req_HdrContent_L, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrContent_L, 'e', Req_HdrContent_Le, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrContent_Le, 'n', Req_HdrContent_Len, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrContent_Len, 'g', Req_HdrContent_Leng, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrContent_Leng, 't', Req_HdrContent_Lengt, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrContent_Lengt, 'h', Req_HdrContent_Length, hdr_a, Req_HdrOther);
	__FSM_TX_AF_LWS(Req_HdrContent_Length, ':', Req_HdrContent_LengthV, hdr_a, Req_HdrOther);

	/* Host header processing. */
	__FSM_TX_AF(Req_HdrH, 'o', Req_HdrHo, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrHo, 's', Req_HdrHos, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrHos, 't', Req_HdrHost, hdr_a, Req_HdrOther);
	__FSM_TX_AF_LWS(Req_HdrHost, ':', Req_HdrHostV, hdr_a, Req_HdrOther);

	/* Transfer-Encoding header processing. */
	__FSM_TX_AF(Req_HdrT, 'r', Req_HdrTr, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTr, 'a', Req_HdrTra, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTra, 'n', Req_HdrTran, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTran, 's', Req_HdrTrans, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTrans, 'f', Req_HdrTransf, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransf, 'e', Req_HdrTransfe, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransfe, 'r', Req_HdrTransfer, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer, '-', Req_HdrTransfer_, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_, 'e', Req_HdrTransfer_E, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_E, 'n', Req_HdrTransfer_En, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_En, 'c', Req_HdrTransfer_Enc, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_Enc, 'o', Req_HdrTransfer_Enco, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_Enco, 'd', Req_HdrTransfer_Encod, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_Encod, 'i', Req_HdrTransfer_Encodi, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_Encodi, 'n', Req_HdrTransfer_Encodin, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrTransfer_Encodin, 'g', Req_HdrTransfer_Encoding, hdr_a, Req_HdrOther);
	__FSM_TX_AF_LWS(Req_HdrTransfer_Encoding, ':', Req_HdrTransfer_EncodingV, hdr_a, Req_HdrOther);

	}
	__FSM_FINISH(req);

	return r;
}

/*
 * ------------------------------------------------------------------------
 *	HTTP response parsing
 * ------------------------------------------------------------------------
 */
/* Helping (inferior) states to process particular parts of HTTP request. */
enum {
	Resp_I_0,

	/* Cache-Control header */
	Resp_I_CC,
	Resp_I_CC_MaxAgeV,
	Resp_I_CC_SMaxAgeV,
	/* Expires header */
	Resp_I_Expires,
	Resp_I_ExpDate,
	Resp_I_ExpMonth,
	Resp_I_ExpYearSP,
	Resp_I_ExpYear,
	Resp_I_ExpHour,
	Resp_I_ExpMin,
	Resp_I_ExpSec,
	/* Keep-Alive header. */
	Resp_I_KeepAlive,
	Resp_I_KeepAliveTO,

	Resp_I_Ext,
	Resp_I_EoT,
	Resp_I_EoL,
};

/**
 * Parse response Cache-Control, RFC 2616 14.9
 */
static int
__resp_parse_cache_control(TfwHttpResp *resp, unsigned char *data, size_t *lenrval)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &resp->parser;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	size_t len = *lenrval;
	unsigned char c = *p;
	bool hlen_set = false;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Resp_I_CC) {
		switch (tolower(c)) {
		case 'm':
			TRY_STR("max-age=", Resp_I_CC_MaxAgeV);
			TRY_STR_LAMBDA("must-revalidate", {
				resp->cache_ctl.flags |= TFW_HTTP_CC_MUST_REV;
				__FSM_I_MOVE_str(Resp_I_EoT, "must-revalidate");
			});
			goto cache_extension;
		case 'n':
			TRY_STR_LAMBDA("no-cache", {
				resp->cache_ctl.flags |= TFW_HTTP_CC_NO_CACHE;
				__FSM_I_MOVE_str(Resp_I_EoT, "no-cache");
			});
			TRY_STR_LAMBDA("no-store", {
				resp->cache_ctl.flags |= TFW_HTTP_CC_NO_STORE;
				__FSM_I_MOVE_str(Resp_I_EoT, "no-store");
			});
			TRY_STR_LAMBDA("no-transform", {
				resp->cache_ctl.flags |= TFW_HTTP_CC_NO_TRANS;
				__FSM_I_MOVE_str(Resp_I_EoT, "no-transform");
			});
			goto cache_extension;
		case 'p':
			TRY_STR_LAMBDA("public", {
				resp->cache_ctl.flags |= TFW_HTTP_CC_PUBLIC;
				__FSM_I_MOVE_str(Resp_I_EoT, "public");
			});
			TRY_STR_LAMBDA("private", {
				resp->cache_ctl.flags |= TFW_HTTP_CC_PUBLIC;
				__FSM_I_MOVE_str(Resp_I_EoT, "private");
			});
			TRY_STR_LAMBDA("proxy-revalidate", {
				resp->cache_ctl.flags |= TFW_HTTP_CC_PROXY_REV;
				__FSM_I_MOVE_str(Resp_I_EoT,
						 "proxy-revalidate");
			});
			goto cache_extension;
		case 's':
			TRY_STR("s-maxage=", Resp_I_CC_SMaxAgeV);
		default:
		cache_extension:
			__FSM_I_MOVE_n(Resp_I_Ext, 0);
		}
	}

	__FSM_STATE(Resp_I_CC_MaxAgeV) {
		unsigned int acc = 0;
		int n = __parse_int(chunk, p, len, &acc);
		if (n < 0)
			return n;
		resp->cache_ctl.max_age = acc;
		__FSM_I_MOVE_n(Resp_I_EoT, n);
	}

	__FSM_STATE(Resp_I_CC_SMaxAgeV) {
		unsigned int acc = 0;
		int n = __parse_int(chunk, p, len, &acc);
		if (n < 0)
			return n;
		resp->cache_ctl.s_maxage = acc;
		__FSM_I_MOVE_n(Resp_I_EoT, n);
	}

	__FSM_STATE(Resp_I_Ext) {
		/*
		 * TODO
		 * - process cache extaensions;
		 * - replace double memchr() below by strspn() analog which
		 *   accepts string length instead of processing null-terminated
		 *   strings.
		 */
		unsigned char *lf = memchr(p, '\n', len);
		unsigned char *comma = memchr(p, ',', len);
		if (comma && comma < lf)
			__FSM_I_MOVE_n(Resp_I_EoT, comma - p);
		if (lf)
			__FSM_I_MOVE_n(Resp_I_EoL, lf - p);
		return CSTR_POSTPONE;
	}

	/* End of term. */
	__FSM_STATE(Resp_I_EoT) {
		if (c == ' ' || c == ',')
			__FSM_I_MOVE(Resp_I_EoT);
		/*
		 * TODO: we're don't support for now field values for no-cache and
		 * private fields, so just skip '=[hdr_a]*'.
		 */
		if (c == '=')
			__FSM_I_MOVE(Resp_I_Ext);
		if (IN_ALPHABET(c, hdr_a))
			__FSM_I_MOVE(Resp_I_CC);
		if (!isspace(c))
			return CSTR_NEQ;
		/* fall through */
	}

	__FSM_STATE(Resp_I_EoL) {
		if (!hlen_set) {
			*lenrval = p - data; /* set header length */
			hlen_set = true;
		}
		if (c == '\n') {
			r = p - data + 1;
			goto done;
		}
		if (isspace(c))
			/* Eat all spaces including '\r'. */
			__FSM_I_MOVE(Resp_I_EoL);

		return CSTR_NEQ;
	}

	} // FSM END
done:
	parser->_i_st = Resp_I_0;
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
/* Number of days befor epoch including leap years. */
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

static int
__resp_parse_expires(TfwHttpResp *resp, unsigned char *data, size_t *lenrval)
{
	TfwHttpParser *parser = &resp->parser;
	TfwStr *chunk = &parser->_tmp_chunk;
	int r = CSTR_NEQ;
	unsigned char *p = data;
	size_t len = *lenrval;
	unsigned char c = *p;
	bool hlen_set = false;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Resp_I_Expires) {
		/* Skip week day as redundant information. */
		unsigned char *sp = memchr(p, ' ', len);
		if (sp)
			__FSM_I_MOVE_n(Resp_I_ExpDate, sp - p);
		return CSTR_POSTPONE;

	}

	__FSM_STATE(Resp_I_ExpDate) {
		unsigned int acc = 0;
		int n;

		if (!isdigit(c))
			return CSTR_NEQ;

		/* date1: parse 2-digit day. */
		n = __parse_int(chunk, p, len, &acc);
		if (n < 0)
			return n;
		else if (n != 2 || acc < 1)
			return CSTR_BADLEN;
		/* Add seconds in full passed days. */
		resp->expires = (acc - 1) * SEC24H;
		/* Skip the day and SP. */
		__FSM_I_MOVE_n(Resp_I_ExpMonth, 3);
	}

	__FSM_STATE(Resp_I_ExpMonth) {
		switch (c) {
		case 'A':
			TRY_STR_LAMBDA("Apr", {
				resp->expires += SB_APR;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			TRY_STR_LAMBDA("Aug", {
				resp->expires += SB_AUG;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			return CSTR_NEQ;
		case 'J':
			TRY_STR_LAMBDA("Jan", {
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			TRY_STR_LAMBDA("Jun", {
				resp->expires += SB_JUN;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			TRY_STR_LAMBDA("Jul", {
				resp->expires += SB_JUL;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			return CSTR_NEQ;
		case 'M':
			TRY_STR_LAMBDA("Mar", {
				/* Add SEC24H for leap year on year parsing. */
				resp->expires += SB_MAR;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			TRY_STR_LAMBDA("May", {
				resp->expires += SB_MAY;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			return CSTR_NEQ;
		default:
			TRY_STR_LAMBDA("Feb", {
				resp->expires += SB_FEB;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			TRY_STR_LAMBDA("Sep", {
				resp->expires += SB_SEP;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			TRY_STR_LAMBDA("Oct", {
				resp->expires += SB_OCT;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			TRY_STR_LAMBDA("Nov", {
				resp->expires += SB_NOV;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			TRY_STR_LAMBDA("Dec", {
				resp->expires += SB_DEC;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 4);
			});
			return CSTR_NEQ;
		}
	}

	/* Eat SP between Month and Year. */
	__FSM_STATE(Resp_I_ExpYearSP) {
		if (c == ' ')
			__FSM_I_MOVE(Resp_I_ExpYear);
		return CSTR_NEQ;
	}

	/* 4-digit year. */
	__FSM_STATE(Resp_I_ExpYear) {
		unsigned int year = 0;
		int n = __parse_int(chunk, p, len, &year);
		if (n < 0)
			return n;
		else if (n != 4)
			return CSTR_BADLEN;
		n = __year_day_secs(year, resp->expires);
		if (n < 0)
			return CSTR_NEQ;
		resp->expires = n;
		/* Skip the year and follwing SP. */
		__FSM_I_MOVE_n(Resp_I_ExpHour, 5);
	}

	__FSM_STATE(Resp_I_ExpHour) {
		unsigned int t = 0;
		int n = __parse_int(chunk, p, len, &t);
		if (n < 0)
			return n;
		else if (n != 2)
			return CSTR_BADLEN;
		resp->expires = t * 3600;
		/* Skip hour and follwing ':'. */
		__FSM_I_MOVE_n(Resp_I_ExpMin, 3);
	}

	__FSM_STATE(Resp_I_ExpMin) {
		unsigned int t = 0;
		int n = __parse_int(chunk, p, len, &t);
		if (n < 0)
			return n;
		else if (n != 2)
			return CSTR_BADLEN;
		resp->expires = t * 60;
		/* Skip minutes and follwing ':'. */
		__FSM_I_MOVE_n(Resp_I_ExpSec, 3);
	}

	__FSM_STATE(Resp_I_ExpSec) {
		unsigned int t = 0;
		int n = __parse_int(chunk, p, len, &t);
		if (n < 0)
			return n;
		else if (n != 2)
			return CSTR_BADLEN;
		resp->expires = t;
		/* Skip seconds and follwing ' GMT'. */
		__FSM_I_MOVE_n(Resp_I_EoL, 6);
	}

	__FSM_STATE(Resp_I_EoL) {
		if (!hlen_set) {
			*lenrval = p - data; /* set header length */
			hlen_set = true;
		}
		if (c == '\n') {
			r = p - data + 1;
			goto done;
		}
		if (isspace(c))
			/* Eat all spaces including '\r'. */
			__FSM_I_MOVE(Resp_I_EoL);

		return CSTR_NEQ;
	}

	} // FSM END
done:
	parser->_i_st = Resp_I_0;
	return r;
}

static int
__resp_parse_keep_alive(TfwHttpResp *resp, unsigned char *data, size_t *lenrval)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &resp->parser;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	size_t len = *lenrval;
	unsigned char c = *p;
	bool hlen_set = false;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Resp_I_KeepAlive) {
		TRY_STR("timeout=", Resp_I_KeepAliveTO);
	}

	__FSM_STATE(Resp_I_KeepAliveTO) {
		unsigned int acc = 0;
		int n = __parse_int(chunk, p, len, &acc);
		if (n < 0)
			return n;
		resp->keep_alive = acc;
		__FSM_I_MOVE_n(Resp_I_EoL, n);
	}

	__FSM_STATE(Resp_I_EoL) {
		if (!hlen_set) {
			*lenrval = p - data; /* set header length */
			hlen_set = true;
		}
		if (c == '\n') {
			r = p - data + 1;
			goto done;
		}
		if (isspace(c))
			/* Eat all spaces including '\r'. */
			__FSM_I_MOVE(Resp_I_EoL);

		return CSTR_NEQ;
	}

	} // FSM END
done:
	parser->_i_st = Resp_I_0;
	return r;
}

/* Main (parent) HTTP response processing states. */
enum {
	Resp_0,
	Resp_EoL,
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
	Resp_HdrOther,
	Resp_HdrDone,
	/* Body */
	Resp_Body,
	Resp_BodyChunkEoL,
	Resp_BodyReadChunk,
	Resp_Done
};

int
tfw_http_parse_resp(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	TfwHttpParser *parser = &resp->parser;
	TfwHttpMsg *msg = (TfwHttpMsg *)resp;
	int r = TFW_BLOCK;
	unsigned char *p = data;
	unsigned char c = *p;

	__FSM_START(parser->state) {

	/* ----------------    Status Line    ---------------- */

	__FSM_STATE(Resp_0) {
		if (unlikely(c == '\r' || c == '\n'))
			__FSM_MOVE(Resp_0);
		__FSM_MOVE(Resp_HttpVer);
	}

	/* HTTP version */
	__FSM_STATE(Resp_HttpVer) {
		if (likely(p + 9 <= data + len)) {
			/* Quick path. */
			if (*(unsigned long *)(p + 1)
			     == TFW_CHAR8_INT('H', 'T', 'T', 'P',
					      '/', '1', '.', '1')
			    && *(p + 8) == ' ')
				__FSM_MOVE(Resp_StatusCode);
			else
				return TFW_BLOCK;
		}

		/* Slow path. */
		if (c == 'H')
			__FSM_MOVE(Resp_HttpVerT1);
		return TFW_BLOCK;
	}

	/* Response Status-Code. */
	__FSM_STATE(Resp_StatusCode) {
		unsigned int acc = 0;
		long n = data + len - p;

		BUG_ON(n < 0);

		parser->_i_st = I_Conn;
		r = __parse_int(&parser->_tmp_chunk, p, n, &acc);
		switch (r) {
		case CSTR_POSTPONE:
			/* Not all the header data is parsed. */
			__FSM_MOVE_n(Resp_StatusCode, n);
		case CSTR_BADLEN:
		case CSTR_NEQ:
			/* bad status value */
			return TFW_BLOCK;
		default:
			/* The header value is fully parsed, move forward. */
			resp->status = acc;
			__FSM_MOVE_n(Resp_ReasonPhrase, r);
		}
	}

	/* Reason-Phrase: just skip. */
	__FSM_STATE(Resp_ReasonPhrase) {
		unsigned char *eol = memchr(p, '\n', len);
		if (!p)
			__FSM_MOVE_n(Resp_ReasonPhrase, len);
		__FSM_MOVE_n(Resp_Hdr, eol - p + 1);
	}

	/* ----------------    Header Lines    ---------------- */

	/* Start of HTTP header or end of whole request. */
	__FSM_STATE(Resp_Hdr) {
		if (parser->hdr.ptr)
			tfw_str_add_compound(resp->pool, &parser->hdr);

		if (unlikely(c == '\r')) {
			if (!resp->body.ptr) {
				resp->crlf = p;
				__FSM_MOVE(Resp_HdrDone);
			} else
				__FSM_MOVE(Resp_Done);
		}
		if (unlikely(c == '\n')) {
			if (!resp->body.ptr) {
				TFW_HTTP_INIT_BODY_PARSING(resp, Resp_Body);
			} else {
				r = TFW_PASS;
				goto done;
			}
		}

		if (unlikely(!IN_ALPHABET(c, hdr_a)))
			return TFW_BLOCK;

		/* We're going to read new header, remember it. */
		TFW_STR_CURR(&parser->hdr)->ptr = p;

		switch (LC(c)) {
		case 'c':
			__FSM_MOVE(Resp_HdrC);
		case 'e':
			if (likely(C8_INT_LCM(p, 'e', 'x', 'p', 'i',
						 'r', 'e', 's', ':')))
			{
				parser->_i_st = Resp_HdrExpiresV;
				__FSM_MOVE_n(RGen_LWS, 8);
			}
			__FSM_MOVE(Resp_HdrE);
		case 'k':
			if (likely(p + 9 <= data + len
				   && C4_INT_LCM(p, 'k', 'e', 'e', 'p')
				   && *(p + 4) == '-'
				   && C4_INT_LCM(p + 5, 'a', 'l', 'i', 'v')
				   && tolower(*(p + 8)) == 'e'
				   && *(p + 9) == ':'))
			{
				parser->_i_st = Resp_HdrKeep_AliveV;
				__FSM_MOVE_n(RGen_LWS, 13);
			}
			__FSM_MOVE(Resp_HdrK);
		case 't':
			if (likely(p + 17 <= data + len
				   && C8_INT_LCM(p, 't', 'r', 'a', 'n',
					   	    's', 'f', 'e', 'r')
				   && *(p + 8) == '-'
				   && C8_INT_LCM(p + 9, 'e', 'n', 'c', 'o',
							'd', 'i', 'n', 'g')
				   && *(p + 17) == ':'))
			{
				parser->_i_st = Resp_HdrTransfer_EncodingV;
				__FSM_MOVE_n(RGen_LWS, 18);
			}
			__FSM_MOVE(Resp_HdrT);
		default:
			__FSM_MOVE(Resp_HdrOther);
		}
	}

	/*
	 * Read LWS at arbitrary position and move to stashed state.
	 * This is bit complicated (however you can think about this as
	 * a plain pushdown automaton), but reduces FSM code size.
	 */
	__FSM_STATE(RGen_LWS) {
		switch (c) {
		case '\r':
			if (likely(!(parser->flags & TFW_HTTP_PF_CRLF))) {
				parser->flags |= TFW_HTTP_PF_CR;
				__FSM_MOVE(RGen_LWS);
			}
			return TFW_BLOCK;
		case '\n':
			if (likely(!(parser->flags & TFW_HTTP_PF_LF))) {
				parser->flags |= TFW_HTTP_PF_LF;
				__FSM_MOVE(RGen_LWS);
			}
			return TFW_BLOCK;
		case ' ':
		case '\t':
			__FSM_MOVE(RGen_LWS);
		default:
			/* Field values should start from ALNUM. */
			if (unlikely(!isalnum(c)))
				return TFW_BLOCK;
			parser->flags &= ~TFW_HTTP_PF_CRLF;
			parser->state = parser->_i_st;
			parser->_i_st = 0;
			____FSM_MOVE_LAMBDA(fsm_reenter, 1, goto done);
		}
	}

	/* Parse headers starting from 'C'. */
	__FSM_STATE(Resp_HdrC) {
		if (unlikely(!IN_ALPHABET(c, hdr_a)))
			return TFW_BLOCK;

		switch (LC(c)) {
		case 'a':
			if (likely(p + 12 <= data + len
				   && C4_INT_LCM(p, 'a', 'c', 'h', 'e')
				   && *(p + 4) == '-'
				   && C8_INT_LCM(p + 5, 'c', 'o', 'n', 't',
							'r', 'o', 'l', ':')))
			{
				parser->_i_st = Resp_HdrCache_ControlV;
				__FSM_MOVE_n(RGen_LWS, 13);
			}
			__FSM_MOVE(Resp_HdrCa);
		case 'o':
			if (likely(p + 13 <= data + len
				   && C4_INT_LCM(p + 1, 'n', 't', 'e', 'n')
				   && tolower(*(p + 5)) == 't'
				   && *(p + 6) == '-'
				   && C4_INT_LCM(p + 7, 'l', 'e', 'n', 'g')
				   && tolower(*(p + 11)) == 't'
				   && tolower(*(p + 12)) == 'h'
				   && *(p + 13) == ':'))
			{
				parser->_i_st = Resp_HdrContent_Length;
				__FSM_MOVE_n(RGen_LWS, 14);
			}
			if (likely(C8_INT_LCM(p + 1, 'n', 'n', 'e', 'c',
						     't', 'i', 'o', 'n')))
				__FSM_MOVE_n(Resp_HdrConnection, 9);
			__FSM_MOVE(Resp_HdrCo);
		default:
			__FSM_MOVE(Resp_HdrOther);
		}
	}

	/* 'Cache-Control:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Resp_HdrCache_ControlV, Resp_Hdr, Resp_I_CC,
			       resp, __resp_parse_cache_control);

	/* 'Connection:*LWS' is read, process field-value. */
	__TFW_HTTP_PARSE_HDR_VAL(Resp_HdrConnectionV, Resp_Hdr, I_Conn,
				 (TfwHttpMsg *)resp, __parse_connection,
				 TFW_HTTP_HDR_CONNECTION);

	/* 'Content-Length:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Resp_HdrContent_LengthV, Resp_Hdr, I_ContLen,
			       (TfwHttpMsg *)resp, __parse_content_length);

	/* 'Expires:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Resp_HdrExpiresV, Resp_Hdr, Resp_I_Expires,
			       resp, __resp_parse_expires);

	/* 'Keep-Alive:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Resp_HdrKeep_AliveV, Resp_Hdr, Resp_I_KeepAlive,
			       resp, __resp_parse_keep_alive);

	/* 'Transfer-Encoding:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Resp_HdrTransfer_EncodingV, Resp_Hdr,
			       I_TransEncod, (TfwHttpMsg *)resp,
			       __parse_transfer_encoding);

	/*
	 * Other (non interesting HTTP headers).
	 * Note that some of them (like Cookie or User-Agent can be
	 * extremely large).
	 */
	__FSM_STATE(Resp_HdrOther) {
		/* Just eat the header until LF. */
		p = memchr(p, '\n', len);
		if (p)
			__FSM_MOVE_n(Resp_Hdr, 1);
		__FSM_MOVE_n(Resp_HdrOther, len);
	}

	/* Response headers are fully read. */
	__FSM_STATE(Resp_HdrDone) {
		if (c == '\n')
			TFW_HTTP_INIT_BODY_PARSING(resp, Resp_Body);
		return TFW_BLOCK;
	}

	/* ----------------    Response body    ---------------- */

	TFW_HTTP_PARSE_BODY(Resp, resp);

	/* ----------------    Improbable states    ---------------- */

	/* Parse HTTP version and SP (only 1.1 is supported). */
	__FSM_TX(Resp_HttpVerT1, 'T', Resp_HttpVerT2);
	__FSM_TX(Resp_HttpVerT2, 'T', Resp_HttpVerP);
	__FSM_TX(Resp_HttpVerP, 'P', Resp_HttpVerSlash);
	__FSM_TX(Resp_HttpVerSlash, '/', Resp_HttpVer11);
	__FSM_TX(Resp_HttpVer11, '1', Resp_HttpVerDot);
	__FSM_TX(Resp_HttpVerDot, '.', Resp_HttpVer12);
	__FSM_TX(Resp_HttpVer12, '1', Resp_SSpace);
	__FSM_TX(Resp_SSpace, ' ', Resp_StatusCode);

	/* Cache-Control header processing. */
	__FSM_TX_AF(Resp_HdrCa, 'c', Resp_HdrCac, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrCac, 'h', Resp_HdrCach, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrCach, 'e', Resp_HdrCache, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrCache, '-', Resp_HdrCache_, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_, 'c', Resp_HdrCache_C, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_C, 'o', Resp_HdrCache_Co, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_Co, 'n', Resp_HdrCache_Con, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_Con, 't', Resp_HdrCache_Cont, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_Cont, 'r', Resp_HdrCache_Contr, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_Contr, 'o', Resp_HdrCache_Contro, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrCache_Contro, 'l', Resp_HdrCache_Control, hdr_a, Resp_HdrOther);
	__FSM_TX_AF_LWS(Resp_HdrCache_Control, ':', Resp_HdrCache_ControlV, hdr_a, Resp_HdrOther);

	/* Connection header processing. */
	__FSM_TX_AF(Resp_HdrCo, 'n', Resp_HdrCon, hdr_a, Resp_HdrOther);
	__FSM_STATE(Resp_HdrCon) {
		if (unlikely(!IN_ALPHABET(c, hdr_a)))
			return TFW_BLOCK;

		switch (LC(c)) {
		case 'n':
			__FSM_MOVE(Resp_HdrConn);
		case 't':
			__FSM_MOVE(Resp_HdrCont);
		default:
			__FSM_MOVE(Resp_HdrOther);
		}
	}
	__FSM_TX_AF(Resp_HdrConn, 'e', Resp_HdrConne, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrConne, 'c', Resp_HdrConnec, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrConnec, 't', Resp_HdrConnect, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrConnect, 'i', Resp_HdrConnecti, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrConnecti, 'o', Resp_HdrConnectio, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrConnectio, 'n', Resp_HdrConnection, hdr_a, Resp_HdrOther);
	__FSM_TX_AF_LWS(Resp_HdrConnection, ':', Resp_HdrConnectionV, hdr_a, Resp_HdrOther);

	/* Content-Length header processing. */
	__FSM_TX_AF(Resp_HdrCont, 'e', Resp_HdrConte, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrConte, 'n', Resp_HdrConten, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrConten, 't', Resp_HdrContent, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrContent, '-', Resp_HdrContent_, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_, 'l', Resp_HdrContent_L, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_L, 'e', Resp_HdrContent_Le, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_Le, 'n', Resp_HdrContent_Len, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_Len, 'g', Resp_HdrContent_Leng, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_Leng, 't', Resp_HdrContent_Lengt, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrContent_Lengt, 'h', Resp_HdrContent_Length, hdr_a, Resp_HdrOther);
	__FSM_TX_AF_LWS(Resp_HdrContent_Length, ':', Resp_HdrContent_LengthV, hdr_a, Resp_HdrOther);

	/* Expires header processing. */
	__FSM_TX_AF(Resp_HdrE, 'x', Resp_HdrEx, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrEx, 'p', Resp_HdrExp, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrExp, 'i', Resp_HdrExpi, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrExpi, 'r', Resp_HdrExpir, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrExpir, 'e', Resp_HdrExpire, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrExpire, 's', Resp_HdrExpires, hdr_a, Resp_HdrOther);
	__FSM_TX_AF_LWS(Resp_HdrExpires, ':', Resp_HdrExpiresV, hdr_a, Resp_HdrOther);

	/* Keep-Alive header processing. */
	__FSM_TX_AF(Resp_HdrK, 'e', Resp_HdrKe, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrKe, 'e', Resp_HdrKee, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrKee, 'p', Resp_HdrKeep, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep, '-', Resp_HdrKeep_, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep_, 'a', Resp_HdrKeep_A, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep_A, 'l', Resp_HdrKeep_Al, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep_Al, 'i', Resp_HdrKeep_Ali, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep_Ali, 'v', Resp_HdrKeep_Aliv, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrKeep_Aliv, 'e', Resp_HdrKeep_Alive, hdr_a, Resp_HdrOther);
	__FSM_TX_AF_LWS(Resp_HdrKeep_Alive, ':', Resp_HdrKeep_AliveV, hdr_a, Resp_HdrOther);

	/* Transfer-Encoding header processing. */
	__FSM_TX_AF(Resp_HdrT, 'r', Resp_HdrTr, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTr, 'a', Resp_HdrTra, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTra, 'n', Resp_HdrTran, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTran, 's', Resp_HdrTrans, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTrans, 'f', Resp_HdrTransf, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransf, 'e', Resp_HdrTransfe, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfe, 'r', Resp_HdrTransfer, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer, '-', Resp_HdrTransfer_, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_, 'e', Resp_HdrTransfer_E, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_E, 'n', Resp_HdrTransfer_En, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_En, 'c', Resp_HdrTransfer_Enc, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_Enc, 'o', Resp_HdrTransfer_Enco, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_Enco, 'd', Resp_HdrTransfer_Encod, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_Encod, 'i', Resp_HdrTransfer_Encodi, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_Encodi, 'n', Resp_HdrTransfer_Encodin, hdr_a, Resp_HdrOther);
	__FSM_TX_AF(Resp_HdrTransfer_Encodin, 'g', Resp_HdrTransfer_Encoding, hdr_a, Resp_HdrOther);
	__FSM_TX_AF_LWS(Resp_HdrTransfer_Encoding, ':', Resp_HdrTransfer_EncodingV, hdr_a, Resp_HdrOther);

	}
	__FSM_FINISH(resp);

	return r;
}
