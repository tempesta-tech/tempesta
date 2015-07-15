/**
 *		Tempesta FW
 *
 * HTTP Parser.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#include "http.h"
#include "lib.h"

/*
 * ------------------------------------------------------------------------
 *	Common HTTP routines
 * ------------------------------------------------------------------------
 */

/* Common states. */
enum {
	RGen_LWS = 10000,
	RGen_LF,
};

/**
 * Set final field length and mark it as finished.
 */
static inline void
__field_finish(TfwStr *field, unsigned char *begin, unsigned char *end)
{
	if (unlikely(!TFW_STR_PLAIN(field))) {
		if (unlikely(begin == end)) {
			tfw_str_del_chunk(field, TFW_STR_CHUNKN(field) - 1);
		} else {
			TfwStr *last = (TfwStr *)field->ptr
				       + TFW_STR_CHUNKN(field) - 1;
			/*
			 * This is not the first data segment,
			 * so current data starts at @begin.
			 */
			last->ptr = begin;
			tfw_str_updlen(field, end);
		}
	} else {
		/* field->ptr must be set before reaching current state. */
		BUG_ON(!field->ptr);
		field->len = end - (unsigned char *)field->ptr;
	}
	field->flags |= TFW_STR_COMPLETE;
}

/**
 * Slow check of generic (raw) header for singularity.
 * Some of the header should be special and moved to tfw_http_hdr_t enum,
 * so linear search is Ok here.
 * @return true for headers which must never have duplicates.
 */
static bool
hdr_is_singular(const TfwStr *hdr)
{
	int i, fc;
	static const TfwStr hdr_singular[] __read_mostly = {
#define TfwStr_string(v) { 0, sizeof(v) - 1, (v) }
		TfwStr_string("authorization:"),
		TfwStr_string("content-type:"),
		TfwStr_string("from:"),
		TfwStr_string("if-modified-since:"),
		TfwStr_string("if-unmodified-since:"),
		TfwStr_string("location:"),
		TfwStr_string("max-forwards:"),
		TfwStr_string("proxy-authorization:"),
		TfwStr_string("referer:"),
		TfwStr_string("user-agent:"),
#undef TfwStr_string
	};

	fc = tolower(*(unsigned char *)TFW_STR_CHUNK(hdr, 0));
	for (i = 0; i < ARRAY_SIZE(hdr_singular); i++) {
		const TfwStr *sh = &hdr_singular[i];
		int sc = *(unsigned char *)sh->ptr;
		if (fc > sc)
			continue;
		if (fc < sc)
			break;
		if (!tfw_stricmpspn(hdr, sh->ptr, ':'))
			return true;
	}
	return false;
}

/**
 * Lookup for the header @hdr in already collected headers table @ht,
 * i.e. check whether the header is duplicate.
 * @return the header id.
 *
 * Certain header fields are strictly singular and may not be repeated in
 * an HTTP message. Duplicate of a singular header fields is a bug worth
 * blocking the whole HTTP message.
 */
static int
hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr)
{
	int id;
	TfwHttpHdrTbl *ht = hm->h_tbl;

	for (id = TFW_HTTP_HDR_RAW; id < ht->off; ++id) {
		TfwStr *h = &ht->tbl[id].field;
		/* There is no sense to compare against all duplicates. */
		if (h->flags & TFW_STR_DUPLICATE)
			h = TFW_STR_CHUNK(h, 0);
		if (tfw_stricmpspn(hdr, h, ':'))
			continue;
		if (hdr_is_singular(hdr))
			hm->flags |= TFW_HTTP_FIELD_DUPENTRY;
		break;
	}

	return id;
}

/**
 * Open currently parsed header.
 */
static void
hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start)
{
	TfwStr *hdr = &hm->parser.hdr;

	BUG_ON(!TFW_STR_EMPTY(hdr));

	hdr->ptr = hdr_start;

	TFW_DBG("open header at char [%c]\n", *hdr_start);
}

/**
 * Fixup the new data chunk to currently parsed HTTP header.
 *
 * @len could be 0 if the header was fully read, but we realized this only
 * now by facinng CRLF at begin of current data chunk.
 */
static void
hdr_chunk_fixup(TfwHttpMsg *hm, unsigned char *data, long len)
{
	TfwStr *hdr = TFW_STR_CURR(&hm->parser.hdr);

	TFW_DBG("store header chunk len=%ld data=%p hdr=<%#x,%u,%p>\n",
		len, data, hdr->flags, hdr->len, hdr->ptr);

	/* The header should be open before. */
	if (unlikely(!hdr->ptr))
		return;

	if (!hdr->len) {
		/*
		 * The first data chunk case.
		 * The header chunk was explicitly opened at some data
		 * position, so close the chunk by end of @data.
		 */
		BUG_ON(!TFW_STR_PLAIN(hdr));
		hdr->len = data + len - (unsigned char *)hdr->ptr;
	}
	else if (len) {
		/*
		 * The data chunk doesn't lay at the header bounds.
		 * There is at least one finished chunk, add a new one.
		 */
		TfwStr *h = tfw_str_add_compound(hm->pool, hdr);
		if (unlikely(!h)) {
			TFW_WARN("Cannot store chunk [%.*s]\n",
				 min((int)len, 10), data);
			return;
		}
		h->ptr = data;
		tfw_str_updlen(hdr, data + len);
	}
}

/**
 * Store fully parsed, probably compound, header (i.e. close it) to
 * HTTP message headers list.
 */
static void
hdr_close(TfwHttpMsg *hm, int id)
{
	TfwStr *h;
	TfwHttpHdrTbl *ht = hm->h_tbl;

	BUG_ON(hm->parser.hdr.flags & TFW_STR_DUPLICATE);
	BUG_ON(id > TFW_HTTP_HDR_RAW);

	/* Close just parsed header. */
	hm->parser.hdr.flags |= TFW_STR_COMPLETE;

	/* Quick path for special headers. */
	if (likely(id < TFW_HTTP_HDR_RAW)) {
		h = &ht->tbl[id].field;
		if (TFW_STR_EMPTY(h))
			/* Just store the special header in empty slot. */
			goto done;

		/*
		 * Process duplicate header.
		 *
		 * RFC 7230 3.2.2: all duplicates of special singular
		 * headers must be blocked as early as possible,
		 * just when parser reads them.
		 */
		BUG_ON(id < TFW_HTTP_HDR_NONSINGULAR);
		/*
		 * RFC 7230 3.2.2: duplicate of non-singular special
		 * header - leave the decision to classification layer.
		 */
		hm->flags |= TFW_HTTP_FIELD_DUPENTRY;
		goto duplicate;
	}

	/*
	 * A new raw header is to be stored, but it can be a duplicate of some
	 * existing header and we must find appropriate index for it.
	 * Both the headers, the new one and existing one, can already be
	 * compound.
	 */
	id = hdr_lookup(hm, &hm->parser.hdr);

	/* Allocate some more room if not enough to store the header. */
	if (unlikely(id == ht->size)) {
		size_t order = hm->h_tbl->size / TFW_HTTP_HDR_NUM;

		if (__HHTBL_SZ(order + 1) >= TFW_HTTP_HDR_NUM_MAX) {
			TFW_WARN("Too many HTTP headers\n");
			return;
		}

		ht = tfw_pool_realloc(hm->pool, hm->h_tbl, TFW_HHTBL_SZ(order),
				      TFW_HHTBL_SZ(order + 1));
		if (!ht)
			return;
		ht->size = __HHTBL_SZ(order + 1);
		ht->off = hm->h_tbl->off;
		memset(ht->tbl + __HHTBL_SZ(order), 0,
		       __HHTBL_SZ(1) * sizeof(TfwHttpHdr));
		hm->h_tbl = ht;

		TFW_DBG("grow http headers table to %d items\n", ht->size);
	}

	h = &ht->tbl[id].field;

	if (!h->ptr)
		/* Add the new header. */
		goto done;

duplicate:
	h = tfw_str_add_duplicate(hm->pool, h);
	if (unlikely(!h)) {
		TFW_WARN("Cannot close header %p id=%d\n",
			 &hm->parser.hdr, id);
		return;
	}

done:
	*h = hm->parser.hdr;

	TFW_STR_INIT(&hm->parser.hdr);
	TFW_DBG("store header w/ ptr=%p len=%d flags=%x id=%d\n",
		h->ptr, h->len, h->flags, id);

	/* Move the offset forward if current header is fully read. */
	if (id == ht->off)
		ht->off++;
}

/**
 * GCC 4.8 (CentOS 7) does a poor work on memory reusage of automatic local
 * variables in nested blocks, so we declare all required temporal variables
 * used in the defines below here to reduce stack frame usage.
 * Since the variables are global now, be careful with them.
 */
#define __FSM_START(s)							\
int __fsm_const_state;							\
/* Declare FSM automatic variables, the variables have only local sense. */ \
int __fsm_n __attribute__((unused));					\
size_t __fsm_sz __attribute__((unused));				\
unsigned char *__fsm_ch __attribute__((unused));			\
TfwStr *__fsm_str __attribute__((unused));				\
parser->data_off = 0; /* new data chunk */				\
fsm_reenter: __attribute__((unused))					\
	TFW_DBG("enter FSM at state %d\n", s);				\
switch (s)

#define __FSM_STATE(st)							\
case st:								\
st: __attribute__((unused)) 						\
 	__fsm_const_state = st; /* optimized out to constant */		\
	c = *p;								\
	TFW_DBG("parser: " #st "(%d:%d): c=%#x(%c), r=%d\n",		\
		st, parser->_i_st, c, isprint(c) ? c : '.', r);

#define __FSM_EXIT(field)						\
do {									\
	if (field) { /* staticaly resolved */				\
		tfw_str_updlen(field, data + len);			\
		if (unlikely(!tfw_str_add_compound(msg->pool, field)))	\
			return TFW_BLOCK;				\
	}								\
	goto done;							\
} while (0)

#define FSM_EXIT()							\
do {									\
	p += 1; /* eat current character */				\
	goto done;							\
} while (0)

#define __FSM_FINISH(m)							\
done:									\
	parser->state = __fsm_const_state;				\
	parser->data_off = p - data;					\

#define ____FSM_MOVE_LAMBDA(to, n, code)				\
do {									\
	p += n;								\
	if (unlikely(p >= data + len || !*p)) {				\
		r = TFW_POSTPONE; /* postpone to more data available */	\
		__fsm_const_state = to; /* start from state @to nest time */\
		/* Close currently parsed header chunk. */		\
		hdr_chunk_fixup(msg, data, len);			\
		code;							\
	}								\
	c = *p;								\
	goto to;							\
} while (0)

#define __FSM_MOVE_nf(to, n, field)					\
	____FSM_MOVE_LAMBDA(to, n, __FSM_EXIT(field))
#define __FSM_MOVE_n(to, n)	__FSM_MOVE_nf(to, n, NULL)
#define __FSM_MOVE_f(to, field)	__FSM_MOVE_nf(to, 1, field)
#define __FSM_MOVE(to)		__FSM_MOVE_nf(to, 1, NULL)
/* The same as __FSM_MOVE_n(), but exactly for jumps w/o data moving. */
#define __FSM_JMP(to)		do { goto to; } while (0)

/*
 * __FSM_I_* macros are intended to help with parsing of message
 * header values. That is done with separate, nested, or interior
 * FSMs, and so _I_ in the name means "interior" FSM.
 */
#define __FSM_I_EXIT()			goto done
#define __FSM_I_MOVE_n(to, n)						\
do {									\
	parser->_i_st = to;						\
	____FSM_MOVE_LAMBDA(to, n, __FSM_I_EXIT());			\
} while (0)
#define __FSM_I_MOVE(to)		__FSM_I_MOVE_n(to, 1)
#define __FSM_I_MOVE_str(to, str)	__FSM_I_MOVE_n(to, sizeof(str) - 1)
/* The same as __FSM_I_MOVE_n(), but exactly for jumps w/o data moving. */
#define __FSM_I_JMP(to)			do { goto to; } while (0)

/* Conditional transition from state @st to @st_next. */
#define __FSM_TX_COND(st, condition, st_next) 				\
__FSM_STATE(st) {							\
	if (likely(condition))						\
		__FSM_MOVE(st_next);					\
	return TFW_BLOCK;						\
}

/* Automaton transition from state @st to @st_next on character @ch. */
#define __FSM_TX(st, ch, st_next) \
	__FSM_TX_COND(st, c == (ch), st_next)

/* Case-insensitive version of __FSM_TX(). */
#define __FSM_TX_LC(st, ch, st_next) 					\
	__FSM_TX_COND(st, LC(c) == (ch), st_next)

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
 * Match 4 or 8 characters with conversion to lower case
 * and type conversion to int or long type.
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
__chunk_strncasecmp(TfwStr *chunk, unsigned char *p, size_t len,
		    const char *str, size_t tot_len)
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

/**
 * Parse probably chunked string representation of an decimal integer.
 * Returns number of parsed bytes (in data, w/o stored chunk) on success
 * or negative value otherwise.
 */
static int
__parse_int_a(TfwStr *chunk, unsigned char *data, size_t len,
	      const unsigned long *delimiter_a, unsigned int *acc)
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
	for (p = data; !IN_ALPHABET(*p, delimiter_a); ++p) {
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
 * Parse an integer followed by whit space.
 */
static inline int
parse_int_ws(TfwStr *chunk, unsigned char *data, size_t len, unsigned int *acc)
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
	return __parse_int_a(chunk, data, len, whitespace_a, acc);
}

/**
 * Parse an integer as part of HTTP list.
 */
static inline int
parse_int_list(TfwStr *chunk, unsigned char *data, size_t len,
	       unsigned int *acc)
{
	/*
	 * Standard white-space plus coma characters are:
	 * '\t' (0x09) horizontal tab (TAB)
	 * '\n' (0x0a) newline (LF)
	 * '\v' (0x0b) vertical tab (VT)
	 * '\f' (0x0c) feed (FF)
	 * '\r' (0x0d) carriage return (CR)
	 * ' '  (0x20) space (SPC)
	 * ','  (0x2c) coma
	 */
	static const unsigned long ws_coma_a[] ____cacheline_aligned = {
		0x0000100100003e00UL, 0, 0, 0
	};
	return __parse_int_a(chunk, data, len, ws_coma_a, acc);
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
	for (p = data; !isspace(*p) && (*p != ';'); ++p) {
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
	I_ConnOther,
	I_ContLen, /* Content-Length */
	I_TransEncod, /* Transfer-Encoding */
	I_TransEncodExt,

	I_EoT, /* end of term */
};

/* Parsing helpers. */
#define TRY_STR_LAMBDA(str, lambda)					\
	r = __chunk_strncasecmp(chunk, p, len - (size_t)(p - data),	\
				str, sizeof(str) - 1);			\
	switch (r) {							\
	case CSTR_EQ:							\
		lambda;							\
	case CSTR_POSTPONE:						\
		hdr_chunk_fixup(msg, data, len);			\
	case CSTR_BADLEN:						\
		return r;						\
	case CSTR_NEQ: /* fall through */				\
		;							\
	}

#define TRY_STR(str, state)						\
	TRY_STR_LAMBDA(str, __FSM_I_MOVE_str(state, str))

#define __TFW_HTTP_PARSE_HDR_VAL(st_curr, st_i, hm, func, id)	\
__FSM_STATE(st_curr) {							\
	__fsm_sz = data + len - p;					\
	BUG_ON(p > data + len);						\
	if (parser->_i_st == I_0)					\
		parser->_i_st = st_i;					\
	if (id < TFW_HTTP_HDR_RAW && !(parser->hdr.flags & TFW_STR_USER)) { \
		/*							\
		 * Check whether the header slot is acquired to catch	\
		 * duplicate headers in sense of RFC 7230 3.2.2.	\
		 */							\
		if (id < TFW_HTTP_HDR_NONSINGULAR			\
		    && unlikely((msg)->h_tbl->tbl[id].field.ptr))	\
			return TFW_BLOCK;				\
		/* Don't store header name for special headers. */	\
		TFW_STR_INIT(&parser->hdr);				\
		hdr_open(msg, p);					\
		parser->hdr.flags |= TFW_STR_USER; /* single shot */	\
	}								\
	__fsm_n = func(hm, p, __fsm_sz);				\
	TFW_DBG("parse header " #func ": len=%d id=%d\n", __fsm_n, id);	\
	switch (__fsm_n) {						\
	case CSTR_POSTPONE:						\
		/* The automaton state keeping is handled in @func. */	\
		r = TFW_POSTPONE;					\
		p += __fsm_sz;						\
		goto done;						\
	case CSTR_BADLEN: /* bad header length */			\
	case CSTR_NEQ: /* bad header value */				\
		return TFW_BLOCK;					\
	default:							\
		BUG_ON(__fsm_n < 0);					\
		/* The header value is fully parsed, move forward. */	\
		hdr_chunk_fixup(msg, data, p + __fsm_n - data);		\
		hdr_close(msg, id);					\
		parser->_i_st = I_0;					\
		__FSM_MOVE_n(RGen_LF, __fsm_n + 1); /* skip \r */	\
	}								\
}

#define TFW_HTTP_PARSE_HDR_VAL(st_curr, st_i, hm, func)			\
	__TFW_HTTP_PARSE_HDR_VAL(st_curr, st_i, hm, func, TFW_HTTP_HDR_RAW)

/*
 * Parse raw (common) HTTP headers.
 * Note that some of these (like Cookie or User-Agent) can be extremely large.
 */
#define TFW_HTTP_PARSE_HDR_OTHER(prefix)				\
__FSM_STATE(prefix ## _HdrOther) {					\
	/* Just eat the header until LF. */				\
	__fsm_sz = len - (size_t)(p - data);				\
	__fsm_ch = memchr(p, '\r', __fsm_sz);				\
	if (__fsm_ch) {							\
		/* Get length of the header. */				\
		hdr_chunk_fixup(msg, data, __fsm_ch - data);		\
		hdr_close(msg, TFW_HTTP_HDR_RAW);			\
		__FSM_MOVE_n(RGen_LF, __fsm_ch - p + 1);		\
	}								\
	__FSM_MOVE_n(prefix ## _HdrOther, __fsm_sz);			\
}

#define TFW_HTTP_PARSE_LF(prefix)					\
__FSM_STATE(RGen_LF) {							\
	if (likely(c == '\n'))						\
		__FSM_MOVE(prefix ## _Hdr);				\
	return TFW_BLOCK;						\
}

/*
 * __FSM_B_* macros are intended to help with parsing of a message
 * body, hence the "_B_" in the names. The macros are similar to
 * those for parsing of message headers (__FSM_*), or for parsing
 * of message header values (__FSM_I_*, where _I_ means "interior",
 * or nested FSM). The major difference from __FSM_* macros is that
 * there can be zeroes in a message body that cannot be in a header.
 */
#define __FSM_B_MOVE_n(to, n)						\
do {									\
	p += n;								\
	if (unlikely(p >= data + len)) {				\
		/*							\
		 * Postpone parsing until more data is available,	\
		 * and start from state @to on next parser run.		\
		 */							\
		r = TFW_POSTPONE;					\
		__fsm_const_state = to;					\
		goto done;						\
	}								\
	c = *p;								\
	goto to;							\
} while (0)

#define __FSM_B_MOVE(to)	__FSM_B_MOVE_n(to, 1)

#define TFW_HTTP_INIT_BODY_PARSING(msg, to_state)			\
do {									\
	TFW_DBG("parse msg body: flags=%#x content_length=%d\n",	\
		msg->flags, msg->content_length);			\
	/* RFC 2616 4.4: firstly check chunked transfer encoding. */	\
	if (msg->flags & TFW_HTTP_CHUNKED)				\
		__FSM_B_MOVE(to_state);					\
	/* Next we check content length. */				\
	if (msg->content_length) {					\
		parser->to_read = msg->content_length;			\
		__FSM_B_MOVE(to_state);					\
	}								\
	/* There is no body at all. */					\
	r = TFW_PASS;							\
	FSM_EXIT();							\
} while (0)

#define TFW_HTTP_PARSE_BODY(prefix)					\
/* Read request|response body. */					\
__FSM_STATE(prefix ## _Body) {						\
	TFW_DBG("read body: to_read=%d\n", parser->to_read);		\
	if (!parser->to_read) {						\
		unsigned int to_read = 0;				\
		__fsm_sz = len - (size_t)(p - data);			\
		/* Read next chunk length. */				\
		__fsm_n = __parse_hex(&parser->_tmp_chunk,		\
				      p, __fsm_sz, &to_read);		\
		TFW_DBG("len=%zu ret=%d to_read=%d\n",			\
			__fsm_sz, __fsm_n, to_read);			\
		switch (__fsm_n) {					\
		case CSTR_POSTPONE:					\
			/* Not all data has been parsed. */		\
			__FSM_B_MOVE_n(prefix ## _Body, __fsm_sz);	\
		case CSTR_BADLEN: /* bad header length */		\
		case CSTR_NEQ: /* bad header value */			\
			return TFW_BLOCK;				\
		default:						\
			BUG_ON(__fsm_n <= 0);				\
			parser->to_read = to_read;			\
			__FSM_B_MOVE_n(prefix ## _BodyChunkEoL, __fsm_n); \
		}							\
	}								\
	/* fall through */						\
}									\
/* Read parser->to_read bytes of message body. */			\
__FSM_STATE(prefix ## _BodyReadChunk) {					\
	__fsm_sz = min(parser->to_read,					\
			  (int)(len - (size_t)(p - data)));		\
	if (!msg->body.ptr)						\
		msg->body.ptr = p;					\
	msg->body.len += __fsm_sz;					\
	parser->to_read -= __fsm_sz;					\
	/* Just skip required number of bytes. */			\
	if (parser->to_read)						\
		__FSM_B_MOVE_n(prefix ## _BodyReadChunk, __fsm_sz);	\
	if (msg->flags & TFW_HTTP_CHUNKED)				\
		__FSM_B_MOVE_n(prefix ## _BodyChunkEnd, __fsm_sz);	\
	/* We've fully read Content-Length bytes. */			\
	p += __fsm_sz;							\
	r = TFW_PASS;							\
	goto done;							\
}									\
__FSM_STATE(prefix ## _BodyChunkEoL) {					\
	if (c == '\n') {						\
		if (parser->to_read)					\
			__FSM_B_MOVE(prefix ## _BodyReadChunk);		\
		else							\
			/* Read trailing headers, RFC 2616 3.6.1. */	\
			__FSM_B_MOVE(prefix ## _Hdr);			\
	}								\
	if (c == '\r' || c == '=' || IN_ALPHABET(*p, hdr_a) || c == ';') \
		__FSM_B_MOVE(prefix ## _BodyChunkEoL);			\
	return TFW_BLOCK;						\
}									\
__FSM_STATE(prefix ## _BodyChunkEnd) {					\
	if (c == '\n') {						\
		__FSM_B_MOVE(prefix ## _Body);				\
	}								\
	if (c == '\r')							\
		__FSM_B_MOVE(prefix ## _BodyChunkEnd);			\
	return TFW_BLOCK;						\
}									\
/* Request|Response is fully read. */					\
__FSM_STATE(prefix ## _Done) {						\
	if (c == '\n') {						\
		r = TFW_PASS;						\
		FSM_EXIT();						\
	}								\
	return TFW_BLOCK;						\
}

/*
 * Read LWS at arbitrary position and move to stashed state.
 * This is bit complicated (however you can think about this as
 * a plain pushdown automaton), but reduces FSM code size.
 */
#define RGEN_LWS()							\
__FSM_STATE(RGen_LWS) {							\
	switch (c) {							\
	case '\r':							\
		if (likely(!(parser->flags & TFW_HTTP_PF_CRLF))) {	\
			parser->flags |= TFW_HTTP_PF_CR;		\
			__FSM_MOVE(RGen_LWS);				\
		}							\
		return TFW_BLOCK;					\
	case '\n':							\
		if (likely(!(parser->flags & TFW_HTTP_PF_LF))) {	\
			parser->flags |= TFW_HTTP_PF_LF;		\
			__FSM_MOVE(RGen_LWS);				\
		}							\
		return TFW_BLOCK;					\
	case ' ':							\
	case '\t':							\
		__FSM_MOVE(RGen_LWS);					\
	default:							\
		parser->flags &= ~TFW_HTTP_PF_CRLF;			\
		parser->state = parser->_i_st;				\
		parser->_i_st = 0;					\
		BUG_ON(unlikely(p >= data + len || !*p));		\
		goto fsm_reenter;					\
	}								\
}

/**
 * Parse Connection header value, RFC 2616 14.10.
 */
static int
__parse_connection(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &msg->parser;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	unsigned char c = *p;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(I_Conn) {
		TRY_STR_LAMBDA("close", {
			if (msg->flags & TFW_HTTP_CONN_KA)
				return CSTR_NEQ;
			msg->flags |= TFW_HTTP_CONN_CLOSE;
			__FSM_I_MOVE_str(I_EoT, "close");
		});
		TRY_STR_LAMBDA("keep-alive", {
			if (msg->flags & TFW_HTTP_CONN_CLOSE)
				return CSTR_NEQ;
			msg->flags |= TFW_HTTP_CONN_KA;
			__FSM_I_MOVE_str(I_EoT, "keep-alive");
		});
		__FSM_I_MOVE_n(I_ConnOther, 0);
	}

	/*
	 * Other connection tokens. Popular examples of the "Connection:"
	 * header value are "Keep-Alive, TE" or "TE, close". However,
	 * it could be names of any headers, including custom headers.
	 */
	__FSM_STATE(I_ConnOther) {
		/*
		 * TODO
		 * - replace double memchr() below by a strspn() analog
		 *   that accepts string length instead of processing
		 *   null-terminated strings.
		 */
		unsigned char *comma;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_ch = memchr(p, '\r', __fsm_sz);
		comma = memchr(p, ',', __fsm_sz);
		if (comma && (!__fsm_ch || (__fsm_ch && (comma < __fsm_ch))))
			__FSM_I_MOVE_n(I_EoT, comma - p);
		if (__fsm_ch)
			return __fsm_ch - data;
		return CSTR_POSTPONE;
	}

	/* End of token */
	__FSM_STATE(I_EoT) {
		if (c == ' ' || c == ',')
			__FSM_I_MOVE(I_EoT);
		if (IN_ALPHABET(c, hdr_a))
			__FSM_I_MOVE_n(I_Conn, 0);
		if (c == '\r')
			return p - data;
		return CSTR_NEQ;
	}

	} /* FSM END */
done:
	TFW_DBG("parser: Connection parsed: flags %#x\n", msg->flags);

	return r;
}

/**
 * Parse Content-Length header value, RFC 2616 14.13.
 */
static int
__parse_content_length(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	return parse_int_ws(&msg->parser._tmp_chunk, data, len,
			    &msg->content_length);
}

/**
 * Parse Transfer-Encoding header value, RFC 2616 14.41 and 3.6.
 */
static int
__parse_transfer_encoding(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &msg->parser;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	unsigned char c = *p;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(I_TransEncod) {
		TRY_STR_LAMBDA("chunked", {
			msg->flags |= TFW_HTTP_CHUNKED;
			__FSM_I_MOVE_str(I_EoT, "chunked");
		});
		__FSM_I_MOVE_n(I_TransEncodExt, 0);
	}

	__FSM_STATE(I_TransEncodExt) {
		/*
		 * TODO
		 * - process transfer encodings:
		 *   gzip, deflate, identity, compress;
		 * - replace double memchr() below by a strspn() analog
		 *   that accepts string length instead of processing
		 *   null-terminated strings.
		 */
		unsigned char *comma;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_ch = memchr(p, '\r', __fsm_sz);
		comma = memchr(p, ',', __fsm_sz);
		if (comma && (!__fsm_ch || (__fsm_ch && (comma < __fsm_ch))))
			__FSM_I_MOVE_n(I_EoT, comma - p);
		if (__fsm_ch)
			return __fsm_ch - data;
		return CSTR_POSTPONE;
	}

	/* End of term. */
	__FSM_STATE(I_EoT) {
		if (c == ' ' || c == ',')
			__FSM_I_MOVE(I_EoT);
		if (IN_ALPHABET(c, hdr_a))
			__FSM_I_MOVE(I_TransEncod);
		if (c == '\r')
			return p - data;
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
/*
 * TODO Performance.
 * The alphabets below are less than 8 ranges, so they can be handled
 * using CMPESTRI(_SIDD_CMP_RANGES).
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
/*
 * BUG: according to RFC 2616, absolute paths doesn't include the query string:
 *     http_URL = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]]
 * So the alphabet contains characters valid for query but invalid for abs_path.
 * In a similar way, that violates RFC 7230 that distinguishes "absolute-path"
 * from "query" and "fragment" components.
 */
static const unsigned long uap_a[] ____cacheline_aligned = {
	0xaffffffa00000000UL, 0x47fffffeafffffffUL, 0, 0
};

/*
 * Alphabet for X-Forwarded-For Node ID (RFC 7239).
 *
 * "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-[]:"
 */
static const unsigned long xff_a[] ____cacheline_aligned = {
	0x7ff600000000000UL, 0x7fffffeaffffffeUL, 0, 0
};

/**
 * Check whether a character is a whitespace (RWS/OWS/BWS according to RFC7230).
 */
#define IS_WS(c) (c == ' ' || c == '\t')

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
	Req_UriHostStart,
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
	Req_HdrOther,
	Req_HdrDone,
	/* Body */
	Req_Body,
	Req_BodyChunkEoL,
	Req_BodyChunkEnd,
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

/*
 * Helping (interior) FSM states
 * for processing specific parts of an HTTP request.
 */
enum {
	Req_I_0,

	/* Host header */
	Req_I_H,
	Req_I_H_Port,
	/* Cache-Control header */
	Req_I_CC,
	Req_I_CC_MaxAgeV,
	Req_I_CC_MinFreshV,
	Req_I_CC_Ext,
	Req_I_CC_EoT,
	/* X-Forwarded-For header */
	Req_I_XFF,
	Req_I_XFF_Node_Id,
	Req_I_XFF_Sep,
};

/**
 * Parse request Cache-Control, RFC 2616 14.9
 */
static int
__req_parse_cache_control(TfwHttpReq *req, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &req->parser;
	TfwHttpMsg *msg = (TfwHttpMsg *)req;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	unsigned char c = *p;

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
		__fsm_sz = len - (size_t)(p - data);
		__fsm_n = parse_int_list(chunk, p, __fsm_sz, &acc);
		if (__fsm_n < 0)
			return __fsm_n;
		req->cache_ctl.max_age = acc;
		__FSM_I_MOVE_n(Req_I_CC_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_MinFreshV) {
		unsigned int acc = 0;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_n = parse_int_list(chunk, p, __fsm_sz, &acc);
		if (__fsm_n < 0)
			return __fsm_n;
		req->cache_ctl.max_fresh = acc;
		__FSM_I_MOVE_n(Req_I_CC_EoT, __fsm_n);
	}

	__FSM_STATE(Req_I_CC_Ext) {
		/*
		 * TODO
		 * - process cache extensions;
		 * - replace double memchr() below by a strspn() analog
		 *   that accepts string length instead of processing
		 *   null-terminated strings.
		 */
		unsigned char *comma;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_ch = memchr(p, '\r', __fsm_sz);
		comma = memchr(p, ',', __fsm_sz);
		if (comma && (!__fsm_ch || (__fsm_ch && (comma < __fsm_ch))))
			__FSM_I_MOVE_n(Req_I_CC_EoT, comma - p);
		if (__fsm_ch)
			return __fsm_ch - data;
		return CSTR_POSTPONE;
	}

	/* End of term. */
	__FSM_STATE(Req_I_CC_EoT) {
		if (c == ' ' || c == ',')
			__FSM_I_MOVE(Req_I_CC_EoT);
		/*
		 * TODO
		 * - For the time being we don't support field values
		 *   for the max-stale field, so just skip '=[hdr_a]*'.
		 */
		if (c == '=')
			__FSM_I_MOVE(Req_I_CC_Ext);
		if (IN_ALPHABET(c, hdr_a))
			__FSM_I_MOVE(Req_I_CC);
		if (c == '\r')
			return p - data;
		return CSTR_NEQ;
	}

	} /* FSM END */
done:
	return r;
}

/**
 * Parse request Host header, RFC 7230 5.4.
 */
static int
__req_parse_host(TfwHttpReq *req, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &req->parser;
	TfwHttpMsg *msg = (TfwHttpMsg *)req;
	unsigned char *p = data;
	unsigned char c = *p;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Req_I_H) {
		/* See Req_UriHost processing. */
		if (likely(isalnum(c) || c == '.' || c == '-'))
			__FSM_I_MOVE(Req_I_H);
		if (c == ':')
			__FSM_I_MOVE(Req_I_H_Port);
		if (isspace(c))
			return p - data;
		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_H_Port) {
		/* See Req_UriPort processing. */
		if (likely(isdigit(c)))
			__FSM_I_MOVE(Req_I_H_Port);
		if (isspace(c))
			return p - data;
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
__req_parse_x_forwarded_for(TfwHttpMsg *msg, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &msg->parser;
	unsigned char *p = data;
	unsigned char c = *p;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Req_I_XFF) {
		/* Eat OWS before the node ID. */
		if (unlikely(IS_WS(c)))
			__FSM_I_MOVE(Req_I_XFF);

		/* Start of an IP address or a host name. */
		if (likely(IN_ALPHABET(c, xff_a)))
			__FSM_I_JMP(Req_I_XFF_Node_Id);

		return CSTR_NEQ;
	}

	__FSM_STATE(Req_I_XFF_Node_Id) {
		/* Eat IP address or host name.
		 * TODO: parse/validate IP addresses and textual IDs.
		 * Currently we just validate separate characters, but the
		 * whole value may be invalid (e.g. "---[_..[[").
		 */
		if (likely(IN_ALPHABET(c, xff_a)))
			__FSM_I_MOVE(Req_I_XFF_Node_Id);

		__FSM_I_JMP(Req_I_XFF_Sep);
	}

	__FSM_STATE(Req_I_XFF_Sep) {
		/*
		 * Proxy chains are rare, so we expect that the list will end
		 * after the first node and we get '\r' here.
		 */
		if (likely(c == '\r'))
			return p - data;

		/* OWS before comma or before \r\n (is unusual). */
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
		/* Fast path: compare 4 characters at once. */
		if (likely(p + 4 <= data + len)) {
			switch (*(unsigned int *)p) {
			case TFW_CHAR4_INT('G', 'E', 'T', ' '):
				req->method = TFW_HTTP_METH_GET;
				__FSM_MOVE_n(Req_Uri, 4);
			case TFW_CHAR4_INT('H', 'E', 'A', 'D'):
				req->method = TFW_HTTP_METH_HEAD;
				__FSM_MOVE_n(Req_MUSpace, 4);
			case TFW_CHAR4_INT('P', 'O', 'S', 'T'):
				req->method = TFW_HTTP_METH_POST;
				__FSM_MOVE_n(Req_MUSpace, 4);
			}
			return TFW_BLOCK; /* Unsupported method */
		}
		/* Slow path: step char-by-char. */
		switch (c) {
		case 'G':
			__FSM_MOVE(Req_MethG);
		case 'H':
			__FSM_MOVE(Req_MethH);
		case 'P':
			__FSM_MOVE(Req_MethP);
		}
                return TFW_BLOCK; /* Unsupported method */
	}

	/*
	 * Eat SP before URI and HTTP (only) scheme.
	 * RFC 7230 3.1.1 requires only one SP.
	 */
	__FSM_STATE(Req_MUSpace) {
		if (unlikely(c != ' '))
			return TFW_BLOCK;
		__FSM_MOVE(Req_Uri);
	}

	__FSM_STATE(Req_Uri) {
		if (likely(c == '/')) {
			req->uri_path.ptr = p;
			__FSM_MOVE_f(Req_UriAbsPath, &req->uri_path);
		}
		if (likely(C4_INT_LCM(p, 'h', 't', 't', 'p')
			   && *(p + 4) == ':' && *(p + 5) == '/'
			   && *(p + 6) == '/'))
			__FSM_MOVE_n(Req_UriHostStart, 7);

		/* "http://" slow path - step char-by-char. */
		if (likely(LC(c) == 'h'))
			__FSM_MOVE(Req_UriSchH);

		return TFW_BLOCK;
	}

	/*
	 * URI host part.
	 *
	 * We must not rewrite abs_path, but still can cast host part
	 * to lower case.
	 */
	__FSM_STATE(Req_UriHostStart) {
		if (likely(isalnum(c) || c == '.' || c == '-')) {
			*p = LC(*p);
			req->host.ptr = p;
			__FSM_MOVE_f(Req_UriHost, &req->host);
		}
		return TFW_BLOCK;
	}

	__FSM_STATE(Req_UriHost) {
		if (likely(isalnum(c) || c == '.' || c == '-')) {
			*p = LC(*p);
			__FSM_MOVE_f(Req_UriHost, &req->host);
		}
		/* fall throught */
	}

	/* Host is read, start to read port or abs_path. */
	__FSM_STATE(Req_UriHostEnd) {
		__field_finish(&req->host, data, p);

		if (likely(c == '/')) {
			req->uri_path.ptr = p;
			__FSM_MOVE_f(Req_UriAbsPath, &req->uri_path);
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

		req->uri_path.ptr = p;
		__FSM_MOVE_f(Req_UriAbsPath, &req->uri_path);
	}

	/* URI abs_path */
	/* BUG: the code parses not only "abs_path".
	 * E.g., we get "/foo/bar/baz?query#fragment" instead of "/foo/bar/baz"
	 * as we should according to RFC 2616 (3.2.2) and RFC 7230 (2.7).
	 */
	__FSM_STATE(Req_UriAbsPath) {
		if (likely(IN_ALPHABET(c, uap_a)))
			/* Move forward through possibly segmented data. */
			____FSM_MOVE_LAMBDA(TFW_HTTP_URI_HOOK, 1,
					    __FSM_EXIT(&req->uri_path));

		if (likely(c == ' ')) {
			__field_finish(&req->uri_path, data, p);
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
		if (unlikely(p + 8 > data + len)) {
			/* Slow path. */
			if (c == 'H')
				__FSM_MOVE(Req_HttpVerT1);
			return TFW_BLOCK;
		}
		/* Fast path. */
		switch (*(unsigned long *)p) {
		case TFW_CHAR8_INT('H', 'T', 'T', 'P', '/', '1', '.', '1'):
		case TFW_CHAR8_INT('H', 'T', 'T', 'P', '/', '1', '.', '0'):
			__FSM_MOVE_n(Req_EoL, 8);
		default:
			return TFW_BLOCK;
		}
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
				FSM_EXIT();
			}
		}

		if (unlikely(!IN_ALPHABET(c, hdr_a)))
			return TFW_BLOCK;

		hdr_open(msg, p);

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
		case 'x':
			if (likely(p + 17 <= data + len
				   && *(p + 1) == '-'
				   && *(p + 11) == '-'
				   && C8_INT_LCM(p, 'x', '-', 'f', 'o',
						    'r', 'w', 'a', 'r')
				   && C8_INT_LCM(p + 8, 'd', 'e', 'd', '-',
						        'f', 'o', 'r', ':')))
			{
				parser->_i_st = Req_HdrX_Forwarded_ForV;
				__FSM_MOVE_n(RGen_LWS, 16);
			}
			__FSM_MOVE(Req_HdrX);
		default:
			__FSM_JMP(Req_HdrOther);
		}
	}

	RGEN_LWS();

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
				parser->_i_st = Req_HdrContent_LengthV;
				__FSM_MOVE_n(RGen_LWS, 14);
			}
			if (likely(p + 8 <= data + len
				   && C8_INT_LCM(p + 1, 'n', 'n', 'e', 'c',
							't', 'i', 'o', 'n')))
				__FSM_MOVE_n(Req_HdrConnection, 9);
			__FSM_MOVE(Req_HdrCo);
		default:
			__FSM_JMP(Req_HdrOther);
		}
	}

	/* 'Host:*LWS' is read, process field-value. */
	__TFW_HTTP_PARSE_HDR_VAL(Req_HdrHostV, Req_I_H, req,
				 __req_parse_host, TFW_HTTP_HDR_HOST);

	/* 'Cache-Control:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Req_HdrCache_ControlV, Req_I_CC, req,
			       __req_parse_cache_control);

	/* 'Connection:*LWS' is read, process field-value. */
	__TFW_HTTP_PARSE_HDR_VAL(Req_HdrConnectionV, I_Conn, msg,
				 __parse_connection, TFW_HTTP_HDR_CONNECTION);

	/* 'Content-Length:*LWS' is read, process field-value. */
	__TFW_HTTP_PARSE_HDR_VAL(Req_HdrContent_LengthV, I_ContLen,
				 msg, __parse_content_length,
				 TFW_HTTP_HDR_CONTENT_LENGTH);

	/* 'Transfer-Encoding:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Req_HdrTransfer_EncodingV,
			       I_TransEncod, msg, __parse_transfer_encoding);

	/* 'X-Forwarded-For:*LWS' is read, process field-value. */
	__TFW_HTTP_PARSE_HDR_VAL(Req_HdrX_Forwarded_ForV, Req_I_XFF,
				 msg, __req_parse_x_forwarded_for,
				 TFW_HTTP_HDR_X_FORWARDED_FOR);

	TFW_HTTP_PARSE_HDR_OTHER(Req);

	TFW_HTTP_PARSE_LF(Req);

	/* Request headers are fully read. */
	__FSM_STATE(Req_HdrDone) {
		if (c == '\n')
			TFW_HTTP_INIT_BODY_PARSING(req, Req_Body);
		return TFW_BLOCK;
	}

	/* ----------------    Request body    ---------------- */

	TFW_HTTP_PARSE_BODY(Req);

	/* ----------------    Improbable states    ---------------- */

	/*
	 * HTTP Method processing.
	 *
	 * GET
	 */
	__FSM_TX(Req_MethG, 'E', Req_MethGe);
	__FSM_STATE(Req_MethGe) {
		if (unlikely(c != 'T'))
			return TFW_BLOCK;
		req->method = TFW_HTTP_METH_GET;
		__FSM_MOVE(Req_MUSpace);
	}
	/* POST */
	__FSM_TX(Req_MethP, 'O', Req_MethPo);
	__FSM_TX(Req_MethPo, 'S', Req_MethPos);
	__FSM_STATE(Req_MethPos) {
		if (unlikely(c != 'T'))
			return TFW_BLOCK;
		req->method = TFW_HTTP_METH_POST;
		__FSM_MOVE(Req_MUSpace);
	}
	/* HEAD */
	__FSM_TX(Req_MethH, 'E', Req_MethHe);
	__FSM_TX(Req_MethHe, 'A', Req_MethHea);
	__FSM_STATE(Req_MethHea) {
		if (unlikely(c != 'D'))
			return TFW_BLOCK;
		req->method = TFW_HTTP_METH_HEAD;
		__FSM_MOVE(Req_MUSpace);
	}

	/* process URI scheme: "http://" */
	__FSM_TX_LC(Req_UriSchH, 't', Req_UriSchHt);
	__FSM_TX_LC(Req_UriSchHt, 't', Req_UriSchHtt);
	__FSM_TX_LC(Req_UriSchHtt, 'p', Req_UriSchHttp);
	__FSM_TX(Req_UriSchHttp, ':', Req_UriSchHttpColon);
	__FSM_TX(Req_UriSchHttpColon, '/', Req_UriSchHttpColonSlash);
	__FSM_TX(Req_UriSchHttpColonSlash, '/', Req_UriHostStart);

	/* Parse HTTP version (1.1 and 1.0 are supported). */
	__FSM_TX(Req_HttpVerT1, 'T', Req_HttpVerT2);
	__FSM_TX(Req_HttpVerT2, 'T', Req_HttpVerP);
	__FSM_TX(Req_HttpVerP, 'P', Req_HttpVerSlash);
	__FSM_TX(Req_HttpVerSlash, '/', Req_HttpVer11);
	__FSM_TX(Req_HttpVer11, '1', Req_HttpVerDot);
	__FSM_TX(Req_HttpVerDot, '.', Req_HttpVer12);
	__FSM_STATE(Req_HttpVer12) {
		switch(c) {
		case '1':
		case '0':
			__FSM_MOVE(Req_EoL);
		default:
			return TFW_BLOCK;
		}
	}

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

	/* X-Forwarded-For header processing. */
	__FSM_TX_AF(Req_HdrX, '-', Req_HdrX_, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_, 'f', Req_HdrX_F, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_F, 'o', Req_HdrX_Fo, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_Fo, 'r', Req_HdrX_For, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_For, 'w', Req_HdrX_Forw, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forw, 'a', Req_HdrX_Forwa, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwa, 'r', Req_HdrX_Forwar, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwar, 'd', Req_HdrX_Forward, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forward, 'e', Req_HdrX_Forwarde, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwarde, 'd', Req_HdrX_Forwarded, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwarded, '-', Req_HdrX_Forwarded_, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwarded_, 'f', Req_HdrX_Forwarded_F, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwarded_F, 'o', Req_HdrX_Forwarded_Fo, hdr_a, Req_HdrOther);
	__FSM_TX_AF(Req_HdrX_Forwarded_Fo, 'r', Req_HdrX_Forwarded_For, hdr_a, Req_HdrOther);
	/* NOTE: we don't eat LWS here because RGEN_LWS() doesn't allow '[' after LWS. */
	__FSM_TX_AF_LWS(Req_HdrX_Forwarded_For, ':', Req_HdrX_Forwarded_ForV, hdr_a, Req_HdrOther);

	}
	__FSM_FINISH(req);

	return r;
}
DEBUG_EXPORT_SYMBOL(tfw_http_parse_req);

/*
 * ------------------------------------------------------------------------
 *	HTTP response parsing
 * ------------------------------------------------------------------------
 */
/*
 * Helping (interior) FSM states
 * for processing specific parts of an HTTP request.
 */
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
__resp_parse_cache_control(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &resp->parser;
	TfwHttpMsg *msg = (TfwHttpMsg *)resp;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	unsigned char c = *p;

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
		__fsm_sz = len - (size_t)(p - data);
		__fsm_n = parse_int_list(chunk, p, __fsm_sz, &acc);
		if (__fsm_n < 0)
			return __fsm_n;
		resp->cache_ctl.max_age = acc;
		__FSM_I_MOVE_n(Resp_I_EoT, __fsm_n);
	}

	__FSM_STATE(Resp_I_CC_SMaxAgeV) {
		unsigned int acc = 0;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_n = parse_int_list(chunk, p, __fsm_n, &acc);
		if (__fsm_n < 0)
			return __fsm_n;
		resp->cache_ctl.s_maxage = acc;
		__FSM_I_MOVE_n(Resp_I_EoT, __fsm_n);
	}

	__FSM_STATE(Resp_I_Ext) {
		/*
		 * TODO
		 * - process cache extensions;
		 * - replace double memchr() below by a strspn() analog
		 *   that accepts string length instead of processing
		 *   null-terminated strings.
		 */
		unsigned char *comma;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_ch = memchr(p, '\r', __fsm_sz);
		comma = memchr(p, ',', __fsm_sz);
		if (comma && (!__fsm_ch || (__fsm_ch && (comma < __fsm_ch))))
			__FSM_I_MOVE_n(Resp_I_EoT, comma - p);
		if (__fsm_ch)
			return __fsm_ch - data;
		return CSTR_POSTPONE;
	}

	/* End of term. */
	__FSM_STATE(Resp_I_EoT) {
		if (c == ' ' || c == ',')
			__FSM_I_MOVE(Resp_I_EoT);
		/*
		 * TODO
		 * - For the time being we don't support field values for
		 *   no-cache and private fields, so just skip '=[hdr_a]*'.
		 */
		if (c == '=')
			__FSM_I_MOVE(Resp_I_Ext);
		if (IN_ALPHABET(c, hdr_a))
			__FSM_I_MOVE(Resp_I_CC);
		if (c == '\r')
			return p - data;
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
__resp_parse_expires(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	static const unsigned long colon_a[] ____cacheline_aligned = {
		/* ':' (0x3a)(58) Colon */
		0x0400000000000000UL, 0, 0, 0
	};
	TfwHttpParser *parser = &resp->parser;
	TfwHttpMsg *msg = (TfwHttpMsg *)resp;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	int r = CSTR_NEQ;
	unsigned char c = *p;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Resp_I_Expires) {
		/* Skip a weekday as redundant information. */
		__fsm_sz = len - (size_t)(p - data);
		__fsm_ch = memchr(p, ' ', __fsm_sz);
		if (__fsm_ch)
			__FSM_I_MOVE_n(Resp_I_ExpDate, __fsm_ch - p + 1);
		return CSTR_POSTPONE;
	}

	__FSM_STATE(Resp_I_ExpDate) {
		unsigned int acc = 0;
		__fsm_sz = len - (size_t)(p - data);

		if (!isdigit(c))
			return CSTR_NEQ;
		/* Parse a 2-digit day. */
		__fsm_n = parse_int_ws(chunk, p, __fsm_sz, &acc);
		if (__fsm_n < 0)
			return __fsm_n;
		else if (__fsm_n != 2 || acc < 1)
			return CSTR_BADLEN;
		/* Add seconds in full passed days. */
		resp->expires = (acc - 1) * SEC24H;
		/* Skip a day and a following SP. */
		__FSM_I_MOVE_n(Resp_I_ExpMonth, 3);
	}

	__FSM_STATE(Resp_I_ExpMonth) {
		switch (c) {
		case 'A':
			TRY_STR_LAMBDA("Apr", {
				resp->expires += SB_APR;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			TRY_STR_LAMBDA("Aug", {
				resp->expires += SB_AUG;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			return CSTR_NEQ;
		case 'J':
			TRY_STR_LAMBDA("Jan", {
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			TRY_STR_LAMBDA("Jun", {
				resp->expires += SB_JUN;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			TRY_STR_LAMBDA("Jul", {
				resp->expires += SB_JUL;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			return CSTR_NEQ;
		case 'M':
			TRY_STR_LAMBDA("Mar", {
				/* Add SEC24H for leap year on year parsing. */
				resp->expires += SB_MAR;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			TRY_STR_LAMBDA("May", {
				resp->expires += SB_MAY;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			return CSTR_NEQ;
		default:
			TRY_STR_LAMBDA("Feb", {
				resp->expires += SB_FEB;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			TRY_STR_LAMBDA("Sep", {
				resp->expires += SB_SEP;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			TRY_STR_LAMBDA("Oct", {
				resp->expires += SB_OCT;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			TRY_STR_LAMBDA("Nov", {
				resp->expires += SB_NOV;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
			});
			TRY_STR_LAMBDA("Dec", {
				resp->expires += SB_DEC;
				__FSM_I_MOVE_n(Resp_I_ExpYearSP, 3);
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
		__fsm_sz = len - (size_t)(p - data);
		__fsm_n = parse_int_ws(chunk, p, __fsm_sz, &year);
		if (__fsm_n < 0)
			return __fsm_n;
		else if (__fsm_n != 4)
			return CSTR_BADLEN;
		__fsm_n = __year_day_secs(year, resp->expires);
		if (__fsm_n < 0)
			return CSTR_NEQ;
		resp->expires = __fsm_n;
		/* Skip a year and a following SP. */
		__FSM_I_MOVE_n(Resp_I_ExpHour, 5);
	}

	__FSM_STATE(Resp_I_ExpHour) {
		unsigned int t = 0;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_n = __parse_int_a(chunk, p, __fsm_sz, colon_a, &t);
		if (__fsm_n < 0)
			return __fsm_n;
		else if (__fsm_n != 2)
			return CSTR_BADLEN;
		resp->expires = t * 3600;
		/* Skip an hour and a following ':'. */
		__FSM_I_MOVE_n(Resp_I_ExpMin, 3);
	}

	__FSM_STATE(Resp_I_ExpMin) {
		unsigned int t = 0;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_n = __parse_int_a(chunk, p, __fsm_sz, colon_a, &t);
		if (__fsm_n < 0)
			return __fsm_n;
		else if (__fsm_n != 2)
			return CSTR_BADLEN;
		resp->expires = t * 60;
		/* Skip minutes and a following ':'. */
		__FSM_I_MOVE_n(Resp_I_ExpSec, 3);
	}

	__FSM_STATE(Resp_I_ExpSec) {
		unsigned int t = 0;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_n = parse_int_ws(chunk, p, __fsm_sz, &t);
		if (__fsm_n < 0)
			return __fsm_n;
		else if (__fsm_n != 2)
			return CSTR_BADLEN;
		resp->expires = t;
		/* Skip seconds and a following ' GMT'. */
		__FSM_I_MOVE_n(Resp_I_EoL, 6);
	}

	__FSM_STATE(Resp_I_EoL) {
		if (c == '\r')
			return p - data;
		return CSTR_NEQ;
	}

	} /* FSM END */
done:
	return r;
}

static int
__resp_parse_keep_alive(TfwHttpResp *resp, unsigned char *data, size_t len)
{
	int r = CSTR_NEQ;
	TfwHttpParser *parser = &resp->parser;
	TfwHttpMsg *msg = (TfwHttpMsg *)resp;
	TfwStr *chunk = &parser->_tmp_chunk;
	unsigned char *p = data;
	unsigned char c = *p;

	__FSM_START(parser->_i_st) {

	__FSM_STATE(Resp_I_KeepAlive) {
		switch (tolower(c)) {
		case 't':
			TRY_STR("timeout=", Resp_I_KeepAliveTO);
		default:
			__FSM_I_MOVE_n(Resp_I_Ext, 0);
		}
	}

	__FSM_STATE(Resp_I_KeepAliveTO) {
		unsigned int acc = 0;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_n = parse_int_list(chunk, p, __fsm_sz, &acc);
		if (__fsm_n < 0)
			return __fsm_n;
		resp->keep_alive = acc;
		__FSM_I_MOVE_n(Resp_I_EoT, __fsm_n);
	}

	/*
	 * Just ignore Keep-Alive extensions. Known extensions:
	 *	max=N
	 */
	__FSM_STATE(Resp_I_Ext) {
		unsigned char *comma;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_ch = memchr(p, '\r', __fsm_sz);
		comma = memchr(p, ',', __fsm_sz);
		if (comma && (!__fsm_ch || (__fsm_ch && (comma < __fsm_ch))))
			__FSM_I_MOVE_n(Resp_I_EoT, comma - p);
		if (__fsm_ch)
			return __fsm_ch - data;
		return CSTR_POSTPONE;
	}

	/* End of term. */
	__FSM_STATE(Resp_I_EoT) {
		if (c == ' ' || c == ',')
			__FSM_I_MOVE(Resp_I_EoT);
		if (c == '=')
			__FSM_I_MOVE(Resp_I_Ext);
		if (IN_ALPHABET(c, hdr_a))
			__FSM_I_MOVE(Resp_I_KeepAlive);
		if (c == '\r')
			return p - data;
		return CSTR_NEQ;
	}

	} /* FSM END */
done:
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
	Resp_BodyChunkEnd,
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
		/* fall through */
	}

	/* HTTP version */
	__FSM_STATE(Resp_HttpVer) {
		if (unlikely(p + 9 > data + len)) {
			/* Slow path. */
			if (c == 'H')
				__FSM_MOVE(Resp_HttpVerT1);
			return TFW_BLOCK;
		}
		/* Fast path. */
		switch (*(unsigned long *)p) {
		case TFW_CHAR8_INT('H', 'T', 'T', 'P', '/', '1', '.', '1'):
		case TFW_CHAR8_INT('H', 'T', 'T', 'P', '/', '1', '.', '0'):
			if (*(p + 8) == ' ')
				__FSM_MOVE_n(Resp_StatusCode, 9);
			/* fall through */
		default:
			return TFW_BLOCK;
		}
	}

	/* Response Status-Code. */
	__FSM_STATE(Resp_StatusCode) {
		unsigned int acc = 0;
		__fsm_sz = len - (size_t)(p - data);
		__fsm_n = parse_int_list(&parser->_tmp_chunk, p, __fsm_sz,
					 &acc);
		parser->_i_st = I_Conn;
		switch (__fsm_n) {
		case CSTR_POSTPONE:
			/* Not all the header data is parsed. */
			__FSM_MOVE_n(Resp_StatusCode, __fsm_sz);
		case CSTR_BADLEN:
		case CSTR_NEQ:
			/* bad status value */
			return TFW_BLOCK;
		default:
			/* The header value is fully parsed, move forward. */
			resp->status = acc;
			__FSM_MOVE_n(Resp_ReasonPhrase, __fsm_n);
		}
	}

	/* Reason-Phrase: just skip. */
	__FSM_STATE(Resp_ReasonPhrase) {
		__fsm_sz = len - (size_t)(p - data);
		__fsm_ch = memchr(p, '\n', __fsm_sz);
		if (__fsm_ch)
			__FSM_MOVE_n(Resp_Hdr, __fsm_ch - p + 1);
		__FSM_MOVE_n(Resp_ReasonPhrase, __fsm_sz);
	}

	/* ----------------    Header Lines    ---------------- */

	/* Start of HTTP header or end of whole request. */
	__FSM_STATE(Resp_Hdr) {
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
				FSM_EXIT();
			}
		}

		if (unlikely(!IN_ALPHABET(c, hdr_a)))
			return TFW_BLOCK;

		hdr_open(msg, p);

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

	RGEN_LWS();

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
				parser->_i_st = Resp_HdrContent_LengthV;
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
	TFW_HTTP_PARSE_HDR_VAL(Resp_HdrCache_ControlV, Resp_I_CC,
			       resp, __resp_parse_cache_control);

	/* 'Connection:*LWS' is read, process field-value. */
	__TFW_HTTP_PARSE_HDR_VAL(Resp_HdrConnectionV, I_Conn, msg,
				 __parse_connection, TFW_HTTP_HDR_CONNECTION);

	/* 'Content-Length:*LWS' is read, process field-value. */
	__TFW_HTTP_PARSE_HDR_VAL(Resp_HdrContent_LengthV, I_ContLen,
				 msg, __parse_content_length,
				 TFW_HTTP_HDR_CONTENT_LENGTH);

	/* 'Expires:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Resp_HdrExpiresV, Resp_I_Expires,
			       resp, __resp_parse_expires);

	/* 'Keep-Alive:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Resp_HdrKeep_AliveV, Resp_I_KeepAlive,
			       resp, __resp_parse_keep_alive);

	/* 'Transfer-Encoding:*LWS' is read, process field-value. */
	TFW_HTTP_PARSE_HDR_VAL(Resp_HdrTransfer_EncodingV,
			       I_TransEncod, msg, __parse_transfer_encoding);

	TFW_HTTP_PARSE_HDR_OTHER(Resp);

	TFW_HTTP_PARSE_LF(Resp);

	/* Response headers are fully read. */
	__FSM_STATE(Resp_HdrDone) {
		if (c == '\n')
			TFW_HTTP_INIT_BODY_PARSING(resp, Resp_Body);
		return TFW_BLOCK;
	}

	/* ----------------    Response body    ---------------- */

	TFW_HTTP_PARSE_BODY(Resp);

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
		case '0':
			__FSM_MOVE(Resp_SSpace);
		default:
			return TFW_BLOCK;
		}
	}
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
