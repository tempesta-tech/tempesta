/**
 *		Tempesta FW
 *
 * Tempesta HTTP fuzzer.
 *
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "fuzzer.h"
#include "log.h"

MODULE_AUTHOR("Tempesta Technologies, Inc");
MODULE_DESCRIPTION("Tempesta HTTP fuzzer");
MODULE_VERSION("0.1.3");
MODULE_LICENSE("GPL");

#define FUZZ_MSG_F_INVAL	FUZZ_INVALID
#define FUZZ_MSG_F_EMPTY_BODY	0x10
#define FUZZ_MSG_F_SHIFT	8

/*
 * @sval	- string value of the field contents;
 * @flags	- message and contents related flags;
 */
typedef struct {
	char		*sval;
	unsigned int	flags;
} FuzzMsg;

#define FUZZ_MSG_INVAL(m)	((m).flags & FUZZ_MSG_F_INVAL)

static FuzzMsg spaces[] = {
	{""}
};
static FuzzMsg methods[] = {
	{"GET"}, {"HEAD"}, {"POST"}
};
static FuzzMsg uri_path_start[] = {
	{"http:/"}, {""}
};
static FuzzMsg uri_file[] = {
	{"file.html"}, {"f-i_l.e"}, {"fi%20le"}, {"xn--80aaxtnfh0b"}
};
static FuzzMsg versions[] = {
	{"1.0"}, {"1.1"}, {"0.9", FUZZ_MSG_F_INVAL}
};
#define FUZZ_FLD_F_STATUS_100		(0x0001 << FUZZ_MSG_F_SHIFT)
#define FUZZ_FLD_F_STATUS_204		(0x0002 << FUZZ_MSG_F_SHIFT)
#define FUZZ_FLD_F_STATUS_304		(0x0004 << FUZZ_MSG_F_SHIFT)
static FuzzMsg resp_code[] = {
	{"100 Continue", FUZZ_FLD_F_STATUS_100 | FUZZ_MSG_F_EMPTY_BODY},
	{"200 OK"},
	{"204 No Content", FUZZ_FLD_F_STATUS_204 | FUZZ_MSG_F_EMPTY_BODY},
	{"302 Found"},
	{"304 Not Modified", FUZZ_FLD_F_STATUS_304 | FUZZ_MSG_F_EMPTY_BODY},
	{"400 Bad Request"}, {"403 Forbidden"},
	{"404 Not Found"}, {"500 Internal Server Error"}
};
static FuzzMsg conn_val[] = {
	{"keep-alive"}, {"close"}, {"upgrade"}
};
static FuzzMsg ua_val[] = {
	{"Wget/1.13.4 (linux-gnu)"}, {"Mozilla/5.0"}
};
static FuzzMsg host_val[] = {
	{"localhost"}, {"127.0.0.1"}, {"example.com"},
	{"xn--80aacbuczbw9a6a.xn--p1ai"}
};
static FuzzMsg content_type[] = {
	{"text/html;charset=utf-8"}, {"image/jpeg"}, {"text/plain"}
};
static FuzzMsg content_len[] = {
	{"10000"}, {"0"}, {"-42", FUZZ_MSG_F_INVAL},
	{"146"}, {"0100"}, {"100500"}
};
#define FUZZ_FLD_F_CHUNKED		(0x0001 << FUZZ_MSG_F_SHIFT)
#define FUZZ_FLD_F_CHUNKED_LAST		(0x0002 << FUZZ_MSG_F_SHIFT)
static FuzzMsg transfer_encoding[] = {
	{"chunked", FUZZ_FLD_F_CHUNKED},
	{"identity"}, {"compress"}, {"deflate"}, {"gzip"}
};
static FuzzMsg accept[] = {
	{"text/plain"}, {"text/html;q=0.5"}, {"application/xhtml+xml"},
	{"application/xml; q=0.2"}, {"*/*; q=0.8"}
};
static FuzzMsg accept_language[] = {
	{"ru"}, {"en-US,en;q=0.5"}, {"da"}, {"en-gb; q=0.8"}, {"ru;q=0.9"}
};
static FuzzMsg accept_encoding[] = {
	{"chunked"}, {"identity;q=0.5"}, {"compress"}, {"deflate; q=0.2"},
	{"*;q=0"}
};
static FuzzMsg accept_ranges[] = {
	{"bytes"}, {"none"}
};
static FuzzMsg cookie[] = {
	{"name=value"}
};
static FuzzMsg set_cookie[] = {
	{"name=value"}
};
static FuzzMsg etag[] = {
	{"\"56d-9989200-1132c580\""}
};
static FuzzMsg server[] = {
	{"Apache/2.2.17 (Win32) PHP/5.3.5"}
};
static FuzzMsg cache_control[] = {
	{"no-cache"}, {"max-age=3600"}, {"no-store"}, {"max-stale=0"},
	{"min-fresh=0"}, {"no-transform"}, {"only-if-cached"},
	{"cache-extension"}
};
static FuzzMsg expires[] = {
	{"Tue, 31 Jan 2012 15:02:53 GMT"},
	{"Tue, 999 Jan 2012 15:02:53 GMT", FUZZ_MSG_F_INVAL}
};

/*
 * A function that makes sure that the header field value is compatible
 * with the RFC. That is needed in complex cases where the correctness
 * may depend on internal or auxiliary values.
 * The function must return the flags of the field ORed with the result
 * of either FUZZ_VALID or FUZZ_INVALID.
 */
typedef unsigned int (*fld_func_t)(TfwFuzzContext *ctx,
				   int type, int fld, int val);

/*
 * Check various conditions that put limitations on correct values of
 * "Transfer-Encoding" header field. Mark the field as invalid in cases
 * where the parser considers the value of this header field incorrect.
 */
static unsigned int
fld_transfer_encoding(TfwFuzzContext *ctx, int type, int fld, int val)
{
	unsigned int fld_data_flags;

	BUG_ON(fld != TRANSFER_ENCODING);
	BUG_ON(val >= sizeof(transfer_encoding) / sizeof(FuzzMsg));

	fld_data_flags = transfer_encoding[val].flags;

	/*
	 * In responses this header field may not be present
	 * if the response status code is one of 1xx or 204.
	 */
	if (type == FUZZ_RESP) {
		if (ctx->fld_flags[RESP_CODE]
		    & (FUZZ_FLD_F_STATUS_100 | FUZZ_FLD_F_STATUS_204))
			return fld_data_flags | FUZZ_INVALID;
	}
	/*
	 * "chunked" coding may not be repeated. Also, mark cases
	 * where "chunked" coding is the last coding. That is used
	 * in verifications later.
	 */
	if (ctx->fld_flags[TRANSFER_ENCODING] & FUZZ_FLD_F_CHUNKED) {
		if (fld_data_flags & FUZZ_FLD_F_CHUNKED)
			return fld_data_flags | FUZZ_INVALID;
		ctx->fld_flags[TRANSFER_ENCODING] &= ~FUZZ_FLD_F_CHUNKED_LAST;
	} else if (fld_data_flags & FUZZ_FLD_F_CHUNKED) {
		fld_data_flags |= FUZZ_FLD_F_CHUNKED_LAST;
	}

	return fld_data_flags | FUZZ_VALID;
}

/*
 * The "Expires:" header field is generated only for responses. The value
 * is the date in a special format. If the date is invalid in this header
 * field, then the value is considered a date in the past, as if already
 * expired.
 */
static unsigned int
fld_expires(TfwFuzzContext *ctx, int type, int fld, int val)
{
	BUG_ON(type != FUZZ_RESP);
	BUG_ON(fld != EXPIRES);
	BUG_ON(val >= sizeof(expires) / sizeof(FuzzMsg));

	return FUZZ_VALID;
}

/*
 * @key		- the header field name;
 * @vals	- the list of various values of the header field;
 * @func	- the function to check the correctness of the values;
 */
static struct {
	char		*key;
	FuzzMsg		*vals;
	fld_func_t	func;
} fld_data[N_FIELDS] = {
	[0 ... N_FIELDS-1] = { 0 },
	[SPACES]		= { NULL, spaces },
	[METHOD]		= { NULL, methods },
	[HTTP_VER]		= { NULL, versions },
	[RESP_CODE]		= { NULL, resp_code },
	[URI_PATH_START]	= { NULL, uri_path_start },
	[URI_FILE]		= { NULL, uri_file },
	[CONNECTION]		= { "Connection:", conn_val },
	[USER_AGENT]		= { "User-Agent:", ua_val },
	[HOST]			= { "Host:", host_val },
	[X_FORWARDED_FOR]	= { "X-Forwarded-For:", host_val },
	[CONTENT_TYPE]		= { "Content-Type:", content_type },
	[CONTENT_LENGTH]	= { "Content-Length:", content_len },
	[TRANSFER_ENCODING]	= { "Transfer-Encoding:", transfer_encoding,
				    fld_transfer_encoding },
	[ACCEPT]		= { "Accept:", accept },
	[ACCEPT_LANGUAGE]	= { "Accept-Language:", accept_language },
	[ACCEPT_ENCODING]	= { "Accept-Encoding:", accept_encoding },
	[ACCEPT_RANGES]		= { "Accept-Ranges:", accept_ranges },
	[COOKIE]		= { "Cookie:", cookie },
	[SET_COOKIE]		= { "Set-Cookie:", set_cookie },
	[ETAG]			= { "ETag:", etag },
	[SERVER]		= { "Server:", server },
	[CACHE_CONTROL]		= { "Cache-Control:", cache_control },
	[EXPIRES]		= { "Expires:", expires, fld_expires },
};

#define A_URI "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
              "abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;="
#define A_URI_INVAL " <>`^{}\"\n\t\x03\x07\x1F"
#define A_UA "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
              "abcdefghijklmnopqrstuvwxyz0123456789" \
              "-._~:/?#[]@!$&'()*+,;= <>`^{}\""
#define A_UA_INVAL "\n\t\x03\x07\x1F"
#define A_HOST "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
	       "abcdefghijklmnopqrstuvwxyz0123456789-."
/* Don't include characters which can be treated as chunk length. */
#define A_BODY	"GHIJKLMNOPQRSTUVWXYZghijklmnopqrstuvwxyz.,-_;: \n\t" \
		"\x03\x07\x1F\x8F\xFF"
#define A_HOST_INVAL A_URI_INVAL
#define A_X_FF A_HOST
#define A_X_FF_INVAL A_URI_INVAL
#define INVALID_FIELD_PERIOD 5
#define DUPLICATES_PERIOD 10
#define MAX_DUPLICATES 9
#define INVALID_BODY_PERIOD 5

/*
 * @size	- the number of possible values;
 * @over	- the number of generated values;
 * @a_val	- the valid alphabet for generated values;
 * @a_inval	- an invalid alphabet for generated values;
 * @singular	- only for headers: 0 = nonsingular, 1 = singular;
 * @dissipation	- duplicate header may have a different value: 0 = yes, 1 = no;
 * @max_val_len	- the maximum length of the value;
 */
static struct {
	int size;
	int over;
	char *a_val;
	char *a_inval;
	int singular;
	int dissipation;
	int max_val_len;
} gen_vector[N_FIELDS] = {
	/* SPACES */
	{sizeof(spaces) / sizeof(FuzzMsg), 0, NULL, NULL},
	/* METHOD */
	{sizeof(methods) / sizeof(FuzzMsg), 0, NULL, NULL},
	/* HTTP_VER */
	{sizeof(versions) / sizeof(FuzzMsg), 0, NULL, NULL},
	/* RESP_CODE */
	{sizeof(resp_code) / sizeof(FuzzMsg), 0, NULL, NULL},
	/* URI_PATH_START */
	{sizeof(uri_path_start) / sizeof(FuzzMsg), 0, NULL, NULL},
	/* URI_FILE */
	{sizeof(uri_file) / sizeof(FuzzMsg), 2, A_URI, A_URI_INVAL},
	/* CONNECTION */
	{sizeof(conn_val) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 0},
	/* USER_AGENT */
	{sizeof(ua_val) / sizeof(FuzzMsg), 2, A_UA, A_UA_INVAL, 1, 1},
	/* HOST */
	{sizeof(host_val) / sizeof(FuzzMsg), 2, A_HOST, A_HOST_INVAL, 1, 1},
	/* X_FORWARDED_FOR */
	{sizeof(host_val) / sizeof(FuzzMsg), 2, A_X_FF, A_X_FF_INVAL, 0, 1},
	/* CONTENT_TYPE */
	{sizeof(content_type) / sizeof(FuzzMsg), 0, NULL, NULL, 1, 1},
	/* CONTENT_LENGTH */
	{sizeof(content_len) / sizeof(FuzzMsg), 2, "0123456789", A_URI, 1, 1,
		MAX_CONTENT_LENGTH_LEN},
	/* TRANSFER_ENCODING */
	{sizeof(transfer_encoding) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 0},
	/* ACCEPT */
	{sizeof(accept) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 1},
	/* ACCEPT_LANGUAGE */
	{sizeof(accept_language) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 1},
	/* ACCEPT_ENCODING */
	{sizeof(accept_encoding) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 1},
	/* ACCEPT_RANGES */
	{sizeof(accept_ranges) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 1},
	/* COOKIE */
	{sizeof(cookie) / sizeof(FuzzMsg), 0, NULL, NULL, 1, 1},
	/* SET_COOKIE */
	{sizeof(set_cookie) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 1},
	/* ETAG */
	{sizeof(etag) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 1},
	/* SERVER */
	{sizeof(server) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 1},
	/* CACHE_CONTROL */
	{sizeof(cache_control) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 1},
	/* EXPIRES */
	{sizeof(expires) / sizeof(FuzzMsg), 0, NULL, NULL, 0, 1},
	/* TRANSFER_ENCODING_NUM */
	{2, 0, NULL, NULL},
	/* URI_PATH_DEPTH */
	{2, 0, NULL, NULL},
	/* BODY_CHUNKS_NUM */
	{3, 0, NULL, NULL},
};

static int
gen_vector_move(TfwFuzzContext *ctx, int i)
{
	int max;

	if (i == N_FIELDS)
		return FUZZ_END;

	max = gen_vector[i].size + gen_vector[i].over - 1;
	do {
		ctx->i[i]++;
		if (ctx->i[i] > max) {
			ctx->i[i] = 0;
			if (gen_vector_move(ctx, i + 1) == FUZZ_END)
				return FUZZ_END;
		}
	} while (ctx->is_only_valid && fld_data[i].vals
		 && ctx->i[i] < gen_vector[i].size
		 && FUZZ_MSG_INVAL(fld_data[i].vals[ctx->i[i]]));

	return FUZZ_VALID;
}

static void
addch(char **p, char *end, char ch)
{
	if (!ch)
		return;

	if(*p + 1 > end)
		return;

	*(*p)++ = ch;
}

static void
add_string(char **p, char *end, const char *str)
{
	for (; *str != '\0'; str++)
		addch(p, end, *str);
}

static void
add_rand_string(char **p, char *end, int n, const char *seed)
{
	int i, len;

	BUG_ON(!seed);

	len = strlen(seed);
	for (i = 0; i < n; ++i)
		addch(p, end, seed[((i + 333) ^ seed[i % len]) % len]);
}

static unsigned int
__add_field(TfwFuzzContext *ctx, int type, char **p, char *end, int t, int n)
{
	BUG_ON(t < 0);
	BUG_ON(t >= TRANSFER_ENCODING_NUM);

	BUG_ON(!fld_data[t].vals);

	if (n < gen_vector[t].size) {
		unsigned int r;
		FuzzMsg fmsg = fld_data[t].vals[n];

		add_string(p, end, fmsg.sval);

		if (fld_data[t].func)
			r = fld_data[t].func(ctx, type, t, n);
		else
			r = fmsg.flags;

		if (r & FUZZ_MSG_F_INVAL) {
			TFW_DBG("generate invalid field %d for header %d\n",
				 n, t);
			r |= FUZZ_INVALID;
		}

		ctx->fld_flags[t] |= r;

		return r;
	} else {
		char *v = *p;
		int len = n * 256;
		unsigned int r;

		if (n % INVALID_FIELD_PERIOD || ctx->is_only_valid) {
			if (gen_vector[t].max_val_len)
				len = gen_vector[t].max_val_len;
			add_rand_string(p, end, len, gen_vector[t].a_val);
			r = FUZZ_VALID;
		} else {
			add_rand_string(p, end, len, gen_vector[t].a_inval);
			r = FUZZ_INVALID;
		}

		if (t == CONTENT_LENGTH && r == FUZZ_VALID) {
			strncpy(ctx->content_length, v, len);
			ctx->content_length[len] = '\0';
		} else {
			ctx->content_length[0] = '\0';
		}

		if (r == FUZZ_INVALID)
			TFW_DBG("generate invalid random field for header %d\n",
				t);

		return r;
	}
}

static unsigned int
add_field(TfwFuzzContext *ctx, int type, char **p, char *end, int t)
{
	return __add_field(ctx, type, p, end, t, ctx->i[t]);
}

static unsigned int
__add_header(TfwFuzzContext *ctx, int type, char **p, char *end, int t, int n)
{
	unsigned int v = 0, i;

	BUG_ON(t < 0);
	BUG_ON(t >= TRANSFER_ENCODING_NUM);

	BUG_ON(!fld_data[t].key);

	add_string(p, end, fld_data[t].key);
	v |= add_field(ctx, type, p, end, SPACES);
	v |= add_field(ctx, type, p, end, t);
	for (i = 0; i < n; ++i) {
		addch(p, end, ',');
		v |= add_field(ctx, type, p, end, SPACES);
		v |= __add_field(ctx, type, p, end, t, (i * 256) %
			(gen_vector[t].size + gen_vector[t].over));
	}

	add_string(p, end, "\r\n");

	if (v & FUZZ_INVALID)
		TFW_DBG("generate invalid header %d\n", t);

	ctx->hdr_flags |= 1 << t;

	return v;
}

static unsigned int
__add_header_rand(TfwFuzzContext *ctx, int type,
		  char **p, char *end, int t, int n)
{
	static unsigned int rand = 0;

	/* For now, just alternate between adding a header and not adding. */
	return (++rand) % 2 ? __add_header(ctx, type, p, end, t, n) : FUZZ_VALID;
}

static unsigned int
add_header(TfwFuzzContext *ctx, int type, char **p, char *end, int t)
{
	return __add_header(ctx, type, p, end, t, 0);
}

static unsigned int
add_body(TfwFuzzContext *ctx, char **p, char *end, int type)
{
	size_t len = 0, i, j;
	char *len_str;
	int err, ret = FUZZ_VALID;

	i = ctx->i[CONTENT_LENGTH];
	len_str = (i < gen_vector[CONTENT_LENGTH].size)
		  ? (content_len[i].flags & FUZZ_MSG_F_INVAL)
		    ? "500" /* Generate content of arbitrary size for invalid
			     * Content-Length value. */
		    : content_len[i].sval
		  : ctx->content_length;

	err = kstrtoul(len_str, 10, &len);
	if (err) {
		TFW_ERR("error %d on getting content length from \"%s\""
			"(%lu)\n", err, len_str, i);
		return FUZZ_INVALID;
	}

	if (!(ctx->fld_flags[TRANSFER_ENCODING] & FUZZ_FLD_F_CHUNKED)) {
		if (!ctx->is_only_valid && len && !(i % INVALID_BODY_PERIOD)) {
			len /= 2;
			ret = FUZZ_INVALID;
			TFW_DBG("1/2 invalid body %lu\n", len);
		}

		add_rand_string(p, end, len, A_BODY);
	}
	else {
		int chunks = ctx->i[BODY_CHUNKS_NUM] + 1;
		size_t chlen, rem, step;

		BUG_ON(chunks <= 0);

		if (len > 0) {
			chlen = len / chunks;
			rem = len % chunks;
			for (j = 0; j < chunks; j++) {
				char buf[256];

				step = chlen;
				if (rem) {
					step += rem;
					rem = 0;
				}

				snprintf(buf, sizeof(buf), "%zx", step);

				add_string(p, end, buf);
				add_string(p, end, "\r\n");

				if (!ctx->is_only_valid && step
				    && !(i % INVALID_BODY_PERIOD))
				{
					step /= 2;
					ret = FUZZ_INVALID;
					TFW_DBG("1/2 invalid chunked body %lu,"
						" chunks %d\n", len, chunks);
				}

				add_rand_string(p, end, step, A_BODY);
				add_string(p, end, "\r\n");
			}
		}

		add_string(p, end, "0\r\n\r\n");
	}

	return ret;
}

static unsigned int
__add_duplicates(TfwFuzzContext *ctx, int type,
		 char **p, char *end, int t, int n)
{
	int i, tmp = 0;
	unsigned int v = FUZZ_VALID;

	if (ctx->curr_duplicates++ % DUPLICATES_PERIOD)
		return FUZZ_VALID;

	if (ctx->is_only_valid && gen_vector[t].singular)
		return FUZZ_VALID;

	for (i = 0; i < ctx->curr_duplicates % MAX_DUPLICATES; ++i) {
		if (gen_vector[t].dissipation) {
			tmp = ctx->i[t];
			ctx->i[t] = (ctx->i[t] + i) % gen_vector[t].size;
		}

		v |= __add_header(ctx, type, p, end, t, n);

		if (gen_vector[t].dissipation)
			ctx->i[t] = tmp;
	}

	if (gen_vector[t].singular && i > 0) {
		TFW_DBG("generate duplicate for singular header %d\n", t);
		return FUZZ_INVALID;
	}

	return v;
}

static unsigned int
add_duplicates(TfwFuzzContext *ctx, int type, char **p, char *end, int t)
{
	return __add_duplicates(ctx, type, p, end, t, 0);
}

/*
 * Make sure that header fields and values in the set of headers
 * are compatible with each other.
 */
static bool
fuzz_hdrs_compatible(TfwFuzzContext *ctx, int type, unsigned int v)
{
	/*
	 * RFC 7230 3.3.3: Any response with a 1xx (Informational),
	 * 204 (No Content), or 304 (Not Modified) status code is
	 * always terminated by the first empty line after the header
	 * fields, regardless of the header fields present in the
	 * message, and thus cannot contain a message body.
	 */
	if (type & FUZZ_RESP) {
		if ((ctx->fld_flags[METHOD]
		     & (FUZZ_FLD_F_STATUS_100
			| FUZZ_FLD_F_STATUS_204
			| FUZZ_FLD_F_STATUS_304))
		    || (v & FUZZ_MSG_F_EMPTY_BODY))
		{
			return true;
		}
	}
	/*
	 * RFC 7230 3.3.2: A sender MUST NOT send a Content-Length
	 * header field in any message that contains a Transfer-Encoding
	 * header field.
	 */
	if (ctx->hdr_flags & (1 << TRANSFER_ENCODING)) {
		unsigned int te_flags = ctx->fld_flags[TRANSFER_ENCODING];
		if (ctx->hdr_flags & (1 << CONTENT_LENGTH))
			return false;
		if (te_flags & FUZZ_FLD_F_CHUNKED) {
			if (!(te_flags & FUZZ_FLD_F_CHUNKED_LAST))
				return false;
		} else if (type == FUZZ_REQ) {
			return false;
		}
	}

	return true;
}

void
fuzz_init(TfwFuzzContext *ctx, bool is_only_valid)
{
	/* Ensure that there's a bit for each header field. */
	BUILD_BUG_ON(sizeof(ctx->hdr_flags) > N_FIELDS);

	memset(ctx->i, 0, sizeof(ctx->i));
	ctx->is_only_valid = is_only_valid;
	ctx->curr_duplicates = 0;
}
EXPORT_SYMBOL(fuzz_init);

/**
 * @returns FUZZ_VALID if the result is a valid HTTP message, FUZZ_INVALID
 * if the result is an invalid HTTP message, FUZZ_END if the HTTP message
 * sequence is over.
 *
 * @move is how many gen_vector's elements should be changed each time a new
 * HTTP message is generated, should be >= 1.
 */
int
fuzz_gen(TfwFuzzContext *ctx, char *str, char *end, field_t start,
	 int move, int type)
{
	int i, n, ret = FUZZ_VALID;
	unsigned int v = 0;

	ctx->hdr_flags = 0;
	memset(ctx->fld_flags, 0, sizeof(ctx->fld_flags));

	if (str == NULL)
		return -EINVAL;

	if (type == FUZZ_REQ) {
		v |= add_field(ctx, type, &str, end, METHOD);
		addch(&str, end, ' ');

		v |= add_field(ctx, type, &str, end, URI_PATH_START);
		addch(&str, end, '/');
		v |= add_field(ctx, type, &str, end, HOST);
		for (i = 0; i < ctx->i[URI_PATH_DEPTH] + 1; ++i) {
			addch(&str, end, '/');
			v |= add_field(ctx, type, &str, end, URI_FILE);
		}
		addch(&str, end, ' ');
	}

	add_string(&str, end, "HTTP/");
	v |= add_field(ctx, type, &str, end, HTTP_VER);

	if (type == FUZZ_RESP) {
		addch(&str, end, ' ');
		v |= add_field(ctx, type, &str, end, SPACES);
		v |= add_field(ctx, type, &str, end, RESP_CODE);
	}

	add_string(&str, end, "\r\n");

	if (type == FUZZ_REQ) {
		v |= add_header(ctx, type, &str, end, HOST);
		v |= add_duplicates(ctx, type, &str, end, HOST);

		v |= add_header(ctx, type, &str, end, ACCEPT);
		v |= add_duplicates(ctx, type, &str, end, ACCEPT);

		v |= add_header(ctx, type, &str, end, ACCEPT_LANGUAGE);
		v |= add_duplicates(ctx, type, &str, end, ACCEPT_LANGUAGE);

		v |= add_header(ctx, type, &str, end, ACCEPT_ENCODING);
		v |= add_duplicates(ctx, type, &str, end, ACCEPT_ENCODING);

		v |= add_header(ctx, type, &str, end, COOKIE);
		v |= add_duplicates(ctx, type, &str, end, COOKIE);

		v |= add_header(ctx, type, &str, end, X_FORWARDED_FOR);
		v |= add_duplicates(ctx, type, &str, end, X_FORWARDED_FOR);

		v |= add_header(ctx, type, &str, end, USER_AGENT);
		v |= add_duplicates(ctx, type, &str, end, USER_AGENT);
	}
	else if (type == FUZZ_RESP) {
		v |= add_header(ctx, type, &str, end, ACCEPT_RANGES);
		v |= add_duplicates(ctx, type, &str, end, ACCEPT_RANGES);

		v |= add_header(ctx, type, &str, end, SET_COOKIE);
		v |= add_duplicates(ctx, type, &str, end, SET_COOKIE);

		v |= add_header(ctx, type, &str, end, ETAG);
		v |= add_duplicates(ctx, type, &str, end, ETAG);

		v |= add_header(ctx, type, &str, end, SERVER);
		v |= add_duplicates(ctx, type, &str, end, SERVER);

		v |= add_header(ctx, type, &str, end, EXPIRES);
		v |= add_duplicates(ctx, type, &str, end, EXPIRES);
	}

	n = ctx->i[TRANSFER_ENCODING_NUM];
	v |= __add_header_rand(ctx, type, &str, end, TRANSFER_ENCODING, n);
	v |= __add_duplicates(ctx, type, &str, end, TRANSFER_ENCODING, n);

	v |= add_header(ctx, type, &str, end, CONNECTION);
	v |= add_duplicates(ctx, type, &str, end, CONNECTION);

	v |= add_header(ctx, type, &str, end, CONTENT_TYPE);
	v |= add_duplicates(ctx, type, &str, end, CONTENT_TYPE);

	v |= add_header(ctx, type, &str, end, CONTENT_LENGTH);
	v |= add_duplicates(ctx, type, &str, end, CONTENT_LENGTH);

	v |= add_header(ctx, type, &str, end, CACHE_CONTROL);
	v |= add_duplicates(ctx, type, &str, end, CACHE_CONTROL);

	add_string(&str, end, "\r\n");

	/*
	 * That's not too bad to add body to invalid message
	 * supposed to have empty body.
	 */
	if (!(v & FUZZ_MSG_F_EMPTY_BODY) || (v & FUZZ_MSG_F_INVAL))
		v |= add_body(ctx, &str, end, type);

	if (str < end) {
		*str = '\0';
	} else {
		v |= FUZZ_INVALID;
		*(end - 1) = '\0';
	}

	if (!(v & FUZZ_INVALID) && !fuzz_hdrs_compatible(ctx, type, v))
		v |= FUZZ_INVALID;

	for (i = 0; i < move; i++) {
		ret = gen_vector_move(ctx, start);
		if (ret == FUZZ_END)
			break;
	}

	if (v & FUZZ_INVALID)
		return FUZZ_INVALID;
	return ret;
}
EXPORT_SYMBOL(fuzz_gen);
