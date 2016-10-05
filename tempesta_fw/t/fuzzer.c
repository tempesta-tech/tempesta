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
MODULE_VERSION("0.1.1");
MODULE_LICENSE("GPL");

#define FUZZ_MSG_F_INVAL	FUZZ_INVALID
#define FUZZ_MSG_F_EMPTY_BODY	0x02

typedef struct {
	char		*s;
	unsigned int	rval;
} FuzzMsg;

#define FUZZ_MSG_INVAL(m)	((m).rval & FUZZ_MSG_F_INVAL)

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
static FuzzMsg resp_code[] = {
	{"100 Continue"}, {"200 OK"}, {"302 Found"},
	{"304 Not Modified", FUZZ_MSG_F_EMPTY_BODY},
	{"400 Bad Request"}, {"403 Forbidden"}, {"404 Not Found"},
	{"500 Internal Server Error"}
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
static FuzzMsg transfer_encoding[] = {
	{"chunked"}, {"identity"}, {"compress"}, {"deflate"}, {"gzip"}
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
	{"no-cache"}, {"no-cache"}, {"max-age=3600"}, {"no-store"},
	{"max-stale=0"}, {"min-fresh=0"}, {"no-transform"}, {"only-if-cached"},
	{"cache-extension"}
};
static FuzzMsg expires[] = {
	{"Tue, 31 Jan 2012 15:02:53 GMT"},
	{"Tue, 999 Jan 2012 15:02:53 GMT", FUZZ_MSG_F_INVAL}
};

static FuzzMsg *vals[] = {
	spaces,
	methods,
	versions,
	resp_code,
	uri_path_start,
	uri_file,
	conn_val,
	ua_val,
	host_val,
	host_val,
	content_type,
	content_len,
	transfer_encoding,
	accept,
	accept_language,
	accept_encoding,
	accept_ranges,
	cookie,
	set_cookie,
	etag,
	server,
	cache_control,
	expires,
	NULL,
	NULL,
	NULL,
	NULL,
};

static char * keys[] = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	"Connection:",
	"User-agent:",
	"Host:",
	"X-Forwarded-For:",
	"Content-Type:",
	"Content-Length:",
	"Transfer-Encoding:",
	"Accept:",
	"Accept-Language:",
	"Accept-Encoding:",
	"Accept-Ranges:",
	"Cookie:",
	"Set-Cookie:",
	"ETag:",
	"Server:",
	"Cache-Control:",
	"Expires:",
	NULL,
	NULL,
	NULL,
	NULL,
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

static struct {
	int size;        /* the number of present values */
	int over;        /* the number of generated values */
	char *a_val;     /* the valid alphabet for generated values */
	char *a_inval;   /* an invalid alphabet for generated values */
	int singular;    /* only for headers; 0 - nonsingular, 1 - singular */
	int dissipation; /* may be duplicates header has diferent values?;
			   0 - no, 1 - yes */
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
	/* USER_AGENT*/
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
	{sizeof(transfer_encoding) / sizeof(FuzzMsg), 0, NULL, NULL, 1, 1},
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
	} while (ctx->is_only_valid && vals[i]
		 && ctx->i[i] < gen_vector[i].size
		 && FUZZ_MSG_INVAL(vals[i][ctx->i[i]]));

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
__add_field(TfwFuzzContext *ctx, char **p, char *end, int t, int n)
{
	FuzzMsg *val;

	BUG_ON(t < 0);
	BUG_ON(t >= TRANSFER_ENCODING_NUM);

	val = vals[t];

	BUG_ON(!val);

	if (n < gen_vector[t].size) {
		FuzzMsg r = val[n];
		add_string(p, end, r.s);

		if (t == TRANSFER_ENCODING && !n)
			ctx->is_chanked_body = true;

		if (FUZZ_MSG_INVAL(r))
			TFW_DBG("generate ivalid field %d for header %d\n",
				 n, t);

		return r.rval;
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
			TFW_DBG("generate ivalid random field for header %d\n",
				t);

		return r;
	}
}

static unsigned int
add_field(TfwFuzzContext *ctx, char **p, char *end, int t)
{
	return __add_field(ctx, p, end, t, ctx->i[t]);
}

static int
__add_header(TfwFuzzContext *ctx, char **p, char *end, int t, int n)
{
	unsigned int v = 0, i;
	char *key;

	BUG_ON(t < 0);
	BUG_ON(t >= TRANSFER_ENCODING_NUM);

	key = keys[t];

	BUG_ON(!key);

	add_string(p, end, key);
	v |= add_field(ctx, p, end, SPACES);
	v |= add_field(ctx, p, end, t);
	for (i = 0; i < n; ++i) {
		addch(p, end, ',');
		v |= add_field(ctx, p, end, SPACES);
		v |= __add_field(ctx, p, end, t, (i * 256) %
			(gen_vector[t].size + gen_vector[t].over));
	}

	add_string(p, end, "\r\n");

	if (v & FUZZ_INVALID)
		TFW_DBG("generate ivalid header %d\n", t);

	return v;
}

static unsigned int
add_header(TfwFuzzContext *ctx, char **p, char *end, int t)
{
	return __add_header(ctx, p, end, t, 0);
}

static unsigned int
add_body(TfwFuzzContext *ctx, char **p, char *end, int type)
{
	size_t len = 0, i, j;
	char *len_str;
	int err, ret = FUZZ_VALID;

	i = ctx->i[CONTENT_LENGTH];
	len_str = (i < gen_vector[CONTENT_LENGTH].size)? content_len[i].s:
							 ctx->content_length;

	err = kstrtoul(len_str, 10, &len);
	if (err) {
		TFW_WARN("error %d on body generation -> invalid\n", err);
		return FUZZ_INVALID;
	}

	if (!ctx->is_chanked_body) {
		if (!ctx->is_only_valid && len
		    && !(i % INVALID_BODY_PERIOD))
		{
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
__add_duplicates(TfwFuzzContext *ctx, char **p, char *end, int t, int n)
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

		v |= __add_header(ctx, p, end, t, n);

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
add_duplicates(TfwFuzzContext *ctx, char **p, char *end, int t)
{
	return __add_duplicates(ctx, p, end, t, 0);
}

void
fuzz_init(TfwFuzzContext *ctx, bool is_only_valid)
{
	memset(ctx->i, 0, sizeof(ctx->i));
	ctx->is_only_valid = is_only_valid;
	ctx->is_chanked_body = false;
	ctx->curr_duplicates = 0;
}
EXPORT_SYMBOL(fuzz_init);

/**
 * @returns FUZZ_VALID if the result is a valid request, FUZZ_INVALID if it's
 * invalid, FUZZ_END if the request sequence is over.
 *
 * @move is how many gen_vector's elements should be changed each time a new
 * request is generated, should be >= 1.
 */
int
fuzz_gen(TfwFuzzContext *ctx, char *str, char *end, field_t start,
	 int move, int type)
{
	int i, n, ret = FUZZ_VALID;
	unsigned int v = 0;

	ctx->is_chanked_body = false;

	if (str == NULL)
		return -EINVAL;

	if (type == FUZZ_REQ) {
		v |= add_field(ctx, &str, end, METHOD);
		addch(&str, end, ' ');

		v |= add_field(ctx, &str, end, URI_PATH_START);
		addch(&str, end, '/');
		v |= add_field(ctx, &str, end, HOST);
		for (i = 0; i < ctx->i[URI_PATH_DEPTH] + 1; ++i) {
			addch(&str, end, '/');
			v |= add_field(ctx, &str, end, URI_FILE);
		}
		addch(&str, end, ' ');
	}

	add_string(&str, end, "HTTP/");
	v |= add_field(ctx, &str, end, HTTP_VER);

	if (type == FUZZ_RESP) {
		addch(&str, end, ' ');
		v |= add_field(ctx, &str, end, SPACES);
		v |= add_field(ctx, &str, end, RESP_CODE);
	}

	add_string(&str, end, "\r\n");

	if (type == FUZZ_REQ) {
		v |= add_header(ctx, &str, end, HOST);
		v |= add_duplicates(ctx, &str, end, HOST);

		v |= add_header(ctx, &str, end, ACCEPT);
		v |= add_duplicates(ctx, &str, end, ACCEPT);

		v |= add_header(ctx, &str, end, ACCEPT_LANGUAGE);
		v |= add_duplicates(ctx, &str, end, ACCEPT_LANGUAGE);

		v |= add_header(ctx, &str, end, ACCEPT_ENCODING);
		v |= add_duplicates(ctx, &str, end, ACCEPT_ENCODING);

		v |= add_header(ctx, &str, end, COOKIE);
		v |= add_duplicates(ctx, &str, end, COOKIE);

		v |= add_header(ctx, &str, end, X_FORWARDED_FOR);
		v |= add_duplicates(ctx, &str, end, X_FORWARDED_FOR);

		v |= add_header(ctx, &str, end, USER_AGENT);
		v |= add_duplicates(ctx, &str, end, USER_AGENT);
	}
	else if (type == FUZZ_RESP) {
		v |= add_header(ctx, &str, end, ACCEPT_RANGES);
		v |= add_duplicates(ctx, &str, end, ACCEPT_RANGES);

		v |= add_header(ctx, &str, end, SET_COOKIE);
		v |= add_duplicates(ctx, &str, end, SET_COOKIE);

		v |= add_header(ctx, &str, end, ETAG);
		v |= add_duplicates(ctx, &str, end, ETAG);

		v |= add_header(ctx, &str, end, SERVER);
		v |= add_duplicates(ctx, &str, end, SERVER);

		v |= add_header(ctx, &str, end, EXPIRES);
		v |= add_duplicates(ctx, &str, end, EXPIRES);

		n = ctx->i[TRANSFER_ENCODING_NUM];
		v |= __add_header(ctx, &str, end, TRANSFER_ENCODING, n);
		v |= __add_duplicates(ctx, &str, end, TRANSFER_ENCODING, n);
	}

	v |= add_header(ctx, &str, end, CONNECTION);
	v |= add_duplicates(ctx, &str, end, CONNECTION);

	v |= add_header(ctx, &str, end, CONTENT_TYPE);
	v |= add_duplicates(ctx, &str, end, CONTENT_TYPE);

	v |= add_header(ctx, &str, end, CONTENT_LENGTH);
	v |= add_duplicates(ctx, &str, end, CONTENT_LENGTH);

	v |= add_header(ctx, &str, end, CACHE_CONTROL);
	v |= add_duplicates(ctx, &str, end, CACHE_CONTROL);

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
