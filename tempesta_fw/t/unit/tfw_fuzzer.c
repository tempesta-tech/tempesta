#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "tfw_fuzzer.h"

typedef struct {
	char *s;
	int inval; /* 0 - valid, 1 - invalid */
} fuzz_msg;

static fuzz_msg spaces[] = {{"", 0}};
static fuzz_msg methods[] = {{"GET", 0}, {"HEAD", 0}, {"POST", 0}};
static fuzz_msg uri_path_start[] = {{"http:/", 0}, {"", 0}};
static fuzz_msg uri_file[] = {{"file.html", 0}, {"f-i_l.e", 0},
	{"fi%20le", 0}, {"xn--80aaxtnfh0b", 0}};
static fuzz_msg versions[] = {{"1.0", 0}, {"1.1", 0},
	{"0.9", 1}}; // HTTP/0.9 is blocked
static fuzz_msg resp_code[] = {{"100 Continue", 0}, {"200 OK", 0},
	{"302 Found", 0}, {"304 Not Modified", 0}, {"400 Bad Request", 0},
	{"403 Forbidden", 0}, {"404 Not Found", 0},
	{"500 Internal Server Error", 0}};
static fuzz_msg conn_val[] = {{"keep-alive", 0}, {"close", 0}, {"upgrade", 0}};
static fuzz_msg ua_val[] = {{"Wget/1.13.4 (linux-gnu)", 0}, {"Mozilla/5.0", 0}};
static fuzz_msg host_val[] = {{"localhost", 0}, {"127.0.0.1", 0},
	{"example.com", 0}, {"xn--80aacbuczbw9a6a.xn--p1ai", 0}};
static fuzz_msg content_type[] = {{"text/html;charset=utf-8", 0},
	{"image/jpeg", 0}, {"text/plain", 0}};
static fuzz_msg content_len[] = {{"10000", 0}, {"0", 0}, {"-42", 1},
	{"146", 1}, {"0100", 1}, {"100500", 1}};
static fuzz_msg transfer_encoding[] = {{"chunked", 0}, {"identity", 0},
	{"compress", 0}, {"deflate", 0}, {"gzip", 0}};
static fuzz_msg accept[] = {{"text/plain", 0}, {"text/html;q=0.5", 0},
	{"application/xhtml+xml", 0}, {"application/xml; q=0.2", 0}, {"*/*; q=0.8", 0}};
static fuzz_msg accept_language[] = {{"ru", 0}, {"en-US,en;q=0.5", 0},
	{"da", 0}, {"en-gb; q=0.8", 0}, {"ru;q=0.9", 0}};
static fuzz_msg accept_encoding[] = {{"chunked", 0}, {"identity;q=0.5", 0},
	{"compress", 0}, {"deflate; q=0.2", 0}, {"*;q=0", 0}};
static fuzz_msg accept_ranges[] = {{"bytes", 0}, {"none", 0}};
static fuzz_msg cookie[] = {{"name=value", 0}};
static fuzz_msg set_cookie[] = {{"name=value", 0}};
static fuzz_msg etag[] = {{"\"56d-9989200-1132c580\"", 0}};
static fuzz_msg server[] = {{"Apache/2.2.17 (Win32) PHP/5.3.5", 0}};
static fuzz_msg cache_control[] = {{"no-cache", 0}, {"no-cache", 0},
	{"max-age=3600", 0}, {"no-store", 0}, {"max-stale=0", 0},
	{"min-fresh=0", 0}, {"no-transform", 0}, {"only-if-cached", 0},
	{"cache-extension", 0}};
static fuzz_msg expires[] = {{"Tue, 31 Jan 2012 15:02:53 GMT", 0}};

enum {
	SPACES,
	METHOD,
	HTTP_VER,
	RESP_CODE,
	URI_PATH_START,
	URI_FILE,
	CONNECTION,
	USER_AGENT,
	HOST,
	X_FORWARDED_FOR,
	CONTENT_TYPE,
	CONTENT_LENGTH,
	TRANSFER_ENCODING,
	ACCEPT,
	ACCEPT_LANGUAGE,
	ACCEPT_ENCODING,
	ACCEPT_RANGES,
	COOKIE,
	SET_COOKIE,
	ETAG,
	SERVER,
	CACHE_CONTROL,
	EXPIRES,
	TRANSFER_ENCODING_NUM,
	URI_PATH_DEPTH,
	DUPLICATES,
	BODY_CHUNKS_NUM,
	N_FIELDS,
};

static fuzz_msg *vals[] = {
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
	NULL,
};

#define A_URI "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
              "abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;="
#define A_URI_INVAL " <>`^{}\"\n\t\x03\x07\x1F"
#define A_UA A_URI
#define A_UA_INVAL A_URI_INVAL
#define A_HOST "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
	       "abcdefghijklmnopqrstuvwxyz0123456789 -._~!$&'()*+,;="
#define A_HOST_INVAL A_URI_INVAL
#define A_X_FF A_HOST
#define A_X_FF_INVAL A_URI_INVAL

static const char *a_body = A_URI A_URI_INVAL;

static struct {
	int i;
	int size;
	int over;
	char *a_val;
	char *a_inval;
	int singular; /* only for headers; 0 - nonsingular, 1 - singular */
} gen_vector[] = {
	/* SPACES */
	{0, sizeof(spaces) / sizeof(fuzz_msg), 1, " ", A_URI},
	/* METHOD */
	{0, sizeof(methods) / sizeof(fuzz_msg), 0, NULL, NULL},
	/* HTTP_VER */
	{0, sizeof(versions) / sizeof(fuzz_msg), 0, NULL, NULL},
	/* RESP_CODE */
	{0, sizeof(resp_code) / sizeof(fuzz_msg), 0, NULL, NULL},
	/* URI_PATH_START */
	{0, sizeof(uri_path_start) / sizeof(fuzz_msg), 0, NULL, NULL},
	/* URI_FILE */
	{0, sizeof(uri_file) / sizeof(fuzz_msg), 1, A_URI, A_URI_INVAL},
	/* CONNECTION */
	{0, sizeof(conn_val) / sizeof(fuzz_msg), 0, NULL, NULL, 1},
	/* USER_AGENT*/
	{0, sizeof(ua_val) / sizeof(fuzz_msg), 1, A_UA, A_UA_INVAL, 1},
	/* HOST */
	{0, sizeof(host_val) / sizeof(fuzz_msg), 1, A_HOST, A_HOST_INVAL, 1},
	/* X_FORWARDED_FOR */
	{0, sizeof(host_val) / sizeof(fuzz_msg), 1, A_X_FF, A_X_FF, 0},
	/* CONTENT_TYPE */
	{0, sizeof(content_type) / sizeof(fuzz_msg), 0, NULL, NULL, 1},
	/* CONTENT_LENGTH */
	{0, sizeof(content_len) / sizeof(fuzz_msg), 1, "0123456789", A_URI, 1},
	/* TRANSFER_ENCODING */
	{0, sizeof(transfer_encoding) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* ACCEPT */
	{0, sizeof(accept) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* ACCEPT_LANGUAGE */
	{0, sizeof(accept_language) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* ACCEPT_ENCODING */
	{0, sizeof(accept_encoding) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* ACCEPT_RANGES */
	{0, sizeof(accept_ranges) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* COOKIE */
	{0, sizeof(cookie) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* SET_COOKIE */
	{0, sizeof(set_cookie) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* ETAG */
	{0, sizeof(etag) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* SERVER */
	{0, sizeof(server) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* CACHE_CONTROL */
	{0, sizeof(cache_control) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* EXPIRES */
	{0, sizeof(expires) / sizeof(fuzz_msg), 0, NULL, NULL, 0},
	/* TRANSFER_ENCODING_NUM */
	{0, 2, 0, NULL, NULL},
	/* URI_PATH_DEPTH */
	{0, 2, 0, NULL, NULL},
	/* DUPLICATES */
	{0, 2, 0, NULL, NULL},
	/* BODY_CHUNKS_NUM */
	{0, 3, 0, NULL, NULL},
};

static int
gen_vector_move(int i)
{
	int max;

	if (i == N_FIELDS)
		return FUZZ_END;

	max = gen_vector[i].size + gen_vector[i].over - 1;
	if (gen_vector[i].i++ == max) {
		gen_vector[i].i = 0;
		if (gen_vector_move(i + 1) == FUZZ_END)
			return FUZZ_END;
	}

	return FUZZ_VALID;
}

static void
addch(char **p, char ch)
{
	if (!ch)
		return;

	*(*p)++ = ch;
}

static void
add_string(char **p, char *str)
{
	for (; *str != '\0'; str++)
		addch(p, *str);
}

static void
add_rand_string(char **p, int n, char *seed)
{
	int i;

	BUG_ON(!seed);

	for (i = 0; i < n; ++i)
		addch(p, seed[((i + 333) ^ seed[i]) % strlen(seed)]);
}

static int
__add_field(char **p, int t, int n)
{
	fuzz_msg *val;

	BUG_ON(t < 0);
	BUG_ON(t >= TRANSFER_ENCODING_NUM);

	val = vals[t];

	BUG_ON(!val);

	if (n < gen_vector[t].size) {
		fuzz_msg r = val[n];
		add_string(p, r.s);
		return r.inval;
	} else {
		if (n % 2 && gen_vector[t].a_val != NULL) {
			add_rand_string(p, n * 256,
				gen_vector[t].a_val);
			return FUZZ_VALID;
		} else {
			add_rand_string(p, n * 256,
				gen_vector[t].a_inval);
		}
	}

	return FUZZ_INVALID;
}

static int
add_field(char **p, int t)
{
	return __add_field(p, t, gen_vector[t].i);
}

static int
__add_header(char **p, int t, int n)
{
	int v = 0, i;
	char *key;

	BUG_ON(t < 0);
	BUG_ON(t >= TRANSFER_ENCODING_NUM);

	key = keys[t];

	BUG_ON(!key);

	add_string(p, key);
	v |= add_field(p, SPACES);
	v |= add_field(p, t);
	for (i = 0; i < n; ++i) {
		addch(p, ',');
		v |= add_field(p, SPACES);
		v |= __add_field(p, t, (i * 256) %
			(gen_vector[t].size + gen_vector[t].over));
	}

	add_string(p, "\r\n");

	return v;
}

static int
add_header(char **p, int t)
{
	return __add_header(p, t, 0);
}

static int
add_body(char **p, int type)
{
	size_t len = 0, i, j;
	char *len_str;
	int err;

	len_str = content_len[gen_vector[CONTENT_LENGTH].i].s;
	if (!len_str)
		return FUZZ_INVALID;

	err = kstrtoul(len_str, 10, &len);
	if (err) {

		return FUZZ_INVALID;
	}

	if (gen_vector[TRANSFER_ENCODING].i) {
		for (i = 0; i < len; i++)
			*(*p)++ = a_body[(i * 256) % strlen(a_body)];
	}
	else {
		int n = gen_vector[BODY_CHUNKS_NUM].i + 1;
		int chunk = len / n;
		for (j = 0; j < n; j++) {
			int fact = (j != n - 1)? chunk: len - (n - 1) * chunk;

			char buf[256];
			snprintf(buf, sizeof(buf), "%d", fact);

			add_string(p, buf);
			add_string(p, "\r\n");

			for (i = 0; i < fact; i++)
				*(*p)++ = a_body[(i * 256) % strlen(a_body)];
		}
	}

	return FUZZ_VALID;
}

static int
__add_duplicates(char **p, int t, int n)
{
	int i, tmp, v = 0;

	for (i = 0; i < gen_vector[DUPLICATES].i; ++i) {
		tmp = gen_vector[t].i;

		gen_vector[t].i = (gen_vector[t].i + i) % gen_vector[t].size;
		v |= __add_header(p, t, n);

		gen_vector[t].i = tmp;
	}

	if (gen_vector[t].singular && i > 0)
		return FUZZ_INVALID;

	return v;
}

static int
add_duplicates(char **p, int t)
{
	return __add_duplicates(p, t, 0);
}

/* Returns:
 * FUZZ_VALID if the result is a valid request,
 * FUZZ_INVALID if it's invalid,
 * FUZZ_END if the request sequence is over.
 * `move` is how many gen_vector's elements should be changed
 * each time a new request is generated, should be >= 1. */
int
fuzz_gen(char *str, int move, int type)
{
	int i, n, ret, v = 0;

	if (str == NULL)
		return -EINVAL;

	if (type == FUZZ_REQ) {
		v |= add_field(&str, METHOD);
		addch(&str, ' ');

		v |= add_field(&str, URI_PATH_START);
		addch(&str, '/');
		v |= add_field(&str, HOST);
		for (i = 0; i < gen_vector[URI_PATH_DEPTH].i + 1; ++i) {
			addch(&str, '/');
			v |= add_field(&str, URI_FILE);
		}
		addch(&str, ' ');
	}

	add_string(&str, "HTTP/");
	v |= add_field(&str, HTTP_VER);

	if (type == FUZZ_RESP) {
		addch(&str, ' ');
		v |= add_field(&str, SPACES);
		v |= add_field(&str, RESP_CODE);
	}

	add_string(&str, "\r\n");

	if (type == FUZZ_REQ) {
		v |= add_header(&str, HOST);
		v |= add_duplicates(&str, HOST);

		v |= add_header(&str, ACCEPT);
		v |= add_duplicates(&str, ACCEPT);

		v |= add_header(&str, ACCEPT_LANGUAGE);
		v |= add_duplicates(&str, ACCEPT_LANGUAGE);

		v |= add_header(&str, ACCEPT_ENCODING);
		v |= add_duplicates(&str, ACCEPT_ENCODING);

		v |= add_header(&str, COOKIE);
		v |= add_duplicates(&str, COOKIE);

		v |= add_header(&str, X_FORWARDED_FOR);
		v |= add_duplicates(&str, X_FORWARDED_FOR);
	}
	else if (type == FUZZ_RESP) {
		v |= add_header(&str, ACCEPT_RANGES);
		v |= add_duplicates(&str, ACCEPT_RANGES);

		v |= add_header(&str, SET_COOKIE);
		v |= add_duplicates(&str, SET_COOKIE);

		v |= add_header(&str, ETAG);
		v |= add_duplicates(&str, ETAG);

		v |= add_header(&str, SERVER);
		v |= add_duplicates(&str, SERVER);
	}

	v |= add_header(&str, CONNECTION);
	v |= add_duplicates(&str, CONNECTION);

	v |= add_header(&str, USER_AGENT);
	v |= add_duplicates(&str, USER_AGENT);

	v |= add_header(&str, CONTENT_TYPE);
	v |= add_duplicates(&str, CONTENT_TYPE);

	v |= add_header(&str, CONTENT_LENGTH);
	v |= add_duplicates(&str, CONTENT_LENGTH);

	n = gen_vector[TRANSFER_ENCODING_NUM].i;
	v |= __add_header(&str, TRANSFER_ENCODING, n);
	v |= __add_duplicates(&str, TRANSFER_ENCODING, n);

	v |= add_header(&str, CACHE_CONTROL);
	v |= add_duplicates(&str, CACHE_CONTROL);

	v |= add_header(&str, EXPIRES);
	v |= add_duplicates(&str, EXPIRES);

	add_string(&str, "\r\n");

	v |= add_body(&str, type);

	*str = '\0';

	for (i = 0; i < move; i++) {
		ret = gen_vector_move((N_FIELDS - 1 + i * ((i % 2) ? 3 : 2))
			% N_FIELDS);
		if (ret == FUZZ_END)
			break;
	}

	if (v & FUZZ_INVALID)
		return FUZZ_INVALID;
	return ret;
}
EXPORT_SYMBOL(fuzz_gen);
