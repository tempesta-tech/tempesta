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
	{"146", 0}, {"0100", 0}, {"100500", 0}};
static fuzz_msg transfer_encoding[] = {{"chunked", 0}, {"identity", 0},
	{"compress", 0}, {"deflate", 0}, {"gzip", 0}};
static fuzz_msg accept[] = {{"text/plain", 0}, {"text/html;q=0.5", 0},
	{"application/xhtml+xml", 0}, {"application/xml; q=0.2", 0},
	{"*/*; q=0.8", 0}};
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
static fuzz_msg expires[] = {{"Tue, 31 Jan 2012 15:02:53 GMT", 0},
	{"Tue, 999 Jan 2012 15:02:53 GMT", 1}};

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
#define A_HOST_INVAL A_URI_INVAL
#define A_X_FF A_HOST
#define A_X_FF_INVAL A_URI_INVAL
#define MAX_CONTENT_LENGTH_LEN 8

static const char *a_body = A_URI A_URI_INVAL;

static struct {
	int i;
	int size;        /* the number of preset values */
	int over;        /* the number of generated values */
	char *a_val;     /* the valid alphabet for generated values */
	char *a_inval;   /* an invalid alphabet for generated values */
	int singular;    /* only for headers; 0 - nonsingular, 1 - singular */
	int dissipation; /* may be duplicates header has diferent values?;
			   0 - no, 1 - yes */
	int max_val_len;
} gen_vector[N_FIELDS] = {
	/* SPACES */
	{0, sizeof(spaces) / sizeof(fuzz_msg), 0, NULL, NULL},
	/* METHOD */
	{0, sizeof(methods) / sizeof(fuzz_msg), 0, NULL, NULL},
	/* HTTP_VER */
	{0, sizeof(versions) / sizeof(fuzz_msg), 0, NULL, NULL},
	/* RESP_CODE */
	{0, sizeof(resp_code) / sizeof(fuzz_msg), 0, NULL, NULL},
	/* URI_PATH_START */
	{0, sizeof(uri_path_start) / sizeof(fuzz_msg), 0, NULL, NULL},
	/* URI_FILE */
	{0, sizeof(uri_file) / sizeof(fuzz_msg), 2, A_URI, A_URI_INVAL},
	/* CONNECTION */
	{0, sizeof(conn_val) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 0},
	/* USER_AGENT*/
	{0, sizeof(ua_val) / sizeof(fuzz_msg), 2, A_UA, A_UA_INVAL, 1, 1},
	/* HOST */
	{0, sizeof(host_val) / sizeof(fuzz_msg), 2, A_HOST, A_HOST_INVAL, 1, 1},
	/* X_FORWARDED_FOR */
	{0, sizeof(host_val) / sizeof(fuzz_msg), 2, A_X_FF, A_X_FF_INVAL, 0, 1},
	/* CONTENT_TYPE */
	{0, sizeof(content_type) / sizeof(fuzz_msg), 0, NULL, NULL, 1, 1},
	/* CONTENT_LENGTH */
	{0, sizeof(content_len) / sizeof(fuzz_msg), 2, "0123456789", A_URI, 1, 1,
		MAX_CONTENT_LENGTH_LEN},
	/* TRANSFER_ENCODING */
	{0, sizeof(transfer_encoding) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 1},
	/* ACCEPT */
	{0, sizeof(accept) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 1},
	/* ACCEPT_LANGUAGE */
	{0, sizeof(accept_language) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 1},
	/* ACCEPT_ENCODING */
	{0, sizeof(accept_encoding) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 1},
	/* ACCEPT_RANGES */
	{0, sizeof(accept_ranges) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 1},
	/* COOKIE */
	{0, sizeof(cookie) / sizeof(fuzz_msg), 0, NULL, NULL, 1, 1},
	/* SET_COOKIE */
	{0, sizeof(set_cookie) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 1},
	/* ETAG */
	{0, sizeof(etag) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 1},
	/* SERVER */
	{0, sizeof(server) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 1},
	/* CACHE_CONTROL */
	{0, sizeof(cache_control) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 1},
	/* EXPIRES */
	{0, sizeof(expires) / sizeof(fuzz_msg), 0, NULL, NULL, 0, 1},
	/* TRANSFER_ENCODING_NUM */
	{0, 2, 0, NULL, NULL},
	/* URI_PATH_DEPTH */
	{0, 2, 0, NULL, NULL},
	/* BODY_CHUNKS_NUM */
	{0, 3, 0, NULL, NULL},
};

static bool is_only_valid = false;

static int
gen_vector_move(int i)
{
	int max;

	if (i == N_FIELDS)
		return FUZZ_END;

	max = gen_vector[i].size + gen_vector[i].over - 1;
	do {
		if (gen_vector[i].i++ == max) {
			gen_vector[i].i = 0;
			if (gen_vector_move(i + 1) == FUZZ_END)
				return FUZZ_END;
		}
	} while (is_only_valid &&
		 vals[i] &&
		 gen_vector[i].i < gen_vector[i].size &&
		 vals[i][gen_vector[i].i].inval);

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

#define INVALID_FIELD_PERIOD 5

static bool is_chancked_body = false;
static char content_length[MAX_CONTENT_LENGTH_LEN + 1];

static int
__add_field(char **p, char *end, int t, int n)
{
	fuzz_msg *val;

	BUG_ON(t < 0);
	BUG_ON(t >= TRANSFER_ENCODING_NUM);

	val = vals[t];

	BUG_ON(!val);

	if (n < gen_vector[t].size) {
		fuzz_msg r = val[n];
		add_string(p, end, r.s);

		if (t == TRANSFER_ENCODING && n == 0) {
			is_chancked_body = true;
		}

		return r.inval;
	} else {
		char *v = *p;
		int len = n * 256;
		int r;

		if (n % INVALID_FIELD_PERIOD ||
		    is_only_valid) {
			if (gen_vector[t].max_val_len)
				len = gen_vector[t].max_val_len;
			add_rand_string(p, end, len,
				gen_vector[t].a_val);
			r = FUZZ_VALID;
		} else {
			add_rand_string(p, end, len,
				gen_vector[t].a_inval);
			r = FUZZ_INVALID;
		}

		if (t == CONTENT_LENGTH && r == FUZZ_VALID) {
			strncpy(content_length, v, len);
			content_length[len] = '\0';
		} else {
			content_length[0] = '\0';
		}

		return r;
	}
}

static int
add_field(char **p, char *end, int t)
{
	return __add_field(p, end, t, gen_vector[t].i);
}

static int
__add_header(char **p, char *end, int t, int n)
{
	int v = 0, i;
	char *key;

	BUG_ON(t < 0);
	BUG_ON(t >= TRANSFER_ENCODING_NUM);

	key = keys[t];

	BUG_ON(!key);

	add_string(p, end, key);
	v |= add_field(p, end, SPACES);
	v |= add_field(p, end, t);
	for (i = 0; i < n; ++i) {
		addch(p, end, ',');
		v |= add_field(p, end, SPACES);
		v |= __add_field(p, end, t, (i * 256) %
			(gen_vector[t].size + gen_vector[t].over));
	}

	add_string(p, end, "\r\n");

	return v;
}

static int
add_header(char **p, char *end, int t)
{
	return __add_header(p, end, t, 0);
}

#define INVALID_BODY_PERIOD 5

static int
add_body(char **p, char *end, int type)
{
	size_t len = 0, i, j;
	char *len_str;
	int err, ret = FUZZ_VALID;

	i = gen_vector[CONTENT_LENGTH].i;
	len_str = (i < gen_vector[CONTENT_LENGTH].size)? content_len[i].s:
							 content_length;

	err = kstrtoul(len_str, 10, &len);
	if (err) {
		return FUZZ_INVALID;
	}

	if (!is_chancked_body) {
		if (!is_only_valid &&
		    len != 0 && !(i % INVALID_BODY_PERIOD)) {
			len /= 2;
			ret = FUZZ_INVALID;
		}

		add_rand_string(p, end, len, a_body);
	}
	else {
		int chunks = gen_vector[BODY_CHUNKS_NUM].i + 1;
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

				if (!is_only_valid &&
				    step != 0 && !(i % INVALID_BODY_PERIOD)) {
					step /= 2;
					ret = FUZZ_INVALID;
				}

				add_rand_string(p, end, step, a_body);
				add_string(p, end, "\r\n");
			}
		}

		add_string(p, end, "0");
		add_string(p, end, "\r\n");
		add_string(p, end, "\r\n");
	}

	return ret;
}

#define DUPLICATES_PERIOD 10
#define MAX_DUPLICATES 9

static int curr_duplicates = 0;

static int
__add_duplicates(char **p, char *end, int t, int n)
{
	int i, tmp, v = FUZZ_VALID;

	if (curr_duplicates++ % DUPLICATES_PERIOD)
		return FUZZ_VALID;

	if (is_only_valid)
		return FUZZ_VALID;

	for (i = 0; i < curr_duplicates % MAX_DUPLICATES; ++i) {
		if (gen_vector[t].dissipation) {
			tmp = gen_vector[t].i;
			gen_vector[t].i = (gen_vector[t].i + i) % gen_vector[t].size;
		}

		v |= __add_header(p, end, t, n);

		if (gen_vector[t].dissipation) {
			gen_vector[t].i = tmp;
		}
	}

	if (gen_vector[t].singular && i > 0)
		return FUZZ_INVALID;

	return v;
}

static int
add_duplicates(char **p, char *end, int t)
{
	return __add_duplicates(p, end, t, 0);
}

/* Returns:
 * FUZZ_VALID if the result is a valid request,
 * FUZZ_INVALID if it's invalid,
 * FUZZ_END if the request sequence is over.
 * `move` is how many gen_vector's elements should be changed
 * each time a new request is generated, should be >= 1. */
int
fuzz_gen(char *str, char *end, field_t start, int move, int type)
{
	int i, n, ret = FUZZ_VALID, v = 0;

	if (str == NULL)
		return -EINVAL;

	if (type == FUZZ_REQ) {
		v |= add_field(&str, end, METHOD);
		addch(&str, end, ' ');

		v |= add_field(&str, end, URI_PATH_START);
		addch(&str, end, '/');
		v |= add_field(&str, end, HOST);
		for (i = 0; i < gen_vector[URI_PATH_DEPTH].i + 1; ++i) {
			addch(&str, end, '/');
			v |= add_field(&str, end, URI_FILE);
		}
		addch(&str, end, ' ');
	}

	add_string(&str, end, "HTTP/");
	v |= add_field(&str, end, HTTP_VER);

	if (type == FUZZ_RESP) {
		addch(&str, end, ' ');
		v |= add_field(&str, end, SPACES);
		v |= add_field(&str, end, RESP_CODE);
	}

	add_string(&str, end, "\r\n");

	if (type == FUZZ_REQ) {
		v |= add_header(&str, end, HOST);
		v |= add_duplicates(&str, end, HOST);

		v |= add_header(&str, end, ACCEPT);
		v |= add_duplicates(&str, end, ACCEPT);

		v |= add_header(&str, end, ACCEPT_LANGUAGE);
		v |= add_duplicates(&str, end, ACCEPT_LANGUAGE);

		v |= add_header(&str, end, ACCEPT_ENCODING);
		v |= add_duplicates(&str, end, ACCEPT_ENCODING);

		v |= add_header(&str, end, COOKIE);
		v |= add_duplicates(&str, end, COOKIE);

		v |= add_header(&str, end, X_FORWARDED_FOR);
		v |= add_duplicates(&str, end, X_FORWARDED_FOR);

		v |= add_header(&str, end, USER_AGENT);
		v |= add_duplicates(&str, end, USER_AGENT);
	}
	else if (type == FUZZ_RESP) {
		v |= add_header(&str, end, ACCEPT_RANGES);
		v |= add_duplicates(&str, end, ACCEPT_RANGES);

		v |= add_header(&str, end, SET_COOKIE);
		v |= add_duplicates(&str, end, SET_COOKIE);

		v |= add_header(&str, end, ETAG);
		v |= add_duplicates(&str, end, ETAG);

		v |= add_header(&str, end, SERVER);
		v |= add_duplicates(&str, end, SERVER);

		v |= add_header(&str, end, EXPIRES);
		v |= add_duplicates(&str, end, EXPIRES);
	}

	v |= add_header(&str, end, CONNECTION);
	v |= add_duplicates(&str, end, CONNECTION);

	v |= add_header(&str, end, CONTENT_TYPE);
	v |= add_duplicates(&str, end, CONTENT_TYPE);

	v |= add_header(&str, end, CONTENT_LENGTH);
	v |= add_duplicates(&str, end, CONTENT_LENGTH);

	n = gen_vector[TRANSFER_ENCODING_NUM].i;
	v |= __add_header(&str, end, TRANSFER_ENCODING, n);
	v |= __add_duplicates(&str, end, TRANSFER_ENCODING, n);

	v |= add_header(&str, end, CACHE_CONTROL);
	v |= add_duplicates(&str, end, CACHE_CONTROL);

	add_string(&str, end, "\r\n");

	v |= add_body(&str, end, type);

	if (str < end) {
		*str = '\0';
	} else {
		v = FUZZ_INVALID;
		*(end - 1) = '\0';
	}

	for (i = 0; i < move; i++) {
		ret = gen_vector_move(start);
		if (ret == FUZZ_END)
			break;
	}

	if (v & FUZZ_INVALID)
		return FUZZ_INVALID;
	return ret;
}
EXPORT_SYMBOL(fuzz_gen);

void
fuzz_reset(void)
{
	int i;
	for (i = 0; i < N_FIELDS; i++)
	{
		gen_vector[i].i = 0;
	}

	curr_duplicates = 0;
}
EXPORT_SYMBOL(fuzz_reset);

void
fuzz_set_only_valid_gen(bool value)
{
	is_only_valid = value;
}
EXPORT_SYMBOL(fuzz_set_only_valid_gen);
