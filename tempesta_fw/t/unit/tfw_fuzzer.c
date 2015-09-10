#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "tfw_fuzzer.h"

struct fuzz_msg {
	char *s;
	int inval; /* 0 - valid, 1 - invalid */
};

static struct fuzz_msg methods[] = {{"GET", 0}, {"HEAD", 0}, {"POST", 0},
	{NULL, }};
static struct fuzz_msg uri_path_start[] = {{"http:/", 0}, {"https:/", 0},
	{"", 0}, {NULL, }};
static struct fuzz_msg uri_file[] = {{"file.html", 0}, {"f-i_l.e", 0},
	{"fi%20le", 0}, {"xn--80aaxtnfh0b", 0}, {NULL, }};
static struct fuzz_msg versions[] = {{"1.0", 0}, {"1.1", 0}, {"0.9", 1},
	{NULL, }}; // HTTP/0.9 is blocked
static struct fuzz_msg resp_code[] = {{"100 Continue", 0}, {"200 OK", 0},
	{"302 Found", 0}, {"304 Not Modified", 0}, {"400 Bad Request", 0},
	{"403 Forbidden", 0}, {"404 Not Found", 0},
	{"500 Internal Server Error", 0}, {NULL, }};
static struct fuzz_msg conn_val[] = {{"keep-alive", 0}, {"close", 0},
	{"upgrade", 0}, {NULL, }};
static struct fuzz_msg ua_val[] = {{"Wget/1.13.4 (linux-gnu)", 0},
	{"Mozilla/5.0", 0}, {NULL, }};
static struct fuzz_msg hosts[] = {{"localhost", 0}, {"127.0.0.1", 0},
	{"example.com", 0}, {"xn--80aacbuczbw9a6a.xn--p1ai", 0}, {NULL, }};
static struct fuzz_msg content_type[] = {{"text/html;charset=utf-8", 0},
	{"image/jpeg", 0}, {"text/plain", 0}, {NULL, }};
static struct fuzz_msg content_length[] = {{"0", 0}, {"10", 1}, {"-42", 1},
	{"146", 1}, {"0100", 1}, {"100500", 1}, {NULL, }};
static struct fuzz_msg transfer_encoding[] = {{"chunked", 0}, {"identity", 0},
	{"compress", 0}, {"deflate", 0}, {"gzip", 0}, {NULL, }};

#define A_URI "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!*'();:@&=+$,/?%#[]"
#define A_URI_INVAL "`\\\03\023\07\r"
#define A_USER_AGENT A_URI
#define A_USER_AGENT_INVAL A_URI_INVAL
#define A_HOST "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-[]:"
#define A_HOST_INVAL "\\`~!*'();@&=+$,/?%#\03\023\07\r"
#define A_X_FORWARDED_FOR A_HOST
#define A_X_FORWARDED_FOR_INVAL A_HOST_INVAL

static const char *a_body = "ABCxyz013\r\n\t-_.~!*'();:@&=+$,/?%#[]\n\r\023\07\013\014\x89\x90\xa0\xc0";

static struct {
	int i;
	int max;
	char *a_val;
	char *a_inval;
	int singular; /* only for headers; 0 - nonsingular, 1 - singular */
} gen_vector[] = {
	/* METHOD */
	{0, sizeof(methods) / sizeof(struct fuzz_msg) - 1, "", NULL},
	/* SPACES */
	{1, 6, "", NULL},
	/* HTTP_VER */
	{0, sizeof(versions) / sizeof(struct fuzz_msg) - 1, "", NULL},
	/* RESP_CODE */
	{0, sizeof(resp_code) / sizeof(struct fuzz_msg) - 1, "", NULL},
	/* URI_PATH_START */
	{0, sizeof(uri_path_start) / sizeof(struct fuzz_msg) - 1, "", NULL},
	/* URI_PATH_DEPTH */
	{1, 3, "", NULL},
	/* URI_FILE */
	{0, sizeof(uri_file) / sizeof(struct fuzz_msg) - 1, A_URI, NULL},
	/* CONNECTION */
	{0, sizeof(conn_val) / sizeof(struct fuzz_msg) - 1, "", NULL, 1},
	/* USER_AGENT*/
	{0, sizeof(ua_val) / sizeof(struct fuzz_msg) - 1, A_USER_AGENT,
		A_USER_AGENT_INVAL, 1},
	/* HOST */
	{0, sizeof(hosts) / sizeof(struct fuzz_msg) - 1, A_HOST,
		A_HOST_INVAL, 1},
	/* X_FORWARDED_FOR */
	{0, sizeof(hosts) / sizeof(struct fuzz_msg) - 1, A_X_FORWARDED_FOR,
		A_X_FORWARDED_FOR_INVAL, 0},
	/* CONTENT_TYPE */
	{0, sizeof(content_type) / sizeof(struct fuzz_msg) - 1, "", NULL, 1},
	/* CONTENT_LENGTH */
	{0, sizeof(content_length) / sizeof(struct fuzz_msg) - 1, "0123456789",
		NULL, 1},
	/* TRANSFER_ENCODING */
	{0, sizeof(transfer_encoding) / sizeof(struct fuzz_msg) - 1, "", NULL, 0},
	/* TRANSFER_ENCODING_NUM */
	{0, 5, "", NULL},
	/* DUPLICATES */
	{0, 3, "", NULL},
	/* BODY_SIZE */
	{0, 10, "", NULL}
};

enum {
	METHOD,
	SPACES,
	HTTP_VER,
	RESP_CODE,
	URI_PATH_START,
	URI_PATH_DEPTH,
	URI_FILE,
	CONNECTION,
	USER_AGENT,
	HOST,
	X_FORWARDED_FOR,
	CONTENT_TYPE,
	CONTENT_LENGTH,
	TRANSFER_ENCODING,
	TRANSFER_ENCODING_NUM,
	DUPLICATES,
	BODY_SIZE,
	N_FIELDS
};

static int gen_vector_move(int i)
{
	if (gen_vector[i].i++ == gen_vector[i].max) {
		if (i == 0)
			return FUZZ_END;
		gen_vector[i].i = 0;
		if (gen_vector_move(i - 1) == FUZZ_END)
			return FUZZ_END;
	}

	return FUZZ_VALID;
}

static char *addch(char *s1, char ch)
{
	size_t len;

	if (!ch)
		return s1;
	len = strlen(s1);
	s1[len] = ch;
	s1[len + 1] = '\0';

	return s1;
}

static char *add_string(char *s1, int i, char *seed)
{
	int j;

	if (seed == NULL)
		seed = "\03\r\023\07";
	if (!strlen(seed))
		return s1;

	for (j = 0; j < i; ++j)
		addch(s1, seed[((j + 333) ^ seed[j]) % sizeof(seed)]);

	return s1;
}

static char *add_spaces(char *s1)
{
	int i;

	for (i = 0; i < gen_vector[SPACES].i; ++i) {
		if (i % 2)
			addch(s1, '\t');
		else if (i % 3)
			addch(s1, '\r');
		else
			addch(s1, ' ');
	}

	return s1;
}

static int add_method(char *s1)
{
	struct fuzz_msg r = methods[gen_vector[METHOD].i];

	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, gen_vector[METHOD].i,
				   gen_vector[METHOD].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, gen_vector[METHOD].i,
				   gen_vector[METHOD].a_inval);
	}

	return FUZZ_INVALID;
}

static int add_uri_path_start(char *s1)
{
	struct fuzz_msg r = uri_path_start[gen_vector[URI_PATH_START].i];

	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, gen_vector[URI_PATH_START].i,
				   gen_vector[URI_PATH_START].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, gen_vector[URI_PATH_START].i,
				   gen_vector[URI_PATH_START].a_inval);
	}

	return 1;
}

static int add_uri_file(char *s1)
{
	struct fuzz_msg r = uri_file[gen_vector[URI_FILE].i];

	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, gen_vector[URI_FILE].i,
				   gen_vector[URI_FILE].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, gen_vector[URI_FILE].i,
				   gen_vector[URI_FILE].a_inval);
	}

	return FUZZ_INVALID;
}

static int add_http_ver(char *s1)
{
	struct fuzz_msg r = versions[gen_vector[HTTP_VER].i];

	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, gen_vector[HTTP_VER].i,
				   gen_vector[HTTP_VER].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, gen_vector[HTTP_VER].i,
				   gen_vector[HTTP_VER].a_inval);
	}

	return FUZZ_INVALID;
}

static int add_resp_code(char *s1)
{
	struct fuzz_msg r = resp_code[gen_vector[RESP_CODE].i];

	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, gen_vector[RESP_CODE].i,
				   gen_vector[RESP_CODE].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, gen_vector[RESP_CODE].i,
				   gen_vector[RESP_CODE].a_inval);
	}

	return FUZZ_INVALID;
}

static int add_connection(char *s1)
{
	struct fuzz_msg r = conn_val[gen_vector[CONNECTION].i];

	strcat(s1, "Connection:");
	add_spaces(s1);
	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, gen_vector[CONNECTION].i,
				   gen_vector[CONNECTION].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, gen_vector[CONNECTION].i,
				   gen_vector[CONNECTION].a_inval);
	}

	return FUZZ_INVALID;
}

static int add_user_agent(char *s1)
{
	struct fuzz_msg r = ua_val[gen_vector[USER_AGENT].i];

	strcat(s1, "User-agent:");
	add_spaces(s1);
	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, gen_vector[USER_AGENT].i,
				   gen_vector[USER_AGENT].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, gen_vector[USER_AGENT].i,
				   gen_vector[USER_AGENT].a_inval);
	}

	return FUZZ_INVALID;
}

static int add_host(char *s1)
{
	struct fuzz_msg r = hosts[gen_vector[HOST].i];

	strcat(s1, "Host:");
	add_spaces(s1);
	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, gen_vector[HOST].i,
				   gen_vector[HOST].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, gen_vector[HOST].i,
				   gen_vector[HOST].a_inval);
	}

	return FUZZ_INVALID;
}

static int add_x_forwarded_for(char *s1)
{
	struct fuzz_msg r = hosts[gen_vector[X_FORWARDED_FOR].i];

	strcat(s1, "X-Forwarded-For:");
	add_spaces(s1);
	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, gen_vector[X_FORWARDED_FOR].i,
				   gen_vector[X_FORWARDED_FOR].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, gen_vector[X_FORWARDED_FOR].i,
				   gen_vector[X_FORWARDED_FOR].a_inval);
	}

	return FUZZ_INVALID;
}

static int add_content_type(char *s1)
{
	struct fuzz_msg r = content_type[gen_vector[CONTENT_TYPE].i];

	strcat(s1, "Content-Type:");
	add_spaces(s1);
	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, gen_vector[CONTENT_TYPE].i,
				   gen_vector[CONTENT_TYPE].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, gen_vector[CONTENT_TYPE].i,
				   gen_vector[CONTENT_TYPE].a_inval);
	}

	return FUZZ_INVALID;
}

static int add_content_length(char *s1)
{
	struct fuzz_msg r = content_length[gen_vector[CONTENT_LENGTH].i];

	strcat(s1, "Content-Length:");
	add_spaces(s1);
	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else
		add_string(s1, gen_vector[CONTENT_LENGTH].i, NULL);

	return FUZZ_INVALID;
}

static int __add_transfer_encoding(char *s1, int n)
{
	struct fuzz_msg r = transfer_encoding[n];

	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else {
		if (gen_vector[CONTENT_LENGTH].i % 2) {
			add_string(s1, n, gen_vector[n].a_val);
			return FUZZ_VALID;
		} else
			add_string(s1, n, gen_vector[n].a_inval);
	}

	return FUZZ_INVALID;
}

static int add_transfer_encoding(char *s1)
{
	int v = 0, i;

	strcat(s1, "Transfer-Encoding:");
	add_spaces(s1);
	v |= __add_transfer_encoding(s1, gen_vector[TRANSFER_ENCODING].i);
	for (i = 0; i < gen_vector[TRANSFER_ENCODING_NUM].i; ++i) {
		addch(s1, ',');
		add_spaces(s1);
		v |= __add_transfer_encoding(s1,
				(i + gen_vector[CONTENT_LENGTH].i) %
				gen_vector[TRANSFER_ENCODING].max);
	}

	return v;
}

static int add_body(char *s1, int type)
{
	size_t len = strlen(s1), cont_len,
	       i, body_size = gen_vector[BODY_SIZE].i * 256;
	char *rc;
	int err;

	for (i = 0; i < body_size; ++i)
		s1[len + i] = a_body[((i + gen_vector[CONTENT_LENGTH].i +
				       gen_vector[BODY_SIZE].i + len) ^
				       (a_body[i] + len)) % sizeof(a_body)];

	err = kstrtoul(content_length[gen_vector[CONTENT_LENGTH].i].s,
			10, &cont_len);
	if (err)
		return FUZZ_INVALID;
	if (cont_len > body_size)
		return FUZZ_INVALID;
	if (type == FUZZ_REQ)
		return FUZZ_VALID;

	rc = resp_code[gen_vector[RESP_CODE].i].s;
	if (!strstr(rc, "100") || !strstr(rc, "101") || !strstr(rc, "102") ||
			!strstr(rc, "204") || !strstr(rc, "304"))
		return FUZZ_INVALID;

	return FUZZ_VALID;
}

static int add_duplicates(char *s1, int n, int(*add_func)(char *s1))
{
	int i, tmp, v = 0;

	for (i = 0; i < gen_vector[DUPLICATES].i; ++i) {
		tmp = gen_vector[n].i;

		gen_vector[n].i = (i + gen_vector[n].i +
				   gen_vector[SPACES].i) %
				  gen_vector[n].max;
		v |= (*add_func)(s1);
		strcat(s1, "\r\n");
		gen_vector[n].i = tmp;
	}

	if (gen_vector[n].singular && i > 0)
		return FUZZ_INVALID;
	return v;
}

/* Returns:
 * FUZZ_VALID if the result is a valid request,
 * FUZZ_INVALID if it's invalid,
 * FUZZ_END if the request sequence is over.
 * `move` is how many gen_vector's elements should be changed
 * each time a new request is generated, should be >= 1. */
int fuzz_gen(char *str, int move, int type)
{
	int i, ret, v = 0;

	if (str == NULL)
		return -EINVAL;
	if (move < 1)
		return -EINVAL;
	*str = '\0';

	if (type == FUZZ_REQ) {
		v |= add_method(str);
		add_spaces(str);

		add_uri_path_start(str);
		if (!gen_vector[URI_PATH_DEPTH].i)
			addch(str, '/');
		for (i = 0; i < gen_vector[URI_PATH_DEPTH].i; ++i) {
			addch(str, '/');
			v |= add_uri_file(str);
		}
		add_spaces(str);
	}

	strcat(str, "HTTP/");
	v |= add_http_ver(str);
	if (type == FUZZ_RESP) {
		add_spaces(str);
		v |= add_resp_code(str);
	}
	strcat(str, "\r\n");

	v |= add_connection(str);
	strcat(str, "\r\n");
	v |= add_duplicates(str, CONNECTION, &add_connection);

	v |= add_user_agent(str);
	strcat(str, "\r\n");
	v |= add_duplicates(str, USER_AGENT, &add_user_agent);

	v |= add_host(str);
	strcat(str, "\r\n");
	v |= add_duplicates(str, HOST, &add_host);

	v |= add_x_forwarded_for(str);
	strcat(str, "\r\n");
	v |= add_duplicates(str, X_FORWARDED_FOR, &add_x_forwarded_for);

	v |= add_content_type(str);
	strcat(str, "\r\n");
	v |= add_duplicates(str, CONTENT_TYPE, &add_content_type);

	v |= add_content_length(str);
	strcat(str, "\r\n");
	v |= add_duplicates(str, CONTENT_LENGTH, &add_content_length);

	v |= add_transfer_encoding(str);
	strcat(str, "\r\n");
	v |= add_duplicates(str, TRANSFER_ENCODING, &add_transfer_encoding);

	strcat(str, "\r\n");

	v |= add_body(str, type);

	for (i = 0; i < move; i++) {
		ret = gen_vector_move((N_FIELDS - 1 + i * ((i % 2) ? 3 : 2)) % N_FIELDS);
		if (ret == FUZZ_END)
			break;
	}
	if (v & FUZZ_INVALID)
		return FUZZ_INVALID;
	return ret;
}
EXPORT_SYMBOL(fuzz_gen);
