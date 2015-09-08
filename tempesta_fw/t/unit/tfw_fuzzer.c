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
static struct fuzz_msg resp_code[] = {{"200 OK", 0}, {"302 Found", 0},
	{"400 Bad Request", 0}, {"403 Forbidden", 0}, {"404 Not Found", 0},
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

static struct {
	int i;
	int max;
	char *a_val;
	char *a_inval;
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
	{0, sizeof(conn_val) / sizeof(struct fuzz_msg) - 1, "", NULL},
	/* USER_AGENT*/
	{0, sizeof(ua_val) / sizeof(struct fuzz_msg) - 1, A_USER_AGENT,
		A_USER_AGENT_INVAL},
	/* HOST */
	{0, sizeof(hosts) / sizeof(struct fuzz_msg) - 1, A_HOST, A_HOST_INVAL},
	/* X_FORWARDED_FOR */
	{0, sizeof(hosts) / sizeof(struct fuzz_msg) - 1, A_X_FORWARDED_FOR,
		A_X_FORWARDED_FOR_INVAL},
	/* CONTENT_TYPE */
	{0, sizeof(content_type) / sizeof(struct fuzz_msg) - 1, "", NULL},
	/* CONTENT_LENGTH */
	{0, sizeof(content_length) / sizeof(struct fuzz_msg) - 1, "0123456789", NULL},
	/* TRANSFER_ENCODING */
	{0, sizeof(transfer_encoding) / sizeof(struct fuzz_msg) - 1, "", NULL},
	/* TRANSFER_ENCODING_NUM */
	{0, 5, "", NULL},
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

	if (r.s) {
		strcat(s1, r.s);
		return r.inval;
	} else
		add_string(s1, gen_vector[CONTENT_LENGTH].i, NULL);

	return FUZZ_INVALID;
}

static int add_transfer_encoding(char *s1, int n)
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

	strcat(str, "Connection:");
	add_spaces(str);
	v |= add_connection(str);
	strcat(str, "\r\n");

	strcat(str, "User-agent:");
	add_spaces(str);
	v |= add_user_agent(str);
	strcat(str, "\r\n");

	strcat(str, "Host:");
	add_spaces(str);
	v |= add_host(str);
	strcat(str, "\r\n");

	strcat(str, "X-Forwarded-For:");
	add_spaces(str);
	v |= add_x_forwarded_for(str);
	strcat(str, "\r\n");

	strcat(str, "Content-Type:");
	add_spaces(str);
	v |= add_content_type(str);
	strcat(str, "\r\n");

	strcat(str, "Content-Length:");
	add_spaces(str);
	v |= add_content_length(str);
	strcat(str, "\r\n");

	strcat(str, "Transfer-Encoding:");
	add_spaces(str);
	v |= add_transfer_encoding(str, gen_vector[TRANSFER_ENCODING].i);
	for (i = 0; i < gen_vector[TRANSFER_ENCODING_NUM].i; ++i) {
		addch(str, ',');
		add_spaces(str);
		v |= add_transfer_encoding(str,
				(i + gen_vector[CONTENT_LENGTH].i) %
				gen_vector[TRANSFER_ENCODING].max);
	}

	strcat(str, "\r\n\r\n");

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
