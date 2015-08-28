#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "tfw_fuzzer.h"

#define ADD(_d, _s)			\
{					\
	char *_tmp = _s;		\
	_d = addstr(_d, _tmp);		\
	kfree(_tmp);			\
}

static char *methods[] = {"GET", "HEAD", "POST", NULL};
static char *versions[] = {"0.9", "1.0", "1.1", NULL};
static char *conn_val[] = {"keep-alive", "close", "upgrade", NULL};
static char *ua_val[] = {"Wget/1.13.4 (linux-gnu)", "Mozilla/5.0", NULL};
static char *hosts[] = {"localhost", "127.0.0.1", "example.com", NULL};
static char *content_type[] = {"text/html;charset=utf-8", "image/jpeg", "text/plain", NULL};
static char *content_length[] = {"0", "10", "-42", "146", "0100", "100500", NULL};
static char *transfer_encoding[] = {"chunked", "identity", "compress", "deflate", "gzip", NULL};

static struct {
	int i;
	int max;
} gen_vector[] = {
	{0, 4},		/* METHOD */
	{0, 5},		/* SPACES */
	{0, 3},		/* HTTP_VER */
	{0, 1}, 	/* URI_PATH_START */
	{0, 1},		/* URI_PATH_DEPTH */
	{0, 1},		/* URI_FILE */
	{0, 4},		/* CONNECTION */
	{0, 3},		/* USER_AGENT*/
	{0, 4},		/* HOST */
	{0, 4},		/* X_FORWARDED_FOR */
	{0, 4},		/* CONTENT_TYPE */
	{0, 7},		/* CONTENT_LENGTH */
	{0, 6},		/* TRANSFER_ENCODING */
	{0, 5}		/* TRANSFER_ENCODING_NUM */
};

enum {
	METHOD,
	SPACES,
	HTTP_VER,
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
	if (++gen_vector[i].i == gen_vector[i].max) {
		if (i == 0)
			return 0;
		gen_vector[i].i = 0;
		if (!gen_vector_move(i - 1))
			return 0;
	}

	return 1;
}

static char *addch(char *s1, char ch)
{
	size_t len1 = strlen(s1);
	char *result;

	if (!ch)
		return s1;
	result = kmalloc(len1 + 2, GFP_KERNEL);
	strncpy(result, s1, len1);
	result[len1] = ch;
	result[len1 + 1] = '\0';
	kfree(s1);

	return result;
}

static char *addstr(char *s1, char *s2)
{
	char *result;

	result = kmalloc(strlen(s1) + strlen(s2) + 1, GFP_KERNEL);
	strcpy(result, s1);
	strcat(result, s2);
	kfree(s1);

	return result;
}

/* kfree `result` after use */
static char *string(int i)
{
	char *str = kmalloc(1, GFP_KERNEL);
	char *seed = "aNx0\03\r\0234fddf";
	int j;

	*str = '\0';
	for (j = 0; j < i; ++j) {
		str = addch(str, seed[((j + 333) ^ seed[j]) % sizeof(seed)]);
	}

	return str;
}

static char *spaces(void)
{
	char *str = kmalloc(2, GFP_KERNEL);
	int i;

	*str = '\0';

	for (i = 0; i <= gen_vector[SPACES].i; ++i) {
		if (i % 2)
			str = addch(str, '\t');
		else if (i % 3)
			str = addch(str, '\r');
		else if (i % 4)
			str = addch(str, '\n');
		else
			str = addch(str, ' ');
	}

	return str;
}

/* kfree `v` after use */
static char *__addhdr(char *s1, char *v)
{
	char *result = kmalloc(strlen(s1) + strlen(v) + 1, GFP_KERNEL);

	strcpy(result, s1);
	strcat(result, v);
	kfree(s1);

	return result;
}

static char *add_method(char *s1)
{
	char *result, *v = methods[gen_vector[METHOD].i];

	if (v)
		result = __addhdr(s1, v);
	else {
		v = string(gen_vector[METHOD].i);
		result = __addhdr(s1, v);
		kfree(v);
	}

	return result;
}

static char *add_http_ver(char *s1)
{
	char *result, *v = versions[gen_vector[HTTP_VER].i];

	if (v)
		result = __addhdr(s1, v);
	else {
		v = string(gen_vector[HTTP_VER].i);
		result = __addhdr(s1, v);
		kfree(v);
	}

	return result;
}

static char *add_connection(char *s1)
{
	char *result, *v = conn_val[gen_vector[CONNECTION].i];

	if (v)
		result = __addhdr(s1, v);
	else {
		v = string(gen_vector[CONNECTION].i);
		result = __addhdr(s1, v);
		kfree(v);
	}

	return result;
}

static char *add_user_agent(char *s1)
{
	char *result, *v = ua_val[gen_vector[USER_AGENT].i];

	if (v)
		result = __addhdr(s1, v);
	else {
		v = string(gen_vector[USER_AGENT].i);
		result = __addhdr(s1, v);
		kfree(v);
	}

	return result;
}

static char *add_host(char *s1)
{
	char *result, *v = hosts[gen_vector[HOST].i];

	if (v)
		result = __addhdr(s1, v);
	else {
		v = string(gen_vector[HOST].i);
		result = __addhdr(s1, v);
		kfree(v);
	}

	return result;
}

static char *add_x_forwarded_for(char *s1)
{
	char *result, *v = hosts[gen_vector[X_FORWARDED_FOR].i];

	if (v)
		result = __addhdr(s1, v);
	else {
		v = string(gen_vector[X_FORWARDED_FOR].i);
		result = __addhdr(s1, v);
		kfree(v);
	}

	return result;
}

static char *add_content_type(char *s1)
{
	char *result, *v = content_type[gen_vector[CONTENT_TYPE].i];

	if (v)
		result = __addhdr(s1, v);
	else {
		v = string(gen_vector[CONTENT_TYPE].i);
		result = __addhdr(s1, v);
		kfree(v);
	}

	return result;
}

static char *add_content_length(char *s1)
{
	char *result, *v = content_length[gen_vector[CONTENT_LENGTH].i];

	if (v)
		result = __addhdr(s1, v);
	else {
		v = string(gen_vector[CONTENT_LENGTH].i);
		result = __addhdr(s1, v);
		kfree(v);
	}

	return result;
}

static char *add_transfer_encoding(char *s1, int i)
{
	char *result, *v = transfer_encoding[gen_vector[i].i];

	if (v)
		result = __addhdr(s1, v);
	else {
		v = string(gen_vector[i].i);
		result = __addhdr(s1, v);
		kfree(v);
	}

	return result;
}

char *fuzz_req(void)
{
	char *str, *tmp;
	int i;

	str = kmalloc(1, GFP_KERNEL);
	*str = '\0';
	str = add_method(str);

	ADD(str, spaces());

	str = addch(str, gen_vector[URI_PATH_START].i ? '/' : 0);

	for (i = 0; i < gen_vector[URI_PATH_DEPTH].i; ++i) {
		str = addch(str, '/');
		ADD(str, spaces());
		tmp = string(gen_vector[URI_FILE].i);
		str = addstr(str, tmp);
		kfree(tmp);
	}

	ADD(str, spaces());
	str = addstr(str, "HTTP/");
	str = add_http_ver(str);
	str = addstr(str, "\r\n");

	str = addstr(str, "Connection:");
	ADD(str, spaces());
	str = add_connection(str);
	str = addstr(str, "\r\n");

	str = addstr(str, "User-agent:");
	ADD(str, spaces());
	str = add_user_agent(str);
	str = addstr(str, "\r\n");

	str = addstr(str, "Host:");
	ADD(str, spaces());
	str = add_host(str);
	str = addstr(str, "\r\n");

	str = addstr(str, "X-Forwarded-For:");
	ADD(str, spaces());
	str = add_x_forwarded_for(str);
	str = addstr(str, "\r\n");

	str = addstr(str, "Content-Type:");
	ADD(str, spaces());
	str = add_content_type(str);
	str = addstr(str, "\r\n");

	str = addstr(str, "Content-Length:");
	ADD(str, spaces());
	str = add_content_length(str);
	str = addstr(str, "\r\n");

	str = addstr(str, "Transfer-Encoding:");
	ADD(str, spaces());
	str = add_transfer_encoding(str, TRANSFER_ENCODING);
	for (i = 0; gen_vector[TRANSFER_ENCODING_NUM].i; ++i) {
		str = addch(str, ',');
		ADD(str, spaces());
		add_transfer_encoding(str,
				gen_vector[CONTENT_LENGTH].i %
				gen_vector[TRANSFER_ENCODING].max);
	}

	str = addstr(str, "\r\n\r\n");

	if (!gen_vector_move(N_FIELDS))
		return NULL;
	return str;
}
EXPORT_SYMBOL(fuzz_req);
