#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "tfw_fuzzer.h"

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
	size_t len;

	if (!ch)
		return s1;
	len = strlen(s1);
	s1[len] = ch;
	s1[len + 1] = '\0';

	return s1;
}

static char *add_string(char *s1, int i)
{
	char *seed = "aNx0\03\r\0234fddf";
	int j;

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
		else if (i % 5)
			addch(s1, '\n');
		else
			addch(s1, ' ');
	}

	return s1;
}

static char *add_method(char *s1)
{
	char *v = methods[gen_vector[METHOD].i];

	if (v) {
		strcat(s1, v);
		return 0;
	} else
		add_string(s1, gen_vector[METHOD].i);

	return 0;
}

static char *add_http_ver(char *s1)
{
	char *v = versions[gen_vector[HTTP_VER].i];

	if (v)
		strcat(s1, v);
	else
		add_string(s1, gen_vector[HTTP_VER].i);

	return s1;
}

static char *add_connection(char *s1)
{
	char *v = conn_val[gen_vector[CONNECTION].i];

	if (v)
		strcat(s1, v);
	else
		add_string(s1, gen_vector[CONNECTION].i);

	return s1;
}

static char *add_user_agent(char *s1)
{
	char *v = ua_val[gen_vector[USER_AGENT].i];

	if (v)
		strcat(s1, v);
	else
		add_string(s1, gen_vector[USER_AGENT].i);

	return s1;
}

static char *add_host(char *s1)
{
	char *v = hosts[gen_vector[HOST].i];

	if (v)
		strcat(s1, v);
	else
		add_string(s1, gen_vector[HOST].i);

	return s1;
}

static char *add_x_forwarded_for(char *s1)
{
	char *v = hosts[gen_vector[X_FORWARDED_FOR].i];

	if (v)
		strcat(s1, v);
	else
		add_string(s1, gen_vector[X_FORWARDED_FOR].i);

	return s1;
}

static char *add_content_type(char *s1)
{
	char *v = content_type[gen_vector[CONTENT_TYPE].i];

	if (v)
		strcat(s1, v);
	else
		add_string(s1, gen_vector[CONTENT_TYPE].i);

	return s1;
}

static char *add_content_length(char *s1)
{
	char *v = content_length[gen_vector[CONTENT_LENGTH].i];

	if (v)
		strcat(s1, v);
	else
		add_string(s1, gen_vector[CONTENT_LENGTH].i);

	return s1;
}

static char *add_transfer_encoding(char *s1, int n)
{
	char *v = transfer_encoding[n];

	if (v)
		strcat(s1, v);
	else
		add_string(s1, n);

	return s1;
}

/* Returns 1 if str is a valid request, -1 if it's invalid.
 * 0 if the request sequence is over. */
int fuzz_req(char *str)
{
	int i;

	BUG_ON(!str);
	*str = '\0';
	add_method(str);
	add_spaces(str);

	str = addch(str, gen_vector[URI_PATH_START].i ? '/' : 0);

	for (i = 0; i < gen_vector[URI_PATH_DEPTH].i; ++i) {
		str = addch(str, '/');
		add_spaces(str);
		add_string(str, gen_vector[URI_FILE].i);
	}

	add_spaces(str);
	str = strcat(str, "HTTP/");
	str = add_http_ver(str);
	str = strcat(str, "\r\n");

	str = strcat(str, "Connection:");
	add_spaces(str);
	str = add_connection(str);
	str = strcat(str, "\r\n");

	str = strcat(str, "User-agent:");
	add_spaces(str);
	str = add_user_agent(str);
	str = strcat(str, "\r\n");

	str = strcat(str, "Host:");
	add_spaces(str);
	str = add_host(str);
	str = strcat(str, "\r\n");

	str = strcat(str, "X-Forwarded-For:");
	add_spaces(str);
	str = add_x_forwarded_for(str);
	str = strcat(str, "\r\n");

	str = strcat(str, "Content-Type:");
	add_spaces(str);
	str = add_content_type(str);
	str = strcat(str, "\r\n");

	str = strcat(str, "Content-Length:");
	add_spaces(str);
	str = add_content_length(str);
	str = strcat(str, "\r\n");

	str = strcat(str, "Transfer-Encoding:");
	add_spaces(str);
	str = add_transfer_encoding(str, gen_vector[TRANSFER_ENCODING].i);
	for (i = 0; i < gen_vector[TRANSFER_ENCODING_NUM].i; ++i) {
		str = addch(str, ',');
		add_spaces(str);
		add_transfer_encoding(str,
				(i + gen_vector[CONTENT_LENGTH].i) %
				gen_vector[TRANSFER_ENCODING].max);
	}

	strcat(str, "\r\n\r\n");

	return gen_vector_move(N_FIELDS - 1);
}
EXPORT_SYMBOL(fuzz_req);
