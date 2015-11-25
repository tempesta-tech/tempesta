#ifndef __TFW_FUZZER_H__
#define __TFW_FUZZER_H__

#define MAX_CONTENT_LENGTH_LEN 8

typedef enum {
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
} field_t;

typedef struct {
	int i[N_FIELDS];
	bool is_only_valid;
	bool is_chancked_body;
	char content_length[MAX_CONTENT_LENGTH_LEN + 1];
	int curr_duplicates;
} TfwFuzzContext;

void fuzz_init(TfwFuzzContext *context, bool is_only_valid);

int fuzz_gen(TfwFuzzContext *context, char *str, char *end, field_t start,
	     int move, int type);

enum {
	FUZZ_VALID,
	FUZZ_INVALID,
	FUZZ_END
};

enum {
	FUZZ_REQ,
	FUZZ_RESP
};

#endif /* __TFW_FUZZER_H__ */
