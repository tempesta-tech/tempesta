#ifndef __TFW_FUZZER_H__
#define __TFW_FUZZER_H__

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

int fuzz_gen(char *str, char *end, field_t start, int move, int type);

void fuzz_reset(void);

void fuzz_set_only_valid_gen(bool value);

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
