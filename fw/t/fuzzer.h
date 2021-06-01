/**
 *		Tempesta FW
 *
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_FUZZER_H__
#define __TFW_FUZZER_H__

#define MAX_CONTENT_LENGTH_LEN 8

enum {
	FUZZ_VALID,
	FUZZ_INVALID,
	FUZZ_END
};

enum {
	FUZZ_REQ,
	FUZZ_RESP
};

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
	BODY_CHUNKS_NUM,
	N_FIELDS,
} field_t;

/*
 * @hdr_flags		- a flag for each header;
 * @fld_flags		- message and contents flags;
 */
typedef struct {
	int i[N_FIELDS];
	bool is_only_valid;
	char content_length[MAX_CONTENT_LENGTH_LEN + 1];
	int curr_duplicates;
	unsigned int hdr_flags;
	unsigned int fld_flags[N_FIELDS];
} TfwFuzzContext;

void fuzz_init(TfwFuzzContext *context, bool is_only_valid);

int fuzz_gen(TfwFuzzContext *context, char *str, char *end, field_t start,
	     int move, int type);

#endif /* __TFW_FUZZER_H__ */
