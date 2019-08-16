/**
 *		Tempesta FW
 *
 * Copyright (C) 2019 Tempesta Technologies, Inc.
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


#include "hpack.c"

#include "test.h"
#include "helpers.h"
#include "tfw_str_helper.h"

#define HDR_COMPOUND_STR(hdr_res, nm, val)			\
({								\
	TfwStr *c;						\
	hdr_res = tfw_pool_alloc(str_pool, sizeof(TfwStr));	\
	BUG_ON(!hdr_res);					\
	*(hdr_res) = *TFW_STR_CHUNK(nm, 0);			\
	if ((c = TFW_STR_CHUNK(nm, 1))) {			\
		TfwStr nm_fin = {				\
			.chunks = c,				\
			.len = (nm)->len - (hdr_res)->len,	\
			.nchunks = (nm)->nchunks - 1		\
		};						\
		collect_compound_str(hdr_res, &nm_fin);		\
	}							\
	collect_compound_str2(hdr_res, ":", 1);			\
	collect_compound_str(hdr_res, val);			\
})

#define HDR_COMPOUND_STR_LIT(hdr_res, nm_lit, val_lit)		\
do {								\
	TFW_STR(name, nm_lit);					\
	TFW_STR(value, val_lit);				\
	BUG_ON(!name || !value);				\
	HP_HDR_COMPOUND_STR(hdr_res, name, value);		\
} while (0)

static TfwH2Ctx ctx;
static TfwHttpReq *test_req;

static inline TfwHttpReq *
test_hpack_req_alloc(void)
{
	TfwHttpReq *req = test_req_alloc(0);

	BUG_ON(!req);
	req->pit.pool = __tfw_pool_new(0);
	BUG_ON(!req->pit.pool);
	req->pit.hdr = &req->stream->parser.hdr;
	__set_bit(TFW_HTTP_B_H2, req->flags);

	return req;
}

static void
test_h2_setup(void)
{
	int r;

	create_str_pool();
	r = tfw_h2_context_init(&ctx);
	BUG_ON(r);
	test_req = test_hpack_req_alloc();
}

static void
test_h2_teardown(void)
{
	test_req_free(test_req);
	tfw_h2_context_clear(&ctx);
	free_all_str();
}

TEST(hpack, dec_table_static)
{
	TfwHPack *hp;
	const TfwHPackEntry *entry;
	TfwHPackStr *name, *value;

	hp = &ctx.hpack;

	entry = tfw_hpack_find_index(&hp->dec_tbl, 43);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		EXPECT_EQ(strlen("if-unmodified-since"), name->len);
		EXPECT_OK(memcmp_fast("if-unmodified-since", name->ptr,
				      name->len));
		EXPECT_NULL(entry->value);
		EXPECT_EQ(entry->tag, TFW_HTTP_HDR_RAW);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 61);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		EXPECT_EQ(strlen("www-authenticate"), name->len);
		EXPECT_OK(memcmp_fast("www-authenticate", name->ptr,
				      name->len));
		EXPECT_NULL(entry->value);
		EXPECT_EQ(entry->tag, TFW_HTTP_HDR_RAW);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 1);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		EXPECT_EQ(strlen(":authority"), name->len);
		EXPECT_OK(memcmp_fast(":authority", name->ptr, name->len));
		EXPECT_NULL(entry->value);
		EXPECT_EQ(entry->tag, TFW_HTTP_HDR_RAW);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 16);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		value = entry->value;
		EXPECT_EQ(strlen("accept-encoding"), name->len);
		EXPECT_OK(memcmp_fast("accept-encoding", name->ptr, name->len));
		EXPECT_OK(memcmp_fast("gzip, deflate", value->ptr, value->len));
		EXPECT_EQ(entry->tag, TFW_HTTP_HDR_RAW);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 57);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		EXPECT_EQ(strlen("transfer-encoding"), name->len);
		EXPECT_OK(memcmp_fast("transfer-encoding", name->ptr,
				      name->len));
		EXPECT_NULL(entry->value);
		EXPECT_EQ(entry->tag, TFW_HTTP_HDR_TRANSFER_ENCODING);
	}
}

TEST(hpack, dec_table_dynamic)
{
	TfwHPack *hp;
	TfwMsgParseIter it;
	const TfwHPackEntry *entry;
	TfwStr *s1, *s2, *s3;
	TfwHPackStr *name, *value;
	unsigned int new_len = 0;
	TFW_STR(s1_name, "custom-key");
	TFW_STR(s1_value, "custom-value");
	TFW_STR(s2_name, "X-Forwarded-For");
	TFW_STR(s2_value, "example.com");
	TFW_STR(s3_name, "X-Custom-Hdr");
	TFW_STR(s3_value, "custom header values");

	HDR_COMPOUND_STR(s1, s1_name, s1_value);
	HDR_COMPOUND_STR(s2, s2_name, s2_value);
	HDR_COMPOUND_STR(s3, s3_name, s3_value);

	hp = &ctx.hpack;

	it.hdr = s1;
	it.nm_len = 10;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, NULL, &it));

	it.hdr = s2;
	it.nm_len = 15;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, NULL, &it));

	it.hdr = s3;
	it.nm_len = 12;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, NULL, &it));

	entry = tfw_hpack_find_index(&hp->dec_tbl, 64);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		value = entry->value;
		EXPECT_TRUE(tfw_str_eq_cstr(s1_name, name->ptr, name->len, 0));
		EXPECT_TRUE(tfw_str_eq_cstr(s1_value, value->ptr,
					    value->len, 0));
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		value = entry->value;
		EXPECT_TRUE(tfw_str_eq_cstr(s2_name, name->ptr, name->len, 0));
		EXPECT_TRUE(tfw_str_eq_cstr(s2_value, value->ptr,
					    value->len, 0));
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 62);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		value = entry->value;
		new_len += name->len + value->len + 32;
		EXPECT_TRUE(tfw_str_eq_cstr(s3_name, name->ptr, name->len, 0));
		EXPECT_TRUE(tfw_str_eq_cstr(s3_value, value->ptr,
					    value->len, 0));
	}

	EXPECT_OK(tfw_hpack_set_length(hp, new_len));

	EXPECT_NULL(tfw_hpack_find_index(&hp->dec_tbl, 64));
	EXPECT_NULL(tfw_hpack_find_index(&hp->dec_tbl, 63));
	EXPECT_NOT_NULL(tfw_hpack_find_index(&hp->dec_tbl, 62));
}

TEST(hpack, dec_table_mixed)
{
	TfwHPack *hp;
	TfwMsgParseIter it;
	TfwHPackStr *name, *value;
	TfwStr *s1, *s2, *s3, *s4, *s5;
	const TfwHPackEntry *entry, *entry_1, *entry_2, *entry_3;
	TFW_STR(s1_name, "custom-header-1");
	TFW_STR(s1_value, "custom value 1");
	TFW_STR(s2_name, "custom-header-2");
	TFW_STR(s2_value, "custom value 2");
	TFW_STR(s3_name, "cache-control");
	TFW_STR(s3_value, "max-age=7, private");
	TFW_STR(s4_value, "custom value 4");
	TFW_STR(s5_value, "custom value 5");

	HDR_COMPOUND_STR(s1, s1_name, s1_value);
	HDR_COMPOUND_STR(s2, s2_name, s2_value);
	HDR_COMPOUND_STR(s3, s3_name, s3_value);
	HDR_COMPOUND_STR(s4, s1_name, s4_value);
	HDR_COMPOUND_STR(s5, s2_name, s5_value);

	hp = &ctx.hpack;

	it.hdr = s1;
	it.nm_len = s1_name->len;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, NULL, &it));

	it.hdr = s2;
	it.nm_len = s2_name->len;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, NULL, &it));

	entry_1 = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry_1);
	if (entry_1) {
		name = entry_1->name;
		value = entry_1->value;
		it.hdr = s4;
		it.nm_len = s1_name->len;
		EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, entry_1, &it));
	}

	entry_2 = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry_2);
	if (entry_2) {
		name = entry_2->name;
		value = entry_2->value;
		it.hdr = s5;
		it.nm_len = s2_name->len;
		EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, entry_2, &it));
	}

	entry_3 = tfw_hpack_find_index(&hp->dec_tbl, 24);
	EXPECT_NOT_NULL(entry_3);
	if (entry_3) {
		it.hdr = s3;
		it.nm_len = s3_name->len;
		EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, entry_3, &it));
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 64);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		/*
		 * Check that entries with 66 and 64 indexes use the same
		 * dynamic @name instance.
		 */
		EXPECT_EQ(entry_1->name, entry->name);
		EXPECT_EQ(entry->name->count, 2);
		EXPECT_EQ(entry->value->count, 1);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		/*
		 * Check that entries with 65 and 63 indexes use the same
		 * dynamic @name instance.
		 */
		EXPECT_EQ(entry_2->name, entry->name);
		EXPECT_EQ(entry->name->count, 2);
		EXPECT_EQ(entry->value->count, 1);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 62);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		/*
		 * Check that entries with 62 and 24(static) indexes use the
		 * same static @name instance.
		 */
		EXPECT_EQ(entry_3->name, entry->name);
		EXPECT_EQ(entry->name->count, -1);
		EXPECT_EQ(entry->value->count, 1);
	}
}

TEST(hpack, dec_table_wrap)
{
	int shift;
	TfwHPack *hp = &ctx.hpack;
	TFW_STR(s_value, "custom value");

	for (shift = 0; shift < 14; ++shift) {
		TfwMsgParseIter it;
		TfwHPackEntry *last_entries;
		const TfwHPackEntry *entries, *entry;
		int i, start_idx = 17, stop_idx = start_idx + shift + 1;
		int cont_idx = stop_idx, end_idx = cont_idx + 31;
		unsigned int lentries_size = shift * sizeof(TfwHPackEntry);
		TfwStr *s = NULL;

		last_entries = tfw_pool_alloc(str_pool, lentries_size);
		BUG_ON(!last_entries);
		bzero_fast(last_entries, lentries_size);

	fill_table:
		/*
		 * To completely fill the dynamic table (up to 32 entries - the
		 * initial dynamic table length), find indexes in static table
		 * add insert found entries with dummy custom value into dynamic
		 * table.
		 */
		for (i = start_idx; i < stop_idx; ++i) {
			TfwStr s_name = {};
			TfwHPackStr *name;

			entry = tfw_hpack_find_index(&hp->dec_tbl, i);
			EXPECT_NOT_NULL(entry);

			if (i >= end_idx - shift)
				last_entries[i - (end_idx - shift)] = *entry;

			EXPECT_NULL(entry->value);
			name = entry->name;
			s_name.len = name->len;
			s_name.data = name->ptr;
			HDR_COMPOUND_STR(s, &s_name, s_value);

			it.hdr = s;
			it.nm_len = s_name.len;

			EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, NULL, &it));

		}

		if (i < end_idx) {
			/*
			 * Evict first @shift entries, i.e shrink table to only
			 * one existing entry.
			 */
			EXPECT_OK(tfw_hpack_set_length(hp, s->len - 1 + 32));
			EXPECT_OK(tfw_hpack_set_length(hp,
						       HPACK_TABLE_DEF_SIZE));

			start_idx = cont_idx;
			stop_idx = end_idx;

			goto fill_table;
		}

		EXPECT_EQ(hp->dec_tbl.length, 32);
		EXPECT_EQ(hp->dec_tbl.n, 32);

		/*
		 * Verify that the last added @shift entries are wrapped, i.e
		 * placed in the beginning of dynamic table.
		 */
		entries = hp->dec_tbl.entries;
		for (i = 0; i < shift; ++i) {
			const TfwHPackEntry *l_entry = &last_entries[i];
			const TfwHPackEntry *t_entry = &entries[i];

			EXPECT_NOT_NULL(l_entry->name);
			if (l_entry->name) {
				EXPECT_EQ(l_entry->name->len,
					  t_entry->name->len);
				EXPECT_OK(memcmp_fast(l_entry->name->ptr,
						      t_entry->name->ptr,
						      t_entry->name->len));
			}
		}

		tfw_h2_context_clear(&ctx);
		BUG_ON(tfw_h2_context_init(&ctx));
	}
}

TEST(hpack, dec_raw)
{
	int r;
	TfwHPack *hp;
	const char *pos;
	TfwMsgParseIter *it;
	unsigned int parsed;
	unsigned long test_len1, test_len2, test_len3;

	const char *test_data1 = "custom-key:custom-value\r\n";
	unsigned long hdr_len1 = 25;
	const char *hdr_data1 =
		"\x40"			/* == With indexing ==		*/
		"\x0A"			/* Literal name (len = 10)	*/
		"\x63\x75\x73\x74\x6F"	/* custom-key			*/
		"\x6D\x2D\x6B\x65\x79"	/*				*/
		"\x0C"			/* Literal value (len = 12)	*/
		"\x63\x75\x73\x74\x6F"	/* custom-value	*/
		"\x6D\x2D\x76\x61\x6C"	/*				*/
		"\x75\x65";		/*				*/

	const char *test_data2 = "x-custom-hdr:test foo example value\r\n";
	unsigned long hdr_len2 = 37;
	const char *hdr_data2 =
		"\x00"			/* == Without indexing ==	*/
		"\x0C"			/* Literal name (len = 12)	*/
		"\x78\x2D\x63\x75\x73"	/* x-custom-hdr			*/
		"\x74\x6F\x6D\x2D\x68"	/*				*/
		"\x64\x72"		/*				*/
		"\x16"			/* Literal value (len = 22)	*/
		"\x74\x65\x73\x74\x20"	/* test foo example value	*/
		"\x66\x6F\x6F\x20\x65"	/*				*/
		"\x78\x61\x6D\x70\x6C"	/*				*/
		"\x65\x20\x76\x61\x6C"	/*				*/
		"\x75\x65";		/*				*/

	const char *test_data3 = "x-forwarded-for: 127.0.0.1, example.com\r\n";
	unsigned long hdr_len3 = 41;
	const char *hdr_data3 =
		"\x10"			/* == Never indexing ==	*/
		"\x0F"			/* Literal name (len = 15)	*/
		"\x78\x2D\x66\x6F\x72"	/* x-forwarded-for		*/
		"\x77\x61\x72\x64\x65"	/*				*/
		"\x64\x2D\x66\x6F\x72"	/*				*/
		"\x17"			/* Literal value (len = 23)	*/
		"\x20\x31\x32\x37\x2E"	/*  127.0.0.1, example.com	*/
		"\x30\x2E\x30\x2E\x31"	/*				*/
		"\x2C\x20\x65\x78\x61"	/*				*/
		"\x6D\x70\x6C\x65\x2E"	/*				*/
		"\x63\x6F\x6D";		/*				*/

	hp = &ctx.hpack;
	it = &test_req->pit;

	test_len1 = strlen(test_data1);
	test_len2 = strlen(test_data2);
	test_len3 = strlen(test_data3);

	r = tfw_hpack_decode(hp, hdr_data1, hdr_len1, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len1);

	r = tfw_hpack_decode(hp, hdr_data2, hdr_len2, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len2);

	r = tfw_hpack_decode(hp, hdr_data3, hdr_len3, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len3);

	pos = it->start_pos;
	EXPECT_OK(memcmp_fast(pos, test_data1, test_len1));

	pos += test_len1;
	EXPECT_OK(memcmp_fast(pos, test_data2, test_len2));

	pos += test_len2;
	EXPECT_OK(memcmp_fast(pos, test_data3, test_len3));
}

TEST(hpack, dec_indexed)
{
	int r;
	TfwHPack *hp;
	const char *pos;
	TfwMsgParseIter *it;
	unsigned int parsed;
	const TfwHPackEntry *entry;
	const TfwHPackStr *name, *value;

	const char *test_data1 = "x-forwarded-for: test.com, foo.com,"
		" example.com\r\n";
	const char *test_data2 = "accept-encoding:gzip, deflate\r\n";
	const char *test_data3 = "accept-encoding:deflate, gzip;q=1.0,"
		" *;q=0.5\r\n";
	const char *test_data4 = "x-forwarded-for:127.0.0.1\r\n";
	const char *test_data5 = "host:localhost\r\n";
	const char *test_data6 = "transfer-encoding:chunked\r\n";
	unsigned long test_len1 = strlen(test_data1);
	unsigned long test_len2 = strlen(test_data2);
	unsigned long test_len3 = strlen(test_data3);
	unsigned long test_len4 = strlen(test_data4);
	unsigned long test_len5 = strlen(test_data5);
	unsigned long test_len6 = strlen(test_data6);

	unsigned long hdr_len1 = 49;
	const char *hdr_data1 =
		"\x40"			/* == With indexing ==		*/
		"\x0F"			/* Literal name (len = 15)	*/
		"\x78\x2D\x66\x6F\x72"	/* x-forwarded-for		*/
		"\x77\x61\x72\x64\x65"	/*				*/
		"\x64\x2D\x66\x6F\x72"	/*				*/
		"\x1F"			/* Literal value (len = 31)	*/
		"\x20\x74\x65\x73\x74"	/*  test.com, foo.com, example.com */
		"\x2E\x63\x6F\x6D\x2C"	/*				*/
		"\x20\x66\x6F\x6F\x2E"	/*				*/
		"\x63\x6F\x6d\x2C\x20"	/*				*/
		"\x65\x78\x61\x6D\x70"	/*				*/
		"\x6C\x65\x2E\x63\x6F"	/*				*/
		"\x6D";			/*				*/

	unsigned long hdr_len2 = 1;
	const char *hdr_data2 = "\xBE";	/* == Indexed (dynamic: 62) ==	*/

	unsigned long hdr_len3 = 1;
	const char *hdr_data3 = "\x90";	/* == Indexed (static: 16) ==	*/

	unsigned long hdr_len4 = 30;
	const char *hdr_data4 =
		"\x50"			/* == With indexing ==		*/
					/* (name indexed - static: 16)	*/
		"\x1C"			/* Literal value (len = 28)	*/
		"\x64\x65\x66\x6C\x61"	/* deflate, gzip;q=1.0, *;q=0.5	*/
		"\x74\x65\x2C\x20\x67"	/*				*/
		"\x7A\x69\x70\x3B\x71"	/*				*/
		"\x3D\x31\x2E\x30\x2C"	/*				*/
		"\x20\x2A\x3B\x71\x3D"	/*				*/
		"\x30\x2E\x35";		/*				*/

	unsigned long hdr_len5 = 12;
	const char *hdr_data5 =
		"\x7F\x00"		/* == With indexing ==		*/
					/* (name indexed - dynamic: 63)	*/
					/* (multibyte integer encoding) */
					/*				*/
		"\x09"			/* Literal value (len = 9)	*/
		"\x31\x32\x37\x2E\x30"	/* 127.0.0.1			*/
		"\x2E\x30\x2E\x31";	/*				*/

	unsigned long hdr_len6 = 12;
	const char *hdr_data6 =
		"\x0F\x17"		/* == Without indexing ==	*/
					/* (name indexed - static: 38)	*/
					/* (multibyte integer encoding) */
					/*				*/
		"\x09"			/* Literal value (len = 9)	*/
		"\x6C\x6F\x63\x61\x6C"	/* localhost			*/
		"\x68\x6F\x73\x74";	/*				*/

	unsigned long hdr_len7 = 10;
	const char *hdr_data7 =
		"\x0F\x2A"		/* == Without indexing ==	*/
					/* (name indexed - static: 57)	*/
					/* (multibyte integer encoding) */
					/*				*/
		"\x07"			/* Literal value (len = 7)	*/
		"\x63\x68\x75\x6E\x6B"	/* chunked			*/
		"\x65\x64";		/*				*/

	hp = &ctx.hpack;
	it = &test_req->pit;

	/*
	 * Processing prepared HTTP/2 headers in HPACK decoding
	 * procedure.
	 */
	r = tfw_hpack_decode(hp, hdr_data1, hdr_len1, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len1);

	r = tfw_hpack_decode(hp, hdr_data2, hdr_len2, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len2);

	r = tfw_hpack_decode(hp, hdr_data3, hdr_len3, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len3);

	r = tfw_hpack_decode(hp, hdr_data4, hdr_len4, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len4);

	r = tfw_hpack_decode(hp, hdr_data5, hdr_len5, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len5);

	r = tfw_hpack_decode(hp, hdr_data6, hdr_len6, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len6);

	r = tfw_hpack_decode(hp, hdr_data7, hdr_len7, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len7);

	/*
	 * Verify that decoded headers had been correctly written into
	 * the special target buffer.
	 */
	pos = it->start_pos;
	EXPECT_OK(memcmp_fast(pos, test_data1, test_len1));

	pos += test_len1;
	EXPECT_OK(memcmp_fast(pos, test_data1, test_len1));

	pos += test_len1;
	EXPECT_OK(memcmp_fast(pos, test_data2, test_len2));

	pos += test_len2;
	EXPECT_OK(memcmp_fast(pos, test_data3, test_len3));

	pos += test_len3;
	EXPECT_OK(memcmp_fast(pos, test_data4, test_len4));

	pos += test_len4;
	EXPECT_OK(memcmp_fast(pos, test_data5, test_len5));

	pos += test_len5;
	EXPECT_OK(memcmp_fast(pos, test_data6, test_len6));

	/*
	 * Verify that decoded headers had been placed into decoder index
	 * table with appropriate indexes. Note, that only three headers
	 * should be contained in the table, since @hdr_data2 and @hdr_data3
	 * are fully indexed headers (thus they hadn't been placed in the
	 * table during decoding), and @hdr_data6 as well as @hdr_data7
	 * have 'without indexing' code in the head part, which means they
	 * hadn't been indexed too.
	 */
	entry = tfw_hpack_find_index(&hp->dec_tbl, 64);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		value = entry->value;
		EXPECT_EQ(strlen("x-forwarded-for"), name->len);
		EXPECT_OK(memcmp_fast(test_data1, name->ptr, name->len));
		EXPECT_EQ(strlen(" test.com, foo.com, example.com"),
			  value->len);
		EXPECT_OK(memcmp_fast(test_data1 + 15 + 1, value->ptr,
				      value->len));
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		value = entry->value;
		EXPECT_EQ(strlen("accept-encoding"), name->len);
		EXPECT_OK(memcmp_fast(test_data3, name->ptr, name->len));
		EXPECT_EQ(strlen("deflate, gzip;q=1.0, *;q=0.5"), value->len);
		EXPECT_OK(memcmp_fast(test_data3 + 15 + 1, value->ptr,
				      value->len));
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 62);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		value = entry->value;
		EXPECT_EQ(strlen("x-forwarded-for"), name->len);
		EXPECT_OK(memcmp_fast(test_data4, name->ptr, name->len));
		EXPECT_EQ(strlen("127.0.0.1"), value->len);
		EXPECT_OK(memcmp_fast(test_data4 + 15 + 1, value->ptr,
				      value->len));
	}
}

TEST(hpack, dec_huffman)
{
	int r;
	TfwHPack *hp;
	const char *pos;
	TfwMsgParseIter *it;
	unsigned int parsed;
	const TfwHPackEntry *entry;
	const TfwHPackStr *name, *value;

	const char *test_data1 = "custom-key:custom-value\r\n";
	unsigned long test_len1 = strlen(test_data1);
	const char *test_data2 = "cache-control:no-cache\r\n";
	unsigned long test_len2 = strlen(test_data2);
	const char *test_data3 = ":authority:www.example.com\r\n";
	unsigned long test_len3 = strlen(test_data3);

	unsigned long hdr_len1 = 20;
	const char *hdr_data1 =
		"\x40"			/* == With indexing ==		*/
		"\x88"			/* Literal name (len = 8)	*/
					/* (Huffman encoded)		*/
		"\x25\xA8\x49\xE9\x5B"	/* custom-key			*/
		"\xA9\x7D\x7F"		/*				*/
					/*				*/
		"\x89"			/* Literal value (len = 9)	*/
					/* (Huffman encoded)		*/
		"\x25\xA8\x49\xE9\x5B"	/* custom-value			*/
		"\xB8\xE8\xB4\xBF";	/*				*/

	unsigned long hdr_len2 = 8;
	const char *hdr_data2 =
		"\x58"			/* == With indexing ==		*/
					/* (name indexed - static: 24)	*/
					/*				*/
		"\x86"			/* Literal value (len = 6)	*/
					/* (Huffman encoded)		*/
		"\xA8\xEB\x10\x64\x9C"	/* no-cache			*/
		"\xBF";			/*				*/

	unsigned long hdr_len3 = 14;
	const char *hdr_data3 =
		"\x41"			/* == With indexing ==		*/
					/* (name indexed - static: 1)	*/
					/*				*/
		"\x8C"			/* Literal value (len = 12)	*/
					/* (Huffman encoded)		*/
		"\xF1\xE3\xC2\xE5\xF2"	/* www.example.com		*/
		"\x3A\x6B\xA0\xAB\x90"	/*				*/
		"\xF4\xFF";		/*				*/

	hp = &ctx.hpack;
	it = &test_req->pit;

	r = tfw_hpack_decode(hp, hdr_data1, hdr_len1, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len1);

	r = tfw_hpack_decode(hp, hdr_data2, hdr_len2, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len2);

	r = tfw_hpack_decode(hp, hdr_data3, hdr_len3, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len3);

	pos = it->start_pos;
	EXPECT_OK(memcmp_fast(pos, test_data1, test_len1));

	pos += test_len1;
	EXPECT_OK(memcmp_fast(pos, test_data2, test_len2));

	pos += test_len2;
	EXPECT_OK(memcmp_fast(pos, test_data3, test_len3));

	entry = tfw_hpack_find_index(&hp->dec_tbl, 64);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		value = entry->value;
		EXPECT_EQ(strlen("custom-key"), name->len);
		EXPECT_OK(memcmp_fast(test_data1, name->ptr, name->len));
		EXPECT_EQ(strlen("custom-value"), value->len);
		EXPECT_OK(memcmp_fast(test_data1 + 10 + 1, value->ptr,
				      value->len));
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		value = entry->value;
		EXPECT_EQ(strlen("cache-control"), name->len);
		EXPECT_OK(memcmp_fast(test_data2, name->ptr, name->len));
		EXPECT_EQ(strlen("no-cache"), value->len);
		EXPECT_OK(memcmp_fast(test_data2 + 13 + 1, value->ptr,
				      value->len));
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 62);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		name = entry->name;
		value = entry->value;
		EXPECT_EQ(strlen(":authority"), name->len);
		EXPECT_OK(memcmp_fast(test_data3, name->ptr, name->len));
		EXPECT_EQ(strlen("www.example.com"), value->len);
		EXPECT_OK(memcmp_fast(test_data3 + 10 + 1, value->ptr,
				      value->len));
	}
}

TEST(hpack, enc_table_hdr_write)
{
	char *buf;
	unsigned long hdr_len, n_len = 0, v_off = 0, v_len = 0;

#define HDR_NAME_1	"x-forwarded-for"
#define HDR_VALUE_1	"test.com, foo.com, example.com"
#define HDR_NAME_2	"custom-header"
#define HDR_VALUE_2	"custom-value"
#define HDR_NAME_3	"X-Custom-Hdr"
#define HDR_VALUE_3	"example header value"
#define HDR_NAME_4	"custom-name"
#define HDR_VALUE_4	"custom-test-value"
#define HDR_NAME_5	"custom-key"
#define HDR_VALUE_5	"custom-example-value"

	TFW_STR(s1, HDR_NAME_1 ":   ");
	TFW_STR(s1_value, HDR_VALUE_1 "    ");
	unsigned long off1 = 4;
	const char *t_s1 = HDR_NAME_1 HDR_VALUE_1;
	unsigned long t_s1_len = strlen(t_s1);

	TFW_STR(s2, HDR_NAME_2 ":");
	TFW_STR(s2_value, HDR_VALUE_2);
	unsigned long off2 = 1;
	const char *t_s2 = HDR_NAME_2 HDR_VALUE_2;
	unsigned long t_s2_len = strlen(t_s2);

	TFW_STR(s3, HDR_NAME_3 ":\t  ");
	TFW_STR(s3_value, HDR_VALUE_3 "   ");
	unsigned long off3 = 4;
	const char *t_s3 = HDR_NAME_3 HDR_VALUE_3;
	unsigned long t_s3_len = strlen(t_s3);

	TFW_STR(s4, HDR_NAME_4 ":     ");
	TFW_STR(s4_value, HDR_VALUE_4 "\t\t   \t");
	unsigned long off4 = 6;
	const char *t_s4 = HDR_NAME_4 HDR_VALUE_4;
	unsigned long t_s4_len = strlen(t_s4);

	TFW_STR(s5, HDR_NAME_5 ":\t\t\t");
	TFW_STR(s5_value, HDR_VALUE_5 "\t\t\t\t");
	unsigned long off5 = 4;
	const char *t_s5 = HDR_NAME_5 HDR_VALUE_5;
	unsigned long t_s5_len = strlen(t_s5);

	collect_compound_str(s1, s1_value);
	collect_compound_str(s2, s2_value);
	collect_compound_str(s3, s3_value);
	collect_compound_str(s4, s4_value);
	collect_compound_str(s5, s5_value);

	hdr_len = tfw_http_msg_hdr_length(s1, &n_len, &v_off, &v_len);
	EXPECT_EQ(n_len, strlen(HDR_NAME_1));
	EXPECT_EQ(v_len, strlen(HDR_VALUE_1));
	EXPECT_EQ(v_off, off1);
	EXPECT_EQ(hdr_len, t_s1_len);
	buf = tfw_pool_alloc(str_pool, hdr_len);
	BUG_ON(!buf);
	tfw_http_msg_hdr_write(s1, n_len, v_off, v_len, buf);
	EXPECT_OK(memcmp_fast(t_s1, buf, hdr_len));

	n_len = v_off = v_len = 0;

	hdr_len = tfw_http_msg_hdr_length(s2, &n_len, &v_off, &v_len);
	EXPECT_EQ(n_len, strlen(HDR_NAME_2));
	EXPECT_EQ(v_len, strlen(HDR_VALUE_2));
	EXPECT_EQ(v_off, off2);
	EXPECT_EQ(hdr_len, t_s2_len);
	buf = tfw_pool_alloc(str_pool, hdr_len);
	BUG_ON(!buf);
	tfw_http_msg_hdr_write(s2, n_len, v_off, v_len, buf);
	EXPECT_OK(memcmp_fast(t_s2, buf, hdr_len));

	n_len = v_off = v_len = 0;

	hdr_len = tfw_http_msg_hdr_length(s3, &n_len, &v_off, &v_len);
	EXPECT_EQ(n_len, strlen(HDR_NAME_3));
	EXPECT_EQ(v_len, strlen(HDR_VALUE_3));
	EXPECT_EQ(v_off, off3);
	EXPECT_EQ(hdr_len, t_s3_len);
	buf = tfw_pool_alloc(str_pool, hdr_len);
	BUG_ON(!buf);
	tfw_http_msg_hdr_write(s3, n_len, v_off, v_len, buf);
	EXPECT_OK(memcmp_fast(t_s3, buf, hdr_len));

	n_len = v_off = v_len = 0;

	hdr_len = tfw_http_msg_hdr_length(s4, &n_len, &v_off, &v_len);
	EXPECT_EQ(n_len, strlen(HDR_NAME_4));
	EXPECT_EQ(v_len, strlen(HDR_VALUE_4));
	EXPECT_EQ(v_off, off4);
	EXPECT_EQ(hdr_len, t_s4_len);
	buf = tfw_pool_alloc(str_pool, hdr_len);
	BUG_ON(!buf);
	tfw_http_msg_hdr_write(s4, n_len, v_off, v_len, buf);
	EXPECT_OK(memcmp_fast(t_s4, buf, hdr_len));

	n_len = v_off = v_len = 0;

	hdr_len = tfw_http_msg_hdr_length(s5, &n_len, &v_off, &v_len);
	EXPECT_EQ(n_len, strlen(HDR_NAME_5));
	EXPECT_EQ(v_len, strlen(HDR_VALUE_5));
	EXPECT_EQ(v_off, off5);
	EXPECT_EQ(hdr_len, t_s5_len);
	buf = tfw_pool_alloc(str_pool, hdr_len);
	BUG_ON(!buf);
	tfw_http_msg_hdr_write(s5, n_len, v_off, v_len, buf);
	EXPECT_OK(memcmp_fast(t_s5, buf, hdr_len));

#undef HDR_NAME_1
#undef HDR_VALUE_1
#undef HDR_NAME_2
#undef HDR_VALUE_2
#undef HDR_NAME_3
#undef HDR_VALUE_3
#undef HDR_NAME_4
#undef HDR_VALUE_4
#undef HDR_NAME_5
#undef HDR_VALUE_5
}

TEST_SUITE(hpack)
{
	TEST_SETUP(test_h2_setup);
	TEST_TEARDOWN(test_h2_teardown);

	TEST_RUN(hpack, dec_table_static);
	TEST_RUN(hpack, dec_table_dynamic);
	TEST_RUN(hpack, dec_table_mixed);
	TEST_RUN(hpack, dec_table_wrap);
	TEST_RUN(hpack, dec_raw);
	TEST_RUN(hpack, dec_indexed);
	TEST_RUN(hpack, dec_huffman);
	TEST_RUN(hpack, enc_table_hdr_write);
}
