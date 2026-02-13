/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2023 Tempesta Technologies, Inc.
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
#define tfw_connection_send(a, b) 0
#include "http_stream.c"
#include "http_stream_sched.c"
#include "http_frame.c"
#include "http.c"

int
tfw_http_websocket_upgrade(TfwSrvConn *srv_conn, TfwCliConn *cli_conn)
{
	(void)srv_conn;
	(void)cli_conn;
	return 0;
}

int tfw_ws_msg_process(TfwConn *conn, struct sk_buff *skb)
{
	(void)conn;
	(void)skb;
	return 0;
}

#include "test.h"
#include "helpers.h"
#include "tfw_str_helper.h"

#define HDR_METHOD_NM	":method"
#define HDR_METHOD_VAL	"GET"
#define HDR_SCHEME_NM	":scheme"
#define HDR_SCHEME_VAL	"https"
#define HDR_PATH_NM	":path"
#define HDR_PATH_VAL	"/"

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
		collect_compound_str(hdr_res, &nm_fin, 0);	\
	}							\
	collect_compound_str(hdr_res, val, TFW_STR_HDR_VALUE);	\
})

#define HDR_COMPOUND_STR_LIT(hdr_res, nm_lit, val_lit)		\
do {								\
	TFW_STR(name, nm_lit);					\
	TFW_STR(value, val_lit);				\
	BUG_ON(!name || !value);				\
	HDR_COMPOUND_STR(hdr_res, name, value);			\
} while (0)

static TfwH2Conn conn;
static TfwH2Ctx *ctx;
static TfwHttpReq *test_req;
static TfwCachedHeaderState dummy_cstate;

static inline TfwHttpReq *
test_hpack_req_alloc(void)
{
	TfwHttpReq *req = test_req_alloc(0);
	TfwHttpMsg *hmreq = (TfwHttpMsg *)req;

	BUG_ON(!req);
	req->pit.pool = __tfw_pool_new(0, tfw_http_msg_client(hmreq));
	BUG_ON(!req->pit.pool);
	req->pit.parsed_hdr = &req->stream->parser.hdr;
	__set_bit(TFW_HTTP_B_H2, req->flags);

	return req;
}

static void
test_h2_setup(void)
{
	int r;

	create_str_pool();
	conn.h2 = ctx = tfw_h2_context_alloc();
	BUG_ON(!ctx);
	r = tfw_h2_context_init(ctx, &conn);
	BUG_ON(r);
	test_req = test_hpack_req_alloc();
}

static void
test_h2_teardown(void)
{
	test_req_free(test_req);
	tfw_h2_context_clear(ctx);
	tfw_h2_context_free(ctx);
	conn.h2 = NULL;
	free_all_str();
}

static void
test_h2_hdr_name(TfwStr *hdr, TfwStr *out_name)
{
	const TfwStr *c, *end;

	if (unlikely(TFW_STR_EMPTY(hdr))) {
		TFW_STR_INIT(out_name);
		return;
	}

	BUG_ON(TFW_STR_DUP(hdr));
	BUG_ON(TFW_STR_EMPTY(hdr));

	*out_name = *hdr;

	if (unlikely(TFW_STR_PLAIN(hdr))) {
		WARN_ON_ONCE(hdr->flags & TFW_STR_HDR_VALUE);
		return;
	}

	TFW_STR_FOR_EACH_CHUNK(c, hdr, end) {
		if (c->flags & TFW_STR_HDR_VALUE) {
			out_name->len -= c->len;
			out_name->nchunks--;
		}
	}
}

/** Helper to validate rbtree invariants */
static int
validator_walk(TfwHPackETbl *tree, TfwHPackNode *n,
               int black_path_acc, int *black_path_len,
               const char *loc)
{
	int r = 0;
	TfwHPackNode *left, *right, *parent;

	if (!n)
		return 0;

	if (n->color != 0) {
		black_path_acc++;
	} else {
		parent = HPACK_NODE_COND(tree, n->parent);
		if (parent && parent->color == 0) {
			TEST_FAIL("Adjanced red nodes found @@ %s", loc);
			r = 1;
		}
	}
	
	left = HPACK_NODE_COND(tree, n->left);
	right = HPACK_NODE_COND(tree, n->right);

	if (!left && !right) {
		/* Leaf node */
		if (*black_path_len == -1) {
			*black_path_len = black_path_acc;
		} else if (black_path_acc != *black_path_len) {
			TEST_FAIL("Leaf nodes has different number of black"
			          " nodes in the path @@ %s", loc);
			r = 1;
		}
	} else {
		if (left && HPACK_NODE_COND(tree, left->parent) != n) {
			TEST_FAIL("Left node parent is broken @@ %s", loc);
			r = 1;
		}
		r |= validator_walk(tree, left, black_path_acc, black_path_len, loc);
		if (right && HPACK_NODE_COND(tree, right->parent) != n) {
			TEST_FAIL("Right node parent is broken @@ %s", loc);
			r = 1;
		}
		r |= validator_walk(tree, right, black_path_acc, black_path_len, loc);
	}

	return r;
}

/** Validate rbtree invariants:
 * 1. root node is always black
 * 2. no two red nodes are adjanced
 * 3. number of black nodes in the path of any leaf node is the same
 */
static bool
validate_rbtree_invariants(TfwHPackETbl *tree, const char *loc)
{
	bool valid = true;
	int black_path_len = -1;

	if (tree->root && tree->root->color == 0) {
		TEST_FAIL("Tree root is not black @@ %s", loc);
		valid = false;
	}

	valid = validator_walk(tree, tree->root, 0, &black_path_len, loc) == 0
		    && valid;

	return valid;
}

#define __STR_HELPER(x) #x
#define __STR__(x) __STR_HELPER(x)
#define __LOC__ __FILE__ __STR__(__LINE__)
#define rbt_validate(t) validate_rbtree_invariants(t, __LOC__);

TEST(hpack, dec_table_static)
{
	TfwHPack *hp;
	TfwStr *hdr, h_val;
	const TfwHPackEntry *entry;
	const char *s_ius = "if-unmodified-since";
	const int ius_len = strlen(s_ius);
	const char *s_wa = "www-authenticate";
	const int wa_len = strlen(s_wa);
	const char *s_auth = ":authority";
	const int auth_len = strlen(s_auth);
	const char *s_aenc = "accept-encoding";
	const int aenc_len = strlen(s_aenc);
	const char *s_aenc_v = "gzip, deflate";
	const int aenc_v_len = strlen(s_aenc_v);
	const char *s_tenc = "transfer-encoding";
	const int tenc_len = strlen(s_tenc);

	hp = &ctx->hpack;

	entry = tfw_hpack_find_index(&hp->dec_tbl, 43);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		EXPECT_EQ(hdr->nchunks, 1);
		EXPECT_EQ(ius_len, hdr->len);
		EXPECT_TRUE(tfw_str_eq_cstr(hdr, s_ius, ius_len, 0));
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_RAW);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 61);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		EXPECT_EQ(hdr->nchunks, 1);
		EXPECT_EQ(wa_len, hdr->len);
		EXPECT_TRUE(tfw_str_eq_cstr(hdr, s_wa, wa_len, 0));
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_RAW);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 1);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		EXPECT_EQ(hdr->nchunks, 1);
		EXPECT_EQ(auth_len, hdr->len);
		EXPECT_TRUE(tfw_str_eq_cstr(hdr, s_auth, auth_len, 0));
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_H2_AUTHORITY);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 16);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		EXPECT_EQ(hdr->nchunks, 2);
		EXPECT_EQ(aenc_len, entry->name_len);
		EXPECT_TRUE(tfw_str_eq_cstr(hdr, s_aenc, aenc_len,
					    TFW_STR_EQ_PREFIX));
		__h2_msg_hdr_val(hdr, &h_val);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_val, s_aenc_v, aenc_v_len, 0));
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_RAW);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 57);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		EXPECT_EQ(hdr->nchunks, 1);
		EXPECT_EQ(tenc_len, hdr->len);
		EXPECT_TRUE(tfw_str_eq_cstr(hdr, s_tenc, tenc_len, 0));
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_TRANSFER_ENCODING);
	}
}

TEST(hpack, dec_table_dynamic)
{
	TfwHPack *hp;
	const TfwHPackEntry *entry;
	TfwStr h_name, *s1, *s2, *s3;
	TfwMsgParseIter *it = &test_req->pit;
	unsigned int new_len = 0;
	TFW_STR(s1_name, "custom-key");
	TFW_STR(s1_value, "custom-value");
	TFW_STR(s2_name, "x-forwarded-for");
	TFW_STR(s2_value, "example.com");
	TFW_STR(s3_name, "x-custom-hdr");
	TFW_STR(s3_value, "custom header values");

	HDR_COMPOUND_STR(s1, s1_name, s1_value);
	HDR_COMPOUND_STR(s2, s2_name, s2_value);
	HDR_COMPOUND_STR(s3, s3_name, s3_value);

	hp = &ctx->hpack;

	test_h2_hdr_name(s1, &h_name);
	it->nm_num = h_name.nchunks;
	it->nm_len = h_name.len;
	it->tag = TFW_TAG_HDR_RAW;
	*it->parsed_hdr = *s1;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, it, &dummy_cstate));

	test_h2_hdr_name(s2, &h_name);
	it->nm_num = h_name.nchunks;
	it->nm_len = h_name.len;
	it->tag = TFW_TAG_HDR_X_FORWARDED_FOR;
	*it->parsed_hdr = *s2;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, it, &dummy_cstate));

	test_h2_hdr_name(s3, &h_name);
	it->nm_num = h_name.nchunks;
	it->nm_len = h_name.len;
	it->tag = TFW_TAG_HDR_RAW;
	*it->parsed_hdr = *s3;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, it, &dummy_cstate));

	entry = tfw_hpack_find_index(&hp->dec_tbl, 64);
	EXPECT_NOT_NULL(entry);
	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s1) == 0);

	entry = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry);
	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s2) == 0);

	entry = tfw_hpack_find_index(&hp->dec_tbl, 62);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		new_len += entry->hdr->len + 32;
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s3) == 0);
	}

	EXPECT_OK(tfw_hpack_set_length(hp, new_len));

	EXPECT_NULL(tfw_hpack_find_index(&hp->dec_tbl, 64));
	EXPECT_NULL(tfw_hpack_find_index(&hp->dec_tbl, 63));
	EXPECT_NOT_NULL(tfw_hpack_find_index(&hp->dec_tbl, 62));
}

TEST(hpack, dec_table_dynamic_inc)
{
	TfwHPack *hp;
	TfwStr h_name, *s1, *s2, *s3, *s4, *s5;
	const TfwHPackEntry *entry;
	TfwMsgParseIter *it = &test_req->pit;

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

	hp = &ctx->hpack;

	test_h2_hdr_name(s1, &h_name);
	it->nm_num = h_name.nchunks;
	it->nm_len = h_name.len;
	it->tag = TFW_TAG_HDR_RAW;
	*it->parsed_hdr = *s1;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, it, &dummy_cstate));

	test_h2_hdr_name(s2, &h_name);
	it->nm_num = h_name.nchunks;
	it->nm_len = h_name.len;
	it->tag = TFW_TAG_HDR_RAW;
	*it->parsed_hdr = *s2;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, it, &dummy_cstate));

	entry = tfw_hpack_find_index(&hp->dec_tbl, 62);
	EXPECT_NOT_NULL(entry);
	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s2) == 0);

	entry = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry);
	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s1) == 0);

	test_h2_hdr_name(s3, &h_name);
	it->nm_num = h_name.nchunks;
	it->nm_len = h_name.len;
	it->tag = TFW_TAG_HDR_CACHE_CONTROL;
	*it->parsed_hdr = *s3;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, it, &dummy_cstate));

	test_h2_hdr_name(s4, &h_name);
	it->nm_num = h_name.nchunks;
	it->nm_len = h_name.len;
	it->tag = TFW_TAG_HDR_RAW;
	*it->parsed_hdr = *s4;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, it, &dummy_cstate));

	entry = tfw_hpack_find_index(&hp->dec_tbl, 62);
	EXPECT_NOT_NULL(entry);
	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s4) == 0);

	entry = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry);
	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s3) == 0);

	test_h2_hdr_name(s5, &h_name);
	it->nm_num = h_name.nchunks;
	it->nm_len = h_name.len;
	it->tag = TFW_TAG_HDR_RAW;
	*it->parsed_hdr = *s5;
	EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, it, &dummy_cstate));

	/* Verify the correctness of the indexes order. */
	entry = tfw_hpack_find_index(&hp->dec_tbl, 66);
	EXPECT_NOT_NULL(entry);
	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s1) == 0);

	entry = tfw_hpack_find_index(&hp->dec_tbl, 65);
	EXPECT_NOT_NULL(entry);
	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s2) == 0);

	entry = tfw_hpack_find_index(&hp->dec_tbl, 64);
	EXPECT_NOT_NULL(entry);

	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s3) == 0);

	entry = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry);
	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s4) == 0);

	entry = tfw_hpack_find_index(&hp->dec_tbl, 62);
	EXPECT_NOT_NULL(entry);
	if (entry)
		EXPECT_TRUE(tfw_strcmp(entry->hdr, s5) == 0);
}

TEST(hpack, dec_table_wrap)
{
	int shift;
	TfwHPack *hp = &ctx->hpack;
	TfwMsgParseIter *it = &test_req->pit;
	TFW_STR(s_value, "custom value");

	for (shift = 0; shift < 14; ++shift) {
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
			TfwStr *hdr;

			entry = tfw_hpack_find_index(&hp->dec_tbl, i);
			EXPECT_NOT_NULL(entry);
			if (!entry)
				continue;

			if (i >= end_idx - shift)
				last_entries[i - (end_idx - shift)] = *entry;

			hdr = entry->hdr;
			EXPECT_EQ(hdr->nchunks, 1);
			HDR_COMPOUND_STR(s, hdr, s_value);

			*it->parsed_hdr = *s;
			EXPECT_OK(tfw_hpack_add_index(&hp->dec_tbl, it, &dummy_cstate));

		}

		if (i < end_idx) {
			unsigned long shrink_sz = s->len + HPACK_ENTRY_OVERHEAD;
			/*
			 * Evict first @shift entries, i.e shrink table to only
			 * one existing entry.
			 */
			EXPECT_OK(tfw_hpack_set_length(hp, shrink_sz));
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
			TfwStr h_name;
			const TfwHPackEntry *l_entry = &last_entries[i];
			const TfwHPackEntry *t_entry = &entries[i];

			EXPECT_NOT_NULL(l_entry->hdr);
			EXPECT_NOT_NULL(t_entry->hdr);
			if (l_entry->hdr) {
				test_h2_hdr_name(t_entry->hdr, &h_name);
				EXPECT_TRUE(tfw_strcmp(&h_name, l_entry->hdr) == 0);
			}
		}

		tfw_h2_context_clear(ctx);
		BUG_ON(tfw_h2_context_init(ctx, &conn));
	}
}

TEST(hpack, dec_raw)
{
	int r;
	TfwHPack *hp;
	TfwHttpHdrTbl *ht;
	TfwStr h_name, h_value;
	unsigned int parsed;

#define HDR_NAME_1	"custom-key"
#define HDR_VALUE_1	"custom-value"
#define HDR_NAME_2	"x-custom-hdr"
#define HDR_VALUE_2	"test foo example value"
#define HDR_NAME_3	"x-forwarded-for"
#define HDR_VALUE_3	" 127.0.0.1, example.com"

	const char *test_name1 = HDR_NAME_1;
	const char *test_value1 = HDR_VALUE_1;
	unsigned long hdr_len1 = 25;
	static char *hdr_data1 =
		"\x40"			/* == With indexing ==		*/
		"\x0A"			/* Literal name (len = 10)	*/
		"\x63\x75\x73\x74\x6F"	/* custom-key			*/
		"\x6D\x2D\x6B\x65\x79"	/*				*/
		"\x0C"			/* Literal value (len = 12)	*/
		"\x63\x75\x73\x74\x6F"	/* custom-value			*/
		"\x6D\x2D\x76\x61\x6C"	/*				*/
		"\x75\x65";		/*				*/


	const char *test_name2 = HDR_NAME_2;
	const char *test_value2 = HDR_VALUE_2;
	unsigned long hdr_len2 = 37;
	static char *hdr_data2 =
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


	const char *test_name3 = HDR_NAME_3;
	const char *test_value3 = HDR_VALUE_3;
	unsigned long hdr_len3 = 41;
	static char *hdr_data3 =
		"\x10"			/* == Never indexing ==		*/
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


	hp = &ctx->hpack;
	ht = test_req->h_tbl;

	/* Set mandatory pseudo-headers to pass checks in @H2_MSG_VERIFY(). */
	ht->tbl[TFW_HTTP_HDR_H2_METHOD] = TFW_STR_STRING(HDR_METHOD_NM);
	collect_compound_str2(&ht->tbl[TFW_HTTP_HDR_H2_METHOD], HDR_METHOD_VAL,
			      SLEN(HDR_METHOD_VAL), TFW_STR_HDR_VALUE);
	ht->tbl[TFW_HTTP_HDR_H2_SCHEME] = TFW_STR_STRING(HDR_SCHEME_NM);
	collect_compound_str2(&ht->tbl[TFW_HTTP_HDR_H2_SCHEME], HDR_SCHEME_VAL,
			      SLEN(HDR_SCHEME_VAL), TFW_STR_HDR_VALUE);
	ht->tbl[TFW_HTTP_HDR_H2_PATH] = TFW_STR_STRING(HDR_PATH_NM);
	collect_compound_str2(&ht->tbl[TFW_HTTP_HDR_H2_PATH], HDR_PATH_VAL,
			      SLEN(HDR_PATH_VAL), TFW_STR_HDR_VALUE);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data1, hdr_len1, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len1);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data2, hdr_len2, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len2);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data3, hdr_len3, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len3);

	/*
	 * Update pointer to headers table, since it had been enlarged and,
	 * as a result, relocated during decoding/parsing procedures.
	 */
	EXPECT_NE(ht, test_req->h_tbl);
	ht = test_req->h_tbl;

	test_h2_hdr_name(&ht->tbl[TFW_HTTP_HDR_RAW], &h_name);
	__h2_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_RAW], &h_value);
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
	if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
		EXPECT_EQ(strlen(test_name1), h_name.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name1,
					    strlen(test_name1), 0));
		EXPECT_EQ(strlen(test_value1), h_value.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value1,
					    strlen(test_value1), 0));
	}

	test_h2_hdr_name(&ht->tbl[TFW_HTTP_HDR_RAW + 1], &h_name);
	__h2_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_RAW + 1], &h_value);
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
	if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
		EXPECT_EQ(strlen(test_name2), h_name.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name2,
					    strlen(test_name2), 0));
		EXPECT_EQ(strlen(test_value2), h_value.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value2,
					    strlen(test_value2), 0));
	}

	test_h2_hdr_name(&ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR], &h_name);
	__h2_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR], &h_value);
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
	if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
		EXPECT_EQ(strlen(test_name3), h_name.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name3,
					    strlen(test_name3), 0));
		EXPECT_EQ(strlen(test_value3), h_value.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value3,
					    strlen(test_value3), 0));
	}

#undef HDR_NAME_1
#undef HDR_VALUE_1
#undef HDR_NAME_2
#undef HDR_VALUE_2
#undef HDR_NAME_3
#undef HDR_VALUE_3
}

TEST(hpack, dec_indexed)
{
	int r;
	TfwHPack *hp;
	TfwHttpHdrTbl *ht;
	unsigned int parsed;
	const TfwHPackEntry *entry;
	TfwStr h_name, h_value, *hdr, *dup;

#define HDR_NAME_1	"x-forwarded-for"
#define HDR_VALUE_1	" test.com, foo.com, example.com"
#define HDR_NAME_2	"accept-encoding"
#define HDR_VALUE_2	"gzip, deflate"
#define HDR_VALUE_3	"deflate, gzip;q=1.0, *;q=0.5"
#define HDR_VALUE_4	"127.0.0.1"
#define HDR_NAME_5	"host"
#define HDR_VALUE_5	"localhost"
#define HDR_NAME_6	"referer"
#define HDR_VALUE_6	"http://www.example.org/overview.html"

	const char *test_name1 = HDR_NAME_1;
	const char *test_value1 = HDR_VALUE_1;
	const char *test_name2 = HDR_NAME_2;
	const char *test_value2 = HDR_VALUE_2;
	const char *test_value3 = HDR_VALUE_3;
	const char *test_value4 = HDR_VALUE_4;
	const char *test_name5 = HDR_NAME_5;
	const char *test_value5 = HDR_VALUE_5;
	const char *test_name6 = HDR_NAME_6;
	const char *test_value6 = HDR_VALUE_6;

	unsigned long test_len_nm1 = strlen(test_name1);
	unsigned long test_len_val1 = strlen(test_value1);
	unsigned long test_len_nm2 = strlen(test_name2);
	unsigned long test_len_val2 = strlen(test_value2);
	unsigned long test_len_val3 = strlen(test_value3);
	unsigned long test_len_val4 = strlen(test_value4);
	unsigned long test_len_nm5 = strlen(test_name5);
	unsigned long test_len_val5 = strlen(test_value5);
	unsigned long test_len_nm6 = strlen(test_name6);
	unsigned long test_len_val6 = strlen(test_value6);

	unsigned long hdr_len1 = 49;
	char *hdr_data1 =
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
	char *hdr_data2 = "\xBE";	/* == Indexed (dynamic: 62) ==	*/

	unsigned long hdr_len3 = 1;
	char *hdr_data3 = "\x90";	/* == Indexed (static: 16) ==	*/

	unsigned long hdr_len4 = 30;
	char *hdr_data4 =
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
	char *hdr_data5 =
		"\x7F\x00"		/* == With indexing ==		*/
					/* (name indexed - dynamic: 63)	*/
					/* (multibyte integer encoding) */
					/*				*/
		"\x09"			/* Literal value (len = 9)	*/
		"\x31\x32\x37\x2E\x30"	/* 127.0.0.1			*/
		"\x2E\x30\x2E\x31";	/*				*/

	unsigned long hdr_len6 = 12;
	char *hdr_data6 =
		"\x0F\x17"		/* == Without indexing ==	*/
					/* (name indexed - static: 38)	*/
					/* (multibyte integer encoding) */
					/*				*/
		"\x09"			/* Literal value (len = 9)	*/
		"\x6C\x6F\x63\x61\x6C"	/* localhost			*/
		"\x68\x6F\x73\x74";	/*				*/

	unsigned long hdr_len7 = 39;
	char *hdr_data7 =
		"\x0F\x24"		/* == Without indexing ==	*/
					/* (name indexed - static: 51)	*/
					/* (multibyte integer encoding) */
					/*				*/
		"\x24"			/* Literal value (len = 36)	*/
		"\x68\x74\x74\x70\x3A"	/* http://www.example.org/...	*/
		"\x2F\x2F\x77\x77\x77"	/* ...overview.html		*/
		"\x2E\x65\x78\x61\x6D"	/*				*/
		"\x70\x6C\x65\x2E\x6F"	/*				*/
		"\x72\x67\x2F\x6F\x76"	/*				*/
		"\x65\x72\x76\x69\x65"	/*				*/
		"\x77\x2E\x68\x74\x6D"	/*				*/
		"\x6C";			/*				*/

	hp = &ctx->hpack;
	ht = test_req->h_tbl;

	/* Set mandatory pseudo-headers to pass checks in @H2_MSG_VERIFY(). */
	ht->tbl[TFW_HTTP_HDR_H2_METHOD] = TFW_STR_STRING(HDR_METHOD_NM);
	collect_compound_str2(&ht->tbl[TFW_HTTP_HDR_H2_METHOD], HDR_METHOD_VAL,
			      SLEN(HDR_METHOD_VAL), TFW_STR_HDR_VALUE);
	ht->tbl[TFW_HTTP_HDR_H2_SCHEME] = TFW_STR_STRING(HDR_SCHEME_NM);
	collect_compound_str2(&ht->tbl[TFW_HTTP_HDR_H2_SCHEME], HDR_SCHEME_VAL,
			      SLEN(HDR_SCHEME_VAL), TFW_STR_HDR_VALUE);
	ht->tbl[TFW_HTTP_HDR_H2_PATH] = TFW_STR_STRING(HDR_PATH_NM);
	collect_compound_str2(&ht->tbl[TFW_HTTP_HDR_H2_PATH], HDR_PATH_VAL,
			      SLEN(HDR_PATH_VAL), TFW_STR_HDR_VALUE);

	/*
	 * Processing prepared HTTP/2 headers in HPACK decoding
	 * procedure.
	 */
	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data1, hdr_len1, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len1);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data2, hdr_len2, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len2);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data3, hdr_len3, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len3);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data4, hdr_len4, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len4);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data5, hdr_len5, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len5);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data6, hdr_len6, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len6);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data7, hdr_len7, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len7);

	EXPECT_EQ(ht, test_req->h_tbl);

	/*
	 * Verify that decoded headers had been correctly written into
	 * the headers table.
	 */
	hdr = &ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
	EXPECT_TRUE(TFW_STR_DUP(hdr));
	EXPECT_EQ(hdr->nchunks, 3);
	if (hdr->nchunks == 3) {
		dup = hdr->chunks;
		test_h2_hdr_name(dup, &h_name);
		__h2_msg_hdr_val(dup, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm1, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name1,
						    test_len_nm1, 0));
			EXPECT_EQ(test_len_val1, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value1,
						    test_len_val1, 0));
		}
		dup = hdr->chunks + 1;
		test_h2_hdr_name(dup, &h_name);
		__h2_msg_hdr_val(dup, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm1, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name1,
						    test_len_nm1, 0));
			EXPECT_EQ(test_len_val1, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value1,
						    test_len_val1, 0));
		}
		dup = hdr->chunks + 2;
		test_h2_hdr_name(dup, &h_name);
		__h2_msg_hdr_val(dup, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm1, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name1,
						    test_len_nm1, 0));
			EXPECT_EQ(test_len_val4, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value4,
						    test_len_val4, 0));
		}
	}

	hdr = &ht->tbl[TFW_HTTP_HDR_RAW];
	EXPECT_TRUE(TFW_STR_DUP(hdr));
	EXPECT_EQ(hdr->nchunks, 2);
	if (hdr->nchunks == 2) {
		dup = hdr->chunks;
		test_h2_hdr_name(dup, &h_name);
		__h2_msg_hdr_val(dup, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm2, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name2,
						    test_len_nm2, 0));
			EXPECT_EQ(test_len_val2, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value2,
						    test_len_val2, 0));
		}
		dup = hdr->chunks + 1;
		test_h2_hdr_name(dup, &h_name);
		__h2_msg_hdr_val(dup, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm2, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name2,
						    test_len_nm2, 0));
			EXPECT_EQ(test_len_val3, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value3,
						    test_len_val3, 0));
		}
	}

	hdr = &ht->tbl[TFW_HTTP_HDR_HOST];
	test_h2_hdr_name(hdr, &h_name);
	__h2_msg_hdr_val(hdr, &h_value);
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
	if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
		EXPECT_EQ(test_len_nm5, h_name.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name5,
					    test_len_nm5, 0));
		EXPECT_EQ(test_len_val5, h_value.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value5,
					    test_len_val5, 0));
	}

	hdr = &ht->tbl[TFW_HTTP_HDR_REFERER];
	test_h2_hdr_name(hdr, &h_name);
	__h2_msg_hdr_val(hdr, &h_value);
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
	if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
		EXPECT_EQ(test_len_nm6, h_name.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name6,
					    test_len_nm6, 0));
		EXPECT_EQ(test_len_val6, h_value.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value6,
					    test_len_val6, 0));
	}

	/*
	 * Verify that decoded headers had been placed into decoder index
	 * table with appropriate indexes. Note, that only three headers
	 * should be contained in the table, since @hdr_data2 and @hdr_data3
	 * are fully indexed headers (thus they hadn't been placed in the
	 * table during decoding), and @hdr_data6 as well as @hdr_data7
	 * have 'without indexing' code in the head part, which means they
	 * hadn't been indexed too.
	 */
	entry = tfw_hpack_find_index(&hp->dec_tbl, 65);
	EXPECT_NULL(entry);

	entry = tfw_hpack_find_index(&hp->dec_tbl, 64);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		test_h2_hdr_name(hdr, &h_name);
		__h2_msg_hdr_val(hdr, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm1, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name1,
						    test_len_nm1, 0));
			EXPECT_EQ(test_len_val1, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value1,
						    test_len_val1, 0));
		}
		EXPECT_EQ(entry->name_len, test_len_nm1);
		EXPECT_EQ(entry->name_num, h_name.nchunks);
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_X_FORWARDED_FOR);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		test_h2_hdr_name(hdr, &h_name);
		__h2_msg_hdr_val(hdr, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm2, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name2,
						    test_len_nm2, 0));
			EXPECT_EQ(test_len_val3, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value3,
						    test_len_val3, 0));
		}
		EXPECT_EQ(entry->name_len, test_len_nm2);
		EXPECT_EQ(entry->name_num, h_name.nchunks);
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_RAW);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 62);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		test_h2_hdr_name(hdr, &h_name);
		__h2_msg_hdr_val(hdr, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm1, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name1,
						    test_len_nm1, 0));
			EXPECT_EQ(test_len_val4, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value4,
						    test_len_val4, 0));
		}
		EXPECT_EQ(entry->name_len, test_len_nm1);
		EXPECT_EQ(entry->name_num, h_name.nchunks);
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_X_FORWARDED_FOR);
	}

#undef HDR_NAME_1
#undef HDR_VALUE_1
#undef HDR_NAME_2
#undef HDR_VALUE_2
#undef HDR_VALUE_3
#undef HDR_VALUE_4
#undef HDR_NAME_5
#undef HDR_VALUE_5
#undef HDR_NAME_6
#undef HDR_VALUE_6
}

TEST(hpack, dec_huffman)
{
	int r;
	TfwHPack *hp;
	TfwHttpHdrTbl *ht;
	unsigned int parsed;
	const TfwHPackEntry *entry;
	TfwStr h_name, h_value, *hdr;

#define HDR_NAME_1	"custom-key"
#define HDR_VALUE_1	"custom-value"
#define HDR_NAME_2	"cache-control"
#define HDR_VALUE_2	"no-cache"
#define HDR_NAME_3	":authority"
#define HDR_VALUE_3	"www.example.com"

	const char *test_name1 = HDR_NAME_1;
	const char *test_value1 = HDR_VALUE_1;
	const char *test_name2 = HDR_NAME_2;
	const char *test_value2 = HDR_VALUE_2;
	const char *test_name3 = HDR_NAME_3;
	const char *test_value3 = HDR_VALUE_3;

	unsigned long test_len_nm1 = strlen(test_name1);
	unsigned long test_len_val1 = strlen(test_value1);
	unsigned long test_len_nm2 = strlen(test_name2);
	unsigned long test_len_val2 = strlen(test_value2);
	unsigned long test_len_nm3 = strlen(test_name3);
	unsigned long test_len_val3 = strlen(test_value3);

	unsigned long hdr_len1 = 20;
	char *hdr_data1 =
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
	char *hdr_data2 =
		"\x58"			/* == With indexing ==		*/
					/* (name indexed - static: 24)	*/
					/*				*/
		"\x86"			/* Literal value (len = 6)	*/
					/* (Huffman encoded)		*/
		"\xA8\xEB\x10\x64\x9C"	/* no-cache			*/
		"\xBF";			/*				*/

	unsigned long hdr_len3 = 14;
	char *hdr_data3 =
		"\x41"			/* == With indexing ==		*/
					/* (name indexed - static: 1)	*/
					/*				*/
		"\x8C"			/* Literal value (len = 12)	*/
					/* (Huffman encoded)		*/
		"\xF1\xE3\xC2\xE5\xF2"	/* www.example.com		*/
		"\x3A\x6B\xA0\xAB\x90"	/*				*/
		"\xF4\xFF";		/*				*/

	hp = &ctx->hpack;
	ht = test_req->h_tbl;

	/* Set mandatory pseudo-headers to pass checks in @H2_MSG_VERIFY(). */
	ht->tbl[TFW_HTTP_HDR_H2_METHOD] = TFW_STR_STRING(HDR_METHOD_NM);
	collect_compound_str2(&ht->tbl[TFW_HTTP_HDR_H2_METHOD], HDR_METHOD_VAL,
			      SLEN(HDR_METHOD_VAL), TFW_STR_HDR_VALUE);
	ht->tbl[TFW_HTTP_HDR_H2_SCHEME] = TFW_STR_STRING(HDR_SCHEME_NM);
	collect_compound_str2(&ht->tbl[TFW_HTTP_HDR_H2_SCHEME], HDR_SCHEME_VAL,
			      SLEN(HDR_SCHEME_VAL), TFW_STR_HDR_VALUE);
	ht->tbl[TFW_HTTP_HDR_H2_PATH] = TFW_STR_STRING(HDR_PATH_NM);
	collect_compound_str2(&ht->tbl[TFW_HTTP_HDR_H2_PATH], HDR_PATH_VAL,
			      SLEN(HDR_PATH_VAL), TFW_STR_HDR_VALUE);

	/*
	 * Processing prepared Huffman-encoded HTTP/2 headers in HPACK
	 * decoding procedure.
	 *
	 * NOTE: the ':authority' pseudo-header should be processed first
	 * (with mandatory pseudo-headers) to pass the verification in
	 * @H2_MSG_VERIFY(), according to RFC.
	 */
	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data3, hdr_len3, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len3);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data1, hdr_len1, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len1);

	parsed = 0;
	r = tfw_hpack_decode(hp, hdr_data2, hdr_len2, test_req, &parsed);
	EXPECT_EQ(r, T_OK);
	EXPECT_EQ(parsed, hdr_len2);

	/*
	 * Update pointer to headers table, since it had been enlarged and,
	 * as a result, relocated during decoding/parsing procedures.
	 */
	EXPECT_NE(ht, test_req->h_tbl);
	ht = test_req->h_tbl;

	/*
	 * Verify that Huffman-decoded headers had been correctly written
	 * into the headers table.
	 */
	hdr = &ht->tbl[TFW_HTTP_HDR_H2_AUTHORITY];
	test_h2_hdr_name(hdr, &h_name);
	__h2_msg_hdr_val(hdr, &h_value);
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
	if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
		EXPECT_EQ(test_len_nm3, h_name.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name3,
					    test_len_nm3, 0));
		EXPECT_EQ(test_len_val3, h_value.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value3,
					    test_len_val3, 0));
	}

	hdr = &ht->tbl[TFW_HTTP_HDR_RAW];
	test_h2_hdr_name(hdr, &h_name);
	__h2_msg_hdr_val(hdr, &h_value);
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
	if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
		EXPECT_EQ(test_len_nm1, h_name.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name1,
					    test_len_nm1, 0));
		EXPECT_EQ(test_len_val1, h_value.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value1,
					    test_len_val1, 0));
	}

	hdr = &ht->tbl[TFW_HTTP_HDR_RAW + 1];
	test_h2_hdr_name(hdr, &h_name);
	__h2_msg_hdr_val(hdr, &h_value);
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
	EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
	if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
		EXPECT_EQ(test_len_nm2, h_name.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name2,
					    test_len_nm2, 0));
		EXPECT_EQ(test_len_val2, h_value.len);
		EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value2,
					    test_len_val2, 0));
	}

	/*
	 * Verify that Huffman-decoded headers had been correctly placed into
	 * decoder index table with appropriate indexes.
	 */
	entry = tfw_hpack_find_index(&hp->dec_tbl, 64);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		test_h2_hdr_name(hdr, &h_name);
		__h2_msg_hdr_val(hdr, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm3, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name3,
						    test_len_nm3, 0));
			EXPECT_EQ(test_len_val3, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value3,
						    test_len_val3, 0));
		}
		EXPECT_EQ(entry->name_len, test_len_nm3);
		EXPECT_EQ(entry->name_num, h_name.nchunks);
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_H2_AUTHORITY);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 63);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		test_h2_hdr_name(hdr, &h_name);
		__h2_msg_hdr_val(hdr, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm1, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name1,
						    test_len_nm1, 0));
			EXPECT_EQ(test_len_val1, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value1,
						    test_len_val1, 0));
		}
		EXPECT_EQ(entry->name_len, test_len_nm1);
		EXPECT_EQ(entry->name_num, h_name.nchunks);
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_RAW);
	}

	entry = tfw_hpack_find_index(&hp->dec_tbl, 62);
	EXPECT_NOT_NULL(entry);
	if (entry) {
		hdr = entry->hdr;
		test_h2_hdr_name(hdr, &h_name);
		__h2_msg_hdr_val(hdr, &h_value);
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_name));
		EXPECT_TRUE(!TFW_STR_EMPTY(&h_value));
		if (!TFW_STR_EMPTY(&h_name) && !TFW_STR_EMPTY(&h_value)) {
			EXPECT_EQ(test_len_nm2, h_name.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_name, test_name2,
						    test_len_nm2, 0));
			EXPECT_EQ(test_len_val2, h_value.len);
			EXPECT_TRUE(tfw_str_eq_cstr(&h_value, test_value2,
						    test_len_val2, 0));
		}
		EXPECT_EQ(entry->name_len, test_len_nm2);
		EXPECT_EQ(entry->name_num, h_name.nchunks);
		EXPECT_EQ(entry->tag, TFW_TAG_HDR_CACHE_CONTROL);
	}

#undef HDR_NAME_1
#undef HDR_VALUE_1
#undef HDR_NAME_2
#undef HDR_VALUE_2
#undef HDR_NAME_3
#undef HDR_VALUE_3
}

TEST(hpack, enc_huffman)
{
	/*
	 * The test dec_huffman checks that the following values was
	 * correctly parsed from the Huffman encoded strings, check that we
	 * can create exactly the same encoded strings.
	 */
	DEFINE_TFW_STR(custom_key_raw, "custom-key");
	DEFINE_TFW_STR(custom_key_exp, "\x25\xA8\x49\xE9\x5B\xA9\x7D\x7F");
	DEFINE_TFW_STR(custom_val_raw, "custom-value");
	DEFINE_TFW_STR(custom_val_exp, "\x25\xA8\x49\xE9\x5B\xB8\xE8\xB4\xBF");
	DEFINE_TFW_STR(no_cache_raw, "no-cache");
	DEFINE_TFW_STR(no_cache_exp, "\xA8\xEB\x10\x64\x9C\xBF");
	TfwStr *www_raw = make_compound_str("www.example.com");
	DEFINE_TFW_STR(www_exp,
		       "\xF1\xE3\xC2\xE5\xF2\x3A\x6B\xA0\xAB\x90\xF4\xFF");
	TfwStr *custom_key_enc, *custom_val_enc, *no_cache_enc, *www_enc;

	custom_key_enc = tfw_huffman_encode_string(&custom_key_raw, str_pool);
	EXPECT_TRUE(!IS_ERR_OR_NULL(custom_key_enc));
	EXPECT_OK(tfw_strcmp(custom_key_enc, &custom_key_exp));

	custom_val_enc = tfw_huffman_encode_string(&custom_val_raw, str_pool);
	EXPECT_TRUE(!IS_ERR_OR_NULL(custom_val_enc));
	EXPECT_OK(tfw_strcmp(custom_val_enc, &custom_val_exp));

	no_cache_enc = tfw_huffman_encode_string(&no_cache_raw, str_pool);
	EXPECT_TRUE(!IS_ERR_OR_NULL(no_cache_enc));
	EXPECT_OK(tfw_strcmp(no_cache_enc, &no_cache_exp));

	www_enc = tfw_huffman_encode_string(www_raw, str_pool);
	EXPECT_TRUE(!IS_ERR_OR_NULL(www_enc));
	EXPECT_OK(tfw_strcmp(www_enc, &www_exp));

	/*
	 * TODO: add more test cases: encode<->decode the same text using
	 * Tempesta functions.
	 */
}

TEST(hpack, enc_table_hdr_write)
{
	char *buf, *ptr;
	unsigned long hdr_len;
	TfwStr s_nm = {}, s_val = {};

#define HDR_NAME_1	"x-forwarded-for"
#define HDR_VALUE_1	"test.com, foo.com, example.com"
#define HDR_NAME_2	"custom-header"
#define HDR_VALUE_2	"custom-value"
#define HDR_NAME_3	"x-custom-hdr"
#define HDR_VALUE_3	"example header value"
#define HDR_NAME_4	"custom-name"
#define HDR_VALUE_4	"custom-test-value"
#define HDR_NAME_5	"custom-key"
#define HDR_VALUE_5	"custom-example-value"

	TFW_STR(col, ":");

	TFW_STR(s1, HDR_NAME_1);
	TFW_STR(s1_lws, "      ");
	TFW_STR(s1_value, HDR_VALUE_1);
	TFW_STR(s1_rws, "    ");
	const char *t_s1 = HDR_NAME_1 HDR_VALUE_1;
	unsigned long t_s1_len = strlen(t_s1);

	TFW_STR(s2, HDR_NAME_2);
	TFW_STR(s2_value, HDR_VALUE_2);
	const char *t_s2 = HDR_NAME_2 HDR_VALUE_2;
	unsigned long t_s2_len = strlen(t_s2);

	TFW_STR(s3, HDR_NAME_3);
	TFW_STR(s3_lws, "\t  ");
	TFW_STR(s3_value, HDR_VALUE_3);
	TFW_STR(s3_rws, "   ");
	const char *t_s3 = HDR_NAME_3 HDR_VALUE_3;
	unsigned long t_s3_len = strlen(t_s3);

	TFW_STR(s4, HDR_NAME_4);
	TFW_STR(s4_lws, "     ");
	TFW_STR(s4_value, HDR_VALUE_4);
	TFW_STR(s4_rws, "\t\t   \t");
	const char *t_s4 = HDR_NAME_4 HDR_VALUE_4;
	unsigned long t_s4_len = strlen(t_s4);

	TFW_STR(s5, HDR_NAME_5);
	TFW_STR(s5_lws, "\t\t\t");
	TFW_STR(s5_value, HDR_VALUE_5);
	TFW_STR(s5_rws, "\t\t\t\t");
	const char *t_s5 = HDR_NAME_5 HDR_VALUE_5;
	unsigned long t_s5_len = strlen(t_s5);

	collect_compound_str(s1, col, 0);
	collect_compound_str(s1, s1_lws, TFW_STR_OWS);
	collect_compound_str(s1, s1_value, 0);
	collect_compound_str(s1, s1_rws, TFW_STR_OWS);
	collect_compound_str(s2, col, 0);
	collect_compound_str(s2, s2_value, 0);
	collect_compound_str(s3, col, 0);
	collect_compound_str(s3, s3_lws, TFW_STR_OWS);
	collect_compound_str(s3, s3_value, 0);
	collect_compound_str(s3, s3_rws, TFW_STR_OWS);
	collect_compound_str(s4, col, 0);
	collect_compound_str(s4, s4_lws, TFW_STR_OWS);
	collect_compound_str(s4, s4_value, 0);
	collect_compound_str(s4, s4_rws, TFW_STR_OWS);
	collect_compound_str(s5, col, 0);
	collect_compound_str(s5, s5_lws, TFW_STR_OWS);
	collect_compound_str(s5, s5_value, 0);
	collect_compound_str(s5, s5_rws, TFW_STR_OWS);

	hdr_len = tfw_http_hdr_split(s1, &s_nm, &s_val, true);
	EXPECT_EQ(s_nm.len, strlen(HDR_NAME_1));
	EXPECT_EQ(s_val.len, strlen(HDR_VALUE_1));
	EXPECT_EQ(hdr_len, t_s1_len);
	buf = tfw_pool_alloc(str_pool, hdr_len);
	BUG_ON(!buf);
	ptr = tfw_hpack_write(&s_nm, buf);
	tfw_hpack_write(&s_val, ptr);
	EXPECT_OK(memcmp_fast(t_s1, buf, hdr_len));

	TFW_STR_INIT(&s_nm);
	TFW_STR_INIT(&s_val);
	hdr_len = tfw_http_hdr_split(s2, &s_nm, &s_val, true);
	EXPECT_EQ(s_nm.len, strlen(HDR_NAME_2));
	EXPECT_EQ(s_val.len, strlen(HDR_VALUE_2));
	EXPECT_EQ(hdr_len, t_s2_len);
	buf = tfw_pool_alloc(str_pool, hdr_len);
	BUG_ON(!buf);
	ptr = tfw_hpack_write(&s_nm, buf);
	tfw_hpack_write(&s_val, ptr);
	EXPECT_OK(memcmp_fast(t_s2, buf, hdr_len));

	TFW_STR_INIT(&s_nm);
	TFW_STR_INIT(&s_val);
	hdr_len = tfw_http_hdr_split(s3, &s_nm, &s_val, true);
	EXPECT_EQ(s_nm.len, strlen(HDR_NAME_3));
	EXPECT_EQ(s_val.len, strlen(HDR_VALUE_3));
	EXPECT_EQ(hdr_len, t_s3_len);
	buf = tfw_pool_alloc(str_pool, hdr_len);
	BUG_ON(!buf);
	ptr = tfw_hpack_write(&s_nm, buf);
	tfw_hpack_write(&s_val, ptr);
	EXPECT_OK(memcmp_fast(t_s3, buf, hdr_len));

	TFW_STR_INIT(&s_nm);
	TFW_STR_INIT(&s_val);
	hdr_len = tfw_http_hdr_split(s4, &s_nm, &s_val, true);
	EXPECT_EQ(s_nm.len, strlen(HDR_NAME_4));
	EXPECT_EQ(s_val.len, strlen(HDR_VALUE_4));
	EXPECT_EQ(hdr_len, t_s4_len);
	buf = tfw_pool_alloc(str_pool, hdr_len);
	BUG_ON(!buf);
	ptr = tfw_hpack_write(&s_nm, buf);
	tfw_hpack_write(&s_val, ptr);
	EXPECT_OK(memcmp_fast(t_s4, buf, hdr_len));

	TFW_STR_INIT(&s_nm);
	TFW_STR_INIT(&s_val);
	hdr_len = tfw_http_hdr_split(s5, &s_nm, &s_val, true);
	EXPECT_EQ(s_nm.len, strlen(HDR_NAME_5));
	EXPECT_EQ(s_val.len, strlen(HDR_VALUE_5));
	EXPECT_EQ(hdr_len, t_s5_len);
	buf = tfw_pool_alloc(str_pool, hdr_len);
	BUG_ON(!buf);
	ptr = tfw_hpack_write(&s_nm, buf);
	tfw_hpack_write(&s_val, ptr);
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

TEST(hpack, enc_table_index)
{
	TfwHPackETbl *tbl;
	TfwHPackETblRes res;
	TfwHPackNodeIter pl = {};
	const TfwHPackNode *node = NULL;
	unsigned short index = 0;
	TfwStr s1_name = {}, s1_val = {};
	TfwStr s2_name = {}, s2_val = {};
	TfwStr s3_name = {}, s3_val = {};

#define HDR_NAME_1	"test-custom-header-name"
#define HDR_VALUE_1	"foo test example value"
#define HDR_NAME_2	"x-custom-hdr"
#define HDR_VALUE_2	"value foo bar"
#define HDR_NAME_3	"test-example-key"
#define HDR_VALUE_3	"custom-example-value"

	TFW_STR(col, ":");

	TFW_STR(s1, HDR_NAME_1);
	TFW_STR(s1_lws, " \t  ");
	TFW_STR(s1_value, HDR_VALUE_1);
	TFW_STR(s1_rws, "       ");
	const char *t_s1 = HDR_NAME_1 HDR_VALUE_1;
	unsigned long t_s1_len = strlen(t_s1);

	TFW_STR(s2, HDR_NAME_2);
	TFW_STR(s2_value, HDR_VALUE_2);
	const char *t_s2 = HDR_NAME_2 HDR_VALUE_2;
	unsigned long t_s2_len = strlen(t_s2);

	TFW_STR(s3, HDR_NAME_3);
	TFW_STR(s3_lws, "\t  \t\t\t");
	TFW_STR(s3_value, HDR_VALUE_3);
	TFW_STR(s3_rws, "\t\t\t\t    ");
	const char *t_s3 = HDR_NAME_3 HDR_VALUE_3;
	unsigned long t_s3_len = strlen(t_s3);

	collect_compound_str(s1, col, 0);
	collect_compound_str(s1, s1_lws, TFW_STR_OWS);
	collect_compound_str(s1, s1_value, 0);
	collect_compound_str(s1, s1_rws, TFW_STR_OWS);
	collect_compound_str(s2, col, 0);
	collect_compound_str(s2, s2_value, 0);
	collect_compound_str(s3, col, 0);
	collect_compound_str(s3, s3_lws, TFW_STR_OWS);
	collect_compound_str(s3, s3_value, 0);
	collect_compound_str(s3, s3_rws, TFW_STR_OWS);

	tfw_http_hdr_split(s1, &s1_name, &s1_val, true);
	tfw_http_hdr_split(s2, &s2_name, &s2_val, true);
	tfw_http_hdr_split(s3, &s3_name, &s3_val, true);

	tbl = &ctx->hpack.enc_tbl;

	/*
	 * Prepare encoder dynamic index: add headers into the appropriate
	 * positions of ring buffer and corresponding red-black tree.
	 */
	res = tfw_hpack_rbtree_find(tbl, &s1_name, &s1_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);
	EXPECT_OK(tfw_hpack_add_node(tbl, &s1_name, &s1_val, &pl));

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s2_name, &s2_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);
	EXPECT_NOT_NULL(pl.parent);
	if (pl.parent)
		EXPECT_OK(tfw_hpack_add_node(tbl, &s2_name, &s2_val, &pl));

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s3_name, &s3_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);
	EXPECT_NOT_NULL(pl.parent);
	if (pl.parent)
		EXPECT_OK(tfw_hpack_add_node(tbl, &s3_name, &s3_val, &pl));

	/*
	 * Verify that headers had been correctly added into encoder dynamic
	 * table and right indexes are assigned to them.
	 */
	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s1_name, &s1_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_FOUND);
	EXPECT_NULL(pl.parent);
	EXPECT_NOT_NULL(node);
	index = HPACK_NODE_GET_INDEX(tbl, node);
	EXPECT_EQ(index, 64);
	if (node) {
		EXPECT_EQ((unsigned long)node->hdr_len, t_s1_len);
		EXPECT_OK(memcmp_fast(t_s1, node->hdr, t_s1_len));
	}

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s2_name, &s2_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_FOUND);
	EXPECT_NULL(pl.parent);
	EXPECT_NOT_NULL(node);
	index = HPACK_NODE_GET_INDEX(tbl, node);
	EXPECT_EQ(index, 63);
	if (node) {
		EXPECT_EQ((unsigned long)node->hdr_len, t_s2_len);
		EXPECT_OK(memcmp_fast(t_s2, node->hdr, t_s2_len));
	}

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s3_name, &s3_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_FOUND);
	EXPECT_NULL(pl.parent);
	EXPECT_NOT_NULL(node);
	index = HPACK_NODE_GET_INDEX(tbl, node);
	EXPECT_EQ(index, 62);
	if (node) {
		EXPECT_EQ((unsigned long)node->hdr_len, t_s3_len);
		EXPECT_OK(memcmp_fast(t_s3, node->hdr, t_s3_len));
	}

#undef HDR_NAME_1
#undef HDR_VALUE_1
#undef HDR_NAME_2
#undef HDR_VALUE_2
#undef HDR_NAME_3
#undef HDR_VALUE_3
}

TEST(hpack, enc_table_rbtree)
{
	TfwHPackETbl *tbl;
	TfwHPackETblRes res;
	TfwHPackNodeIter pl = {};
	const TfwHPackNode *node = NULL;
	const TfwHPackNode *n1 = NULL, *n2 = NULL, *n3 = NULL;
	const TfwHPackNode *n4 = NULL, *n5 = NULL;
	TfwStr s1_name = {}, s1_val = {};
	TfwStr s2_name = {}, s2_val = {};
	TfwStr s3_name = {}, s3_val = {};
	TfwStr s4_name = {}, s4_val = {};
	TfwStr s5_name = {}, s5_val = {};

#define HDR_NAME_1	"test-custom-name"
#define HDR_VALUE_1	"test-custom-value"
#define HDR_NAME_2	"x-forwarded-for"
#define HDR_VALUE_2	"example.com"
#define HDR_NAME_3	"test-key"
#define HDR_VALUE_3	"test-value"
#define HDR_NAME_4	"custom-key"
#define HDR_VALUE_4	"custom-value"
#define HDR_NAME_5	"test-foo-name"
#define HDR_VALUE_5	"test-foo-value"

	TFW_STR(col, ":");
	TFW_STR(s1, HDR_NAME_1);
	TFW_STR(s1_value, HDR_VALUE_1);
	TFW_STR(s2, HDR_NAME_2);
	TFW_STR(s2_value, HDR_VALUE_2);
	TFW_STR(s3, HDR_NAME_3);
	TFW_STR(s3_value, HDR_VALUE_3);
	TFW_STR(s4, HDR_NAME_4);
	TFW_STR(s4_value, HDR_VALUE_4);
	TFW_STR(s5, HDR_NAME_5);
	TFW_STR(s5_value, HDR_VALUE_5);

	collect_compound_str(s1, col, 0);
	collect_compound_str(s1, s1_value, 0);
	collect_compound_str(s2, col, 0);
	collect_compound_str(s2, s2_value, 0);
	collect_compound_str(s3, col, 0);
	collect_compound_str(s3, s3_value, 0);
	collect_compound_str(s4, col, 0);
	collect_compound_str(s4, s4_value, 0);
	collect_compound_str(s5, col, 0);
	collect_compound_str(s5, s5_value, 0);

	tfw_http_hdr_split(s1, &s1_name, &s1_val, true);
	tfw_http_hdr_split(s2, &s2_name, &s2_val, true);
	tfw_http_hdr_split(s3, &s3_name, &s3_val, true);
	tfw_http_hdr_split(s4, &s4_name, &s4_val, true);
	tfw_http_hdr_split(s5, &s5_name, &s5_val, true);

	tbl = &ctx->hpack.enc_tbl;

	/*
	 * Insert nodes with new headers into the table in the order which will
	 * necessitate tree re-balancing. After the @n3 node will be inserted
	 * the tree structure should have the following view:
	 *
	 *               n1
	 *             (BLACK)
	 *                \
	 *                 n2
	 *               (RED)
	 *                /
	 *               n3
	 *             (RED)
	 *
	 * Thus, the 4th property of red-black tree will be broken after the 3rd
	 * node insertion, and the re-balancing procedure must be performed
	 * during the 3rd call of @tfw_hpack_add_node() function.
	 */
	res = tfw_hpack_rbtree_find(tbl, &s1_name, &s1_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);
	EXPECT_OK(tfw_hpack_add_node(tbl, &s1_name, &s1_val, &pl));
	rbt_validate(tbl);
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s1_name, &s1_val, &n1, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_FOUND);
	EXPECT_NULL(pl.parent);
	EXPECT_NOT_NULL(n1);
	rbt_validate(tbl);
	if (n1) {
		/* Check that the 1st node @n1 is the root node. */
		EXPECT_NULL(HPACK_NODE_COND(tbl, n1->parent));
	}

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s2_name, &s2_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);
	EXPECT_NOT_NULL(pl.parent);
	if (pl.parent) {
		EXPECT_OK(tfw_hpack_add_node(tbl, &s2_name, &s2_val, &pl));
		rbt_validate(tbl);
	}
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s2_name, &s2_val, &n2, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_FOUND);
	EXPECT_NULL(pl.parent);
	EXPECT_NOT_NULL(n2);

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s3_name, &s3_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);
	EXPECT_NOT_NULL(pl.parent);
	if (pl.parent) {
		EXPECT_OK(tfw_hpack_add_node(tbl, &s3_name, &s3_val, &pl));
		rbt_validate(tbl);
	}
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s3_name, &s3_val, &n3, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_FOUND);
	EXPECT_NULL(pl.parent);
	EXPECT_NOT_NULL(n3);
	if (!n3)
		return;

	/*
	 * After re-balancing (which includes one right and one left rotations)
	 * the tree structure should look like below:
	 *
	 *                n3
	 *             (BLACK)
	 *               / \
	 *              n1  n2
	 *           (RED)  (RED)
	 *
	 * As a result the 4th property has been restored, and the other
	 * properties of red-black tree are not broken.
	 */

	/*
	 * Insert 4th node with header, which is less than all other headers in
	 * the tree. After that the tree structure should have the following
	 * view:
	 *
	 *                n3
	 *             (BLACK)
	 *               / \
	 *              n1  n2
	 *           (RED)  (RED)
	 *             /
	 *            n4
	 *         (RED)
	 *
	 * Again, the 4th property is broken, and the re-balancing procedure
	 * must take place during @tfw_hpack_add_node() function execution.
	 */
	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s4_name, &s4_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);
	EXPECT_NOT_NULL(pl.parent);
	if (pl.parent) {
		EXPECT_OK(tfw_hpack_add_node(tbl, &s4_name, &s4_val, &pl));
		rbt_validate(tbl);
	}
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s4_name, &s4_val, &n4, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_FOUND);
	EXPECT_NULL(pl.parent);
	EXPECT_NOT_NULL(n4);
	if (!n4)
		return;

	/*
	 * After re-balancing (which should not include any rotations, only
	 * color changes) the tree structure should look like:
	 *
	 *                n3
	 *             (BLACK)
	 *               / \
	 *              n1  n2
	 *         (BLACK)  (BLACK)
	 *             /
	 *            n4
	 *         (RED)
	 *
	 * Thus, all properties of red-black tree are not broken. Next, insert
	 * 5th node:
	 *
	 *                n3
	 *             (BLACK)
	 *               / \
	 *              n1  n2
	 *         (BLACK)  (BLACK)
	 *             / \
	 *            n4  n5
	 *         (RED)  (RED)
	 *
	 * In this case, the properties are not broken, and the re-balancing
	 * procedure is not needed at all.
	 */
	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s5_name, &s5_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);
	EXPECT_NOT_NULL(pl.parent);
	if (pl.parent) {
		EXPECT_OK(tfw_hpack_add_node(tbl, &s5_name, &s5_val, &pl));
		rbt_validate(tbl);
	}
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s5_name, &s5_val, &n5, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_FOUND);
	EXPECT_NULL(pl.parent);
	EXPECT_NOT_NULL(n5);
	if (!n5)
		return;

	/*
	 * Delete the root @n3 node from the tree. Immediately after the removal
	 * the tree should have the following view:
	 *
	 *                n2
	 *             (BLACK)
	 *               /
	 *              n1
	 *           (BLACK)
	 *             / \
	 *            n4  n5
	 *         (RED)  (RED)
	 *
	 * Thus, the 5th property of red-black tree became broken (accounting
	 * the empty leaf nodes, which have the BLACK color by definition); so,
	 * re-balancing procedure (which should include nodes' color changes
	 * and the right rotation relative to the root node) is needed in
	 * this case, and after it the tree must have next balanced structure:
	 *
	 *                n1
	 *             (BLACK)
	 *               / \
	 *              n4  n2
	 *         (BLACK)  (BLACK)
	 *                 /
	 *                 n5
	 *                (RED)
	 *
	 * All tree-specific removing and re-balancing actions are executed in
	 * @tfw_hpack_rbtree_erase() procedure.
	 */
	tfw_hpack_rbtree_erase(tbl, (TfwHPackNode *)n3);
	rbt_validate(tbl);

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s3_name, &s3_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);

	/*
	 * Delete the @n4 node from the tree. As a result, the 5th property
	 * became broken again; so, re-balancing procedure (should include
	 * nodes' color changes, the right rotation relative to @n2 node and
	 * the left rotation relative to root node) must be executed. Finally,
	 * we should get the following balanced tree:
	 *
	 *                n5
	 *             (BLACK)
	 *               / \
	 *              n1  n2
	 *         (BLACK)  (BLACK)
	 */
	tfw_hpack_rbtree_erase(tbl, (TfwHPackNode *)n4);
	rbt_validate(tbl);

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s4_name, &s4_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);

	/*
	 * Delete the @n2 node from the tree. To restore broken 5th property
	 * re-balancing procedure should be performed, without any rotations
	 * in this case: only color change (to RED) for @n1 node should be
	 * done. The following tree balanced structure should be obtained as
	 * a result:
	 *
	 *                n5
	 *             (BLACK)
	 *               /
	 *              n1
	 *            (RED)
	 */
	tfw_hpack_rbtree_erase(tbl, (TfwHPackNode *)n2);
	rbt_validate(tbl);

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s2_name, &s2_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);
	
	/*
	 * Delete the @n5 node from the tree. No rotations are needed in this
	 * case too: only the color for the @n1 node (which should become root)
	 * must be set to BLACK. The resulting balanced structure of the tree:
	 *
	 *              n1
	 *            (BLACK)
	 */
	tfw_hpack_rbtree_erase(tbl, (TfwHPackNode *)n5);
	rbt_validate(tbl);

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s5_name, &s5_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);

	tfw_hpack_rbtree_erase(tbl, (TfwHPackNode *)n1);

	node = NULL;
	bzero_fast(&pl, sizeof(pl));
	res = tfw_hpack_rbtree_find(tbl, &s1_name, &s1_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);

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

TEST(hpack, enc_table_eviction)
{
	TfwHPackETbl *tbl;
	int i = 0;
	TfwStr *filler;
	TfwStr *f_hdr, *l_hdr_val, *filler_val;
	TfwHPackETblRes res;
	TfwHPackNodeIter pl = {};
	char hdr[64];
	char long_val[255] = "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"
			     "uiopqwertyuiopqwertyuiop";
	const TfwHPackNode *node = NULL;
	TfwStr f_name = {}, f_val = {};
	TfwStr l_name = {}, l_val = {};

	TFW_STR(col, ":");
	TFW_STR(f_hdr_val, "first header");
	TFW_STR(l_hdr, "LastHeader");

	tbl = &ctx->hpack.enc_tbl;

	f_hdr = make_compound_str("HeaderFirst");
	collect_compound_str(f_hdr, col, 0);
	collect_compound_str(f_hdr, f_hdr_val, 0);
	tfw_http_hdr_split(f_hdr, &f_name, &f_val, true);

	res = tfw_hpack_rbtree_find(tbl, &f_name, &f_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);

	EXPECT_OK(tfw_hpack_add_node(tbl, &f_name, &f_val, &pl));
	bzero_fast(&pl, sizeof(pl));

	for (;;) {
		unsigned long node_size;
		unsigned long new_size;
		TfwStr fil_name = {}, fil_val = {};

		sprintf(hdr, "Header%i", i);

		filler = make_compound_str(hdr);
		filler_val = make_compound_str(long_val);
		collect_compound_str(filler, col, 0);
		collect_compound_str(filler, filler_val, 0);

		node_size = filler->len + HPACK_ENTRY_OVERHEAD;
		new_size = tbl->size + node_size;

		/* next large addition evict some headers. */
		if (new_size > tbl->window)
			break;

		tfw_http_hdr_split(filler, &fil_name, &fil_val, true);

		res = tfw_hpack_rbtree_find(tbl, &fil_name, &fil_val,
					    &node, &pl);
		EXPECT_GT(res, HPACK_IDX_ST_FOUND);
		EXPECT_NULL(node);
		EXPECT_OK(tfw_hpack_add_node(tbl, &fil_name, &fil_val, &pl));
		bzero_fast(&pl, sizeof(pl));
		bzero_fast(hdr, sizeof(hdr));
		i++;
	}

	res = tfw_hpack_rbtree_find(tbl, &f_name, &f_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_FOUND);
	node = NULL;
	bzero_fast(&pl, sizeof(pl));

	l_hdr_val = make_compound_str(long_val);
	collect_compound_str(l_hdr, col, 0);
	collect_compound_str(l_hdr, l_hdr_val, 0);

	tfw_http_hdr_split(l_hdr, &l_name, &l_val, true);

	res = tfw_hpack_rbtree_find(tbl, &l_name, &l_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
	EXPECT_NULL(node);
	EXPECT_OK(tfw_hpack_add_node(tbl, &l_name, &l_val, &pl));
	bzero_fast(&pl, sizeof(pl));

	/* first header must not present. */
	res = tfw_hpack_rbtree_find(tbl, &f_name, &f_val, &node, &pl);
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);
}

#define ADD_NODE(s, n)								\
do {										\
	TfwStr s_name = {}, s_val = {};						\
	tfw_http_hdr_split(s, &s_name, &s_val, true);				\
	res = tfw_hpack_rbtree_find(tbl, &s_name, &s_val, &n, &pl);		\
	EXPECT_EQ(res, HPACK_IDX_ST_NOT_FOUND);					\
	EXPECT_NULL(n);								\
	EXPECT_OK(tfw_hpack_add_node(tbl, &s_name, &s_val, &pl));		\
	bzero_fast(&pl, sizeof(pl));						\
	res = tfw_hpack_rbtree_find(tbl, &s_name, &s_val, &n, &pl);		\
	EXPECT_EQ(res, HPACK_IDX_ST_FOUND);					\
	EXPECT_NULL(pl.parent);							\
	EXPECT_NOT_NULL(n);							\
} while (0)

TEST(hpack, rbtree_ins_rebalance)
{
	TfwHPackETbl *tbl;
	TfwHPackETblRes res;
	TfwHPackNodeIter pl = {};
	const TfwHPackNode *n1 = NULL, *n2 = NULL, *n3 = NULL, *n4 = NULL;
	const TfwHPackNode *n5 = NULL, *n6 = NULL, *n7 = NULL, *n8 = NULL;
	const TfwHPackNode *n9 = NULL, *n10 = NULL;

	TFW_STR(col, ":");
	TFW_STR(s1, "80");
	TFW_STR(s1_value, "80");
	TFW_STR(s2, "70");
	TFW_STR(s2_value, "70");
	TFW_STR(s3, "60");
	TFW_STR(s3_value, "60");
	TFW_STR(s4, "50");
	TFW_STR(s4_value, "50");
	TFW_STR(s5, "40");
	TFW_STR(s5_value, "40");
	TFW_STR(s6, "30");
	TFW_STR(s6_value, "30");
	TFW_STR(s7, "20");
	TFW_STR(s7_value, "20");
	TFW_STR(s8, "55");
	TFW_STR(s8_value, "55");
	TFW_STR(s9, "65");
	TFW_STR(s9_value, "65");
	TFW_STR(s10, "67");
	TFW_STR(s10_value, "67");

	collect_compound_str(s1, col, 0);
	collect_compound_str(s1, s1_value, 0);
	collect_compound_str(s2, col, 0);
	collect_compound_str(s2, s2_value, 0);
	collect_compound_str(s3, col, 0);
	collect_compound_str(s3, s3_value, 0);
	collect_compound_str(s4, col, 0);
	collect_compound_str(s4, s4_value, 0);
	collect_compound_str(s5, col, 0);
	collect_compound_str(s5, s5_value, 0);
	collect_compound_str(s6, col, 0);
	collect_compound_str(s6, s6_value, 0);
	collect_compound_str(s7, col, 0);
	collect_compound_str(s7, s7_value, 0);
	collect_compound_str(s8, col, 0);
	collect_compound_str(s8, s8_value, 0);
	collect_compound_str(s9, col, 0);
	collect_compound_str(s9, s9_value, 0);
	collect_compound_str(s10, col, 0);
	collect_compound_str(s10, s10_value, 0);

	tbl = &ctx->hpack.enc_tbl;

	ADD_NODE(s1, n1);
	ADD_NODE(s2, n2);
	ADD_NODE(s3, n3);
	ADD_NODE(s4, n4);
	ADD_NODE(s5, n5);
	ADD_NODE(s6, n6);
	ADD_NODE(s7, n7);
	ADD_NODE(s8, n8);
	ADD_NODE(s9, n9);

	/*
	 *                 n2
	 *              (BLACK)
	 *               /    \
	 *              n4     n1
	 *            (RED)  (BLACK)
	 *            /    \
	 *           n6     n3
	 *        (BLACK) (BLACK)
	 *         /  \     /  \
	 *        n7  n5   n8   n9
	 *     (RED)(RED) (RED)(RED)
	 */

	ADD_NODE(s10, n10);

	/*
	 * Add the node n10 as the right child of n9.
	 * Because parent n9 - red and uncle n8 - red, we make them (n9 and n8)
	 * black, and grandparent n3 - red.
	 *                 n2
	 *              (BLACK)
	 *               /    \
	 *              n4     n1
	 *             (RED)  (BLACK)
	 *            /     \
	 *           n6     n3
	 *        (BLACK)  (RED)
	 *         /  \     /   \
	 *        n7  n5   n8    n9
	 *     (RED)(RED)(BLACK)(BLACK)
	 *                         \
	 *                         n10
	 *                         (RED)
	 * The grandparent n3 becomes the new current node.
	 * Then, since the parent n4 of the current node n3 (great-grandparent of
	 * the original n10) is red, and its uncle n1 is not red, and the node n3 is
	 * the right child of the left child - we rotate to the left relative to the
	 * parent n4.
	 *                 n2
	 *              (BLACK)
	 *               /    \
	 *              n3   n1
	 *            (RED) (BLACK)
	 *            /   \
	 *           n4    n9
	 *         (RED)  (BLACK)
	 *        /     \      \
	 *       n6     n8     n10
	 *    (BLACK) (BLACK) (RED)
	 *    /  \
	 *   n7  n5
	 *  (RED)(RED)
	 * The new current node n4 is the left child of the current node n3.
	 * Because the current node n4 is the left child of the left child, then we
	 * make the parent n3 black and the grandparent n2 red and rotate to the
	 * right relative to its grandparent n3.
	 *                    n3
	 *                 (BLACK)
	 *               /         \
	 *              n4          n2
	 *            (RED)         (RED)
	 *            /   \         /   \
	 *           n6    n8      n9     n1
	 *        (BLACK)(BLACK) (BLACK) (BLACK)
	 *         /  \               \
	 *        n7  n5              n10
	 *     (RED)(RED)            (RED)
	 */

	EXPECT_EQ(HPACK_NODE_COND(tbl, n3->left), n4);
	EXPECT_EQ(HPACK_NODE_COND(tbl, n4->left), n6);
	EXPECT_EQ(HPACK_NODE_COND(tbl, n6->left), n7);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n7->left));
	EXPECT_NULL(HPACK_NODE_COND(tbl, n7->right));
	EXPECT_EQ(HPACK_NODE_COND(tbl, n6->right), n5);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n5->left));
	EXPECT_NULL(HPACK_NODE_COND(tbl, n5->right));
	EXPECT_EQ(HPACK_NODE_COND(tbl, n4->right), n8);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n8->left));
	EXPECT_NULL(HPACK_NODE_COND(tbl, n8->right));
	EXPECT_EQ(HPACK_NODE_COND(tbl, n3->right), n2);
	EXPECT_EQ(HPACK_NODE_COND(tbl, n2->left), n9);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n9->left));
	EXPECT_EQ(HPACK_NODE_COND(tbl, n9->right), n10);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n10->left));
	EXPECT_NULL(HPACK_NODE_COND(tbl, n10->right));
	EXPECT_EQ(HPACK_NODE_COND(tbl, n2->right), n1);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n1->left));
	EXPECT_NULL(HPACK_NODE_COND(tbl, n1->right));
}

TEST(hpack, rbtree_del_rebalance)
{
	TfwHPackETbl *tbl;
	TfwHPackETblRes res;
	TfwHPackNodeIter pl = {};
	const TfwHPackNode *n1 = NULL, *n2 = NULL, *n3 = NULL, *n4 = NULL;
	const TfwHPackNode *n5 = NULL, *n6 = NULL, *n7 = NULL, *n8 = NULL;
	const TfwHPackNode *n9 = NULL, *n10 = NULL;

	TFW_STR(col, ":");
	TFW_STR(s1, "1");
	TFW_STR(s1_value, "1");
	TFW_STR(s2, "2");
	TFW_STR(s2_value, "2");
	TFW_STR(s3, "3");
	TFW_STR(s3_value, "3");
	TFW_STR(s4, "4");
	TFW_STR(s4_value, "4");
	TFW_STR(s5, "5");
	TFW_STR(s5_value, "5");
	TFW_STR(s6, "6");
	TFW_STR(s6_value, "6");
	TFW_STR(s7, "7");
	TFW_STR(s7_value, "7");
	TFW_STR(s8, "8");
	TFW_STR(s8_value, "8");
	TFW_STR(s9, "9");
	TFW_STR(s9_value, "9");
	TFW_STR(s10, "a");
	TFW_STR(s10_value, "a");

	collect_compound_str(s1, col, 0);
	collect_compound_str(s1, s1_value, 0);
	collect_compound_str(s2, col, 0);
	collect_compound_str(s2, s2_value, 0);
	collect_compound_str(s3, col, 0);
	collect_compound_str(s3, s3_value, 0);
	collect_compound_str(s4, col, 0);
	collect_compound_str(s4, s4_value, 0);
	collect_compound_str(s5, col, 0);
	collect_compound_str(s5, s5_value, 0);
	collect_compound_str(s6, col, 0);
	collect_compound_str(s6, s6_value, 0);
	collect_compound_str(s7, col, 0);
	collect_compound_str(s7, s7_value, 0);
	collect_compound_str(s8, col, 0);
	collect_compound_str(s8, s8_value, 0);
	collect_compound_str(s9, col, 0);
	collect_compound_str(s9, s9_value, 0);
	collect_compound_str(s10, col, 0);
	collect_compound_str(s10, s10_value, 0);

	tbl = &ctx->hpack.enc_tbl;

	ADD_NODE(s1, n1);
	ADD_NODE(s2, n2);
	ADD_NODE(s3, n3);
	ADD_NODE(s4, n4);
	ADD_NODE(s5, n5);
	ADD_NODE(s6, n6);
	ADD_NODE(s7, n7);
	ADD_NODE(s8, n8);
	ADD_NODE(s9, n9);
	ADD_NODE(s10, n10);

	/*
	 *                  n4
	 *                (BLACK)
	 *               /      \
	 *              n2        n6
	 *            (BLACK)    (BLACK)
	 *            /    \     /      \
	 *           n1     n3   n5      n8
	 *        (BLACK) (BLACK)(BLACK)(RED)
	 *                               /   \
	 *                              n7    n9
	 *                           (BLACK)(BLACK)
	 *                                        \
	 *                                         n10
	 *                                        (RED)
	 */

	tfw_hpack_rbtree_erase(tbl, (TfwHPackNode *)n1);
	/*
	 * Erase the node n1.
	 *
	 *                   n4
	 *                 (BLACK)
	 *               /        \
	 *              n2         n6
	 *            (BLACK)      (BLACK)
	 *                 \      /      \
	 *                  n3    n5      n8
	 *               (BLACK)(BLACK)  (RED)
	 *                               /   \
	 *                              n7    n9
	 *                           (BLACK)(BLACK)
	 *                                        \
	 *                                         n10
	 *                                        (RED)
	 *
	 * Since there is no red brother and the brother n3 has no children, then we
	 * make the brother red.
	 *
	 *                  n4
	 *                (BLACK)
	 *               /       \
	 *              n2        n6
	 *            (BLACK)    (BLACK)
	 *                 \     /      \
	 *                  n3   n5      n8
	 *                (RED)(BLACK)   (RED)
	 *                               /   \
	 *                              n7    n9
	 *                           (BLACK)(BLACK)
	 *                                        \
	 *                                         n10
	 *                                        (RED)
	 *
	 * The current node n2 is the parent of erased n1.
	 * Since there is no red brother, the brother n6 has a red right child n8,
	 * but the current node n2 is a left child, then we assign the color of the
	 * parent n4 to the brother n6, make the parent n4 black, make the right
	 * child of the brother n8 black and make a left turn relative to the parent
	 * n4.
	 *
	 *                           n6
	 *                         (BLACK)
	 *                        /       \
	 *                       n4        n8
	 *                     (BLACK)    (BLACK)
	 *                       /  \       /   \
	 *                      n2   n5     n7    n9
	 *                   (BLACK)(BLACK)(BLACK)(BLACK)
	 *                       \                  \
	 *                        n3                n10
	 *                       (RED)             (RED)
	 */

	EXPECT_EQ(HPACK_NODE_COND(tbl, n6->left), n4);
	EXPECT_EQ(HPACK_NODE_COND(tbl, n4->left), n2);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n2->left));
	EXPECT_EQ(HPACK_NODE_COND(tbl, n2->right), n3);
	EXPECT_EQ(HPACK_NODE_COND(tbl, n4->right), n5);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n5->left));
	EXPECT_NULL(HPACK_NODE_COND(tbl, n5->right));
	EXPECT_EQ(HPACK_NODE_COND(tbl, n6->right), n8);
	EXPECT_EQ(HPACK_NODE_COND(tbl, n8->left), n7);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n7->left));
	EXPECT_NULL(HPACK_NODE_COND(tbl, n7->right));
	EXPECT_EQ(HPACK_NODE_COND(tbl, n8->right), n9);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n9->left));
	EXPECT_EQ(HPACK_NODE_COND(tbl, n9->right), n10);
	EXPECT_NULL(HPACK_NODE_COND(tbl, n10->left));
	EXPECT_NULL(HPACK_NODE_COND(tbl, n10->right));
}

#undef ADD_NODE

TEST_SUITE(hpack)
{
	TEST_SETUP(test_h2_setup);
	TEST_TEARDOWN(test_h2_teardown);

	TEST_RUN(hpack, dec_table_static);
	TEST_RUN(hpack, dec_table_dynamic);
	TEST_RUN(hpack, dec_table_dynamic_inc);
	TEST_RUN(hpack, dec_table_wrap);
	TEST_RUN(hpack, dec_raw);
	TEST_RUN(hpack, dec_indexed);
	TEST_RUN(hpack, dec_huffman);
	TEST_RUN(hpack, enc_huffman);
	TEST_RUN(hpack, enc_table_hdr_write);
	TEST_RUN(hpack, enc_table_index);
	TEST_RUN(hpack, enc_table_rbtree);
	TEST_RUN(hpack, rbtree_ins_rebalance);
	TEST_RUN(hpack, rbtree_del_rebalance);
	TEST_RUN(hpack, enc_table_eviction);
}
