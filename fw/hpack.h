/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2025 Tempesta Technologies, Inc.
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
#ifndef __TFW_HPACK_H__
#define __TFW_HPACK_H__

#include "http_types.h"

/**
 * Default allowed size for dynamic tables (in bytes). Note, that for encoder's
 * dynamic table - this is also the maximum allowed size and the maximum storage
 * (ring buffer) size.
 */
#define HPACK_TABLE_DEF_SIZE		4096
#define HPACK_ENC_TABLE_MAX_SIZE	HPACK_TABLE_DEF_SIZE

/* Limit for the HPACK variable-length integer. */
#define HPACK_INT_LIMIT			(1 << 20)

/* Static table size. Defined by RFC 7541. */
#define HPACK_STATIC_ENTRIES		61

/* Static table offset where starts regular headers (not pseudo-headers) */
#define HPACK_STATIC_TABLE_REGULAR	14
/**
 * Red-black tree node representation in the ring buffer.
 * Note, the field @hdr_len use only 15 bits and the 16th bit of unsigned
 * short type is used for RBTree color attribute; this is possible because
 * the maximum size of encoder dynamic index is 4096 bytes and, consequently,
 * the maximum size of stored header must be not greater than (4096 - 32)
 * bytes which is less then 32768 (0x7FFF - the half of unsigned short
 * capacity) - thus, 15 bits is enough for @hdr_len field.
 *
 * @rindex	- index (in reverse form) of stored header string in the
 *		  encoder dynamic table;
 * @name_len	- length of the header name;
 * @hdr_len	- length of stored header string;
 * @color	- RBTree color flag;
 * @parent	- parent node offset in the ring buffer (in bytes);
 * @left	- left child offset in the ring buffer (in bytes);
 * @right	- right child offset in the ring buffer (in bytes);
 * @hdr		- pointer to header string.
 */
typedef struct {
	unsigned long		rindex;
	unsigned short		name_len;
	unsigned short		hdr_len	: 15;
	unsigned short		color	: 1;
	short			parent;
	short			left;
	short			right;
	DECLARE_FLEX_ARRAY(char, hdr);
} TfwHPackNode;

/**
 * Common members of HPack encoder dynamic index.
 *
 * @first	- pointer to the first (i.e. the eldest) node in ring buffer;
 * @last	- pointer to the last (i.e. the youngest) node in ring buffer;
 * @rb_len	- actual size of all nodes in the ring buffer (in bytes);
 * @rb_size	- actual size of ring buffer (in bytes);
 * @size	- current pseudo-length of the encoder dynamic index (in bytes).
 */
#define TFW_HPACK_ETBL_COMMON					\
	TfwHPackNode		*first;				\
	TfwHPackNode		*last;				\
	unsigned short		rb_len;				\
	unsigned short		rb_size;			\
	unsigned short		size;

/**
 * HPack encoder dynamic index, implemented as ring buffer with entries
 * organized in form of binary tree.
 *
 * @window	- maximum pseudo-length of the dynamic table (in bytes); this
 *		  value used as threshold to flushing old entries;
 * @wnd_changed - flag indicates, that window was changed by settings update;
 * @rbuf	- pointer to the ring buffer;
 * @root	- pointer to the root node of binary tree;
 * @pool	- memory pool for dynamic table;
 * @idx_acc	- current accumulated index, intended for real indexes
 *		  calculation;
 */
typedef struct {
	TFW_HPACK_ETBL_COMMON;
	unsigned short		window;
	bool			wnd_changed;
	char			*rbuf;
	TfwHPackNode		*root;
	TfwPool			*pool;
	unsigned long		idx_acc;
} TfwHPackETbl;

/**
 * Auxiliary iterator for operations on a dynamic encoder table.
 */
typedef struct {
	TFW_HPACK_ETBL_COMMON;
} TfwHPackETblIter;

typedef enum {
	TFW_TAG_HDR_H2_STATUS,
	TFW_TAG_HDR_H2_METHOD,
	TFW_TAG_HDR_H2_SCHEME,
	TFW_TAG_HDR_H2_AUTHORITY,
	TFW_TAG_HDR_H2_PATH,
	TFW_TAG_HDR_ACCEPT,
	TFW_TAG_HDR_AUTHORIZATION,
	TFW_TAG_HDR_CACHE_CONTROL,
	TFW_TAG_HDR_CONTENT_ENCODING,
	TFW_TAG_HDR_CONTENT_LENGTH,
	TFW_TAG_HDR_CONTENT_TYPE,
	TFW_TAG_HDR_COOKIE,
	TFW_TAG_HDR_EXPECT,
	TFW_TAG_HDR_IF_NONE_MATCH,
	TFW_TAG_HDR_ETAG = TFW_TAG_HDR_IF_NONE_MATCH,
	TFW_TAG_HDR_HOST,
	TFW_TAG_HDR_IF_MODIFIED_SINCE,
	TFW_TAG_HDR_PRAGMA,
	TFW_TAG_HDR_REFERER,
	TFW_TAG_HDR_X_FORWARDED_FOR,
	TFW_TAG_HDR_FORWARDED,
	TFW_TAG_HDR_USER_AGENT,
	TFW_TAG_HDR_SERVER = TFW_TAG_HDR_USER_AGENT,
	TFW_TAG_HDR_TRANSFER_ENCODING,
	TFW_TAG_HDR_TE = TFW_TAG_HDR_TRANSFER_ENCODING,
	TFW_TAG_HDR_X_METHOD_OVERRIDE,
	TFW_TAG_HDR_RAW
} TfwHPackTag;

/**
 * This strucutre holds reusable parsed information from different HTTP
 * headers.
 *
 * @is_set	- boolean flag indicating that the state is set
 */
typedef struct {
	union {
		unsigned char	method;
		unsigned char	accept_text_html;
		long		if_msince_date;
		unsigned long	authority_port;
		unsigned char	ifnmatch_etag_any;
		struct {
			unsigned int flags;
			unsigned int max_age;
			unsigned int max_stale;
			unsigned int min_fresh;
			unsigned int stale_if_error;
		} cache_ctl;
		struct {
			DECLARE_BITMAP (flags, _TFW_HTTP_FLAGS_NUM);
			TfwStr multipart_boundary_raw;
			TfwStr multipart_boundary;
		} content_type;
		unsigned long	content_length;
		struct {
			unsigned int flags;
			unsigned int port;
		} forwarded;
		struct {
			bool has_referer;
		} referer;
		struct {
			unsigned int cookie_num;
		} cookie;
		unsigned char	method_override;
	};
	unsigned char		is_set;
} TfwCachedHeaderState;

/**
 * Representation of the entry in HPack decoder index.
 *
 * @hdr		- pointer to the header data descriptor;
 * @name_len	- length of the header's name part;
 * @name_num	- chunks count of the header's name part;
 * @tag		- tag of the indexed header;
 * @last	- flag bit indicating that corresponding header is the last on
 *		  the page.
 * @cstate	- part of the parser state for reusage with headers
 *		  stored in hpack dynamic table without re-parsing them.
 */
typedef struct {
	TfwStr			*hdr;
	unsigned long		name_len;
	unsigned long		name_num;
	TfwHPackTag		tag;
	unsigned char		last : 1;
	TfwCachedHeaderState	cstate;
} TfwHPackEntry;

/**
 * HPack decoder dynamic index table.
 *
 * @entries	- dynamic table of entries;
 * @pool	- memory pool for constantly sized entries (i.e. the entry
 *		  descriptors);
 * @h_pool	- memory pool for entries of variable size (headers themselves
 *		- and @TfwStr descriptors for them);
 * @n		- actual number of entries in the table;
 * @curr	- circular buffer index of recent entry;
 * @length	- current length of the dynamic table (in entries);
 * @size	- current pseudo-length of the dynamic headers table (in bytes);
 * @window	- maximum pseudo-length of the dynamic table (in bytes); this
 *		  value used as threshold to flushing old entries;
 * wnd_update	- we expect table size update before first header block;
 */
typedef struct {
	TfwHPackEntry		*entries;
	TfwPool			*pool;
	TfwPool			*h_pool;
	unsigned int		n;
	unsigned int		curr;
	unsigned int		length;
	unsigned int		size;
	unsigned int		window;
	bool			wnd_update;
} TfwHPackDTbl;

/**
 * Representation of current HPACK context.
 *
 * @enc_tbl	- table for headers compression;
 * @dec_tbl	- table for headers decompression;
 * @length	- remaining length of decoded string;
 * @max_window	- maximum allowed size for the decoder dynamic table;
 * @curr	- current shift in Huffman decoding context;
 * @hctx	- current Huffman decoding context;
 * @__off	- offset to reinitialize processing context;
 * @offset	- current offset in hpack ht_decode table;
 * @state	- current state;
 * @shift	- current shift, used when integer decoding interrupted due
 *		  to absence of the next fragment;
 * @index	- saved index value, used when decoding is interrupted due to
 *		  absence of the next fragment;
 */
typedef struct {
	TfwHPackETbl		enc_tbl;
	TfwHPackDTbl		dec_tbl;
	unsigned long		length;
	unsigned int		max_window;
	int			curr;
	unsigned short		hctx;
	char			__off[0];
	unsigned short		offset;
	unsigned int		state;
	unsigned int		shift;
	unsigned int		index;
} TfwHPack;

/**
 * Maximum length (in bytes) of HPACK variable-length integer representation,
 * encoded from 64-bit unsigned long integer: one byte for each 7-bit part of
 * source long integer plus on byte for initial prefix.
 */
#define HPACK_MAX_INT						\
	(DIV_ROUND_UP(sizeof(unsigned long), 7) + 1)

typedef struct {
	unsigned int		sz;
	unsigned char		buf[HPACK_MAX_INT];
} TfwHPackInt;


/**
 * Iterator for the message headers decoding from HTTP/2-cache.
 *
 * @h_mods	- pointer to the headers configured to be changed;
 * @skip	- flag to skip particular cached data in order to switch
 *		  between HTTP/2 and HTTP/1.1 resulting representation during
 *		  decoding from HTTP/2-cache;
 * @acc_len	- accumulated length of the resulting headers part of the
 *		  response;
 * @hdr_data	- header's data currently received from cache;
 */
typedef struct {
	TfwHdrMods		*h_mods;
	bool			skip;
	unsigned long		acc_len;
	TfwStr			hdr_data;
} TfwDecodeCacheIter;

void write_int(unsigned long index, unsigned short max, unsigned short mask,
	       TfwHPackInt *__restrict res_idx);
int tfw_hpack_init(TfwHPack *__restrict hp, void *owner, unsigned int htbl_sz);
void tfw_hpack_clean(TfwHPack *__restrict hp);
int tfw_hpack_transform(TfwHttpResp *__restrict resp, TfwStr *__restrict hdr);
int tfw_hpack_encode(TfwHttpResp *__restrict resp, TfwStr *__restrict hdr,
		     bool use_pool, bool dyn_indexing);
void tfw_hpack_set_rbuf_size(TfwHPackETbl *__restrict tbl,
			     unsigned short new_size);
int tfw_hpack_decode(TfwHPack *__restrict hp, unsigned char *__restrict src,
		     unsigned long n, TfwHttpReq *__restrict req,
		     unsigned int *__restrict parsed);
int tfw_hpack_cache_decode_expand(TfwHPack *__restrict hp,
				  TfwHttpResp *__restrict resp,
				  unsigned char *__restrict src, unsigned long n,
				  TfwDecodeCacheIter *__restrict cd_iter);
int tfw_hpack_enc_tbl_write_sz(TfwHPackETbl *__restrict tbl, TfwStream *stream);

static inline unsigned int
tfw_hpack_int_size(unsigned long index, unsigned short max)
{
	unsigned int size = 1;

	if (likely(index < max))
		return size;

	++size;
	index -= max;
	while (index > 0x7F) {
		++size;
		index >>= 7;
	}

	return size;
}
unsigned short tfw_hpack_find_hdr_idx(const TfwStr *hdr);
#endif /* __TFW_HPACK_H__ */
