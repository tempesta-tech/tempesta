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
#ifndef __TFW_HPACK_H__
#define __TFW_HPACK_H__

/**
 * Default allowed size for dynamic tables (in bytes). Note, that for encoder's
 * dynamic table - this is also the maximum allowed size and the maximum storage
 * (ring buffer) size.
 */
#define HPACK_TABLE_DEF_SIZE		4096
#define HPACK_ENC_TABLE_MAX_SIZE	HPACK_TABLE_DEF_SIZE

/**
 * Red-black tree node representation in the ring buffer.
 * Note, that the most significant bit of @hdr_len is used for RB Tree color
 * attribute; this is possible because the maximum size of encoder dynamic
 * index is 4096 bytes and, consequently, the maximum size of stored header
 * must be not greater than (4096 - 32) bytes which is less then 32768
 * (0x7FFF - the half of unsigned short capacity) - thus, we can additionally
 * use the most significant bit.
 *
 * @rindex	- index (in reverse form) of stored header string in the
 *		  encoder dynamic table;
 * @hdr_len	- length of stored header string;
 * @parent	- parent node offset in the ring buffer (in bytes);
 * @left	- left child offset in the ring buffer (in bytes);
 * @right	- right child offset in the ring buffer (in bytes);
 * @hdr		- pointer to header string.
 */
typedef struct {
	unsigned long		rindex;
	unsigned short		hdr_len;
	short			parent;
	short			left;
	short			right;
	char			hdr[0];
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
 * @rbuf	- pointer to the ring buffer;
 * @root	- pointer to the root node of binary tree;
 * @pool	- memory pool for dynamic table;
 * @idx_acc	- current accumulated index, intended for real indexes
 *		  calculation;
 * @guard	- atomic protection against races during entries
 *		  addition/eviction in encoder dynamic index;
 * @lock	- spinlock to synchronize concurrent access to encoder index.
 */
typedef struct {
	TFW_HPACK_ETBL_COMMON;
	unsigned short		window;
	char			*rbuf;
	TfwHPackNode		*root;
	TfwPool			*pool;
	unsigned long		idx_acc;
	atomic64_t		guard;
	spinlock_t		lock;
} TfwHPackETbl;

/**
 * Auxiliary iterator for operations on a dynamic encoder table.
 */
typedef struct {
	TFW_HPACK_ETBL_COMMON;
} TfwHPackETblIter;

/**
 * HPack strings representation.
 *
 * @ptr		- pointer to the actual string data;
 * @len		- length of the string;
 * @count	- number of users of the string instance.
 */
typedef struct {
	char			*ptr;
	unsigned long		len;
	int			count;
} TfwHPackStr;

/**
 * Representation of the entry in HPack decoder index.
 *
 * @name	- name of the indexed header;
 * @value	- value of the indexed header;
 * @tag		- ID of the indexed header.
 */
typedef struct {
	TfwHPackStr		*name;
	TfwHPackStr		*value;
	long			tag;
} TfwHPackEntry;

/**
 * HPack decoder dynamic index table.
 *
 * @entries	- dynamic table of entries;
 * @pool	- memory pool for dynamic table;
 * @n		- actual number of entries in the table;
 * @curr	- circular buffer index of recent entry;
 * @length	- current length of the dynamic table (in entries);
 * @size	- current pseudo-length of the dynamic headers table (in bytes);
 * @window	- maximum pseudo-length of the dynamic table (in bytes); this
 *		  value used as threshold to flushing old entries;
 */
typedef struct {
	TfwHPackEntry		*entries;
	TfwPool			*pool;
	unsigned int		n;
	unsigned int		curr;
	unsigned int		length;
	unsigned int		size;
	unsigned int		window;
} TfwHPackDTbl;

/**
 * Representation of current HPACK context.
 *
 * @enc_tbl	- table for headers compression;
 * @dec_tbl	- table for headers decompression;
 * @length	- remaining length of decoded string;
 * @max_window	- maximum allowed dynamic table size;
 * @curr	- current shift in Huffman decoding context;
 * @hctx	- current Huffman decoding context;
 * @__off	- offset to reinitialize processing context;
 * @state	- current state;
 * @shift	- current shift, used when integer decoding interrupted due
 *		  to absence of the next fragment;
 * @index	- saved index value, used when decoding is interrupted due to
 *		  absence of the next fragment;
 * @entry	- index entry found in context of currently parsed header.
 */
typedef struct {
	TfwHPackETbl		enc_tbl;
	TfwHPackDTbl		dec_tbl;
	unsigned long		length;
	unsigned int		max_window;
	int			curr;
	unsigned short		hctx;
	char			__off[0];
	unsigned int		state;
	unsigned int		shift;
	unsigned long		index;
	const TfwHPackEntry	*entry;
} TfwHPack;

#define	BUFFER_GET(len, it)					\
do {								\
	BUG_ON(!(len));						\
	WARN_ON_ONCE((it)->rspace);				\
	(it)->rspace = len;					\
	(it)->pos = tfw_pool_alloc_na((it)->pool, len);		\
	T_DBG3("%s: get buffer, len=%lu, it->pos=[%p],"		\
	       " it->pos=%lu\n", __func__, (unsigned long)len,	\
	       (it)->pos, (unsigned long)(it)->pos);		\
} while (0)

int tfw_hpack_init(TfwHPack *__restrict hp, unsigned int htbl_sz);
void tfw_hpack_clean(TfwHPack *__restrict hp);
int tfw_hpack_hdrs_transform(TfwHttpResp *__restrict resp, bool *entered);
int tfw_hpack_decode(TfwHPack *__restrict hp, const unsigned char *src,
		     unsigned long n, TfwHttpReq *__restrict req,
		     unsigned int *__restrict parsed);

#endif /* __TFW_HPACK_H__ */
