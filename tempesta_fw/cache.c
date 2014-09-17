/**
 *		Tempesta FW
 *
 * HTTP cache (see RFC 2616).
 * Here is implementation of expiration and validation models and other HTTP
 * specific stuff. The cache is backed by physical storage layer.
 *
 * TODO:
 * 1. Cache-Control, Expires, ETag, Last-Modified, Vary and some other
 *    RFC 2616 HTTP cache control facilities are not supported yet.
 *    RFC 3143 also affects the caching design.
 *
 * 2. Purge cache by individual entities (e.g. curl -X PURGE <URL>)
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/freezer.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>

#include "tdb.h"

#include "tempesta.h"
#include "cache.h"
#include "http_msg.h"

/*
 * @trec	- Database record descriptor.
 * @key_len and @key - the cache enty key (URI + Host header)
 * @hdr_lens	- array of size @hdr_num with all HTTP header lengths
 * @hdrs	- pointer to list of HTTP headers (with trailing CRLFs)
 * @body	- pointer to response body (with a prepending CRLF)
 * @resp	- Linked response if the entry is just created from recent
 * 		  message and NULL if loaded from database.
 *
 * Members from @trec to @body_len are directly written to database file.
 * Data pointers from @key to @body are converted from pointers to offsets
 * on database writing.
 */
typedef struct {
	TdbRecord	trec;
	/* trec.data_len begins from the below. */
	unsigned int	key_len;
	unsigned int	hdr_num;
	unsigned long	body_len;
	/* db direct write bound */
	unsigned char	*key;
	unsigned int	*hdr_lens;
	unsigned char	*hdrs;
	unsigned char	*body;
	/* db conversion bound */
	TfwHttpResp	*resp;
} TfwCacheEntry;

/* Work to copy response body to database. */
typedef struct tfw_cache_work_t {
	struct work_struct	work;
	TfwCacheEntry		*ce;
} TfwCWork;

#define CKEY_SZ			2

static TDB *db;
static struct task_struct *cache_mgr_thr;
static struct workqueue_struct *cache_wq;
static struct kmem_cache *c_cache;

/**
 * Calculates search key for the request URI and Host header.
 */
static void
tfw_cache_key_calc(TfwHttpReq *req, unsigned long *key)
{
	/*
	 * TODO: do we need so long key?
	 * Aren't 64bit single long not enough?
	 */
}

/**
 * Cache entry key is the request URI + Host header value.
 */
static int
tfw_cache_entry_key_copy(TfwCacheEntry *ce, TfwHttpReq *req)
{
	/*
	 * TODO
	 * We do not need the field in TfwCacheEntry if we use index
	 * like patricia tree. Postpone the code until index is ready.
	 */

	return 0;
}

/**
 * Copies plain TfwStr to TdbRecord.
 * @return number of copied bytes (@src length).
 */
static unsigned int
tfw_cache_copy_str(TdbRecord **trec, TfwStr *src)
{
	unsigned int copied = 0;

	BUG_ON(src->flags & (TFW_STR_COMPOUND | TFW_STR_COMPOUND2));

	while (copied < src->len) {
		size_t n = TDB_REC_ROOM(*trec)
			   ? min(TDB_REC_ROOM(*trec),
				 (size_t)(src->len - copied))
			   : min(TDB_REC_DMAXSZ,
				 (size_t)(src->len - copied));
		char *dst = tdb_entry_add(db, trec, n);
		memcpy(dst, (char *)src->ptr + copied, n);
		copied += n;
	}

	return copied;
}

/**
 * Copies TfwStr (probably compound) to TdbRecord.
 * @return number of copied bytes (@src overall length).
 */
static unsigned int
tfw_cache_copy_str_compound(TdbRecord **trec, TfwStr *src)
{
	int i;
	unsigned int copied = 0;

	if (!(src->flags & TFW_STR_COMPOUND))
		return tfw_cache_copy_str(trec, src);

	for (i = 0; i < src->len; ++i)
		copied += tfw_cache_copy_str(trec, (TfwStr *)src->ptr + i);

	return copied;
}

/**
 * Work to copy response skbs to database mapped area.
 */
static void
tfw_cache_copy_resp(struct work_struct *work)
{
	int i;
	int *p_hlen;
	TdbRecord *trec;
	TfwCWork *cw = (TfwCWork *)work;
	TfwCacheEntry *ce = cw->ce;
	TfwHttpHdrTbl *htbl;

	BUG_ON(!ce->resp);

	/* Get current write position. */
	for (trec = (TdbRecord *)ce; !TDB_REC_ISLAST(trec);
	     trec = TDB_REC_DNEXT(trec))
		;

	/* Write HTTP headers. */
	htbl = ce->resp->h_tbl;
	ce->hdr_num = htbl->size;
	/*
	 * Header length array are always allocated in single page due to
	 * headers number limitation.
	 */
	p_hlen = tdb_entry_add(db, &trec, sizeof(ce->hdr_lens[0])
					  * ce->hdr_num);
	/* Set start of headers pointer just after array of header lengthh. */
	ce->hdrs = tdb_get_next_data_ptr(db, &trec);
	for (i = 0; i < ce->hdr_num; ++i) {
		TfwStr *hdr = &htbl->tbl[i].field;
		p_hlen[i] = tfw_cache_copy_str_compound(&trec, hdr);
	}

	/* Write HTTP response body. */
	ce->body = tdb_get_next_data_ptr(db, &trec);
	ce->body_len += tfw_cache_copy_str_compound(&trec, &ce->resp->body);

	kmem_cache_free(c_cache, cw);
}

void
tfw_cache_add(TfwHttpResp *resp, TfwHttpReq *req)
{
	TfwCWork *cw;
	TfwCacheEntry *ce;
	unsigned long key[CKEY_SZ];

	if (!tfw_cfg.cache)
		return;

	tfw_cache_key_calc(req, key);

	ce = (TfwCacheEntry *)tdb_entry_create(db, key, sizeof(*ce));
	if (!ce)
		return;

	ce->resp = resp;

	/*
	 * We must write the entry key now because the request dies
	 * when the function finishes.
	 */
	if (tfw_cache_entry_key_copy(ce, req))
		return;

	cw = kmem_cache_alloc(c_cache, GFP_ATOMIC);
	if (!cw)
		return;
	INIT_WORK(&cw->work, tfw_cache_copy_resp);
	cw->ce = ce;
	queue_work(cache_wq, (struct work_struct *)cw);
}

#define SKB_HDR_SZ	(MAX_HEADER + sizeof(struct ipv6hdr)		\
			 + sizeof(struct tcphdr))

/**
 * Build ce->resp and ce->resp->msg that it can be sent via TCP socket.
 *
 * Cache entry data is set as paged fragments of skb.
 * See do_tcp_sendpages() as reference.
 *
 * We return skbs in the cache entry response w/o setting any
 * network headers - tcp_transmit_skb() will do it for us.
 */
static int
tfw_cache_build_resp(TfwCacheEntry *ce)
{
	int f;
	TdbRecord *trec;
	unsigned char *data;
	struct sk_buff *skb = NULL;

	/*
	 * Allocated response won't be checked by any filters and
	 * is used for sending response data only, so don't initialize
	 * connection and GFSM fields.
	 */
	ce->resp = (TfwHttpResp *)tfw_http_msg_alloc(Conn_Srv);
	if (!ce->resp)
		return -ENOMEM;

	trec = TDB_REC_FROM_PTR(ce->hdrs);
	data = ce->hdrs;
	while (1) {
		int off, size = trec->d_len;

		if (!skb || f == MAX_SKB_FRAGS) {
			/* Protocol headers are placed in linear data only. */
			skb = alloc_skb(SKB_HDR_SZ, GFP_ATOMIC);
			if (!skb)
				goto err_skb;
			skb_reserve(skb, SKB_HDR_SZ);
			ss_skb_queue_tail(&ce->resp->msg.skb_list, skb);
			f = 0;
		}

		off = (unsigned long)data & ~PAGE_MASK;
		size -= off - sizeof(*trec);

		skb_fill_page_desc(skb, f, virt_to_page(data), off, size);

		if (TDB_REC_ISLAST(trec))
			break;
		trec = TDB_REC_DNEXT(trec);
		data = trec->data;
		++f;
	}

	return 0;
err_skb:
	tfw_http_msg_free((TfwHttpMsg *)ce->resp);
	return -ENOMEM;
}

TfwHttpResp *
tfw_cache_lookup(TfwHttpReq *req)
{
	TfwCacheEntry *ce;
	unsigned long key[CKEY_SZ];

	if (!tfw_cfg.cache)
		return NULL;

	tfw_cache_key_calc(req, key);

	ce = tdb_lookup(db, key);
	if (!ce)
		return NULL;

	if (ce->resp)
		/* Already assembled response. */
		return ce->resp;

	if (tfw_cache_build_resp(ce))
		return NULL;

	return ce->resp;
}

/**
 * Cache management thread.
 * The thread loads and preprcess static Web content using inotify (TODO).
 */
static int
tfw_cache_mgr(void *arg)
{
	do {
		/*
		 * TODO wait while the thread is propagating disk Web data
		 * to the cache when the server starts.
		 */

		if (!freezing(current)) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
			__set_current_state(TASK_RUNNING);
		}
		else
			try_to_freeze();
	} while (!kthread_should_stop());

	return 0;
}

int __init
tfw_cache_init(void)
{
	int r = 0;

	if (!tfw_cfg.cache)
		return 0;

	db = tdb_open(tfw_cfg.c_path, tfw_cfg.c_size,
		      TDB_IDX_TREE, CKEY_SZ, TDB_EVC_LRU);
	if (!db)
		return 1;

	cache_mgr_thr = kthread_run(tfw_cache_mgr, NULL, "tfw_cache_mgr");
	if (IS_ERR(cache_mgr_thr)) {
		r = PTR_ERR(cache_mgr_thr);
		TFW_ERR("Can't start cache manager, %d\n", r);
		goto err_thr;
	}

	c_cache = KMEM_CACHE(tfw_cache_work_t, 0);
	if (!c_cache)
		goto err_cache;

	cache_wq = create_singlethread_workqueue("tfw_cache_wq");
	if (!cache_wq)
		goto err_wq;

	return 0;
err_wq:
	kmem_cache_destroy(c_cache);
err_cache:
	kthread_stop(cache_mgr_thr);
err_thr:
	tdb_close(db);
	return r;
}

void
tfw_cache_exit(void)
{
	if (!tfw_cfg.cache)
		return;

	destroy_workqueue(cache_wq);
	kmem_cache_destroy(c_cache);
	kthread_stop(cache_mgr_thr);
	tdb_close(db);
}
