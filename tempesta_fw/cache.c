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
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#include <linux/topology.h>
#include <linux/workqueue.h>

#include "tdb.h"

#include "tempesta_fw.h"
#include "cache.h"
#include "http_msg.h"
#include "lib.h"

/*
 * @trec	- Database record descriptor.
 * @key		- the cache enty key (URI + Host header)
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
	TdbVRec		trec;
	/* TDB record body begins from the below. */
	unsigned int	hdr_num;
	unsigned int	key_len;
	unsigned long	body_len;
	/* db direct write bound */
	char		*key;
	unsigned int	*hdr_lens;
	char		*hdrs;
	char		*body;
	/* db conversion bound */
	TfwHttpResp	*resp;
} TfwCacheEntry;

/* Work to copy response body to database. */
typedef struct tfw_cache_work_t {
	struct work_struct	work;
	union {
		TfwCacheEntry			*ce;
		struct {
			TfwHttpReq		*req;
			tfw_http_req_cache_cb_t	action;
			void			*data;
			unsigned long		key;
		} _r;
	} _u;
#define cw_ce	_u.ce
#define cw_req	_u._r.req
#define cw_act	_u._r.action
#define cw_data	_u._r.data
#define cw_key	_u._r.key
} TfwCWork;

static TDB *db;
static struct task_struct *cache_mgr_thr;
static struct workqueue_struct *cache_wq;
static struct kmem_cache *c_cache;

static struct {
	bool cache;
	unsigned int db_size;
	const char *db_path;
} cache_cfg __read_mostly;


/**
 * Calculates search key for the request URI and Host header.
 */
static unsigned long
tfw_cache_key_calc(TfwHttpReq *req)
{
	return tfw_http_req_key_calc(req);
}

/**
 * Cache entry key is the request URI + Host header value.
 */
static int
tfw_cache_entry_key_copy(TfwCacheEntry *ce, TfwHttpReq *req)
{
	return 0;
}

/**
 * Get NUMA node by the cache key.
 */
static int
tfw_cache_key_node(unsigned long key)
{
	/* TODO distribute keys among NUMA nodes. */
	return numa_node_id();
}

/**
 * Get a CPU identifier from @node to schedule a work.
 */
static int
tfw_cache_sched_work_cpu(int node)
{
	/* TODO schedule the CPU */
	return smp_processor_id();
}

/**
 * Copies plain TfwStr to TdbRec.
 * @return number of copied bytes (@src length).
 *
 * The function copies part of some large data of length @tot_len,
 * so it tries to minimizae total number of allocations regardles
 * how many chunks are copied.
 */
static long
tfw_cache_copy_str(char **p, TdbVRec **trec, TfwStr *src, size_t tot_len)
{
	long copied = 0;

	while (copied < src->len) {
		int room = (char *)(*trec + 1) + (*trec)->len - *p;
		BUG_ON(room < 0);
		if (!room) {
			BUG_ON(tot_len < copied);
			*trec = tdb_entry_add(db, *trec, tot_len - copied);
			if (!*trec)
				return -ENOMEM;
			*p = (char *)(*trec + 1);
			room = (*trec)->len;
		}
		room = min((long)room, src->len - copied);
		memcpy(p, (char *)src->ptr + copied, room);
		*p += room;
		copied += room;
	}

	return copied;
}

/**
 * Copies TfwStr (probably compound) to TdbRec.
 * @return number of copied bytes (@src overall length).
 */
static long
tfw_cache_copy_str_compound(char **p, TdbVRec **trec, TfwStr *src,
			    size_t tot_len)
{
	int i;
	long copied = 0;

	BUG_ON(!tot_len);

	if (TFW_STR_PLAIN(src))
		return tfw_cache_copy_str(p, trec, src, tot_len);

	for (i = 0; i < TFW_STR_CHUNKN(src); ++i) {
		long n = tfw_cache_copy_str(p, trec, (TfwStr *)src->ptr + i,
					    tot_len - copied);
		if (n < 0)
			return n;
		copied += n;
		BUG_ON(tot_len < copied);
	}

	return copied;
}

/**
 * Copies TfwStr (probably compound and duplicate) to TdbRec.
 * @return number of copied bytes (@src overall length).
 */
static long
tfw_cache_copy_str_duplicate(char **p, TdbVRec **trec, TfwStr *src,
			     size_t tot_len)
{
	int i;
	long copied = 0;

	BUG_ON(!tot_len);

	if (!(src->flags & TFW_STR_DUPLICATE))
		return tfw_cache_copy_str_compound(p, trec, src, tot_len);

	for (i = 0; i < TFW_STR_CHUNKN(src); ++i) {
		long n = tfw_cache_copy_str_compound(p, trec,
						     (TfwStr *)src->ptr + i,
						     tot_len - copied);
		if (n < 0)
			return n;
		copied += n;
		BUG_ON(tot_len < copied);
	}

	return copied;
}

/**
 * Work to copy response skbs to database mapped area.
 *
 * It's nasty to copy data on CPU, but we can't use DMA for mmaped file
 * as well as for unaligned memory areas.
 */
static void
tfw_cache_copy_resp(struct work_struct *work)
{
	int i;
	size_t hlens, tot_len;
	long n;
	char *p;
	TfwCWork *cw = (TfwCWork *)work;
	TfwCacheEntry *ce = cw->cw_ce;
	TdbVRec *trec;
	TfwHttpHdrTbl *htbl;
	TfwStr *hdr;

	BUG_ON(!ce->resp);

	/* Write HTTP headers. */
	htbl = ce->resp->h_tbl;
	ce->hdr_num = htbl->size;

	hlens = sizeof(ce->hdr_lens[0]) * ce->hdr_num;
	tot_len = hlens + ce->resp->msg.len;

	/*
	 * Try to place the cached response in single memory chunk.
	 *
	 * Number of HTTP headers is limited by TFW_HTTP_HDR_NUM_MAX while TDB
	 * should be able to allocate an empty page if we issued a large
	 * request. So HTTP header lengths must fit the first allocated data
	 * chunk, also there must be some space for headers and message bodies.
	 */
	trec = tdb_entry_add(db, (TdbVRec *)ce, tot_len);
	if (!trec || trec->len <= hlens) {
		TFW_WARN("Cannot allocate memory to cache HTTP headers."
			 " Probably TDB cache is exhausted.\n");
		goto err;
	}
	p = (char *)(trec + 1) + hlens;
	tot_len -= hlens;

	/*
	 * Set start of headers pointer just after array of
	 * header length.
	 */
	ce->hdrs = p;
	hdr = htbl->tbl;
	for (i = 0; i < hlens / sizeof(ce->hdr_lens[0]); ++i, ++hdr) {
		n = tfw_cache_copy_str_duplicate(&p, &trec, hdr, tot_len);
		if (n < 0) {
			TFW_ERR("Cache: cannot copy HTTP header\n");
			goto err;
		}
		BUG_ON(n > tot_len);
		tot_len -= n;
	}

	/* Write HTTP response body. */
	ce->body = p;
	n = tfw_cache_copy_str_duplicate(&p, &trec, &ce->resp->body, tot_len);
	if (n < 0) {
		TFW_ERR("Cache: cannot copy HTTP body\n");
		goto err;
	}
	ce->body_len = n;

err:
	/* FIXME all allocated TDB blocks are leaked here. */
	kmem_cache_free(c_cache, cw);
}

void
tfw_cache_add(TfwHttpResp *resp, TfwHttpReq *req)
{
	TfwCWork *cw;
	TfwCacheEntry *ce, cdata = {{}};
	unsigned long key;
	size_t len = sizeof(cdata);

	if (!cache_cfg.cache)
		goto out;

	key = tfw_cache_key_calc(req);

	/* TODO copy at least first part of URI here. */

	// FIXME we should not copy cdata->trec to TDB
	ce = (TfwCacheEntry *)tdb_entry_create(db, key, &cdata, &len);
	BUG_ON(len != sizeof(cdata));
	if (!ce)
		goto out;

	ce->resp = resp;

	/*
	 * We must write the entry key now because the request dies
	 * when the function finishes.
	 */
	if (tfw_cache_entry_key_copy(ce, req))
		goto out;

	cw = kmem_cache_alloc(c_cache, GFP_ATOMIC);
	if (!cw)
		goto out;
	INIT_WORK(&cw->work, tfw_cache_copy_resp);
	cw->cw_ce = ce;
	queue_work_on(tfw_cache_sched_work_cpu(numa_node_id()), cache_wq,
		      (struct work_struct *)cw);

out:
	/* Now we don't need the request and the reponse anymore. */
	tfw_http_conn_msg_free((TfwHttpMsg *)req);
	tfw_http_conn_msg_free((TfwHttpMsg *)resp);
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
	int f = 0;
	TdbVRec *trec = &ce->trec;
	char *data;
	struct sk_buff *skb = NULL;

	/*
	 * Allocated response won't be checked by any filters and
	 * is used for sending response data only, so don't initialize
	 * connection and GFSM fields.
	 */
	ce->resp = (TfwHttpResp *)tfw_http_msg_alloc(Conn_Srv);
	if (!ce->resp)
		return -ENOMEM;

	/* Deserialize offsets to pointers. */
	ce->key = TDB_PTR(db->hdr, (unsigned long)ce->key);
	ce->hdr_lens = TDB_PTR(db->hdr, (unsigned long)ce->hdr_lens);
	ce->hdrs = TDB_PTR(db->hdr, (unsigned long)ce->hdrs);
	ce->body = TDB_PTR(db->hdr, (unsigned long)ce->body);

	/* See tfw_cache_copy_resp(). */
	BUG_ON((char *)(trec + 1) + trec->len <= ce->hdrs);

	trec = TDB_PTR(db->hdr, TDB_DI2O(trec->chunk_next));
	for (data = ce->hdrs;
	     (long)trec != (long)db->hdr;
	     trec = TDB_PTR(db->hdr, TDB_DI2O(trec->chunk_next)),
		data = trec->data)
	{
		int off, size = trec->len;

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
		size = (char *)(trec + 1) + trec->len - data;

		skb_fill_page_desc(skb, f, virt_to_page(data), off, size);

		++f;
	}

	return 0;
err_skb:
	tfw_http_msg_free((TfwHttpMsg *)ce->resp);
	return -ENOMEM;
}

static void
__cache_req_process_node(TfwHttpReq *req, unsigned long key,
			 void (*action)(TfwHttpReq *, TfwHttpResp *, void *),
			 void *data)
{
	TfwCacheEntry *ce;
	TfwHttpResp *resp = NULL;

	ce = tdb_rec_get(db, key);
	if (!ce)
		goto finish_req_processing;

	/* TODO process collisions. */

	if (!ce->resp)
		if (tfw_cache_build_resp(ce))
			/*
			 * It seems we have the cache entry,
			 * but there is memory issues.
			 * Try to send send the request to backend in hope
			 * that we have memory when we get an answer.
			 */
			goto finish_req_processing;

	/* We have already assembled response. */
	resp = ce->resp;

finish_req_processing:

	/*
	 * TODO perform the call on original CPU to avoid inter-node
	 * memory transfers.
	 */
	action(req, resp, data);

	if (ce)
		tdb_rec_put(ce);
}

static void
tfw_cache_req_process_node(struct work_struct *work)
{
	TfwCWork *cw = (TfwCWork *)work;
	TfwHttpReq *req = cw->cw_req;
	tfw_http_req_cache_cb_t action = cw->cw_act;
	void *data = cw->cw_data;

	__cache_req_process_node(req, cw->cw_key, action, data);
}

/**
 * Process @req at node which possesses the cached data required to fulfill
 * the request. In worse case the request can be assembled in softirq at
 * one node, the cached response can be prepared at the second node while
 * the final response is sent by third node (see dev_queue_xmit()).
 */
void
tfw_cache_req_process(TfwHttpReq *req, tfw_http_req_cache_cb_t action,
		      void *data)
{
	int node;
	unsigned long key;

	if (!cache_cfg.cache) {
		action(req, NULL, data);
		return;
	}

	key = tfw_cache_key_calc(req);

	node = tfw_cache_key_node(key);
	if (node != numa_node_id()) {
		/*
		 * Schedule the cache entry to the right node.
		 *
		 * TODO work queues are slow, use common kernel threads.
		 * Probably threading should be at TDB side...
		 */
		TfwCWork *cw = kmem_cache_alloc(c_cache, GFP_ATOMIC);
		if (!cw)
			goto process_locally;
		INIT_WORK(&cw->work, tfw_cache_req_process_node);
		cw->cw_req = req;
		cw->cw_act = action;
		cw->cw_data = data;
		cw->cw_key = key;
		queue_work_on(tfw_cache_sched_work_cpu(node), cache_wq,
			      (struct work_struct *)cw);
		return;
	}

process_locally:
	__cache_req_process_node(req, key, action, data);
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

static int
tfw_cache_start(void)
{
	int r = 0;

	if (!cache_cfg.cache)
		return 0;

	/* TODO open db for each node. */
	db = tdb_open(cache_cfg.db_path, cache_cfg.db_size, 0, numa_node_id());
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

	cache_wq = alloc_workqueue("tfw_cache_wq", WQ_MEM_RECLAIM, 0);
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

static void
tfw_cache_stop(void)
{
	if (!cache_cfg.cache)
		return;

	destroy_workqueue(cache_wq);
	kmem_cache_destroy(c_cache);
	kthread_stop(cache_mgr_thr);

	tdb_close(db);
}

static TfwCfgSpec tfw_cache_cfg_specs[] = {
	{
		"cache",
		"on",
		tfw_cfg_set_bool,
		&cache_cfg.cache
	},
	{
		"cache_size",
		"268435456",
		tfw_cfg_set_int,
		&cache_cfg.db_size,
		&(TfwCfgSpecInt) {
			.multiple_of = PAGE_SIZE,
			.range = { PAGE_SIZE, (1 << 30) },
		}
	},
	{
		"cache_db",
		"/opt/tempesta/db/cache.tdb",
		tfw_cfg_set_str,
		&cache_cfg.db_path,
		&(TfwCfgSpecStr) {
			.len_range = { 1, PATH_MAX },
		}
	},
	{}
};

TfwCfgMod tfw_cache_cfg_mod = {
	.name 	= "cache",
	.start	= tfw_cache_start,
	.stop	= tfw_cache_stop,
	.specs	= tfw_cache_cfg_specs,
};
