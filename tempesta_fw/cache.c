/**
 *		Tempesta FW
 *
 * HTTP cache (RFC 7234).
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#include <linux/freezer.h>
#include <linux/irq_work.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>
#include <linux/tcp.h>
#include <linux/topology.h>

#include "tdb.h"

#include "tempesta_fw.h"
#include "cache.h"
#include "http_msg.h"
#include "procfs.h"
#include "ss_skb.h"
#include "work_queue.h"

#if MAX_NUMNODES > ((1 << 16) - 1)
#warning "Please set CONFIG_NODES_SHIFT to less than 16"
#endif

/*
 * @trec	- Database record descriptor;
 * @key_len	- length of key (URI + Host header);
 * @status_len	- length of response satus line;
 * @hdr_num	- numbder of headers;
 * @hdr_len	- length of whole headers data;
 * @key		- the cache enty key (URI + Host header);
 * @status	- pointer to status line  (with trailing CRLFs);
 * @hdrs	- pointer to list of HTTP headers (with trailing CRLFs);
 * @body	- pointer to response body (with a prepending CRLF);
 */
typedef struct {
	TdbVRec		trec;
#define ce_body		key_len
	unsigned int	key_len;
	unsigned int	status_len;
	unsigned int	hdr_num;
	unsigned int	hdr_len;
	long		key;
	long		status;
	long		hdrs;
	long		body;
} TfwCacheEntry;

/**
 * String header for cache entries used for TfwStr serialization.
 *
 * @flags	- only TFW_STR_DUPLICATE or zero;
 * @len		- string length or number of duplicates;
 */
typedef struct {
	unsigned long	flags : 8,
			len : 56;
} TfwCStr;

#define TFW_CSTR_MAXLEN		(1UL << 56)
#define TFW_CSTR_HDRLEN		(sizeof(TfwCStr))

/* Work to copy response body to database. */
typedef struct {
	TfwHttpReq		*req;
	TfwHttpResp		*resp;
	tfw_http_cache_cb_t	action;
	unsigned long		key;
} TfwCWork;

typedef struct {
	struct tasklet_struct	tasklet;
	struct irq_work		ipi_work;
	TfwRBQueue		wq;
} TfwWorkTasklet;

static struct {
	int cache;
	unsigned int db_size;
	const char *db_path;
} cache_cfg __read_mostly;

/* Cache modes. */
enum {
	TFW_CACHE_NONE = 0,
	TFW_CACHE_SHARD,
	TFW_CACHE_REPLICA,
};

/*
 * Non-cacheable hop-by-hop response headers in terms of RFC 2068.
 * The table is used if server doesn't specify Cache-Control no-cache
 * directive (RFC 7234 5.2.2.2) explicitly.
 *
 * Server header isn't defined as hop-by-hop by the RFC, but we don't show
 * protected server to world.
 *
 * We don't store the headers in cache and create then from scratch.
 * Adding a header is faster then modify it, so this speeds up headers
 * adjusting as well as saves cache storage.
 *
 * TODO process Cache-Control no-cache
 */
static const int hbh_hdrs[] = {
	[0 ... TFW_HTTP_HDR_RAW]	= 0,
        [TFW_HTTP_HDR_SERVER]		= 1,
	[TFW_HTTP_HDR_CONNECTION]	= 1,
};

static struct {
	int	cpu;
	TDB	*db;
} c_nodes[MAX_NUMNODES] __read_mostly;

static struct task_struct *cache_mgr_thr;
static DEFINE_PER_CPU(TfwWorkTasklet, cache_wq);

static TfwStr g_crlf = { .ptr = S_CRLF, .len = SLEN(S_CRLF) };

/* Iterate over request URI and Host header to process request key. */
#define TFW_CACHE_REQ_KEYITER(c, req, u_end, h_start, h_end)		\
	if (TFW_STR_PLAIN(&req->uri_path)) {				\
		c = &req->uri_path;					\
		u_end = &req->uri_path + 1;				\
	} else {							\
		c = req->uri_path.ptr;					\
		u_end = (TfwStr *)req->uri_path.ptr			\
			+ TFW_STR_CHUNKN(&req->uri_path);		\
	}								\
	if (TFW_STR_PLAIN(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST])) {	\
		h_start = req->h_tbl->tbl + TFW_HTTP_HDR_HOST;		\
		h_end = req->h_tbl->tbl + TFW_HTTP_HDR_HOST + 1;	\
	} else {							\
		h_start = req->h_tbl->tbl[TFW_HTTP_HDR_HOST].ptr;	\
		h_end = (TfwStr *)req->h_tbl->tbl[TFW_HTTP_HDR_HOST].ptr \
			+ TFW_STR_CHUNKN(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST]);\
	}								\
	for ( ; c != h_end; ++c, c = (c == u_end) ? h_start : c)

static bool
tfw_cache_entry_key_eq(TDB *db, TfwHttpReq *req, TfwCacheEntry *ce)
{
	/* Record key starts at first data chunk. */
	int n, c_off = 0, t_off;
	TdbVRec *trec = &ce->trec;
	TfwStr *c, *h_start, *u_end, *h_end;

	if (req->uri_path.len + req->h_tbl->tbl[TFW_HTTP_HDR_HOST].len
	    != ce->key_len)
		return false;

	t_off = sizeof(*ce) - offsetof(TfwCacheEntry, ce_body);
	TFW_CACHE_REQ_KEYITER(c, req, u_end, h_start, h_end) {
		if (!trec)
			return false;
this_chunk:
		n = min(c->len - c_off, (unsigned long)trec->len - t_off);
		if (strncasecmp((char *)c->ptr + c_off, trec->data + t_off, n))
			return false;
		if (n == c->len - c_off) {
			c_off = 0;
		} else {
			c_off += n;
		}
		if (n == trec->len - t_off) {
			t_off = 0;
			trec = tdb_next_rec_chunk(db, trec);
			if (trec && c_off)
				goto this_chunk;
		} else {
			t_off += n;
		}
	}

	return true;
}

/**
 * Get NUMA node by the cache key.
 * The function gives different results if number of nodes changes,
 * e.g. due to hot-plug CPU. Cache eviction restores memory acquired by
 * inaccessible entries. The event of new/dead CPU is rare, so there is
 * no sense to use expensive rendezvous hashing.
 */
static unsigned short
tfw_cache_key_node(unsigned long key)
{
	return key % num_online_nodes();
}

/**
 * Just choose any CPU for each node to use queue_work_on() for
 * nodes scheduling. Reserve 0th CPU for other tasks.
 */
static void
tfw_init_node_cpus(void)
{
	int cpu, node;

	for_each_online_cpu(cpu) {
		node = cpu_to_node(cpu);
		if (!c_nodes[node].cpu)
			c_nodes[node].cpu = cpu;
	}
}

static TDB *
node_db(void)
{
	return c_nodes[numa_node_id()].db;
}

/**
 * Get a CPU identifier from @node to schedule a work.
 * TODO do better CPU scheduling
 */
static int
tfw_cache_sched_cpu(TfwHttpReq *req)
{
	return c_nodes[req->node].cpu;
}

static void
tfw_cache_str_write_hdr(const TfwStr *str, char *p)
{
	TfwCStr *s = (TfwCStr *)p;

	if (TFW_STR_DUP(str)) {
		s->flags = TFW_STR_DUPLICATE;
		s->len = TFW_STR_CHUNKN(str);
	} else {
		s->flags = 0;
		s->len = str->len ? str->len + SLEN(S_CRLF) : 0;
	}
}

/**
 * Copies plain TfwStr @src to TdbRec @trec.
 * @return number of copied bytes (@src length).
 *
 * The function copies part of some large data of length @tot_len,
 * so it tries to minimize total number of allocations regardles
 * how many chunks are copied.
 */
static long
tfw_cache_strcpy(char **p, TdbVRec **trec, TfwStr *src, size_t tot_len)
{
	long copied = 0;

	while (copied < src->len) {
		int room = (*trec)->data + (*trec)->len - *p;
		BUG_ON(room < 0);
		if (!room) {
			BUG_ON(tot_len < copied);
			*trec = tdb_entry_add(node_db(), *trec,
					      tot_len - copied);
			if (!*trec)
				return -ENOMEM;
			*p = (*trec)->data;
			room = (*trec)->len;
		}

		TFW_DBG3("Cache: copy [%.*s](%lu) to rec=%p(len=%u, next=%u),"
			 " p=%p tot_len=%lu room=%d copied=%ld\n",
			 PR_TFW_STR(src), src->len, *trec, (*trec)->len,
			 (*trec)->chunk_next, *p, tot_len, room, copied);

		room = min((unsigned long)room, src->len - copied);
		memcpy(*p, (char *)src->ptr + copied, room);
		*p += room;
		copied += room;
	}

	return copied;
}

/**
 * Copies plain or compound (chunked) TfwStr @src to TdbRec @trec may be
 * appending EOL marker at the end.
 *
 * @src is copied (possibly with EOL appended)
 * @return number of copied bytes on success and negative value otherwise.
 */
static long
tfw_cache_copy_str(char **p, TdbVRec **trec,
		   TfwStr *src, size_t *tot_len, bool eol)
{
	long n, copied = 0;
	TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(src));

	TFW_STR_FOR_EACH_CHUNK(c, src, end) {
		if ((n = tfw_cache_strcpy(p, trec, c, *tot_len)) < 0) {
			TFW_ERR("Cache: cannot copy chunk of string\n");
			return -ENOMEM;
		}
		*tot_len -= n;
		copied += n;
	}

	if (eol) {
		if ((n = tfw_cache_strcpy(p, trec, &g_crlf, *tot_len)) < 0)
			return -ENOMEM;
		BUG_ON(n != SLEN(S_CRLF));
		*tot_len -= n;
		copied += n;
	}

	return copied;
}

/**
 * Deep HTTP header copy to TdbRec.
 * @src is copied in depth first fashion to speed up upcoming scans.
 * @return number of copied bytes on success and negative value otherwise.
 */
static long
tfw_cache_copy_hdr(char **p, TdbVRec **trec, TfwStr *src, size_t *tot_len)
{
	long n = sizeof(TfwCStr), copied;
	TfwStr *dup, *dup_end;

	if (unlikely(src->len >= TFW_CSTR_MAXLEN)) {
		TFW_WARN("Cache: trying to store too big string %lx\n",
			 src->len);
		return -E2BIG;
	}
	/* Don't split short strings. */
	if (likely(!TFW_STR_DUP(src))
	    && sizeof(TfwCStr) + src->len <= L1_CACHE_BYTES)
		n += src->len;

	*p = tdb_entry_get_room(node_db(), trec, *p, n, *tot_len);
	if (!*p) {
		TFW_WARN("Cache: cannot allocate TDB space\n");
		return -ENOMEM;
	}
	tfw_cache_str_write_hdr(src, *p);
	*p += TFW_CSTR_HDRLEN;
	*tot_len -= TFW_CSTR_HDRLEN;
	copied = TFW_CSTR_HDRLEN;

	/*
	 * Place empty strings for absent headers to
	 * properly restore heanders table.
	 */
	if (!src->len)
		return copied;

	if (TFW_STR_PLAIN(src))
		return tfw_cache_copy_str(p, trec, src, tot_len, 1);

	TFW_STR_FOR_EACH_DUP(dup, src, dup_end) {
		if (dup != src) {
			tfw_cache_str_write_hdr(dup, *p);
			*p += TFW_CSTR_HDRLEN;
			*tot_len -= TFW_CSTR_HDRLEN;
			copied += TFW_CSTR_HDRLEN;
		}
		if ((n = tfw_cache_copy_str(p, trec, dup, tot_len, 1)) < 0)
			return n;
		copied += n;
	}

	return copied;
}

/**
 * Copy response skbs to database mapped area.
 * @tot_len - total length of actual data to write w/o TfwCStr's etc.
 *
 * It's nasty to copy data on CPU, but we can't use DMA for mmaped file
 * as well as for unaligned memory areas.
 *
 * TODO Store the cache entries as a templates with placeholders for
 * changeable headers. That we can faster build the final answers instead
 * of adjusting skb's.
 */
static int
tfw_cache_copy_resp(TfwCacheEntry *ce, TfwHttpResp *resp, TfwHttpReq *req,
		    size_t tot_len)
{
	long n;
	char *p;
	TdbVRec *trec = &ce->trec;
	TDB *db = node_db();
	TfwStr *field, *h, *end1, *end2, empty = {};

	/* Write record key (URI + Host header). */
	p = (char *)(ce + 1);
	ce->key = TDB_OFF(db->hdr, p);
	ce->key_len = 0;
	TFW_CACHE_REQ_KEYITER(field, req, end1, h, end2) {
		if ((n = tfw_cache_strcpy(&p, &trec, field, tot_len)) < 0) {
			TFW_ERR("Cache: cannot copy request key\n");
			return -ENOMEM;
		}
		BUG_ON(n > tot_len);
		tot_len -= n;
		ce->key_len += n;
	}

	ce->status = TDB_OFF(db->hdr, p);
	if ((n = tfw_cache_copy_str(&p, &trec, &resp->s_line, &tot_len, 1)) < 0) {
		TFW_ERR("Cache: cannot copy HTTP status line\n");
		return -ENOMEM;
	}
	ce->status_len += n;

	ce->hdrs = TDB_OFF(db->hdr, p);
	ce->hdr_len = 0;
	ce->hdr_num = resp->h_tbl->off;
	FOR_EACH_HDR_FIELD(field, end1, resp) {
		n = field - resp->h_tbl->tbl;
		/* Skip hop-by-hop headers. */
		h = (n < TFW_HTTP_HDR_RAW && hbh_hdrs[n]) ? &empty : field;
		n = tfw_cache_copy_hdr(&p, &trec, h, &tot_len);
		if (n < 0) {
			TFW_ERR("Cache: cannot copy HTTP header\n");
			return -ENOMEM;
		}
		ce->hdr_len += n;
	}

	/* Write HTTP response body. */
	ce->body = TDB_OFF(db->hdr, p);
	tot_len = resp->body.len;
	if ((n = tfw_cache_copy_str(&p, &trec, &resp->body, &tot_len, 0)) < 0) {
		TFW_ERR("Cache: cannot copy HTTP body\n");
		return -ENOMEM;
	}
	BUG_ON(tot_len);

	TFW_DBG("Cache copied msg: content-length=%lu msg_len=%lu, ce=%p"
		" (len=%u key_len=%u status_len=%u hdr_num=%u hdr_len=%u"
		" key_off=%ld status_off=%ld hdrs_off=%ld body_off=%ld)",
		resp->content_length, resp->msg.len, ce, ce->trec.len,
		ce->key_len, ce->status_len, ce->hdr_num, ce->hdr_len,
		ce->key, ce->status, ce->hdrs, ce->body);

	return 0;
}

static void
__cache_add_node(TDB *db, TfwHttpResp *resp, TfwHttpReq *req,
		 unsigned long key)
{
	TfwCacheEntry *ce, cdata = {{}};
	size_t data_len = sizeof(*ce) + req->uri_path.len
			  + req->h_tbl->tbl[TFW_HTTP_HDR_HOST].len
			  + sizeof(TfwCStr) * resp->h_tbl->off
			  + resp->msg.len;
	size_t len = data_len;

	/*
	 * Try to place the cached response in single memory chunk.
	 * TDB should provide enough space to place at least head of
	 * the record key at first chunk.
	 */
	ce = (TfwCacheEntry *)tdb_entry_create(db, key, &cdata.ce_body, &len);
	BUG_ON(len <= sizeof(cdata));
	if (!ce)
		return;

	TFW_DBG3("cache db=%p resp=%p/req=%p/ce=%p: alloc_len=%lu\n",
		 db, resp, req, ce, len);

	if (tfw_cache_copy_resp(ce, resp, req, data_len)) {
		/* TODO delete the probably partially built TDB entry. */
	}

}

/**
 * @return false (i.e. don't reuse socket buffers)
 * if @resp is needed for caching.
 */
bool
tfw_cache_add(TfwHttpResp *resp, TfwHttpReq *req)
{
	unsigned long key;

	if (!cache_cfg.cache)
		return true;

	key = tfw_http_req_key_calc(req);

	if (cache_cfg.cache == TFW_CACHE_SHARD) {
		__cache_add_node(node_db(), resp, req, key);
	} else {
		int nid;
		/*
		 * TODO probably it's better to do this in TDB per-node threads
		 * rather than in softirq...
		 */
		for_each_node_with_cpus(nid)
			__cache_add_node(c_nodes[nid].db, resp, req, key);
	}

	/*
	 * Cache population is synchronous now, change the return value
	 * depending on the TODO above.
	 */
	return true;
}

static void
tfw_cache_ipi(struct irq_work *work)
{
	TfwWorkTasklet *ct = container_of(work, TfwWorkTasklet, ipi_work);

	tasklet_schedule(&ct->tasklet);
}

int
tfw_cache_process(TfwHttpReq *req, TfwHttpResp *resp,
		  tfw_http_cache_cb_t action)
{
	int cpu;
	TfwWorkTasklet *ct;
	TfwCWork cw;

	if (!cache_cfg.cache) {
		action(req, resp);
		return 0;
	}

	cw.req = req;
	cw.resp = resp;
	cw.action = action;
	cw.key = tfw_http_req_key_calc(req);
	req->node = (cache_cfg.cache == TFW_CACHE_SHARD)
		    ? tfw_cache_key_node(cw.key)
		    : numa_node_id();
	cpu = tfw_cache_sched_cpu(req);
	ct = &per_cpu(cache_wq, cpu);

	TFW_DBG2("Cache: schedule tasklet w/ work: to_cpu=%d from_cpu=%d"
		 " req=%p resp=%p key=%lx\n", cpu, smp_processor_id(),
		 cw.req, cw.resp, cw.key);

	return tfw_wq_push(&ct->wq, &cw, cpu, &ct->ipi_work, tfw_cache_ipi);
}

static int
tfw_cache_write_field(TDB *db, TdbVRec **trec, TfwHttpResp *resp,
		      TfwMsgIter *it, char **data, size_t len, TfwStr *hdr)
{
	int r, copied = 0;
	TdbVRec *tr = *trec;
	TfwStr c = { 0 };

	while (1)  {
		c.ptr = *data;
		c.len = min(tr->data + tr->len - *data,
			    (long)(len - copied));
		r = tfw_http_msg_add_data(it, (TfwHttpMsg *)resp, hdr, &c);
		if (r)
			return r;

		copied += c.len;
		*data += c.len;
		if (copied == hdr->len)
			break;

		tr = *trec = tdb_next_rec_chunk(db, tr);
		BUG_ON(!tr);
		*data = tr->data;
	}

	return 0;
}

/**
 * Write HTTP header to skb data.
 * The headers are likely to be adjusted, so copy them.
 */
static int
tfw_cache_build_resp_hdr(TDB *db, TfwHttpResp *resp, TfwStr *hdr,
			 TdbVRec **trec, TfwMsgIter *it, char **p)
{
	int r, d, dn;
	TfwStr *dups;
	TfwCStr *s = (TfwCStr *)*p;

	*p += TFW_CSTR_HDRLEN;
	BUG_ON(*p > (*trec)->data + (*trec)->len);

	if (likely(!(s->flags & TFW_STR_DUPLICATE)))
		return tfw_cache_write_field(db, trec, resp, it, p, s->len,
					     hdr);

	/* Process duplicated headers. */
	dn = s->len;
	dups = tfw_pool_alloc(resp->pool, dn * sizeof(TfwStr));
	if (!dups)
		return -ENOMEM;

	for (d = 0; d < dn; ++d) {
		s = (TfwCStr *)*p;
		BUG_ON(s->flags);
		dups[d].len = s->len;
		dups[d].flags = s->flags;
		*p += TFW_CSTR_HDRLEN;
		if ((r = tfw_cache_write_field(db, trec, resp, it, p, s->len,
					       hdr)))
			return r;
	}

	return 0;
}

/**
 * Build the message body as paged fragments of skb.
 * See do_tcp_sendpages() as reference.
 */
static int
tfw_cache_build_resp_body(TDB *db, TfwHttpResp *resp, TdbVRec *trec,
			  TfwMsgIter *it, char *p)
{
	int off, f_size;
	skb_frag_t *frag;

	BUG_ON(!it->skb);
	frag = &skb_shinfo(it->skb)->frags[it->frag];
	if (skb_frag_size(frag))
		++it->frag;
	if (it->frag >= MAX_SKB_FRAGS - 1) {
		if (!(it->skb = ss_skb_alloc()))
			return -ENOMEM;
		ss_skb_queue_tail(&resp->msg.skb_list, it->skb);
		it->frag = 0;
	}

	while (1) {
		if (it->frag == MAX_SKB_FRAGS) {
			if (!(it->skb = ss_skb_alloc()))
				return -ENOMEM;
			ss_skb_queue_tail(&resp->msg.skb_list, it->skb);
			it->frag = 0;
		}

		/* TDB keeps data by pages and we can reuse the pages. */
		off = (unsigned long)p & ~PAGE_MASK;
		f_size = trec->data + trec->len - p;
		if (f_size) {
			skb_fill_page_desc(it->skb, it->frag, virt_to_page(p),
					   off, f_size);
			skb_frag_ref(it->skb, it->frag);
			ss_skb_adjust_data_len(it->skb, f_size);
		} else {
			p = NULL;
		}
		if (__tfw_http_msg_add_data_ptr((TfwHttpMsg *)resp,
						&resp->body, p, f_size,
						it->skb))
			return - ENOMEM;

		++it->frag;
		if (!(trec = tdb_next_rec_chunk(db, trec)))
			break;
		BUG_ON(trec && !f_size);
		p = trec->data;
	}

	return 0;
}

/**
 * Build response that can be sent via TCP socket.
 *
 * We return skbs in the cache entry response w/o setting any
 * network headers - tcp_transmit_skb() will do it for us.
 *
 * TODO Prebuild the response and use clones/copies for sending
 * (copy the list of skbs is faster than scan TDB and build TfwHttpResp).
 * TLS should encrypt the data in already prepared skbs.
 *
 * TODO use iterator and passed skbs to be called from net_tx_action.
 */
static TfwHttpResp *
tfw_cache_build_resp(TfwCacheEntry *ce)
{
	int h;
	char *p;
	TfwHttpResp *resp;
	TdbVRec *trec = &ce->trec;
	TDB *db = node_db();
	TfwMsgIter it;

	/*
	 * Allocated response won't be checked by any filters and
	 * is used for sending response data only, so don't initialize
	 * connection and GFSM fields.
	 */
	resp = (TfwHttpResp *)tfw_http_msg_create(NULL, &it, Conn_Srv,
						  ce->hdr_len + 2);
	if (!resp)
		return NULL;

	/*
	 * Allocate HTTP headers table of proper size.
	 * There were no other allocations since the table is allocated,
	 * so realloc() just grows the table and returns the same pointer.
	 */
	h = (ce->hdr_num + 2 * TFW_HTTP_HDR_NUM - 1) & ~(TFW_HTTP_HDR_NUM - 1);
	p = tfw_pool_realloc(resp->pool, resp->h_tbl, TFW_HHTBL_SZ(1),
			     TFW_HHTBL_EXACTSZ(h));
	BUG_ON(p != (char *)resp->h_tbl);

	/* Skip record key until status line. */
	for (p = TDB_PTR(db->hdr, ce->status);
	     trec && (unsigned long)(p - trec->data) > trec->len;
	     trec = tdb_next_rec_chunk(db, trec))
		;
	if (unlikely(!trec)) {
		TFW_WARN("Huh, partially stored cache entry (key=%lx)?\n",
			 ce->key);
		goto err;
	}

	if (tfw_cache_write_field(db, &trec, resp, &it, &p,
				  ce->status_len, &resp->s_line))
		goto err;

	for (h = 0; h < ce->hdr_num; ++h) {
		if (tfw_cache_build_resp_hdr(db, resp, resp->h_tbl->tbl + h,
					     &trec, &it, &p))
			goto err;
	}

	if (tfw_http_msg_add_data(&it, (TfwHttpMsg *)resp, &resp->crlf,
				  &g_crlf))
		goto err;

	BUG_ON(p != TDB_PTR(db->hdr, ce->body));
	if (tfw_cache_build_resp_body(db, resp, trec, &it, p))
		goto err;

	return resp;
err:
	TFW_WARN("Cannot use cached response, key=%lx\n", ce->key);
	tfw_http_msg_free((TfwHttpMsg *)resp);
	return NULL;
}

static void
cache_req_process_node(TfwHttpReq *req, unsigned long key,
			 tfw_http_cache_cb_t action)
{
	TfwCacheEntry *ce = NULL;
	TfwHttpResp *resp = NULL;
	TDB *db = node_db();
	TdbIter iter;

	iter = tdb_rec_get(db, key);
	if (TDB_ITER_BAD(iter)) {
		TFW_INC_STAT_BH(cache.misses);
		goto out;
	}

	for (ce = (TfwCacheEntry *)iter.rec;
	     !tfw_cache_entry_key_eq(db, req, ce); )
	{
		tdb_rec_next(db, &iter);
		if (!(ce = (TfwCacheEntry *)iter.rec)) {
			TFW_INC_STAT_BH(cache.misses);
			goto out;
		}
	}

	TFW_DBG("Cache: service request w/ key=%lx, ce=%p (len=%u key_len=%u"
		" status_len=%u hdr_num=%u hdr_len=%u key_off=%ld"
		" status_off=%ld hdrs_off=%ld body_off=%ld)\n",
		ce->trec.key, ce, ce->trec.len, ce->key_len, ce->status_len,
		ce->hdr_num, ce->hdr_len, ce->key, ce->status, ce->hdrs,
		ce->body);
	TFW_INC_STAT_BH(cache.hits);

	resp = tfw_cache_build_resp(ce);
out:
	action(req, resp);

	if (ce)
		tdb_rec_put(ce);
}

static void
tfw_wq_tasklet(unsigned long data)
{
	TfwWorkTasklet *ct = (TfwWorkTasklet *)data;
	TfwCWork cw;

	while (!tfw_wq_pop(&ct->wq, &cw)) {
		if (cw.resp)
			cw.action(cw.req, cw.resp);
		else 
			cache_req_process_node(cw.req, cw.key, cw.action);
	}
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
	int i, r = 1;

	if (!cache_cfg.cache)
		return 0;

	for_each_node_with_cpus(i) {
		c_nodes[i].db = tdb_open(cache_cfg.db_path,
					 cache_cfg.db_size, 0, i);
		if (!c_nodes[i].db)
			goto close_db;
	}

	cache_mgr_thr = kthread_run(tfw_cache_mgr, NULL, "tfw_cache_mgr");
	if (IS_ERR(cache_mgr_thr)) {
		r = PTR_ERR(cache_mgr_thr);
		TFW_ERR("Can't start cache manager, %d\n", r);
		goto close_db;
	}

	tfw_init_node_cpus();

	TFW_WQ_CHECKSZ(TfwCWork);
	for_each_online_cpu(i) {
		TfwWorkTasklet *ct = &per_cpu(cache_wq, i);
		tfw_wq_init(&ct->wq, cpu_to_node(i));
		init_irq_work(&ct->ipi_work, tfw_cache_ipi);
		tasklet_init(&ct->tasklet, tfw_wq_tasklet, (unsigned long)ct);
	}

	return 0;
close_db:
	for_each_node_with_cpus(i)
		tdb_close(c_nodes[i].db);
	return r;
}

static void
tfw_cache_stop(void)
{
	int i;

	if (!cache_cfg.cache)
		return;

	for_each_online_cpu(i) {
		TfwWorkTasklet *ct = &per_cpu(cache_wq, i);
		tasklet_kill(&ct->tasklet);
		irq_work_sync(&ct->ipi_work);
		tfw_wq_destroy(&ct->wq);
	}
	kthread_stop(cache_mgr_thr);

	for_each_node_with_cpus(i)
		tdb_close(c_nodes[i].db);
}

static TfwCfgSpec tfw_cache_cfg_specs[] = {
	{
		"cache",
		"2",
		tfw_cfg_set_int,
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
