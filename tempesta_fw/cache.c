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
#include "vhost.h"
#include "cache.h"
#include "http_msg.h"
#include "procfs.h"
#include "sync_socket.h"
#include "work_queue.h"

#if MAX_NUMNODES > ((1 << 16) - 1)
#warning "Please set CONFIG_NODES_SHIFT to less than 16"
#endif

/* Flags stored in a Cache Entry. */
#define TFW_CE_MUST_REVAL	0x0001		/* MUST revalidate if stale. */

/*
 * @trec	- Database record descriptor;
 * @key_len	- length of key (URI + Host header);
 * @status_len	- length of response satus line;
 * @hdr_num	- number of headers;
 * @hdr_len	- length of whole headers data;
 * @method	- request method, part of the key;
 * @flags	- various cache entry flags;
 * @age		- the value of response Age: header field;
 * @date	- the value of response Date: header field;
 * @req_time	- the time the request was issued;
 * @resp_time	- the time the response was received;
 * @lifetime	- the cache entry's current lifetime;
 * @key		- the cache enty key (URI + Host header);
 * @status	- pointer to status line  (with trailing CRLFs);
 * @hdrs	- pointer to list of HTTP headers (with trailing CRLFs);
 * @body	- pointer to response body (with a prepending CRLF);
 * @version	- HTTP version of the response;
 * @hmflags	- flags of the response after parsing and post-processing.
 */
typedef struct {
	TdbVRec		trec;
#define ce_body		key_len
	unsigned int	key_len;
	unsigned int	status_len;
	unsigned int	hdr_num;
	unsigned int	hdr_len;
	unsigned int	method: 4;
	unsigned int	flags: 28;
	time_t		age;
	time_t		date;
	time_t		req_time;
	time_t		resp_time;
	time_t		lifetime;
	long		key;
	long		status;
	long		hdrs;
	long		body;
	unsigned char	version;
	unsigned int	hmflags;
} TfwCacheEntry;

#define CE_BODY_SIZE							\
	(sizeof(TfwCacheEntry) - offsetof(TfwCacheEntry, ce_body))

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
	unsigned long		__unused;
} TfwCWork;

typedef struct {
	struct tasklet_struct	tasklet;
	struct irq_work		ipi_work;
	TfwRBQueue		wq;
} TfwWorkTasklet;

static struct {
	int cache;
	unsigned int methods;
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

typedef struct {
	int		cpu[NR_CPUS];
	atomic_t	cpu_idx;
	unsigned int	nr_cpus;
	TDB		*db;
} CaNode;

static CaNode c_nodes[MAX_NUMNODES];

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

/*
 * The mask of non-cacheable methods per RFC 7231 4.2.3.
 * Currently none of the non-cacheable methods are supported.
 * Note: POST method is cacheable but not supported at this time.
 */
static unsigned int tfw_cache_nc_methods = (1 << TFW_HTTP_METH_POST);

static inline bool
__cache_method_nc_test(tfw_http_meth_t method)
{
	return tfw_cache_nc_methods & (1 << method);
}

static inline void
__cache_method_add(tfw_http_meth_t method)
{
	cache_cfg.methods |= (1 << method);
}

static inline bool
__cache_method_test(tfw_http_meth_t method)
{
	return cache_cfg.methods & (1 << method);
}

bool
tfw_cache_msg_cacheable(TfwHttpReq *req)
{
	return cache_cfg.cache && __cache_method_test(req->method);
}

/*
 * Find caching policy in specific vhost and location.
 */
static int
tfw_cache_policy(TfwVhost *vhost, TfwLocation *loc, TfwStr *arg)
{
	TfwCaPolicy *capo;

	/* Search locations in current vhost. */
	if (loc && loc->capo_sz) {
		if ((capo = tfw_capolicy_match(loc, arg)))
			return capo->cmd;
	}

	/*
	 * Search default policies in current vhost.
	 * If there's none, then search global default policies.
	 */
	loc = vhost->loc_dflt;
	if (loc && loc->capo_sz) {
		if ((capo = tfw_capolicy_match(loc, arg)))
			return capo->cmd;
	} else {
		TfwVhost *vhost_dflt = tfw_vhost_get_default();
		if (vhost == vhost_dflt)
			return TFW_D_CACHE_BYPASS;

		loc = vhost_dflt->loc_dflt;
		if (loc && loc->capo_sz) {
			if ((capo = tfw_capolicy_match(loc, arg)))
				return capo->cmd;
		}
	}

	return TFW_D_CACHE_BYPASS;
}

/*
 * Decide if the cache can be employed. For a request that means
 * that it can be served from cache if there's a cached response.
 * For a response it means that the response can be stored in cache.
 *
 * Various cache action/control directives are consulted when making
 * the resulting decision.
 */
static bool
tfw_cache_employ_req(TfwHttpReq *req)
{
	int cmd = tfw_cache_policy(req->vhost, req->location, &req->uri_path);

	if (cmd == TFW_D_CACHE_BYPASS) {
		req->cache_ctl.flags |= TFW_HTTP_CC_CFG_CACHE_BYPASS;
		return false;
	}
	/* cache_fulfill - work as usual in cache mode. */
	BUG_ON(cmd != TFW_D_CACHE_FULFILL);

	if (req->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE)
		return false;

	return true;
}

/**
 * Check whether the response status code is defined as cacheable by default
 * by RFC 7231 6.1.
 */
static inline bool
tfw_cache_status_bydef(TfwHttpResp *resp)
{
	/*
	 * TODO: Add 206 (Partial Content) status. Requires support
	 * of incomplete responses, Range: and Content-Range: header
	 * fields, and RANGE request method.
	 */
	switch (resp->status) {
	case 200: case 203: case 204:
	case 300: case 301:
	case 404: case 405: case 410: case 414:
	case 501:
		return true;
	}
	return false;
}

static bool
tfw_cache_employ_resp(TfwHttpReq *req, TfwHttpResp *resp)
{
#define CC_REQ_DONTCACHE				\
	(TFW_HTTP_CC_CFG_CACHE_BYPASS | TFW_HTTP_CC_NO_STORE)
#define CC_RESP_DONTCACHE				\
	(TFW_HTTP_CC_NO_STORE | TFW_HTTP_CC_PRIVATE	\
	 | TFW_HTTP_CC_NO_CACHE)
#define CC_RESP_CACHEIT					\
	(TFW_HTTP_CC_HDR_EXPIRES | TFW_HTTP_CC_MAX_AGE	\
	 | TFW_HTTP_CC_S_MAXAGE | TFW_HTTP_CC_PUBLIC)
#define CC_RESP_AUTHCAN					\
	(TFW_HTTP_CC_S_MAXAGE | TFW_HTTP_CC_PUBLIC	\
	 | TFW_HTTP_CC_MUST_REVAL | TFW_HTTP_CC_PROXY_REVAL)
	/*
	 * TODO: Response no-cache -- should be cached.
	 * Should turn on unconditional revalidation.
	 */
	if (req->cache_ctl.flags & CC_REQ_DONTCACHE)
		return false;
	if (resp->cache_ctl.flags & CC_RESP_DONTCACHE)
		return false;
	if (!(resp->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT)
	    && (resp->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE))
		return false;
	if ((req->cache_ctl.flags & TFW_HTTP_CC_HDR_AUTHORIZATION)
	    && !(req->cache_ctl.flags & CC_RESP_AUTHCAN))
		return false;
	if (!(resp->cache_ctl.flags & CC_RESP_CACHEIT)
	    && !tfw_cache_status_bydef(resp))
		return false;
#undef CC_RESP_AUTHCAN
#undef CC_RESP_CACHEIT
#undef CC_RESP_DONTCACHE
#undef CC_REQ_DONTCACHE

	return true;
}

/*
 * Calculate freshness lifetime according to RFC 7234 4.2.1.
 */
static time_t
tfw_cache_calc_lifetime(TfwHttpResp *resp)
{
	unsigned int lifetime;

	if (resp->cache_ctl.flags & TFW_HTTP_CC_S_MAXAGE)
		lifetime = resp->cache_ctl.s_maxage;
	else if (resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE)
		lifetime = resp->cache_ctl.max_age;
	else if (resp->cache_ctl.flags & TFW_HTTP_CC_HDR_EXPIRES)
		lifetime = resp->cache_ctl.expires - resp->date;
	else
		/* For now, set "unlimited" lifetime in this case. */
		lifetime = UINT_MAX;	/* TODO: Heuristic lifetime. */

	return lifetime;
}

/*
 * Calculate the current entry age according to RFC 7234 4.2.3.
 */
static time_t
tfw_cache_entry_age(TfwCacheEntry *ce)
{
	time_t apparent_age = max_t(time_t, 0, ce->resp_time - ce->date);
	time_t corrected_age = ce->age + ce->resp_time - ce->req_time;
	time_t initial_age = max(apparent_age, corrected_age);
	return (initial_age + tfw_current_timestamp() - ce->resp_time);
}

/*
 * Given Cache Control arguments in the request and the response,
 * as well as the stored cache entry parameters, determine if the
 * cache entry is live and may be served to a client. For that,
 * the cache entry freshness is calculated according to RFC 7234
 * 4.2, 5.2.1.1, 5.2.1.2, and 5.2.1.3.
 *
 * Returns the value of calculated cache entry lifetime if the entry
 * is live and may be served to a client. Returns zero if the entry
 * may not be served.
 *
 * Note that if the returned value of lifetime is greater than
 * ce->lifetime, then the entry is stale but still may be served
 * to a client, provided that the cache policy allows that.
 */
static time_t
tfw_cache_entry_is_live(TfwHttpReq *req, TfwCacheEntry *ce)
{
	time_t ce_age = tfw_cache_entry_age(ce);
	time_t ce_lifetime, lt_fresh = UINT_MAX;

	if (ce->lifetime <= 0)
		return 0;

#define CC_LIFETIME_FRESH	(TFW_HTTP_CC_MAX_AGE | TFW_HTTP_CC_MIN_FRESH)
	if (req->cache_ctl.flags & CC_LIFETIME_FRESH) {
		time_t lt_max_age = UINT_MAX, lt_min_fresh = UINT_MAX;
		if (req->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE)
			lt_max_age = req->cache_ctl.max_age;
		if (req->cache_ctl.flags & TFW_HTTP_CC_MIN_FRESH)
			lt_min_fresh = ce->lifetime - req->cache_ctl.min_fresh;
		lt_fresh = min(lt_max_age, lt_min_fresh);
	}
	if (!(req->cache_ctl.flags & TFW_HTTP_CC_MAX_STALE)) {
		ce_lifetime = min(lt_fresh, ce->lifetime);
	} else {
		time_t lt_max_stale = ce->lifetime + req->cache_ctl.max_stale;
		ce_lifetime = min(lt_fresh, lt_max_stale);
	}
#undef CC_LIFETIME_FRESH

	return ce_lifetime > ce_age ? ce_lifetime : 0;
}

static bool
tfw_cache_entry_key_eq(TDB *db, TfwHttpReq *req, TfwCacheEntry *ce)
{
	/* Record key starts at first data chunk. */
	int n, c_off = 0, t_off;
	TdbVRec *trec = &ce->trec;
	TfwStr *c, *h_start, *u_end, *h_end;

	if (ce->method != req->method)
		return false;
	if (req->uri_path.len
	    + req->h_tbl->tbl[TFW_HTTP_HDR_HOST].len != ce->key_len)
		return false;

	t_off = CE_BODY_SIZE;
	TFW_CACHE_REQ_KEYITER(c, req, u_end, h_start, h_end) {
		if (!trec)
			return false;
this_chunk:
		n = min(c->len - c_off, (unsigned long)trec->len - t_off);
		/* Cache key is stored in lower case. */
		if (tfw_stricmp_2lc((char *)c->ptr + c_off,
				    trec->data + t_off, n))
			return false;
		c_off = (n == c->len - c_off) ? 0 : c_off + n;
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
		c_nodes[node].cpu[c_nodes[node].nr_cpus++] = cpu;
	}
}

static TDB *
node_db(void)
{
	return c_nodes[numa_node_id()].db;
}

/**
 * Get a CPU identifier from @node to schedule a work.
 * The request should be processed on remote node, use round robin strategy
 * to distribute such requests.
 *
 * Note that atomic_t is a signed 32-bit value, and it's intentionally
 * cast to unsigned type value before taking a modulo operation.
 * If this place becomes a hot spot, then @cpu_idx may be made per_cpu.
 */
static int
tfw_cache_sched_cpu(TfwHttpReq *req)
{
	CaNode *node = &c_nodes[req->node];
	unsigned int idx = atomic_inc_return(&node->cpu_idx);

	return node->cpu[idx % node->nr_cpus];
}

static TfwCacheEntry *
tfw_cache_dbce_get(TDB *db, TdbIter *iter, TfwHttpReq *req)
{
	TfwCacheEntry *ce;
	unsigned long key = tfw_http_req_key_calc(req);

	*iter = tdb_rec_get(db, key);
	if (TDB_ITER_BAD(*iter)) {
		TFW_INC_STAT_BH(cache.misses);
		return NULL;
	}
	ce = (TfwCacheEntry *)iter->rec;
	do {
		/*
		 * Basically we don't need to compare keys if only one record
		 * is in the bucket. Checking for next record instead of
		 * comparing the keys would has sense for long URI, but
		 * performance benchmarks don't show any improvement.
		 */
		if (tfw_cache_entry_key_eq(db, req, ce))
			break;
		tdb_rec_next(db, iter);
		if (!(ce = (TfwCacheEntry *)iter->rec)) {
			TFW_INC_STAT_BH(cache.misses);
			return NULL;
		}
	} while (true);

	return ce;
}

static inline void
tfw_cache_dbce_put(TfwCacheEntry *ce)
{
	if (ce)
		tdb_rec_put(ce);
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
__tfw_cache_strcpy(char **p, TdbVRec **trec, TfwStr *src, size_t tot_len,
		   void *cpy(void *dest, const void *src, size_t n))
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
		cpy(*p, (char *)src->ptr + copied, room);
		*p += room;
		copied += room;
	}

	return copied;
}

/**
 * We need the function wrapper if memcpy() is defined as __inline_memcpy().
 */
static void *
__tfw_memcpy(void *dst ,const void *src, size_t n)
{
	return memcpy(dst, src, n);
}

static inline long
tfw_cache_strcpy(char **p, TdbVRec **trec, TfwStr *src, size_t tot_len)
{
	return __tfw_cache_strcpy(p, trec, src, tot_len, __tfw_memcpy);
}

/**
 * The same as tfw_cache_strcpy(), but copies @src with lower case conversion.
 */
static inline long
tfw_cache_strcpy_lc(char **p, TdbVRec **trec, TfwStr *src, size_t tot_len)
{
	return __tfw_cache_strcpy(p, trec, src, tot_len, tfw_strtolower);
}

/**
 * Copies plain or compound (chunked) TfwStr @src to TdbRec @trec may be
 * appending EOL marker at the end.
 *
 * @src is copied (possibly with EOL appended)
 * @return number of copied bytes on success and negative value otherwise.
 */
static long
tfw_cache_strcpy_eol(char **p, TdbVRec **trec,
		   TfwStr *src, size_t *tot_len, bool eol)
{
	long n, copied = 0;
	TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(src));

	if (unlikely(!src->len))
		return 0;

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

#define CSTR_WRITE_HDR(str)			\
	tfw_cache_str_write_hdr(str, *p);	\
	*p += TFW_CSTR_HDRLEN;			\
	*tot_len -= TFW_CSTR_HDRLEN;		\
	copied = TFW_CSTR_HDRLEN;

	*p = tdb_entry_get_room(node_db(), trec, *p, n, *tot_len);
	if (!*p) {
		TFW_WARN("Cache: cannot allocate TDB space\n");
		return -ENOMEM;
	}

	CSTR_WRITE_HDR(src);

	if (!TFW_STR_DUP(src)) {
		if ((n = tfw_cache_strcpy_eol(p, trec, src, tot_len, 1)) < 0)
			return n;
		return copied + n;
	}

	TFW_STR_FOR_EACH_DUP(dup, src, dup_end) {
		CSTR_WRITE_HDR(dup);
		if ((n = tfw_cache_strcpy_eol(p, trec, dup, tot_len, 1)) < 0)
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

	p = (char *)(ce + 1);
	tot_len -= CE_BODY_SIZE;

	/* Write record key (URI + Host header). */
	ce->key = TDB_OFF(db->hdr, p);
	ce->key_len = 0;
	TFW_CACHE_REQ_KEYITER(field, req, end1, h, end2) {
		if ((n = tfw_cache_strcpy_lc(&p, &trec, field, tot_len)) < 0) {
			TFW_ERR("Cache: cannot copy request key\n");
			return -ENOMEM;
		}
		BUG_ON(n > tot_len);
		tot_len -= n;
		ce->key_len += n;
	}
	/* Request method is a part of the cache record key. */
	ce->method = req->method;

	ce->status = TDB_OFF(db->hdr, p);
	if ((n = tfw_cache_strcpy_eol(&p, &trec, &resp->s_line, &tot_len, 1)) < 0) {
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
	if ((n = tfw_cache_strcpy_eol(&p, &trec, &resp->body, &tot_len,
				      resp->flags & TFW_HTTP_CHUNKED)) < 0) {
		TFW_ERR("Cache: cannot copy HTTP body\n");
		return -ENOMEM;
	}
	BUG_ON(tot_len != 0);

	ce->version = resp->version;
	ce->hmflags = resp->flags;

	if (resp->cache_ctl.flags
	    & (TFW_HTTP_CC_MUST_REVAL | TFW_HTTP_CC_PROXY_REVAL))
		ce->flags |= TFW_CE_MUST_REVAL;
	ce->date = resp->date;
	ce->age = resp->cache_ctl.age;
	ce->req_time = req->cache_ctl.timestamp;
	ce->resp_time = resp->cache_ctl.timestamp;
	ce->lifetime = tfw_cache_calc_lifetime(resp);

	TFW_DBG("Cache copied msg: content-length=%lu msg_len=%lu, ce=%p"
		" (len=%u key_len=%u status_len=%u hdr_num=%u hdr_len=%u"
		" key_off=%ld status_off=%ld hdrs_off=%ld body_off=%ld)",
		resp->content_length, resp->msg.len, ce, ce->trec.len,
		ce->key_len, ce->status_len, ce->hdr_num, ce->hdr_len,
		ce->key, ce->status, ce->hdrs, ce->body);

	return 0;
}

static size_t
__cache_entry_size(TfwHttpResp *resp, TfwHttpReq *req)
{
	long n;
	size_t size = CE_BODY_SIZE;
	TfwStr *h, *hdr, *hdr_end, *dup, *dup_end, empty = {};

	/* Add compound key size */
	size += req->uri_path.len;
	size += req->h_tbl->tbl[TFW_HTTP_HDR_HOST].len;

	/* Add all the headers size */
	FOR_EACH_HDR_FIELD(hdr, hdr_end, resp) {
		/* Skip hop-by-hop headers. */
		n = hdr - resp->h_tbl->tbl;
		h = (n < TFW_HTTP_HDR_RAW && hbh_hdrs[n]) ? &empty : hdr;
		if (!TFW_STR_DUP(h)) {
			size += sizeof(TfwCStr);
			size += h->len ? (h->len + SLEN(S_CRLF)) : 0;
		} else {
			size += sizeof(TfwCStr);
			TFW_STR_FOR_EACH_DUP(dup, h, dup_end) {
				size += sizeof(TfwCStr);
				size += dup->len + SLEN(S_CRLF);
			}
		}
	}

	/* Add status line length + CRLF */
	size += resp->s_line.len + SLEN(S_CRLF);

	/* Add body size accounting CRLF after the last chunk */
	size += resp->body.len;
	if (resp->flags & TFW_HTTP_CHUNKED)
		size += SLEN(S_CRLF);

	return size;
}

static void
__cache_add_node(TDB *db, TfwHttpResp *resp, TfwHttpReq *req,
		 unsigned long key)
{
	TfwCacheEntry *ce, cdata = {{}};
	size_t data_len = __cache_entry_size(resp, req);
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

static void
tfw_cache_add(TfwHttpResp *resp, TfwHttpReq *req, tfw_http_cache_cb_t action)
{
	unsigned long key;
	bool keep_skb = false;

	if (!tfw_cache_msg_cacheable(req))
		goto out;
	if (!tfw_cache_employ_resp(req, resp))
		goto out;

	key = tfw_http_req_key_calc(req);

	if (cache_cfg.cache == TFW_CACHE_SHARD) {
		BUG_ON(req->node != numa_node_id());
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
	 * Cache population is synchronous now. Don't forget to set
	 * @keep_skb properly in case of asynchronous operation is being
	 * performed.
	 */

out:
	((TfwMsg *)resp)->ss_flags |= keep_skb ? SS_F_KEEP_SKB : 0;
	action(req, resp);
}

/**
 * Invalidate a cache entry.
 * In fact, this is implemented by making the cache entry stale.
 */
static int
tfw_cache_purge_invalidate(TfwHttpReq *req)
{
	TdbIter iter;
	TDB *db = node_db();
	TfwCacheEntry *ce = NULL;

	if (!(ce = tfw_cache_dbce_get(db, &iter, req)))
		return -ENOENT;
	ce->lifetime = 0;
	tfw_cache_dbce_put(ce);
	return 0;
}

/**
 * Process PURGE request method according to the configuration.
 */
static int
tfw_cache_purge_method(TfwHttpReq *req)
{
	int ret;
	TfwAddr saddr;
	TfwVhost *vhost = tfw_vhost_get_default();

	/* Deny PURGE requests by default. */
	if (!(cache_cfg.cache && vhost->cache_purge && vhost->cache_purge_acl))
		return tfw_http_send_403(req, "unconfigured purge request");

	/* Accept requests from configured hosts only. */
	ss_getpeername(req->conn->sk, &saddr);
	if (!tfw_capuacl_match(vhost, &saddr))
		return tfw_http_send_403(req, "purge request ACL violation");

	/* Only "invalidate" option is implemented at this time. */
	switch (vhost->cache_purge_mode) {
	case TFW_D_CACHE_PURGE_INVALIDATE:
		ret = tfw_cache_purge_invalidate(req);
		break;
	default:
		return tfw_http_send_403(req, "bad purge option");
	}

	return ret
		? tfw_http_send_404(req, "purge error")
		: tfw_http_send_200(req);
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
		if (copied == len)
			break;

		tr = *trec = tdb_next_rec_chunk(db, tr);
		BUG_ON(!tr);
		*data = tr->data;
	}

	/* Every non-empty header contains CRLF at the end. We need to translate
	 * it to { str, eolen } presentation. */
	if (hdr->len)
		tfw_str_fixup_eol(hdr, SLEN(S_CRLF));

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
		TFW_STR_INIT(&dups[d]);
		*p += TFW_CSTR_HDRLEN;
		if ((r = tfw_cache_write_field(db, trec, resp, it, p, s->len,
					       &dups[d])))
			return r;
	}

	hdr->ptr = dups;
	__TFW_STR_CHUNKN_SET(hdr, dn);
	hdr->flags |= TFW_STR_DUPLICATE;

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
		if (__tfw_http_msg_add_str_data((TfwHttpMsg *)resp,
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
 * Basically, skb copy/clonning involves skb creation, so it seems performance
 * of response body creation won't change since now we just reuse TDB pages.
 * Perfromace benchmarks and profiling shows that cache_req_process_node()
 * is the bottleneck, so the problem is either in tfw_cache_dbce_get() or this
 * function, in headers compilation.
 * Also it seems cachig prebuilt responses requires introducing
 * TfwCacheEntry->resp pointer to avoid additional indexing data structure.
 * However, the pointer must be zeroed on TDB shutdown and recovery.
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
		TFW_STR_INIT(resp->h_tbl->tbl + h);
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

	resp->version = ce->version;
	resp->flags = ce->hmflags;

	return resp;
err:
	TFW_WARN("Cannot use cached response, key=%lx\n", ce->key);
	tfw_http_msg_free((TfwHttpMsg *)resp);
	return NULL;
}

static void
cache_req_process_node(TfwHttpReq *req, tfw_http_cache_cb_t action)
{
	TfwCacheEntry *ce = NULL;
	TfwHttpResp *resp = NULL;
	TDB *db = node_db();
	TdbIter iter;
	time_t lifetime;

	if (!(ce = tfw_cache_dbce_get(db, &iter, req)))
		goto out;

	if (!(lifetime = tfw_cache_entry_is_live(req, ce)))
		goto out;

	TFW_DBG("Cache: service request w/ key=%lx, ce=%p (len=%u key_len=%u"
		" status_len=%u hdr_num=%u hdr_len=%u key_off=%ld"
		" status_off=%ld hdrs_off=%ld body_off=%ld)\n",
		ce->trec.key, ce, ce->trec.len, ce->key_len, ce->status_len,
		ce->hdr_num, ce->hdr_len, ce->key, ce->status, ce->hdrs,
		ce->body);
	TFW_INC_STAT_BH(cache.hits);

	resp = tfw_cache_build_resp(ce);
	if (lifetime > ce->lifetime)
		resp->flags |= TFW_HTTP_RESP_STALE;
out:
	if (!resp && (req->cache_ctl.flags & TFW_HTTP_CC_OIFCACHED))
		tfw_http_send_504(req, "resource not cached");
	else
		action(req, resp);

	tfw_cache_dbce_put(ce);
}

static void
tfw_cache_do_action(TfwHttpReq *req, TfwHttpResp *resp,
		    tfw_http_cache_cb_t action)
{
	if (resp) {
		tfw_cache_add(resp, req, action);
	}
	else if (req->method == TFW_HTTP_METH_PURGE) {
		tfw_cache_purge_method(req);
	}
	else {
		cache_req_process_node(req, action);
	}
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
	int r, cpu;
	unsigned long key;
	TfwWorkTasklet *ct;
	TfwCWork cw;

	if (req->method == TFW_HTTP_METH_PURGE)
		goto do_cache;
	if (!tfw_cache_msg_cacheable(req))
		goto dont_cache;
	if (!resp && !tfw_cache_employ_req(req))
		goto dont_cache;

do_cache:
	key = tfw_http_req_key_calc(req);
	req->node = (cache_cfg.cache == TFW_CACHE_SHARD)
		    ? tfw_cache_key_node(key)
		    : numa_node_id();

	/*
	 * Queue the cache work only when it must be served by a remote node.
	 * Otherwise we can do everything right now on local CPU.
	 *
	 * TODO #391: it appears that req->node is not really needed and can
	 * be eliminated from TfwHttpReq{} structure and it can easily be
	 * replaced by a local variable here.
	 */
	if (likely(req->node == numa_node_id())) {
		tfw_cache_do_action(req, resp, action);
		return 0;
	}

	cw.req = req;
	cw.resp = resp;
	cw.action = action;
	cpu = tfw_cache_sched_cpu(req);
	ct = per_cpu_ptr(&cache_wq, cpu);

	TFW_DBG2("Cache: schedule tasklet w/ work: to_cpu=%d from_cpu=%d"
		 " req=%p resp=%p key=%lx\n", cpu, smp_processor_id(),
		 cw.req, cw.resp, key);

	r = tfw_wq_push(&ct->wq, &cw, cpu, &ct->ipi_work, tfw_cache_ipi, false);
	if (unlikely(r))
		TFW_WARN("Cache work queue overrun: [%s]\n",
			 resp ? "response" : "request");
	return r;

dont_cache:
	action(req, resp);
	return 0;
}

static void
tfw_wq_tasklet(unsigned long data)
{
	TfwWorkTasklet *ct = (TfwWorkTasklet *)data;
	TfwCWork cw;

	while (!tfw_wq_pop(&ct->wq, &cw))
		tfw_cache_do_action(cw.req, cw.resp, cw.action);
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
	TfwVhost *vhost = tfw_vhost_get_default();

	if (!(cache_cfg.cache || vhost->cache_purge))
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

static int
tfw_cache_cfg_method(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int i, method;
	const char *val;

	BUILD_BUG_ON(sizeof(cache_cfg.methods) * 8 < _TFW_HTTP_METH_COUNT);

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (!strcasecmp(val, "GET")) {
			method = TFW_HTTP_METH_GET;
		} else if (!strcasecmp(val, "HEAD")) {
			method = TFW_HTTP_METH_HEAD;
		} else if (!strcasecmp(val, "POST")) {
			method = TFW_HTTP_METH_POST;
		} else {
			TFW_ERR("%s: unsupported method: '%s'\n",
				cs->name, val);
			return -EINVAL;
		}
		if (__cache_method_nc_test(method)) {
			TFW_ERR("%s: non-cacheable method: '%s'\n",
				cs->name, val);
			return -EINVAL;
		}
		if (__cache_method_test(method)) {
			TFW_WARN("%s: duplicate method: '%s'\n",
				 cs->name, val);
			continue;
		}
		__cache_method_add(method);
	}

	return 0;
}

static TfwCfgSpec tfw_cache_cfg_specs[] = {
	{
		"cache",
		"2",
		tfw_cfg_set_int,
		&cache_cfg.cache,
		&(TfwCfgSpecInt) {
			.range = { 0, 2 },
		}
	},
	{
		"cache_methods",
		"GET",
		tfw_cache_cfg_method,
		.allow_none = true,
		.allow_repeat = false,
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
