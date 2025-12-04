/**
 *		Tempesta FW
 *
 * HTTP cache (RFC 7234).
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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
#include <linux/nodemask.h>
#include <linux/skbuff_ref.h>

#undef DEBUG
#if DBG_CACHE > 0
#define DEBUG DBG_CACHE
#endif

#include "tdb.h"

#include "apm.h"
#include "lib/str.h"
#include "tempesta_fw.h"
#include "vhost.h"
#include "cache.h"
#include "http_msg.h"
#include "http_sess.h"
#include "procfs.h"
#include "sync_socket.h"
#include "work_queue.h"
#include "lib/common.h"

#if MAX_NUMNODES > ((1 << 16) - 1)
#warning "Please set CONFIG_NODES_SHIFT to less than 16"
#endif

static const int tfw_cache_spec_headers_304[] = {
	[0 ... TFW_HTTP_HDR_RAW] = 0,
	[TFW_HTTP_HDR_ETAG] = 1,
	[TFW_HTTP_HDR_CONTENT_LOCATION] = 1,
};
static const TfwStr tfw_cache_raw_headers_304[] = {
	TFW_STR_STRING("cache-control:"),
	TFW_STR_STRING("date:"),
	TFW_STR_STRING("expires:"),
	TFW_STR_STRING("last-modified:"),
	TFW_STR_STRING("vary:"),
	/* Etag are Spec headers */
};
#define TFW_CACHE_304_SPEC_HDRS_NUM	1	/* ETag. */
#define TFW_CACHE_304_HDRS_NUM						\
	ARRAY_SIZE(tfw_cache_raw_headers_304) + TFW_CACHE_304_SPEC_HDRS_NUM


/* Flags stored in a Cache Entry. */
#define TFW_CE_MUST_REVAL	0x0001		/* MUST revalidate if stale. */
#define TFW_CE_STALE_IF_ERROR	0x0002
#define TFW_CE_CHUNKED_BODY	0x0004		/* CE entry contains chunked body. */

/*
 * @trec	- Database record descriptor;
 * @key_len	- length of key (URI + Host header);
 * @status_len	- length of response status code;
 * @rph_len	- length of response reason phrase;
 * @hdr_num	- number of headers;
 * @hdr_len	- length of whole headers data;
 * @hdr_h2_off	- start of http/2-only headers in the headers list;
 * @trailer_off	- start of trailer headers;
 * @body_len	- length of the response body;
 * @method	- request method, part of the key;
 * @flags	- various cache entry flags;
 * @age		- the value of response Age: header field;
 * @date	- the value of response Date: header field;
 * @req_time	- the time the request was issued;
 * @resp_time	- the time the response was received;
 * @lifetime	- the cache entry's current lifetime;
 * @last_modified - the value of response Last-Modified: header field;
 * @key		- the cache entry key (URI + Host header);
 * @status	- pointer to status line;
 * @hdrs	- pointer to list of HTTP headers;
 * @body	- pointer to response body;
 * @hdrs_304	- pointers to headers used to build 304 response;
 * @stale_if_error - the value of response "Cache-control: stale_if_error"
 * 		  header field;
 * @version	- HTTP version of the response;
 * @resp_status - Http status of the cached response.
 * @hmflags	- flags of the response after parsing and post-processing.
 * @etag	- entity-tag, stored as a pointer to ETag header in @hdrs.
 */
typedef struct {
	TdbVRec		trec;
#define ce_body		key_len
	unsigned int	key_len;
	unsigned int	status_len;
	unsigned int	rph_len;
	unsigned int	hdr_num;
	unsigned int	hdr_h2_off;
	unsigned int	trailer_off;
	unsigned int	hdr_len;
	unsigned int	method: 4;
	unsigned int	flags: 28;
	size_t		body_len;
	long		age;
	long		date;
	long		req_time;
	long		resp_time;
	long		lifetime;
	long		last_modified;
	long		key;
	long		status;
	long		hdrs;
	long		trailers;
	long		body;
	long		hdrs_304[TFW_CACHE_304_HDRS_NUM];
	long		stale_if_error;
	DECLARE_BITMAP	(hmflags, _TFW_HTTP_FLAGS_NUM);
	unsigned char	version;
	unsigned short	resp_status;
	TfwStr		etag;
} TfwCacheEntry;

#define CE_BODY_SIZE							\
	(sizeof(TfwCacheEntry) - offsetof(TfwCacheEntry, ce_body))

static size_t
ce_total_size(const TfwCacheEntry *ce)
{
	return ce->key_len + ce->status_len + ce->rph_len + ce->hdr_len +
		ce->body_len + CE_BODY_SIZE;
}

#if defined(DEBUG)
#define CE_DBGBUF_LEN	1024
static DEFINE_PER_CPU(char *, ce_dbg_buf) = NULL;

static void
__tfw_dbg_dump_ce(const TfwCacheEntry *ce)
{
	char *buf;
	int len = 0;
	buf = *this_cpu_ptr(&ce_dbg_buf);
	bzero_fast(buf, CE_DBGBUF_LEN);

#define CE_DUMP_MEMBER(fmt, ...)					\
	snprintf(buf + len, CE_DBGBUF_LEN - len, "    %14s: " fmt "\n",	\
		 __VA_ARGS__)

	len += CE_DUMP_MEMBER("key %lx, chunk_next %d, len %d total_len: %lu",
			      "TdbVRec", ce->trec.key, ce->trec.chunk_next,
			      ce->trec.len, ce_total_size(ce));
	len += CE_DUMP_MEMBER("%d", "key_len",		ce->key_len);
	len += CE_DUMP_MEMBER("%d", "status_len",	ce->status_len);
	len += CE_DUMP_MEMBER("%d", "rph_len",		ce->rph_len);
	len += CE_DUMP_MEMBER("%d", "hdr_num",		ce->hdr_num);
	len += CE_DUMP_MEMBER("%d", "hdr_h2_off",	ce->hdr_h2_off);
	len += CE_DUMP_MEMBER("%d", "trailer_off",	ce->trailer_off);
	len += CE_DUMP_MEMBER("%d", "hdr_len",		ce->hdr_len);
	len += CE_DUMP_MEMBER("%d", "body_len",		ce->body_len);
	len += CE_DUMP_MEMBER("%d", "method",		ce->method);
	len += CE_DUMP_MEMBER("%d", "flags",		ce->flags);

	len += CE_DUMP_MEMBER("%lu", "age",		ce->age);
	len += CE_DUMP_MEMBER("%lu", "date",		ce->date);
	len += CE_DUMP_MEMBER("%lu", "req_time",	ce->req_time);
	len += CE_DUMP_MEMBER("%lu", "resp_time",	ce->resp_time);
	len += CE_DUMP_MEMBER("%lu", "last_modified",	ce->last_modified);
	len += CE_DUMP_MEMBER("%lx", "key off",		ce->key);
	len += CE_DUMP_MEMBER("%lx", "status off",	ce->status);
	len += CE_DUMP_MEMBER("%lx", "hdrs off",	ce->hdrs);
	len += CE_DUMP_MEMBER("%lx", "body off",	ce->body);
	/* @hmflags occupies a single ulong */
	len += CE_DUMP_MEMBER("%lx [%*pbl]", "hmflags", *ce->hmflags,
			      _TFW_HTTP_FLAGS_NUM, ce->hmflags);
	len += CE_DUMP_MEMBER("%x",  "version",     ce->version);
	len += CE_DUMP_MEMBER("%d",  "resp_status", ce->resp_status);

	T_DBG("Tdb CE [%p]: \n%s", ce, buf);
}
#else
#define __tfw_dbg_dump_ce(...)
#endif

/* TfwCStr contains duplicated header. */
#define TFW_CSTR_DUPLICATE	TFW_STR_DUPLICATE
/* TfwCStr contains special header and its id. */
#define TFW_CSTR_SPEC_IDX	0x2
/*
 * TfwCStr contains header, which should be skipped for http2 responses
 * constructed from cache. We skip transfer encoding header, when we
 * build response from cache for HTTP2 request.
 * RFC 9113 8.1:
 * HTTP/2 uses DATA frames to carry message content. The chunked
 * transfer encoding defined in Section 7.1 of [HTTP/1.1] cannot be
 * used in HTTP/2; see Section 8.2.2.
 */
#define TFW_CSTR_SKIP_FOR_H2	0x4

/* TfwCStr contains trailer. */
#define TFW_CSTR_TRAILER	0x8

/**
 * String header for cache entries used for TfwStr serialization.
 *
 * @flags	- TFW_CSTR_DUPLICATE and TFW_CSTR_HPACK_IDX or zero;
 * @name_len	- Header name length. Used for raw headers;
 * @name_len_sz	- HPACK int size of @name_len;
 * @len		- Total string length or number of duplicates;
 * @idx		- HPACK static index or index of special header;
 */
typedef struct {
	unsigned long	flags : 8,
			name_len: 11,
			name_len_sz : 2,
			len : 35,
			idx : 8;
} TfwCStr;

#define TFW_CSTR_MAXLEN		(1UL << 56)
#define TFW_CSTR_HDRLEN		(sizeof(TfwCStr))

/* Work to copy response body to database. */
typedef struct {
	TfwHttpMsg		*msg;
	tfw_http_cache_cb_t	action;
	unsigned long		__unused[2];
} TfwCWork;

typedef struct {
	struct tasklet_struct	tasklet;
	struct irq_work		ipi_work;
	TfwRBQueue		wq;
} TfwWorkTasklet;

/* Cache modes. */
typedef enum {
	TFW_CACHE_UNDEFINED = -1,
	TFW_CACHE_NONE = 0,
	TFW_CACHE_SHARD,
	TFW_CACHE_REPLICA,
} TfwCacheMode;

typedef enum {
	TFW_CACHE_HDR,
	TFW_CACHE_TRAILER,
} TfwCacheHdrType;

static struct {
	int cache;
	unsigned int methods;
	unsigned long db_size;
	const char *db_path;
} cache_cfg __read_mostly = {
	.cache = TFW_CACHE_UNDEFINED,
	.methods = 0,
	.db_size = 0,
	.db_path = NULL
};

unsigned int cache_default_ttl;

typedef struct {
	int 		*cpu;
	atomic_t	cpu_idx;
	unsigned int	nr_cpus;
	TDB		*db;
} CaNode;

static CaNode *c_nodes;

typedef int tfw_cache_write_actor_t(TDB *, TdbVRec **, TfwHttpResp *, char **,
				    size_t, TfwDecodeCacheIter *);
/*
 * TODO the thread doesn't do anything for now, however, kthread_stop() crashes
 * on restarts, so comment to logic out.
 */
#if 0
static struct task_struct *cache_mgr_thr;
#endif
static DEFINE_PER_CPU(TfwWorkTasklet, cache_wq);

#define RESP_BUF_LEN		128

static DEFINE_PER_CPU(char[RESP_BUF_LEN], g_c_buf);

static TfwStr g_crlf = { .data = S_CRLF, .len = SLEN(S_CRLF) };

/*
 * Iterate over request URI and vhost name to process request key.
 * uri_path is chunked, vhost_name is a BasicStr pointer.
 * v_start is a TfwStr that will be initialized to wrap vhost_name.
 */
#define TFW_CACHE_REQ_KEYITER(c, uri_path, vhost_name, u_end, v_start,	\
			      v_end, u_fin, v_fin)			\
	c = NULL;							\
	if (!(u_fin = WARN_ON_ONCE(TFW_STR_EMPTY(uri_path)))) {		\
		if (TFW_STR_PLAIN(uri_path)) {				\
			c = uri_path;					\
			u_end = (uri_path) + 1;				\
		} else {						\
			c = (uri_path)->chunks;				\
			u_end = (uri_path)->chunks + (uri_path)->nchunks; \
		}							\
	}								\
	if (!(v_fin = WARN_ON_ONCE(!(vhost_name)->len))) {		\
		(v_start)->data = (vhost_name)->data;			\
		(v_start)->len = (vhost_name)->len;			\
		v_end = (v_start) + 1;					\
		c = c ? : (v_start);					\
	}								\
	for ( ; !u_fin || !v_fin;					\
	     ++c, u_fin = u_fin ? true : (c == u_end),			\
	     v_fin = v_fin ? true : (c == v_end),			\
	     c = (c == u_end) ? (v_start) : c)

/*
 * The mask of non-cacheable methods per RFC 7231 4.2.3.
 * Safe methods that do not depend on a current or authoritative response
 * are defined as cacheable: GET, HEAD, and POST.
 * Note: caching of POST method responses need further support.
 * Issue #506 describes, which steps must be made to support caching of POST
 * requests.
 */
static unsigned int tfw_cache_nc_methods =
		~((1 << TFW_HTTP_METH_GET) | (1 << TFW_HTTP_METH_HEAD) |
		  (1 << TFW_HTTP_METH_POST));

static inline bool
__cache_method_nc_test(tfw_http_meth_t method)
{
	BUILD_BUG_ON(sizeof(tfw_cache_nc_methods) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);

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

static inline bool
tfw_cache_msg_cacheable(TfwHttpReq *req)
{
	/* POST request is not idempotent, but can be cacheble. */
	return cache_cfg.cache && __cache_method_test(req->method) &&
		(!tfw_http_req_is_nip(req)
		 || req->method == TFW_HTTP_METH_POST);
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
 * Release node-cpu map.
 */
static void
tfw_release_node_cpus(void)
{
	int node;

	if(!c_nodes)
		return;

	for_each_node_with_cpus(node) {
		if(c_nodes[node].cpu)
			kfree(c_nodes[node].cpu);
	}
	kfree(c_nodes);
}

/**
 * Create node-cpu map to use queue_work_on() for nodes scheduling.
 * 0th CPU is reserved for other tasks.
 * At the moment we doesn't support CPU hotplug, so enumerate only online CPUs.
 */
static int
tfw_init_node_cpus(void)
{
	int nr_cpus, cpu, node;

	T_DBG2("nr_online_nodes: %d", nr_online_nodes);

	c_nodes = kzalloc(nr_online_nodes * sizeof(CaNode), GFP_KERNEL);
	if(!c_nodes) {
		T_ERR("Failed to allocate nodes map for cache work scheduler");
		return -ENOMEM;
	}

	for_each_node_with_cpus(node) {
		nr_cpus = nr_cpus_node(node);
		T_DBG2("node: %d  nr_cpus: %d",node, nr_cpus);
		c_nodes[node].cpu = kmalloc(nr_cpus * sizeof(int), GFP_KERNEL);
		if(!c_nodes[node].cpu) {
			T_ERR("Failed to allocate CPU array for node %d for cache work scheduler",
				node);
			return -ENOMEM;
		}
	}

	for_each_online_cpu(cpu) {
		node = cpu_to_node(cpu);
		T_DBG2("node: %d  cpu: %d",node, cpu);
		c_nodes[node].cpu[c_nodes[node].nr_cpus++] = cpu;
	}

	return 0;
}

/**
 * Return TDB located on current NUMA node.
 *
 * NOTE: Use only if you ensure that only local node must be used.
 */
static TDB *
node_db(void)
{
	return c_nodes[numa_node_id()].db;
}

/**
 * Return TDB located on NUMA node with id @node.
 */
static TDB *
get_db_for_node(int node)
{
	return c_nodes[node].db;
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

/*
 * Find caching policy in specific vhost and location.
 */
static int
tfw_cache_policy(TfwVhost *vhost, TfwLocation *loc, TfwStr *arg)
{
	TfwCaPolicy *capo;

	/* Search locations in current loc. */
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
		TfwVhost *vhost_dflt = vhost->vhost_dflt;
		if (!vhost_dflt)
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
 * Decide if the cache can be employed. For a request path that means
 * that it can be served from cache if there's a cached response.
 * For a response path it means that the response can be stored in cache.
 *
 * Various cache action/control directives are consulted when making
 * the resulting decision.
 */
static bool
tfw_cache_employ_req(TfwHttpReq *req)
{
	/* TFW_HTTP_CC_CFG_CACHE_BYPASS set from config by "cache_disable" */
	if (req->cache_ctl.flags & TFW_HTTP_CC_CFG_CACHE_BYPASS)
		return false;

	int cmd = tfw_cache_policy(req->vhost, req->location, &req->uri_path);

	if (cmd == TFW_D_CACHE_BYPASS) {
		req->cache_ctl.flags |= TFW_HTTP_CC_CFG_CACHE_BYPASS;
		return false;
	}
	/* cache_fulfill - work as usual in cache mode. */
	BUG_ON(cmd != TFW_D_CACHE_FULFILL);

	if (req->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE)
		/*
		 * TODO: RFC 7234 4. "... a cache MUST NOT reuse a stored
		 * response, unless... the request does not contain the no-cache
		 * pragma, nor the no-cache cache directive unless the stored
		 * response is successfully validated."
		 *
		 * We can validate the stored response and serve request from
		 * cache. This reduces traffic to origin server.
		 */
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
	case 300: case 301: case 308:
		return true;
	case 404: case 405: case 410: case 414:
	case 501:
		/*
		 * According RFC 9111 all this status codes are cacheble
		 * but we don't cache response to POST request if fails.
		 */
		if (resp->req->method == TFW_HTTP_METH_GET
		    || resp->req->method == TFW_HTTP_METH_HEAD)
			return true;
	}
	return false;
}

static unsigned int
tfw_cache_get_effective_resp_flags(TfwHttpResp *resp, TfwHttpReq *req)
{
	unsigned int cc_ignore_flags =
		tfw_vhost_get_cc_ignore(req->location, req->vhost);
	return resp->cache_ctl.flags & ~cc_ignore_flags;
}

static bool
tfw_cache_employ_resp(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	unsigned int effective_resp_flags =
		tfw_cache_get_effective_resp_flags(resp, req);

#define CC_REQ_DONTCACHE				\
	(TFW_HTTP_CC_CFG_CACHE_BYPASS | TFW_HTTP_CC_NO_STORE)
#define CC_RESP_DONTCACHE				\
	(TFW_HTTP_CC_NO_STORE | TFW_HTTP_CC_PRIVATE	\
	 | TFW_HTTP_CC_NO_CACHE)
#define CC_RESP_EXPLICIT_FRESH_INFO			\
	(TFW_HTTP_CC_HDR_EXPIRES | TFW_HTTP_CC_MAX_AGE	\
	 | TFW_HTTP_CC_S_MAXAGE)
#define CC_RESP_CACHEIT					\
	(CC_RESP_EXPLICIT_FRESH_INFO | TFW_HTTP_CC_PUBLIC)
/*
 * RFC 9111 3.5:
 * A shared cache MUST NOT use a cached response to a request with an
 * Authorization header field (Section 11.6.2 of [HTTP]) to satisfy any
 * subsequent request unless the response contains a Cache-Control field
 * with a response directive (Section 5.2.2) that allows it to be stored
 * by a shared cache, and the cache conforms to the requirements of that
 * directive for that response.
 * In this specification, the following response directives have such an
 * effect: must-revalidate (Section 5.2.2.2), public (Section 5.2.2.9),
 * and s-maxage (Section 5.2.2.10).
 */
#define CC_RESP_AUTHCAN					\
	(TFW_HTTP_CC_S_MAXAGE | TFW_HTTP_CC_PUBLIC	\
	 | TFW_HTTP_CC_MUST_REVAL)
	/*
	 * TODO: Response no-cache -- should be cached.
	 * Should turn on unconditional revalidation.
	 */
	if (req->cache_ctl.flags & CC_REQ_DONTCACHE)
		return false;
	if (effective_resp_flags & CC_RESP_DONTCACHE)
		return false;
	if (!(req->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT)
	    && (req->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE))
		return false;
	if (!(effective_resp_flags & TFW_HTTP_CC_IS_PRESENT)
	    && (effective_resp_flags & TFW_HTTP_CC_PRAGMA_NO_CACHE))
		return false;
	if ((req->cache_ctl.flags & TFW_HTTP_CC_HDR_AUTHORIZATION)
	    && !(effective_resp_flags & CC_RESP_AUTHCAN))
		return false;
	if (!(effective_resp_flags & CC_RESP_CACHEIT)
	    && !tfw_cache_status_bydef(resp))
		return false;

	/*
	 * According to RFC 9110 9.3.3:
	 * Responses to POST requests are only cacheable when they include
	 * explicit freshness information and a Content-Location header field
	 * that has the same value as the POST's target URI.
	 */
	if (req->method == TFW_HTTP_METH_POST) {
		TfwStr *h = &resp->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_LOCATION];
		TfwStr h_val;

		if (!(effective_resp_flags & CC_RESP_EXPLICIT_FRESH_INFO))
			return false;
		tfw_http_msg_srvhdr_val(h, TFW_HTTP_HDR_CONTENT_LOCATION,
					&h_val);
		/*
		 * According to RFC 9110 8.7:
		 * If Content-Location is included in a 2xx (Successful)
		 * response message and its value refers (after conversion
		 * to absolute form) to a URI that is the same as the target
		 * URI, then the recipient MAY consider the content to be a
		 * current representation of that resource at the time indicated
		 * by the message origination date. But our research showed that
		 * none of the legitimate clients use absolute forms of URI, so
		 * we do not convert URI and Content-Location to absolute form.
		 */
		if (tfw_strcmp(&h_val, &req->uri_path))
			return false;
	}

#undef CC_RESP_AUTHCAN
#undef CC_RESP_CACHEIT
#undef CC_RESP_DONTCACHE
#undef CC_REQ_DONTCACHE

	return true;
}

/*
 * Calculate freshness lifetime according to RFC 7234 4.2.1.
 */
static long
tfw_cache_calc_lifetime(TfwHttpResp *resp)
{
	long lifetime;
	TfwHttpReq *req = resp->req;
	unsigned int effective_resp_flags =
		tfw_cache_get_effective_resp_flags(resp, req);

	if (effective_resp_flags & TFW_HTTP_CC_S_MAXAGE)
		lifetime = resp->cache_ctl.s_maxage;
	else if (effective_resp_flags & TFW_HTTP_CC_MAX_AGE)
		lifetime = resp->cache_ctl.max_age;
	else if (resp->cache_ctl.flags & TFW_HTTP_CC_HDR_EXPIRES)
		lifetime = resp->cache_ctl.expires - resp->date;
	else
		lifetime = req->cache_ctl.default_ttl;

	return lifetime;
}

/*
 * Calculate the current entry age according to RFC 7234 4.2.3.
 */
static long
tfw_cache_entry_age(TfwCacheEntry *ce)
{
	long apparent_age = max_t(long, 0, ce->resp_time - ce->date);
	long corrected_age = ce->age + ce->resp_time - ce->req_time;
	long initial_age = max(apparent_age, corrected_age);
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
static long
tfw_cache_entry_is_live(TfwHttpReq *req, TfwCacheEntry *ce, long ce_age)
{
	long ce_lifetime, lt_fresh = UINT_MAX;

	if (ce->lifetime <= 0)
		return 0;

#define CC_LIFETIME_FRESH	(TFW_HTTP_CC_MAX_AGE | TFW_HTTP_CC_MIN_FRESH)
	if (req->cache_ctl.flags & CC_LIFETIME_FRESH) {
		long lt_max_age = UINT_MAX, lt_min_fresh = UINT_MAX;
		if (req->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE)
			lt_max_age = req->cache_ctl.max_age;
		if (req->cache_ctl.flags & TFW_HTTP_CC_MIN_FRESH)
			lt_min_fresh = ce->lifetime - req->cache_ctl.min_fresh;
		lt_fresh = min(lt_max_age, lt_min_fresh);
	}
	/*
	 * RFC 7234 Section 4.2.4:
	 * A cache MUST NOT generate a stale response if it is prohibited by an
	 * explicit in-protocol directive (e.g., by a "no-store" or "no-cache"
	 * cache directive, a "must-revalidate" cache-response-directive, or an
	 * applicable "s-maxage" or "proxy-revalidate" cache-response-directive;
	 * see Section 5.2.2).
	 */
	/* tfw_cache_copy_resp() calculates the TFW_CE_MUST_REVAL flag */
	if (!(req->cache_ctl.flags & TFW_HTTP_CC_MAX_STALE)
	    || (ce->flags & TFW_CE_MUST_REVAL))
	{
		ce_lifetime = min(lt_fresh, ce->lifetime);
	} else {
		long lt_max_stale = ce->lifetime + req->cache_ctl.max_stale;
		ce_lifetime = min(lt_fresh, lt_max_stale);
	}
#undef CC_LIFETIME_FRESH

	return ce_age > ce_lifetime ? 0 : ce_lifetime;
}

static bool
tfw_cache_cond_none_match(TfwHttpReq *req, TfwCacheEntry *ce)
{
	TfwStr match_list, iter;

	if (TFW_STR_EMPTY(&ce->etag))
		return true;

	if (req->cond.flags & TFW_HTTP_COND_ETAG_ANY)
		return false;

	match_list = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
	iter = tfw_str_next_str_val(&match_list);

	while (!TFW_STR_EMPTY(&iter)) {
		/* RFC 7232 3.2: Weak validation. Don't check WEAK tagging. */
		if (!tfw_strcmpspn(&iter, &ce->etag, '"'))
			return false;

		iter = tfw_str_next_str_val(&iter);
	}

	return true;
}

/**
 * Add a new header with size of @len starting from @data to HTTP response @resp,
 * expanding the @resp with new skb/frags if needed.
 */
static int
tfw_cache_h2_write(TDB *db, TdbVRec **trec, TfwHttpResp *resp, char **data,
		   size_t len, TfwDecodeCacheIter *dc_iter)
{
	TfwStr c = { 0 };
	TdbVRec *tr = *trec;
	TfwHttpTransIter *mit = &resp->mit;
	TfwMsgIter *it = &resp->iter;
	int r = 0, copied = 0;

	while (1)  {
		c.data = *data;
		c.len = min(tr->data + tr->len - *data, (long)(len - copied));
		if (!dc_iter->skip) {
			r = tfw_http_msg_expand_data(it, &resp->msg.skb_head,
						     &c, &mit->start_off);
			if (unlikely(r))
				break;

			dc_iter->acc_len += c.len;
		}

		copied += c.len;
		*data += c.len;

		T_DBG3("%s: len='%zu', copied='%d', dc_iter->acc_len='%lu',"
		       " dc_iter->skip='%d'\n", __func__, len, copied,
		       dc_iter->acc_len, dc_iter->skip);

		if (copied == len)
			break;

		tr = *trec = tdb_next_rec_chunk(db, tr);
		BUG_ON(!tr);
		*data = tr->data;
	}

	return r;
}

/**
 * Same as @tfw_cache_h2_write(), but also decode the header from HTTP/2 format
 * before writing it into the response (used e.g. for HTTP/1.1-response creation
 * from cache).
 */
static int
tfw_cache_h2_decode_write(TDB *db, TdbVRec **trec, TfwHttpResp *resp,
			  char **data, size_t len, TfwDecodeCacheIter *dc_iter)
{
	unsigned long m_len;
	TdbVRec *tr = *trec;
	int r = 0, acc = 0;
	TfwHPack hp = {};

	while (1)  {
		m_len = min(tr->data + tr->len - *data, (long)(len - acc));
		if (!dc_iter->skip) {
			r = tfw_hpack_cache_decode_expand(&hp, resp, *data,
							  m_len, dc_iter);
			if (unlikely(r))
				break;
		}

		acc += m_len;
		*data += m_len;
		if (acc == len) {
			TFW_STR_INIT(&dc_iter->hdr_data);
			break;
		}

		tr = *trec = tdb_next_rec_chunk(db, tr);
		BUG_ON(!tr);
		*data = tr->data;
	}

	return r;
}

static int
tfw_cache_set_status(TDB *db, TfwCacheEntry *ce, TfwHttpResp *resp,
		     TdbVRec **trec, char **p, unsigned long *acc_len)
{
	int r;
	TfwMsgIter *it = &resp->iter;
	struct sk_buff **skb_head = &resp->msg.skb_head;
	bool h2_mode = TFW_MSG_H2(resp->req);
	TfwDecodeCacheIter dc_iter = {};

	if (h2_mode)
		resp->mit.start_off = FRAME_HEADER_SIZE;
	else
		dc_iter.skip = true;


	r = tfw_cache_h2_write(db, trec, resp, p, ce->status_len, &dc_iter);
	if (unlikely(r))
		return r;

	resp->status = ce->resp_status;

	if (!h2_mode) {
		char buf[H2_STAT_VAL_LEN];
		TfwStr s_line = {
			.chunks = (TfwStr []){
				{ .data = S_0, .len = SLEN(S_0) },
				{ .data = buf, .len =  H2_STAT_VAL_LEN}
			},
			.len = SLEN(S_0) + H2_STAT_VAL_LEN,
			.nchunks = 2
		};

		if (!tfw_ultoa(ce->resp_status, __TFW_STR_CH(&s_line, 1)->data,
			       H2_STAT_VAL_LEN))
			return -E2BIG;

		r = tfw_http_msg_expand_data(it, skb_head, &s_line, NULL);
		if (unlikely(r))
			return r;

		*acc_len += s_line.len;
	}

	dc_iter.skip = h2_mode ? true : false;

	r = tfw_cache_h2_write(db, trec, resp, p, ce->rph_len, &dc_iter);
	if (unlikely(r))
		return r;

	*acc_len += dc_iter.acc_len;

	if (!h2_mode) {
		r = tfw_http_msg_expand_data(it, skb_head, &g_crlf, NULL);
		if (unlikely(r))
			return r;

		*acc_len += g_crlf.len;
	}

	return 0;
}

static bool
tfw_cache_skip_hdr(const TfwCStr *str, char *p, const TfwHdrMods *h_mods,
		   bool h2_mode)
{
	unsigned int i;
	const TfwHdrModsDesc *desc;
	/*
	 * Move to beggining of the header name. Skip first byte of HPACK
	 * string and name length size.
	 */
	TfwStr hdr = { .data = p + str->name_len_sz + 1,
		       .len  = str->name_len };

	if (h2_mode && str->flags & TFW_CSTR_SKIP_FOR_H2)
		return true;

	if (!h_mods)
		return false;

	/* Fast path for special headers */
	if (str->flags & TFW_CSTR_SPEC_IDX)
		return test_bit(str->idx, h_mods->spec_hdrs);

	if (str->idx) {
		unsigned short hpack_idx = str->idx;

		if (hpack_idx <= HPACK_STATIC_TABLE_REGULAR)
			return false;

		return test_bit(hpack_idx, h_mods->s_tbl);
	}

	for (i = h_mods->scan_off; i < h_mods->set_num; ++i) {
		char* mod_hdr_name;
		size_t mod_hdr_len;

		desc = &h_mods->hdrs[i];
		mod_hdr_len = TFW_STR_CHUNK(desc->hdr, 0)->len;
		if (mod_hdr_len != hdr.len)
			continue;

		mod_hdr_name = TFW_STR_CHUNK(desc->hdr, 0)->data;

		if (!tfw_cstricmp(hdr.data, mod_hdr_name, hdr.len))
			return true;
	}

	return false;
}

/**
 * Write HTTP header to skb data.
 */
static int
tfw_cache_build_resp_hdr(TDB *db, TfwHttpResp *resp, TfwHdrMods *hmods,
			 TdbVRec **trec, char **p, unsigned long *acc_len,
			 bool skip, TfwCacheHdrType type)
{
	tfw_cache_write_actor_t *write_actor;
	TfwCStr *s;
	TfwHttpReq *req = resp->req;
	TfwDecodeCacheIter dc_iter = { .h_mods = hmods, .skip = skip };
	int d, dn, r = 0;
	bool h2_mode = TFW_MSG_H2(req);

/* Go to the next chunk if we at the end of current. */
#define NEXT_CHUNK()							\
do {									\
	if (*p - (*trec)->data == (*trec)->len) {			\
		*trec = tdb_next_rec_chunk(db, (*trec));		\
		*p = (*trec)->data;					\
	}								\
} while (0)

	BUG_ON(!req);

	write_actor = !h2_mode ? tfw_cache_h2_decode_write
			       : tfw_cache_h2_write;

	NEXT_CHUNK();
	s = (TfwCStr *)*p;
	*p += TFW_CSTR_HDRLEN;
	BUG_ON(*p > (*trec)->data + (*trec)->len);

	if (likely(!(s->flags & TFW_CSTR_DUPLICATE))) {
		if (!skip)
			dc_iter.skip = tfw_cache_skip_hdr(s, *p, hmods,
							  h2_mode);
		r = write_actor(db, trec, resp, p, s->len, &dc_iter);
		if (likely(!r))
			*acc_len += dc_iter.acc_len;
		return r;
	}

	if (!skip)
		dc_iter.skip = tfw_cache_skip_hdr((TfwCStr *)*p,
						  *p + TFW_CSTR_HDRLEN, hmods,
						  h2_mode);

	/* Process duplicated headers. */
	dn = s->len;
	for (d = 0; d < dn; ++d) {
		NEXT_CHUNK();
		s = (TfwCStr *)*p;
		BUG_ON(s->flags & TFW_CSTR_DUPLICATE);

		skip = dc_iter.skip;
		if (!dc_iter.skip) {
			/*
			 * If header is present in headers and in trailers
			 * we save this header in cache two times. When we
			 * build response from cache we check what chunks
			 * of duplicate header belong to headers and what
			 * to trailers and write it to response depends on
			 * header or trailer we restore now.
			 */
			dc_iter.skip = !(((type == TFW_CACHE_HDR &&
					 !(s->flags & TFW_CSTR_TRAILER))
					|| (type == TFW_CACHE_TRAILER
					    && (s->flags & TFW_CSTR_TRAILER))));
		}

		*p += TFW_CSTR_HDRLEN;
		r = write_actor(db, trec, resp, p, s->len, &dc_iter);
		if (unlikely(r))
			break;

		dc_iter.skip = skip;
	}
	*acc_len += dc_iter.acc_len;

	return r;
}

/**
 * RFC 7232 Section-4.1: The server generating a 304 response MUST generate:
 * Cache-Control, Content-Location, Date, ETag, Expires, and Vary.
 * Last-Modified might be used if the response does not have an ETag field.
 *
 * The 304 response should be as short as possible, we don't need to add
 * extra headers.
 */
static void
tfw_cache_send_304(TfwHttpReq *req, TfwCacheEntry *ce)
{
	char *p;
	int r, i;
	TfwMsgIter *it;
	TfwHttpResp *resp;
	struct sk_buff **skb_head;
	unsigned long h_len = 0;
	TdbVRec *trec = &ce->trec;
	TDB *db = node_db();

	WARN_ON_ONCE(!list_empty(&req->fwd_list));
	WARN_ON_ONCE(!list_empty(&req->nip_list));

	if (!(resp = tfw_http_msg_alloc_resp_light(req)))
		goto err_create;

	it = &resp->iter;
	skb_head = &resp->msg.skb_head;

	if (!TFW_MSG_H2(req)) {
		r = tfw_http_prep_304(req, skb_head, it);
		if (unlikely(r))
			goto err_setup;
	} else {
		resp->mit.start_off = FRAME_HEADER_SIZE;

		r = tfw_h2_resp_status_write(resp, 304, false, true);
		if (unlikely(r))
			goto err_setup;
		/* account for :status field itself */
		h_len++;

		resp->status = 304;

		/*
		 * Responses built from cache has room for frame header reserved
		 * in SKB linear data.
		 */
		resp->mit.frame_head = it->skb_head->data;
	}

	/* Put 304 headers */
	for (i = 0; i < ARRAY_SIZE(ce->hdrs_304); ++i) {
		if (!ce->hdrs_304[i])
			continue;

		p = TDB_PTR(db->hdr, ce->hdrs_304[i]);
		while (trec && (p > trec->data + trec->len))
			trec = tdb_next_rec_chunk(db, trec);
		BUG_ON(!trec);

		if (tfw_cache_build_resp_hdr(db, resp, NULL, &trec, &p, &h_len,
					     false, TFW_CACHE_HDR))
		{
			goto err_setup;
		}
	}

	if (!TFW_MSG_H2(req)) {
		if (tfw_http_msg_expand_data(it, skb_head, &g_crlf, NULL))
			goto err_setup;

		tfw_http_resp_fwd(resp);

		return;
	}

	if (tfw_h2_frame_local_resp(resp, h_len, NULL))
		goto err_setup;

	tfw_h2_req_unlink_stream(req);
	tfw_h2_resp_fwd(resp);

	return;
err_setup:
	T_WARN("Can't build 304 response, key=%lx\n", ce->key);
	tfw_http_msg_free((TfwHttpMsg *)resp);
err_create:
	tfw_http_resp_build_error(req);
}

/**
 * Received request can contain validation information. Process it according to
 * RFC 7234 Section 4.3.2.
 *
 * Return value:
 *	@true: @req can be served from cache;
 *	@false: Response was sent to client (412 or 304).
 */
static bool
tfw_handle_validation_req(TfwHttpReq *req, TfwCacheEntry *ce)
{
	if ((ce->resp_status != 200) && (ce->resp_status != 206))
		return true;

	/* All other methods can't be satisfied by cache. */
	BUG_ON(req->method != TFW_HTTP_METH_GET
	       && req->method != TFW_HTTP_METH_HEAD);

	/* If-None-Match: */
	if (!TFW_STR_EMPTY(&req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH])) {
		if (!tfw_cache_cond_none_match(req, ce)) {
			tfw_cache_send_304(req, ce);
			return false;
		}
	}
	/* If-Modified-Since: */
	else if (req->cond.m_date) {
		bool send_304 = false;

		if (ce->last_modified) {
			if (ce->last_modified <= req->cond.m_date)
				send_304 = true;
		}
		else if (ce->date) {
			if (ce->date <= req->cond.m_date)
				send_304 = true;
		}
		else {
			if (ce->resp_time <= req->cond.m_date)
				send_304 = true;
		}

		if (send_304) {
			tfw_cache_send_304(req, ce);
			return false;
		}
	}
	/* TODO #499: Range GET requests. RFC 7232 Section 6, step 5. */

	return true;
}

static bool
tfw_cache_should_satisfy(TfwHttpReq *req, TfwCacheEntry *ce)
{
	/*
	 * According to RFC 9110 9.3.1:
	 * The response to a GET request is cacheable; a cache MAY use
	 * it to satisfy subsequent GET and HEAD requests unless otherwise
	 * indicated by the Cache-Control header field.
	 */
	/*
	 * According to RFC 9110 9.3.3:
	 * A cached POST response can be reused to satisfy a later GET or
	 * HEAD request.
	 */
	if ((req->method != TFW_HTTP_METH_PURGE)
	    && !(ce->method == TFW_HTTP_METH_GET
		 && req->method == TFW_HTTP_METH_HEAD)
	    && !(ce->method == TFW_HTTP_METH_POST
		 && (req->method == TFW_HTTP_METH_GET
		     || req->method == TFW_HTTP_METH_HEAD))
	    && (ce->method != req->method))
		return false;

	/*
	 * According to RFC 9110 9.3.3:
	 * In contrast, a POST request cannot be satisfied by a cached
	 * POST response because POST is potentially unsafe.
	 */
	if ((req->method == TFW_HTTP_METH_POST
	     && ce->method == TFW_HTTP_METH_POST))
		return false;

	return true;
}

static bool
tfw_cache_entry_key_eq(TDB *db, TfwHttpReq *req, TfwCacheEntry *ce)
{
	/* Record key starts at first data chunk. */
	int n, c_off = 0, t_off;
	TdbVRec *trec = &ce->trec;
	TfwStr *c, *u_end, *v_end;
	TfwStr v_start;
	bool u_fin, v_fin;

	if (req->uri_path.len + req->vhost->name.len != ce->key_len)
		return false;

	t_off = CE_BODY_SIZE;
	TFW_CACHE_REQ_KEYITER(c, &req->uri_path, &req->vhost->name, u_end,
			      &v_start, v_end, u_fin, v_fin)
	{
		if (!trec)
			return false;
this_chunk:
		n = min(c->len - c_off, (unsigned long)trec->len - t_off);
		/* Cache key is stored in lower case. */
		if (tfw_cstricmp_2lc(c->data + c_off, trec->data + t_off, n))
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

/*
 * Select the most appropriate cache entry for this request.
 */
static TfwCacheEntry *
tfw_cache_dbce_get(TDB *db, TdbIter *iter, TfwHttpReq *req)
{
	TfwCacheEntry *ce;
	unsigned long key = tfw_http_req_key_calc(req);

	*iter = tdb_rec_get(db, key);
	if (TDB_ITER_BAD(*iter)) {
		return NULL;
	}
	/*
	 * Basically, it is sufficient to store only the most recent response and
	 * remove other representations from cache(current approach).
	 * (RFC 7234 4: When more than one suitable response is stored, a cache
	 * MUST use the most recent response) But there are still some cases
	 * when it is needed to store more than one representation:
	 *   - If selected representation of the effective Request URI depends
	 *     on client capabilities. See RFC 7234 4.1 (Vary Header).
	 *   - If origin server has several states of the resource, so during
	 *     revalidation we can get the current state without downloading the
	 *     full representation. This can reduce traffic to origin server.
	 *     See RFC 7323 2.1 for the example.
	 *
	 * TODO: tfw_cache_entry_key_eq() should be extended to support
	 * secondary keys (#508) and to skip not current representations.
	 * Currently this function is used only to serve clients.
	 */
	ce = (TfwCacheEntry *)iter->rec;
	do {
		/* Find record with the same key. */
		if (tfw_cache_should_satisfy(req, ce) &&
		    tfw_cache_entry_key_eq(db, req, ce))
		{
			return ce;
		}
		tdb_rec_next(db, iter);
		ce = (TfwCacheEntry *)iter->rec;
	} while (ce);

	return NULL;
}

/**
 * Copies plain TfwStr @src to TdbRec @trec.
 * @return number of copied bytes (@src length).
 *
 * The function copies part of some large data of length @tot_len,
 * so it tries to minimize total number of allocations regardless
 * how many chunks are copied.
 */
static long
__tfw_cache_strcpy(TDB *db, char **p, TdbVRec **trec, TfwStr *src, size_t tot_len,
		   void cpy(void *dest, const void *src, size_t n))
{
	long copied = 0;

	while (copied < src->len) {
		int room = (*trec)->data + (*trec)->len - *p;
		BUG_ON(room < 0);
		if (!room) {
			BUG_ON(tot_len < copied);
			*trec = tdb_entry_add(db, *trec, tot_len - copied);
			if (!*trec)
				return -ENOMEM;
			*p = (*trec)->data;
			room = (*trec)->len;
		}

		T_DBG3("Cache: copy [%.*s](%lu) to rec=%p(len=%u, next=%u),"
		       " p=%p tot_len=%lu room=%d copied=%ld\n",
		       PR_TFW_STR(src), src->len, *trec, (*trec)->len,
		       (*trec)->chunk_next, *p, tot_len, room, copied);

		room = min((unsigned long)room, src->len - copied);
		cpy(*p, src->data + copied, room);
		*p += room;
		copied += room;
	}

	return copied;
}

/**
 * We need the function wrapper if memcpy() is defined as __inline_memcpy().
 */
static void
__tfw_memcpy(void *dst ,const void *src, size_t n)
{
	memcpy_fast(dst, src, n);
}

static inline long
tfw_cache_strcpy(TDB *db, char **p, TdbVRec **trec, TfwStr *src, size_t tot_len)
{
	return __tfw_cache_strcpy(db, p, trec, src, tot_len, __tfw_memcpy);
}

/**
 * The same as tfw_cache_strcpy(), but copies @src with lower case conversion.
 */
static inline long
tfw_cache_strcpy_lc(TDB *db, char **p, TdbVRec **trec, TfwStr *src,
		    size_t tot_len)
{
	return __tfw_cache_strcpy(db, p, trec, src, tot_len, tfw_cstrtolower);
}

#define CSTR_MOVE_HDR()				\
do {						\
	cs = (TfwCStr *)*p;			\
	*p += TFW_CSTR_HDRLEN;			\
	*tot_len -= TFW_CSTR_HDRLEN;		\
	ce->hdr_len += TFW_CSTR_HDRLEN;		\
} while (0)

#define CSTR_WRITE_HDR(f, l, nl, i)			\
do {							\
	cs->flags = f;					\
	cs->len = l;					\
	cs->name_len = nl;				\
	cs->name_len_sz = tfw_hpack_int_size(nl, 0x7f);	\
	cs->idx = i;					\
} while (0)

/**
 * Copies http *chunked* body to TdbRec @trec. The copied data does not
 * contain the chunked encoding descriptors.
 *
 * @body basically used for validation.
 * @cut TfwStr containing chunked descriptors. Used as beginning of the body.
 * @return zero on success and negative value otherwise.
 */
static int
tfw_cache_h2_copy_chunked_body(TDB *db, size_t *acc_len, char **p,
			       TdbVRec **trec, TfwHttpResp *resp, TfwStr *cut,
			       size_t *tot_len)
{
	long n;
	TfwMsgIter it;
	TfwStr *tmp;
	char *curr = NULL, *stop, *begin, *end, *prev_end = NULL;
	int stop_len, c_chunk = 0;
	TfwStr *body = &resp->body;

	BUG_ON(TFW_STR_DUP(body));

	/* Body has only zero chunk. */
	if (unlikely(!body->len || body->len == cut->len))
		return 0;

	if (unlikely(!cut->len))
		return -EINVAL;

	/*
	 * If we have cut-chunks less then two and body is not empty it means
	 * parser is broken.
	 */
	BUG_ON(cut->nchunks < 2 && body->len > 0);

	it.skb = cut->skb;
	it.skb_head = resp->msg.skb_head;
	it.frag = -(!!skb_headlen(it.skb));

	/* Skip frags and chunks with headers. */
	tmp = __TFW_STR_CH(cut, c_chunk);
	curr = stop = tmp->data;
	stop_len = tmp->len;

	while (true) {
		if (it.frag == -1) {
			begin = it.skb->data;
			end = begin + skb_headlen(it.skb);
		} else {
			skb_frag_t *f = &skb_shinfo(it.skb)->frags[it.frag];

			begin = skb_frag_address(f);
			end = begin + skb_frag_size(f);
		}

		if (likely(!curr)) {
			/* Previous fragment is fully copied. */
			curr = begin;
		}
		else if (curr == prev_end) {
			/* Chunk descriptor is at the end of the last frag. */
			if (stop == begin) {
				/*
				 * New frags starts from the suffix of the chunk
				 * descriptor...
				 */
				curr = stop;
				goto continue_curr_frag;
			}
			/*
			 * ...otherwise we start copying from the beginning of
			 * the new frag.
			 */
			curr = begin;
		}
		else if (curr == stop) {
continue_curr_frag:
			/* Stop is reached, get the next stop. */
			if (++c_chunk >= cut->nchunks)
				return 0;
			curr += stop_len;
			tmp = __TFW_STR_CH(cut, c_chunk);
			stop = tmp->data;
			stop_len = tmp->len;
		}
		/*
		 * ...otherwise curr = stop + stop_len, i.e. we still didn't
		 * reach the place where we should start copying.
		 */

		if (likely(ss_skb_is_within_fragment(begin, curr, end))) {
			TfwStr chunk = {.len = 0};

			/* Stop found in current frag. */
			if (ss_skb_is_within_fragment(begin, stop, end)) {
				chunk.data = curr;
				chunk.len = stop - curr;
				curr = stop;
			} else {
				/* Stop not found. Copy whole frag. */
				chunk.data = curr;
				chunk.len = end - curr;
				curr = NULL;
			}

			if (likely(chunk.len)) {
				n = tfw_cache_strcpy(db, p, trec, &chunk,
						     *tot_len);
				if (unlikely(n < 0)) {
					T_ERR("Cache: cannot copy chunk of HTTP body\n");
					return -ENOMEM;
				}

				*tot_len -= n;
				*acc_len += n;
			}

			if (curr)
				goto continue_curr_frag;
		}

		prev_end = end;

		it.frag++;
		if (it.frag >= skb_shinfo(it.skb)->nr_frags) {
			it.skb = it.skb->next;
			if (it.skb == it.skb_head)
				return 0;

			it.frag = -(!!skb_headlen(it.skb));
		}
	}

	return 0;
}

/**
 * Copies http body to TdbRec @trec.
 *
 * @body Http response body.
 * @return zero on success and negative value otherwise.
 */
static int
tfw_cache_h2_copy_body(TDB *db, size_t *acc_len, char **p, TdbVRec **trec,
		       TfwHttpResp *resp, size_t *tot_len)
{
	long n;
	int r;
	TfwMsgIter it;
	TfwStr chunk = {0};
	TfwStr *body = &resp->body;

	BUG_ON(TFW_STR_DUP(body));

	if (unlikely(!body->len))
		return 0;

	r = tfw_body_iter_init(&it, &chunk, body->data, body->skb,
			       resp->msg.skb_head);
	if (unlikely(r))
		return r;

	TFW_BODY_ITER_WALK(&it, &chunk)
	{
		n = tfw_cache_strcpy(db, p, trec, &chunk, *tot_len);
		if (unlikely(n < 0)) {
			T_ERR("Cache: cannot copy chunk of HTTP body\n");
			return -ENOMEM;
		}

		*tot_len -= n;
		*acc_len += n;
	}

	WARN_ON(*acc_len != body->len);

	return 0;
}

/**
 * Copies plain or compound (chunked) TfwStr @src to TdbRec @trec.
 *
 * @src is copied
 * @return number of copied bytes on success and negative value otherwise.
 */
static int
tfw_cache_h2_copy_str_common(TDB *db, unsigned int *acc_len, char **p,
			     TdbVRec **trec, TfwStr *src, size_t *tot_len,
			     long cache_strcpy(TDB *db, char **p,
					       TdbVRec **trec, TfwStr *src,
					       size_t tot_len))
{
	long n;
	TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(src));

	if (unlikely(!src->len))
		return 0;

	TFW_STR_FOR_EACH_CHUNK(c, src, end) {
		n = cache_strcpy(db, p, trec, c, *tot_len);
		if (unlikely(n < 0)) {
			T_ERR("Cache: cannot copy chunk of HTTP/2 string\n");
			return -ENOMEM;
		}

		*tot_len -= n;
		*acc_len += n;
	}

	return 0;
}

static int
tfw_cache_h2_copy_str(TDB *db, unsigned int *acc_len, char **p, TdbVRec **trec,
		      TfwStr *src, size_t *tot_len)
{
	return tfw_cache_h2_copy_str_common(db, acc_len, p, trec, src, tot_len,
					    tfw_cache_strcpy);
}

static int
tfw_cache_h2_copy_str_lc(TDB *db, unsigned int *acc_len, char **p,
			 TdbVRec **trec, TfwStr *src, size_t *tot_len)
{
	return tfw_cache_h2_copy_str_common(db, acc_len, p, trec, src, tot_len,
					    tfw_cache_strcpy_lc);
}

static inline int
tfw_cache_h2_copy_int(TDB *db, unsigned int *acc_len, unsigned long src,
		      unsigned short max, char **p, TdbVRec **trec,
		      size_t *tot_len)
{
	int r;
	TfwHPackInt hp_int;
	TfwStr str = {};

	write_int(src, max, 0, &hp_int);

	str.data = hp_int.buf;
	str.len = hp_int.sz;

	r = tfw_cache_h2_copy_str(db, acc_len, p, trec, &str, tot_len);
	if (unlikely(r))
		return r;

	return 0;
}

static int
tfw_cache_copy_str_with_extra_quotes(TDB *db, TfwCacheEntry *ce, char **p,
				     TdbVRec **trec, TfwStr *src,
				     size_t *tot_len, bool need_extra_quotes)
{
#define ADD_ETAG_QUOTE(flag)                                            \
do {                                                                    \
	TfwStr quote = { .data = "\"", .len = 1, .flags = flag };       \
	if (tfw_cache_h2_copy_str(db, &ce->hdr_len, p, trec, &quote,        \
				  tot_len))                             \
		return -ENOMEM;                                         \
} while(0)

	if (need_extra_quotes)
		ADD_ETAG_QUOTE(0);

	if (tfw_cache_h2_copy_str(db, &ce->hdr_len, p, trec, src, tot_len))
		return -ENOMEM;

	if (need_extra_quotes)
		ADD_ETAG_QUOTE(TFW_STR_VALUE);

	return 0;

#undef ADD_ETAG_QUOTE
}

/**
 * Deep HTTP header copy to TdbRec.
 * @hdr is copied in depth first fashion to speed up upcoming scans.
 * @return number of copied bytes on success and negative value otherwise.
 */
static long
tfw_cache_h2_copy_hdr(TDB *db, TfwCacheEntry *ce, TfwHttpResp *resp, int hid,
		      char **p, TdbVRec **trec, TfwStr *hdr, size_t *tot_len)
{
	TfwCStr *cs;
	long n = sizeof(TfwCStr);
	unsigned short st_index = 0;
	bool dupl = TFW_STR_DUP(hdr);
	unsigned int init_len = ce->hdr_len;
	TfwStr s_nm, s_val, *dup, *dup_end;
	unsigned long s_val_len;
	const bool need_extra_quotes =
		test_bit(TFW_HTTP_B_HDR_ETAG_HAS_NO_QOUTES, resp->flags)
		&& (hid == TFW_HTTP_HDR_ETAG);
	unsigned int extra_flags = (hid == TFW_HTTP_HDR_TRANSFER_ENCODING ?
		TFW_CSTR_SKIP_FOR_H2 : 0);
	unsigned int dupl_extra_flags = 0;

	T_DBG3("%s: ce=[%p] p=[%p], trec=[%p], tot_len='%zu'\n", __func__, ce,
	       *p, *trec, *tot_len);

	if (likely(!dupl)) {
		unsigned long h_len;

		TFW_STR_INIT(&s_nm);
		TFW_STR_INIT(&s_val);
		tfw_http_hdr_split(hdr, &s_nm, &s_val, true);

		st_index = hdr->hpack_idx;
		h_len = tfw_h2_hdr_size(s_nm.len, s_val.len, st_index) +
			2 * need_extra_quotes;

		/* Don't split short strings and header name. */
		if (sizeof(TfwCStr) + h_len <= L1_CACHE_BYTES)
			n += h_len;
		else
			n += s_nm.len;
	}

	*p = tdb_entry_get_room(db, trec, *p, n, *tot_len);
	if (unlikely(!*p)) {
		T_WARN("Cache: cannot allocate TDB space\n");
		return -ENOMEM;
	}

	if (TFW_STR_DUP(hdr)) {
		CSTR_MOVE_HDR();
		if (hid >= TFW_HTTP_HDR_REGULAR  && hid < TFW_HTTP_HDR_RAW)
			CSTR_WRITE_HDR(TFW_CSTR_SPEC_IDX | TFW_CSTR_DUPLICATE |
				       extra_flags, hdr->nchunks, 0, hid);
		else
			CSTR_WRITE_HDR(TFW_CSTR_DUPLICATE | extra_flags,
				       hdr->nchunks, 0, st_index);
	}

	TFW_STR_FOR_EACH_DUP(dup, hdr, dup_end) {
		unsigned int prev_len;

		if (dupl) {
			TFW_STR_INIT(&s_nm);
			TFW_STR_INIT(&s_val);
			tfw_http_hdr_split(dup, &s_nm, &s_val, true);
			st_index = dup->hpack_idx;
			*p = tdb_entry_get_room(db, trec, *p, n + s_nm.len,
						*tot_len);
			if (unlikely(!*p)) {
				T_WARN("Cache: cannot allocate TDB space\n");
				return -ENOMEM;
			}
		}
		CSTR_MOVE_HDR();
		prev_len = ce->hdr_len;

		if (st_index) {
			if (tfw_cache_h2_copy_int(db, &ce->hdr_len, st_index,
						  0xF, p, trec, tot_len))
				return -ENOMEM;
		}
		else {
			if (tfw_cache_h2_copy_int(db, &ce->hdr_len, 0, 0xF, p,
						  trec, tot_len)
			    || tfw_cache_h2_copy_int(db, &ce->hdr_len, s_nm.len,
						     0x7f, p, trec, tot_len)
			    || tfw_cache_h2_copy_str_lc(db, &ce->hdr_len, p,
							trec, &s_nm, tot_len))
				return -ENOMEM;
		}

		s_val_len =  s_val.len + 2 * need_extra_quotes;
		if (tfw_cache_h2_copy_int(db, &ce->hdr_len, s_val_len, 0x7f, p,
					  trec, tot_len)
		    || tfw_cache_copy_str_with_extra_quotes(db, ce, p, trec,
							    &s_val, tot_len,
							    need_extra_quotes))
			return -ENOMEM;

		dupl_extra_flags = extra_flags | (dup->flags & TFW_STR_TRAILER ?
			TFW_CSTR_TRAILER : 0);

		if (hid >= TFW_HTTP_HDR_REGULAR && hid < TFW_HTTP_HDR_RAW)
			CSTR_WRITE_HDR(TFW_CSTR_SPEC_IDX | dupl_extra_flags,
				       ce->hdr_len - prev_len, 0, hid);
		else
			CSTR_WRITE_HDR(dupl_extra_flags, ce->hdr_len - prev_len,
				       s_nm.len, st_index);
	}

	T_DBG3("%s: p=[%p], trec=[%p], ce->hdr_len='%u', tot_len='%zu'\n",
	       __func__, *p, *trec, ce->hdr_len, *tot_len);

	return ce->hdr_len - init_len;
}

static long
tfw_cache_h2_add_hdr(TDB *db, TfwCacheEntry *ce, char **p, TdbVRec **trec,
		     unsigned short st_idx, TfwStr *val, size_t *tot_len,
		     unsigned int flags)
{
	TfwCStr *cs;
	unsigned long len;
	unsigned int prev_len = ce->hdr_len;
	long n = TFW_CSTR_HDRLEN;

	BUG_ON(!st_idx || TFW_STR_EMPTY(val) || st_idx > 61);

	len = tfw_hpack_int_size(st_idx, 0xF)
		+ tfw_hpack_int_size(val->len, 0x7F)
		+ val->len;

	if (unlikely(len >= TFW_CSTR_MAXLEN)) {
		T_WARN("Cache: trying to store too big string %lx\n", len);
		return -E2BIG;
	}

	/* Don't split short strings. */
	if (TFW_CSTR_HDRLEN + len <= L1_CACHE_BYTES)
		n += len;

	*p = tdb_entry_get_room(db, trec, *p, n, *tot_len);
	if (unlikely(!*p)) {
		T_WARN("jCache: cannot allocate TDB space\n");
		return -ENOMEM;
	}

	CSTR_MOVE_HDR();

	if (tfw_cache_h2_copy_int(db, &ce->hdr_len, st_idx, 0xF, p, trec,
				  tot_len))
		return -ENOMEM;

	if (tfw_cache_h2_copy_int(db, &ce->hdr_len, val->len, 0x7f, p, trec,
				  tot_len))
		return -ENOMEM;

	if (tfw_cache_h2_copy_str(db, &ce->hdr_len, p, trec, val, tot_len))
		return -ENOMEM;

	CSTR_WRITE_HDR(flags, ce->hdr_len - prev_len - TFW_CSTR_HDRLEN, 0,
		       st_idx);

	return ce->hdr_len - prev_len;
}

/**
 * Add 'Content-Encoding' header to the cache record. The list of encodings
 * will be taken from 'Transfer-Encoding' header.
 */
static long
tfw_cache_add_hdr_cenc(TDB *db, TfwHttpResp *resp, TfwCacheEntry *ce, char **p,
		       TdbVRec **trec, size_t *tot_len)
{
	char *buf = *this_cpu_ptr(&g_c_buf);
	long r;
	TfwStr chunk = { .data = buf, .len = 0 };
	TfwStr val_ce = { .chunks = &chunk, .nchunks = 1 };

	r = tfw_http_resp_copy_encodings(resp, &chunk, RESP_BUF_LEN);
	if (unlikely(r))
		return r;

	val_ce.len = chunk.len;
	return tfw_cache_h2_add_hdr(db, ce, p, trec, 26, &val_ce, tot_len, 0);
}

/**
 * Fill @ce->etag with entity-tag value. RFC 7232 Section-2.3 doesn't limit
 * etag size, so can't just have a copy of entity-tag value somewhere in @ce,
 * instead fill @ce->etag TfwStr to correct offset in @ce->hdrs. Also set
 * WEAK tag to the first chunk of @ce->etag if applied. This is needed for Range
 * requests.
 *
 * @h_off, @h_trec	- supposed offset and record of stored 'ETag:' header;
 * @curr_p, @curr_rec	- used to store compound @ce->etag.
 */
static int
__set_etag(TDB *db, TfwCacheEntry *ce, TfwHttpResp *resp, long h_off,
	   TdbVRec *h_trec, char *curr_p, TdbVRec **curr_trec)
{
	char *e_p;
	size_t c_size;
	size_t len = 0;
	unsigned short flags = 0;
	TfwStr h_val, *c, *end, *h = &resp->h_tbl->tbl[TFW_HTTP_HDR_ETAG];

#define CHECK_REC_SPACE()						\
	while (c_size) {						\
		size_t tail = h_trec->len - (e_p - h_trec->data);	\
		if (c_size > tail) {					\
			c_size -= tail;					\
			h_trec = tdb_next_rec_chunk(db, h_trec);	\
			e_p = h_trec->data;				\
		} else {						\
			e_p += c_size;					\
			c_size = 0;					\
		}							\
	}

	if (TFW_STR_EMPTY(h))
		return 0;

	tfw_http_msg_srvhdr_val(h, TFW_HTTP_HDR_ETAG, &h_val);

	/* Update supposed Etag offset to real value. */
	/* TODO: #803 */
	e_p = TDB_PTR(db->hdr, h_off);
	if (e_p + TFW_CSTR_HDRLEN > h_trec->data + h_trec->len) {
		h_trec = tdb_next_rec_chunk(db, h_trec);
		e_p = h_trec->data;
	}
	/*
	 * Skip anything that is not etag value. Note, since headers are
	 * stored in cache in HTTP/2 representation (and the name of 'etag'
	 * header is always statically indexed), we should also skip index
	 * and value length fields; the 'etag' header has the 34 index in
	 * HPACK static table, thus we definitely now here, that it will
	 * occupy 2 bytes (RFC 7541 section 6.2.2).
	 */
	e_p += TFW_CSTR_HDRLEN;
	c_size = 2 + tfw_hpack_int_size(h_val.len, 0x7F);
	CHECK_REC_SPACE();

	if (test_bit(TFW_HTTP_B_HDR_ETAG_HAS_NO_QOUTES, resp->flags)) {
		len += 1;
		c_size = 1;
		CHECK_REC_SPACE();
	}

	TFW_STR_FOR_EACH_CHUNK(c, &h_val, end) {
		if (c->flags & TFW_STR_VALUE) {
			flags = c->flags;
			break;
		}
		c_size = c->len;
		CHECK_REC_SPACE();
	}
	for ( ; (c < end) && (c->flags & TFW_STR_VALUE); ++c)
		len += c->len;

	/* Create TfWStr that contains only entity-tag value. */
	ce->etag.data = e_p;
	ce->etag.flags = flags;
	ce->etag.len = min(len, (size_t)(h_trec->len -
					 (e_p - h_trec->data)));
	len -= ce->etag.len;

	while (len) {
		h_trec = tdb_next_rec_chunk(db, h_trec);
		e_p = h_trec->data;
		c = tfw_str_add_compound(resp->pool, &ce->etag);
		if (!c)
			return -ENOMEM;
		c->data = e_p;
		c->len = min(len, (size_t)(h_trec->len -
					   (e_p - h_trec->data)));
		len -= c->len;
	}

	/* Compound string was allocated in resp->pool, move to cache entry. */
	if (!TFW_STR_PLAIN(&ce->etag)) {
		len = sizeof(TfwStr *) * ce->etag.nchunks;
		curr_p = tdb_entry_get_room(db, curr_trec, curr_p, len, len);
		if (!curr_p)
			return -ENOMEM;
		memcpy_fast(curr_p, ce->etag.data, len);
		ce->etag.data = curr_p;
		/* Old ce->etag.data will be destroyed with resp. */
	}

	return 0;

#undef CHECK_REC_SPACE
}

/**
 * Check if the header @hdr must be present in 304 response. If yes save its
 * offset in cache entry @ce for fast creation of 304 response in
 * tfw_cache_send_304().
 */
static bool
__save_hdr_304_off(TfwCacheEntry *ce, TfwHttpResp *resp, TfwStr *hdr, long off)
{
	int i;
	unsigned int num;
	const TfwStr *match;

	if (TFW_STR_EMPTY(hdr))
		return false;

	num = hdr - resp->h_tbl->tbl;
	if (num < TFW_HTTP_HDR_RAW) {
		if (!tfw_cache_spec_headers_304[num])
			return false;

		for (i = 0; ce->hdrs_304[i]; ++i)
			;
		ce->hdrs_304[i] = off;
		return true;
	}

	match = tfw_http_msg_find_hdr(hdr, tfw_cache_raw_headers_304);
	if (match) {
		unsigned char sc = *(unsigned char *)match->data;

		/* RFC 7234 4.1: Don't send Last-Modified if ETag is present. */
		 if ((sc == 'l')
		     && !TFW_STR_EMPTY(&resp->h_tbl->tbl[TFW_HTTP_HDR_ETAG]))
			return false;

		i = match - tfw_cache_raw_headers_304;
		ce->hdrs_304[i + TFW_CACHE_304_SPEC_HDRS_NUM] = off;
		return true;
	}

	return false;
}

/*
 * Initialize the cache entry and return a pointer to the start of the payload.
 */
static char *
tfw_init_cache_entry(TfwCacheEntry *ce)
{
	bzero_fast(((char *)ce) + offsetof(TfwCacheEntry, ce_body),
		   CE_BODY_SIZE);

	return (char *)(ce + 1);
}

/**
 * Copy response skbs to database mapped area.
 * @tot_len	- total length of actual data to write w/o TfwCStr's etc;
 * @rph		- response reason-phrase to be saved in the cache.
 *
 * It's nasty to copy data on CPU, but we can't use DMA for mmaped file
 * as well as for unaligned memory areas.
 */
static int
tfw_cache_copy_resp(TDB *db, TfwCacheEntry *ce, TfwHttpResp *resp, TfwStr *rph,
		    size_t tot_len)
{
	int r, i;
	char *p;
	unsigned short status_idx;
	TfwStr *field, *end1, *end2;
	TfwStr v_start;
	bool u_fin, v_fin;
	TdbVRec *trec = &ce->trec, *etag_trec = NULL;
	long n, etag_off = 0;
	TfwHttpReq *req = resp->req;
	TfwGlobal *g_vhost = tfw_vhost_get_global();
	TfwStr val_srv = TFW_STR_STRING(TFW_SERVER);
	TfwStr val_via = {
		.chunks = (TfwStr []) {
			{ .data = S_VIA_H2_PROTO, .len = SLEN(S_VIA_H2_PROTO) },
			{ .data = *this_cpu_ptr(&g_c_buf),
			  .len = g_vhost->hdr_via_len },
		},
		.len = SLEN(S_VIA_H2_PROTO) + g_vhost->hdr_via_len,
		.nchunks = 2
	};

	unsigned int effective_resp_flags =
		tfw_cache_get_effective_resp_flags(resp, req);

	if (tot_len >= db->hdr->dbsz)
		return -E2BIG;

	p = tfw_init_cache_entry(ce);
	tot_len -= CE_BODY_SIZE;

	/* Write record key (URI + Vhost name). */
	ce->key = TDB_OFF(db->hdr, p);
	ce->key_len = 0;

	TFW_CACHE_REQ_KEYITER(field, &req->uri_path, &req->vhost->name, end1,
			      &v_start, end2, u_fin, v_fin)
	{
		n = tfw_cache_strcpy_lc(db, &p, &trec, field, tot_len);
		if (unlikely(n < 0)) {
			T_ERR("Cache: cannot copy request key\n");
			return -ENOMEM;
		}
		BUG_ON(n > tot_len);
		tot_len -= n;
		ce->key_len += n;
	}

	/* Request method is a part of the cache record key. */
	if (unlikely(req->method == TFW_HTTP_METH_PURGE
	    && test_bit(TFW_HTTP_B_PURGE_GET, req->flags)))
		ce->method = TFW_HTTP_METH_GET;
	else if (req->method == TFW_HTTP_METH_HEAD)
		ce->method = TFW_HTTP_METH_GET;
	else
		ce->method = req->method;

	/* Write ':status' pseudo-header. */
	ce->status = TDB_OFF(db->hdr, p);
	status_idx = tfw_h2_pseudo_index(resp->status);
	if (status_idx) {
		TfwHPackInt hp_idx;
		TfwStr str = {};

		write_int(status_idx, 0x7F, 0x80, &hp_idx);
		str.data = hp_idx.buf;
		str.len = hp_idx.sz;

		if (tfw_cache_h2_copy_str(db, &ce->status_len, &p, &trec, &str,
					  &tot_len))
			return -ENOMEM;
	} else {
		char buf[H2_STAT_VAL_LEN];
		TfwStr str = {
			.data = buf,
			.len = H2_STAT_VAL_LEN
		};

		/*
		 * If the ':status' pseudo-header is not fully indexed, set
		 * the default static index (8) just for the name.
		 */
		if (tfw_cache_h2_copy_int(db, &ce->status_len, 8, 0xF, &p,
					  &trec, &tot_len)
		    || tfw_cache_h2_copy_int(db, &ce->status_len,
					     H2_STAT_VAL_LEN, 0x7f, &p, &trec,
					     &tot_len))
			return -ENOMEM;

		if (!tfw_ultoa(resp->status, str.data, H2_STAT_VAL_LEN))
			return -E2BIG;

		if (tfw_cache_h2_copy_str(db, &ce->status_len, &p, &trec, &str,
					  &tot_len))
			return -ENOMEM;
	}

	if (tfw_cache_h2_copy_str(db, &ce->rph_len, &p, &trec, rph, &tot_len))
		return -ENOMEM;

	ce->hdrs = TDB_OFF(db->hdr, p);
	ce->hdr_len = 0;
	ce->hdr_num = resp->h_tbl->off;
	FOR_EACH_HDR_FIELD_FROM(field, end1, resp, TFW_HTTP_HDR_REGULAR) {
		int hid = field - resp->h_tbl->tbl;
		/*
		 * Skip hop-by-hop headers. Also skip 'Server' header (with
		 * possible duplicates), since we will substitute it with our
		 * version of this header.
		 */
		if (TFW_STR_EMPTY(field)
		    || (field->flags &
			(TFW_STR_HBH_HDR | TFW_STR_NOCCPY_HDR
			 | TFW_STR_TRAILER_HDR))
		    || hid == TFW_HTTP_HDR_SERVER
		    || hid == TFW_HTTP_HDR_AGE)
		{
			--ce->hdr_num;
			continue;
		}

		/*
		 * Save header if it contains chunks which belongs both
		 * for headers and trailers two times here and later.
		 */
		if ((field->flags & TFW_STR_TRAILER
		    && !(field->flags & TFW_STR_TRAILER_AND_HDR))) {
			--ce->hdr_num;
			continue;
		}

		if (hid == TFW_HTTP_HDR_ETAG) {
			/* Must be updated after tfw_cache_h2_copy_hdr(). */
			etag_off = TDB_OFF(db->hdr, p);
			etag_trec = trec;
		}

		__save_hdr_304_off(ce, resp, field, TDB_OFF(db->hdr, p));
		n = tfw_cache_h2_copy_hdr(db, ce, resp, hid, &p, &trec, field,
					  &tot_len);
		if (unlikely(n < 0))
			return n;
	}

	/* Add 'server' header. */
	n = tfw_cache_h2_add_hdr(db, ce, &p, &trec, 54, &val_srv, &tot_len, 0);
	if (unlikely(n < 0))
		return n;

	/*
	 * Add `Content-Encoding` header and copy encodings from
	 * `Transfer-Encoding` to it.
	 */
	if (test_bit(TFW_HTTP_B_TE_EXTRA, resp->flags)) {
		n = tfw_cache_add_hdr_cenc(db, resp, ce, &p, &trec, &tot_len);
		if (unlikely(n < 0))
			return n;

		ce->hdr_num += 1;
	}

	/* Headers added only for h2 responses. */
	/* Add 'via' header. */
	memcpy_fast(__TFW_STR_CH(&val_via, 1)->data, g_vhost->hdr_via,
		    g_vhost->hdr_via_len);
	n = tfw_cache_h2_add_hdr(db, ce, &p, &trec, 60, &val_via, &tot_len, 0);
	if (unlikely(n < 0))
		return n;

	ce->hdr_h2_off = ce->hdr_num + 1;
	ce->hdr_num += 2;

	ce->trailer_off = ce->hdr_num;
	ce->trailers = TDB_OFF(db->hdr, p);
	if (resp->trailers_len > 0) {
		FOR_EACH_HDR_FIELD_FROM(field, end1, resp,
					TFW_HTTP_HDR_REGULAR)
		{
			int hid = field - resp->h_tbl->tbl;

			if ((!(field->flags & TFW_STR_TRAILER) &&
			     !(field->flags & TFW_STR_TRAILER_AND_HDR)) ||
			    (field->flags & TFW_STR_NOCCPY_HDR)
			    || hid == TFW_HTTP_HDR_SERVER
			    || hid == TFW_HTTP_HDR_AGE)
				continue;

			n = tfw_cache_h2_copy_hdr(db, ce, resp, hid, &p, &trec,
						  field, &tot_len);
			if (unlikely(n < 0))
				return n;

			ce->hdr_num++;
		}
	}

	/* Write HTTP response body. */
	ce->body = TDB_OFF(db->hdr, p);
	if (test_bit(TFW_HTTP_B_CHUNKED, resp->flags)) {
		ce->flags |= TFW_CE_CHUNKED_BODY;
		r = tfw_cache_h2_copy_chunked_body(db, &ce->body_len, &p, &trec,
						   resp, &resp->cut, &tot_len);
	} else {
		r = tfw_cache_h2_copy_body(db, &ce->body_len, &p, &trec,
					   resp, &tot_len);
	}

	if (unlikely(r)) {
		T_ERR("Cache: cannot copy HTTP body\n");
		return -ENOMEM;
	}

	if (WARN_ON_ONCE(tot_len != 0))
		return -EINVAL;

	ce->version = resp->version;
	tfw_http_copy_flags(ce->hmflags, resp->flags);

	/* RFC 7234 Section 3.2:
	 * Note that cached responses that contain the "must-revalidate" and/or
	 * "s-maxage" response directives are not allowed to be served stale
	 * (Section 4.2.4) by shared caches. In particular, a response with
	 * either "max-age=0, must-revalidate" or "s-maxage=0" cannot be used
	 * to satisfy a subsequent request without revalidating it on the origin
	 * server.
	 * Also see tfw_cache_entry_is_live().
	 */
	if (effective_resp_flags
	    & (TFW_HTTP_CC_MUST_REVAL | TFW_HTTP_CC_PROXY_REVAL |
	       TFW_HTTP_CC_S_MAXAGE))
	{
		ce->flags |= TFW_CE_MUST_REVAL;
	}

	if (effective_resp_flags & TFW_HTTP_CC_STALE_IF_ERROR) {
		ce->stale_if_error = resp->cache_ctl.stale_if_error;
		ce->flags |= TFW_CE_STALE_IF_ERROR;
	}

	ce->date = resp->date;
	ce->age = resp->cache_ctl.age;
	ce->req_time = req->cache_ctl.timestamp;
	ce->resp_time = resp->cache_ctl.timestamp;
	ce->lifetime = tfw_cache_calc_lifetime(resp);
	ce->last_modified = resp->last_modified;
	ce->resp_status = resp->status;

	r = __set_etag(db, ce, resp, etag_off, etag_trec, p, &trec);
	if (unlikely(r)) {
		T_ERR("Cache: cannot copy entity-tag\n");
		return r;
	}

	/* Update offsets of 304 headers to real values */
	/* TODO: #803 */
	trec = &ce->trec;
	for (i = 0; i < ARRAY_SIZE(ce->hdrs_304); ++i) {
		if (!ce->hdrs_304[i])
			continue;

		p = TDB_PTR(db->hdr, ce->hdrs_304[i]);
		while (trec && (p + TFW_CSTR_HDRLEN > trec->data + trec->len))
			trec = tdb_next_rec_chunk(db, trec);
		BUG_ON(!trec);

		ce->hdrs_304[i] = TDB_OFF(db->hdr, p);
	}

	T_DBG("Copied message to cache: resp=%p content-length=%lu msg_len=%lu",
	      resp, resp->content_length, resp->msg.len);
	__tfw_dbg_dump_ce(ce);

	return 0;
}

static bool
check_cfg_ignored_header(const TfwStr *field, TfwCaToken *tokens,
			 unsigned int tokens_sz)
{
	int i;
	int bytes_count = 0;
	TfwCaToken *token = tokens;
	const TfwStr *hdr = TFW_STR_DUP(field) ?
		TFW_STR_CHUNK(field, 0) : field;

	for (i = 0; i < tokens_sz; i++) {
		const TfwStr to_del = {
			.data = token->str,
			.len = token->len - 1
		};
		BUG_ON(token->len > 10000);
		if (tfw_stricmpspn(hdr, &to_del, ':') == 0)
			return true;

		bytes_count += sizeof(TfwCaToken) + token->len;
		token = (TfwCaToken *)(bytes_count + (char *)tokens);
	}
	return false;
}

static bool
check_cc_ignored_header(const TfwStr *field, const TfwStr *tokens)
{
	int i;
	const TfwStr *hdr = TFW_STR_DUP(field) ?
		TFW_STR_CHUNK(field, 0) : field;

	for (i = 0; i < tokens->nchunks; i++) {
		if (tfw_stricmpspn(hdr, &tokens->chunks[i], ':') == 0)
			return true;
	}
	return false;
}

static unsigned long
te_codings_size(TfwHttpResp *resp)
{
	TfwStr *te_hdr = &resp->h_tbl->tbl[TFW_HTTP_HDR_TRANSFER_ENCODING];
	TfwStr *chunk, *end, *dup, *end_dup;
	size_t len = 0;
	bool first = true;

	TFW_STR_FOR_EACH_DUP(dup, te_hdr, end_dup) {
		TFW_STR_FOR_EACH_CHUNK(chunk, dup, end) {
			if (!(chunk->flags & TFW_STR_NAME))
				continue;

			if (!first)
				len += 1;

			len += chunk->len;
			first = false;
		}
	}

	return len;
}

/*
 * __cache_entry_size is supposed to be called before tfw_cache_copy_resp,
 * to set the TFW_STR_NOCCPY_HDR flag on the headers, so we don't double-check
 * the ignored header list (this check is O(N*M) currently).
 */
static long
__cache_entry_size(TfwHttpResp *resp)
{
#define INDEX_SZ 2

	TfwStr *hdr, *hdr_end;
	TfwHttpReq *req = resp->req;
	size_t size, res_size = CE_BODY_SIZE;
	unsigned long via_sz = SLEN(S_VIA_H2_PROTO)
		+ tfw_vhost_get_global()->hdr_via_len;
	TfwCaTokenArray hdr_del_tokens =
			tfw_vhost_get_capo_hdr_del(req->location, req->vhost);
	/* Add compound key size */
	res_size += req->uri_path.len;
	res_size += req->vhost->name.len;

	/*
	 * Add the length of ':status' pseudo-header: one byte if fully indexed,
	 * or five bytes (one byte for name index, one for status code length
	 * and three for status code itself) if only name is indexed.
	 */
	++res_size;
	res_size += (1 + H2_STAT_VAL_LEN) * !tfw_h2_pseudo_index(resp->status);

	/* Add all the headers size */
	FOR_EACH_HDR_FIELD_FROM(hdr, hdr_end, resp, TFW_HTTP_HDR_REGULAR) {
		TfwStr *d, *d_end;
		int hid = hdr - resp->h_tbl->tbl;
		/*
		 * Skip hop-by-hop headers. Also skip 'Server' header (with
		 * possible duplicates), since we will substitute it with our
		 * version of this header.
		 */
		if (TFW_STR_EMPTY(hdr)
		    || (hdr->flags & (TFW_STR_HBH_HDR | TFW_STR_NOCCPY_HDR |
			TFW_STR_TRAILER_HDR))
		    || hid == TFW_HTTP_HDR_SERVER
		    || hid == TFW_HTTP_HDR_AGE)
			continue;

		/*
		 * TODO #496: assemble all the string patterns into state
		 * machines (one if possible) to avoid the loops over all
		 * configured and mentioned in `private` and `no-cache`
		 * directives.
		 */
		/* remove headers mentioned in cache_resp_hdr_del */
		if (hdr_del_tokens.tokens) {
			if (check_cfg_ignored_header(hdr, hdr_del_tokens.tokens,
						     hdr_del_tokens.sz))
			{
				hdr->flags |= TFW_STR_NOCCPY_HDR;
				continue;
			}
		}

		/* remove headers mentioned in Cache-Control: no-cache */
		if (resp->no_cache_tokens.nchunks != 0) {
			if (check_cc_ignored_header(hdr, &resp->no_cache_tokens))
			{
				hdr->flags |= TFW_STR_NOCCPY_HDR;
				continue;
			}
		}
		/* remove headers mentioned in Cache-Control: private */
		if (resp->private_tokens.nchunks != 0) {
			if (check_cc_ignored_header(hdr, &resp->private_tokens))
			{
				hdr->flags |= TFW_STR_NOCCPY_HDR;
				continue;
			}
		}

		size = sizeof(TfwCStr);

		if (!TFW_STR_DUP(hdr)) {
			TfwStr s_nm = {}, s_val = {};

			tfw_http_hdr_split(hdr, &s_nm, &s_val, true);
			size += tfw_h2_hdr_size(s_nm.len, s_val.len,
						hdr->hpack_idx);
		} else {
			TFW_STR_FOR_EACH_DUP(d, hdr, d_end) {
				TfwStr s_nm = {}, s_val = {};

				size += sizeof(TfwCStr);
				tfw_http_hdr_split(d, &s_nm, &s_val, true);
				size += tfw_h2_hdr_size(s_nm.len, s_val.len,
							d->hpack_idx);
			}

			if (hdr->flags & TFW_STR_TRAILER_AND_HDR)
				size *= 2;
		}

		if (unlikely(size >= TFW_CSTR_MAXLEN))
			goto err;
		res_size += size;
	}

	/*
	 * Add the length of value of Transfer-Encoding, which will be used
	 * as length of value of Content-Encoding, since Transfer-Encoding is
	 * hop-by-hop it must not placed to cache and will be replaced by
	 * Content-Encoding during caching response.
	 */
	if (test_bit(TFW_HTTP_B_TE_EXTRA, resp->flags)) {
		unsigned long ce_len = te_codings_size(resp);

		res_size += sizeof(TfwCStr) + INDEX_SZ
				   + tfw_hpack_int_size(ce_len, 0x7F) + ce_len;
	}

	/*
	 * Add the length of our version of 'Server' header and 'Via' header.
	 * Note, that we need two bytes for static index, since in the first
	 * byte we have only four available bits for the index (we do not use
	 * dynamic indexing during headers storing into the cache, thus `without
	 * indexing` code must be set in the first index byte, see RFC 7541
	 * section 6.2.2 for details), and the 'Server' (as well as 'Via')
	 * static index doesn't fit to that space.
	 */
	res_size += sizeof(TfwCStr) + INDEX_SZ
			   + tfw_hpack_int_size(SLEN(TFW_SERVER), 0x7F)
			   + SLEN(TFW_SERVER);

	res_size += sizeof(TfwCStr) + INDEX_SZ
			   + tfw_hpack_int_size(via_sz, 0x7F) + via_sz;

	/* Add body size. */
	res_size += TFW_HTTP_RESP_CUT_BODY_SZ(resp);

	return res_size;
err:
	T_WARN("Cache: trying to store too big string %ld\n", size);
	return -E2BIG;

#undef STATIC_INDEX_SZ
}

static bool
tfw_cache_rec_eq_req(TdbHdr *db_hdr, TdbRec *rec, void *request)
{
	TDB *db = (TDB *)db_hdr;
	TfwCacheEntry *ce = (TfwCacheEntry *)rec;
	TfwHttpReq *req = (TfwHttpReq *)request;

	return tfw_cache_entry_key_eq(db, req, ce);
}

static bool
tfw_cache_rec_eq(TdbHdr *db_hdr, TdbRec *r1, void *r2)
{
	return r1 == r2;
}

static void
tfw_cache_decrease_stat(TdbRec *rec)
{
	TfwCacheEntry *ce = (TfwCacheEntry *)rec;

	/* Stats should be updated(dec/inc) only for complete records. */
	if (!tdb_entry_is_complete(rec))
		return;

	TFW_SUB_STAT_BH(ce_total_size(ce), cache.bytes);
	TFW_DEC_STAT_BH(cache.objects);
}

static void
__cache_add_node(TDB *db, TfwHttpResp *resp, unsigned long key)
{
	TfwCacheEntry *ce;
	TfwStr rph, *s_line;
	size_t data_len = __cache_entry_size(resp), len;
	int r;

	if (test_bit(TFW_HTTP_B_HDR_ETAG_HAS_NO_QOUTES, resp->flags))
		data_len += 2;

	if (unlikely(data_len < 0))
		return;

	/*
	 * We need to save the reason-phrase for the case of HTTP/1.1-response
	 * creation from cache. Note, that reason-phrase is always the last part
	 * of status-line with the TFW_STR_VALUE flag set.
	 */
	s_line = &resp->h_tbl->tbl[TFW_HTTP_STATUS_LINE];
	rph = tfw_str_next_str_val(s_line);
	if (WARN_ON_ONCE(TFW_STR_EMPTY(&rph)))
		return;

	data_len += rph.len;
	len = data_len;

	T_DBG3("%s: db=[%p] resp=[%p], req=[%p], key='%lu', data_len='%lu'\n",
	       __func__, db, resp, resp->req, key, data_len);

	/*
	 * Try to place the cached response in single memory chunk.
	 * TDB should provide enough space to place at least head of
	 * the record key at first chunk.
	 */
	ce = (TfwCacheEntry *)tdb_entry_alloc_unique(db, key, &len,
						     &tfw_cache_rec_eq_req,
						     resp->req);
	BUG_ON(len <= sizeof(TfwCacheEntry));
	if (!ce)
		return;

	T_DBG3("%s: ce=[%p], alloc_len='%lu'\n", __func__, ce, len);

	if ((r = tfw_cache_copy_resp(db, ce, resp, &rph, data_len))) {
		/*
		 * Error occured during response copying. Remove allocated entry.
		 */
		tdb_entry_remove(db, key, &tfw_cache_rec_eq, ce, true);
		T_DBG3("%s: Can't copy response ce=[%p], resp=[%p], data_len="
		       "'%lu' r=%i \n", __func__, ce, resp, data_len, r);
	} else {
		tdb_entry_mark_complete(ce);
		TFW_INC_STAT_BH(cache.objects);
		TFW_ADD_STAT_BH(ce_total_size(ce), cache.bytes);
	}

	tdb_rec_put(db, ce);
}

static void
tfw_cache_add(TfwHttpResp *resp, tfw_http_cache_cb_t action)
{
	unsigned long key;
	bool keep_skb = false;
	TfwHttpReq *req = resp->req;

	/*
	 * TODO #521:
	 * According RFC 9111 4.3.5:
	 * When a cache makes an inbound HEAD request for a target URI
	 * and receives a 200 (OK) response, the cache SHOULD update each
	 * of its stored GET responses that could have been chosen for
	 * that request.
	 */

	if (!tfw_cache_employ_resp(resp))
		goto out;

	key = tfw_http_req_key_calc(req);

	if (cache_cfg.cache == TFW_CACHE_SHARD) {
		BUG_ON(req->node != numa_node_id());
		__cache_add_node(node_db(), resp, key);
	} else {
		int nid;
		/*
		 * TODO probably it's better to do this in TDB per-node threads
		 * rather than in softirq...
		 */
		for_each_node_with_cpus(nid)
			__cache_add_node(get_db_for_node(nid), resp, key);
	}

	/*
	 * Cache population is synchronous now. Don't forget to set
	 * @keep_skb properly in case of asynchronous operation is being
	 * performed.
	 */

out:
	resp->msg.ss_flags |= keep_skb ? SS_F_KEEP_SKB : 0;
	action((TfwHttpMsg *)resp);
}

/*
 * Invalidate all cache entries that match the request. This is implemented by
 * making the entries stale.
 *
 */
static int
tfw_cache_purge_invalidate(TDB *db, TfwHttpReq *req)
{
	TdbIter iter;
	TfwCacheEntry *ce = NULL;
	unsigned long key = tfw_http_req_key_calc(req);

	iter = tdb_rec_get(db, key);
	if (TDB_ITER_BAD(iter))
		return 0;

	ce = (TfwCacheEntry *)iter.rec;
	do {
		if (tfw_cache_entry_key_eq(db, req, ce))
			ce->lifetime = 0;
		tdb_rec_next(db, &iter);
		ce = (TfwCacheEntry *)iter.rec;
	} while (ce);

	return 0;
}

/*
 * Remove all cache entries that match the request.
 */
static int
tfw_cache_purge_immediate(TDB *db, TfwHttpReq *req)
{
	unsigned long key = tfw_http_req_key_calc(req);

	tdb_entry_remove(db, key, &tfw_cache_rec_eq_req, req, false);

	return 0;
}

static int
tfw_cache_purge_invoke_impl(TfwHttpReq *req,
			    int purge_impl(TDB *db, TfwHttpReq *req))
{
	int ret;

	if (cache_cfg.cache == TFW_CACHE_REPLICA) {
		int nid;

		for_each_node_with_cpus(nid)
			ret = purge_impl(get_db_for_node(nid), req);
	} else {
		/* Expected only local node access. */
		ret = purge_impl(get_db_for_node(req->node), req);
	}

	return ret;
}

/**
 * Process PURGE request method according to the configuration. Send a response,
 * unless there are no errors *and* we're also told to refresh the cache.
 */
static int
tfw_cache_purge_method(TfwHttpReq *req)
{
	int ret;
	TfwAddr saddr;
	TfwGlobal *g_vhost = tfw_vhost_get_global();

	/* Deny PURGE requests by default. */
	if (!(cache_cfg.cache && g_vhost->cache_purge
	    && g_vhost->cache_purge_acl))
	{
		tfw_http_send_err_resp(req, 403, "purge: not configured");
		return -EINVAL;
	}

	/* Accept requests from configured hosts only. */
	ss_getpeername(req->conn->sk, &saddr);
	if (!tfw_capuacl_match(&saddr)) {
		tfw_http_send_err_resp(req, 403, "purge: ACL violation");
		return -EINVAL;
	}

	switch (g_vhost->cache_purge_mode) {
	case TFW_D_CACHE_PURGE_INVALIDATE:
		ret = tfw_cache_purge_invoke_impl(req,
						  tfw_cache_purge_invalidate);
		break;
	case TFW_D_CACHE_PURGE_IMMEDIATE:
		ret = tfw_cache_purge_invoke_impl(req,
						  tfw_cache_purge_immediate);
		break;
	default:
		tfw_http_send_err_resp(req, 403, "purge: invalid option");
		return -EINVAL;
	}

	if (ret)
		tfw_http_send_err_resp(req, 404, "purge: processing error");
	else if (!test_bit(TFW_HTTP_B_PURGE_GET, req->flags))
		tfw_http_send_err_resp(req, 200, "purge: success");

	return ret;
}

/**
 * Add page from cache into response.
 */
static int
tfw_cache_add_body_page(TfwMsgIter *it, char *p, int sz, bool h2)
{
	int off;
	struct page *page;

	if (h2) {
		char *new_p;
		if (!(page = alloc_page(GFP_ATOMIC))) {
			return -ENOMEM;
		}
		new_p = page_address(page);
		off = 0;
		memcpy_fast(new_p, p, sz);
	}
	else {
		off = ((unsigned long)p & ~PAGE_MASK);
		page = virt_to_page(p);
	}

	++it->frag;
	skb_fill_page_desc(it->skb, it->frag, page, off, sz);
	if (!h2)
		skb_frag_ref(it->skb, it->frag);
	ss_skb_adjust_data_len(it->skb, sz);

	return 0;
}

static inline bool
tfw_cache_should_append_body_skb(TfwMsgIter *it, size_t body_sz,
				 bool chunked_body)
{
/*
 * 18 bytes to encode ULONG_MAX body_sz and 5 bytes to
 * encode S_CRLF and S_ZERO.
 */
#define CHUNKED_B_SZ 23

	size_t body_sz_in_skb = (chunked_body * CHUNKED_B_SZ) + body_sz;

	/*
	 * If sh_frag is true we should copy skb with headers during
	 * encryption. In this case we calculate count of skbs to build
	 * response, if we force add/not add extra skb for body here.
	 * - If count of skbs are equal add skb (we don't increase count of
	 * skbs in response, but avoid extra body copying).
	 * - If count of skbs are not equal we calculte count of body bytes
	 * should be copied during encryption and if this count is greater
	 * then PAGE_SIZE >> 2 create extra skb. This value (PAGE_SIZE >> 2)
	 * was choosen empirically through performance testing.
	 */
	return (DIV_ROUND_UP(body_sz_in_skb + it->skb->len,
			     SS_SKB_MAX_DATA_LEN) ==
		1 + DIV_ROUND_UP(body_sz_in_skb, SS_SKB_MAX_DATA_LEN))
		|| (min(SS_SKB_MAX_DATA_LEN - it->skb->len, body_sz_in_skb) >
		    (PAGE_SIZE >> 2));

#undef CHUNKED_B_SZ
}

/**
 * Build the message body as paged fragments of skb.
 * See do_tcp_sendpages() as reference.
 *
 * Different strategies are used to avoid extra data copying depending on
 * client connection type:
 * - for http connections - pages are reused in skbs and SKBFL_SHARED_FRAG is
 * set to avoid any data copies.
 * - for https connections - pages are reused in skbs and SKBFL_SHARED_FRAG is
 * set, but in-place crypto operations are not allowed, so data copy happens
 * right before data is pushed into network.
 * - for h2 connections - every response has unique frame header, so need to
 * copy on constructing response body from cache. SKBFL_SHARED_FRAG is left
 * unset to allow in-place crypto operations.
 *
 * Since we can't encrypt shared data in-place we always copy it, so we need
 * reserve some space in cached pages to avoid extra skb fragmentation. Since
 * body fragments are stored in cache by pages with at least cache record
 * header preceding, which is bigger than h2 frame header, it's always possible
 * to fit body fragment and h2 header into a single page. So there is no need
 * to actually reserve any space for h2 frame header.
 */
static int
tfw_cache_build_resp_body(TDB *db, TdbVRec *trec, TfwHttpResp *resp, char *p,
			  size_t body_sz, bool h2, bool chunked_body)
{
/*
 * Finish chunked body encoding. Add 0\r\n
 * after chunked body.
 */
#define S_ZERO "0"

	TfwMsgIter *it = &resp->iter;
	bool sh_frag = !h2 && TFW_CONN_TLS(resp->req->conn);
	int r;

	if (WARN_ON_ONCE(!it->skb_head))
		return -EINVAL;

	/*
	 * If all skbs/frags are used up (see @tfw_http_msg_expand_data()),
	 * create new skb with empty frags to reference the cached body;
	 * otherwise, use next empty frag in current skb.
	 */
	if (!it->skb || it->frag + 1 >= MAX_SKB_FRAGS
	    || (sh_frag && tfw_cache_should_append_body_skb(it, body_sz,
							    chunked_body)))
	{
		if  ((r = tfw_msg_iter_append_skb(it)))
			return r;
	}
	if (sh_frag)
		skb_shinfo(it->skb)->flags |= SKBFL_SHARED_FRAG;

	if (unlikely(!body_sz))
		goto add_zero_chunk;

	if (chunked_body) {
		char cstr_blen[TFW_ULTOA_BUF_SIZ] = {0};
		/*
		 * Encode body in one single chunk.
		 * blen\r\nbody
		 */
		TfwStr b_len = {
			.chunks = (TfwStr []){
				{},
				{.data = S_CRLF, .len = SLEN(S_CRLF)},
			},
			.len = SLEN(S_CRLF),
			.nchunks = 2
		};
		size_t digs;

		digs = tfw_ultohex(body_sz, cstr_blen,
				   TFW_ULTOA_BUF_SIZ);
		if (!digs)
			return -E2BIG;

		__TFW_STR_CH(&b_len, 0)->data = cstr_blen;
		__TFW_STR_CH(&b_len, 0)->len = digs;
		b_len.len += digs;

		r = tfw_http_msg_expand_data(it, &it->skb_head,
					     &b_len, NULL);
		if (unlikely(r))
			return r;
	}

	while (1) {
		int f_size;

		f_size = trec->data + trec->len - p;

		BUG_ON(f_size < 0 || f_size > PAGE_SIZE);
		if (f_size) {
			f_size = min(body_sz, (unsigned long)f_size);
			body_sz -= f_size;
			r = tfw_cache_add_body_page(it, p, f_size, h2);
			if (r)
				return r;
		}
		if (!body_sz || !(trec = tdb_next_rec_chunk(db, trec)))
			break;
		/*
		 * Broken record: body is not fully copied yet, but there is
		 * no data in the next record part.
		 */
		if (WARN_ON_ONCE(!trec->len))
			return -EINVAL;
		p = trec->data;

		if (it->frag + 1 == MAX_SKB_FRAGS
		    && (r = tfw_msg_iter_append_skb(it)))
		{
			return r;
		}
	}

	if (chunked_body) {
		static TfwStr b_len = {
			.data = S_ZERO S_CRLF,
			.len = SLEN(S_ZERO S_CRLF)
		};

		r = tfw_http_msg_expand_data(it, &it->skb_head,
					     &g_crlf, NULL);
		if (unlikely(r))
			return r;

add_zero_chunk:
		r = tfw_http_msg_expand_data(it, &it->skb_head,
					     &b_len, NULL);
		if (unlikely(r))
			return r;
	}

	return 0;

#undef S_ZERO
}

static int
tfw_cache_set_hdr_age(TfwHttpResp *resp, TfwCacheEntry *ce, long age)
{
	int r;
	size_t digs;
	bool to_h2 = TFW_MSG_H2(resp->req);
	struct sk_buff **skb_head = &resp->msg.skb_head;
	char cstr_age[TFW_ULTOA_BUF_SIZ] = {0};
	char *name = to_h2 ? "age" : "age" S_DLM;
	unsigned int nlen = to_h2 ? SLEN("age") : SLEN("age" S_DLM);
	TfwStr h_age = {
		.chunks = (TfwStr []){
			{ .data = name, .len = nlen },
			{}
		},
		.len = nlen,
		.nchunks = 2
	};

	if (!(digs = tfw_ultoa(age, cstr_age, TFW_ULTOA_BUF_SIZ))) {
		r = -E2BIG;
		goto err;
	}

	__TFW_STR_CH(&h_age, 1)->data = cstr_age;
	__TFW_STR_CH(&h_age, 1)->len = digs;
	h_age.len += digs;

	if (to_h2) {
		h_age.hpack_idx = 21;
		if ((r = tfw_hpack_encode(resp, &h_age, false, false)))
			goto err;
	} else {
		if ((r = tfw_http_msg_expand_data(&resp->iter, skb_head,
						  &h_age, NULL)))
			goto err;

		if ((r = tfw_http_msg_expand_data(&resp->iter, skb_head,
						  &g_crlf, NULL)))
			goto err;
	}

	return 0;

err:
	T_WARN("Unable to add Age: header, cached response [%p] dropped"
	       " (err: %d)\n", resp, r);
	return r;
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
 * Basically, skb copy/cloning involves skb creation, so it seems performance
 * of response body creation won't change since now we just reuse TDB pages.
 * Performance benchmarks and profiling shows that cache_req_process_node()
 * is the bottleneck, so the problem is either in tfw_cache_dbce_get() or this
 * function, in headers compilation.
 * Also it seems caching prebuilt responses requires introducing
 * TfwCacheEntry->resp pointer to avoid additional indexing data structure.
 * However, the pointer must be zeroed on TDB shutdown and recovery.
 *
 * TODO use iterator and passed skbs to be called from net_tx_action.
 */
static TfwHttpResp *
tfw_cache_build_resp(TfwHttpReq *req, TfwCacheEntry *ce, long age)
{
	int h;
	TfwStr dummy_body = { 0 };
	TfwMsgIter *it;
	TfwHttpResp *resp;
	char *p;
	TfwHttpTransIter *mit;
	TDB *db = get_db_for_node(req->node);
	unsigned long h_len = 0;
	struct sk_buff **skb_head;
	TdbVRec *trec = &ce->trec, *trailers_trec = NULL;
	TfwHdrMods *h_mods = tfw_vhost_get_hdr_mods(req->location, req->vhost,
						    TFW_VHOST_HDRMOD_RESP);
	bool h2_mode = TFW_MSG_H2(req);
	bool first = false;
	bool chunked_body = false;

	/*
	 * The allocated response won't be checked by any filters and
	 * is used for sending response data only, so don't initialize
	 * connection and GFSM fields.
	 */
	if (!(resp = tfw_http_msg_alloc_resp(req)))
		goto out;

	/* Copy version information and flags */
	resp->version = ce->version;
	tfw_http_copy_flags(resp->flags, ce->hmflags);

	resp->date = ce->date;

	/* Skip record key until status line. */
	for (p = TDB_PTR(db->hdr, ce->status);
	     trec && (unsigned long)(p - trec->data) > trec->len;
	     trec = tdb_next_rec_chunk(db, trec))
		;
	if (unlikely(!trec)) {
		T_WARN("Huh, partially stored cache entry (key=%lx)?\n",
		       ce->key);
		goto free;
	}

	if (tfw_cache_set_status(db, ce, resp, &trec, &p, &h_len))
		goto free;

	for (h = TFW_HTTP_HDR_REGULAR; h < ce->hdr_num; ++h) {
		bool skip = !h2_mode && (h >= ce->hdr_h2_off)
			     && (h < ce->trailer_off);

		if (h >= ce->trailer_off) {
			skip = true;
			if (!first) {
				trailers_trec = trec;
				first = true;
			}
		}
		if (tfw_cache_build_resp_hdr(db, resp, h_mods, &trec, &p,
					     &h_len, skip, TFW_CACHE_HDR))
			goto free;
	}

	mit = &resp->mit;
	skb_head = &resp->msg.skb_head;
	WARN_ON_ONCE(mit->acc_len);
	it = &resp->iter;

	/*
	 * Set 'set-cookie' header if needed, for HTTP/2 or HTTP/1.1
	 * response.
	 */
	if (tfw_http_sess_resp_process(resp, true))
		goto free;

	/*
	 * RFC 7234 p.4 Constructing Responses from Caches:
	 * When a stored response is used to satisfy a request without
	 * validation, a cache MUST generate an Age header field.
	 */
	if (tfw_cache_set_hdr_age(resp, ce, age))
		goto free;

	if (!h2_mode) {
		/*
		 * Set additional headers and final CRLF for HTTP/1.1
		 * response.
		 */
		if (tfw_http_expand_hbh(resp, ce->resp_status)
		    || tfw_http_expand_hdr_via(resp)
		    || tfw_h1_add_loc_hdrs((TfwHttpMsg *)resp, h_mods, true)
		    || (age > ce->lifetime
			&& tfw_http_expand_stale_warn(resp))
		    || (!test_bit(TFW_HTTP_B_HDR_DATE, resp->flags)
			&& tfw_http_expand_hdr_date(resp))
		    || tfw_http_msg_expand_data(it, skb_head, &g_crlf, NULL))
		{
			goto free;
		}

		goto write_body;
	}

	/* Set additional headers for HTTP/2 response. */
	if (tfw_h2_resp_add_loc_hdrs(resp, h_mods, true)
	    || (age > ce->lifetime
		&& tfw_h2_set_stale_warn(resp))
	    || (!test_bit(TFW_HTTP_B_HDR_DATE, resp->flags)
		&& tfw_h2_add_hdr_date(resp, true)))
		goto free;

	h_len += mit->acc_len;

	/*
	 * Responses built from cache has room for frame header reserved
	 * in SKB linear data.
	 */
	resp->mit.frame_head = it->skb_head->data;

	/*
	 * Split response to h2 frames. Don't write body with generic function,
	 * just indicate that we have body for correct framing.
	 */
	/*
	 * According RFC 9110 9.3.2:
	 * The HEAD method is identical to GET except that the server MUST NOT
	 * send content in the response.
	 */
	dummy_body.len = req->method != TFW_HTTP_METH_HEAD ? ce->body_len : 0;
	if (tfw_h2_frame_local_resp(resp, h_len, &dummy_body))
		goto free;

	it->skb = ss_skb_peek_tail(&it->skb_head);
	it->frag = skb_shinfo(it->skb)->nr_frags - 1;

write_body:
	chunked_body = (ce->flags & TFW_CE_CHUNKED_BODY) && !h2_mode;
	/* Fill skb with body from cache for HTTP/2 or HTTP/1.1 response. */
	BUG_ON(p != TDB_PTR(db->hdr, ce->body));
	if ((ce->body_len || chunked_body)
	    && req->method != TFW_HTTP_METH_HEAD)
	{
		if (tfw_cache_build_resp_body(db, trec, resp, p, ce->body_len,
					      h2_mode, chunked_body))
			goto free;
	}
	resp->content_length = ce->body_len;

	if (unlikely(ce->trailer_off < ce->hdr_num)
	    && req->method != TFW_HTTP_METH_HEAD)
	{
		unsigned long t_len = 0;

		if (h2_mode)
			mit->start_off = FRAME_HEADER_SIZE;

		p = TDB_PTR(db->hdr, ce->trailers);
		for (h = ce->trailer_off; h < ce->hdr_num; ++h) {
			if (tfw_cache_build_resp_hdr(db, resp, h_mods,
						     &trailers_trec, &p,
						     &t_len, false,
						     TFW_CACHE_TRAILER))
				goto free;
		}
		if (h2_mode && tfw_h2_stream_init_t_len_for_xmit(resp, t_len))
			goto free;
	}

	/*
	 * For http1 we should add finishing \r\n after last
	 * trailer or chunked body.
	 */
	if (chunked_body && req->method != TFW_HTTP_METH_HEAD
	    && tfw_http_msg_expand_data(it, skb_head, &g_crlf, NULL))
		goto free;

	return resp;
free:
	tfw_http_msg_free((TfwHttpMsg *)resp);
out:
	T_WARN("Cannot use cached response, key=%lx\n", ce->key);
	TFW_INC_STAT_BH(clnt.msgs_otherr);

	return NULL;
}

TfwHttpResp *
tfw_cache_build_resp_stale(TfwHttpReq *req)
{
	TDB *db = get_db_for_node(req->node);
	TfwCacheEntry *ce = req->stale_ce;
	TfwHttpResp *resp = tfw_cache_build_resp(req, ce, req->stale_ce_age);

	if (resp)
		T_DBG("Cache: Stale response assigned to req [%p] w/ key=%lx, \
		      ce=%p", req, ce->trec.key, ce);
	else
		T_DBG("Cache: Cannot assigne stale response to req [%p] w/ \
		      key=%lx, ce=%p", req, ce->trec.key, ce);

	tdb_rec_put(db, ce);
	/* Set to NULL to prevent double free in req destructor. */
	req->stale_ce = NULL;

	return resp;
}
ALLOW_ERROR_INJECTION(tfw_cache_build_resp_stale, NULL);

/**
 * Release cache entry reference.
 */
void
tfw_cache_put_entry(int node, void *ce)
{
	tdb_rec_put(get_db_for_node(node), ce);
}

static bool
tfw_cache_can_use_stale(TfwHttpReq *req, TfwCacheEntry *ce, long age)
{
	bool stale_cfg =
		tfw_vhost_get_cache_use_stale(req->location, req->vhost);
	unsigned int ce_flags = ce->flags;

	/* RFC 9111 Section 4.2.4
	 *
	 * A cache MUST NOT generate a stale response if it is prohibited by an
	 * explicit in-protocol directive (e.g., by a no-cache response
	 * directive, a must-revalidate response directive, or an applicable
	 * s-maxage or proxy-revalidate response directive; see Section 5.2.2).
	 *
	 * We can check only flags, because tfw_cache_entry_is_live()
	 * must be called before this function and lifetime already calculated.
	 */
	if (ce_flags & TFW_CE_MUST_REVAL
	    || req->cache_ctl.flags & TFW_HTTP_CC_MAX_STALE)
		return false;

	/*
	 * Use stale response if "cache_use_stale" directive is configured.
	 * Has higher priority than "cache-control: stale-if-error".
	 */
	if (stale_cfg)
		return true;

	/*
	 * RFC 5861.
	 *
	 * Use stale response if the request or the cached entry has
	 * stale-if-error cache-control directive with a valid value.
	 *
	 * Once stale_if_error presents in boths response and request,
	 * response's directive has higher priority - this behaviour not
	 * specified in RFC.
	 */
	if (ce_flags & TFW_CE_STALE_IF_ERROR && ce->stale_if_error >= age) {
		/*
		 * NOTE: Be careful! Set request's stale-if-error flag even for
		 * response, because at this moment we don't have constructed
		 * response.
		 */
		req->cache_ctl.flags |= TFW_HTTP_CC_STALE_IF_ERROR;
		return true;
	}

	return req->cache_ctl.flags & TFW_HTTP_CC_STALE_IF_ERROR &&
		req->cache_ctl.stale_if_error >= age;
}

static void
cache_do_service_request_stale(TfwHttpReq *req, tfw_http_cache_cb_t action,
			       TfwCacheEntry *stale_ce, long age)
{
	TFW_INC_STAT_BH(cache.hits);

	T_DBG("Cache: assign stale for request [%p] w/ key=%lx, ce=%p", req,
	      stale_ce->trec.key, stale_ce);

	/*
	 * TODO: #2271.
	 * Do tfw_handle_validation_req for stale-while-revalidate.
	 */

	/*
	 * stale_ce will be released by req destructor or during stale
	 * forwarding.
	 */
	req->stale_ce = stale_ce;
	req->stale_ce_age = age;

	action((TfwHttpMsg *)req);
}

static void
cache_do_not_service_request(TfwHttpReq *req, tfw_http_cache_cb_t action)
{
	if (req->cache_ctl.flags & TFW_HTTP_CC_OIFCACHED) {
		tfw_http_send_err_resp(req, 504, "resource not cached");
	} else {
		/*
		 * TODO: RFC 7234 4.3.2: Extend preconditional request headers
		 * if any with values from cached entries to revalidate stored
		 * stale responses for both: client and Tempesta.
		 */
		action((TfwHttpMsg *)req);
	}
}

static void
cache_do_service_request(TfwHttpReq *req, tfw_http_cache_cb_t action,
			 TfwCacheEntry *ce, long age)
{
	TfwHttpResp *resp = NULL;

	T_DBG("Cache: service request [%p] w/ key=%lx, ce=%p", req,
	      ce->trec.key, ce);

	TFW_INC_STAT_BH(cache.hits);

	if (!tfw_handle_validation_req(req, ce))
		return;

	resp = tfw_cache_build_resp(req, ce, age);
	if (unlikely(!resp)) {
		cache_do_not_service_request(req, action);
		T_ERR("Cache: Can't allocate response.");
		return;
	}

	/*
	 * The stream of HTTP/2-request should be closed here since we have
	 * successfully created the resulting response from cache and will
	 * send this response to the client (without forwarding request to
	 * the backend), thus the stream will be finished.
	 */
	if (TFW_MSG_H2(req))
		tfw_h2_req_unlink_stream(req);

	action((TfwHttpMsg *)req);
}

/*
 * Try to service request from the cache. If it allowed use stale cached
 * response.
 *
 * NOTE: This function is responsible for releasing non stale cache entry
 * using @tdb_rec_put(). Stale cache entry must be assigned to request then
 * released during response forwarding or request destruction.
 */
static bool
cache_try_service_request(TfwHttpReq *req, tfw_http_cache_cb_t action)
{
	TDB *db = node_db();
	TdbIter iter;
	TfwCacheEntry *ce = NULL;
	long lifetime;
	long age;

	if (!(ce = tfw_cache_dbce_get(db, &iter, req))) {
		T_DBG3("%s: db=[%p] req=[%p] CE has not been found\n",
		       __func__, db, req);
		return false;
	}
	__tfw_dbg_dump_ce(ce);

	age = tfw_cache_entry_age(ce);

	if (!(lifetime = tfw_cache_entry_is_live(req, ce, age))) {
		bool success;

		T_DBG3("%s: db=[%p] req=[%p] ce=[%p] CE is not alive\n",
		       __func__, db, req, ce);

		if ((success = tfw_cache_can_use_stale(req, ce, age)))
			cache_do_service_request_stale(req, action, ce, age);
			/*
			 * Stale record will be released by req destructor or
			 * during forwarding stale response.
			 */
		else
			tdb_rec_put(db, ce);

		return success;
	}

	cache_do_service_request(req, action, ce, age);
	tdb_rec_put(db, ce);

	return true;
}

static void
cache_req_process_node(TfwHttpReq *req, tfw_http_cache_cb_t action)
{
	if (cache_try_service_request(req, action))
		return;

	TFW_INC_STAT_BH(cache.misses);

	/* Record not found in the cache. */
	cache_do_not_service_request(req, action);
}

static void
tfw_cache_do_action(TfwHttpMsg *msg, tfw_http_cache_cb_t action)
{
	TfwHttpReq *req;

	if (TFW_CONN_TYPE(msg->conn) & Conn_Srv) {
		tfw_cache_add((TfwHttpResp *)msg, action);
		return;
	}

	req = (TfwHttpReq *)msg;
	if (unlikely(req->method == TFW_HTTP_METH_PURGE)) {
		int ret;

		ret = tfw_cache_purge_method(req);
		/* Check if we want to do a GET in addition to PURGE. */
		if (!ret && test_bit(TFW_HTTP_B_PURGE_GET, req->flags))
			action((TfwHttpMsg *)req);
	} else {
		/*
		 * For request that can be employed from cache, we always
		 * rewrite method from HEAD to GET to store to cache complete
		 * response.
		 */
		if (req->method == TFW_HTTP_METH_HEAD)
			set_bit(TFW_HTTP_B_REQ_HEAD_TO_GET, req->flags);
		cache_req_process_node(req, action);
	}
}

static void
tfw_cache_ipi(struct irq_work *work)
{
	TfwWorkTasklet *ct = container_of(work, TfwWorkTasklet, ipi_work);
	clear_bit(TFW_QUEUE_IPI, &ct->wq.flags);
	tasklet_schedule(&ct->tasklet);
}

/**
 * According RFC 9111 4.4:
 * A cache MUST invalidate the target URI when it receives
 * a non-error status code in response to an unsafe request
 * method (including methods whose safety is unknown).
 * A "non-error response" is one with a 2xx (Successful) or
 * 3xx (Redirection) status code.
 * Also invalidate target URI for all nonidempotent requests
 * because they can change internal server state.
 */
static bool
tfw_cache_should_invalidate_uri(TfwHttpReq *req, TfwHttpResp *resp)
{
	return cache_cfg.cache && (req->method == TFW_HTTP_METH_PUT
		|| req->method == TFW_HTTP_METH_DELETE
		|| req->method == TFW_HTTP_METH_POST
		|| tfw_http_req_is_nip(req))
		&& resp->status >= 200 && resp->status < 400;
}

static void
tfw_cache_invalidate_uri(TfwHttpReq *req, TfwHttpResp *resp)
{
	unsigned long key;

	key = tfw_http_req_key_calc(req);
	req->node = (cache_cfg.cache == TFW_CACHE_SHARD)
			? tfw_cache_key_node(key)
			: numa_node_id();

	if (cache_cfg.cache == TFW_CACHE_SHARD) {
		/* Potential inter-node access. */
		tdb_entry_remove(get_db_for_node(req->node), key,
				 &tfw_cache_rec_eq_req,
				 req, false);
	} else {
		int nid;

		for_each_node_with_cpus(nid)
			tdb_entry_remove(get_db_for_node(nid), key,
					 &tfw_cache_rec_eq_req,
					 req, false);
	}
}

/**
 * If the message is a request, serve it from the cache; if it's a response,
 * cache it. Then, invoke the specified @action with the cached or original
 * message passed (request or response, respectively). If the message wasn't
 * cached, the original one will be passed to @action; otherwise, the cached
 * one will be passed. A cached request will have an attached response
 * (@req->resp), while an original one won't. This distinction allows us to
 * differentiate between the two.
 *
 * Therefore, this routine serves two purposes: adding a response to the cache
 * when @msg is a response and returning a cached response by attaching it to
 * @req->resp when @msg is a request. Perhaps not the optimal design, but it is
 * what it is.
 *
 * We use the callback @action because the message will be served
 * synchronously only if the routine is called on the same NUMA node to which
 * the request is attached. Otherwise, it will be served asynchronously.
 */
int
tfw_cache_process(TfwHttpMsg *msg, tfw_http_cache_cb_t action)
{
	int cpu;
	unsigned long key;
	TfwWorkTasklet *ct;
	TfwCWork cw;
	TfwHttpResp *resp = NULL;
	TfwHttpReq *req = (TfwHttpReq *)msg;

	if (TFW_CONN_TYPE(msg->conn) & Conn_Srv) {
		resp = (TfwHttpResp *)msg;
		req = resp->req;

		/*
		 * Don't cache response to HEAD, to prevent caching response
		 * without body.
		 */
		if (req->method == TFW_HTTP_METH_HEAD &&
		    !test_bit(TFW_HTTP_B_REQ_HEAD_TO_GET, req->flags))
			goto dont_cache;

		if (tfw_cache_should_invalidate_uri(req, resp))
			tfw_cache_invalidate_uri(req, resp);
	}

	/*
	 * We service non-challengeble resources from cache only
	 * for safe methods.
	 */
	if (test_bit(TFW_HTTP_B_JS_NOT_SUPPORTED, req->flags)
	    && req->method != TFW_HTTP_METH_GET
	    && req->method != TFW_HTTP_METH_HEAD)
		goto dont_cache;
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
	 */
	if (likely(req->node == numa_node_id())) {
		tfw_cache_do_action(msg, action);
		return 0;
	}

	cw.msg = msg;
	cw.action = action;
	cpu = tfw_cache_sched_cpu(req);
	ct = per_cpu_ptr(&cache_wq, cpu);

	T_DBG2("Cache: schedule tasklet w/ work: to_cpu=%d from_cpu=%d"
	       " msg=%p key=%lx\n", cpu, smp_processor_id(),
	       cw.msg, key);
	if (tfw_wq_push(&ct->wq, &cw, cpu, &ct->ipi_work, tfw_cache_ipi)) {
		T_WARN("Cache work queue overrun: [%s]\n",
		       resp ? "response" : "request");
		return -EBUSY;
	}
	return 0;

dont_cache:
	action(msg);
	return 0;
}

static void
tfw_wq_tasklet(unsigned long data)
{
	TfwWorkTasklet *ct = (TfwWorkTasklet *)data;
	TfwRBQueue *wq = &ct->wq;
	TfwCWork cw;

	while (!tfw_wq_pop(wq, &cw))
		tfw_cache_do_action(cw.msg, cw.action);

	TFW_WQ_IPI_SYNC(tfw_wq_size, wq);

	tasklet_schedule(&ct->tasklet);
}

/**
 * Cache management thread.
 * The thread loads and preprocesses static Web content using inotify (TODO).
 */
#if 0
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
#endif

static inline int
tfw_cache_wq_init(int cpu)
{
	TfwWorkTasklet *ct = &per_cpu(cache_wq, cpu);
	int r;

	r = tfw_wq_init(&ct->wq, TFW_DFLT_QSZ, cpu_to_node(cpu));
	if (unlikely(r))
		return r;
	init_irq_work(&ct->ipi_work, tfw_cache_ipi);
	tasklet_init(&ct->tasklet, tfw_wq_tasklet, (unsigned long)ct);

	return 0;
}

static inline void
tfw_cache_wq_clear(int cpu)
{
	TfwWorkTasklet *ct = &per_cpu(cache_wq, cpu);

	tasklet_kill(&ct->tasklet);
	irq_work_sync(&ct->ipi_work);
	tfw_wq_destroy(&ct->wq);
}

static int
tfw_cache_start(void)
{
	int i, r = 1;

	if (WARN_ON_ONCE(cache_cfg.cache == TFW_CACHE_UNDEFINED))
		return -EINVAL;

	if (tfw_runstate_is_reconfig())
		return 0;
	if (!cache_cfg.cache)
		return 0;

	if ((r = tfw_init_node_cpus()))
		goto node_cpus_alloc_err;

	for_each_node_with_cpus(i) {
		c_nodes[i].db = tdb_open(cache_cfg.db_path,
					 cache_cfg.db_size, 0, i);
		if (!c_nodes[i].db) {
			r = -ENOMEM;
			goto close_db;
		}
		c_nodes[i].db->hdr->before_free = tfw_cache_decrease_stat;
	}
#if 0
	cache_mgr_thr = kthread_run(tfw_cache_mgr, NULL, "tfw_cache_mgr");
	if (IS_ERR(cache_mgr_thr)) {
		r = PTR_ERR(cache_mgr_thr);
		T_ERR_NL("Can't start cache manager, %d\n", r);
		goto close_db;
	}
#endif

	TFW_WQ_CHECKSZ(TfwCWork);
	for_each_online_cpu(i) {
		if (unlikely(r = tfw_cache_wq_init(i))) {
			T_ERR_NL("%s: Can't initialize cache work"
				 " queue for CPU #%d\n", __func__, i);
			goto free_tasklet;
		}
	}

#if defined(DEBUG)
	for_each_online_cpu(i) {
		char *dbg_buf = kmalloc_node(CE_DBGBUF_LEN, GFP_KERNEL,
					     cpu_to_node(i));
		if (!dbg_buf) {
			T_WARN("Failed to allocate CE dump buffer\n");
			goto dbg_buf_free;
		}
		per_cpu(ce_dbg_buf, i) = dbg_buf;
	}
#endif

	return 0;

#if defined(DEBUG)
dbg_buf_free:
	for_each_online_cpu(i)
		kfree(per_cpu(ce_dbg_buf, i));
#endif
free_tasklet:
	for_each_online_cpu(i)
		tfw_cache_wq_clear(i);
close_db:
	for_each_node_with_cpus(i)
		tdb_close(c_nodes[i].db);

node_cpus_alloc_err:
	tfw_release_node_cpus();
	return r;
}

static void
tfw_cache_stop(void)
{
	int i;

	BUG_ON(cache_cfg.cache == TFW_CACHE_UNDEFINED);

	if (tfw_runstate_is_reconfig())
		return;
	if (!cache_cfg.cache)
		return;

	for_each_online_cpu(i)
		tfw_cache_wq_clear(i);
#if 0
	kthread_stop(cache_mgr_thr);
#endif

#if defined(DEBUG)
	for_each_online_cpu(i)
		kfree(per_cpu(ce_dbg_buf, i));
#endif

	for_each_node_with_cpus(i)
		tdb_close(c_nodes[i].db);

	tfw_release_node_cpus();
}

static const TfwCfgEnum cache_http_methods_enum[] = {
	{ "copy",	TFW_HTTP_METH_COPY },
	{ "delete",	TFW_HTTP_METH_DELETE },
	{ "get",	TFW_HTTP_METH_GET },
	{ "head",	TFW_HTTP_METH_HEAD },
	{ "lock",	TFW_HTTP_METH_LOCK },
	{ "mkcol",	TFW_HTTP_METH_MKCOL },
	{ "move",	TFW_HTTP_METH_MOVE },
	{ "options",	TFW_HTTP_METH_OPTIONS },
	{ "patch",	TFW_HTTP_METH_PATCH },
	{ "post",	TFW_HTTP_METH_POST },
	{ "propfind",	TFW_HTTP_METH_PROPFIND },
	{ "proppatch",	TFW_HTTP_METH_PROPPATCH },
	{ "put",	TFW_HTTP_METH_PUT },
	{ "trace",	TFW_HTTP_METH_TRACE },
	{ "unlock",	TFW_HTTP_METH_UNLOCK },
	/* Unknown methods can't be cached. */
	{}
};

static int
tfw_cfgop_cache_val(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwGlobal *g_vhost = tfw_vhost_get_global();
	int cache;
	int r;

	cs->dest = &cache;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	if (r)
		return r;

	/* Note: Issue #400. Tempesta doesn't support NUMA nodes without CPU. */
	if (cache == TFW_CACHE_SHARD) {
		int node;

		for_each_online_node(node) {
			if (!nr_cpus_node(node)) {
				T_ERR_NL("NUMA: Node %d doesn't have cpu. "
					 "Tempesta doesn't support nodes without cpu in SHARD mode.\n",
					 node);
				return -EINVAL;
			}
		}
	}

	if (g_vhost->cache_purge && !cache) {
		T_ERR_NL("Directives mismatching: 'cache_purge' directive "
			  "requires 'cache' be not zero\n");
		return -EINVAL;
	}

	cache_cfg.cache = cache;
	return r;
}

static int
tfw_cfgop_cache_methods(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int i, method;
	const char *val;

	BUILD_BUG_ON(sizeof(cache_cfg.methods) * BITS_PER_BYTE
		     < _TFW_HTTP_METH_COUNT);
	BUILD_BUG_ON(sizeof(method) * BITS_PER_BYTE < _TFW_HTTP_METH_COUNT);

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (tfw_cfg_map_enum(cache_http_methods_enum, val, &method)) {
			T_ERR_NL("%s: unsupported method: '%s'\n",
				   cs->name, val);
			return -EINVAL;
		}
		if (__cache_method_nc_test(method)) {
			T_ERR_NL("%s: non-cacheable method '%s' is set "
				  "as cacheable\n",
				  cs->name, val);
			return -EINVAL;
		}
		if (__cache_method_test(method)) {
			T_WARN_NL("%s: duplicate method: '%s'\n",
				  cs->name, val);
			continue;
		}
		__cache_method_add(method);
	}

	return 0;
}

static void
tfw_cfgop_cleanup_cache_methods(TfwCfgSpec *cs)
{
	cache_cfg.methods = 0;
}

bool
tfw_cache_is_enabled_or_not_configured(void)
{
	return cache_cfg.cache != TFW_CACHE_NONE;
}

static TfwCfgSpec tfw_cache_specs[] = {
	{
		.name = "cache",
		.deflt = "2",
		.handler = tfw_cfgop_cache_val,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { TFW_CACHE_NONE, TFW_CACHE_REPLICA },
		},
	},
	{
		.name = "cache_methods",
		.deflt = "GET",
		.handler = tfw_cfgop_cache_methods,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_cfgop_cleanup_cache_methods,
	},
	{
		.name = "cache_size",
		.deflt = "256M",
		.handler = tfw_cfg_set_mem,
		.dest = &cache_cfg.db_size,
		.spec_ext = &(TfwCfgSpecMem) {
			.multiple_of = "2M",
			.range = { "16M", "128G" },
		}
	},
	{
		.name = "cache_db",
		.deflt = "/opt/tempesta/db/cache.tdb",
		.handler = tfw_cfg_set_str,
		.dest = &cache_cfg.db_path,
		.spec_ext = &(TfwCfgSpecStr) {
			.len_range = { 1, PATH_MAX },
		}
	},
	{
		.name = "cache_ttl",
		.deflt = "2147483647",
		.handler = tfw_cfg_set_int,
		.dest = &cache_default_ttl,
	},
	{ 0 }
};

TfwMod tfw_cache_mod = {
	.name 	= "cache",
	.start	= tfw_cache_start,
	.stop	= tfw_cache_stop,
	.specs	= tfw_cache_specs,
};

int
tfw_cache_init(void)
{
	tfw_mod_register(&tfw_cache_mod);
	return 0;
}

void
tfw_cache_exit(void)
{
	tfw_mod_unregister(&tfw_cache_mod);
}
