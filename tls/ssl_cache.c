/*
 *		Tempesta TLS
 *
 * TLS session cache implementation
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 * TODO #1054: the lists are bad, use TDB instead.
 */
/**
 * TODO #1054.
 * ttls_conf_session_cache() was removed since we don't need to set
 * f_get_cache() and f_set_cache() callbacks, instead just remove the callbacks
 * completely and call the cache functions directly.
 *
 * The session cache has the responsibility to check for stale
 * entries based on timeout. See RFC 5246 for recommendations.
 *
 * Warning: session.peer_cert is cleared by the SSL/TLS layer on
 * connection shutdown, so do not cache the pointer! Either set
 * it to NULL or make a full copy of the certificate.
 *
 * The get callback is called once during the initial handshake
 * to enable session resuming. The get function has the
 * following parameters: (void *parameter, TlsSess *session)
 * If a valid entry is found, it should fill the master of
 * the session object with the cached values and return 0,
 * return 1 otherwise. Optionally peer_cert can be set as well
 * if it is properly present in cache entry.
 *
 * The set callback is called once during the initial handshake
 * to enable session resuming after the entire handshake has
 * been finished. The set function has the following parameters:
 * (void *parameter, const TlsSess *session). The function
 * should create a cache entry for future retrieval based on
 * the data in the session structure and should keep in mind
 * that the TlsSess object presented (and all its referenced
 * data) is cleared by the SSL/TLS layer when the connection is
 * terminated. It is recommended to add metadata to determine if
 * an entry is still valid in the future. Return 0 if
 * successfully cached, return 1 otherwise.
 */

#include "config.h"

#if defined(TTLS_CACHE_C)

#include "ssl_cache.h"

/* TODO #515: the constants must go to configuration directive describing
 * the TDB collection.
 */
#define TTLS_CACHE_DEFAULT_TIMEOUT	86400 /* 1 day  */
#define TTLS_CACHE_DEFAULT_MAX_ENTRIES	50 /* Maximum entries in cache */

void ttls_cache_init(ttls_cache_context *cache)
{
	memset(cache, 0, sizeof(ttls_cache_context));

	cache->timeout = TTLS_CACHE_DEFAULT_TIMEOUT;
	cache->max_entries = TTLS_CACHE_DEFAULT_MAX_ENTRIES;
	spin_lock_init(&cache->mutex);
}

int ttls_cache_get(void *data, TlsSess *session)
{
	int ret = 1;
	time_t t = ttls_time();
	ttls_cache_context *cache = (ttls_cache_context *) data;
	ttls_cache_entry *cur, *entry;

	spin_lock(&cache->mutex);

	cur = cache->chain;
	entry = NULL;

	while (cur != NULL)
	{
		entry = cur;
		cur = cur->next;

		if (cache->timeout != 0 &&
			(int) (t - entry->timestamp) > cache->timeout)
			continue;

		if (session->ciphersuite != entry->session.ciphersuite ||
			session->compression != entry->session.compression ||
			session->id_len != entry->session.id_len)
			continue;

		if (memcmp(session->id, entry->session.id,
				entry->session.id_len) != 0)
			continue;

		memcpy(session->master, entry->session.master, 48);

		session->verify_result = entry->session.verify_result;

		/*
		 * Restore peer certificate (without rest of the original chain)
		 */
		if (entry->peer_cert.p != NULL)
		{
			if ((session->peer_cert = ttls_calloc(1,
				 sizeof(ttls_x509_crt))) == NULL)
			{
				ret = 1;
				goto exit;
			}

			ttls_x509_crt_init(session->peer_cert);
			if (ttls_x509_crt_parse(session->peer_cert, entry->peer_cert.p,
						entry->peer_cert.len) != 0)
			{
				ttls_free(session->peer_cert);
				session->peer_cert = NULL;
				ret = 1;
				goto exit;
			}
		}

		ret = 0;
		goto exit;
	}

exit:
	spin_unlock(&cache->mutex);

	return ret;
}

int ttls_cache_set(void *data, const TlsSess *session)
{
	int ret = 1;
	time_t t = ttls_time(), oldest = 0;
	ttls_cache_entry *old = NULL;
	ttls_cache_context *cache = (ttls_cache_context *) data;
	ttls_cache_entry *cur, *prv;
	int count = 0;

	spin_lock(&cache->mutex);

	cur = cache->chain;
	prv = NULL;

	while (cur != NULL)
	{
		count++;

		if (cache->timeout != 0 &&
			(int) (t - cur->timestamp) > cache->timeout)
		{
			cur->timestamp = t;
			break; /* expired, reuse this slot, update timestamp */
		}

		if (memcmp(session->id, cur->session.id, cur->session.id_len) == 0)
			break; /* client reconnected, keep timestamp for session id */

		if (oldest == 0 || cur->timestamp < oldest)
		{
			oldest = cur->timestamp;
			old = cur;
		}

		prv = cur;
		cur = cur->next;
	}

	if (cur == NULL)
	{
		/*
		 * Reuse oldest entry if max_entries reached
		 */
		if (count >= cache->max_entries)
		{
			if (old == NULL)
			{
				ret = 1;
				goto exit;
			}

			cur = old;
		}
		else
		{
			/*
			 * max_entries not reached, create new entry
			 */
			cur = ttls_calloc(1, sizeof(ttls_cache_entry));
			if (cur == NULL)
			{
				ret = 1;
				goto exit;
			}

			if (prv == NULL)
				cache->chain = cur;
			else
				prv->next = cur;
		}

		cur->timestamp = t;
	}

	memcpy(&cur->session, session, sizeof(TlsSess));

	/*
	 * If we're reusing an entry, free its certificate first
	 */
	if (cur->peer_cert.p != NULL)
	{
		ttls_free(cur->peer_cert.p);
		memset(&cur->peer_cert, 0, sizeof(ttls_x509_buf));
	}

	/*
	 * Store peer certificate
	 */
	if (session->peer_cert != NULL)
	{
		cur->peer_cert.p = ttls_calloc(1, session->peer_cert->raw.len);
		if (cur->peer_cert.p == NULL)
		{
			ret = 1;
			goto exit;
		}

		memcpy(cur->peer_cert.p, session->peer_cert->raw.p,
				session->peer_cert->raw.len);
		cur->peer_cert.len = session->peer_cert->raw.len;

		cur->session.peer_cert = NULL;
	}

	ret = 0;

exit:
	spin_unlock(&cache->mutex);

	return ret;
}

void ttls_cache_set_timeout(ttls_cache_context *cache, int timeout)
{
	if (timeout < 0) timeout = 0;

	cache->timeout = timeout;
}

void ttls_cache_set_max_entries(ttls_cache_context *cache, int max)
{
	if (max < 0) max = 0;

	cache->max_entries = max;
}

void ttls_cache_free(ttls_cache_context *cache)
{
	ttls_cache_entry *cur, *prv;

	cur = cache->chain;

	while (cur != NULL)
	{
		prv = cur;
		cur = cur->next;

		bzero_fast(&prv->session, sizeof(prv->session));

		ttls_free(prv->peer_cert.p);

		ttls_free(prv);
	}

	cache->chain = NULL;
}

#endif /* TTLS_CACHE_C */
