/**
 *		Tempesta FW
 *
 * Synchronous Sockets API for Linux socket buffers manipulation.
 *
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
#ifndef __TFW_SS_SKB_H__
#define __TFW_SS_SKB_H__

#include <linux/skbuff.h>
#include <net/tcp.h>

#include "str.h"
#include "lib/log.h"

/**
 * Responses from socket hook functions.
 */
enum {
	/* Generic socket error. */
	SS_BAD		  = T_BAD,
	/* The packet must be dropped, but connection should be alive. */
	SS_DROP		  = T_DROP,
	/*
	 * The packet must be blocked with TCP FIN (typically on a
	 * security event, when we reply to client).
	 */
	SS_BLOCK_WITH_FIN = T_BLOCK_WITH_FIN,
	/*
	 * The packet must be blocked with TCP RST (typically on a
	 * security event).
	 */
	SS_BLOCK_WITH_RST = T_BLOCK_WITH_RST,
	/* The packet should be stashed (made by callback). */
	SS_POSTPONE	  = T_POSTPONE,
	/* The packet looks good and we can safely pass it. */
	SS_OK		  = T_OK,
};

typedef int (*on_send_cb_t)(void *conn, struct sk_buff **skb_head);
typedef void (*on_tcp_entail_t)(void *conn, struct sk_buff *skb_head);

/*
 * Tempesta FW sk_buff private data.
 * @opaque_data 	- pointer to some private data (typically http response);
 * @destructor		- destructor of the opaque data, should be set if data is
 *                        not NULL
 * @on_send		- callback to special handling this skb before sending;
 * @on_tcp_entail 	- callback to special handling this skb before pushing
 *                        to socket write queue;
 * @stream_id		- id of sender stream;
 * @is_head		- flag indicates that this is a head of skb list;
 */
struct tfw_skb_cb {
	void 		*opaque_data;
	void 		(*destructor)(void *opaque_data);
	on_send_cb_t	on_send;
	on_tcp_entail_t on_tcp_entail;
	unsigned int 	stream_id;
	bool		is_head;
};

#define TFW_SKB_CB(skb) ((struct tfw_skb_cb *)&((skb)->cb[0]))

void ss_skb_set_owner(struct sk_buff *skb, void *owner);
void ss_skb_adjust_sk_mem(struct sk_buff *skb, int delta);

static inline bool
ss_skb_is_within_fragment(char *begin_fragment, char *position,
                          char *end_fragment)
{
        return begin_fragment <= position && position < end_fragment;
}

static inline void
ss_skb_setup_head_of_list(struct sk_buff *skb_head, unsigned int mark,
			  unsigned char tls_type)
{
	if (tls_type)
		skb_set_tfw_tls_type(skb_head, tls_type);
	skb_head->mark = mark;
	TFW_SKB_CB(skb_head)->is_head = true;
}

static inline void
ss_skb_setup_opaque_data(struct sk_buff *skb_head, void *opaque_data,
			 void (*destructor)(void *))
{
	TFW_SKB_CB(skb_head)->opaque_data = opaque_data;
	TFW_SKB_CB(skb_head)->destructor = destructor;
}

static inline void
ss_skb_destroy_opaque_data(struct sk_buff *skb_head)
{
	void *opaque_data = TFW_SKB_CB(skb_head)->opaque_data;
	void (*destructor)(void *) = TFW_SKB_CB(skb_head)->destructor;

	BUILD_BUG_ON(sizeof(struct tfw_skb_cb) >
		     sizeof(((struct sk_buff *)(0))->cb));

	if (opaque_data) {
		BUG_ON(!destructor);
		destructor(opaque_data);
	}
}

static inline int
ss_skb_on_send(void *conn, struct sk_buff **skb_head)
{
	on_send_cb_t on_send = TFW_SKB_CB(*skb_head)->on_send;
	int r = 0;

	if (on_send)
		r = on_send(conn, skb_head);

	return r;
}

static inline void
ss_skb_on_tcp_entail(void *conn, struct sk_buff *skb_head)
{
	on_tcp_entail_t on_tcp_entail = TFW_SKB_CB(skb_head)->on_tcp_entail;

	if (on_tcp_entail)
		on_tcp_entail(conn, skb_head);
}

typedef int ss_skb_actor_t(void *conn, unsigned char *data, unsigned int len,
			   unsigned int *read);

/**
 * Add new _single_ @skb to the queue in FIFO order.
 */
static inline void
ss_skb_queue_tail(struct sk_buff **skb_head, struct sk_buff *skb)
{
	/* The skb shouldn't be in any other queue. */
	WARN_ON_ONCE(skb->next || skb->prev);
	if (!*skb_head) {
		*skb_head = skb;
		skb->prev = skb->next = skb;
		return;
	}
	skb->next = *skb_head;
	skb->prev = (*skb_head)->prev;
	skb->next->prev = skb->prev->next = skb;
}

/**
 * Append list of @skb to the queue in FIFO order.
 */
static inline void
ss_skb_queue_append(struct sk_buff **skb_head, struct sk_buff *skb)
{
	struct sk_buff *tail;

	if (WARN_ON_ONCE(!*skb_head)) {
		*skb_head = skb;
		return;
	}

	tail = (*skb_head)->prev;
	skb->prev->next = *skb_head;
	(*skb_head)->prev = skb->prev;
	skb->prev = tail;
	tail->next = skb;
}

static inline void
ss_skb_queue_splice(struct sk_buff **skb_head, struct sk_buff **skb)
{
	struct sk_buff *tail;

	if ((!*skb_head)) {
		swap(*skb_head, *skb);
		return;
	}

	tail = (*skb_head)->prev;
	(*skb_head)->prev = (*skb)->prev;
	(*skb)->prev->next = (*skb_head);
	tail->next = *skb;
	(*skb)->prev = tail;

	*skb = NULL;
}

static inline void
ss_skb_remove(struct sk_buff *skb)
{
	skb->prev->next = skb->next;
	skb->next->prev = skb->prev;
}

static inline void
ss_skb_unlink(struct sk_buff **skb_head, struct sk_buff *skb)
{
	WARN_ON_ONCE(!skb->prev || !skb->next);
	/* If this is last skb, set head to NULL. */
	if (skb->next == skb) {
		*skb_head = NULL;
	} else {
		ss_skb_remove(skb);
		/* If this is head skb and not last, set head to the next skb. */
		if (*skb_head == skb)
			*skb_head = skb->next;
	}
	skb->next = skb->prev = NULL;
}

static inline struct sk_buff *
ss_skb_peek_tail(struct sk_buff **skb_head)
{
	return *skb_head ? (*skb_head)->prev : NULL;
}

/**
 * Split single queue into two, where the @skb will be a head of a new queue.
 */
static inline void
ss_skb_queue_split(struct sk_buff *skb_head, struct sk_buff *skb)
{
	struct sk_buff *prev = skb->prev;
	WARN_ON_ONCE(skb_head == skb);

	skb->prev = skb_head->prev;
	prev->next = skb_head;

	skb->prev->next = skb;
	skb_head->prev = prev;
}

/*
 * Insert @nskb in the list after @skb. Note that standard
 * kernel 'skb_insert()' function does not suit here, as it
 * works with 'sk_buff_head' structure with additional fields
 * @qlen and @lock; we don't need these fields for our skb
 * list, so a custom function had been introduced.
 */
static inline void
ss_skb_insert_after(struct sk_buff *skb, struct sk_buff *nskb)
{
	nskb->next = skb->next;
	nskb->prev = skb;
	nskb->next->prev = skb->next = nskb;
}

/*
 * Insert @nskb in the list before @skb and update @skb_head.
 */
static inline void
ss_skb_insert_before(struct sk_buff **skb_head, struct sk_buff *skb,
		     struct sk_buff *nskb)
{
	/* The skb shouldn't be in any other queue. */
	WARN_ON_ONCE(nskb->next || nskb->prev);
	nskb->next = skb;
	nskb->prev = skb->prev;
	nskb->next->prev = nskb->prev->next = nskb;

	if (*skb_head == skb)
		*skb_head = nskb;
}

static inline void
ss_skb_queue_head(struct sk_buff **skb_head, struct sk_buff *skb)
{
	/* The skb shouldn't be in any other queue. */
	WARN_ON_ONCE(skb->next || skb->prev);
	if (!*skb_head) {
		*skb_head = skb;
		skb->prev = skb->next = skb;
		return;
	}
	ss_skb_insert_before(skb_head, *skb_head, skb);
}

/**
 * Almost a copy of standard skb_dequeue() except it works with skb list
 * instead of sk_buff_head. Several crucial data include skb list and we don't
 * want to spend extra memory for unused members of skb_buff_head.
 */
static inline struct sk_buff *
ss_skb_dequeue(struct sk_buff **skb_head)
{
	struct sk_buff *skb = *skb_head;
	if (skb)
		ss_skb_unlink(skb_head, skb);
	return skb;
}

static inline void
ss_skb_queue_purge(struct sk_buff **skb_head)
{
	struct sk_buff *skb;
	while ((skb = ss_skb_dequeue(skb_head)) != NULL)
		kfree_skb(skb);
}

static inline void
ss_skb_adjust_data_len(struct sk_buff *skb, int delta)
{
	skb->len += delta;
	skb->data_len += delta;
	skb->truesize += delta;
	if (skb->sk)
		ss_skb_adjust_sk_mem(skb, delta);
}

/*
 * skb_tailroom - number of bytes at buffer end
 *
 * This function is nearly a copy of the original that is defined
 * in include/linux/skbuff.h. The difference is that the original
 * only works on a linear skb, while this one works on any skb.
 */
static inline int
ss_skb_tailroom(const struct sk_buff *skb)
{
	return skb->end - skb->tail;
}

/*
 * skb_put - add data to a buffer
 *
 * This function is nearly a copy of the original that is defined
 * in net/core/skbuff.c. The difference is that the original only
 * works on a linear skb, while this one works on any skb.
 */
static inline unsigned char *
ss_skb_put(struct sk_buff *skb, const int len)
{
	unsigned char *tmp = skb_tail_pointer(skb);

	skb->tail += len;
	skb->len  += len;

	WARN_ON_ONCE(skb->tail > skb->end);

	return tmp;
}

static inline struct sk_buff *
ss_skb_alloc(size_t n)
{
	struct sk_buff *skb = alloc_skb(MAX_TCP_HEADER + n, GFP_ATOMIC);

	if (!skb)
		return NULL;
	skb_reserve(skb, MAX_TCP_HEADER);

	return skb;
}

static inline int
ss_skb_find_frag_by_offset(struct sk_buff *skb, char *off, int *frag)
{
	char *begin, *end;
	unsigned char i;

	if (skb_headlen(skb)) {
		begin = skb->data;
		end = begin + skb_headlen(skb);

		if (ss_skb_is_within_fragment(begin, off, end)) {
			*frag = -1;
			return 0;
		}
	}
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];

		begin = skb_frag_address(f);
		end = begin + skb_frag_size(f);

		if (ss_skb_is_within_fragment(begin, off, end)) {
			*frag = i;
			return 0;
		}
	}

	return -E2BIG;
}

static inline void
ss_skb_move_frags(struct sk_buff *skb, struct sk_buff *nskb, int from,
		  unsigned count)
{
	struct skb_shared_info *si = skb_shinfo(skb);
	struct skb_shared_info *nsi = skb_shinfo(nskb);
	skb_frag_t *f;
	int i = 0, e_size = 0;

	while (i++ < count) {
		f = &si->frags[from++];
		skb_shinfo(nskb)->frags[nsi->nr_frags++] = *f;
		si->nr_frags--;
		e_size += skb_frag_size(f);
	}

	nskb->pp_recycle = skb->pp_recycle;
	ss_skb_adjust_data_len(skb, -e_size);
	ss_skb_adjust_data_len(nskb, e_size);
}

static inline char *
ss_skb_data_ptr_by_offset(struct sk_buff *skb, unsigned int off)
{
	char *begin, *end;
	unsigned char i;

	if (skb_headlen(skb)) {
		begin = skb->data;
		end = begin + skb_headlen(skb);

		if (ss_skb_is_within_fragment(begin, begin + off, end))
			return begin + off;
		off -= skb_headlen(skb);
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];

		begin = skb_frag_address(f);
		end = begin + skb_frag_size(f);

		if (ss_skb_is_within_fragment(begin, begin + off, end))
			return begin + off;

		off -= end - begin;
	}

	return NULL;
}

#define SS_SKB_MAX_DATA_LEN	(SKB_MAX_HEADER + MAX_SKB_FRAGS * PAGE_SIZE)

char *ss_skb_fmt_src_addr(const struct sk_buff *skb, char *out_buf);

int ss_skb_alloc_data(struct sk_buff **skb_head, void *owner, size_t len);
struct sk_buff *ss_skb_split(struct sk_buff *skb, int len);
int ss_skb_get_room_w_frag(struct sk_buff *skb_head, struct sk_buff *skb,
			   char *pspt, unsigned int len, TfwStr *it, int *fragn);
int ss_skb_expand_head_tail(struct sk_buff *skb_head, struct sk_buff *skb,
			    size_t head, size_t tail);
int ss_skb_chop_head_tail(struct sk_buff *skb_head, struct sk_buff *skb,
			  size_t head, size_t tail);
int ss_skb_list_chop_head_tail(struct sk_buff **skb_list_head,
			       size_t head, size_t trail);
int ss_skb_cutoff_data(struct sk_buff *skb_head, TfwStr *hdr,
		       int skip, int tail);
int skb_next_data(struct sk_buff *skb, char *last_ptr, TfwStr *it);

int ss_skb_process(struct sk_buff *skb, ss_skb_actor_t actor, void *objdata,
		   unsigned int *chunks, unsigned int *processed);

int ss_skb_unroll(struct sk_buff **skb_head, struct sk_buff *skb);
void ss_skb_init_for_xmit(struct sk_buff *skb);
void ss_skb_dump(struct sk_buff *skb);
int ss_skb_to_sgvec_with_new_pages(struct sk_buff *skb, struct scatterlist *sgl,
				   struct page ***old_pages);
int ss_skb_add_frag(struct sk_buff *skb_head, struct sk_buff **skb, char* addr,
		    int *frag_idx, size_t frag_sz);
int ss_skb_linear_transform(struct sk_buff *skb_head, struct sk_buff *skb,
			    unsigned char *split_point);
int ss_skb_realloc_headroom(struct sk_buff *skb);

#if defined(DEBUG) && (DEBUG >= 4)
#define ss_skb_queue_for_each_do(queue, lambda)		\
do {							\
	int i = 0;					\
	struct sk_buff *skb = *queue;			\
	if (likely(skb)) {				\
		do {					\
			lambda;				\
			skb = skb->next;		\
		} while (skb != *queue);		\
	}						\
} while(0)

#define SS_SKB_QUEUE_DUMP(queue)			\
	ss_skb_queue_for_each_do(queue, {		\
		pr_debug("#%2d skb => %pK\n", i++, skb);	\
		skb_dump(KERN_DEBUG, skb, true);	\
	});
#else
#define SS_SKB_QUEUE_DUMP(...)
#endif

#endif /* __TFW_SS_SKB_H__ */
