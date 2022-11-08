/**
 *		Tempesta FW
 *
 * Synchronous Sockets API for Linux socket buffers manipulation.
 *
 * Copyright (C) 2015-2022 Tempesta Technologies, Inc.
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

#include "str.h"

/**
 * Responses from socket hook functions.
 */
enum {
	/*
	 * SS functions must return the code on shutdown process.
	 * This code means that we can't finish requested operation due to
	 * shutdown process, but this isn't error.
	 */
	SS_SHUTDOWN	= -4,
	/* Generic socket error. */
	SS_BAD		= -3,
	/* The packet must be dropped (typically on a security event). */
	SS_DROP		= -2,
	/* The packet should be stashed (made by callback). */
	SS_POSTPONE	= -1,
	/* The packet looks good and we can safely pass it. */
	SS_OK		= 0,
};

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
ss_skb_unlink(struct sk_buff **skb_head, struct sk_buff *skb)
{
	WARN_ON_ONCE(!skb->prev || !skb->next);
	/* If this is last skb, set head to NULL. */
	if (skb->next == skb) {
		*skb_head = NULL;
	} else {
		skb->prev->next = skb->next;
		skb->next->prev = skb->prev;
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

#define SS_SKB_MAX_DATA_LEN	(SKB_MAX_HEADER + MAX_SKB_FRAGS * PAGE_SIZE)

char *ss_skb_fmt_src_addr(const struct sk_buff *skb, char *out_buf);

int ss_skb_alloc_data(struct sk_buff **skb_head, size_t len,
		      unsigned int tx_flags);
struct sk_buff *ss_skb_split(struct sk_buff *skb, int len);
int ss_skb_get_room(struct sk_buff *skb_head, struct sk_buff *skb,
		    char *pspt, unsigned int len, TfwStr *it);
int ss_skb_get_room_w_frag(struct sk_buff *skb_head, struct sk_buff *skb,
			   char *pspt, unsigned int len, TfwStr *it, int *fragn);
int ss_skb_expand_head_tail(struct sk_buff *skb_head, struct sk_buff *skb,
			    size_t head, size_t tail);
int ss_skb_chop_head_tail(struct sk_buff *skb_head, struct sk_buff *skb,
			  size_t head, size_t tail);
int
ss_skb_list_chop_head_tail(struct sk_buff **skb_list_head,
                           size_t head, size_t trail);
int
ss_skb_cutoff_data_flagged(struct sk_buff *skb_head, const TfwStr *str,
			   unsigned short flag, int tail);
int ss_skb_cutoff_data(struct sk_buff *skb_head, const TfwStr *hdr,
		       int skip, int tail);
int skb_next_data(struct sk_buff *skb, char *last_ptr, TfwStr *it);

int ss_skb_process(struct sk_buff *skb, ss_skb_actor_t actor, void *objdata,
		   unsigned int *chunks, unsigned int *processed);

int ss_skb_unroll(struct sk_buff **skb_head, struct sk_buff *skb);
void ss_skb_init_for_xmit(struct sk_buff *skb);
void ss_skb_dump(struct sk_buff *skb);
int ss_skb_to_sgvec_with_new_pages(struct sk_buff *skb, struct scatterlist *sgl,
                                   struct page ***old_pages);
int ss_skb_cut_extra_data(struct sk_buff *skb_head, struct sk_buff *skb,
			  int frag_num, char *curr, const char *stop);

#endif /* __TFW_SS_SKB_H__ */
