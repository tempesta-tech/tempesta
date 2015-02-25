/**
 *		Tempesta FW
 *
 * Copyright (C) 2015 Tempesta Technologies.
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

#include <linux/percpu.h>
#include <linux/smp.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "http_match.h"
#include "lb_mod.h"
#include "log.h"
#include "tempesta.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta HTTP load balancer");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");

#define TFW_LB_GROUP_MAX 32

typedef enum {
	TFW_LB_SCHED_RR,
	TFW_LB_SCHED_HASH,
} tfw_lb_sched_t;

/* XXX-comments are only for the review, they will be removed afterwards. */

/**
 * XXX: the structure should correspond to one "backend_group" configuration
 * entry and contain all nested "backend" servers.
 */
typedef struct {
	tfw_lb_sched_t	sched;
	int		rr_idx;
	int		sks_n;
	struct sock 	**sks;
	u32		*sk_hashes;
} TfwLbGroup;

/**
 * XXX: the structure is adopted from tfw_sched_http. It allows to route HTTP
 * requests to a certain group of backend servers depending on HTTP request
 * fields: URI, Host, headers, etc.
 */
typedef struct {
	TfwLbGroup *group;
	TfwHttpMatchRule rule;
} TfwLbRule;

/**
 * The list of rules that allow to route HTTP requests to specific backend
 * servers based on certain HTTP request fields: URI, Host, headers, etc.
 */
TfwHttpMatchList *tfw_lb_rules;

/**
 * XXX: non-shared round-robin counters allow to avoid atomic instructions
 * and prevent cache line bouncing.
 */
DEFINE_PER_CPU(u8[TFW_LB_GROUP_MAX], tfw_lb_group_rr_ctrs);

#define TFW_LB_GROUP_RR_CTR(group) \
	(__get_cpu_var(tfw_lb_group_rr_ctrs)[(group)->rr_idx])


static struct sock *
tfw_lb_sched_rr_failover(TfwLbGroup *group)
{
	int sks_n, ctr, ctr_end;
	struct sock *sk, **sks;

	sks = group->sks;
	sks_n = group->sks_n;
	ctr = TFW_LB_GROUP_RR_CTR(group);
	ctr_end = ctr + sks_n;

	while (likely(++ctr < ctr_end)) {
		sk = sks[ctr % sks_n];
		if (likely(sk->sk_state == TCP_ESTABLISHED)) {
			TFW_LB_GROUP_RR_CTR(group) = ctr;
			return sk;
		}
	}

	TFW_ERR("can't find any online backend server\n");
	return NULL;
}

/**
 * XXX: the whole tfw_sched_rr is collapsed into this single function.
 */
static struct sock *
tfw_lb_sched_rr(TfwLbGroup *group)
{
	struct sock *sk;

	sk = group->sks[++TFW_LB_GROUP_RR_CTR(group) % group->sks_n];
	if (likely(sk->sk_state == TCP_ESTABLISHED))
		return sk;

	return tfw_lb_sched_rr_failover(group);
}

/**
 * XXX: the whole tfw_sched_hash is collapsed into this single function.
 * Rendezvous hashing is included as a failovering strategy.
 *
 * XXX: the linear search is slow but it is required for failover switching.
 * Perhaps we should do binary search first, and then fall back to linear if
 * the chosen socket is dead.
 *
 * XXX: schedulers will be separated into modules later. Now the code is here
 * because it determines how to build everything else around it.
 */
static struct sock *
tfw_lb_sched_hash(TfwLbGroup *group, TfwHttpReq *req)
{
	struct sock **sk_pos, *sk, *best_sk;
	u32 *hash_pos, hash, best_hash, req_hash;

	best_sk = NULL;
	best_hash = 0;
	req_hash = tfw_http_req_key_calc(req);

	sk_pos = group->sks;
	hash_pos = group->sk_hashes;
	do {
		sk = *sk_pos;
		hash = *hash_pos;

		if ((req_hash ^ hash) > (req_hash ^ best_hash) &&
		    likely(sk->sk_state == TCP_ESTABLISHED)) {
			best_sk = sk;
			best_hash = hash;
		}
	} while (*(++sk_pos) && *(++hash_pos));

	return best_sk;
}

static struct sock *
tfw_lb_sched(TfwLbGroup *group, TfwHttpReq *req)
{
	/* Should be done via a function pointer, but KISS for now. */
	return (group->sched == TFW_LB_SCHED_RR)
	       ? tfw_lb_sched_rr(group)
	       : tfw_lb_sched_hash(group, req);
}

/**
 * XXX: all useful logic from tfw_sched_http is merged into this function.
 * The rest of tfw_sched_http is configuration parsing and boilerplate code.
 */
static int
tfw_lb_http_send_msg(TfwMsg *msg)
{
	struct sock *sk;
	TfwLbRule *rule;
	TfwHttpReq *req = container_of(msg, TfwHttpReq, msg);

	rule = tfw_http_match_req_entry(req, tfw_lb_rules, TfwLbRule, rule);
	sk = tfw_lb_sched(rule->group, req);
	ss_send(sk, &msg->skb_list);
	return 0;
}

static const TfwLbMod tfw_lb_http_mod = {
	.name = "tfw_lb_http",
	.send_msg = tfw_lb_http_send_msg
};

int
tfw_lb_http_init(void)
{
	return tfw_lb_mod_register(&tfw_lb_http_mod);
}
module_init(tfw_lb_http_init);

void
tfw_lb_http_exit(void)
{
	tfw_lb_mod_unregister();
}
module_exit(tfw_lb_http_exit);
