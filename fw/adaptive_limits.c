/**
 *		Tempesta FW
 *
 * Copyright (C) 2026 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "adaptive_limits.h"
#include "client.h"
#include "http_limits.h"
#include "tempesta_fw.h"
#include "lib/fault_injection_alloc.h"
#include "lib/128bit.h"

/* Training period in seconds. Zero means disabled. */
static unsigned int tfw_training_mode_period = 0;
unsigned int tfw_adaptive_limits_mode =
	TFW_ADAPTIVE_LIMITS_MODE_IS_DISABLED;
unsigned int g_training_epoch = 0;

/* Z-score thresholds for different metrics. */
static int tfw_adaptive_limits_z_score_conn_num = 0;
static int tfw_adaptive_limits_z_score_req_num = 0;
static int tfw_adaptive_limits_z_score_mem = 0;
static int tfw_adaptive_limits_z_score_cpu = 0;

/* Timer and worker used to switch training -> defence asynchronously. */
static struct timer_list training_timer;
static struct work_struct training_work;

/*
 * Per-metric aggregated statistics.
 *
 * @sumsq 		- sum of squares of observed values;
 * @sum			- sum of observed values;
 * @mean  		- calculated mean (scaled);
 * @std   		- calculated standard deviation (scaled);
 * @num   		- number of samples (e.g. number of clients);
 * @scale_shift		- scaling factor;
 */
struct stats {
	u128 __percpu	*sumsq;
	u64 __percpu	*sum;
	u64 		mean;
	u64 		std;
	u32 __percpu	*num;
	unsigned int	scale_shift;
};

/* Global RCU-protected statistics for each metric. */
static struct stats __rcu *g_conn_num = NULL;
static struct stats __rcu *g_req_num = NULL;
static struct stats __rcu *g_mem_num = NULL;
static struct stats __rcu *g_cpu_num = NULL;

/*
 * Allocate and initialize stats structure.
 * Returns NULL on failure.
 */
static inline struct stats *
__alloc_stats(void)
{
	struct stats *s;
	gfp_t flags = GFP_KERNEL | __GFP_ZERO;	

	s = tfw_kmalloc(sizeof(struct stats), flags);
	if (unlikely(!s))
		return NULL;

	s->sumsq = tfw_alloc_percpu_gfp(u128, flags);
	if (unlikely(!s->sumsq))
		goto fail_alloc_sumsq;

	s->sum = tfw_alloc_percpu_gfp(u64, flags);
	if (unlikely(!s->sum))
		goto fail_alloc_sum;

	s->num = tfw_alloc_percpu_gfp(unsigned int, flags);
	if (unlikely(!s->num))
		goto fail_alloc_num;

	return s;

fail_alloc_num:
	free_percpu(s->sum);
fail_alloc_sum:
	free_percpu(s->sumsq);
fail_alloc_sumsq:
	kfree(s);

	return NULL;
}

/* Free stats structure and all embedded percpu counters. */
static inline void
__free_stats(struct stats *s)
{
	if (likely(s)) {
		free_percpu(s->sumsq);
		free_percpu(s->sum);
		free_percpu(s->num);
		kfree(s);
	}
}

/*
 * Disable both training and defence modes.
 *
 * Ensures that no readers are accessing RCU-protected stats,
 * so pointers can be safely replaced.
 */
static inline void
tfw_adaptive_limits_disable_training_or_defence(void)
{
	/*
	 * Set TFW_ADAPTIVE_LIMITS_MODE_IS_DISABLED, now we stop
	 * calling all new defence and training functions. We don't
	 * try to make rcu pointer dereference after it.
	 */
	WRITE_ONCE(tfw_adaptive_limits_mode,
		   TFW_ADAPTIVE_LIMITS_MODE_IS_DISABLED);
	/*
	 * Wait until all previous rcu calls finished, to be sure
	 * that we can safely change pointers.
	 */
	synchronize_rcu();
}

/*
 * Replace all global stats with new instances.
 *
 * Safe due to prior call to tfw_adaptive_limits_disable_training_or_defence().
 */
static inline void
__upgrade_all_stats(struct stats *new_conn_num,
		    struct stats *new_req_num,
		    struct stats *new_mem_num,
		    struct stats *new_cpu_num)
{
	struct stats *old_conn_num, *old_req_num, *old_mem_num, *old_cpu_num;

	tfw_adaptive_limits_disable_training_or_defence();
	old_conn_num = rcu_replace_pointer(g_conn_num, new_conn_num, true);
	old_req_num = rcu_replace_pointer(g_req_num, new_req_num, true);
	old_mem_num = rcu_replace_pointer(g_mem_num, new_mem_num, true);
	old_cpu_num = rcu_replace_pointer(g_cpu_num, new_cpu_num, true);
	/*
	 * We don't need second `synchronize_rcu` here (first `synchronize_rcu`
	 * is called inside `tfw_adaptive_limits_disable_training_or_defence`),
	 * because we check that adaptive limits mode is not disabled in all
	 * places where we access `stats`.
	 * So after calling `tfw_adaptive_limits_disable_training_or_defence`
	 * we are sure that all concurrent calls (where we can access `old_*
	 * stats) are finished or don't try to dereference appropriate pointer,
	 * because of already in disabled mode.
	 */
	__free_stats(old_conn_num);
	__free_stats(old_req_num);
	__free_stats(old_mem_num);
	__free_stats(old_cpu_num);
}

static inline int
__alloc_all_stats(struct stats **new_conn_num,
		  struct stats **new_req_num,
		  struct stats **new_mem_num,
		  struct stats **new_cpu_num)
{
	struct stats *conn_num = NULL;
	struct stats *req_num = NULL;
	struct stats *mem_num = NULL;
	struct stats *cpu_num = NULL;

	conn_num = __alloc_stats();
	if (unlikely(!conn_num))
		return -ENOMEM;

	req_num = __alloc_stats();
	if (unlikely(!req_num))
		goto fail_alloc_req_num;

	mem_num = __alloc_stats();
	if (unlikely(!mem_num))
		goto fail_alloc_mem_num;

	cpu_num = __alloc_stats();
	if (unlikely(!cpu_num))
		goto fail_alloc_cpu_num;

	*new_conn_num = conn_num;
	*new_req_num = req_num;
	*new_mem_num = mem_num;
	*new_cpu_num = cpu_num;

	return 0;

fail_alloc_cpu_num:
	__free_stats(mem_num);
fail_alloc_mem_num:
	__free_stats(req_num);
fail_alloc_req_num:
	__free_stats(conn_num);

	return -ENOMEM;
}

static inline int
__alloc_upgrade_stats(void)
{
	struct stats *new_conn_num = NULL;
	struct stats *new_req_num = NULL;
	struct stats *new_mem_num = NULL;
	struct stats *new_cpu_num = NULL;
	int r;

	r = __alloc_all_stats(&new_conn_num, &new_req_num, &new_mem_num,
			      &new_cpu_num);
	if (unlikely(r))
		return r;

	__upgrade_all_stats(new_conn_num, new_req_num, new_mem_num,
			    new_cpu_num);

	return 0;
}

static inline int
__init_z_score(void)
{
	int r;

	r = __alloc_upgrade_stats();
	if (unlikely(r))
		return r;

	/*
	 * After set TFW_ADAPTIVE_LIMITS_MODE_IS_DISABLED and calling
	 * `synchronize_rcu` from `__upgrade_all_stats` we are sure that
	 * all defence and training functions were finished. Start new
	 * training epoch.
	 */
	g_training_epoch++;

	return 0;
}

/*
 * Compute mean and standard deviation from aggregated stats.
 * Uses integer arithmetic with scaling.
 */
static inline void
__calculate_mean_and_std(struct stats *s)
{
	u128 variance, tmp1, tmp2;
	u128 total_sumsq;
	u64 total_sum;
	u32 num_clients;

	total_sumsq = tfw_percpu_u128_counter_sum(s->sumsq);
	total_sum = tfw_percpu_u64_counter_sum(s->sum);
	num_clients = tfw_percpu_u32_counter_sum(s->num);

	if (!unlikely(num_clients))
		return;

	/*
	 * Use fixed-point scaling only if the accumulated sum is small enough.
	 * Once the sum approaches the u32 limit, disable scaling to prevent
	 * arithmetic overflow in subsequent calculations.
	 */
	s->scale_shift = total_sum < U32_MAX ? SCALE_SHIFT : 0; 
	/*
	 * Since total_sum < U32_MAX implies total_sumsq < U64_MAX,
	 * the fixed-point left shift cannot overflow.
	 */
	tmp1 = total_sumsq << s->scale_shift;
	tmp1 = u128_div_u32(tmp1, num_clients);
	s->mean = (total_sum << s->scale_shift) / num_clients;
	tmp2 = (u128)s->mean * (u128)s->mean;
	tmp2 = tmp2 >> s->scale_shift;
	variance = tmp1 - tmp2;
	s->std = u128_sqrt(variance << s->scale_shift);
}

static inline bool
__calculate_z_score(u64 val, struct stats *s, s64 *z_score)
{
	if (unlikely(!s->std))
		return false;

	/*
	 * We store `mean` and `std` values in scaled format, so
	 * we should convert `val` to scaled format also.
	 */
	*z_score = ((s64)(val << s->scale_shift) - (s64)s->mean) / (s64)s->std;

	return true;
}

static inline void
tfw_adaptive_limits_adjust_new_client(struct stats __rcu *g_stats)
{
	struct stats *s;

	/*
	 * rcu pointer dereference should be done under rcu lock,
	 * to prevent memory corruption.
	 */
	BUG_ON(!rcu_read_lock_held());
	s = rcu_dereference(g_stats);
	this_cpu_add(*s->num, 1);
}

static void
tfw_adaptive_limits_adjust_conn_new_client(void)
{
	return tfw_adaptive_limits_adjust_new_client(g_conn_num);
}

static inline void
tfw_adaptive_limits_adjust_new_el(struct stats __rcu *g_stats, u64 delta1,
				  u128 delta2)
{
	struct stats *s;

	/*
	 * rcu pointer dereference should be done under rcu lock,
	 * to prevent memory corruption.
	 */
	BUG_ON(!rcu_read_lock_held());
	s = rcu_dereference(g_stats);
	this_cpu_add(*s->sum, delta1);
	/* `this_cpu_add` is not implemented for 128-bit value. */
	*this_cpu_ptr(s->sumsq) += delta2;
}

static void
tfw_adaptive_limits_adjust_conn_num(u64 delta1, u128 delta2)
{
	return tfw_adaptive_limits_adjust_new_el(g_conn_num, delta1, delta2);
}

/**
 * Perform z-score based defence check
 * 
 * @g_stats	- RCU-protected pointer to aggregated statistics
 * @val		- current observed value
 * @threshold	- configured z-score threshold
 *
 * In defence mode, this function evaluates @val against previously
 * learned statistics using z-score:
 *
 *   z = (val - mean) / std
 *
 * If z-score exceeds @threshold, the value is considered anomalous
 * and the function returns false (caller should reject the event)
 * and drop connection with TCP RST.
 *
 * Return:
 *   true  - value is acceptable
 *   false - value exceeds threshold (reject)
 */
static inline bool
tfw_adaptive_limits_defence(struct stats __rcu *g_stats, u64 val, int threshold)
{
	struct stats *p;
	s64 z_score;

	/*
	 * rcu pointer dereference should be done under rcu lock,
	 * to prevent memory corruption.
	 */
	BUG_ON(!rcu_read_lock_held());

	p = rcu_dereference(g_stats);
	if (!__calculate_z_score(val, p, &z_score))
		return true;

	return z_score <= threshold;
}

static inline bool
tfw_adaptive_limits_defence_conn_num(u64 val)
{
	int threshold = tfw_adaptive_limits_z_score_conn_num;

	return tfw_adaptive_limits_defence(g_conn_num, val, threshold);
}

bool
tfw_adaptive_limits_check_conn_num(TfwAdaptiveLimit *limit, int delta,
				   u16 *epoch)
{
	u128 delta2;
	u64 delta1;
	unsigned int old_max;
	bool new_client = false;
	bool rc = true;

	/*
	 * Prevent training epoch changes while processing the event.
	 *
	 * A new training epoch is started only after:
	 *
	 *	synchronize_rcu();
	 *	g_training_epoch++;
	 *
	 * Therefore, while we are inside this RCU read-side critical
	 * section, `g_training_epoch` cannot change and the event is
	 * guaranteed to be processed against a stable training epoch.
	 *
	 * This avoids races where an event is validated against one
	 * epoch and accounted after statistics have already been reset
	 * for the next epoch.
	 */
	rcu_read_lock();

	if (tfw_adaptive_limits_mode_is_disabled())
		goto out;

	/*
	 * Ignore connection close events from previous training epochs.
	 * For new connections, assign current training epoch.
	 */
	if (delta < 0 && *epoch < g_training_epoch)
		goto out;
	else if (delta > 0)
		*epoch = g_training_epoch;

	if (tfw_adaptive_limits_mode_is_defence()) {
		limit->counter += delta;
		WARN_ON(limit->counter < 0);

		if (delta > 0)
			rc = tfw_adaptive_limits_defence_conn_num(limit->counter);
		goto out;
	}

	/*
	 * Training mode.
	 *
	 * Reset limit on each new training epoch.
	 * This is safe without extra synchronization as we are under
	 * client-private lock.
	 */
	if (limit->epoch < g_training_epoch) {
		limit->epoch = g_training_epoch;
		limit->counter = 0;
		limit->max = 0;
		new_client = true;
	}

	if (new_client)
		tfw_adaptive_limits_adjust_conn_new_client();
	limit->counter += delta;
	WARN_ON(limit->counter < 0);

	old_max = limit->max;
	if (limit->counter <= old_max)
		goto out;

	limit->max = limit->counter;
	delta1 = limit->counter - old_max;
	delta2 = (u128)limit->counter * (u128)limit->counter -
		(u128)old_max * (u128)old_max;
	tfw_adaptive_limits_adjust_conn_num(delta1, delta2);

out:
	rcu_read_unlock();

	return rc;
}

static inline void
tfw_adaptive_limits_prepare_for_defence(void)
{
	/*
	 * Wait until all threads finish using of global pointers.
	 * After this call we are sure that no one access any g_*_num
	 * structures, so we can safely calculated mean and std.
	 */
	tfw_adaptive_limits_disable_training_or_defence();
	__calculate_mean_and_std(g_conn_num);
	__calculate_mean_and_std(g_req_num);
	__calculate_mean_and_std(g_mem_num);
	__calculate_mean_and_std(g_cpu_num);
	WRITE_ONCE(tfw_adaptive_limits_mode,
		   TFW_ADAPTIVE_LIMITS_MODE_IS_DEFENCE);
}

/*
 * Workqueue handler to safely switch modes (sleepable context).
 */
static void
training_work_fn(struct work_struct *work)
{
	tfw_adaptive_limits_prepare_for_defence();
}

static void
tfw_training_timer_cb(struct timer_list *t)
{
	/*
	 * We should use working thread, because we should call
	 * `synchronize_rcu` before start defence mode.
	 */
	schedule_work(&training_work);
}

/*
 * Stop training early and switch to defence mode if needed.
 */
static inline void
tfw_training_stop(void)
{
	/*
	 * If training mode has already completed and the system has switched
	 * to defence mode, or training was never started, the timer is already
	 * inactive and no further action is required.
	*/
	if (del_timer_sync(&training_timer))
		tfw_adaptive_limits_prepare_for_defence();
}

static inline int
tfw_training_start(void)
{
	unsigned long training_period_in_jiffies =
		msecs_to_jiffies(1000 * tfw_training_mode_period);
	int r;

	r = __init_z_score();
	if (unlikely(r))
		return r;

	WRITE_ONCE(tfw_adaptive_limits_mode,
		   TFW_ADAPTIVE_LIMITS_MODE_IS_TRAINING);
	mod_timer(&training_timer, jiffies + training_period_in_jiffies);

	return 0;
}

int
tfw_ctlfn_adaptive_limits_mode_change(unsigned int mode)
{
	if (mode)
		return tfw_training_start();

	tfw_training_stop();
	return 0;
}

static int
tfw_training_mode_start(void)
{
	if (tfw_runstate_is_reconfig())
		return 0;

	INIT_WORK(&training_work, training_work_fn);
	timer_setup(&training_timer, tfw_training_timer_cb, 0);

	return __alloc_all_stats(&g_conn_num, &g_req_num, &g_mem_num,
				 &g_cpu_num);
}

static void
tfw_training_mode_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;

	timer_shutdown_sync(&training_timer);
	flush_work(&training_work);
	__upgrade_all_stats(NULL, NULL, NULL, NULL);
}

static TfwCfgSpec tfw_training_mode_specs[] = {
	{
		.name = "training_period",
		.deflt = "75",
		.handler = tfw_cfg_set_int,
		.allow_reconfig = true,
		.dest = &tfw_training_mode_period,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		},
	},
	{
		.name = "adaptive_limits_z_score_connection_num",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.allow_reconfig = true,
		.dest = &tfw_adaptive_limits_z_score_conn_num,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "adaptive_limits_z_score_request_num",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.allow_reconfig = true,
		.dest = &tfw_adaptive_limits_z_score_req_num,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "adaptive_limits_z_score_mem",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.allow_reconfig = true,
		.dest = &tfw_adaptive_limits_z_score_mem,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "adaptive_limits_z_score_cpu",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.allow_reconfig = true,
		.dest = &tfw_adaptive_limits_z_score_cpu,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{ 0 }
};

TfwMod tfw_training_mod = {
	.name 	= "training",
	.start	= tfw_training_mode_start,
	.stop	= tfw_training_mode_stop,
	.specs	= tfw_training_mode_specs,
};

int __init
tfw_adaptive_limits_init(void)
{
	tfw_mod_register(&tfw_training_mod);

	return 0;
}

void
tfw_adaptive_limits_exit(void)
{
	tfw_mod_unregister(&tfw_training_mod);
}
