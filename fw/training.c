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
#include "training.h"
#include "client.h"
#include "http_limits.h"
#include "tempesta_fw.h"
#include "lib/fault_injection_alloc.h"

/* Training period in seconds. Zero means disabled. */
static unsigned int tfw_training_mod_period = 0;
unsigned int tfw_training_mod_state = TFW_MODE_DISABLED;
unsigned int g_training_epoch = 0;

/* Z-score thresholds for different metrics. */
static int tfw_training_mod_z_score_mem_num = 0;
static int tfw_training_mod_z_score_cpu_num = 0;
static int tfw_training_mod_z_score_conn_num = 0;
static int tfw_training_mod_z_score_req_num = 0;

/* Timer and worker used to switch training -> defence asynchronously. */
static struct timer_list training_timer;
static struct work_struct training_work;

/*
 * Per-metric aggregated statistics.
 *
 * @num   - number of samples (e.g. number of clients).
 * @sum   - sum of observed values.
 * @sumsq - sum of squares of observed values.
 * @mean  - calculated mean (scaled by SCALE_SHIFT).
 * @std   - calculated standard deviation (scaled).
 *
 * percpu_counter is used to reduce contention on hot paths.
 */
struct stats {
	struct percpu_counter num;
	struct percpu_counter sum;
	struct percpu_counter sumsq;
	s64 mean;
	s64 std;
};

/* Global RCU-protected statistics for each metric. */
static struct stats __rcu *g_conn_num = NULL;
static struct stats __rcu *g_req_num = NULL;
static struct stats __rcu *g_cpu_num = NULL;

/*
 * Allocate and initialize stats structure.
 * Returns NULL on failure.
 */
static inline struct stats *
__alloc_stats(void)
{
	struct stats *s;
	int r;

	s = tfw_kzalloc(sizeof(struct stats), GFP_KERNEL);
	if (unlikely(!s))
		return NULL;

	r = percpu_counter_init(&s->num, 0, GFP_KERNEL);
	if (unlikely(r))
		goto fail_alloc_num;

	r = percpu_counter_init(&s->sum, 0, GFP_KERNEL);
	if (unlikely(r))
		goto fail_alloc_sum;

	r = percpu_counter_init(&s->sumsq, 0, GFP_KERNEL);
	if (unlikely(r))
		goto fail_alloc_sumsq;

	return s;

fail_alloc_sumsq:
	percpu_counter_destroy(&s->sum);
fail_alloc_sum:
	percpu_counter_destroy(&s->num);
fail_alloc_num:
	kfree(s);

	return NULL;
}

/* Free stats structure and all embedded percpu counters. */
static inline void
__free_stats(struct stats *s)
{
	percpu_counter_destroy(&s->num);
	percpu_counter_destroy(&s->sum);
	percpu_counter_destroy(&s->sumsq);
	kfree(s);
}

/*
 * Disable both training and defence modes.
 *
 * Ensures that no readers are accessing RCU-protected stats,
 * so pointers can be safely replaced.
 */
static inline void
tfw_disable_training_or_defence(void)
{
	/*
	 * Set TFW_MODE_DISABLED, now we stop calling all new defence
	 * and training functions.
	 */
	WRITE_ONCE(tfw_training_mod_state, TFW_MODE_DISABLED);
	/*
	 * Wait until all previous rcu calls finished, to be sure
	 * that we can safely change pointers.
	 */
	synchronize_rcu();
}

/*
 * Replace all global stats with new instances.
 *
 * Safe due to prior call to tfw_disable_training_or_defence().
 */
static inline void
__upgrade_all_stats(struct stats *new_conn_num,
		    struct stats *new_req_num,
		    struct stats *new_cpu_num)
{
	struct stats *old_conn_num, *old_req_num, *old_cpu_num;

	tfw_disable_training_or_defence();
	old_conn_num = rcu_replace_pointer(g_conn_num, new_conn_num, true);
	old_req_num = rcu_replace_pointer(g_req_num, new_req_num, true);
	old_cpu_num = rcu_replace_pointer(g_cpu_num, new_cpu_num, true);
	/*
	 * We don't need second `synchronize_rcu`, because all readers
	 * check `tfw_training_mod_state` before `rcu_read_lock`
	 */
	__free_stats(old_conn_num);
	__free_stats(old_req_num);
	__free_stats(old_cpu_num);
}

static inline int
__alloc_all_stats(struct stats **new_conn_num,
		  struct stats **new_req_num,
		  struct stats **new_cpu_num)
{
	struct stats *conn_num = NULL;
	struct stats *req_num = NULL;
	struct stats *cpu_num = NULL;

	conn_num = __alloc_stats();
	if (unlikely(!conn_num))
		return -ENOMEM;

	req_num = __alloc_stats();
	if (unlikely(!req_num))
		goto fail_alloc_req_num;

	cpu_num = __alloc_stats();
	if (unlikely(!cpu_num))
		goto fail_alloc_cpu_num;

	*new_conn_num = conn_num;
	*new_req_num = req_num;
	*new_cpu_num = cpu_num;

	return 0;

fail_alloc_cpu_num:
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
	struct stats *new_cpu_num = NULL;
	int r;

	r = __alloc_all_stats(&new_conn_num, &new_req_num, &new_cpu_num);
	if (unlikely(r))
		return r;

	__upgrade_all_stats(new_conn_num, new_req_num, new_cpu_num);

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
	 * After set TFW_MODE_DISABLED and calling `synchronize_rcu` from
	 * `__upgrade_all_stats` we are sure that all defence and training
	 * functions were finished. Start new training epoch.
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
	s64 variance;
	u64 total_sum = 0;
	u64 total_sumsq = 0;
	u32 num_clients = 0;

	num_clients = percpu_counter_sum(&s->num);
	total_sum = percpu_counter_sum(&s->sum);
	total_sumsq = percpu_counter_sum(&s->sumsq);

	if (!unlikely(num_clients))
		return;

	s->mean = (total_sum << SCALE_SHIFT) / num_clients;
	variance = ((total_sumsq << SCALE_SHIFT) / num_clients) -
		((s->mean * s->mean) >> SCALE_SHIFT);
	s->std = int_sqrt64(variance << SCALE_SHIFT);
}

static inline bool
__calculate_z_score(u64 val, struct stats *s, s64 *z_score)
{
	if (unlikely(!s->std))
		return false;

	*z_score = ((s64)(val << SCALE_SHIFT) - s->mean) / s->std;
	return true;

}

static bool
tfw_training_mode_adjust_new_start(TfwTrainingStat *stat)
{
	bool rc = false;

	/*
	 * We increment `g_training_epoch` each time when we start new
	 * training, when we are sure that all threads don't use `max`
	 * and `curr`. During training all threads call this function
	 * before use `curr` and `max`, so we are sure that `curr` and
	 * `max` will be zeroed on the start of the new training.
	 * We make first check to prevent unnecessary lock on the hot
	 * path on each call.
	 */
	if (unlikely(stat->epoch < g_training_epoch)) {
		spin_lock(&stat->lock);
		if (likely(stat->epoch < g_training_epoch)) {
			atomic64_set(&stat->curr, 0);
			atomic64_set(&stat->max, 0);
			stat->epoch = g_training_epoch;
			rc = true;
		}
		spin_unlock(&stat->lock);
 	}

	return rc;
}

static inline void
tfw_training_mode_adjust_new_client(struct stats __rcu *g_stats)
{
	struct stats *s;

	rcu_read_lock();

	BUG_ON(tfw_mode_is_disabled());	
	s = rcu_dereference(g_stats);
	percpu_counter_add(&s->num, 1);

	rcu_read_unlock();
}

static inline void
tfw_training_mode_adjust_new_client_req_num(void)
{
	return tfw_training_mode_adjust_new_client(g_req_num);
}

static inline void
tfw_training_mode_adjust_new_client_cpu_num(void)
{
	return tfw_training_mode_adjust_new_client(g_cpu_num);
}

static inline void
tfw_training_mode_adjust_new_el(struct stats __rcu *g_stats, u64 delta1,
				u64 delta2, bool new_client)
{
	struct stats *s;

	rcu_read_lock();

	BUG_ON(tfw_mode_is_disabled());
	s = rcu_dereference(g_stats);
	if (new_client)
		percpu_counter_add(&s->num, 1);
	percpu_counter_add(&s->sum, delta1);
	percpu_counter_add(&s->sumsq, delta2);

	rcu_read_unlock();
}

void
tfw_training_mode_adjust_conn_num(u64 delta1, u64 delta2, bool new_client)
{
	return tfw_training_mode_adjust_new_el(g_conn_num, delta1, delta2,
					       new_client);
}

static void
tfw_training_mode_adjust_req_num(u64 delta1, u64 delta2, bool new_client)
{
	return tfw_training_mode_adjust_new_el(g_req_num, delta1, delta2,
					       new_client);
}

static void
tfw_training_mode_adjust_cpu_num(u64 delta1, u64 delta2, bool new_client)
{
	return tfw_training_mode_adjust_new_el(g_cpu_num, delta1, delta2,
					       new_client);
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
 * The statistics are accessed under RCU read-side critical section.
 * If standard deviation is zero (insufficient data), the check is
 * skipped.
 *
 * Return:
 *   true  - value is acceptable
 *   false - value exceeds threshold (reject)
 */
static inline bool
tfw_training_mode_defence(struct stats __rcu *g_stats, u64 val, int threshold)
{
	struct stats *p;
	s64 z_score;

	if (!tfw_mode_is_defence())
		return true;

	rcu_read_lock();

	p = rcu_dereference(g_stats);

	if (!__calculate_z_score(val, p, &z_score)) {
		rcu_read_unlock();
		return true;
	}

	rcu_read_unlock();

	return z_score <= threshold;
}

bool
tfw_training_mode_defence_conn_num(u64 val)
{
	return tfw_training_mode_defence(g_conn_num, val,
					 tfw_training_mod_z_score_conn_num);
}

static bool
tfw_training_mode_defence_req_num(u64 val)
{
	return tfw_training_mode_defence(g_req_num, val,
					 tfw_training_mod_z_score_req_num);
}

static bool
tfw_training_mode_defence_cpu_num(u64 val)
{
	return tfw_training_mode_defence(g_cpu_num, val,
					 tfw_training_mod_z_score_cpu_num);
}

static inline void
tfw_training_mode_adjust(atomic64_t *max, u64 curr, bool new_client,
			 void (*adjust)(u64, u64, bool),
			 void (*adjust_client)(void))
{
	u64 delta1, delta2, old_max;

	old_max = atomic64_read(max);

	/*
	 * Can be called concurrentrly on other cpu with different
	 * curr value, so we need syncronization here.
	 */
	do {
		if (curr <= old_max) {
			if (unlikely(new_client))
				adjust_client();
			return;
		}
	} while (!atomic64_try_cmpxchg(max, &old_max, curr));

	delta1 = curr - old_max;
	delta2 = (u64)curr * curr - (u64)old_max * old_max;
	adjust(delta1, delta2, new_client);
}

static inline bool
tfw_training_mode_update(TfwTrainingStat *stat, void (*adjust)(u64, u64, bool),
			 bool (*defence)(u64), void (*adjust_client)(void),
			 int delta, unsigned int *training_epoch)
{
	bool new_client = false;
	s64 curr;

	WARN_ON(!delta);
	if (tfw_mode_is_disabled())
		return true;

	/*
	 * If delta < 0, event finished (request deleted from server
	 * connection queue). If event starts during the old training
	 * period, skip this event.
	 * If delta > 0, set event `training_epoch`, later we will use
	 * it to adjust it, when event finished if training period is
	 * same.
	 */
	if (delta < 0 && *training_epoch < g_training_epoch)
		return true;
	else if (delta > 0)
		*training_epoch = g_training_epoch;

	if (tfw_mode_is_defence()) {
		curr = atomic64_add_return(delta, &stat->curr);
		WARN_ON(curr < 0);

		if (delta < 0)
			return true;
		return defence(curr);
	}

	/*
	 * Each client has it's own stat for each observed value.
	 * When new training start, first call of this function
	 * returns true, and we increment count of clients for
	 * further mean and std calculation.
	 */ 
	if (tfw_training_mode_adjust_new_start(stat))
		new_client = true;

	curr = atomic64_add_return(delta, &stat->curr);
	tfw_training_mode_adjust(&stat->max, curr, new_client,
				 adjust, adjust_client);

	return true;
}

#define TFW_TRAINING_MODE_UPDATE_STAT(name)				\
bool									\
tfw_training_mode_update##_##name##_##stat(TfwTrainingStat *stat,	\
					   int delta,			\
					   unsigned int *training_epoch) \
{									\
	void (*adjust)(u64, u64, bool) =				\
		tfw_training_mode_adjust##_##name;			\
	bool (*defence)(u64) =						\
		tfw_training_mode_defence##_##name;			\
	void (*adjust_client)(void) =					\
		tfw_training_mode_adjust_new_client##_##name;		\
									\
	return tfw_training_mode_update(stat, adjust, defence,		\
					adjust_client, delta,		\
					training_epoch);		\
}

TFW_TRAINING_MODE_UPDATE_STAT(req_num);
TFW_TRAINING_MODE_UPDATE_STAT(cpu_num);

#undef TFW_TRAINING_MODE_UPDATE_STAT

static inline void
tfw_training_mode_prepare_for_defence(void)
{
	/*
	 * Wait until all threads finish using of global pointers.
	 * After this call we are sure that no one access any g_*_num
	 * structures, so we can safely calculated mean and std.
	 */
	tfw_disable_training_or_defence();
	__calculate_mean_and_std(g_conn_num);
	__calculate_mean_and_std(g_req_num);
	__calculate_mean_and_std(g_cpu_num);
	WRITE_ONCE(tfw_training_mod_state, TFW_MODE_IS_DEFENCE);
}

/*
 * Workqueue handler to safely switch modes (sleepable context).
 */
static void
training_work_fn(struct work_struct *work)
{
	tfw_training_mode_prepare_for_defence();
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
	if (del_timer_sync(&training_timer))
		tfw_training_mode_prepare_for_defence();
}

static inline int
tfw_training_start(void)
{
	unsigned long training_perid_in_jiffies =
		msecs_to_jiffies(1000 * tfw_training_mod_period);
	int r;

	r = __init_z_score();
	if (unlikely(r))
		return r;

	WRITE_ONCE(tfw_training_mod_state, TFW_MODE_IS_TRAINING);
	mod_timer(&training_timer, jiffies + training_perid_in_jiffies);

	return 0;
}

int
tfw_ctlfn_training_mode_state_change(unsigned int training_mode)
{
	if (training_mode)
		return tfw_training_start();

	tfw_training_stop();
	return 0;
}

static int
tfw_training_mode_start(void)
{
	int r;

	if (tfw_runstate_is_reconfig())
		return 0;

	r = __alloc_all_stats(&g_conn_num, &g_req_num, &g_cpu_num);
	if (unlikely(r))
		return r;

	INIT_WORK(&training_work, training_work_fn);
	timer_setup(&training_timer, tfw_training_timer_cb, 0);
	return 0;
}

static void
tfw_training_mode_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;

	timer_shutdown_sync(&training_timer);
	flush_work(&training_work);
	__upgrade_all_stats(NULL, NULL, NULL);
}

static TfwCfgSpec tfw_training_mode_specs[] = {
	{
		.name = "training_period",
		.deflt = "75",
		.handler = tfw_cfg_set_int,
		.allow_reconfig = true,
		.dest = &tfw_training_mod_period,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		},
	},
	{
		.name = "training_z_score_mem",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.allow_reconfig = true,
		.dest = &tfw_training_mod_z_score_mem_num,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "training_z_score_cpu",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.allow_reconfig = true,
		.dest = &tfw_training_mod_z_score_cpu_num,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "training_z_score_connection_num",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.allow_reconfig = true,
		.dest = &tfw_training_mod_z_score_conn_num,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "training_z_score_request_num",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.allow_reconfig = true,
		.dest = &tfw_training_mod_z_score_req_num,
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
tfw_training_mode_init(void)
{
	tfw_mod_register(&tfw_training_mod);

	return 0;
}

void
tfw_training_mode_exit(void)
{
	tfw_mod_unregister(&tfw_training_mod);
}
