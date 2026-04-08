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

static const unsigned int req_num_batch = 64;
static const unsigned int cpu_num_batch = 1024;

unsigned int tfw_training_mod_period = 0;
unsigned int tfw_training_mod_state = TFW_MODE_DISABLED;
int g_training_num = 0;

static u64 training_start_time;
static int tfw_training_mod_z_score_mem_num = 0;
static int tfw_training_mod_z_score_cpu_num = 0;
static int tfw_training_mod_z_score_conn_num = 0;
static int tfw_training_mod_z_score_req_num = 0;
static struct timer_list training_timer;
static struct work_struct training_work;

struct stats {
	struct percpu_counter num;
	struct percpu_counter sum;
	struct percpu_counter sumsq;
	s64 mean;
	s64 std;
};

static struct stats __rcu *g_conn_num = NULL;
static struct stats __rcu *g_req_num = NULL;
static struct stats __rcu *g_cpu_num = NULL;

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

static inline void
__free_stats(struct stats *s)
{
	percpu_counter_destroy(&s->num);
	percpu_counter_destroy(&s->sum);
	percpu_counter_destroy(&s->sumsq);
	kfree(s);
}

static inline void
tfw_disable_trainging_or_defence(void)
{
	/*
	 * Set TFW_MODE_DISABLED, now we stop calling new all defence
	 * and trainging functions.
	 */
	WRITE_ONCE(tfw_training_mod_state, TFW_MODE_DISABLED);
	/*
	 * Wait until all previous rcu calls finished, to be sure
	 * that we can safely change pointers.
	 */
	synchronize_rcu();
}

static inline void
__upgrade_all_stats(struct stats *new_conn_num,
		    struct stats *new_req_num,
		    struct stats *new_cpu_num)
{
	struct stats *old_conn_num, *old_req_num, *old_cpu_num;

	tfw_disable_trainging_or_defence();
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
	 * functions were finished, update all other variables they are not
	 * used in separate threads.
	 */
	g_training_num++;

	return 0;
}

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

static inline void
tfw_training_mode_adjust_new_el(struct stats *s, u64 delta1, u64 delta2,
				bool new_client)
{
	if (new_client)
		percpu_counter_add(&s->num, 1);
	percpu_counter_add(&s->sum, delta1);
	percpu_counter_add(&s->sumsq, delta2);
}

static bool
tfw_trainging_mode_adjust_new_start(atomic64_t *max, int *num,
				    spinlock_t *lock)
{
	/*
	 * We increment `g_training_num` each time when we start new
	 * training. When we are sure that all threads don't use
	 * `max`. During trainging all threads call this function
	 * before read `max`, so we are sure that `max` will be zeroed
	 * on the start of the new trainging.
	 */
	if (unlikely(*num < g_training_num)) {
		spin_lock(lock);
		atomic64_set(max, 0);
		*num = g_training_num;
		spin_unlock(lock);
		return true;
 	}

	return false;
}

#define TFW_TRAINING_MODE_ADJUST(name, retcode)						\
retcode										\
tfw_training_mode_adjust##_##name(u64 delta1, u64 delta2, bool new_client)	\
{										\
	struct stats *s;							\
										\
	rcu_read_lock();							\
										\
	BUG_ON(tfw_mode_is_disabled());						\
	s = rcu_dereference(g##_##name);					\
	tfw_training_mode_adjust_new_el(s, delta1, delta2, new_client);		\
										\
	rcu_read_unlock();							\
}

TFW_TRAINING_MODE_ADJUST(conn_num, void);
TFW_TRAINING_MODE_ADJUST(req_num, static void);
TFW_TRAINING_MODE_ADJUST(cpu_num, static void);

#define TFW_TRAINING_MODE_DEFENCE(name, retcode)		\
retcode								\
tfw_training_mode_defence##_##name(u64 val)			\
{								\
	struct stats *p;					\
	s64 z_score;						\
								\
	if (!tfw_mode_is_defence())				\
		return true;					\
								\
	rcu_read_lock();					\
								\
	p = rcu_dereference(g##_##name);			\
								\
	if (!__calculate_z_score(val, p, &z_score)) {		\
		rcu_read_unlock();				\
		return true;					\
	}							\
								\
	rcu_read_unlock();					\
								\
	if (z_score > tfw_training_mod_z_score##_##name)	\
		return false;					\
								\
	return true;						\
}

TFW_TRAINING_MODE_DEFENCE(conn_num, bool)
TFW_TRAINING_MODE_DEFENCE(req_num, static bool)
TFW_TRAINING_MODE_DEFENCE(cpu_num, static bool)

#undef TFW_TRAINING_MODE_DEFENCE

static inline void
tfw_training_mode_adjust(atomic64_t *max, u64 curr, bool new_client,
			 void (*adjust)(u64, u64, bool))
{
	u64 delta1, delta2, old_max;

	old_max = atomic64_read(max);

	/*
	 * Can be called concurrentrly on other cpu with different
	 * curr value, so we need syncronization here.
	 */
	do {
		if (curr <= old_max)
			return;
	} while (!atomic64_try_cmpxchg(max, &old_max, curr));

	delta1 = curr - old_max;
	delta2 = (u64)curr * curr - (u64)old_max * old_max;
	adjust(delta1, delta2, new_client);
}

static inline bool
tfw_training_mode_flush_inc(TfwTrainingStat *stat,
			    void (*adjust)(u64, u64, bool),
			    bool (*defence)(u64))
{
	u64 *inc = this_cpu_ptr(stat->inc);
	bool new_client = false;
	u64 delta = *inc;
	u64 curr;

	*inc = 0;
	curr = atomic64_add_return(delta, &stat->curr);

	if (tfw_mode_is_disabled())
		return true;

	if (tfw_mode_is_defence())
		return defence(curr);

	if (tfw_trainging_mode_adjust_new_start(&stat->max, &stat->num,
						&stat->lock))
		new_client = true;

	tfw_training_mode_adjust(&stat->max, curr, new_client, adjust);

	return true;
}

#define TFW_TRAINING_MODE_UPDATE_STAT(name)				\
bool									\
tfw_training_mode_update##_##name##_##stat(TfwTrainingStat *stat,	\
					   int delta) 			\
{									\
	bool r = true;							\
									\
	if (delta > 0) {						\
		s64 *inc = this_cpu_ptr(stat->inc);			\
		void (*adjust)(u64, u64, bool) =			\
			tfw_training_mode_adjust##_##name;		\
		bool (*defence)(u64) =					\
			tfw_training_mode_defence##_##name;		\
									\
		*inc += delta;						\
		if (unlikely(*inc >= name##_batch))			\
			r = tfw_training_mode_flush_inc(stat, adjust,	\
							defence);	\
	} else {							\
		atomic64_add(delta, &stat->curr);			\
	}								\
									\
	return r;							\
}

TFW_TRAINING_MODE_UPDATE_STAT(req_num);
TFW_TRAINING_MODE_UPDATE_STAT(cpu_num);

#undef TFW_TRAINING_MODE_UPDATE_STAT

static inline void
tfw_training_mode_prepare_for_defence(void)
{
	/*
	 * Wait until all threads finish using of global pointers.
	 */
	tfw_disable_trainging_or_defence();
	__calculate_mean_and_std(g_conn_num);
	__calculate_mean_and_std(g_req_num);
	__calculate_mean_and_std(g_cpu_num);
	WRITE_ONCE(tfw_training_mod_state, TFW_MODE_IS_DEFENCE);
}

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

static inline void
tfw_training_stop(void)
{
	if (del_timer_sync(&training_timer))
		tfw_training_mode_prepare_for_defence();
}

static inline int
tfw_training_start(void)
{
	unsigned long trainging_perid_in_jiffies =
		msecs_to_jiffies(1000 * tfw_training_mod_period);
	int r;

	r = __init_z_score();
	if (unlikely(r))
		return r;

	training_start_time = get_jiffies_64();
	WRITE_ONCE(tfw_training_mod_state, TFW_MODE_IS_TRAINING);
	mod_timer(&training_timer, jiffies + trainging_perid_in_jiffies);

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
		.dest = &tfw_training_mod_period,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		},
	},
	{
		.name = "training_z_score_mem",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &tfw_training_mod_z_score_mem_num,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "training_z_score_cpu",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &tfw_training_mod_z_score_cpu_num,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "training_z_score_connection_num",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &tfw_training_mod_z_score_conn_num,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "training_z_score_request_num",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
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
