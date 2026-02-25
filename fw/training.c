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

unsigned int tfw_training_mod_period = 0;
unsigned int tfw_training_mod_state = TFW_MODE_DISABLED;
unsigned int g_training_num = 0;

static int tfw_training_mod_z_score_mem = 0;
static int tfw_training_mod_z_score_cpu = 0;
static int tfw_training_mod_z_score_conn_num = 0;
static struct timer_list training_timer;

static bool defence_ignore_conn_num;

struct stats {
	u32 num;
	u64 sum;
	u64 sumsq;
};

static struct stats __percpu __rcu *g_conn_num = NULL;

#define __FREE_G_PER_CPU(name, new)				\
do {								\
	struct stats __percpu *old;				\
								\
	old = rcu_replace_pointer(g##_##name, new, true);	\
	synchronize_rcu();					\
	free_percpu(old);					\
} while(0)

#define UPDATE_G_PER_CPU(name)					\
static inline int						\
__update_g_per_cpu##_##name(void)				\
{								\
	struct stats __percpu *new;				\
	int cpu;						\
								\
	new = tfw_alloc_percpu(struct stats);			\
	if (unlikely(!new))					\
		return -ENOMEM;					\
								\
	for_each_online_cpu(cpu) {				\
		bzero_fast(per_cpu_ptr(new, cpu),		\
			   sizeof(struct stats));		\
								\
	}							\
	__FREE_G_PER_CPU(name, new);				\
								\
	return 0;						\
}

UPDATE_G_PER_CPU(conn_num);

#undef UPDATE_G_PER_CPU

static inline int
__init_z_score(void)
{
	int r;
	unsigned int old_state = READ_ONCE(tfw_training_mod_state);

	/*
	 * Set TFW_MODE_DISABLED, now we stop calling new all defence
	 * and trainging functions.
	 */
	WRITE_ONCE(tfw_training_mod_state, TFW_MODE_DISABLED);
	r = __update_g_per_cpu_conn_num();
	if (unlikely(r)) {
		WRITE_ONCE(tfw_training_mod_state, old_state);
		return r;
	}

	/*
	 * After set TFW_MODE_DISABLED and calling `synchronize_rcu` from
	 * `__update_g_per_cpu_*` we are sure that all defence and training
	 * functions were finished, update all other variables they are not
	 * used in separate threads.
	 */
	g_training_num++;
	defence_ignore_conn_num = false;

	return 0;
}

static inline bool
__calculate_z_score(u64 val, struct stats __percpu *arr, s64 *z_score)
{
#define SCALE_SHIFT 16

	u64 mean, std, variance;
	u64 total_sum = 0;
	u64 total_sumsq = 0;
	u32 num_clients = 0;
	int cpu;

	if (unlikely(READ_ONCE(defence_ignore_conn_num)))
		return false;

	for_each_online_cpu(cpu) {
		struct stats *s = per_cpu_ptr(arr, cpu);
		
		num_clients += s->num;
		total_sum   += s->sum;
		total_sumsq += s->sumsq;
	}

	if (!num_clients) {
		WRITE_ONCE(defence_ignore_conn_num, true);
		return false;
	}
	mean = (total_sum << SCALE_SHIFT) / num_clients;
	variance = ((total_sumsq << SCALE_SHIFT) / num_clients) -
		((mean * mean) >> SCALE_SHIFT);
	std = int_sqrt64(variance << SCALE_SHIFT);
	if (!std) {
		WRITE_ONCE(defence_ignore_conn_num, true);
		return false;
	}
	*z_score = ((s64)(val << SCALE_SHIFT) - (s64)mean) / (s64)std;

	return true;

#undef SCALE_SHIFT
}

void
tfw_training_mode_adjust_new_conn(int cpu, u64 delta1, u64 delta2, bool new_client)
{
	struct stats __percpu *p;
	struct stats *s;

	rcu_read_lock();

	p = rcu_dereference(g_conn_num);
	s = per_cpu_ptr(p, cpu);
	s->num += new_client;
	s->sum += delta1;
	s->sumsq += delta2;

	rcu_read_unlock();
}

#define TFW_TRAINING_MODE_DEFENCE(name)				\
bool								\
tfw_training_mode_defence##_##name(u64 val)			\
{								\
	struct stats __percpu *p;				\
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
	if (z_score > tfw_training_mod_z_score_##name)		\
		return false;					\
								\
	return true;						\
}

TFW_TRAINING_MODE_DEFENCE(conn_num)

#undef TFW_TRAINING_MODE_DEFENCE

static void
tfw_training_timer_cb(struct timer_list *t)
{
	WRITE_ONCE(tfw_training_mod_state, TFW_MODE_IS_DEFENCE);
}

static inline void
tfw_training_stop(void)
{
	if (del_timer_sync(&training_timer))
		WRITE_ONCE(tfw_training_mod_state, TFW_MODE_IS_DEFENCE);
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
	int cpu;

	if (tfw_runstate_is_reconfig())
		return 0;

	g_conn_num = tfw_alloc_percpu(struct stats);
	if (unlikely(!g_conn_num))
		return -ENOMEM;

	for_each_online_cpu(cpu)
		bzero_fast(per_cpu_ptr(g_conn_num, cpu), sizeof(struct stats));
	timer_setup(&training_timer, tfw_training_timer_cb, 0);
	return 0;
}

static void
tfw_training_mode_stop(void)
{
	if (tfw_runstate_is_reconfig())
		return;

	timer_shutdown_sync(&training_timer);
	WRITE_ONCE(tfw_training_mod_state, TFW_MODE_DISABLED);
	__FREE_G_PER_CPU(conn_num, NULL);
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
		.dest = &tfw_training_mod_z_score_mem,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "training_z_score_cpu",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &tfw_training_mod_z_score_cpu,
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
