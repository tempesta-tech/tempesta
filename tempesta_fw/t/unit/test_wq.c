/**
 *		Tempesta FW
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
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
#include <asm/fpu/api.h>
#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/slab.h>

#include "test.h"
#include "work_queue.h"

#define QSZ	2048		/* From work_queue.c */
#define N	QSZ * 10
#define JOB_N	10		/* Jobs per core. */

static const int X_EMPTY = 0;		/* The address skipped by producers. */
static const int X_MISSED = 255;	/* The address skipped by consumers. */
static const int X_DONE = 100;		/* The address is processed. */

static TfwRBQueue *wq;

typedef struct {
	struct task_struct	*task;
	int			ptr[N];
} TfwTestProducer;

typedef struct {
	size_t			prods_n;
	TfwTestProducer		prods[0];
} TfwTestProducers;

typedef struct {
	struct task_struct	*task;
} TfwTestConsumer;

typedef struct {
	size_t			cons_n;
	TfwTestConsumer		cons[0];
} TfwTestConsumers;

typedef struct {
	int			*work;
	unsigned long		_[3];
} TfwTestWork;

static atomic_t active_prods;
static atomic_t active_cons;

static void
tfw_test_wq_suite_setup(void)
{
	int r;

	wq = kzalloc(sizeof(TfwRBQueue), GFP_KERNEL);
	BUG_ON(!wq);
	r = tfw_wq_init(wq, cpu_to_node(smp_processor_id()));
	BUG_ON(r);
}

static void
tfw_test_wq_suite_teardown(void)
{
	tfw_wq_destroy(wq);
	kfree(wq);
}

static int
tfw_test_wq_work_prod(void *data)
{
	TfwTestProducer *prod_data = (TfwTestProducer *)data;
	size_t work = 0;

	TFW_WQ_CHECKSZ(TfwTestWork);

	while (work < N){
		TfwTestWork wq_item = { &prod_data->ptr[work] };

		prod_data->ptr[work] = X_MISSED;
		while (__tfw_wq_push(wq, &wq_item))
			schedule();
		++work;

		schedule();
	}
	atomic_dec(&active_prods);

	return 0;
}

static int
tfw_test_wq_work_cons(void *data)
{
	while (atomic_read(&active_prods) || tfw_wq_size(wq)) {
		TfwTestWork wq_item;

		schedule();
		if (tfw_wq_pop(wq, &wq_item))
			continue;

		EXPECT_EQ(*wq_item.work, X_MISSED);
		*wq_item.work = X_DONE;
	}
	atomic_dec(&active_cons);

	return 0;
}

struct task_struct *
tfw_thread_create(int (*threadfn)(void *data), void *data,
			  unsigned int cpu, const char *namefmt)
{
	struct task_struct *p;

	p = kthread_create_on_node(threadfn, data, cpu_to_node(cpu), namefmt,
				   cpu);
	if (IS_ERR(p))
		return p;
	kthread_bind(p, cpu);
	return p;
}

static void
tfw_test_cleanup_prods(TfwTestProducers *prods)
{
	size_t i = 0;

	for ( ; i < prods->prods_n; ++i) {
		TfwTestProducer *prod = &prods->prods[i];
		if (prod->task)
			kthread_stop(prod->task);
	}
	atomic_set(&active_prods, 0);
	kfree(prods);
}

static TfwTestProducers*
tfw_test_spawn_prods(size_t n)
{
	TfwTestProducers *prods;
	size_t size, i;
	int cpu = -1;

	size = sizeof(TfwTestProducers) + n * sizeof(TfwTestProducer);
	if (!(prods = kzalloc(size, GFP_KERNEL)))
		return NULL;
	prods->prods_n = n;

	/* Spawn produces across all available cpus. */
	for (i = 0; i < n; ++i) {
		TfwTestProducer *prod = &prods->prods[i];

		do {
			cpu = cpumask_next(cpu, cpu_online_mask);
			if (cpu >= nr_cpu_ids)
				cpu = -1;
		} while (cpu == -1);

		prod->task = tfw_thread_create(tfw_test_wq_work_prod,
					       prod, cpu, "TfwTestWqProd");
		if (IS_ERR_OR_NULL(prod->task))
			goto err;
	}
	atomic_add(n, &active_prods);

	return prods;
err:
	tfw_test_cleanup_prods(prods);
	return NULL;
}

static void
tfw_test_cleanup_cons(TfwTestConsumers *cons)
{
	size_t i = 0;

	for ( ; i < cons->cons_n; ++i) {
		TfwTestConsumer *con = &cons->cons[i];
		if (con->task)
			kthread_stop(con->task);
	}
	atomic_set(&active_cons, 0);
	kfree(cons);
}

static TfwTestConsumers*
tfw_test_spawn_cons(size_t n)
{
	size_t cpu_n = num_online_cpus();
	TfwTestConsumers *cons;
	int cpu = -1;
	size_t size, i;

	size = sizeof(TfwTestConsumers) + n * sizeof(TfwTestConsumer);
	if (!(cons = kcalloc(cpu_n, size, GFP_KERNEL)))
		return NULL;
	cons->cons_n = n;

	/* Spawn consumers across all available cpus. */
	for (i = 0; i < n; ++i) {
		TfwTestConsumer *con = &cons->cons[i];

		do {
			cpu = cpumask_next(cpu, cpu_online_mask);
			if (cpu >= nr_cpu_ids)
				cpu = -1;
		} while (cpu == -1);

		con->task = tfw_thread_create(tfw_test_wq_work_cons,
					       con, cpu, "TfwTestWqCons");
		if (IS_ERR_OR_NULL(con->task))
			goto err;
	}
	atomic_add(n, &active_cons);

	return cons;
err:
	tfw_test_cleanup_cons(cons);
	return NULL;
}

static void
tfw_test_assert_prods(TfwTestProducers *prods)
{
	size_t i = 0, j = 0;

	for ( ; i < prods->prods_n; ++i)
		for ( ; j < N; ++j)
			EXPECT_EQ(prods->prods[i].ptr[j], X_DONE);
}

static void
tfw_test_wq_run(TfwTestProducers *prods, TfwTestConsumers *cons)
{
	size_t i;

	for (i = 0; i < prods->prods_n; ++i)
		wake_up_process(prods->prods[i].task);
	/* Wait until queue is full. */
	while (tfw_wq_size(wq) < QSZ)
		schedule();
	for (i = 0; i < cons->cons_n; ++i)
		wake_up_process(cons->cons[i].task);
	while(atomic_read(&active_cons))
		schedule();

	tfw_test_assert_prods(prods);
}

static void
tfw_test_wq_test(size_t prod_n, size_t con_n)
{
	TfwTestProducers *prods;
	TfwTestConsumers *cons;

	if (!(prods = tfw_test_spawn_prods(prod_n))) {
		TEST_FAIL("Cannot initialize producers threads\n");
		return;
	}
	if (!(cons = tfw_test_spawn_cons(con_n))) {
		TEST_FAIL("Cannot initialize consumers threads\n");
		tfw_test_cleanup_prods(prods);
		return;
	}

	tfw_test_wq_run(prods, cons);

	kfree(cons);
	kfree(prods);
}

TEST(wq, one_prod_one_con)
{
	tfw_test_wq_test(1, 1);
}

TEST(wq, many_prod_one_con)
{
	tfw_test_wq_test(JOB_N * num_online_cpus(), 1);
}

TEST_SUITE(wq)
{
	TEST_SETUP(tfw_test_wq_suite_setup);
	TEST_TEARDOWN(tfw_test_wq_suite_teardown);

	/* The queue is MPSC queue, multiple consumers are not allowed. */
	TEST_RUN(wq, one_prod_one_con);
	TEST_RUN(wq, many_prod_one_con);
}
