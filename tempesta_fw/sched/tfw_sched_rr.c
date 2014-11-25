/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#include <linux/kernel.h>
#include <linux/module.h>

#include "debugfs.h"
#include "log.h"
#include "sched.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta round-robin scheduler");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");

#define RR_BANNER "tfw_sched_rr: "
#define RR_ERR(...) TFW_ERR(RR_BANNER __VA_ARGS__)
#define RR_LOG(...) TFW_LOG(RR_BANNER __VA_ARGS__)

/**
 * The memory for servers list is allocated statically, so this is a maximum
 * number of servers that may be added for scheduling in this module.
 */
#define RR_MAX_SERVERS_N TFW_SCHED_MAX_SERVERS

/**
 * The structure represents a list of servers read in a round-robin fashion.
 *
 * The @counter is incremented on each get() call and the "current" server is
 * obtained as servers[counter % servers_n].
 * This approach is chosen (instead of storing an index of the current server)
 * for optimization purposes: it allows sequential reading from the array
 * without synchronization between readers.
 */
typedef struct {
	unsigned int servers_n;
	unsigned int counter;
	TfwServer *servers[RR_MAX_SERVERS_N];
} RrSrvList;

/**
 * There is a total of NR_CPUS identical copies of the RrSrvList.
 * Each CPU has its own copy stored in its local memory.
 * The effects are following:
 *  1. get() operates faster on because:
 *    - Counter is not shared among CPUs, so the cache line bouncing is reduced.
 *    - Access to the local memory is faster on NUMA systems.
 *  2. add()/del() work slower because they need to update all copies.
 *  3. Each CPU has its own "current" server independent from other CPUs.
 */
static DEFINE_PER_CPU(RrSrvList, rr_srv_list) = {
	.servers_n = 0,
	.counter = 0,
	.servers = { NULL }
};

/**
 * The lock is needed only to synchronize writers (add() and del() methods).
 * The get() doesn't require it.
 */
static DEFINE_SPINLOCK(rr_write_lock);


/**
 * On each subsequent call the function returns the next element from the
 * list of servers added to the scheduler.
 *
 * This function is called for each incoming HTTP request, so it is relatively
 * performance critical. Therefore, a bunch of optimizations is used to reduce
 * the overhead and that imposes certain effects:
 *
 *  - Each CPU has its own "current" server, so the sequence of servers is
 *    broken when you switch to another CPU. On average, messages are still
 *    distributed equally across the servers, but you can't rely on the order.
 *
 *  - The function intended for use from a softirq context, it uses per-CPU
 *    variables and busy-waiting without disabling the preemption or perform
 *    any locking (although it is safe to call it with preemption enabled - you
 *    get a wasted CPU time slice in a worst case).
 *
 *  - The function assumes that add() doesn't add NULL elements to the list
 *    and del() sets deleted elements to NULL. If this invariant is violated,
 *    it may lock up the system or return a pointer to deleted server.
 */
static TfwServer *
tfw_sched_rr_get_srv(TfwMsg *msg)
{
	unsigned int n;
	TfwServer *srv;
	RrSrvList *lst = &__get_cpu_var(rr_srv_list);

	do {
		n = lst->servers_n;
		n |= !n; /* Return the first element if n=0 (has to be NULL). */
		srv = lst->servers[lst->counter++ % n];
	} while (unlikely(n > 1 && !srv));

	return srv;
}

static int
get_servers_n(void)
{
	return __get_cpu_var(rr_srv_list).servers_n;
}

static int
find_server_idx(TfwServer *srv)
{
	int i;
	RrSrvList *lst = &__get_cpu_var(rr_srv_list);
	for (i = 0; i < lst->servers_n; ++i) {
		if (lst->servers[i] == srv)
			return i;
	}

	return -1;
}

/**
 * Add a server to the end of the round-robin list.
 *
 * Returns:
 *  Zero if the server is added.
 *  ENOMEM if there is no room for the server in the statically allocated array.
 *  EEXIST if the given pointer is already present in the list.
 */
static int
tfw_sched_rr_add_srv(TfwServer *srv)
{
	int ret = 0;
	int cpu;
	RrSrvList *lst;

	BUG_ON(!srv);

	spin_lock_bh(&rr_write_lock);
	if (get_servers_n() >= RR_MAX_SERVERS_N) {
		RR_ERR("Can't add a server to the scheduler - "
		       "the maximum number of servers (%d) is reached\n",
		       RR_MAX_SERVERS_N);
		ret = -ENOMEM;
	} else if (find_server_idx(srv) >= 0) {
		RR_ERR("Can't add the server to the scheduler - "
		       "it is already present in the servers list\n");
		ret = -EEXIST;
	} else {
		for_each_possible_cpu(cpu) {
			lst = &per_cpu(rr_srv_list, cpu);
			lst->servers[lst->servers_n] = srv;
			++lst->servers_n;
		}
	}
	spin_unlock_bh(&rr_write_lock);

	return ret;
}

/**
 * Delete a given server from the round-robin list.
 *
 * The function deletes an element by replacing it with the last element in the
 * array and then deleting this last element. This is fast, but it changes the
 * order of servers.
 *
 * Returns zero on success or ENOENT if the serve is not found in the list.
 */
static int
tfw_sched_rr_del_srv(TfwServer *srv)
{
	int ret = 0;
	int i, cpu;
	RrSrvList *lst;

	spin_lock_bh(&rr_write_lock);
	i = find_server_idx(srv);
	if (i < 0) {
		RR_ERR("Can't delete the server from the scheduler - "
			" it is not found in the servers list\n");
		ret = -ENOENT;
	} else {
		for_each_possible_cpu(cpu) {
			lst = &per_cpu(rr_srv_list, cpu);
			lst->servers[i] = lst->servers[lst->servers_n - 1];
			--lst->servers_n;
			lst->servers[lst->servers_n] = NULL;
		}
	}
	spin_unlock_bh(&rr_write_lock);

	return ret;
}

static int
tfw_sched_rr_debugfs_hook(bool input, char *buf, size_t size)
{
	int pos = 0;
	int cpu, i;
	RrSrvList *my, *this;

	/* Turn the current server on write(). */
	if (input) {
		tfw_sched_rr_get_srv(NULL);
		return 0;
	}

	spin_lock_bh(&rr_write_lock);

	/* Dump the servers list on read(). */
	my = &__get_cpu_var(rr_srv_list);
	pos += snprintf(buf + pos, size - pos, "servers: %d, counter: %d\n",
	               my->servers_n, my->counter);

	for (i = 0; i < my->servers_n; ++i) {
		char mark = (i == (my->counter % my->servers_n)) ? '>' : ' ';
		char srv_str[TFW_SRV_STR_MAX_SIZE];

		tfw_server_snprint(my->servers[i], srv_str, sizeof(srv_str));
		pos += snprintf(buf + pos, size - pos, "%c%s\n", mark, srv_str);
	}

	for_each_possible_cpu(cpu) {
		this = &per_cpu(rr_srv_list, cpu);
		BUG_ON(my->servers_n != this->servers_n);
		BUG_ON(memcmp(my->servers, this->servers, sizeof(my->servers)));
	}

	spin_unlock_bh(&rr_write_lock);

	return pos;
}

int
tfw_sched_rr_init(void)
{
	static TfwScheduler tfw_sched_rr_mod = {
		.name = "round-robin",
		.get_srv = tfw_sched_rr_get_srv,
		.add_srv = tfw_sched_rr_add_srv,
		.del_srv = tfw_sched_rr_del_srv
	};

	RR_LOG("init\n");

	tfw_debugfs_bind("/sched/rr/state", tfw_sched_rr_debugfs_hook);

	return tfw_sched_register(&tfw_sched_rr_mod);
}
module_init(tfw_sched_rr_init);

void
tfw_sched_rr_exit(void)
{
	tfw_sched_unregister();
}
module_exit(tfw_sched_rr_exit);

