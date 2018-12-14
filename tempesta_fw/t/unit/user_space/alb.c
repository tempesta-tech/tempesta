/**
 *		Tempesta FW
 *
 * Algorithm for ratio scheduler with as uniform as possible requests
 * distribution.
 *
 * Copyright (C) 2017-2018 Tempesta Technologies, Inc.
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
#include <stdio.h>
#include <string.h>

#include <linux/kernel.h>
#include <linux/spinlock.h>

/**
 * The server descriptor used for the ration round-robin scheduler.
 * Must be cache line aligned to avoid false sharing.
 *
 * @ratio	- original server ratio;
 * @curr_ration	- current (temporal) ratio value adjusted by the algorithm.
 * @__padding	- required for cache line alignment.
 */
typedef struct {
	unsigned int	ratio;
	unsigned int	curr_ratio;
	unsigned int	__padding[14];
} RatioSrv ____cacheline_aligned_in_smp;

/**
 * The scheduler iteration data.
 *
 * @lock	- must be in the same cache line for faster operations.
 * @srv_n	- number of available servers.
 * @curr	- pointer to current server.
 * @ri		- ratio iteration, determines how many times we have to choose
 * 		  all servers before current until we can choose current server.
 * @rsum	- sum of all ratios, used to avoid scanning fully zeroed array
 * 		  of servers.
 * @rsum_orig	- original value of @rsum.
 * @rearm	- next server id which ratio we need to rearm or @srv_n if no
 *		  rearming is needed.
 */
typedef struct {
	spinlock_t	lock;
	unsigned int	srv_n;
	unsigned int	curr;
	unsigned int	ri;
	unsigned int	rsum;
	unsigned int	rsum_orig;
	unsigned int	rearm;
} RatioSched;

#define MAX_SRV		16 /* Maximum number of servers for this test. */
static unsigned int srv_cnt[MAX_SRV];
static RatioSrv srvs[MAX_SRV] ____cacheline_aligned_in_smp;
static RatioSched rs ____cacheline_aligned_in_smp;

/*
 * Ratios array must be sorted in reverse order. It's trivial to do for static
 * ratios. Unfortunately we still need to sort ratios array for dynamic
 * scheduling. Use heap sort from linux/lib/sort.c.
 */
/* Small numbers easy test. Zero weight isn't allowed. */
static const unsigned int ratios0[] = { 1 };
static const unsigned int ratios1[] = { 2, 1, 1 };
static const unsigned int ratios2[] = { 3, 1, 1 };
/* Small repeated numbers with a medium-size number - just good to test. */
static const unsigned int ratios3[] = { 38, 9, 5, 4, 3, 3, 1 };
static const unsigned int ratios4[] = { 100, 80, 60, 50, 45, 30 };
static const unsigned int ratios5[] = { 760, 190, 110, 90, 70, 60, 20 };
static const unsigned int ratios6[] = { 105, 104, 103, 102, 101, 100, 1 };
/*
 * The very bad case for slots-based algorithms: 1/1000 proportions requires
 * thousands of slots, bit more than 2 thousands in this case.
 */
static const unsigned int ratios7[] = { 1010, 1000, 20, 3, 2, 1, 1, 1 };
/*
 * All the big numbers have common devisor, so the case can be represented
 * in very small number of slots. The two cases at the below behave differently.
 * See comment for is_srv_turn().
 */
static const unsigned int ratios8[] = { 5, 4, 3, 2, 1 };
static const unsigned int ratios9[] = { 5000, 4000, 3000, 2000, 1000 };
/* Fair static weights, plain round-robin must be here. */
static const unsigned int ratios10[] = { 1, 1, 1, 1 };
static const unsigned int ratios11[] = { 4, 4, 4 };
/* Semi-fair weights. */
static const unsigned int ratios12[] = { 10, 10, 10, 1, 1 };

/**
 * Initialize the scheduler data structures by the servers ratios.
 */
static void
init_sched(const unsigned int *ratios, unsigned int n)
{
	unsigned int i;

	BUG_ON(n > MAX_SRV);

	memset(srvs, 0, sizeof(srvs));
	memset(&rs, 0, sizeof(rs));

	for (i = 0; i < n; ++i) {
		srvs[i].ratio = srvs[i].curr_ratio = ratios[i];
		rs.rsum += ratios[i];
	}
	spin_lock_init(&rs.lock);
	rs.srv_n = n;
	rs.ri = 1;
	rs.rsum_orig = rs.rsum;
	rs.rearm = n;
}

/**
 * The algorithm decides that now is turn for i'th server, if sums of the left
 * and of the right series are proportional to current iteration.
 * As the scheduler algorithm moves forward sum of the left series decreases.
 * Since each server selection just decrements current server ration, the
 * sum of the series contains the server also decrements, i.e. decreases for
 * 1.
 *
 * Thus, a user must not specify weights like {1000, 100} since decrement
 * doesn't affect the sum of series. Instead, they must specify the weights
 * as {10, 1}. Both the cases will distribute requests proportional to the
 * specified wights on large numbers, but significant bursts are possible in
 * the first case.
 *
 * Dynamic weights must be adjusted by division for minimal weight. The same
 * can be done for static weights. Or at least document the algorithm
 * peculiarity for a user.
 *
 * TODO I think the algorithm can be and should be improved.
 */
static inline bool
is_srv_turn(unsigned int i)
{
	unsigned int head_sum2, tail_sum2;

	/* The server w/ the largest ratio is always chosen. */
	if (!i)
		return true;

	head_sum2 = (srvs[0].curr_ratio + srvs[i - 1].curr_ratio) * i;
	tail_sum2 = (srvs[i].curr_ratio
		     + (srvs[rs.srv_n - 1].curr_ratio
			? : srvs[rs.srv_n - 1].ratio))
		    * (rs.srv_n - i);
	return tail_sum2 * rs.ri > head_sum2;
}

/**
 * The scheduler algorithm.
 * The function is synchronized by plain spin lock. Lock-free implementation
 * of the algorithm as it is would require to many atomic operations including
 * CMPXCHG and checking loops, so it seems we won't win anything.
 *
 * @return the next server's ID.
 */
static unsigned int
sched(void)
{
	unsigned int s;

	/* Start for the server the with highest ratio. */
	spin_lock(&rs.lock);
retry:
	s = rs.curr;

	if (!srvs[s].curr_ratio) {
		/* Rearm current server ratio if needed. */
		if (rs.rearm != s) {
			/*
			 * Do not choose the server if we fully exhausted its
			 * counter. Likely branch for ratios { N, 1, 1, ... },
			 * where N > 1, at some point. This is not the case if
			 * all server weights were specified as 1: in this case
			 * we're fall to plain round-robin.
			 */
			++rs.curr;
			if (rs.curr == rs.srv_n) {
				rs.curr = 0;
				rs.ri = 1;
			}
			goto retry;
		}
		srvs[s].curr_ratio = srvs[s].ratio;
		++rs.rearm;
		/* Fall down to check the server ratio. */
	}

	if (likely(is_srv_turn(s))) {
		--srvs[s].curr_ratio;
		if (unlikely(!--rs.rsum)) {
			/*
			 * All server ratios are zero now.
			 * Start from the begin with the ratios rearming.
			 */
			rs.curr = 0;
			rs.ri = 1;
			rs.rsum = rs.rsum_orig;
			rs.rearm = 0;
		}
		else if (unlikely(++rs.curr == rs.srv_n)) {
			/*
			 * Reached the last server and all server ratios are
			 * rearmed if rearming took place.
			 * Start a new iteration.
			 */
			BUG_ON(rs.rearm != rs.srv_n);
			rs.curr = 0;
			rs.ri = 1;
		}
		spin_unlock(&rs.lock);
		return s;
	}
	/*
	 * It isn't turn of the current server.
	 * Start a new iteration from the server with the largest ratio.
	 */
	rs.curr = 0;
	++rs.ri;
	goto retry;
}

//#define TRACE
static void
trace(unsigned int s, unsigned int n __attribute__((unused)))
{
#ifdef TRACE
	int i;

	printf("srv=%u, rs: srv_n=%u curr=%u ri=%u rsum=%u/%u rearm=%u\n",
	       s, rs.srv_n, rs.curr, rs.ri, rs.rsum, rs.rsum_orig, rs.rearm);
	printf("servers: ");
	for (i = 0; i < n; ++i)
		printf("%u/%u ", srvs[i].ratio, srvs[i].curr_ratio);
	printf("\n");
#else
	printf("%u ", s);
#endif
	fflush(stdout);
}

/* How many requests should be scheduled by the server. */
#define TEST_REQ_N	100

#define TEST(ratio)							\
do {									\
	int i, n = ARRAY_SIZE(ratio);					\
	memset(srv_cnt, 0, sizeof(srv_cnt));				\
	init_sched(ratio, n);						\
	for (i = 0; i < TEST_REQ_N; ++i) {				\
		unsigned int s = sched();				\
		srv_cnt[s]++;						\
		trace(s, n);						\
	}								\
	printf("\n");							\
	for (i = 0; i < MAX_SRV; ++i) {					\
		if (i < n)						\
			printf("srv[%d] (ratio = %d):\t%d\n",		\
			       i, ratio[i], srv_cnt[i]);		\
		else							\
			BUG_ON(srv_cnt[i]);				\
	}								\
	printf("\n");							\
	fflush(stdout);							\
} while (0)

int
main(int argc, char *argv[])
{
	printf("Test for scheduling %u requests\n", TEST_REQ_N);

	TEST(ratios0);
	TEST(ratios1);
	TEST(ratios2);
	TEST(ratios3);
	TEST(ratios4);
	TEST(ratios5);
	TEST(ratios6);
	TEST(ratios7);
	TEST(ratios8);
	TEST(ratios9);
	TEST(ratios10);
	TEST(ratios11);
	TEST(ratios12);

	return 0;
}
