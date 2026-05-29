#include <benchmark/benchmark.h>
#include <random>
#include <cstring>
#include <cstdlib>

#include "common.h"

using namespace std;

static struct client clients[TFW_CLIENT_CNT];
static struct sum_sumsq_state s1;
static struct welford_state s2;

static void
BM_welford_fixed_point(benchmark::State& state)
{
	unsigned int idx = 0;
	unsigned long new_max;

	memset(&s2, 0, sizeof(s2));
	memset(clients, 0, sizeof(clients));
	/*
	 * Initialize all clients with value 1.
	 */
	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		adjust_welford_fp(&clients[i], &s2, 1);

	for (auto _ : state) {
		idx++;
		idx %= TFW_CLIENT_CNT;
		new_max = clients[idx].max + 1;
		adjust_welford_fp(&clients[idx], &s2, new_max);
		benchmark::DoNotOptimize(s2.mean_fp);
		benchmark::DoNotOptimize(s2.M2_fp);
	}
}
BENCHMARK(BM_welford_fixed_point);

static void BM_sum_sumsq(benchmark::State& state) {
	unsigned int idx = 0;
	unsigned long new_max;

	memset(&s1, 0, sizeof(s1));
	memset(clients, 0, sizeof(clients));
	/*
	 * Initialize all clients with value 1.
	 */
	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		adjust_sum_sumsq(&clients[i], &s1, 1);

	for (auto _ : state) {
		idx++;
		idx %= TFW_CLIENT_CNT;
		new_max = clients[idx].max + 1;
		adjust_sum_sumsq(&clients[idx], &s1, new_max);
		benchmark::DoNotOptimize(s1.sum);
		benchmark::DoNotOptimize(s1.sumsq);
	}
}
BENCHMARK(BM_sum_sumsq);


BENCHMARK_MAIN();