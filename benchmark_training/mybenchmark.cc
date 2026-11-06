#include <benchmark/benchmark.h>
#include <random>
#include <cstring>
#include <cstdlib>

#include "common.h"

using namespace std;

static struct client clients[TFW_CLIENT_CNT];
static struct sum_sumsq_state s11;
static struct welford_state s21;

static void
BM_welford_fixed_point(benchmark::State& state)
{
	unsigned int idx = 0;
	unsigned long new_max;

	memset(&s21, 0, sizeof(s21));
	memset(clients, 0, sizeof(clients));
	/*
	 * Initialize all clients with value 1.
	 */
	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		adjust_welford_fp(&clients[i], &s21, 1);

	for (auto _ : state) {
		idx++;
		idx %= TFW_CLIENT_CNT;
		new_max = clients[idx].max + 1;
		adjust_welford_fp(&clients[idx], &s21, new_max);
		benchmark::DoNotOptimize(s21.mean_fp);
		benchmark::DoNotOptimize(s21.M2_fp);
	}
}
BENCHMARK(BM_welford_fixed_point);


static void BM_sum_sumsq(benchmark::State& state) {
	unsigned int idx = 0;
	unsigned long new_max;

	memset(&s11, 0, sizeof(s11));
	memset(clients, 0, sizeof(clients));
	/*
	 * Initialize all clients with value 1.
	 */
	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		adjust_sum_sumsq(&clients[i], &s11, 1);

	for (auto _ : state) {
		idx++;
		idx %= TFW_CLIENT_CNT;
		new_max = clients[idx].max + 1;
		adjust_sum_sumsq(&clients[idx], &s11, new_max);
		benchmark::DoNotOptimize(s11.sum);
		benchmark::DoNotOptimize(s11.sumsq);
	}
}
BENCHMARK(BM_sum_sumsq);

BENCHMARK_MAIN();
