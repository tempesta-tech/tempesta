#include <benchmark/benchmark.h>
#include <random>
#include <cstring>
#include <cstdlib>

#include "common.h"

using namespace std;

static struct client clients[TFW_CLIENT_CNT];
static struct sum_sumsq_state_native s11;
static struct sum_sumsq_state_lib s12;
static struct welford_state_native s21;
static struct welford_state_lib s22;

static void
BM_welford_fixed_point_native(benchmark::State& state)
{
	unsigned int idx = 0;
	unsigned long new_max;

	memset(&s21, 0, sizeof(s21));
	memset(clients, 0, sizeof(clients));
	/*
	 * Initialize all clients with value 1.
	 */
	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		adjust_welford_fp_native(&clients[i], &s21, 1);

	for (auto _ : state) {
		idx++;
		idx %= TFW_CLIENT_CNT;
		new_max = clients[idx].max + 1;
		adjust_welford_fp_native(&clients[idx], &s21, new_max);
		benchmark::DoNotOptimize(s21.mean_fp);
		benchmark::DoNotOptimize(s21.M2_fp);
	}
}
BENCHMARK(BM_welford_fixed_point_native);

static void
BM_welford_fixed_point_lib(benchmark::State& state)
{
	unsigned int idx = 0;
	unsigned long new_max;

	memset(&s22, 0, sizeof(s22));
	memset(clients, 0, sizeof(clients));
	/*
	 * Initialize all clients with value 1.
	 */
	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		adjust_welford_fp_lib(&clients[i], &s22, 1);

	for (auto _ : state) {
		idx++;
		idx %= TFW_CLIENT_CNT;
		new_max = clients[idx].max + 1;
		adjust_welford_fp_lib(&clients[idx], &s22, new_max);
		benchmark::DoNotOptimize(s22.mean_fp);
		benchmark::DoNotOptimize(s22.M2_fp);
	}
}
BENCHMARK(BM_welford_fixed_point_lib);

static void BM_sum_sumsq_native(benchmark::State& state) {
	unsigned int idx = 0;
	unsigned long new_max;

	memset(&s11, 0, sizeof(s11));
	memset(clients, 0, sizeof(clients));
	/*
	 * Initialize all clients with value 1.
	 */
	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		adjust_sum_sumsq_native(&clients[i], &s11, 1);

	for (auto _ : state) {
		idx++;
		idx %= TFW_CLIENT_CNT;
		new_max = clients[idx].max + 1;
		adjust_sum_sumsq_native(&clients[idx], &s11, new_max);
		benchmark::DoNotOptimize(s11.sum);
		benchmark::DoNotOptimize(s11.sumsq);
	}
}
BENCHMARK(BM_sum_sumsq_native);

static void BM_sum_sumsq_lib(benchmark::State& state) {
	unsigned int idx = 0;
	unsigned long new_max;

	memset(&s12, 0, sizeof(s12));
	memset(clients, 0, sizeof(clients));
	/*
	 * Initialize all clients with value 1.
	 */
	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		adjust_sum_sumsq_lib(&clients[i], &s12, 1);

	for (auto _ : state) {
		idx++;
		idx %= TFW_CLIENT_CNT;
		new_max = clients[idx].max + 1;
		adjust_sum_sumsq_lib(&clients[idx], &s12, new_max);
		benchmark::DoNotOptimize(s12.sum);
		benchmark::DoNotOptimize(s12.sumsq);
	}
}
BENCHMARK(BM_sum_sumsq_lib);

BENCHMARK_MAIN();
