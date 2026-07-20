#include <random>
#include <cstring>
#include <cstdlib>
#include <iostream>

#include "common.h"

using namespace std;

static struct client s1_clients[TFW_CLIENT_CNT];
static struct client s2_clients[TFW_CLIENT_CNT];
static struct client w1_clients[TFW_CLIENT_CNT];
static struct client w2_clients[TFW_CLIENT_CNT];

static struct sum_sumsq_state s11;
static struct sum_sumsq_state_64 s12;
static struct welford_state s21;
static struct welford_state_64 s22;

static void
__check_accuracy(unsigned int (*valgen)(void), const char *preambula)
{
	unsigned int idx = 0;
	unsigned long long int new_max, old_max = 1;

	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++) {
		adjust_sum_sumsq(&s1_clients[i], &s11, 1);
		adjust_sum_sumsq_64(&s2_clients[i], &s12, 1);
		adjust_welford_fp(&w1_clients[i], &s21, 1);
		adjust_welford_fp_64(&w2_clients[i], &s22, 1);
	}

	for (unsigned int i = 0; i < TFW_CLIENT_CNT * 100; i++) {
		idx++;
		idx %= TFW_CLIENT_CNT;
		new_max = old_max + valgen();

		adjust_sum_sumsq(&s1_clients[idx], &s11, new_max);
		adjust_sum_sumsq_64(&s2_clients[idx], &s12, new_max);
		adjust_welford_fp(&w1_clients[idx], &s21, new_max);
		adjust_welford_fp_64(&w2_clients[idx], &s22, new_max);

		old_max = new_max;
	}

	cout << preambula << endl;
	cout << "accuracy (exact, sum_sumsq 128,  sum_sumsq 64): " << "( " << compute_exact_variance(s1_clients) << ", "
		<< variance_sum_sumsq(&s11) << ", " << variance_sum_sumsq_64(&s12) << " )" << endl;
	cout << "accuracy (exact, welford 128, welford 64): " << "( " << compute_exact_variance(w1_clients) << ", "
		<< variance_welford(&s21) << ", " << variance_welford_64(&s22) << " )" << endl;
}

static unsigned int
valgen_1(void)
{
	return 1;
}

static unsigned int
valgen_rnd(unsigned int min, unsigned int max)
{
	random_device rd;
	mt19937 gen(rd());
	uniform_int_distribution<int> distrib(min, max);

	return  distrib(gen);
}

static unsigned int
valgen_rnd_1_10(void)
{
	return valgen_rnd(1, 10);
}

static unsigned int
valgen_rnd_1_100(void)
{
	return valgen_rnd(1, 100);
}

static unsigned int
valgen_rnd_1_1000(void)
{
	return valgen_rnd(1, 1000);
}

int main()
{
	__check_accuracy(valgen_1, "+1");
	__check_accuracy(valgen_rnd_1_10, "random 1 - 10");
	__check_accuracy(valgen_rnd_1_100, "random 1 - 100");
	__check_accuracy(valgen_rnd_1_1000, "random 1 - 1000");

	return 0;
}
