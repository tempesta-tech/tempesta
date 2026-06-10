#include <random>
#include <cstring>
#include <cstdlib>
#include <iostream>

#include "common.h"

using namespace std;

static struct client s_clients[TFW_CLIENT_CNT];
static struct client w_clients[TFW_CLIENT_CNT];

static struct sum_sumsq_state s1;
static struct welford_state s2;

static void
__check_accuracy(unsigned int (*valgen)(void), const char *preambula)
{
	unsigned int idx = 0;
	unsigned long long int new_max, old_max = 1;

	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		adjust_sum_sumsq(&s_clients[i], &s1, 1);

	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		adjust_welford_fp(&w_clients[i], &s2, 1);

	for (unsigned int i = 0; i < TFW_CLIENT_CNT * 100; i++) {
		idx++;
		idx %= TFW_CLIENT_CNT;
		new_max = old_max + valgen();

		adjust_sum_sumsq(&s_clients[idx], &s1, new_max);
		adjust_welford_fp(&w_clients[idx], &s2, new_max);

		old_max = new_max;
	}

	cout << preambula << endl;
	cout << "accuracy (exact, sum_sumsq): " << "( " << compute_exact_variance(s_clients) << ", " << variance_sum_sumsq(&s1) << " )" << endl;
	cout << "accuracy (exact, welford): " << "( " << compute_exact_variance(w_clients) << ", " << variance_welford(&s2) << " )" << endl;
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
	__check_accuracy(valgen_rnd_1_100, "random 1 - 1000");

	return 0;
}