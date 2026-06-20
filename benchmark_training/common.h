#pragma once

#include "128bit.h"

/*
 * Currenly accuracy test is rather slow. Decrease this value to 10000, if you
 * have no time to wait.
 */
#define TFW_CLIENT_CNT 100000

/*
 * Fixed-point configuration.
 * We store numbers as Q16.16:
 * upper 16 bits -> integer part
 * lower 16 bits -> fractional part
 * Example:
 * 1.0 -> 65536
 * 0.5 -> 32768
*/
#define FP_SHIFT 32
#define FP_ONE (1ULL << FP_SHIFT)

struct client {
	unsigned long long max;
};

struct sum_sumsq_state_native_64 {
	u64 sumsq;
	unsigned long long sum;
	unsigned int n;
};

struct sum_sumsq_state_native {
	__int128 sumsq;
	unsigned long long sum;
	unsigned int n;
};

struct sum_sumsq_state_lib {
	u128_acc sumsq;
	unsigned long long sum;
	unsigned int n;
};

struct welford_state_native_64 {
	int64_t mean_fp;
	int64_t M2_fp;
	uint32_t n;
};

/*
 * Welford running statistics using fixed-point arithmetic.
 * mean - fixed-point mean value
 * M2 - fixed-point accumulated squared deviation
 * n - number of active clients
 */
struct welford_state_native {
	int64_t mean_fp;
	__int128 M2_fp;
	uint32_t n;
};

struct welford_state_lib {
	int64_t mean_fp;
	i128_acc M2_fp;
	uint32_t n;
};

/* Convert integer to fixed-point. */
static inline int64_t
to_fp(uint64_t x)
{
	return (int64_t)(x << FP_SHIFT);
}

static inline void
add_welford_fp_native_64(struct welford_state_native_64 *s, long x)
{
	int64_t x_fp;
	int64_t delta;
	int64_t delta2;

	/* Convert input value to fixed-point. */
 	x_fp = to_fp(x);
	/* Increase sample count. */
	s->n++;
	/* delta = x - mean */
	delta = x_fp - s->mean_fp;
	/*
	 * mean += delta / n
	 * Still fixed-point because delta
	 * already contains fractional bits.
	 */
	s->mean_fp += delta / (unsigned long)s->n;
	/* Recompute deviation using updated mean. */
	delta2 = x_fp - s->mean_fp;
	/* Update M2.
	 * Since both values are fixed-point,
	 * multiplication produces Q32.32.
	 * Shift back to Q16.16.
	 */
	s->M2_fp +=
		(delta * delta2)
		>> FP_SHIFT;
}

/*
 * Add a new sample using fixed-point Welford.
 * Integer-only version suitable for kernel-style code.
 */
static inline void
add_welford_fp_native(struct welford_state_native *s, long x)
{
	int64_t x_fp;
	int64_t delta;
	int64_t delta2;

	/* Convert input value to fixed-point. */
 	x_fp = to_fp(x);
	/* Increase sample count. */
	s->n++;
	/* delta = x - mean */
	delta = x_fp - s->mean_fp;
	/*
	 * mean += delta / n
	 * Still fixed-point because delta
	 * already contains fractional bits.
	 */
	s->mean_fp += delta / (unsigned long)s->n;
	/* Recompute deviation using updated mean. */
	delta2 = x_fp - s->mean_fp;
	/* Update M2.
	 * Since both values are fixed-point,
	 * multiplication produces Q32.32.
	 * Shift back to Q16.16.
	 */
	s->M2_fp +=
		((__int128)delta * (__int128)delta2)
		>> FP_SHIFT;
}

/*
 * Add a new sample using fixed-point Welford.
 * Integer-only version suitable for kernel-style code.
 */
static inline void
add_welford_fp_lib(struct welford_state_lib *s, long x)
{
	int64_t x_fp;
	int64_t delta;
	int64_t delta2;
	i128_acc tmp1, tmp2;


	/* Convert input value to fixed-point. */
 	x_fp = to_fp(x);
	/* Increase sample count. */
	s->n++;
	/* delta = x - mean */
	delta = x_fp - s->mean_fp;
	/*
	 * mean += delta / n
	 * Still fixed-point because delta
	 * already contains fractional bits.
	 */
	s->mean_fp += delta / (unsigned long)s->n;
	/* Recompute deviation using updated mean. */
	delta2 = x_fp - s->mean_fp;
	/* Update M2.
	 * Since both values are fixed-point,
	 * multiplication produces Q32.32.
	 * Shift back to Q16.16.
	 */

	tmp1 = i128_i64_mult_i64(delta, delta2);
	tmp1 = i128_right_shift_u32(tmp1, FP_SHIFT);
	s->M2_fp = i128_add_i128(s->M2_fp, tmp1);
}

static inline void
replace_welford_fp_native_64(struct client *c,
		   struct welford_state_native_64 *s,
		   unsigned long long new_max)
{
	int64_t old_fp;
	int64_t new_fp;
	int64_t mean_old;
	int64_t mean_new;
	int64_t delta_fp;

	/*
	 * New client:
	 * fall back to standard Welford add().
	 */
	if (!c->max) {
		add_welford_fp_native_64(s, new_max);
		c->max = new_max;
		return;
	}

	old_fp = to_fp(c->max);
	new_fp = to_fp(new_max);

	mean_old = s->mean_fp;

	/*
	 * delta = new - old
	 * Q32.32 -> Q32.32
	 */
	delta_fp = new_fp - old_fp;

	/*
	 * mean' = mean + delta / n
	 */
	mean_new = mean_old +
		   delta_fp / (int64_t)s->n;

	/*
	 * M2' = M2 +
	 *       delta *
	 *       ((new - mean') + (old - mean))
	 *
	 * All values are Q32.32.
	 *
	 * Product:
	 * Q32.32 * Q32.32 = Q64.64
	 *
	 * Shift back to Q32.32.
	 */
	s->M2_fp +=
		(delta_fp *
		 ((new_fp - mean_new) +
		  (old_fp - mean_old)))
		>> FP_SHIFT;

	s->mean_fp = mean_new;
	c->max = new_max;
}

static inline void
replace_welford_fp_native(struct client *c,
		   struct welford_state_native *s,
		   unsigned long long new_max)
{
	int64_t old_fp;
	int64_t new_fp;
	int64_t mean_old;
	int64_t mean_new;
	int64_t delta_fp;

	/*
	 * New client:
	 * fall back to standard Welford add().
	 */
	if (!c->max) {
		add_welford_fp_native(s, new_max);
		c->max = new_max;
		return;
	}

	old_fp = to_fp(c->max);
	new_fp = to_fp(new_max);

	mean_old = s->mean_fp;

	/*
	 * delta = new - old
	 * Q32.32 -> Q32.32
	 */
	delta_fp = new_fp - old_fp;

	/*
	 * mean' = mean + delta / n
	 */
	mean_new = mean_old +
		   delta_fp / (int64_t)s->n;

	/*
	 * M2' = M2 +
	 *       delta *
	 *       ((new - mean') + (old - mean))
	 *
	 * All values are Q32.32.
	 *
	 * Product:
	 * Q32.32 * Q32.32 = Q64.64
	 *
	 * Shift back to Q32.32.
	 */
	s->M2_fp +=
		((__int128)delta_fp *
		 ((__int128)(new_fp - mean_new) +
		  (__int128)(old_fp - mean_old)))
		>> FP_SHIFT;

	s->mean_fp = mean_new;
	c->max = new_max;
}

static inline void
replace_welford_fp_lib(struct client *c,
		   struct welford_state_lib *s,
		   unsigned long long new_max)
{
	int64_t old_fp;
	int64_t new_fp;
	int64_t mean_old;
	int64_t mean_new;
	int64_t delta_fp;
	int64_t tmp1;
	i128_acc tmp2;

	/*
	 * New client:
	 * fall back to standard Welford add().
	 */
	if (!c->max) {
		add_welford_fp_lib(s, new_max);
		c->max = new_max;
		return;
	}

	old_fp = to_fp(c->max);
	new_fp = to_fp(new_max);

	mean_old = s->mean_fp;

	/*
	 * delta = new - old
	 * Q32.32 -> Q32.32
	 */
	delta_fp = new_fp - old_fp;

	/*
	 * mean' = mean + delta / n
	 */
	mean_new = mean_old +
		   delta_fp / (int64_t)s->n;

	/*
	 * M2' = M2 +
	 *       delta *
	 *       ((new - mean') + (old - mean))
	 *
	 * All values are Q32.32.
	 *
	 * Product:
	 * Q32.32 * Q32.32 = Q64.64
	 *
	 * Shift back to Q32.32.
	 */
	tmp1 = (new_fp - mean_new) + (old_fp - mean_old);
	tmp2 = i64_mul_i64(tmp1, delta_fp);
	s->M2_fp = i128_add_i128(s->M2_fp, i128_right_shift_u32(tmp2, FP_SHIFT));

	s->mean_fp = mean_new;
	c->max = new_max;
}

static inline void
adjust_welford_fp_native_64(struct client *c, struct welford_state_native_64 *s, long new_max)
{
	/*
	 * Existing client update - remove old value, add new value
	 */
	replace_welford_fp_native_64(c, s, new_max);
}

/*
 * Replace old client maximum with new one.
 * Example:
 * 400 -> 401
*/
static inline void
adjust_welford_fp_native(struct client *c, struct welford_state_native *s, long new_max)
{
	/*
	 * Existing client update - remove old value, add new value
	 */
	replace_welford_fp_native(c, s, new_max);
}

static inline void
adjust_welford_fp_lib(struct client *c, struct welford_state_lib *s, long new_max)
{
	/*
	 * Existing client update - remove old value, add new value
	 */
	replace_welford_fp_lib(c, s, new_max);
}

static void
adjust_sum_sumsq_native_64(struct client *c, struct sum_sumsq_state_native_64 *s, unsigned long new_max)
{
	unsigned long old_max = c->max;
	unsigned long delta1 = new_max - old_max;
	u64 delta2 = new_max * new_max - old_max * old_max;

	c->max = new_max;
	/*
	 * If there was no connection for current client, we should adjust it
	 * as a new client in our statistic.
	 */
	if (!old_max)
		s->n++;
	s->sum += delta1;
	s->sumsq += delta2;	
}

static void
adjust_sum_sumsq_native(struct client *c, struct sum_sumsq_state_native *s, unsigned long new_max)
{
	unsigned long old_max = c->max;
	unsigned long delta1 = new_max - old_max;
	unsigned __int128 delta2 = (unsigned __int128)new_max * new_max -
		(unsigned __int128)old_max * old_max;

	c->max = new_max;
	/*
	 * If there was no connection for current client, we should adjust it
	 * as a new client in our statistic.
	 */
	if (!old_max)
		s->n++;
	s->sum += delta1;
	s->sumsq += delta2;	
}

static void
adjust_sum_sumsq_lib(struct client *c, struct sum_sumsq_state_lib *s, unsigned long new_max)
{
	unsigned long old_max = c->max;
	unsigned long delta1 = new_max - old_max;
	u128_acc delta2, tmp1, tmp2;

	tmp1 = u128_u64_mult_u64(new_max, new_max);
	tmp2 = u128_u64_mult_u64(old_max, old_max);

	delta2 = u128_sub_u128(tmp1, tmp2);
	c->max = new_max;
	/*
	 * If there was no connection for current client, we should adjust it
	 * as a new client in our statistic.
	 */
	if (!old_max)
		s->n++;
	s->sum += delta1;
	s->sumsq = u128_add_u128(s->sumsq, delta2);
}

static long double
compute_exact_variance(struct client *clients)
{
	long double mean = 0.0;
	long double variance = 0.0;

	/*
	 * First pass:
	 * compute exact mean.
	 */
	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++)
		mean += clients[i].max;
	mean /= TFW_CLIENT_CNT;
	/*
	 * Second pass:
	 * compute sum of squared deviations.
	 */
	for (unsigned int i = 0; i < TFW_CLIENT_CNT; i++) {
		/*
		 * Difference between current value
		 * and exact mean.
		 */
		long double d = clients[i].max - mean;
		/*
		 * Accumulate squared deviation.
		 */
		variance += d * d;
	}

	/*
	 * Population variance:
	 * divide by total number of clients.
	 */
	variance /= TFW_CLIENT_CNT;

	return variance;
}

static long double
variance_sum_sumsq_native_64(struct sum_sumsq_state_native_64 *s)
{
	long double mean;

	if (!s->n)
		return 0;
	/*
	 * Compute average value.
	 */
	mean = (long double)s->sum / s->n;

	/*
	 * E[x²] - E[x]²
	 */
	return ((long double)s->sumsq / s->n) - mean * mean;
}

/*
 * Compute variance using sum/sumsq method.
 *
 * Formula:
 *
 * variance = E[x²] - E[x]²
 *
 * This method is very fast and simple,
 * but may lose precision when:
 *
 * - values are very large
 * - variance is very small
 *
 * due to catastrophic cancellation.
 */
static long double
variance_sum_sumsq_native(struct sum_sumsq_state_native *s)
{
	long double mean;

	if (!s->n)
		return 0;
	/*
	 * Compute average value.
	 */
	mean = (long double)s->sum / s->n;

	/*
	 * E[x²] - E[x]²
	 */
	return ((long double)s->sumsq / s->n) - mean * mean;
}

static long double
variance_sum_sumsq_lib(struct sum_sumsq_state_lib *s)
{
	long double mean;

	if (!s->n)
		return 0;
	/*
	 * Compute average value.
	 */
	mean = (long double)s->sum / s->n;

	/*
	 * E[x²] - E[x]²
	 */
	return ((long double)u128_to_int128(s->sumsq) / s->n) - mean * mean;
}

static long double
variance_welford_native_64(struct welford_state_native_64 *s)
{
	if (!s->n)
		return 0;

	return ((long double)s->M2_fp / FP_ONE) / s->n;
}

/*
 * Compute variance from fixed-point Welford state.
 *
 * M2 stores accumulated squared deviations
 * in fixed-point representation.
 *
 * To convert back:
 * - divide by FP_ONE to remove fixed-point scaling
 * - divide by n to compute variance
 */
static long double
variance_welford_native(struct welford_state_native *s)
{
	if (!s->n)
		return 0;

	return ((long double)s->M2_fp / FP_ONE) / s->n;
}

static long double
variance_welford_lib(struct welford_state_lib *s)
{
	if (!s->n)
		return 0;

	return ((long double)i128_to_int128(s->M2_fp) / FP_ONE) / s->n;
}
