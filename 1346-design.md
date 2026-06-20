## HTTP protection modes

### Training Mode
During the training phase the system collects per-client metrics for each new event and aggregates global statistics required for subsequent z-score calculation in defence mode. For each client, only the current maximum number of connections, requests, memory usage, and CPU usage is stored. Global statistics include:

- number of samples ("n", i.e. number of active clients),
- sum of values ("sum"),
- sum of squared values ("sumsq").

At the end of the training phase the mean and standard deviation are computed and later used for z-score calculation during anomaly detection:

- μ = sum / n -> mean
- σ² = (sumsq / n) - μ² -> variance
- sqrt(σ²) -> standard deviation
- z = (x - μ) / σ — z-score, calculated for each new value (x)

Several approaches for online variance calculation were evaluated, including Welford’s algorithm and the sum/sumsq method.

The classical Welford algorithm was found to be unsuitable for this workload. In its original form Welford assumes an append-only stream of samples, where each new observation increases the total sample count. In our case, however, "n" represents the number of clients rather than the number of events. For each client we continuously update the current maximum number of connections/requests/memory/cpu usage. Therefore, when a client metric changes, the previous value must first be removed from the aggregated statistics before the updated value can be inserted. In other words, the algorithm must support a replace operation rather than a simple append operation. This requires a modified reversible version of Welford’s algorithm, which significantly complicates the implementation.

In addition, kernel-space constraints prohibit floating-point arithmetic, requiring the use of fixed-point integer arithmetic instead. While Welford’s algorithm is well known for its numerical stability when implemented with floating-point arithmetic, a fixed-point implementation introduces truncation errors due to repeated division operations. In workloads where metric values remain relatively small and close to each other (e.g. connection/request maxima), these rounding errors accumulate over time and may lead to noticeable precision degradation. Since memory usage is tracked in pages and CPU usage is represented as an EMA value, the range of possible maximum values is also relatively limited.

Benchmarking (see the benchmark_training directory) demonstrated that the modified fixed-point Welford implementation is slower than the sum/sumsq approach due to additional arithmetic operations, extra division steps, and the need to perform a more complex replace operation on every update.

Operation	Native `__int128`	Custom 128-bit
Welford update		7.24 ns		20.9 ns
sum/sumsq update	4.59 ns		15.6 ns

Accuracy was also calculated for four different cases.

client maximum increases +1 on each iteration (same as for connection tracking):
exact                = 8.33e+08
sum/sumsq (128-bit)  = 8.33e+08
Welford (128-bit)    = 8.33e+08
sum/sumsq (64-bit)	 = 8.33e+08
Welford (64-bit)     = 32.4295

client maximum randomly increases in a range (1 - 10) on each iteration (possible for non-idempotent request tracking, since we use algorithm at the end of the `ss_tcp_process_data`, when we can already process several requests):
exact 				 = 2.51356e+10
sum/sumsq (128-bit)	 = 2.51356e+10
Welford (128-bit)	 = 2.51356e+10
sum/sumsq (64-bit)	 = -2.95145e+15
Welford (64-bit)	 = 32.4279

client maximum randomly increases in a range (1 - 100) on each iteration:
exact                = 2.11991e+12
sum/sumsq (128-bit)  = 2.11991e+12
Welford (128-bit)    = 2.11991e+12
sum/sumsq (64-bit)	 = -2.52349e+17
Welford (64-bit)     = 32.4355

client maximum randomly increases in a range (1 - 1000) on each iteration (possible for memory usage tracking, since we use algorithm at the end of the `ss_tcp_process_data`, and track memory usage in pages):
exact                = 2.07582e+14
sum/sumsq (128-bit)  = 2.07582e+14
Welford (128-bit)    = 2.07582e+14
sum/sumsq (64-bit)	 = -2.48049e+19
Welford (64-bit)	 = 32.4198

As shown above, both algorithms provide excellent accuracy; however, the sum/sumsq method is consistently faster. As a result, the implementation uses the sum of values / sum of squares method (sum/sumsq method). This approach maintains:

- the sum of all values,
- the sum of squared values,
- the total number of clients.

The variance is then computed using the standard relation:

Var(X) = E[X²] − E[X]²

This is a classic streaming-statistics technique commonly referred to as the sum/squared-sum method or the "naive variance algorithm” (Wikipedia — “Algorithms for calculating variance”)
This approach is efficient because:

- O(1) update cost,
- no historical samples must be stored,
- naturally supports per-CPU counters and lockless aggregation,
- very cheap for hot-path telemetry.

However, the algorithm may become numerically unstable when:

- the mean is very large,
- variance is very small,
- or values are extremely close relative to the magnitude of the mean.

This method is generally considered less numerically stable than Welford’s algorithm because subtracting two large close values may lead to catastrophic cancellation and precision loss.
For example, the following dataset `(1000000000, 1000000001, 999999999, 1000000000)` may become problematic. In this case - mean ≈ 1,000,000,000, standard deviation ≈ 1.
The variance computation subtracts two extremely large nearly identical numbers, which can cause catastrophic cancellation and precision loss.

For the target workload, client metrics are bounded and remain within a relatively small range. Under these conditions, the sum/sumsq approach provides sufficient numerical accuracy while being significantly simpler, faster, and easier to maintain than a reversible fixed-point implementation of Welford’s algorithm.

Mean and standard deviation are calculated using SCALE_SHIFT = 10, a fixed-point scaling factor used for integer arithmetic. We also save both these values in scaled format for accuracy, because linux kernel code avoids floating point operations.

### Defence Mode
Each new observation is evaluated using:

z = ((x << SCALE_SHIFT) - mean) / std

where SCALE_SHIFT = 10 is the fixed-point scaling factor used during mean and standard deviation calculation. All fractional computations (e.g. mean, variance, and z-score) are therefore performed using scaled integers. If z > configured_threshold the event is considered anomalous. Drop connection with TCP RST and optionally block client by IP.

### Disabled Mode
Internal state used during transitions. Ensures safe updates of shared data (via RCU synchronization). This mode can also be exposed as a user-configurable operating mode rather than being used solely as an internal transition state. Doing so completely eliminates the overhead associated with statistics collection and anomaly detection when the feature is not required.


## 128-bit arithmetic support

### Accuracy
Both the `sum/sumsq` and fixed-point Welford implementations require 128-bit intermediate values to maintain sufficient numerical accuracy.

The Linux kernel does not provide generic 128-bit arithmetic support and many architectures do not support native `__int128` operations in kernel code. To address this limitation, a lightweight 128-bit arithmetic library was implemented using a pair of 64-bit values.

The library provides the operations required by the adaptive limits
subsystem:

* addition and subtraction;
* multiplication;
* division by a 64-bit value;
* square root;
* left and right shifts.

Accuracy tests show that a 64-bit implementation is insufficient for production use. While the native and library-backed 128-bit implementations produce results identical to the exact variance 
calculation, the 64-bit implementation quickly loses precision and eventually overflows (see accuracy results in previous chapter). The results demonstrate that 64-bit accumulators are unable to maintain acceptable precision for the large datasets (100000 clients), while the custom 128-bit implementation matches the native `__int128` implementation.

### Performance impact
The custom 128-bit implementation introduces additional arithmetic overhead compared to native `__int128` operations. However, statistics are updated relatively infrequently, and the most computationally expensive operations (such as division and square-root calculation) are performed only during transitions from Training Mode to Defence Mode. Consequently, no measurable impact on overall performance was observed (see the benchmark results at the end of this document).


## HTTP Protection Library Implementation Details (Adaptive Limits Library Implementation)

### Common structures
We use two different structures to track events:
```C
/*
 * A simple adaptive limit structure used to track events,
 * which is already protected by an external lock.
 *
 * @counter	- current value (e.g. active connections).
 * @max		- maximum observed value within the current epoch.
 * @epoch	- training epoch identifier. compared against the global
 *			  @g_training_epoch to detect epoch change and trigger
 *			  reinitialization of @max and @counter.
 */
typedef struct {
	int				counter;
	unsigned int	max;
	u16				epoch;
} TfwAdaptiveLimit;

/*
 * counter	- percpu array to track current value of the tracked metric;
 * lock		- spinlock used to serialize lazy reinitialization of
 *            @max and @counter when a new training epoch begins.
 * max		- maximum observed value of the tracked metric within the
 *			  current training epoch;
 * @epoch	- training epoch identifier. Compared against the global
 *			  @g_training_epoch to detect epoch change and trigger
 *			  reinitialization of @max and @counter;
 */
typedef struct {
	s64 __percpu	*counter;
	spinlock_t		lock;
	atomic64_t		max;
	u16				epoch;
} TfwAdaptiveLimitLock;
```

`TfwAdaptiveLimit` is currently used only for connection tracking because connection establishment and teardown are already serialized by `ra->lock`. No additional synchronization is therefore required.
`TfwAdaptiveLimitLock` is used for all other metrics that may be updated concurrently from different execution contexts. To minimize synchronization overhead, only the current counter is updated on the hot path. The corresponding maximum value (max) is evaluated only once per invocation of `ss_tcp_process_data` and updated atomically only when the current value exceeds the previously observed maximum.

We introduce a dedicated structure for tracking all adaptive-limit related client statistics and store a pointer to it in the `TfwClient` structure.
```C
/*
 * Structure to track different client statistic.
 *
 * @kill_work	- workqueue item used for asynchronous structure
 *				  cleanup/destruction;
 * @next_free	- pointer to the next free object in the freelist;
 * @refcnt		- percpu reference counter. Provides scalable and
 *				  thread-safe reference tracking on SMP systems with
 *				  minimal contention;
 * @cli_mem		- client memory accounting structure for Tempesta FW;
 * @req_lim 	- tracks the number of in-flight non-idempotent requests
 *				  for the current client;
 */
typedef struct tfw_adaptive_limits_t {
	union {
		struct work_struct				kill_work;
		struct tfw_adaptive_limits_t	*next_free;
	};
	struct percpu_ref		refcnt;
	TfwAdaptiveLimitLock	req_lim;
	TfwAdaptiveLimitLock	cpu_lim;
	TfwClientMem			cli_mem; // Contains TfwAdaptiveLimitLock inside.
} TfwClientAdaptiveLimits;
```

We use new implemented structure and common function to track `sum/sumsq` for each observed event type in training mode:

```C
/*
 * Per-metric aggregated statistics.
 *
 * @sumsq - sum of squares of observed values.
 * @sum   - sum of observed values.
 * @mean  - calculated mean (scaled by SCALE_SHIFT).
 * @std   - calculated standard deviation (scaled).
 * @num   - number of samples (e.g. number of clients).
 */
struct stats {
	u128_acc __percpu	*sumsq;
	u64 __percpu		*sum;
	u64 			mean;
	u64 			std;
	u32 __percpu		*num;
};
```
A separate instance of `struct stats` is maintained for each tracked metric (connections, non-idempotent requests, memory usage, and CPU usage). Per-CPU counters are used to avoid atomic contention during training. The statistics are aggregated over client maxima rather than individual events. Consequently, the sample count (`num`) corresponds to the number of participating clients rather than the total number of observed events. The global values are aggregated only during switching from training mode to defence mode. 

### Training mode
```C
/*
 * When a client's maximum value increases, the global statistics are updated
 * incrementally using the difference between the new and previous maxima:
 * delta1 = new_max - old_max
 * delta2 = new_max² - old_max²
 * This avoids recomputing global aggregates from scratch.
 */
static inline void
tfw_adaptive_limits_adjust_new_el(struct stats __rcu *g_stats, u64 delta1,
				  u128_acc delta2)
{
	struct stats *s;

	/*
	 * rcu pointer dereference should be done under rcu lock,
	 * to prevent memory corruption.
	 */
	BUG_ON(!rcu_read_lock_held());
	s = rcu_dereference(g_stats);
	this_cpu_add(*s->sum, delta1);
	*this_cpu_ptr(s->sumsq) =
		u128_add_u128(*this_cpu_ptr(s->sumsq), delta2);
}
```

Event accounting is performed through a common helper that updates per-CPU counters without requiring global synchronization.
```C
static void
__tfw_adaptive_limits_acc(TfwAdaptiveLimitLock *limit, int delta,
			 void (*adjust_new_client)(void),
			 void (*add)(TfwAdaptiveLimitLock *limit, int delta))
{
	if (tfw_adaptive_limits_mode_is_training()
	    && tfw_adaptive_limits_change_epoch(limit))
		adjust_new_client();
	add(limit, delta);
}
```
When a metric is observed for the first time for a given client within the current training epoch, `adjust_new_client` increments the corresponding sample count (`n`).

```C
static void
tfw_adaptive_limits_acc(TfwAdaptiveLimitLock *limit, int delta,
			void (*adjust_new_client)(void),
			void (*add)(TfwAdaptiveLimitLock *limit, int delta),
			u16 *epoch)
{
	bool new_event;

	/*
	 * Prevent training epoch changes while processing the event.
	 *
	 * A new training epoch is started only after:
	 *
	 *	synchronize_rcu();
	 *	g_training_epoch++;
	 *
	 * Therefore, while we are inside this RCU read-side critical
	 * section, `g_training_epoch` cannot change and the event is
	 * guaranteed to be processed against a stable training epoch.
	 *
	 * This avoids races where an event is validated against one
	 * epoch and accounted after statistics have already been reset
	 * for the next epoch.
	 */
	rcu_read_lock();

	if (tfw_adaptive_limits_mode_is_disabled())
		goto out;

	new_event = delta > 0 && !(*epoch);
	if (!tfw_adaptive_limits_check_and_set_epoch(epoch, new_event))
		goto out;

	__tfw_adaptive_limits_acc(limit, delta, adjust_new_client, add);

out:
	rcu_read_unlock();
}
```
To minimize hot-path overhead, maximum values are evaluated only once at the end of `ss_tcp_process_data`.
```C
static inline bool
tfw_adaptive_limits_change_max(TfwAdaptiveLimitLock *limit,
			       s64 (*convert_val)(s64), s64 curr,
			       u64 *delta1, u128_acc *delta2)
{
	s64 old_max = atomic64_read(&limit->max);
	u128_acc tmp1, tmp2;

	/*
	 * Can be called concurrentrly on other cpu with different
	 * curr value, so we need syncronization here.
	 */
	do {
		if (curr <= old_max)
			return false;
	} while (!atomic64_try_cmpxchg(&limit->max, &old_max, curr));

	curr = convert_val(curr);
	old_max = convert_val(old_max);

	*delta1 = ((u64)curr - (u64)old_max);
	tmp1 = u128_u64_mult_u64(curr, curr);
	tmp2 = u128_u64_mult_u64(old_max, old_max);
	*delta2 = u128_sub_u128(tmp1, tmp2);

	return true;
}
```
The function performs an atomic max-update operation and returns the difference between the old and new maxima. These deltas are later applied to the global `sum` and `sumsq` counters, allowing statistics to be updated incrementally without recomputing them from scratch.


During switching from training to defence modes Tempesta FW aggregates all per-CPU statistics and computes the mean and standard deviation for each tracked metric.
```C
/*
 * Compute mean and standard deviation from aggregated stats.
 * Uses integer arithmetic with scaling.
 */
static inline void
__calculate_mean_and_std(struct stats *s)
{
	u128_acc variance, tmp1, tmp2;
	u128_acc total_sumsq;
	u64 total_sum;
	u32 num_clients;

	total_sumsq = tfw_percpu_u128_counter_sum(s->sumsq);
	total_sum = tfw_percpu_u64_counter_sum(s->sum);
	num_clients = tfw_percpu_u32_counter_sum(s->num);

	if (!unlikely(num_clients))
		return;

	tmp1 = u128_left_shift_u32(total_sumsq, SCALE_SHIFT);
	tmp1 = u128_div_u64(tmp1, num_clients, NULL);
	tmp2 = u128_u64_mult_u64(s->mean, s->mean);
	tmp2 = u128_right_shift_u32(tmp2, SCALE_SHIFT);

	s->mean = (total_sum << SCALE_SHIFT) / num_clients;
	variance = u128_sub_u128(tmp1, tmp2);
	s->std = u128_sqrt(u128_left_shift_u32(variance, SCALE_SHIFT));
}
```

### Defence mode
In defence mode Tempesta FW calculates z-score for each new event observation using common function. The calculated z-score is compared against the configured threshold. Observations whose z-score exceeds the threshold are classified as anomalous and may trigger mitigation actions such as TCP connection termination or client IP blocking.
```C
static inline bool
tfw_adaptive_limits_defence(struct stats __rcu *g_stats, u64 val, int threshold)
{
	struct stats *p;
	s64 z_score;

	/*
	 * rcu pointer dereference should be done under rcu lock,
	 * to prevent memory corruption.
	 */
	BUG_ON(!rcu_read_lock_held());

	p = rcu_dereference(g_stats);
	if (!__calculate_z_score(val, p, &z_score)) {
		/*
		 * Observations are treated as valid if a z-score cannot
		 * be computed (e.g. due to zero variance).
		 */
		return true;
	}

	/*
	 * Only positive deviations are currently considered. Observations whose
	 * z-score exceeds the configured threshold are treated as anomalous.
	 */
	return z_score <= threshold;
}
```

### Epoch handling
We use global `g_training_epoch` identifier to track current training epoch number. This design avoids a global traversal of all clients when a new training phase begins. Instead, state reinitialization is performed lazily on first access. As a result, the cost of epoch transitions is distributed across subsequent requests rather than concentrated into a single expensive synchronization point.

Training epoch handling is implemented as follows: for each event type, a `u16 epoch` field is added to the corresponding event structure. Inside the library, a dedicated function is called to determine whether the incoming event is new.
```C
/*
 * An event is considered new only if:
 *  - delta > 0, and
 *  - no epoch has yet been assigned.
 *
 * Removal events (delta < 0) are always treated as existing events.
 */
new_event = delta > 0 && !(*epoch);

static inline bool
tfw_adaptive_limits_check_and_set_epoch(u16 *epoch, bool new_event)
{
	/*
	 * Ignore events from the previous training epochs. Set epoch for
	 * the new events.
	 */
	if (!new_event && *epoch < g_training_epoch)
		return false;
	else if (new_event)
		*epoch = g_training_epoch;

	return true;
}
```

This function compares the event’s epoch and assigns the appropriate epoch value if the event is considered new.
If the event is identified as old (i.e., its epoch does not match the current active epoch), it is ignored and not processed further.

When the new training starts global `g_training_epoch` counter is incremented. For each tracked event, the function `tfw_adaptive_limits_change_epoch` is invoked. Its purpose is to ensure that the internal counters are consistent with the current training epoch and to lazily reset state when a new training phase begins.
```C
static inline bool
tfw_adaptive_limits_change_epoch(TfwAdaptiveLimitLock *limit)
{
	bool new_client = false;

	/*
	 * We increment `g_training_epoch` each time when we start new
	 * training, when we are sure that all threads don't use `max`
	 * and `counter`. During training all threads call this function
	 * before use `counter` and `max`, so we are sure that `counter`
	 * and `max` will be zeroed on the start of the new training.
	 * We make first check to prevent unnecessary lock on the hot
	 * path on each call.
	 */
	if (limit->epoch < g_training_epoch) {
		spin_lock_bh(&limit->lock);
		if (likely(limit->epoch < g_training_epoch)) {
			int cpu;

			for_each_online_cpu(cpu)
				*(per_cpu_ptr(limit->counter, cpu)) = 0;
			atomic64_set(&limit->max, 0);
			limit->epoch = g_training_epoch;
			new_client = true;
		}
		spin_unlock_bh(&limit->lock);
	}

	return new_client;
}
```

When new training started we call special function:
```C
/*
 * Disable both training and defence modes.
 *
 * Ensures that no readers are accessing RCU-protected stats,
 * so pointers can be safely replaced.
 */
static inline void
tfw_adaptive_limits_disable_training_or_defence(void)
{
	/*
	 * Set TFW_ADAPTIVE_LIMITS_MODE_IS_DISABLED, now we stop
	 * calling all new defence and training functions. We don't
	 * try to make rcu pointer dereference after it.
	 */
	WRITE_ONCE(tfw_adaptive_limits_mode,
		   TFW_ADAPTIVE_LIMITS_MODE_IS_DISABLED);
	/*
	 * Wait until all previous rcu calls finished, to be sure
	 * that we can safely change pointers.
	 */
	synchronize_rcu();
}
```

Since all library functions enter an RCU read-side critical section before accessing statistics, the active training epoch cannot change while an operation is in progress.
```C
	rcu_read_lock();

	if (tfw_adaptive_limits_mode_is_disabled())
		goto out;
```

### Concurrency model

The implementation combines several synchronization mechanisms:

- per-CPU counters for lockless hot-path accounting;
- atomic operations for maximum tracking;
- spinlocks for lazy epoch reinitialization;
- RCU for safe mode transitions and statistics replacement;

This separation allows the common request-processing path to avoid global locks while still providing consistent statistics during training and defence mode transitions.


## Connection Count Tracking
A `TfwAdaptiveLimit conn_lim` field is stored in the `TfwClient` structure to track the number of active client connections and to support anomaly detection. As described earlier, we don't need any lock here, because connection establishment and teardown are already synchronized using the internal `ra->lock` in frang. The common helper `tfw_adaptive_limits_check_conn_num()` is used in both
training and defence modes.

### Training mode
During Training Mode, conn_lim->counter tracks the current number of active client connections. The counter is incremented when a connection is established and decremented when it is closed.
For each client, the subsystem tracks the maximum number of concurrent connections observed during the current training epoch (`conn_lim->max`). Whenever this maximum increases, the corresponding
global statistics are updated incrementally:

- `delta1 = new_max - old_max`
- `delta2 = new_max² - old_max²`

These deltas are added to the global `sum` and `sumsq` accumulators, which are later used to calculate the mean and standard deviation without storing historical samples.
```C
bool
tfw_adaptive_limits_check_conn_num(TfwAdaptiveLimit *limit, int delta,
				   u16 *epoch)
{
	u128_acc delta2, tmp1, tmp2;
	u64 delta1;
	unsigned int old_max;
	bool new_event, new_client = false;
	bool rc = true;

	/*
	 * Prevent training epoch changes while processing the event.
	 *
	 * A new training epoch is started only after:
	 *
	 *	synchronize_rcu();
	 *	g_training_epoch++;
	 *
	 * Therefore, while we are inside this RCU read-side critical
	 * section, `g_training_epoch` cannot change and the event is
	 * guaranteed to be processed against a stable training epoch.
	 *
	 * This avoids races where an event is validated against one
	 * epoch and accounted after statistics have already been reset
	 * for the next epoch.
	 */
	rcu_read_lock();

	if (tfw_adaptive_limits_mode_is_disabled())
		goto out;

	new_event = delta > 0 && !(*epoch);
	if (!tfw_adaptive_limits_check_and_set_epoch(epoch, new_event))
		goto out;

	if (tfw_adaptive_limits_mode_is_defence()) {
		limit->counter += delta;
		WARN_ON(limit->counter < 0);

		if (delta > 0)
			rc = tfw_adaptive_limits_defence_conn_num(limit->counter);
		goto out;
	}

	/*
	 * Training mode.
	 *
	 * Reset limit on each new training epoch.
	 * This is safe without extra synchronization as we are under
	 * client-private lock.
	 */
	if (limit->epoch < g_training_epoch) {
		limit->epoch = g_training_epoch;
		limit->counter = 0;
		limit->max = 0;
		new_client = true;
	}

	if (new_client)
		tfw_adaptive_limits_adjust_conn_new_client();
	limit->counter += delta;
	WARN_ON(limit->counter < 0);

	old_max = limit->max;
	if (limit->counter <= old_max)
		goto out;
	limit->max = limit->counter;
	delta1 = limit->counter - old_max;
	tmp1 = u128_u64_mult_u64(limit->counter, limit->counter);
	tmp2 = u128_u64_mult_u64(old_max, old_max);
	delta2 = u128_sub_u128(tmp1, tmp2);
	tfw_adaptive_limits_adjust_conn_num(delta1, delta2);

out:
	rcu_read_unlock();

	return rc;
}
```

As discussed in the previous section, the sum/sumsq approach provides sufficient numerical accuracy for this workload while remaining significantly simpler and faster than a reversible fixed-point implementation of Welford’s algorithm.

### Defence mode
During Defence Mode, every newly established connection triggers an anomaly check based on the current value of conn_lim->counter:

`z = ((conn_lim->counter << SCALE_SHIFT) - mean) / std`

where `mean` and `std` are the values calculated during the preceding training phase (both `mean` and `std` are stored in scaled form using the fixed-point factor SCALE_SHIFT). If the calculated z-score exceeds the configured threshold, the connection is considered anomalous and is rejected. Depending on the configuration, the client IP address may also be temporarily blocked.

### Epoch handling
Each connection is associated with a training epoch identifier. A dedicated epoch field is added to `tempesta_sock` and initialized when the connection is first observed. Epoch handling is required to prevent statistics collected during different training phases from being mixed together. If an event originates from a connection that belongs to an older training epoch, the event is ignored and does not contribute to the statistics of the current epoch. We also check epoch for `TfwAdaptiveLimit` structure and lazy zero statistic (`counter` and `max`) on the new training epoch.


## Request Count Tracking (Non-idempotent)
The `TfwAdaptiveLimitLock req_lim` structure is used to track the number of in-flight non-idempotent requests associated with a client. As described earlier, `req_lim` is stored inside the common
`TfwClientAdaptiveLimits` structure referenced from `TfwClient`.

### Training mode
Tracking of in-flight non-idempotent requests is performed in two stages.
First, a dedicated helper is invoked whenever a non-idempotent request is added to or removed from a server connection queue:
```C
static inline void
tfw_http_adjust_nip_req(TfwHttpReq *req, int delta)
{
	TfwClient *cli = req->conn ? (TfwClient *)req->conn->peer : NULL;
	TfwAdaptiveLimitLock *req_lim;
	unsigned int epoch;

	if (unlikely(!cli))
		return;

	req_lim = &cli->limits->req_lim;
	epoch = tempesta_sock(req->conn->sk)->training_epoch;
	tfw_adaptive_limits_acc_req_num(req_lim, delta,  epoch);
}
```
This function is called with delta = +1 when a non-idempotent request enters the queue and with delta = -1 when it leaves the queue. The helper updates the current request count using per-CPU counters without acquiring any locks. Internally, `tfw_adaptive_limits_acc_req_num` delegates to the generic adaptive-limits infrastructure and performs lockless accounting on the hot path.

The second stage occurs in the `on_rcv_finish` callback at the end of `ss_tcp_process_data`. At this point, the current number of in-flight requests is obtained by aggregating all per-CPU counters
```C
curr = tfw_percpu_s64_counter_sum(limit->counter);
if (tfw_adaptive_limits_change_max(limit, curr, &delta1, &delta2))
	adjust_num(delta1, delta2);
```
If the aggregated value exceeds the previously recorded maximum, the maximum is updated atomically and the corresponding deltas are applied to the global `sum` and `sumsq` statistics. This approach avoids expensive synchronization on every request while still maintaining accurate client maxima for statistical analysis. As discussed earlier, the `sum/sumsq` approach provides sufficient numerical accuracy for this workload while remaining significantly simpler and faster than a reversible fixed-point implementation of Welford's algorithm.

### Defence mode 
During defence mode, request accounting is performed in the same manner as during training. At the end of `ss_tcp_process_data`, the current number of in-flight non-idempotent requests is obtained by summing all per-CPU counters. Instead of updating training statistics, the aggregated value is evaluated against the statistics collected during the training phase. The z-score is calculated using the common adaptive-limits infrastructure (`tfw_adaptive_limits_defence_req_num` ultimately calls `tfw_adaptive_limits_defence` with the corresponding statistics structure). If the calculated z-score exceeds the configured threshold, the request activity is considered anomalous. In this case, the client connection is terminated and, depending on the configuration, the client IP address may also be temporarily blocked.

### Epoch handling
Epoch handling for non-idempotent requests is identical to that used for connection tracking. Each request is associated with a training epoch identifier. A dedicated epoch field is added to `TfwHttpReq`structure and initialized when the request is added to the server connection queue (if this request is non-idempotent). The corresponding fields in `TfwAdaptiveLimitLock req_lim` are also reset lazily when the first event of a new training epoch is processed (see `tfw_adaptive_limits_change_epoch`).

## Memory usage tracking
Memory usage tracking differs slightly from connection and request tracking. A dedicated structure is required because memory accounting is used not only by the adaptive-limits subsystem but also by Frang's existing client memory limit enforcement logic. Unlike other tracked metrics, memory allocations may outlive a training epoch. Since adaptive-limits counters are reset when a new training epoch begins and memory allocation events from previous epochs are ignored, a separate accounting mechanism is required to maintain the actual amount of memory currently owned by the client. 
For this reason, `TfwClientMem` structure contains both:

- `mem_lim`, used by the adaptive-limits subsystem for training and anomaly detection;
- `mem`, used for persistent client memory accounting independent of training epochs.

As with all other adaptive-limit related data, this structure is stored inside `TfwClientAdaptiveLimits`.
```C
/*
 * Client memory accounting structure for Tempesta FW.
 *
 * @mem_lim - memory usage tracking used by the adaptive-limits
 *            subsystem for statistics collection and anomaly
 *            detection;
 * @mem     - per-CPU memory accounting storage used for actual
 *            client memory tracking and Frang memory limits.
 */
typedef struct tfw_client_mem_t {
	TfwAdaptiveLimitLock	mem_lim;
	s64 __percpu			*mem;
} TfwClientMem;

```

### Training mode
Memory usage is tracked in two places.
First, all client memory allocations and deallocations are accounted through `tfw_client_adjust_mem`:
```C
static inline void
tfw_client_adjust_mem(TfwClientMem *cli_mem, int delta, u16 *epoch)
{
	this_cpu_add(*cli_mem->mem, delta);
	tfw_adaptive_limits_acc_mem(&cli_mem->mem_lim, delta, epoch);
}
```
The `mem` counter tracks the actual amount of memory currently associated with the client and is used by Frang's memory limit enforcement logic. The adaptive-limits subsystem maintains a separate epoch-aware accounting stream through `mem_lim`. Internally, `tfw_adaptive_limits_acc_mem` delegates to the generic adaptive-limits infrastructure and updates per-CPU counters without acquiring locks on the hot path. To reduce the range of tracked values and improve numerical stability, memory usage is converted from bytes to pages before being accumulated: `pages = bytes >> PAGE_SHIFT`.
The second stage occurs in the `on_rcv_finish` callback at the end of `ss_tcp_process_data` The current client memory usage is obtained by aggregating all per-CPU counters:
```C
curr = tfw_percpu_s64_counter_sum(limit->counter);
if (tfw_adaptive_limits_change_max(limit, curr, &delta1, &delta2))
	adjust_num(delta1, delta2);
```
Whenever the current value exceeds the previously observed maximum, the maximum is updated atomically and the corresponding `delta1` and `delta2` values are applied to the global sum and sumsq accumulators. From the adaptive-limits perspective, memory usage tracking follows exactly the same model as non-idempotent request tracking: per-CPU counters are maintained on the hot path, while maximum updates and statistical aggregation are performed only once at the end of request processing.

### Defence mode 
During defence mode, client memory usage is evaluated in the same way as during training. At the end of `ss_tcp_process_data`, the current memory usage is obtained by summing all per-CPU counters. Instead of updating training statistics, the aggregated value is compared against the statistics collected during the training phase. The z-score is calculated using the common adaptive-limits infrastructure (`tfw_adaptive_limits_defence_mem` ultimately calls `tfw_adaptive_limits_defence` with the corresponding statistics structure). If the calculated z-score exceeds the configured threshold, the client activity is considered anomalous. In this case, the client connection is terminated and, depending on the configuration, the client IP address may also be temporarily blocked.

### Epoch handling
Memory allocations are associated with the training epoch in which the corresponding object was created. To support this, a dedicated `u16 epoch` field is added to both `TfwPoolChunk` and `TFW_SKB_CB`. The current training epoch is stored when the chunk or skb is created. During subsequent allocation and deallocation operations, the stored epoch is compared against the current global training epoch. If the object belongs to an older training epoch, the corresponding memory accounting event is ignored by the adaptive-limits subsystem and does not contribute to the statistics collected for the current training phase. This mechanism prevents memory usage observations from different training epochs from being mixed together while still allowing the separate mem accounting path to maintain the correct amount of memory currently owned by the client.


## CPU Tracking
The `TfwAdaptiveLimitLock cpu_lim` structure is used to track per-client CPU consumption. As described earlier, `cpu_lim` is stored inside the common `TfwClientAdaptiveLimits` structure referenced from TfwClient. Rather than measuring CPU utilization directly, the subsystem estimates client CPU consumption using the number of CPU cycles spent processing client requests/responses. Processing time is measured using `get_cycles` and accumulated into an exponentially weighted moving average (EMA).
At the beginning of `ss_tcp_process_data`, the current CPU cycle counter is recorded: `u64 time_begin = get_cycles();`. At the end of `skb` processing, in the `on_rcv_finish` callback, the elapsed processing time is calculated as `delta_time = get_cycles() - time_begin;`. This value is treated as the CPU usage and is used for adaptive-limits accounting.

Using an EMA instead of a raw accumulated counter is important for CPU tracking because CPU consumption is inherently time-dependent. A simple counter would grow monotonically throughout the lifetime of a client, making it unsuitable for anomaly detection. The EMA provides a bounded and continuously adapting estimate of recent CPU activity.

### Time Source Selection

The implementation uses `get_cycles()` rather than `ktime_get_ns()` as the time source for CPU usage tracking and EMA (Exponential Moving Average) calculations.

The primary reason is that `get_cycles()` provides lower overhead than `ktime_get_ns()`, making it more suitable for performance-sensitive code paths. Although end-to-end benchmarking did not reveal a measurable difference in overall system performance, the lower cost of cycle-counter reads remains preferable for hot-path telemetry.

An additional consideration is numerical stability. The EMA calculation uses the elapsed time (`delta`) between observations. When `ktime_get_ns()` is used, `delta` values are expressed in nanoseconds and may become very large, particularly when observations are infrequent. Since the adaptive-limits subsystem relies entirely on fixed-point integer arithmetic, large time deltas can significantly increase the magnitude of intermediate calculations and may theoretically lead to overflow, even when 128-bit accumulators are used in large-scale deployments involving millions of clients.

In contrast, `get_cycles()` provides sufficient timing precision while keeping the numerical range of `delta` values substantially smaller. This results in a more practical operating range for EMA calculations, reduces the risk of arithmetic overflow, and simplifies fixed-point computations without sacrificing the accuracy required for anomaly detection.

### Training mode
CPU usage is tracked in two places.
The primary accounting path is `the on_rcv_finish` callback executed at the end of `ss_tcp_process_data`. This captures the CPU time spent processing incoming client data. In addition, CPU usage is also accounted during response processing in `tfw_http_msg_process_generic`. In this case, CPU cycles are measured at function entry and exit:
```C
u64 time_begin = get_cycles();
/* response processing */
delta_time = get_cycles() - time_begin;
```
This allows CPU costs associated with response handling to be attributed to the corresponding client. Unlike connection, request, and memory tracking, CPU accounting uses an exponentially weighted moving average rather than a simple counter. This provides a smoothed estimate of recent CPU consumption while reducing sensitivity to short processing spikes. The EMA is updated using the following helper:
```C
static inline void
tfw_adaptive_limits_counter_add_ema(TfwAdaptiveLimitLock *limit, int delta)
{
	s64 *ema = this_cpu_ptr(limit->counter);
	static const unsigned int ema_alpha_shift = 4;

	*ema += ((s64)delta - *ema) >> ema_alpha_shift;
}
```
The update corresponds to: `EMAnew = EMAold + α × (sample − EMAold)`, where `α = 1 / 16`
Using an EMA allows the system to track sustained increases in CPU consumption while filtering short-lived fluctuations. As with other adaptive-limit metrics, the current value is aggregated from all per-CPU counters in the `on_rcv_finish` callback. If the aggregated value exceeds the previously observed maximum, `max`, `sum`, and `sumsq` are updated accordingly.

### Defence mode 
During defence mode, CPU accounting is performed in the same manner as during training. At the end of client data processing, the current CPU usage estimate is obtained by summing all per-CPU EMA values. The resulting value is then evaluated using the statistics collected during the training phase. The z-score calculation is performed through the common adaptive-limits infrastructure
(`tfw_adaptive_limits_defence_cpu` ultimately calls `tfw_adaptive_limits_defence` with the corresponding statistics structure). If the calculated z-score exceeds the configured threshold, the client activity is considered anomalous. In this case, the client connection is terminated and, depending on the configuration, the client IP address may also be temporarily blocked.

### Epoch handling
CPU accounting uses the same epoch handling mechanism as other adaptive-limit metrics. When a new training epoch begins, the `cpu_lim` structure is lazily reinitialized on first access. The per-CPU EMA values and the recorded maximum are reset, ensuring that statistics collected during previous training epochs do not affect the current training phase. 


## Performance
Performance measurements were conducted to verify that the adaptive-limits subsystem does not introduce a measurable performance regression.
Benchmark results:

```text
Training mode:
finished in 50.03s, 1262705.36 req/s, 977.65MB/s
finished in 50.03s, 1272612.60 req/s, 986.17MB/s
finished in 50.03s, 1264687.98 req/s, 980.56MB/s
Defence Mode:
finished in 50.03s, 1272456.16 req/s, 986.58MB/s
finished in 50.03s, 1263205.18 req/s, 979.41MB/s
finished in 50.03s, 1256503.58 req/s, 974.21MB/s
master:
finished in 50.03s, 1253438.10 req/s, 970.45MB/s
finished in 50.03s, 1253206.98 req/s, 970.75MB/s
finished in 50.03s, 1248472.82 req/s, 967.99MB/s

```
The results show no statistically significant throughput degradation in either training or defence mode. This is primarily achieved through the use of per-CPU accounting structures on the request-processing hot path. Most metric updates are performed using lockless per-CPU counters, while atomic operations are only required when updating client maxima. Furthermore, maximum updates are performed only once per invocation of `ss_tcp_process_data`, rather than for every individual event. As a result, the adaptive-limits subsystem introduces negligible overhead while providing continuous statistics collection and anomaly detection capabilities.
