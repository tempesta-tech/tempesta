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

The classical Welford algorithm was found to be unsuitable for this workload. In its original form Welford assumes an append-only stream of samples, where each new observation increases the total sample count. In our case, however, "n" represents the number of clients rather than the number of events. For each client we continuously update the current maximum number of connections/requests/memory/cpu usage. Therefore, when a client metric changes, the previous value must first be removed from the statistics and only then the new value can be added (we need replace operation). This requires a modified reversible version of Welford’s algorithm, which significantly complicates the implementation.

In addition, kernel-space constraints prohibit floating-point arithmetic, requiring the use of fixed-point integer arithmetic instead. While Welford’s algorithm is known for its excellent numerical stability with floating-point arithmetic, its fixed-point implementation introduces truncation errors during repeated division operations. In workloads where metric values remain relatively small and close to each other (e.g. connection/request maxima), these rounding errors accumulate over time and may lead to noticeable precision degradation. Since memory usage is tracked in pages and CPU usage is represented as an EMA value, the range of possible maximum values is also relatively limited.

Benchmarking (see `benchmark_training` folder) also demonstrated that the modified fixed-point Welford implementation is slower than the alternative approach due to additional arithmetic operations, extra division steps, and the need to perform a more sophisticated replace operation for each update.

Benchmark                       Time             CPU   Iterations
BM_welford_fixed_point       6.75 ns         6.75 ns    102297118
BM_sum_sumsq                 4.55 ns         4.55 ns    151356982

Accuracy was also calculated for four different cases.
client maximum increases +1 on each iteration (same as for connection tracking).
accuracy (exact, sum_sumsq): ( 8.33333e+06, 8.33333e+06 )
accuracy (exact, welford): ( 8.33333e+06, 8.33334e+06 )
client maximum randomly increases in a range (1 - 10) on each iteration (possible for non-idempotent request tracking, since we use algorithm at the end of the `ss_tcp_process_data`, when we can already process several requests). 
accuracy (exact, sum_sumsq): ( 2.55257e+08, 2.55257e+08 )
accuracy (exact, welford): ( 2.55257e+08, 2.55257e+08 )
client maximum randomly increases in a range (1 - 100) on each iteration
accuracy (exact, sum_sumsq): ( 2.11362e+10, 2.11362e+10 )
accuracy (exact, welford): ( 2.11362e+10, 2.11362e+10 )
client maximum randomly increases in a range (1 - 1000) on each iteration (possible for memory usage tracking, since we use algorithm at the end of the `ss_tcp_process_data`, and track memory usage in pages). 
accuracy (exact, sum_sumsq): ( 2.15425e+10, 2.15425e+10 )
accuracy (exact, welford): ( 2.15425e+10, 2.15426e+10 )

As shown above, both algorithms provide very good accuracy, with the sum/sumsq method demonstrating slightly better results in the evaluated scenarios. But sum of squares method is faster. As a result, the implementation uses the sum of values / sum of squares method (sum/sumsq method). This approach maintains:

- the sum of all values,
- the sum of squared values,
- the total number of clients.

The variance is then computed using the standard relation:

Var(X) = E[X²] − E[X]²

This is a classic streaming statistics approach commonly referred to as the “sum/squared-sum” method or “naive variance algorithm” (Wikipedia — “Algorithms for calculating variance”)
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

We calculate mean and standard deviation using SCALE_SHIFT = 10 - fixed-point scaling factor used for integer arithmetic. We also save both these values in scaled format for accuracy, because linux kernel code avoids floating point operations.

### Defence Mode
Each new observation is evaluated using:

z = ((x << SCALE_SHIFT) - mean) / std

where SCALE_SHIFT = 10 is the fixed-point scaling factor used during mean and standard deviation calculation. So all fractional calculations (e.g. mean, variance, z-score) are performed using scaled integers). If z > configured_threshold the event is considered anomalous. Drop connection with TCP RST and optionally block client by IP.

### Disabled Mode
Internal state used during transitions. Ensures safe updates of shared data (via RCU synchronization). This mode can also be exposed as a user-configurable operating mode rather than being used solely as an internal transition state. Doing so completely eliminates the overhead associated with statistics collection and anomaly detection when the feature is not required.


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
 * @num   - number of samples (e.g. number of clients).
 * @mean  - calculated mean (scaled by SCALE_SHIFT).
 * @std   - calculated standard deviation (scaled).
 */
struct stats {
	u64 __percpu	*sumsq;
	u64 __percpu	*sum;
	u32 __percpu	*num;
	u64 			mean;
	u64 			std;
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
								  u64 delta2)
{
	struct stats *s;

	rcu_read_lock();

	/*
	 * We check mode every where before call this function (see appropriate
	 * functions e.g. `tfw_adaptive_limits_check_conn_num`). But there is a
	 * race - mode can be switched after appropriate check and before this
	 * function call. Here we check mode again for safe access `stats`
	 * pointer under `rcu`.
	 * During switching modes we first of all disable trainging mode (using
	 * `tfw_adaptive_limits_disable_training_or_defence`) and then call
	 * `synchronize_rcu`, so we will wait until we finish to collect
	 * statistic before free `stats` pointers.
	 */
	if (likely(!tfw_adaptive_limits_mode_is_disabled())) {
		s = rcu_dereference(g_stats);
		this_cpu_add(*s->sum, delta1);
		this_cpu_add(*s->sumsq, delta2);
	}

	rcu_read_unlock();
}
```

We also implement some functions for fast track count of events in per cpu storage without any lock.
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

	if (tfw_adaptive_limits_mode_is_disabled())
		return;

	new_event = delta > 0 && !(*epoch);
	if (!tfw_adaptive_limits_check_and_set_epoch(epoch, new_event))
		return;

	__tfw_adaptive_limits_acc(limit, delta, adjust_new_client, add);
}
```
We also update `max` value for further `sum`/`sumsq` calculation only at the end of  `ss_tcp_process_data` function to prevent performance degradation.
```C
static inline bool
tfw_adaptive_limits_change_max(TfwAdaptiveLimitLock *limit, s64 curr,
			       u64 *delta1, u64 *delta2)
{
	s64 old_max = atomic64_read(&limit->max);

	/*
	 * Can be called concurrentrly on other cpu with different
	 * curr value, so we need syncronization here.
	 */
	do {
		if (curr <= old_max)
			return false;
	} while (!atomic64_try_cmpxchg(&limit->max, &old_max, curr));

	*delta1 = (u64)curr - (u64)old_max;
	*delta2 = (u64)curr * curr - (u64)old_max * old_max;

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
	u64 total_sumsq = 0;
	u64 total_sum = 0;
	u32 num_clients = 0;
	u64 variance;

	total_sumsq = tfw_percpu_u64_counter_sum(s->sumsq);
	total_sum = tfw_percpu_u64_counter_sum(s->sum);
	num_clients = tfw_percpu_u32_counter_sum(s->num);

	if (!unlikely(num_clients))
		return;

	s->mean = (total_sum << SCALE_SHIFT) / num_clients;
	/*
	 * Population variance:
	 *
	 * Var(X) = E[X²] - E[X]²
	 *
	 * All values are represented using fixed-point arithmetic
	 * scaled by SCALE_SHIFT.
	 */
	variance = ((total_sumsq << SCALE_SHIFT) / num_clients) -
		((s->mean * s->mean) >> SCALE_SHIFT);
	s->std = int_sqrt64(variance << SCALE_SHIFT);
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

	rcu_read_lock();

	if (!tfw_adaptive_limits_mode_is_defence()) {
		rcu_read_unlock();
		return true;
	}

	p = rcu_dereference(g_stats);

	if (!__calculate_z_score(val, p, &z_score)) {
		rcu_read_unlock();
		return true;
	}

	rcu_read_unlock();

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
During training, `conn_lim->counter` is incremented when a connection is established and decremented when it is closed.
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
	u64 delta1, delta2;
	unsigned int old_max;
	bool new_client = false;
	bool new_event;

	if (tfw_adaptive_limits_mode_is_disabled())
		return true;

	new_event = delta > 0 && !(*epoch);
	if (!tfw_adaptive_limits_check_and_set_epoch(epoch, new_event))
		return true;

	if (tfw_adaptive_limits_mode_is_defence()) {
		limit->counter += delta;
		WARN_ON(limit->counter < 0);

		if (delta < 0)
			return true;
		return tfw_adaptive_limits_defence_conn_num(limit->counter);
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
		return true;
	limit->max = limit->counter;
	delta1 = limit->counter - old_max;
	delta2 = (u64)limit->counter * limit->counter -
		(u64)old_max * old_max;
	tfw_adaptive_limits_adjust_conn_num(delta1, delta2);

	return true;
}
```

As discussed earlier, the sum/sumsq approach provides sufficient numerical accuracy for this workload while being simpler and faster than the evaluated reversible fixed-point implementation of Welford’s
algorithm.

### Defence mode
During defence mode, `conn_lim->counter` tracks the current number of active connections associated with the client. Whenever a new connection is established, the current connection count is
evaluated using:

`z = ((conn_lim->counter << SCALE_SHIFT) - mean) / std`

where `mean` and `std` are the values calculated during the preceding training phase. If the calculated z-score exceeds the configured threshold, the connection is considered anomalous and is rejected. Depending on the configuration, the client IP address may also be temporarily blocked.

### Epoch handling
Each connection is tagged with the training epoch identifier (A dedicated epoch field is added to `tempesta_sock` and initialized when the connection is first observed). Epoch handling is required to prevent statistics collected during different training phases from being mixed together. If an event originates from a connection that belongs to an older training epoch, the event is ignored and does not contribute to the statistics of the current epoch. We also check epoch for `TfwAdaptiveLimit` structure and lazy zero statistic (`counter` and `max`) on the new training epoch.


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
Non-idempotent request tracking uses the client connection epoch identifier If a new training epoch begins while an existing connection remains active, requests originating from that connection continue to carry the previous epoch identifier. Such requests are ignored and do not contribute to the statistics collected for the new training epoch. This mechanism prevents mixing observations collected during different training phases and ensures that all statistics correspond to a single training generation. Because training periods are expected to be relatively long, only a small number of active connections typically survive an epoch transition. Consequently, the number of ignored requests is negligible and has no meaningful impact on the resulting statistics.


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
Memory allocations are associated with the training epoch in which the corresponding object was created. To support this, a dedicated `u16 epoch` field is added to both `TfwPool` and `TFW_SKB_CB`. The current training epoch is stored when the pool or skb is created. During subsequent allocation and deallocation operations, the stored epoch is compared against the current global training epoch. If the object belongs to an older training epoch, the corresponding memory accounting event is ignored by the adaptive-limits subsystem and does not contribute to the statistics collected for the current training phase. This mechanism prevents memory usage observations from different training epochs from being mixed together while still allowing the separate mem accounting path to maintain the correct amount of memory currently owned by the client.


## CPU Tracking
The `TfwAdaptiveLimitLock cpu_lim` structure is used to track per-client CPU consumption. As described earlier, `cpu_lim` is stored inside the common `TfwClientAdaptiveLimits` structure referenced from TfwClient. Rather than measuring CPU utilization directly, the subsystem estimates client CPU consumption using the number of CPU cycles spent processing client requests/responses. Processing time is measured using `get_cycles` and accumulated into an exponentially weighted moving average (EMA).
At the beginning of `ss_tcp_process_data`, the current CPU cycle counter is recorded: `u64 time_begin = get_cycles();`. At the end of `skb` processing, in the `on_rcv_finish` callback, the elapsed processing time is calculated as `delta_time = get_cycles() - time_begin;`. This value is treated as the CPU usage and is used for adaptive-limits accounting.

Using an EMA instead of a raw accumulated counter is important for CPU tracking because CPU consumption is inherently time-dependent. A simple counter would grow monotonically throughout the lifetime of a client, making it unsuitable for anomaly detection. The EMA provides a bounded and continuously adapting estimate of recent CPU activity.

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
No mode:
finished in 50.03s, 1244320.00 req/s, 963.47 MB/s
finished in 50.03s, 1242224.16 req/s, 962.34 MB/s
finished in 50.03s, 1249728.72 req/s, 968.96 MB/s

Training mode:
finished in 50.03s, 1245938.16 req/s, 966.02 MB/s
finished in 50.03s, 1224614.22 req/s, 949.49 MB/s
finished in 50.03s, 1238774.08 req/s, 960.47 MB/s

Defence mode:
finished in 50.03s, 1257063.30 req/s, 974.65 MB/s
finished in 50.03s, 1231469.62 req/s, 954.80 MB/s
finished in 50.03s, 1240568.38 req/s, 961.86 MB/s

Master:
finished in 50.03s, 1209948.62 req/s, 936.78 MB/s
finished in 50.03s, 1221063.28 req/s, 945.85 MB/s
finished in 50.03s, 1221093.04 req/s, 946.76 MB/s
```
The results show no statistically significant throughput degradation in either training or defence mode. This is primarily achieved through the use of per-CPU accounting structures on the request-processing hot path. Most metric updates are performed using lockless per-CPU counters, while atomic operations are only required when updating client maxima. Furthermore, maximum updates are performed only once per invocation of `ss_tcp_process_data`, rather than for every individual event. As a result, the adaptive-limits subsystem introduces negligible overhead while providing continuous statistics collection and anomaly detection capabilities.
