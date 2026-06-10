**Training Mode:**
During the training phase the system collects per-client metrics for each new event and aggregates global statistics required for subsequent z-score calculation in defence mode. For each client only the current maximum number of connections/requests/memory usage is stored. Global statistics include:

- number of samples ("n", i.e. number of active clients),
- sum of values ("sum"),
- sum of squared values ("sumsq").

At the end of the training phase the mean and standard deviation are computed and later used for z-score calculation during anomaly detection.
    sum
μ = ─── -> mean
     n

     sumsq
σ² = ───── - μ² -> variance
       n

σ = √σ² -> standard deviation

    x - μ
z = ───── -> z-score, calculated for each new value (x)
      σ

Several approaches for online variance calculation were evaluated, including Welford’s algorithm and the sum/sumsq method.

The classical Welford algorithm was found to be unsuitable for this workload. In its original form Welford assumes an append-only stream of samples, where each new observation increases the total sample count. In our case, however, "n" represents the number of clients rather than the number of events. For each client we continuously update the current maximum number of connections/requests/memory usage. Therefore, when a client metric changes, the previous value must first be removed from the statistics and only then the new value can be added (we need replace operation). This requires a modified reversible version of Welford’s algorithm, which significantly complicates the implementation.

In addition, kernel-space constraints prohibit floating-point arithmetic, requiring the use of fixed-point integer arithmetic instead. While Welford’s algorithm is known for its excellent numerical stability with floating-point arithmetic, its fixed-point implementation introduces truncation errors during repeated division operations. In workloads where metric values remain relatively small and close to each other (e.g. connection/request maxima), these rounding errors accumulate over time and may lead to noticeable precision degradation. Since we track client memory usage in pages, we have also quite limited range for it's maxima.

Benchmarking (see `benchmark_training` folder) also demonstrated that the modified fixed-point Welford implementation is slower than the alternative approach due to additional arithmetic operations, divisions, and the need to perform sofisticated replace operation for each update.

Benchmark                       Time             CPU   Iterations
BM_welford_fixed_point       6.75 ns         6.75 ns    102297118
BM_sum_sumsq                 4.55 ns         4.55 ns    151356982

Accuracy was also calculated for four different cases.
client maximum increases +1 on each iteration (same as for connection tracking).
accuracy (exact, sum_sumsq): ( 8.33333e+06, 8.33333e+06 )
accuracy (exact, welford): ( 8.33333e+06, 8.33334e+06 )
client maximum randomly increases in a range (1 - 10) on each iteration (possible for non idempodent request tracking, since we use algorithm at the end of the `ss_tcp_process_data`, when we can already process several requests). 
accuracy (exact, sum_sumsq): ( 2.55257e+08, 2.55257e+08 )
accuracy (exact, welford): ( 2.55257e+08, 2.55257e+08 )
client maximum randomly increases in a range (1 - 100) on each iteration
accuracy (exact, sum_sumsq): ( 2.11362e+10, 2.11362e+10 )
accuracy (exact, welford): ( 2.11362e+10, 2.11362e+10 )
clien maximum randomly increases in a range (1 - 1000) on each iteration (possible for memory usage tracking, since we use algorithm at the end of the `ss_tcp_process_data`, and track memory usage in pages). 
accuracy (exact, sum_sumsq): ( 2.15425e+10, 2.15425e+10 )
accuracy (exact, welford): ( 2.15425e+10, 2.15426e+10 )

As we can see both these algorithms demonstrate good accuracy (sum/sumsq method little bit better!), but sum of squares method is faster. As a result, the implementation uses the sum of values / sum of squares method (sum/sumsq method). This approach maintains:

- the sum of all values,
- the sum of squared values,
- the total number of clients.

The variance is then computed using the standard relation:

[
Var(X) = E[X^2] - E[X]^2
]

This method is generally considered less numerically stable than Welford’s algorithm because subtracting two large close values may lead to catastrophic cancellation and precision loss. However, this issue primarily affects workloads with very large numbers and extremely small variance.

For the considered workload, where client metrics are bounded and remain relatively small, the sum/sumsq approach provides sufficient numerical accuracy while being substantially simpler and faster. It also maps naturally to the mutable per-client update model used by the system and avoids the complexity of reversible online variance algorithms.
(It should also be noted that accurate and stable calculation of CPU consumption in streaming or long-running workloads may require the use of Welford’s algorithm).

We calculate mean and standard deviation using SCALE_SHIFT = 10 - fixed-point scaling factor used for integer arithmetic. We also save both these values in scaled format for accuracy, because linux kernel code avoids floating point operations.

**Defence Mode**
Each new observation is evaluated using z = ((x << SCALE_SHIFT) − mean) / std (Where SCALE_SHIFT = 10 - the same scaling factor, which is used during mean and standart deviation calculation), so all fractional calculations (e.g. mean, variance, z-score) are performed using scaled integers). If z > configured_threshold the event is considered anomalous. Reject request / connection, drop connection with TCP RST and optionally block client by IP.

**Disabled Mode**
Internal state used during transitions. Ensures safe updates of shared data (via RCU synchronization). Also I think it's better to implement this state also, not only as internal state, to prevent any additional calculations, when it is not necessary (for example administrator don't need this security feature at all).

**Connection Count Tracking**
In`TfwClient` structure we additionally store `unsigned int conn_max`, `int conn_curr` and `u16 conn_training_epoch`. We don't need any lock here, because all this fields are updated under private `ra->lock` in frang. We use new implemented function `tfw_client_training_adjust_conn_num` both for training and defence mode.

**Training mode**
`conn_curr` is incremented/decremented.
Track maximum concurrent connections (`conn_max`). When max increases - compute `delta1 = new_max - old_max` and `delta2 = new_max² - old_max²` and use this values to update `sum` and `sumsq`.
"sum" and "sumsq" are accumulated values used for online calculation of the mean and standard deviation without storing the full history of samples.

The algorithm keeps:

- "sum = Σx"
- "sumsq = Σx²"

which allows computing:

- mean:
- variance:

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

For example, the following dataset (1000000000, 1000000001, 999999999, 1000000000) may become problematic. In this case - mean ≈ 1,000,000,000, standard deviation ≈ 1.
The variance computation subtracts two extremely large nearly identical numbers, which can cause catastrophic cancellation and precision loss. In contrast, a connection telemetry workload such as (1000,
1005, 1003, 998, 1010) is generally safe because:

- values are integer-based,
- the variance is reasonably large relative to the mean,
- the dynamic range is moderate,

According to our investigation (described at the beginning of the document for connections, requests and memory usage this simplest algorithm is better both in terms of performance and accuracy).

**Defence mode**
Track `conn_curr` on each new opened connection. Calculate `z = ((conn_curr << SCALE_SHIFT) - mean) / std` if `z > threshold` reject connection and block client by IP if necessary.

**Epoch handling**
Each connection tagged with training_epoch (we add new field to `tempesta_sock` and save epoch in this field) and also we add `conn_training_epoch` to the `TfwClient` structure. We need epoch handling  to zero history from previous trainging and prevent mixing old and new training data. When we call `tfw_client_training_adjust_conn_num` (function for both trainging and defence mode) first of all we check `if (delta < 0 && *training_epoch < g_training_epoch)` and immediately return if condition is true (`delta < 0` means that connection is dropped and belongs to previous epoch). If `delta > 0` we set `*training_epoch = g_training_epoch` to the new established connection (when connection is opening it always belongs to the new epoch if trainging enabled!). In trainging mode we also check
`if (cli->conn_training_epoch < g_training_epoch)` to zero all client training data (`conn_curr` and `conn_max`).

**Request Count Tracking (Non-idempotent) / Client Memory Usage Tracking**
We track non-idempotent requests and client memory usage in the same way. First of all we implement `TfwClientCounter` structure to track non idempotent requests count and client memory usage. 
```C
/*
 * lock				- spinlock for serialized reset of @max and @counter when a
 *					  new training epoch starts.
 * max				- maximum observed value of the tracked metric within the
 *					  current training epoch (e.g. peak number of in-flight
 *					  non-idempotent requests);
 * counter			- percpu array to track current value of the tracked metric;
 * @epoch			- training epoch identifier. Compared against the global
 *					  @g_training_epoch to detect epoch change and trigger
 *					  reinitialization of @max and @counter.
 */
typedef struct tfw_client_counter_t {
	spinlock_t			lock;
	atomic_long_t		max;
	long 	__percpu	*counter;
	u16					epoch;
} TfwClientCounter;
```

We also implement parent structure to track non idempotent requests count with `kill_work` to be able to delete this structure safely asynchroniously. 
```C
/*
 * Non idempotent request accounting structure for Tempesta FW.
 *
 * @counter	- 	  non idempotent requests accounting storage;
 * @kill_work	- Workqueue item used for asynchronous structure
 *				  cleanup/destruction;
 */
typedef struct tfw_client_req_counter_t {
	TfwClientCounter	counter;
	struct work_struct	kill_work;
} TfwClientReqCounter;
```

We also implement parent structure to track client memory usage.
```C
/*
 * Client memory accounting structure for Tempesta FW.
 *
 * @counter	- memory accounting storage;
 * @mem		- Per-CPU memory accounting storage. Used for
 *			  soft/hard memory limits. Not zeroed on the new
 *			  training epoch;
 * @refcnt	- Per-CPU reference counter. Provides scalable and
 *			  thread-safe reference tracking on SMP systems with
 *			  minimal contention;
 * @kill_work	- Workqueue item used for asynchronous structure
 *				  cleanup/destruction;
 */
typedef struct tfw_client_mem_t {
	TfwClientCounter	counter;
	long	__percpu	*mem;	
	struct percpu_ref	refcnt;
	struct work_struct	kill_work;
} TfwClientMem;
```

We add new field `training_epoch` to several structures (`request` structure, `pool` structure and `skb->cb`) to track is event belongs to current trainging epoch or no.
When we add (in `tfw_http_req_enlist`)/remove (in `tfw_http_req_nip_delist`) non-idempotent request from the server connection queue, we call new implemented function `void tfw_client_counter_training_adjust_req(TfwClient *cli, int delta, unsigned int *training_epoch)`. We also call `tfw_client_counter_training_adjust_mem` when we allocate some memory for current client. Both these functions call `void tfw_client_counter_training_adjust(TfwClientCounter *counter, int delta, void (*adjust_new_client)(void), u16 *training_epoch)` for real event tracking. In this function (same as we do for connections) first of all we check if event belongs to the current training epoch and skip it if doesn't belong.
```C
/*
 * Ignore event removing events from previous training epochs. If we
 * add new request (`delta > 0`) it always belongs to the new epoch.
 * For memory tracking there is a case when we make allocation in the
 * new epoch for the pool or skb which was allocated in the previous
 * epoch, we should also ignore such cases (there is only one epoch
 * identifier for structure, which we set on it's first tracking.
 * `training_epoch` - is a new field in the appropriate structure.
 */
if ((*training_epoch || delta < 0)
    && *training_epoch < g_training_epoch)
	return
else if (!(*training_epoch) && delta > 0)
	*training_epoch = g_training_epoch;
```

We also check epoch for the whole `TfwClientCounter` structure and zero statistic for the new training epoch.
```C
/*
 * We increment `g_training_epoch` each time when we start new
 * training, when we are sure that all threads don't use `max`
 * and `counter`. During training all threads call this function
 * before use `counter` and `max`, so we are sure that `counter`
 * and `max` will be zeroed on the start of the new training.
 * We make first check to prevent unnecessary lock on the hot
 * path on each call.
 */
if (counter->epoch < g_training_epoch) {
	spin_lock_bh(&counter->lock);
	if (likely(counter->epoch < g_training_epoch)) {
		int cpu;

		for_each_online_cpu(cpu)
			*(per_cpu_ptr(counter->counter, cpu)) = 0;
		atomic_long_set(&counter->max, 0);
		counter->epoch = g_training_epoch;
		new_client = true;
	}
	spin_unlock_bh(&counter->lock);
}
```
Finally we increment count of clients (`new_client` == true) and appropritate percpu `counter`. This function works same both for the `trainging` and `defence` mode.
The real event adujusting is implemented int the `tfw_http_conn_recv_finish` callback which is called at the end of the `ss_tcp_process_data` (to prevent performance degradation). In `trainging` mode we track maximum count of non idempodent requests for the client / maximum memory usage for the client. When max increases - compute `delta1 = new_max - old_max` and `delta2 = new_max² - old_max²` and use this values to update `sum` and `sumsq` (same as for connections we use more simple and fast `sum/sumsq` algorithm).
```C
static inline bool
tfw_client_counter_change_max(TfwClientCounter *counter, long curr,
			      u64 *delta1, u64 *delta2)
{
	long old_max = atomic_long_read(&counter->max);

	/*
	 * Can be called concurrentrly on other cpu with different
	 * curr value, so we need syncronization here.
	 */
	do {
		if (curr <= old_max)
			return false;
	} while (!atomic_long_try_cmpxchg(&counter->max, &old_max, curr));

	*delta1 = curr - old_max;
	*delta2 = (u64)curr * curr - (u64)old_max * old_max;

	return true;
}

static bool
tfw_client_counter_training_check(TfwClientCounter *counter,
				  void (*adjust_num)(u64, u64),
				  bool(*defence)(u64))
{
	u64 delta1, delta2;
	long curr;

	if (tfw_mode_is_disabled())
		return true;

	curr = tfw_client_counter_get(counter);
	if (tfw_mode_is_defence())
		return defence(curr);

	if (tfw_client_counter_change_max(counter, curr, &delta1, &delta2))
		adjust_num(delta1, delta2);

	return true;
}
```
`adjust_num` - function to track `sum/sumsq` values for non-idempotent requests/memory usage.
`defence` - function to calculate `z-score` according current event count and return true/false depends on if calculated `z-score` less or greater then configured threshold.    

Since we use percpu aggregation in `tfw_client_req_count` and `atomic` only once at the end of the `ss_tcp_process_data` it doesn't affect performance.
Performance statistic:
```
trainging:
finished in 50.03s, 1102774.42 req/s, 855.02MB/s
finished in 50.03s, 1094190.10 req/s, 848.37MB/s
finished in 50.06s, 1119276.64 req/s, 867.82MB/s
finished in 50.06s, 1111121.46 req/s, 861.49MB/s
defence:
finished in 50.08s, 1085963.46 req/s, 841.99MB/s
finished in 50.08s, 1102987.66 req/s, 855.19MB/s
finished in 50.08s, 1099386.24 req/s, 852.40MB/s
master:
finished in 50.03s, 1083363.94 req/s, 838.78MB/s
finished in 50.03s, 1083501.30 req/s, 839.42MB/s
finished in 50.03s, 1081202.90 req/s, 838.30MB/s
```
We check performance statistics for GET requests with cache, so we don't check how non idempotent requests tracking influence on perfomance. But we track memory usage much more often, so it seems that if doesn't affect perfomance, non idempotent requests counting also doesn't affect it. In `defence` mode we use `curr = tfw_client_counter_get(cli);` to calculate `z-score` amd compare it with configured threshold (in `defence` function) and drop client connection (and block client by ip, if necessary).

We also implement some structures for fast memory allocation, during client creation. First of all we implement new data structure
```C
typedef struct tfw_client_pool_obj_t {
	union {
		TfwClientCounter 		counter;
		struct tfw_client_pool_obj_t	*next_free;
	};
	DECLARE_FLEX_ARRAY(char, data);
} TfwClientPoolObj;
```
and special pool
```C
typedef struct {
	TfwClientPoolObj 			*obj;
	TfwClientPoolObj			*free_list;
	tfw_client_pool_release_t		release;
	size_t					obj_size;
	unsigned int				size;
	unsigned int				order;
} TfwClientPool;
```
Then we create two pools one for `TfwClientReqCounter` and one for `TfwClientMem`. (Previously we have one pool of `TfwClientMem` structures). We initialize these pools when Tempesta FW start work and destroy when Tempesta FW unload. We use these pools for fast memory allocations. (In fact we just rework current `TfwClientMem` allocation mechanizm to have ability to allocate `TfwClientReqCounter` in the same way using common data structures and functions).





**CPU Tracking**
In addition to `TfwTrainingStat` implement structure and per-cpu array of this structures.
```C
/**
 * Exponential moving average (EMA) tracker for per-CPU time usage.
 *
 * The structure is used to accumulate execution time deltas and maintain
 * a smoothed estimate (EMA) of CPU consumption.
 *
 * @last_ts	- timestamp of the last update (in ns). Used to compute
 *		  time delta between consecutive measurements;
 * @ema		- current exponential moving average of CPU usage;
 * @pending_cpu	- accumulated raw CPU time (in ns) since the last EMA
 *		  update. This value is periodically folded into @ema;
 */
typedef struct {
    u64 last_ts;
    s64 ema;
    u64 pending_cpu;
} TfwCpuEma;
```
Save time at the beginning of SoftIRQ shot and  check CPU usage at the end of SoftIRQ shot (to prevent perfomance regression in case when we do it on each request) .

**Training mode**
Calculate `delta_cpu = now - begin_time;`, update CPU ema.
```C
/**
 * Update per-client CPU usage EMA.
 * @cpu_ema: per-CPU EMA state for the client.
 * @delta_cpu: CPU time consumed since the last measurement (in ns).
 *
 * Accumulates raw CPU time in @pending_cpu and periodically folds it
 * into the exponential moving average (@ema).
 *
 * The update is performed only if enough time (@min_time_to_adjust)
 * has passed since the previous update to avoid excessive noise and
 * high-frequency recalculations.
 *
 * The function:
 *   - computes elapsed time (@dt);
 *   - converts accumulated CPU time into normalized usage value;
 *   - applies time-based decay (older history loses weight);
 *   - updates EMA using a combination of decay and smoothing factor.
 */
static void
tfw_client_update_cpu_ema(TfwCpuEma *cpu_ema, u64 delta_cpu)
{
	u64 now = ktime_get_ns();
	u64 dt = now - cpu_ema->last_ts;
	u64 usage, decay, total_cpu = 0;
	static const u64 time_to_forget_ns = 100000000;
	static const u64 min_time_to_adjust = 1000;
	static const unsigned int ema_alpha_shift = 4;

	cpu_ema->pending_cpu += delta_cpu;
	if (unlikely(dt < min_time_to_adjust))
		return;

	cpu_ema->last_ts = now;
	swap(cpu_ema->pending_cpu, total_cpu);
	usage = (total_cpu << SCALE_SHIFT) / dt;
	decay = (dt << SCALE_SHIFT) / time_to_forget_ns;

	if (decay > (1 << SCALE_SHIFT))
		decay = 1 << SCALE_SHIFT;
	cpu_ema->ema = cpu_ema->ema *
		((1 << SCALE_SHIFT) - decay) >> SCALE_SHIFT;
	cpu_ema->ema += ((s64)usage - (s64)cpu_ema->ema) >> ema_alpha_shift;
}
```
Pass `delta = new_ema - prev_ema` to  `tfw_client_training_adjust_cpu_num` which do the same as ` `tfw_client_training_adjust_req_num`.

**Defence mode**
In defence mode use `delta_ema` on each SoftIRQ shot to calculate `z = (delta_ema - mean) / std` and if calculated `z > threshold` reject connection with TCP RST and block client by IP if necessary.

**Current method and alternatives**

**Alternatives**
1. Use raw CPU time
* ✔ simple
* ✔ accuracy
* ❌ very noisy
* ❌ strong peaks
* ❌ Bad normalization
2. Sliding window average (store CPU usage for the last N ms)
3. Use `ema` directly. Currently we measure change, not level (constant high CPU → delta ≈ 0 → no detection).  

