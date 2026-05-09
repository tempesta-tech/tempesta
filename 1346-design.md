**Training Mode:**
Collects per-client metrics on each new event aggregates global statistics: number of samples (num of clients),  sum of values (sum), sum of squares (sumsq). At the end of training computes mean and standard deviation, which will be used for z-score calculation in defence mode.
**Defence Mode**
Each new observation is evaluated using z=std / (x−mean). If z > configured_threshold he event is considered anomalous. 
Reject request / connection, drop connection with TCP RST and optionally block client by IP.
**Disabled Mode**
Internal state used during transitions. Ensures safe updates of shared data (via RCU synchronization). May be it's better to implement this state also, not only as internal state, to prevent any additional calculations, when it is not necessary.

**Connection Count Tracking**
In`TfwClient` structure we additionally store `unsigned int conn_max`, `int conn_curr` and `unsigned int conn_training_epoch`. We don't need any lock here, because all this fields updated under private `ra->lock` in frang.
We use new implemented function `tfw_client_training_adjust_conn_num` both for training and  defence mode.

**Training mode**
`conn_curr` is incremented/decremented.
Track maximum concurrent connections (`conn_max`). When max increases - compute `delta1 = new_max - old_max` and `delta2 = new_max² - old_max²` and use this values to update `sum` and `sumsq`.

**Defence mode**
Track `conn_curr` on each new opened connection. Calculate `z = (conn_curr - mean) / std` if `z > threshold` reject connection and block client by IP if necessary.

**Epoch handling**
Each connection tagged with training_epoch to prevents mixing old and new training data (we add new field to `tempesta_sock` and save epoch in this field). When connection closing we don't update `conn_curr` in case when connection belongs to previous epoch. (When connection is opening it always belongs to new epoch if trainging enabled!).

**Current method and alternatives**
In current approach during trainging mode we track maximum concurrent connections per client, in defence mode we compare current connections count (`conn_curr`) against a distribution of per-client maximum.
* ✔ effective for burst detection
* ❌ max vs current mismatch
* ❌ sensitivity to outliers (one client opens 10000 connections other clients 1 connection during trainging.)
* ❌ Not good against syn flood. If client open/close connections very fast, such client will not be blocked, because current connection count will be low.
**Alternatives:**

1. Use distribution of current concurrent connections - in trainging mode every `conn_curr` update stats, in defence mode compare `conn_curr` against this distribution. 
* ✔ Consistent model (same metric
* ❌ Noisy signal
* ❌ Dominated by low values (many idle clients, if they close there connections durig training)

2. Z-score on max, check only max
* ✔ Fully consistent model
* ✔ Low false positives
* ❌ Slow reaction
* ❌ Attack can stay just below max

In all this cases we don't take into account time awareness (100 connections for 1 second, 100 connections for 1 hour).
May be it will be good to calculate z-score for connection rate also (or we rely on frang for this case?).

**Request Count Tracking (Non-idempotent)**
We implement `TfwTrainingStat` structure to track all trainging events except connections.
```C
/*
 * max		- maximum observed value of the tracked metric within the
 *		  current training epoch (e.g. peak number of in-flight
 *		  non-idempotent requests);
 * curr		- current value of the tracked metric;
 * lock		- spinlock for serialized reset of @max and @curr when a
 *		  new training epoch starts.
 * @epoch	- training epoch identifier. Compared against the global
 *		  @g_training_epoch to detect epoch change and trigger
 *		  reinitialization of @max and @curr.
 */
typedef struct {
	atomic64_t	max;
	atomic64_t	curr;
	spinlock_t	lock;
	unsigned int	epoch;
} TfwTrainingStat;
```
We use new implemented function `tfw_client_training_adjust_req_num` both for training and  defence mode.

**Training mode**
Track `curr` - current in-flight non-idempotent requests. Increment `curr` in `tfw_http_req_enlist`, decrement in  `tfw_http_req_nip_delist`. Also track `max` maximum count  in-flight non-idempotent requests per client. When max increases update global trainging stats, same as we do it for connections (`delta1 = new_max - old_max` and `delta2 = new_max² - old_max²`).

**Defence mode**
Change signature for `tfw_http_req_enlist` from `void` to `bool`.  Call `tfw_client_training_adjust_req_num` on each new non-idempotent request, calculate z-score, return false if `z > threshold`. `tfw_http_req_enlist` is called from `tfw_http_req_fwd` and `tfw_http_req_fwd_resched`, this functions now return T_BLOCK if `tfw_http_req_enlist` fails.
Callers of `tfw_http_req_fwd` and `tfw_http_req_fwd_resched` send 403 error response, drop client connection with TCP RST and block client by IP if these functions return T_BLOCK.

**Epoch handling**
Each request tagged with `training_epoch` to prevent mixing old and new training data (we add new field to `request` structure and save epoch in this field). When request removed from server connection queue we don't update `curr` field in case when request belongs to previous epoch. (When request added to server connection queue it always belongs to new epoch if trainging enabled!).

**Current method and alternatives**
The same problems and altgernatives as for connections.

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

