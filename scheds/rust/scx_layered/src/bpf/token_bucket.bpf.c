/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define CLOCK_BOOTTIME 7
#define MAX_TOKEN_BUCKETS 8192
#define MAX_PER_CPU_TOKEN_BUCKETS 16
#define GLOBAL_REFRESH_TIMER 0
#define PER_CPU_REFRESH_TIMER 1

const volatile u32 token_bucket_refresh_intvl_ns = 100 * NSEC_PER_MSEC;

const volatile u32 nr_token_buckets = 16;
const volatile u32 nr_percpu_token_buckets = 16;
static bool initialized_buckets = false;


struct refresh_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, struct refresh_timer);
} refresh_timer_data SEC(".maps");


struct token_bucket_lock {
	struct bpf_spin_lock	lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct token_bucket_lock);
	__uint(max_entries, MAX_TOKEN_BUCKETS);
	__uint(map_flags, 0);
} bucket_locks SEC(".maps");

static struct token_bucket_lock *lookup_token_bucket_lock(u32 bucket_id)
{
	struct token_bucket_lock *buck_lock;

	buck_lock = bpf_map_lookup_elem(&bucket_locks, &bucket_id);
	if (!buck_lock) {
		scx_bpf_error("invalid bucket %d", bucket_id);
		return NULL;
	}

	return buck_lock;
}


struct token_bucket {
	int	tokens;
	int	capacity;
	int	rate_per_ms;
	u64	last_update;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct token_bucket);
	__uint(max_entries, MAX_TOKEN_BUCKETS);
	__uint(map_flags, 0);
} token_bucket_data SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct token_bucket);
	__uint(max_entries, MAX_PER_CPU_TOKEN_BUCKETS);
} cpu_token_bucket SEC(".maps");


static struct token_bucket *lookup_token_bucket(u32 bucket_id)
{
	struct token_bucket *buck;

	buck = bpf_map_lookup_elem(&token_bucket_data, &bucket_id);
	if (!buck) {
		scx_bpf_error("invalid token bucket %d", bucket_id);
		return NULL;
	}

	return buck;
}

struct token_bucket *lookup_cpu_token_bucket(u32 bucket_id, s32 cpu)
{
	struct token_bucket *buck;

	if (cpu < 0)
		buck = bpf_map_lookup_elem(&cpu_token_bucket, &bucket_id);
	else
		buck = bpf_map_lookup_percpu_elem(&cpu_token_bucket, &bucket_id, cpu);

	if (!buck) {
		scx_bpf_error("invalid token bucket %d", bucket_id);
		return NULL;
	}

	return buck;
}


/*
 * Returns if a bucket was successfully consumed.
 */
bool consume_bucket(u32 bucket_id)
{
	struct token_bucket *buck;
	struct token_bucket_lock *buck_lock;
	bool consumed = false;

	if (!(buck = lookup_token_bucket(bucket_id)) ||
	    !(buck_lock = lookup_token_bucket_lock(bucket_id)))
		return consumed;

	bpf_spin_lock(&buck_lock->lock);
	if (buck->tokens > 0) {
		buck->tokens -= 1;
		consumed = true;
	}
	bpf_spin_unlock(&buck_lock->lock);

	return consumed;
}

/*
 * Returns if a cpu bucket is empty.
 */
bool cpu_bucket_empty(u32 bucket_id)
{
	struct token_bucket *buck;

	if (!(buck = lookup_cpu_token_bucket(bucket_id, -1)))
		return true;

	return buck->tokens == 0;
}

/*
 * Returns if a cpu bucket was successfully consumed.
 */
bool consume_cpu_bucket(u32 bucket_id)
{
	struct token_bucket *buck;

	if (!(buck = lookup_cpu_token_bucket(bucket_id, -1)))
		return false;

	if (buck->tokens > 0) {
		__sync_fetch_and_sub(&buck->tokens, 1);
		return true;
	}

	return false;
}

/*
 * Returns all the tokens from a bucket.
 */
static int drain_cpu_bucket(u32 bucket_id, s32 cpu)
{
	struct token_bucket *buck;

	if (!(buck = lookup_cpu_token_bucket(bucket_id, -1)))
		return 0;

	if (buck->tokens > 0) {
		return __sync_lock_test_and_set(&buck->tokens, buck->tokens);
	}

	return 0;
}

/*
 * Returns a partial number of tokens from a bucket.
 */
static int partial_drain_cpu_bucket(u32 bucket_id, s32 cpu, int count)
{
	struct token_bucket *buck;
	int cur_tokens;

	if (!(buck = lookup_cpu_token_bucket(bucket_id, -1)))
		return 0;

	cur_tokens = buck->tokens;
	if (cur_tokens < 0)
		return 0;

	if (count > cur_tokens)
		count = cur_tokens;

	__sync_fetch_and_sub(&buck->tokens, count);

	return count;
}

/*
 * Refreshes a token bucket. This should typically be called by the bpf timer
 * initialized by start_token_buckets.
 */
static void refresh_token_bucket(u32 bucket_id)
{
	struct token_bucket *buck;
	struct token_bucket_lock *buck_lock;
	u64 refresh_intvl;

	if (!(buck = lookup_token_bucket(bucket_id)) ||
	    !(buck_lock = lookup_token_bucket_lock(bucket_id)))
		return;

	u64 now = bpf_ktime_get_ns();
	bpf_spin_lock(&buck_lock->lock);
	if (buck->last_update > now) {
		bpf_spin_unlock(&buck_lock->lock);
		scx_bpf_error("invalid bucket time for bucket %d", bucket_id);
		return;
	}

	refresh_intvl = now - buck->last_update;
	if (refresh_intvl < NSEC_PER_MSEC) {
		bpf_spin_unlock(&buck_lock->lock);
		return;
	}

	buck->tokens += buck->rate_per_ms * (refresh_intvl / NSEC_PER_MSEC);
	if (buck->tokens > buck->capacity)
		buck->tokens = buck->capacity;

	buck->last_update = now;
	bpf_spin_unlock(&buck_lock->lock);
}
/*
 * Refreshes a per cpu token bucket. This should typically be called by the bpf timer
 * initialized by start_token_buckets.
 */
static void refresh_cpu_token_bucket(u32 bucket_id)
{
	struct token_bucket *buck;
	u64 refresh_intvl;
	int new_tokens, cur_tokens;

	if (!(buck = lookup_token_bucket(bucket_id)))
		return;

	u64 now = bpf_ktime_get_ns();
	if (buck->last_update > now) {
		scx_bpf_error("invalid bucket time for bucket %d", bucket_id);
		return;
	}

	refresh_intvl = now - buck->last_update;
	if (refresh_intvl < NSEC_PER_MSEC)
		return;

	new_tokens = buck->rate_per_ms * (refresh_intvl / NSEC_PER_MSEC);
	cur_tokens = buck->tokens;

	if (new_tokens + cur_tokens > buck->capacity) {
		if (cur_tokens < buck->capacity) {
			__sync_fetch_and_add(&buck->tokens, buck->capacity - cur_tokens);
		}
	} else {
		__sync_fetch_and_add(&buck->tokens, new_tokens);
	}

	buck->last_update = now;
}

/*
 * Initializes a bucket. This should be for all buckets before calling
 * start_token_buckets.
 */
static void initialize_bucket(u32 bucket_id, u64 capacity, u64 rate_per_ms)
{
	struct token_bucket *buck;
	struct token_bucket_lock *buck_lock;

	if (!(buck = lookup_token_bucket(bucket_id)) ||
	    !(buck_lock = lookup_token_bucket_lock(bucket_id)))
		return;

	if (!initialized_buckets)
		initialized_buckets = true;

	bpf_spin_lock(&buck_lock->lock);
	u64 now = bpf_ktime_get_ns();
	buck->capacity = capacity;
	if (buck->tokens > buck->capacity)
		buck->tokens = buck->capacity;
	buck->rate_per_ms = rate_per_ms;
	buck->last_update = now;
	bpf_spin_unlock(&buck_lock->lock);
}

/*
 * Initializes a per cpu bucket. This should be for all buckets before calling
 * start_token_buckets.
 */
static void initialize_cpu_bucket(s32 cpu, u32 bucket_id, int capacity, int rate_per_ms)
{
	struct token_bucket *buck;

	if (!(buck = lookup_cpu_token_bucket(bucket_id, cpu)))
		return;

	if (!initialized_buckets)
		initialized_buckets = true;

	u64 now = bpf_ktime_get_ns();
	buck->capacity = capacity;
	if (buck->tokens > buck->capacity)
		buck->tokens = buck->capacity;

	buck->rate_per_ms = rate_per_ms;
	buck->last_update = now;
}

/*
 * Refreshes all token buckets.
 */
static void refresh_token_buckets(void)
{
	u32 bucket_id;

	if (nr_token_buckets > MAX_TOKEN_BUCKETS) {
		scx_bpf_error("Invalid nr_token_buckets %d", nr_token_buckets);
		return;
	}

	bpf_for(bucket_id, 0, nr_token_buckets) {
		refresh_token_bucket(bucket_id);
	}
}

/*
 * Refreshes all per cpu token buckets.
 */
static void refresh_cpu_token_buckets(void)
{
	u32 bucket_id;

	if (nr_token_buckets > MAX_TOKEN_BUCKETS) {
		scx_bpf_error("Invalid nr_token_buckets %d", nr_token_buckets);
		return;
	}

	bpf_for(bucket_id, 0, nr_token_buckets) {
		refresh_cpu_token_bucket(bucket_id);
	}
}

/*
 * Callback for bpf timer, do not call directly.
 */
static int on_refresh_timer_intvl(void *map, int *key, struct bpf_timer *timer)
{
	int err;

	refresh_token_buckets();

	err = bpf_timer_start(timer, token_bucket_refresh_intvl_ns, 0);
	if (err)
		scx_bpf_error("Failed to update token bucket timer");

	return 0;
}

/*
 * Callback for per cpu bpf timer, do not call directly.
 */
static int on_cpu_refresh_timer_intvl(void *map, int *key, struct bpf_timer *timer)
{
	int err;

	refresh_cpu_token_buckets();

	err = bpf_timer_start(timer, token_bucket_refresh_intvl_ns, 0);
	if (err)
		scx_bpf_error("Failed to update token bucket timer");

	return 0;
}

/*
 * Starts the bpf timer that refreshes all token buckets on an interval.
 * Buckets should be initialized with initialize_bucket before calling this
 * method.
 */
static s32 start_token_buckets(u32 key)
{
	struct bpf_timer *timer;
	int err;

	if (!initialized_buckets) {
		scx_bpf_error("Token bucket started without no buckets");
		return -EINVAL;
	}

	timer = bpf_map_lookup_elem(&refresh_timer_data, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup refresh timer");
		return -ENOENT;
	}

	bpf_timer_init(timer, &refresh_timer_data, CLOCK_BOOTTIME);
	switch (key) {
		case GLOBAL_REFRESH_TIMER:
			bpf_timer_set_callback(timer, on_refresh_timer_intvl);
			break;
		case PER_CPU_REFRESH_TIMER:
			bpf_timer_set_callback(timer, on_cpu_refresh_timer_intvl);
			break;
		default:
			scx_bpf_error("Failed to initialize token bucket");
			return -ENOENT;
	}

	bpf_timer_set_callback(timer, on_refresh_timer_intvl);
	err = bpf_timer_start(timer, 0, 0);
	if (err) {
		scx_bpf_error("Failed to initialize token bucket");
		return err;
	}
}
