#pragma once

#include <lib/atq.h>
#include <lib/minheap.h>

/*
 * Architecture-specific cache line size for padding hot structures.
 * ARM64 systems can have 64, 128, or 256-byte cache lines depending on
 * the microarchitecture. We use a conservative size to ensure proper
 * separation of hot fields across different ARM64 implementations.
 */
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
/* ARM64: Use 128-byte padding (conservative for Neoverse and other high-end cores) */
#define CACHE_LINE_SIZE 128
#elif defined(__TARGET_ARCH_x86) || defined(__x86_64__)
/* x86/x86_64: Typically 64-byte cache lines */
#define CACHE_LINE_SIZE 64
#else
/* Other architectures: Use conservative 128 bytes */
#define CACHE_LINE_SIZE 128
#endif

struct p2dq_timer {
	// if set to 0 the timer will only be scheduled once
	u64 interval_ns;
	u64 init_flags;
	int start_flags;
};

/* cpu_ctx flag bits */
#define CPU_CTX_F_INTERACTIVE	(1 << 0)
#define CPU_CTX_F_IS_BIG	(1 << 1)
#define CPU_CTX_F_NICE_TASK	(1 << 2)

/* Helper macros for cpu_ctx flags */
#define cpu_ctx_set_flag(cpuc, flag)	((cpuc)->flags |= (flag))
#define cpu_ctx_clear_flag(cpuc, flag)	((cpuc)->flags &= ~(flag))
#define cpu_ctx_test_flag(cpuc, flag)	((cpuc)->flags & (flag))

/* Arena-backed LLC context pointer */
struct llc_ctx;
typedef struct llc_ctx __arena *llc_ptr;

struct cpu_ctx {
	int				id;
	u32				llc_id;
	u64				affn_dsq;
	u64				slice_ns;
	u32				core_id;
	u32				dsq_index;
	u32				perf;
	u32				flags;  /* Bitmask for interactive, is_big, nice_task */
	u64				ran_for;
	u32				node_id;
	u64				mig_dsq;
	u64				llc_dsq;
	u64				max_load_dsq;

	scx_atq_t			*mig_atq;

	u64				idle_start_clk;  /* timestamp when CPU went idle, 0 if busy */
	u64				idle_total;      /* accumulated idle time in current period */
} __attribute__((aligned(CACHE_LINE_SIZE)));

/* llc_ctx state flag bits */
#define LLC_CTX_F_SATURATED	(1 << 0)

/* Helper macros for llc_ctx state flags */
#define llc_ctx_set_flag(llcx, flag)	((llcx)->state_flags |= (flag))
#define llc_ctx_clear_flag(llcx, flag)	((llcx)->state_flags &= ~(flag))
#define llc_ctx_test_flag(llcx, flag)	((llcx)->state_flags & (flag))

struct llc_ctx {
	/*
	 * CACHE LINE 0: Read-mostly metadata (accessed during initialization and lookups)
	 * These fields are read frequently but rarely written
	 */
	u32				id;
	u32				nr_cpus;
	u32				node_id;
	u32				lb_llc_id;
	u32				index;
	u32				nr_shards;
	u64				dsq;
	u64				mig_dsq;
	u64				last_period_ns;

	/*
	 * CACHE LINE 1: Hot atomic counters (updated in p2dq_stopping - very hot!)
	 * Keep vtime and load counters together since they're updated atomically in the same path
	 * This minimizes cache line bouncing across CPUs
	 */
	char				__pad1[CACHE_LINE_SIZE];
	u64				vtime;
	u64				load;
	u64				affn_load;
	u64				intr_load;
	u32				state_flags;  /* Bitmask for saturated and other state */

	/*
	 * CACHE LINE 2: Hot idle tracking bitmaps (HOT PATH!)
	 * These are the most critical fields for wakeup latency
	 * Accessed together in pick_idle_cpu() hot path - keep on same cache line
	 * Updated atomically (lock-free) in update_idle() callback
	 */
	char				__pad2[CACHE_LINE_SIZE - 4*sizeof(u64) - sizeof(u32)];
	scx_bitmap_t			idle_cpumask;    /* Idle CPUs in this LLC */
	scx_bitmap_t			idle_smtmask;    /* Idle SMT cores in this LLC */

	/*
	 * CACHE LINE 3: CPU priority heap and lock (only used when cpu_priority enabled)
	 * Separate from hot idle masks to avoid false sharing
	 * Most deployments don't use cpu_priority, so this is cold
	 */
	char				__pad3[CACHE_LINE_SIZE - 2*sizeof(scx_bitmap_t)];
	arena_spinlock_t		idle_lock;       /* Protects idle_cpu_heap operations */
	scx_minheap_t			*idle_cpu_heap;  /* Priority-ordered idle CPUs (optional) */

	/*
	 * CACHE LINE 4+: Read-mostly pointers and masks
	 * Accessed during CPU selection but not in the absolute hottest path
	 */
	char				__pad4[CACHE_LINE_SIZE - sizeof(arena_spinlock_t) - sizeof(scx_minheap_t*)];
	scx_bitmap_t			cpumask;
	scx_bitmap_t			big_cpumask;
	scx_bitmap_t			little_cpumask;
	scx_bitmap_t			node_cpumask;
	scx_bitmap_t			tmp_cpumask;     /* Scratch space for intersections */

	scx_atq_t			*mig_atq;
	u64				dsq_load[MAX_DSQS_PER_LLC];
	u64				shard_dsqs[MAX_LLC_SHARDS];
};

struct node_ctx {
	u32				id;
	scx_bitmap_t			cpumask;
	scx_bitmap_t			big_cpumask;
};

/* task_ctx flag bits */
#define TASK_CTX_F_INTERACTIVE	(1 << 0)
#define TASK_CTX_F_WAS_NICE	(1 << 1)
#define TASK_CTX_F_IS_KWORKER	(1 << 2)
#define TASK_CTX_F_ALL_CPUS	(1 << 3)

/* Helper macros for task_ctx flags */
#define task_ctx_set_flag(taskc, flag)		((taskc)->flags |= (flag))
#define task_ctx_clear_flag(taskc, flag)	((taskc)->flags &= ~(flag))
#define task_ctx_test_flag(taskc, flag)		((taskc)->flags & (flag))

/*
 * Task context - optimized for cache efficiency
 * Most-accessed fields grouped at the beginning for better cache utilization
 */
struct task_p2dq {
	/* HOT FIELDS - Accessed on every enqueue/dequeue */
	u64			dsq_id;          /* Current DSQ assignment */
	u64			slice_ns;        /* Current time slice */
	u32			llc_id;          /* Current LLC affinity */
	int			dsq_index;       /* DSQ priority index (0=interactive) */
	u32			flags;           /* Bitmask: interactive, was_nice, is_kworker, all_cpus */
	u32			node_id;         /* Current NUMA node */

	/* MEDIUM HOT - Accessed in stopping/running callbacks */
	u64 			last_run_at;     /* Timestamp of last execution */
	u64 			last_run_started;/* When current run started */
	u64			llc_runs;        /* Runs remaining on current LLC before migration eligible */

	/* COOLER - Only accessed during DSQ transitions */
	u64			last_dsq_id;     /* Previous DSQ for debugging */
	int			last_dsq_index;  /* Previous DSQ index */
	u64			enq_flags;       /* Enqueue flags (for ATQ path) */
	u64			used;            /* Time used in last run (temporary) */
};

typedef struct task_p2dq __arena task_ctx;

enum enqueue_promise_kind {
	P2DQ_ENQUEUE_PROMISE_COMPLETE,
	P2DQ_ENQUEUE_PROMISE_VTIME,
	P2DQ_ENQUEUE_PROMISE_FIFO,
	P2DQ_ENQUEUE_PROMISE_ATQ_VTIME,
	P2DQ_ENQUEUE_PROMISE_ATQ_FIFO,
	P2DQ_ENQUEUE_PROMISE_FAILED,
};

struct enqueue_promise_vtime {
	u64	dsq_id;
	u64	enq_flags;
	u64	slice_ns;
	u64	vtime;

	scx_atq_t	*atq;
};

struct enqueue_promise_fifo {
	u64	dsq_id;
	u64	enq_flags;
	u64	slice_ns;

	scx_atq_t	*atq;
};

/* enqueue_promise flag bits */
#define ENQUEUE_PROMISE_F_KICK_IDLE		(1 << 0)
#define ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE	(1 << 1)

/* Helper macros for enqueue_promise flags */
#define enqueue_promise_set_flag(pro, flag)	((pro)->flags |= (flag))
#define enqueue_promise_clear_flag(pro, flag)	((pro)->flags &= ~(flag))
#define enqueue_promise_test_flag(pro, flag)	((pro)->flags & (flag))

// This struct is zeroed at the beginning of `async_p2dq_enqueue` and only
// relevant fields are set, so assume 0 as default when adding fields.
struct enqueue_promise {
	enum enqueue_promise_kind	kind;

	s32				cpu;
	u32				flags;  /* Bitmask for kick_idle, has_cleared_idle */

	union {
		struct enqueue_promise_vtime	vtime;
		struct enqueue_promise_fifo	fifo;
	};
};
