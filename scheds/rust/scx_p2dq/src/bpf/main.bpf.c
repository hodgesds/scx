/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * scx_p2dq is a scheduler where the load balancing is done using a pick 2
 * algorithm.
 */

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#include "../../../../include/scx/bpf_arena_common.bpf.h"
#include "../../../../include/scx/percpu.bpf.h"
#include "../../../../include/lib/atq.h"
#include "../../../../include/lib/cpumask.h"
#include "../../../../include/lib/minheap.h"
#include "../../../../include/lib/percpu.h"
#include "../../../../include/lib/sdt_task.h"
#include "../../../../include/lib/topology.h"
#else
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>
#include <scx/percpu.bpf.h>
#include <lib/atq.h>
#include <lib/cpumask.h>
#include <lib/minheap.h>
#include <lib/percpu.h>
#include <lib/sdt_task.h>
#include <lib/topology.h>
#endif

#include "intf.h"
#include "types.h"


#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef P2DQ_CREATE_STRUCT_OPS
#define P2DQ_CREATE_STRUCT_OPS 1
#endif

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)

const volatile struct {
	u32 nr_cpus;
	u32 nr_llcs;
	u32 nr_nodes;

	bool smt_enabled;
	bool has_little_cores;
} topo_config = {
	.nr_cpus = 64,
	.nr_llcs = 32,
	.nr_nodes = 32,

	.smt_enabled = true,
	.has_little_cores = false,
};

const volatile struct {
	u64 min_slice_us;
	u64 max_exec_ns;
	bool autoslice;
	bool deadline;
} timeline_config = {
	.min_slice_us = 100,
	.max_exec_ns = 20 * NSEC_PER_MSEC,
	.autoslice = true,
	.deadline = true,
};

const volatile struct {
	u64 backoff_ns;
	u64 dispatch_lb_busy;
	u64 min_llc_runs_pick2;
	u64 min_nr_queued_pick2;
	u64 slack_factor;
	u64 wakeup_lb_busy;

	bool dispatch_lb_interactive;
	bool dispatch_pick2_disable;
	bool eager_load_balance;
	bool max_dsq_pick2;
	bool wakeup_llc_migrations;
	bool single_llc_mode;
} lb_config = {
	.backoff_ns = 5LLU * NSEC_PER_MSEC,
	.dispatch_lb_busy = 75,
	.min_llc_runs_pick2 = 4,
	.min_nr_queued_pick2 = 10,
	.slack_factor = LOAD_BALANCE_SLACK,
	.wakeup_lb_busy = 90,

	.dispatch_lb_interactive = false,
	.dispatch_pick2_disable = false,
	.eager_load_balance = true,
	.max_dsq_pick2 = false,
	.wakeup_llc_migrations = false,
	.single_llc_mode = false,
};

const volatile struct {
	u32 nr_dsqs_per_llc;
	int init_dsq_index;
	u64 dsq_shift;
	u32 interactive_ratio;
	u32 saturated_percent;
	u32 sched_mode;
	u32 llc_shards;

	bool atq_enabled;
	bool cpu_priority;
	bool task_slice;
	bool freq_control;
	bool interactive_sticky;
	bool keep_running_enabled;
	bool kthreads_local;
	bool arena_idle_tracking;
} p2dq_config = {
	.sched_mode = MODE_DEFAULT,
	.nr_dsqs_per_llc = 3,
	.init_dsq_index = 0,
	.dsq_shift = 2,
	.interactive_ratio = 10,
	.saturated_percent = 5,
	.llc_shards = 0,

	.atq_enabled = false,
	.cpu_priority = false,
	.task_slice = true,
	.freq_control = false,
	.interactive_sticky = false,
	.keep_running_enabled = true,
	.kthreads_local = true,
	.arena_idle_tracking = true,
};

const volatile u32 debug = 2;
const u32 zero_u32 = 0;
extern const volatile u32 nr_cpu_ids;

/* Arena map for allocating context structures */
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	__uint(max_entries, 1 << 16); /* number of pages */
	__ulong(map_extra, (1ull << 32)); /* start of mmap() region */
#else
	__uint(max_entries, 1 << 20); /* number of pages */
	__ulong(map_extra, (1ull << 44)); /* start of mmap() region */
#endif
} arena __weak SEC(".maps");

const u64 lb_timer_intvl_ns = 250LLU * NSEC_PER_MSEC;

static u32 llc_lb_offset = 1;
static u64 min_llc_runs_pick2 = 1;
static bool saturated = false;
static bool overloaded = false;

u64 llc_ids[MAX_LLCS];
u32 cpu_core_ids[MAX_CPUS];
u64 cpu_llc_ids[MAX_CPUS];
u64 cpu_node_ids[MAX_CPUS];
u64 big_core_ids[MAX_CPUS];
u64 dsq_time_slices[MAX_DSQS_PER_LLC];

u64 min_slice_ns = 500;

private(A) scx_bitmap_t all_cpumask;
private(A) scx_bitmap_t big_cpumask;

static u64 max(u64 a, u64 b)
{
	return a >= b ? a : b;
}

static u64 min(u64 a, u64 b)
{
	return a <= b ? a : b;
}

static __always_inline u64 dsq_time_slice(int dsq_index)
{
	if (dsq_index > p2dq_config.nr_dsqs_per_llc || dsq_index < 0) {
		scx_bpf_error("Invalid DSQ index");
		return 0;
	}
	return dsq_time_slices[dsq_index];
}

static __always_inline bool valid_dsq(u64 dsq_id)
{
	return dsq_id != 0 && dsq_id != SCX_DSQ_INVALID;
}

static __always_inline u64 max_dsq_time_slice(void)
{
	return dsq_time_slices[p2dq_config.nr_dsqs_per_llc - 1];
}

static __always_inline u64 min_dsq_time_slice(void)
{
	return dsq_time_slices[0];
}

static __always_inline u64 clamp_slice(u64 slice_ns)
{
	return min(max(min_dsq_time_slice(), slice_ns),
		   max_dsq_time_slice());
}

static __always_inline u64 shard_dsq_id(u32 llc_id, u32 shard_id)
{
	return ((MAX_DSQS_PER_LLC * MAX_LLCS) << 3) + (llc_id * MAX_DSQS_PER_LLC) + shard_id;
}

static __always_inline u64 cpu_dsq_id(s32 cpu)
{
	return ((MAX_DSQS_PER_LLC * MAX_LLCS) << 2) + cpu;
}

static __always_inline u32 wrap_index(u32 index, u32 min, u32 max)
{
	if (min > max) {
		scx_bpf_error("invalid min");
		return min;
	}
	u32 range = max - min + 1;
	return min + (index % range);
}

/*
 * Native arena bitmap CPU picker - works directly on arena bitmaps.
 * Optimized with efficient bit-scanning to minimize latency.
 * This operates purely on the provided mask without kernel idle checks.
 * The mask should already be filtered (e.g., LLC's idle_cpumask).
 *
 * Returns the first CPU found in the mask, or -1 if none found.
 */
__noinline static s32 __pick_idle_cpu(scx_bitmap_t mask, int flags)
{
	u64 word;
	s32 cpu, bit, sibling;
	u32 i, max_words;

	if (unlikely(!mask))
		return -1;

	// Fast path for PICK_IDLE_CORE when SMT is disabled
	if ((flags & SCX_PICK_IDLE_CORE) && !topo_config.smt_enabled)
		flags = 0;

	// Calculate max words once - this is faster than checking i*64 >= nr_cpus in the loop
	// On large systems (316 CPUs), this avoids per-iteration overhead
	max_words = (topo_config.nr_cpus + 63) >> 6;  // Faster than division
	if (max_words > SCXMASK_NLONG)
		max_words = SCXMASK_NLONG;

	// Scan through bitmap words to find first idle CPU
	bpf_for(i, 0, max_words) {
		word = mask->bits[i];
		if (!word)
			continue;

		bit = __builtin_ffsll(word);
		if (unlikely(bit <= 0 || bit > 64))
			continue;
		bit -= 1;

		cpu = i * 64 + bit;

		// Bounds check: ensure CPU is valid
		// This is critical on large systems where bitmap may have trailing bits set
		if (unlikely(cpu < 0 || cpu >= topo_config.nr_cpus))
			continue;  // Try next bit in next word instead of failing

		// For PICK_IDLE_CORE flag, verify sibling is also idle
		if (flags & SCX_PICK_IDLE_CORE) {
			sibling = cpu_core_ids[cpu];
			if (sibling == cpu || sibling < 0 || sibling >= topo_config.nr_cpus)
				return cpu;
			if (scx_bitmap_test_cpu(sibling, mask))
				return cpu;
			// Sibling not idle, continue to next word
			continue;
		}

		return cpu;
	}

	return -1;
}

/*
 * Pick an idle CPU from the mask and atomically claim it.
 * Returns the CPU number if successful, -1 if no idle CPU found or claim failed.
 * This combines __pick_idle_cpu() with the required scx_bpf_test_and_clear_cpu_idle()
 * operation to prevent races where multiple tasks try to claim the same CPU.
 */
static __always_inline s32 pick_and_claim_idle_cpu(scx_bitmap_t mask, int flags)
{
	s32 cpu = __pick_idle_cpu(mask, flags);
	if (cpu >= 0 && scx_bpf_test_and_clear_cpu_idle(cpu))
		return cpu;
	return -1;
}

/*
 * Helper: Clear a CPU from arena idle masks (arena tracking mode).
 * When arena_idle_tracking is enabled, the arena masks ARE the source of truth.
 * Keeps idle_cpumask and idle_smtmask synchronized (lock-free, slightly racy).
 */
static __always_inline void llc_clear_idle_cpu(struct llc_ctx __arena *llcx, s32 cpu)
{
	if (!llcx)
		return;

	// Clear from idle_cpumask
	if (llcx->idle_cpumask)
		scx_bitmap_atomic_clear_cpu(cpu, llcx->idle_cpumask);

	// Clear both CPU and sibling from smtmask (core no longer fully idle)
	if (topo_config.smt_enabled && llcx->idle_smtmask) {
		scx_bitmap_atomic_clear_cpu(cpu, llcx->idle_smtmask);

		s32 sibling = cpu_core_ids[cpu];
		if (sibling != cpu && sibling >= 0 && sibling < topo_config.nr_cpus) {
			scx_bitmap_atomic_clear_cpu(sibling, llcx->idle_smtmask);
		}
	}
}

/*
 * Helper: Set a CPU in arena idle masks.
 * Keeps idle_cpumask and idle_smtmask synchronized (lock-free, slightly racy).
 * Used by update_idle() callback to mark CPUs as idle.
 *
 * idle_smtmask should only contain CPUs where BOTH the CPU and sibling are idle.
 */
static __always_inline void llc_set_idle_cpu(struct llc_ctx __arena *llcx, s32 cpu)
{
	if (!llcx)
		return;

	// Always set in idle_cpumask
	if (llcx->idle_cpumask)
		scx_bitmap_atomic_set_cpu(cpu, llcx->idle_cpumask);

	// Only set in idle_smtmask if sibling is also idle
	if (topo_config.smt_enabled && llcx->idle_smtmask) {
		s32 sibling = cpu_core_ids[cpu];
		if (sibling != cpu && sibling >= 0 && sibling < topo_config.nr_cpus) {
			// Check if sibling is idle in the arena mask
			if (scx_bitmap_test_cpu(sibling, llcx->idle_cpumask)) {
				// Both CPU and sibling are idle - set both in smtmask
				scx_bitmap_atomic_set_cpu(cpu, llcx->idle_smtmask);
				scx_bitmap_atomic_set_cpu(sibling, llcx->idle_smtmask);
			}
		}
	}
}

/*
 * Fast path CPU picker - bypasses heap entirely for hot path optimization.
 * Use this in the wakeup hot path when cpu_priority is not needed.
 * Always uses simple pick strategy regardless of cpu_priority setting.
 */
static __always_inline s32 llc_pick_idle_cpu_fast(struct llc_ctx __arena *llcx, int flags)
{
	s32 cpu;

	if (!llcx || !llcx->idle_cpumask)
		return -1;

	cpu = __pick_idle_cpu(llcx->idle_cpumask, flags);
	if (cpu >= 0) {
		// Arena mask is the source of truth - test and clear it
		if (scx_bitmap_test_and_clear_cpu(cpu, llcx->idle_cpumask)) {
			// Keep idle_smtmask in sync
			if (topo_config.smt_enabled && llcx->idle_smtmask)
				scx_bitmap_atomic_clear_cpu(cpu, llcx->idle_smtmask);
			// Notify kernel
			scx_bpf_test_and_clear_cpu_idle(cpu);
			return cpu;
		}
	}

	return -1;
}

/*
 * Pick an idle SMT CPU from the LLC's idle SMT mask with lock-free atomic claiming (arena tracking mode).
 * When arena_idle_tracking is enabled, the arena mask IS the source of truth.
 * Returns the CPU number if successfully claimed, -1 if no idle CPU found or claim failed.
 */
static __always_inline s32 llc_pick_idle_smt(struct llc_ctx __arena *llcx)
{
	s32 cpu;

	if (!llcx || !llcx->idle_smtmask)
		return -1;

	cpu = __pick_idle_cpu(llcx->idle_smtmask, 0);
	if (cpu >= 0) {
		// Arena SMT mask is the source of truth - test and clear it
		if (scx_bitmap_test_and_clear_cpu(cpu, llcx->idle_smtmask)) {
			// Keep idle_cpumask in sync
			if (llcx->idle_cpumask)
				scx_bitmap_atomic_clear_cpu(cpu, llcx->idle_cpumask);
			// Notify kernel
			scx_bpf_test_and_clear_cpu_idle(cpu);
			return cpu;
		}
	}

	return -1;
}

/* For arena-backed structures (LLC contexts) */
static int init_arena_bitmap_arena(scx_bitmap_t __arena *mask_p)
{
	u64 bitmap_addr;

	bitmap_addr = scx_bitmap_alloc_internal();
	if (!bitmap_addr) {
		return -ENOMEM;
	}

	*mask_p = (scx_bitmap_t)bitmap_addr;
	return 0;
}

/* For non-arena structures (node contexts, global cpumasks) */
static int init_arena_bitmap(scx_bitmap_t *mask_p)
{
	u64 bitmap_addr;

	bitmap_addr = scx_bitmap_alloc_internal();
	if (!bitmap_addr) {
		return -ENOMEM;
	}

	*mask_p = (scx_bitmap_t)bitmap_addr;
	return 0;
}

static u32 nr_idle_cpus(const struct cpumask *idle_cpumask)
{
	u32 nr_idle;

	nr_idle = bpf_cpumask_weight(idle_cpumask);

	return nr_idle;
}

static u32 idle_cpu_percent(const struct cpumask *idle_cpumask)
{
	return (100 * nr_idle_cpus(idle_cpumask)) / topo_config.nr_cpus;
}

static u64 task_slice_ns(struct task_struct *p, u64 slice_ns)
{
	return clamp_slice(scale_by_task_weight(p, slice_ns));
}

static u64 task_dsq_slice_ns(struct task_struct *p, int dsq_index)
{
	return task_slice_ns(p, dsq_time_slice(dsq_index));
}

static void task_refresh_llc_runs(task_ctx *taskc)
{
	taskc->llc_runs = min_llc_runs_pick2;
}

static u64 llc_nr_queued(struct llc_ctx __arena *llcx)
{
	if (!llcx)
		return 0;

	u64 nr_queued = scx_bpf_dsq_nr_queued(llcx->dsq);

	if (topo_config.nr_llcs > 1) {
		if (p2dq_config.atq_enabled)
			nr_queued += scx_atq_nr_queued(llcx->mig_atq);
		else
			nr_queued += scx_bpf_dsq_nr_queued(llcx->mig_dsq);
	}

	return nr_queued;
}

static int llc_create_atqs(struct llc_ctx __arena *llcx)
{
	if (!p2dq_config.atq_enabled)
		return 0;

	if (topo_config.nr_llcs > 1) {
		llcx->mig_atq = (scx_atq_t *)scx_atq_create_size(false,
								 topo_config.nr_cpus);
		if (!llcx->mig_atq) {
			scx_bpf_error("ATQ failed to create ATQ for LLC %u",
				      llcx->id);
			return -ENOMEM;
		}
		trace("ATQ mig_atq %llu created for LLC %llu",
		      (u64)llcx->mig_atq, llcx->id);
	}

	return 0;
}

struct p2dq_timer p2dq_timers[MAX_TIMERS] = {
	{lb_timer_intvl_ns,
	     CLOCK_BOOTTIME, 0},
};

struct timer_wrapper {
	struct bpf_timer timer;
	int	key;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_TIMERS);
	__type(key, int);
	__type(value, struct timer_wrapper);
} timer_data SEC(".maps");


/* Non-arena global array for CPU contexts (verifier-friendly) */
/* CPU contexts stored in topology library data pointers */

static __always_inline struct cpu_ctx __arena *lookup_cpu_ctx(int cpu)
{
	topo_ptr topo;
	struct cpu_ctx __arena *cpuc;

	if (cpu < 0)
		cpu = bpf_get_smp_processor_id();

	/* topo_nodes is sized [TOPO_MAX_LEVEL][NR_CPUS], so check against NR_CPUS */
	if (cpu >= NR_CPUS || cpu >= topo_config.nr_cpus) {
		scx_bpf_error("invalid cpu %d", cpu);
		return NULL;
	}

	/* Mask cpu for verifier bounds checking against NR_CPUS */
	cpu &= (NR_CPUS - 1);

	/* Get topology node for this CPU */
	topo = (topo_ptr)topo_nodes[TOPO_CPU][cpu];
	if (!topo) {
		/* CPU doesn't have topology node (offline, hotplugged, etc) */
		return NULL;
	}

	cast_kern(topo);
	cpuc = (struct cpu_ctx __arena *)topo->data;
	cast_kern(cpuc);
	return cpuc;
}

/* LLC contexts stored in topology library data pointers */

static __always_inline struct llc_ctx __arena *lookup_llc_ctx(u32 llc_id)
{
	topo_ptr topo;
	struct llc_ctx __arena *llcx;

	/* topo_nodes is sized [TOPO_MAX_LEVEL][NR_CPUS], so check against NR_CPUS */
	if (llc_id >= NR_CPUS) {
		scx_bpf_error("invalid llc_id %u", llc_id);
		return NULL;
	}

	/* Mask llc_id for verifier bounds checking against NR_CPUS */
	llc_id &= (NR_CPUS - 1);

	/* Get topology node for this LLC */
	topo = (topo_ptr)topo_nodes[TOPO_LLC][llc_id];
	if (!topo) {
		scx_bpf_error("no topo node for llc %u", llc_id);
		return NULL;
	}

	cast_kern(topo);
	llcx = (struct llc_ctx __arena *)topo->data;
	cast_kern(llcx);
	return llcx;
}

static __always_inline struct llc_ctx __arena *lookup_cpu_llc_ctx(s32 cpu)
{
	if (cpu >= topo_config.nr_cpus || cpu < 0) {
		scx_bpf_error("invalid CPU");
		return NULL;
	}

	return lookup_llc_ctx(cpu_llc_ids[cpu]);
}

/* Node contexts stored in topology library data pointers */

static __always_inline struct node_ctx __arena *lookup_node_ctx(u32 node_id)
{
	topo_ptr topo;
	struct node_ctx __arena *nodec;

	/* topo_nodes is sized [TOPO_MAX_LEVEL][NR_CPUS], so check against NR_CPUS */
	if (node_id >= NR_CPUS) {
		scx_bpf_error("invalid node_id %u", node_id);
		return NULL;
	}

	/* Mask node_id for verifier bounds checking against NR_CPUS */
	node_id &= (NR_CPUS - 1);

	/* Get topology node for this NUMA node */
	topo = (topo_ptr)topo_nodes[TOPO_NODE][node_id];
	if (!topo) {
		scx_bpf_error("no topo node for NUMA node %u", node_id);
		return NULL;
	}

	cast_kern(topo);
	nodec = (struct node_ctx __arena *)topo->data;
	cast_kern(nodec);
	return nodec;
}

/* Task storage removed - using LLC tmp_cpumask instead */

static task_ctx *lookup_task_ctx(struct task_struct *p)
{
	task_ctx *taskc = scx_task_data(p);

	if (!taskc)
		scx_bpf_error("task_ctx lookup failed");

	return taskc;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, P2DQ_NR_STATS);
} stats SEC(".maps");

static inline void stat_add(enum stat_idx idx, u64 amount)
{
	u32 idx_v = idx;
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
	if (cnt_p)
		(*cnt_p) += amount;
}

static inline void stat_inc(enum stat_idx idx)
{
	stat_add(idx, 1);
}

/*
 * Returns if the task is interactive based on the tasks DSQ index.
 */
static bool is_interactive(task_ctx *taskc)
{
	if (p2dq_config.nr_dsqs_per_llc <= 1)
		return false;
	// For now only the shortest duration DSQ is considered interactive.
	return taskc->dsq_index == 0;
}

static bool can_migrate(task_ctx *taskc, struct llc_ctx __arena *llcx)
{
	// Single-LLC fast path: never migrate
	if (unlikely(lb_config.single_llc_mode))
		return false;

	if (topo_config.nr_llcs < 2 ||
	    !task_ctx_test_flag(taskc, TASK_CTX_F_ALL_CPUS) ||
	    (!lb_config.dispatch_lb_interactive && task_ctx_test_flag(taskc, TASK_CTX_F_INTERACTIVE)))
		return false;

	if (lb_config.max_dsq_pick2 &&
	    taskc->dsq_index != p2dq_config.nr_dsqs_per_llc - 1)
		return false;

	if (taskc->llc_runs > 0)
		return false;

	if (unlikely(saturated || overloaded))
		return true;

	if (unlikely(llc_ctx_test_flag(llcx, LLC_CTX_F_SATURATED)))
		return true;

	return false;
}

static void set_deadline_slice(struct task_struct *p, task_ctx *taskc,
			       struct llc_ctx __arena *llcx)
{
	u64 nr_idle;
	u64 max_ns = scale_by_task_weight(p, max_dsq_time_slice());
	u64 nr_queued = llc_nr_queued(llcx);

	const struct cpumask *idle_cpumask = scx_bpf_get_idle_cpumask();
	nr_idle = bpf_cpumask_weight(idle_cpumask);
	scx_bpf_put_cpumask(idle_cpumask);

	if (nr_idle == 0)
		nr_idle = 1;

	if (nr_queued > nr_idle)
		taskc->slice_ns = (max_ns * nr_idle) / nr_queued;
	else
		taskc->slice_ns = max_ns;

	taskc->slice_ns = clamp_slice(taskc->slice_ns);
}

/*
 * Updates a tasks vtime based on the newly assigned cpu_ctx and returns the
 * updated vtime.
 */
static void update_vtime(struct task_struct *p, struct cpu_ctx __arena *cpuc,
			 task_ctx *taskc, struct llc_ctx __arena *llcx)
{
	/*
	 * If in the same LLC we only need to clamp the vtime to ensure no task
	 * accumulates too much vtime.
	 */
	if (taskc->llc_id == cpuc->llc_id) {
		if (p->scx.dsq_vtime >= llcx->vtime)
			return;

		u64 scaled_min = scale_by_task_weight(p, max_dsq_time_slice());

		if (p->scx.dsq_vtime < llcx->vtime - scaled_min)
			p->scx.dsq_vtime = llcx->vtime - scaled_min;

		return;
	}

	p->scx.dsq_vtime = llcx->vtime;

	return;
}

/*
 * Returns a random llc_ctx
 */
static struct llc_ctx __arena *rand_llc_ctx(void)
{
	u32 llc_id = bpf_get_prandom_u32() % topo_config.nr_llcs;

	/* Explicitly bound for verifier */
	if (llc_id >= NR_CPUS)
		llc_id = 0;

	return lookup_llc_ctx(llc_id);
}

static bool keep_running(struct cpu_ctx __arena *cpuc, struct llc_ctx __arena *llcx,
			 struct task_struct *p)
{
	// Only tasks in the most interactive DSQs can keep running.
	if (!p2dq_config.keep_running_enabled ||
	    !llcx || !cpuc ||
	    cpuc->dsq_index == p2dq_config.nr_dsqs_per_llc - 1 ||
	    p->scx.flags & SCX_TASK_QUEUED ||
	    cpuc->ran_for >= timeline_config.max_exec_ns)
		return false;

	int nr_queued = llc_nr_queued(llcx);

	if (nr_queued >= llcx->nr_cpus)
		return false;

	u64 slice_ns = task_slice_ns(p, cpuc->slice_ns);
	cpuc->ran_for += slice_ns;
	p->scx.slice = slice_ns;
	stat_inc(P2DQ_STAT_KEEP);
	return true;
}

static s32 pick_idle_affinitized_cpu(struct task_struct *p, task_ctx *taskc,
				     s32 prev_cpu, bool *is_idle)
{
	const struct cpumask *idle_smtmask, *idle_cpumask;
	struct llc_ctx __arena *llcx;
	s32 cpu = prev_cpu;

	idle_cpumask = scx_bpf_get_idle_cpumask();
	idle_smtmask = scx_bpf_get_idle_smtmask();

	if (!(llcx = lookup_llc_ctx(taskc->llc_id)) ||
	    !llcx->cpumask || !llcx->tmp_cpumask)
		goto found_cpu;

	// First try last CPU
	if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		*is_idle = true;
		goto found_cpu;
	}

	// Use LLC's tmp_cpumask for intersection
	if (llcx->cpumask)
		scx_bitmap_and_cpumask(llcx->tmp_cpumask, llcx->cpumask, p->cpus_ptr);

	// First try to find an idle SMT in the LLC
	if (topo_config.smt_enabled) {
		cpu = __pick_idle_cpu(llcx->tmp_cpumask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
	}

	// Next try to find an idle CPU in the LLC
	cpu = __pick_idle_cpu(llcx->tmp_cpumask, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto found_cpu;
	}

	// Next try to find an idle CPU in the node
	if (llcx->node_cpumask) {
		scx_bitmap_and_cpumask(llcx->tmp_cpumask, llcx->node_cpumask, p->cpus_ptr);

		cpu = __pick_idle_cpu(llcx->tmp_cpumask, 0);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
	}

	// Fallback to anywhere the task can run
	cpu = bpf_cpumask_any_distribute(p->cpus_ptr);

found_cpu:
	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);

	return cpu;
}

static s32 pick_idle_cpu(struct task_struct *p, task_ctx *taskc,
			 s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	const struct cpumask *idle_smtmask = NULL, *idle_cpumask = NULL;
	struct llc_ctx __arena *llcx;
	s32 cpu = prev_cpu;
	bool migratable = false;
	bool use_arena = false;

	if (p2dq_config.interactive_sticky && task_ctx_test_flag(taskc, TASK_CTX_F_INTERACTIVE)) {
		*is_idle = scx_bpf_test_and_clear_cpu_idle(prev_cpu);
		return cpu;
	}

	// CRITICAL FAST PATH: Check prev_cpu BEFORE expensive LLC lookup
	// This is the most common case - task waking on same CPU
	if (p2dq_config.arena_idle_tracking) {
		// Arena path: need LLC context for masks, but check kernel idle first
		llcx = lookup_llc_ctx(taskc->llc_id);
		if (llcx && llcx->idle_cpumask && llcx->idle_smtmask) {
			use_arena = true;
			scx_bitmap_t mask = (topo_config.smt_enabled &&
					     !task_ctx_test_flag(taskc, TASK_CTX_F_INTERACTIVE)) ?
					    llcx->idle_smtmask : llcx->idle_cpumask;

			// Fast inline check: test arena mask + claim kernel state
			if (likely(scx_bitmap_test_cpu(prev_cpu, mask) &&
				   scx_bpf_test_and_clear_cpu_idle(prev_cpu))) {
				// Sync arena masks after successful claim
				scx_bitmap_atomic_clear_cpu(prev_cpu, llcx->idle_cpumask);
				if (topo_config.smt_enabled && llcx->idle_smtmask)
					scx_bitmap_atomic_clear_cpu(prev_cpu, llcx->idle_smtmask);
				*is_idle = true;
				return cpu;
			}
		}
	} else {
		// Kernel path: get idle masks first, THEN check prev_cpu
		idle_cpumask = scx_bpf_get_idle_cpumask();
		idle_smtmask = scx_bpf_get_idle_smtmask();

		if (!idle_cpumask || !idle_smtmask)
			goto found_cpu;

		// First check if last CPU is idle (common case - CPU cache warm)
		if (likely(bpf_cpumask_test_cpu(prev_cpu,
					 (topo_config.smt_enabled && !task_ctx_test_flag(taskc, TASK_CTX_F_INTERACTIVE)) ?
					 idle_smtmask : idle_cpumask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu))) {
			*is_idle = true;
			goto found_cpu;
		}

		llcx = lookup_llc_ctx(taskc->llc_id);
	}

	if (!use_arena && !llcx)
		llcx = lookup_llc_ctx(taskc->llc_id);

	if (!llcx || !llcx->cpumask) {
		if (use_arena)
			return cpu;
		goto found_cpu;
	}

	migratable = can_migrate(taskc, llcx);
	if (topo_config.nr_llcs > 1 &&
	    (llc_ctx_test_flag(llcx, LLC_CTX_F_SATURATED) || saturated || overloaded) &&
	    !migratable) {
		cpu = prev_cpu;
		if (use_arena)
			return cpu;
		goto found_cpu;
	}

	if (!valid_dsq(taskc->dsq_id)) {
		if (!(llcx = rand_llc_ctx())) {
			if (use_arena)
				return cpu;
			goto found_cpu;
		}
	}

	/*
	 * If the current task is waking up another task and releasing the CPU
	 * (WAKE_SYNC), attempt to migrate the wakee on the same CPU as the
	 * waker.
	 */
	if (wake_flags & SCX_WAKE_SYNC) {
		// Interactive tasks aren't worth migrating across LLCs.
		if (task_ctx_test_flag(taskc, TASK_CTX_F_INTERACTIVE) ||
		    (topo_config.nr_llcs == 2 && topo_config.nr_nodes == 2)) {
			// Try an idle CPU in the LLC.
			if (llcx->cpumask &&
			    (cpu = pick_and_claim_idle_cpu(llcx->cpumask, 0)
			     ) >= 0) {
				stat_inc(P2DQ_STAT_WAKE_LLC);
				*is_idle = true;
				goto found_cpu;
			}
			// Nothing idle, stay sticky
			stat_inc(P2DQ_STAT_WAKE_PREV);
			cpu = prev_cpu;
			goto found_cpu;
		}

		struct task_struct *waker = (void *)bpf_get_current_task_btf();
		task_ctx *waker_taskc = scx_task_data(waker);
		// Shouldn't happen, but makes code easier to follow
		if (!waker_taskc) {
			stat_inc(P2DQ_STAT_WAKE_PREV);
			goto found_cpu;
		}

		if (waker_taskc->llc_id == llcx->id ||
		    !lb_config.wakeup_llc_migrations) {
			// Try an idle smt core in the LLC.
			if (topo_config.smt_enabled &&
			    llcx->cpumask &&
			    (cpu = pick_and_claim_idle_cpu(llcx->cpumask,
							   SCX_PICK_IDLE_CORE)
			     ) >= 0) {
				stat_inc(P2DQ_STAT_WAKE_LLC);
				*is_idle = true;
				goto found_cpu;
			}
			// Try an idle cpu in the LLC.
			if (llcx->cpumask &&
			    (cpu = pick_and_claim_idle_cpu(llcx->cpumask, 0)
			     ) >= 0) {
				stat_inc(P2DQ_STAT_WAKE_LLC);
				*is_idle = true;
				goto found_cpu;
			}
			// Nothing idle, stay sticky
			stat_inc(P2DQ_STAT_WAKE_PREV);
			cpu = prev_cpu;
			goto found_cpu;
		}

		// If wakeup LLC are allowed then migrate to the waker llc.
		struct llc_ctx __arena *waker_llcx = lookup_llc_ctx(waker_taskc->llc_id);
		if (!waker_llcx) {
			stat_inc(P2DQ_STAT_WAKE_PREV);
			cpu = prev_cpu;
			goto found_cpu;
		}

		if (waker_llcx->cpumask &&
		    (cpu = pick_and_claim_idle_cpu(waker_llcx->cpumask,
						   SCX_PICK_IDLE_CORE)
		     ) >= 0) {
			stat_inc(P2DQ_STAT_WAKE_MIG);
			*is_idle = true;
			goto found_cpu;
		}

		// Couldn't find an idle core so just migrate to the CPU
		if (waker_llcx->cpumask &&
		    (cpu = pick_and_claim_idle_cpu(waker_llcx->cpumask, 0)
		     ) >= 0) {
			stat_inc(P2DQ_STAT_WAKE_MIG);
			*is_idle = true;
			goto found_cpu;
		}

		// Nothing idle, move to waker CPU
		cpu = scx_bpf_task_cpu(waker);
		stat_inc(P2DQ_STAT_WAKE_MIG);
		goto found_cpu;
	}

	if (p2dq_config.sched_mode == MODE_PERF &&
	    topo_config.has_little_cores &&
	    llcx->big_cpumask) {
		cpu = pick_and_claim_idle_cpu(llcx->big_cpumask,
					      SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
		if (llcx->big_cpumask) {
			cpu = pick_and_claim_idle_cpu(llcx->big_cpumask, 0);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		}
	}

	if (p2dq_config.sched_mode == MODE_EFFICIENCY &&
	    topo_config.has_little_cores &&
	    llcx->little_cpumask) {
		cpu = pick_and_claim_idle_cpu(llcx->little_cpumask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
		if (llcx->little_cpumask) {
			cpu = pick_and_claim_idle_cpu(llcx->little_cpumask, 0);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		}
	}


	if (llcx->lb_llc_id < MAX_LLCS &&
	    taskc->llc_runs == 0) {
		u32 target_llc_id = llcx->lb_llc_id;
		llcx->lb_llc_id = MAX_LLCS;
		if (!(llcx = lookup_llc_ctx(target_llc_id)))
			goto found_cpu;
		stat_inc(P2DQ_STAT_SELECT_PICK2);
	}

	if (topo_config.has_little_cores &&
	    llcx->little_cpumask && llcx->big_cpumask) {
		if (task_ctx_test_flag(taskc, TASK_CTX_F_INTERACTIVE)) {
			cpu = pick_and_claim_idle_cpu(llcx->little_cpumask, 0);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		} else {
			cpu = pick_and_claim_idle_cpu(llcx->big_cpumask,
						      SCX_PICK_IDLE_CORE);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		}
	}

	// Next try in the local LLC (usually succeeds)
	if (use_arena) {
		// ARENA PATH: Use fast picker (bypasses heap check)
		if (likely((cpu = llc_pick_idle_smt(llcx)) >= 0)) {
			*is_idle = true;
			goto found_cpu;
		}
	} else {
		// KERNEL PATH: Use kernel masks
		if (likely(llcx->cpumask &&
		    (cpu = pick_and_claim_idle_cpu(llcx->cpumask, SCX_PICK_IDLE_CORE)) >= 0)) {
			*is_idle = true;
			goto found_cpu;
		}
	}

	// Try an idle CPU in the llc (also likely to succeed)
	if (use_arena) {
		// ARENA PATH: Use fast picker (bypasses heap check)
		if (likely((cpu = llc_pick_idle_cpu_fast(llcx, 0)) >= 0)) {
			*is_idle = true;
			goto found_cpu;
		}
	} else {
		// KERNEL PATH: Use kernel masks
		if (likely(llcx->cpumask &&
		    (cpu = pick_and_claim_idle_cpu(llcx->cpumask, 0)) >= 0)) {
			*is_idle = true;
			goto found_cpu;
		}
	}

	if (topo_config.nr_llcs > 1 &&
	    llc_ctx_test_flag(llcx, LLC_CTX_F_SATURATED) &&
	    migratable &&
	    llcx->node_cpumask) {
		cpu = pick_and_claim_idle_cpu(llcx->node_cpumask,
					      SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto found_cpu;
		}
		if (llcx->node_cpumask) {
			cpu = pick_and_claim_idle_cpu(llcx->node_cpumask, 0);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
		}
		if (saturated && migratable && all_cpumask) {
			cpu = pick_and_claim_idle_cpu(all_cpumask,
						      SCX_PICK_IDLE_CORE);
			if (cpu >= 0) {
				*is_idle = true;
				goto found_cpu;
			}
			if (all_cpumask) {
				cpu = pick_and_claim_idle_cpu(all_cpumask, 0);
				if (cpu >= 0) {
					*is_idle = true;
					goto found_cpu;
				}
			}
		}
	}

	cpu = prev_cpu;

found_cpu:
	// Release kernel cpumasks only if we fetched them
	if (!use_arena) {
		if (idle_cpumask)
			scx_bpf_put_cpumask(idle_cpumask);
		if (idle_smtmask)
			scx_bpf_put_cpumask(idle_smtmask);
	}

	return cpu;
}


static s32 p2dq_select_cpu_impl(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	task_ctx *taskc;
	bool is_idle = false;
	s32 cpu;

	if (!(taskc = lookup_task_ctx(p)))
		return prev_cpu;

	if (unlikely(!task_ctx_test_flag(taskc, TASK_CTX_F_ALL_CPUS)))
		cpu = pick_idle_affinitized_cpu(p, taskc, prev_cpu, &is_idle);
	else
		cpu = pick_idle_cpu(p, taskc, prev_cpu, wake_flags, &is_idle);

	if (likely(is_idle)) {
		stat_inc(P2DQ_STAT_IDLE);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, taskc->slice_ns, 0);
	}
	trace("SELECT [%d][%s] %i->%i idle %i",
	      p->pid, p->comm, prev_cpu, cpu, is_idle);

	return cpu;
}


/*
 * Perform the enqueue logic for `p` but don't enqueue it where possible.  This
 * is primarily used so that scx_chaos can decide to enqueue a task either
 * immediately in `enqueue` or later in `dispatch`. This returns a tagged union
 * with three states:
 * - P2DQ_ENQUEUE_PROMISE_COMPLETE: The enqueue has been completed. Note that
 *     this case _must_ be determinstic, or else scx_chaos will stall. That is,
 *     if the same task and enq_flags arrive twice, it must have returned
 *     _COMPLETE the first time to return it again.
 * - P2DQ_ENQUEUE_PROMISE_FIFO: The completer should enqueue this task on a fifo dsq.
 * - P2DQ_ENQUEUE_PROMISE_VTIME: The completer should enqueue this task on a vtime dsq.
 * - P2DQ_ENQUEUE_PROMISE_FAILED: The enqueue failed.
 */
static void async_p2dq_enqueue(struct enqueue_promise *ret,
			       struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx __arena *cpuc;
	struct llc_ctx __arena *llcx;
	task_ctx *taskc;
	s32 cpu = scx_bpf_task_cpu(p);

	// Default to 0 and set to failed.
	__builtin_memset(ret, 0, sizeof(*ret));
	ret->kind = P2DQ_ENQUEUE_PROMISE_FAILED;

	/*
	 * Per-cpu kthreads are considered interactive and dispatched directly
	 * into the local DSQ.
	 */
	if (unlikely(p2dq_config.kthreads_local &&
	    (p->flags & PF_KTHREAD) &&
	    p->nr_cpus_allowed == 1)) {
		stat_inc(P2DQ_STAT_DIRECT);
		scx_bpf_dsq_insert(p,
				   SCX_DSQ_LOCAL,
				   max_dsq_time_slice(),
				   enq_flags);
		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		ret->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
		return;
	}

	if(!(taskc = lookup_task_ctx(p))) {
		scx_bpf_error("invalid lookup");
		return;
	}

	// Handle affinitized tasks separately
	if (!task_ctx_test_flag(taskc, TASK_CTX_F_ALL_CPUS) ||
	    (p->cpus_ptr == &p->cpus_mask &&
	     p->nr_cpus_allowed != topo_config.nr_cpus)) {
		bool has_cleared_idle = false;
		if (!__COMPAT_is_enq_cpu_selected(enq_flags) ||
		    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			cpu = pick_idle_affinitized_cpu(p,
							taskc,
							cpu,
							&has_cleared_idle);
		else
			has_cleared_idle = scx_bpf_test_and_clear_cpu_idle(cpu);

		if (has_cleared_idle)
			enqueue_promise_set_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE);
		else
			enqueue_promise_clear_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE);

		ret->cpu = cpu;
		cpuc = lookup_cpu_ctx(cpu);
		if (!cpuc) {
			// CPU doesn't have topology, use CPU 0 as fallback
			cpuc = lookup_cpu_ctx(0);
			if (!cpuc) {
				scx_bpf_error("no valid CPU contexts");
				return;
			}
			// Update cpu variable to match the fallback
			cpu = 0;
			ret->cpu = 0;
		}

		llcx = lookup_llc_ctx(cpuc->llc_id);
		if (!llcx) {
			scx_bpf_error("no LLC context for CPU %d", cpuc->id);
			return;
		}

		stat_inc(P2DQ_STAT_ENQ_CPU);
		taskc->dsq_id = cpuc->affn_dsq;
		update_vtime(p, cpuc, taskc, llcx);
		if (timeline_config.deadline)
			set_deadline_slice(p, taskc, llcx);

		if (cpu_ctx_test_flag(cpuc, CPU_CTX_F_NICE_TASK))
			enq_flags |= SCX_ENQ_PREEMPT;

		// Idle affinitized tasks can be direct dispatched.
		if ((enqueue_promise_test_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE) ||
		    cpu_ctx_test_flag(cpuc, CPU_CTX_F_NICE_TASK)) &&
		    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			ret->kind = P2DQ_ENQUEUE_PROMISE_FIFO;
			ret->fifo.dsq_id = SCX_DSQ_LOCAL;
			ret->fifo.slice_ns = taskc->slice_ns;
			ret->fifo.enq_flags = enq_flags;
			if (enqueue_promise_test_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE))
				enqueue_promise_set_flag(ret, ENQUEUE_PROMISE_F_KICK_IDLE);
			return;
		}

		ret->kind = P2DQ_ENQUEUE_PROMISE_VTIME;
		ret->vtime.dsq_id = taskc->dsq_id;
		ret->vtime.slice_ns = taskc->slice_ns;
		ret->vtime.enq_flags = enq_flags;
		ret->vtime.vtime = p->scx.dsq_vtime;

		trace("ENQUEUE %s weight %d slice %llu vtime %llu llc vtime %llu",
		      p->comm, p->scx.weight, taskc->slice_ns,
		      p->scx.dsq_vtime, llcx->vtime);

		return;
	}

	// If an idle CPU hasn't been found in select_cpu find one now
	if (!__COMPAT_is_enq_cpu_selected(enq_flags)) {
		bool has_cleared_idle = false;
		cpu = pick_idle_cpu(p,
				    taskc,
				    cpu,
				    0,
				    &has_cleared_idle);
		if (has_cleared_idle)
			enqueue_promise_set_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE);
		else
			enqueue_promise_clear_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE);

		cpuc = lookup_cpu_ctx(cpu);
		if (!cpuc) {
			// CPU doesn't have topology, use CPU 0 as fallback
			cpuc = lookup_cpu_ctx(0);
			if (!cpuc) {
				scx_bpf_error("no valid CPU contexts");
				return;
			}
		}

		llcx = lookup_llc_ctx(cpuc->llc_id);
		if (!llcx) {
			scx_bpf_error("no LLC context for CPU %d", cpuc->id);
			return;
		}

		ret->cpu = cpu;
		update_vtime(p, cpuc, taskc, llcx);
		if (timeline_config.deadline)
			set_deadline_slice(p, taskc, llcx);

		if (cpu_ctx_test_flag(cpuc, CPU_CTX_F_NICE_TASK))
			enq_flags |= SCX_ENQ_PREEMPT;

		if ((enqueue_promise_test_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE) ||
		     cpu_ctx_test_flag(cpuc, CPU_CTX_F_NICE_TASK)) &&
		    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			ret->kind = P2DQ_ENQUEUE_PROMISE_FIFO;
			ret->fifo.dsq_id = SCX_DSQ_LOCAL_ON|cpu;
			ret->fifo.slice_ns = taskc->slice_ns;
			ret->fifo.enq_flags = enq_flags;
			if (enqueue_promise_test_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE))
				enqueue_promise_set_flag(ret, ENQUEUE_PROMISE_F_KICK_IDLE);
			return;
		}

		bool migrate = likely(!lb_config.single_llc_mode) && can_migrate(taskc, llcx);
		if (migrate) {
			taskc->dsq_id = llcx->mig_dsq;
			if (p2dq_config.atq_enabled) {
				taskc->enq_flags = enq_flags;
				ret->kind = P2DQ_ENQUEUE_PROMISE_ATQ_VTIME;
				ret->vtime.dsq_id = cpuc->llc_dsq;
				ret->vtime.atq = llcx->mig_atq;
				ret->vtime.slice_ns = taskc->slice_ns;
				ret->vtime.vtime = p->scx.dsq_vtime;
			} else {
				ret->kind = P2DQ_ENQUEUE_PROMISE_VTIME;
				ret->vtime.dsq_id = taskc->dsq_id;
				ret->vtime.slice_ns = taskc->slice_ns;
				ret->vtime.enq_flags = enq_flags;
				ret->vtime.vtime = p->scx.dsq_vtime;
			}
			stat_inc(P2DQ_STAT_ENQ_MIG);
		} else {
			taskc->dsq_id = cpuc->llc_dsq;
			ret->kind = P2DQ_ENQUEUE_PROMISE_VTIME;
			ret->vtime.dsq_id = taskc->dsq_id;
			ret->vtime.slice_ns = taskc->slice_ns;
			ret->vtime.enq_flags = enq_flags;
			ret->vtime.vtime = p->scx.dsq_vtime;
			stat_inc(P2DQ_STAT_ENQ_LLC);
		}

		trace("ENQUEUE %s weight %d slice %llu vtime %llu llc vtime %llu",
		      p->comm, p->scx.weight, taskc->slice_ns,
		      p->scx.dsq_vtime, llcx->vtime);

		return;
	}

	cpuc = lookup_cpu_ctx(scx_bpf_task_cpu(p));
	if (!cpuc) {
		// CPU doesn't have topology, use CPU 0 as fallback
		cpuc = lookup_cpu_ctx(0);
		if (!cpuc) {
			scx_bpf_error("no valid CPU contexts");
			return;
		}
	}

	llcx = lookup_llc_ctx(cpuc->llc_id);
	if (!llcx) {
		scx_bpf_error("no LLC context for CPU %d", cpuc->id);
		return;
	}
	ret->cpu = cpuc->id;
	cpu = cpuc->id;  // Update cpu to match cpuc after potential fallback

	if (cpu_ctx_test_flag(cpuc, CPU_CTX_F_NICE_TASK))
		enq_flags |= SCX_ENQ_PREEMPT;

	update_vtime(p, cpuc, taskc, llcx);
	if (timeline_config.deadline)
		set_deadline_slice(p, taskc, llcx);

	bool has_cleared_idle = scx_bpf_test_and_clear_cpu_idle(cpu);
	if (has_cleared_idle)
		enqueue_promise_set_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE);
	else
		enqueue_promise_clear_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE);

	if (enqueue_promise_test_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE) ||
	    cpu_ctx_test_flag(cpuc, CPU_CTX_F_NICE_TASK)) {
		ret->kind = P2DQ_ENQUEUE_PROMISE_FIFO;
		// Validate CPU before using for SCX_DSQ_LOCAL_ON
		if (unlikely(cpu < 0 || cpu >= topo_config.nr_cpus ||
		    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr)))
			ret->fifo.dsq_id = SCX_DSQ_LOCAL;
		else
			ret->fifo.dsq_id = SCX_DSQ_LOCAL_ON|cpu;
		ret->fifo.slice_ns = taskc->slice_ns;
		ret->fifo.enq_flags = enq_flags;
		if (enqueue_promise_test_flag(ret, ENQUEUE_PROMISE_F_HAS_CLEARED_IDLE))
			enqueue_promise_set_flag(ret, ENQUEUE_PROMISE_F_KICK_IDLE);
		return;
	}

	bool migrate = likely(!lb_config.single_llc_mode) && can_migrate(taskc, llcx);
	if (migrate) {
		taskc->dsq_id = llcx->mig_dsq;
		stat_inc(P2DQ_STAT_ENQ_MIG);
		if (p2dq_config.atq_enabled) {
			taskc->enq_flags = enq_flags;
			ret->kind = P2DQ_ENQUEUE_PROMISE_ATQ_VTIME;
			ret->vtime.dsq_id = cpuc->llc_dsq;
			ret->vtime.atq = llcx->mig_atq;
			ret->vtime.slice_ns = taskc->slice_ns;
			ret->vtime.vtime = p->scx.dsq_vtime;

			return;
		}
	} else {
		taskc->dsq_id = cpuc->llc_dsq;
		stat_inc(P2DQ_STAT_ENQ_LLC);
	}

	trace("ENQUEUE %s weight %d slice %llu vtime %llu llc vtime %llu",
	      p->comm, p->scx.weight, taskc->slice_ns,
	      p->scx.dsq_vtime, llcx->vtime);

	ret->kind = P2DQ_ENQUEUE_PROMISE_VTIME;
	ret->vtime.dsq_id = taskc->dsq_id;
	ret->vtime.enq_flags = enq_flags;
	ret->vtime.slice_ns = taskc->slice_ns;
	ret->vtime.vtime = p->scx.dsq_vtime;
}

static void complete_p2dq_enqueue(struct enqueue_promise *pro, struct task_struct *p)
{
	int ret;

	switch (pro->kind) {
	case P2DQ_ENQUEUE_PROMISE_COMPLETE:
		break;
	case P2DQ_ENQUEUE_PROMISE_FIFO:
		scx_bpf_dsq_insert(p,
				   pro->fifo.dsq_id,
				   pro->fifo.slice_ns,
				   pro->fifo.enq_flags);
		break;
	case P2DQ_ENQUEUE_PROMISE_VTIME:
		scx_bpf_dsq_insert_vtime(p,
					 pro->vtime.dsq_id,
					 pro->vtime.slice_ns,
				         pro->vtime.vtime,
					 pro->vtime.enq_flags);
		break;
	case P2DQ_ENQUEUE_PROMISE_ATQ_FIFO:
		if (!pro->fifo.atq) {
			scx_bpf_error("invalid ATQ");
			break;
		}
		ret = scx_atq_insert(pro->fifo.atq, (u64)p->pid);
		if (!ret) {
			// The ATQ was full, fallback to the DSQ.
			scx_bpf_dsq_insert(p,
					   pro->vtime.dsq_id,
					   pro->vtime.slice_ns,
					   pro->vtime.enq_flags);
			stat_inc(P2DQ_STAT_ATQ_REENQ);
		} else {
			stat_inc(P2DQ_STAT_ATQ_ENQ);
		}
		break;
	case P2DQ_ENQUEUE_PROMISE_ATQ_VTIME:
		if (!pro->vtime.atq) {
			scx_bpf_error("invalid ATQ");
			break;
		}
		ret = scx_atq_insert_vtime(pro->vtime.atq,
					       (u64)p->pid,
					       pro->vtime.vtime);
		if (!ret) {
			// The ATQ was full, fallback to the DSQ.
			scx_bpf_dsq_insert_vtime(p,
						 pro->vtime.dsq_id,
						 pro->vtime.slice_ns,
						 pro->vtime.vtime,
						 pro->vtime.enq_flags);
			stat_inc(P2DQ_STAT_ATQ_REENQ);
		} else {
			stat_inc(P2DQ_STAT_ATQ_ENQ);
		}
		break;
	case P2DQ_ENQUEUE_PROMISE_FAILED:
		// should have already errored with a more specific error, but
		// just for luck.
		scx_bpf_error("p2dq enqueue failed");
		break;
	}

	if (enqueue_promise_test_flag(pro, ENQUEUE_PROMISE_F_KICK_IDLE)) {
		stat_inc(P2DQ_STAT_IDLE);
		scx_bpf_kick_cpu(pro->cpu, SCX_KICK_IDLE);
	}

	pro->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
}

static int p2dq_running_impl(struct task_struct *p)
{
	task_ctx *taskc;
	struct cpu_ctx __arena *cpuc;
	struct llc_ctx __arena *llcx;
	s32 task_cpu = scx_bpf_task_cpu(p);

	taskc = lookup_task_ctx(p);
	if (!taskc)
		return -EINVAL;

	cpuc = lookup_cpu_ctx(task_cpu);
	if (!cpuc) {
		// CPU doesn't have topology, use CPU 0 as fallback
		cpuc = lookup_cpu_ctx(0);
		if (!cpuc)
			return -EINVAL;
	}

	llcx = lookup_llc_ctx(cpuc->llc_id);
	if (!llcx)
		return -EINVAL;

	if (taskc->llc_id != cpuc->llc_id) {
		task_refresh_llc_runs(taskc);
		stat_inc(P2DQ_STAT_LLC_MIGRATION);
		trace("RUNNING %d cpu %d->%d llc %d->%d",
		      p->pid, cpuc->id, task_cpu,
		      taskc->llc_id, llcx->id);
	} else {
		if (taskc->llc_runs == 0)
			task_refresh_llc_runs(taskc);
		else
			taskc->llc_runs -= 1;
	}
	if (taskc->node_id != cpuc->node_id) {
		stat_inc(P2DQ_STAT_NODE_MIGRATION);
	}

	taskc->llc_id = llcx->id;
	taskc->node_id = llcx->node_id;
	if (p->scx.weight < 100)
		task_ctx_set_flag(taskc, TASK_CTX_F_WAS_NICE);
	else
		task_ctx_clear_flag(taskc, TASK_CTX_F_WAS_NICE);

	if (task_ctx_test_flag(taskc, TASK_CTX_F_INTERACTIVE))
		cpu_ctx_set_flag(cpuc, CPU_CTX_F_INTERACTIVE);
	else
		cpu_ctx_clear_flag(cpuc, CPU_CTX_F_INTERACTIVE);

	cpuc->dsq_index = taskc->dsq_index;

	if (p->scx.weight < 100)
		cpu_ctx_set_flag(cpuc, CPU_CTX_F_NICE_TASK);
	else
		cpu_ctx_clear_flag(cpuc, CPU_CTX_F_NICE_TASK);

	cpuc->slice_ns = taskc->slice_ns;
	cpuc->ran_for = 0;
	// racy, but don't care
	if (p->scx.dsq_vtime > llcx->vtime &&
	    p->scx.dsq_vtime < llcx->vtime + max_dsq_time_slice()) {
		__sync_val_compare_and_swap(&llcx->vtime,
					    llcx->vtime, p->scx.dsq_vtime);
	}

	// If the task is running in the least interactive DSQ, bump the
	// frequency.
	if (p2dq_config.freq_control &&
	    taskc->dsq_index == p2dq_config.nr_dsqs_per_llc - 1) {
		scx_bpf_cpuperf_set(task_cpu, SCX_CPUPERF_ONE);
	}

	u64 now = bpf_ktime_get_ns();
	if (taskc->last_run_started == 0)
		taskc->last_run_started = now;

	taskc->last_run_at = now;

	return 0;
}

void BPF_STRUCT_OPS(p2dq_stopping, struct task_struct *p, bool runnable)
{
	task_ctx *taskc;
	struct llc_ctx __arena *llcx;
	struct cpu_ctx __arena *cpuc;
	u64 used, scaled_used, last_dsq_slice_ns;
	u64 now = bpf_ktime_get_ns();

	if (unlikely(!(taskc = lookup_task_ctx(p)) ||
	    !(llcx = lookup_llc_ctx(taskc->llc_id))))
		return;

	// can't happen, appease the verifier
	int dsq_index = taskc->dsq_index;
	if (dsq_index < 0 || dsq_index >= p2dq_config.nr_dsqs_per_llc) {
		scx_bpf_error("taskc invalid dsq index");
		return;
	}

	// This is an optimization to not have to lookup the cpu_ctx every
	// time. When a nice task was run we need to update the cpu_ctx so that
	// tasks are no longer enqueued to the local DSQ.
	if (task_ctx_test_flag(taskc, TASK_CTX_F_WAS_NICE) &&
	    (cpuc = lookup_cpu_ctx(scx_bpf_task_cpu(p)))) {
		cpu_ctx_clear_flag(cpuc, CPU_CTX_F_NICE_TASK);
		task_ctx_clear_flag(taskc, TASK_CTX_F_WAS_NICE);
	}

	taskc->last_dsq_id = taskc->dsq_id;
	taskc->last_dsq_index = taskc->dsq_index;
	taskc->used = 0;

	last_dsq_slice_ns = taskc->slice_ns;
	used = now - taskc->last_run_at;
	scaled_used = scale_by_task_weight_inverse(p, used);

	p->scx.dsq_vtime += scaled_used;
	__sync_fetch_and_add(&llcx->vtime, used);
	__sync_fetch_and_add(&llcx->load, used);
	if (taskc->dsq_index >= 0 && taskc->dsq_index < MAX_DSQS_PER_LLC)
		__sync_fetch_and_add(&llcx->dsq_load[taskc->dsq_index], used);

	if (task_ctx_test_flag(taskc, TASK_CTX_F_INTERACTIVE))
		__sync_fetch_and_add(&llcx->intr_load, used);

	if (!task_ctx_test_flag(taskc, TASK_CTX_F_ALL_CPUS))
		// Note that affinitized load is absolute load, not scaled.
		__sync_fetch_and_add(&llcx->affn_load, used);

	trace("STOPPING %s weight %d slice %llu used %llu scaled %llu",
	      p->comm, p->scx.weight, last_dsq_slice_ns, used, scaled_used);

	if (!runnable) {
		used = now - taskc->last_run_started;
		// On stopping determine if the task can move to a longer DSQ by
		// comparing the used time to the scaled DSQ slice.
		if (used >= ((9 * last_dsq_slice_ns) / 10)) {
			if (taskc->dsq_index < p2dq_config.nr_dsqs_per_llc - 1 &&
			    p->scx.weight >= 100) {
				taskc->dsq_index += 1;
				stat_inc(P2DQ_STAT_DSQ_CHANGE);
				trace("%s[%p]: DSQ inc %llu -> %u", p->comm, p,
				      taskc->last_dsq_index, taskc->dsq_index);
			} else {
				stat_inc(P2DQ_STAT_DSQ_SAME);
			}
		// If under half the slice was consumed move the task back down.
		} else if (used < last_dsq_slice_ns / 2) {
			if (taskc->dsq_index > 0) {
				taskc->dsq_index -= 1;
				stat_inc(P2DQ_STAT_DSQ_CHANGE);
				trace("%s[%p]: DSQ dec %llu -> %u",
				      p->comm, p,
				      taskc->last_dsq_index, taskc->dsq_index);
			} else {
				stat_inc(P2DQ_STAT_DSQ_SAME);
			}
		} else {
			stat_inc(P2DQ_STAT_DSQ_SAME);
		}

		// nice tasks can only get the minimal amount of non
		// interactive slice.
		if (p->scx.weight < 100 && taskc->dsq_index > 1)
			taskc->dsq_index = 1;

		if (p2dq_config.task_slice) {
			if (used >= ((7 * last_dsq_slice_ns) / 8)) {
				taskc->slice_ns = clamp_slice((5 * taskc->slice_ns) >> 2);
			} else if (used < last_dsq_slice_ns / 2) {
				taskc->slice_ns = clamp_slice((7 * taskc->slice_ns) >> 3);
			}
		} else {
			taskc->slice_ns = task_dsq_slice_ns(p, taskc->dsq_index);
		}
		taskc->last_run_started = 0;
		if (is_interactive(taskc))
			task_ctx_set_flag(taskc, TASK_CTX_F_INTERACTIVE);
		else
			task_ctx_clear_flag(taskc, TASK_CTX_F_INTERACTIVE);
	}
}

static bool consume_llc(struct llc_ctx __arena *llcx)
{
	struct task_struct *p;
	task_ctx *taskc;
	u64 pid;

	if (!llcx)
		return false;

	if (p2dq_config.atq_enabled &&
	    scx_atq_nr_queued(llcx->mig_atq) > 0) {
		pid = scx_atq_pop(llcx->mig_atq);
		p = bpf_task_from_pid((s32)pid);
		if (!p) {
			trace("ATQ failed to get pid %llu", pid);
			return false;
		}

		if (!(taskc = lookup_task_ctx(p))) {
			bpf_task_release(p);
			return false;
		}

		trace("ATQ %llu insert %s->%d",
		      llcx->mig_atq, p->comm, p->pid);
		scx_bpf_dsq_insert(p,
				   SCX_DSQ_LOCAL,
				   taskc->slice_ns,
				   taskc->enq_flags);
		bpf_task_release(p);

		return false;
	}

	if (likely(scx_bpf_dsq_move_to_local(llcx->mig_dsq))) {
		stat_inc(P2DQ_STAT_DISPATCH_PICK2);
		return true;
	}

	return false;
}

static __always_inline int dispatch_pick_two(s32 cpu, struct llc_ctx __arena *cur_llcx, struct cpu_ctx __arena *cpuc)
{
	struct llc_ctx __arena *first, *second, *left, *right;
	int i;
	u64 cur_load;

	// Single-LLC fast path: skip pick-2 entirely
	if (unlikely(lb_config.single_llc_mode))
		return -EINVAL;

	if (!cur_llcx || !cpuc)
		return -EINVAL;

	// If on a single LLC there isn't anything left to try.
	if (unlikely(topo_config.nr_llcs == 1 ||
	    lb_config.dispatch_pick2_disable ||
	    topo_config.nr_llcs >= MAX_LLCS))
		return -EINVAL;


	if (lb_config.min_nr_queued_pick2 > 0) {
		u64 nr_queued = llc_nr_queued(cur_llcx);
		if (nr_queued < lb_config.min_nr_queued_pick2)
			return -EINVAL;
	}

	if (lb_config.backoff_ns > 0) {
		u64 now = scx_bpf_now();
		if (now - cur_llcx->last_period_ns < lb_config.backoff_ns)
			return -EINVAL;
	}

	/*
	 * For pick two load balancing we randomly choose two LLCs. We then
	 * first try to consume from the LLC with the largest load. If we are
	 * unable to consume from the first LLC then the second LLC is consumed
	 * from. This yields better work conservation on machines with a large
	 * number of LLCs.
	 */
	left = topo_config.nr_llcs == 2 ? lookup_llc_ctx(llc_ids[0]) : rand_llc_ctx();
	right = topo_config.nr_llcs == 2 ? lookup_llc_ctx(llc_ids[1]) : rand_llc_ctx();

	if (!left || !right)
		return -EINVAL;

	if (left->id == right->id) {
		i = cur_llcx->load % topo_config.nr_llcs;
		i &= 0x3; // verifier
		if (i >= 0 && i < topo_config.nr_llcs)
			right = lookup_llc_ctx(llc_ids[i]);
		if (!right)
			return -EINVAL;
	}


	if (right->load > left->load) {
		first = right;
		second = left;
	} else {
		first = left;
		second = right;
	}

	// Handle the edge case where there are two LLCs and the current has
	// more load. Since it's already been checked start with the other LLC.
	if (topo_config.nr_llcs == 2 && first->id == cur_llcx->id) {
		first = second;
		second = cur_llcx;
	}

	trace("PICK2 cpu[%d] first[%d] %llu second[%d] %llu",
	      cpu, first->id, first->load, second->id, second->load);

	cur_load = cur_llcx->load + ((cur_llcx->load * lb_config.slack_factor) / 100);

	if (first->load >= cur_load &&
	    consume_llc(first))
		return 0;

	if (second->load >= cur_load &&
	    consume_llc(second))
		return 0;

	if (saturated) {
		if (consume_llc(first))
			return 0;

		if (consume_llc(second))
			return 0;

		// If the system is saturated then be aggressive in trying to load balance.
		if (topo_config.nr_llcs > 2 &&
		    (first = rand_llc_ctx()) &&
		    consume_llc(first))
			return 0;
	}

	return 0;
}


static void p2dq_dispatch_impl(s32 cpu, struct task_struct *prev)
{
	struct task_struct *p;
	task_ctx *taskc;
	struct cpu_ctx __arena *cpuc;
	struct llc_ctx __arena *llcx;
	u64 pid, peeked_pid, dsq_id = 0;
	scx_atq_t *min_atq = NULL;

	cpuc = lookup_cpu_ctx(cpu);
	if (unlikely(!cpuc)) {
		// CPU doesn't have topology, use CPU 0 as fallback
		cpuc = lookup_cpu_ctx(0);
		if (!cpuc) {
			// No valid CPUs - this is a critical error
			scx_bpf_error("no valid CPU contexts in dispatch");
			return;
		}
	}

	u64 min_vtime = 0;

	if (!saturated) {
		// First search affinitized DSQ
		p = __COMPAT_scx_bpf_dsq_peek(cpuc->affn_dsq);
		if (p) {
			if (p->scx.dsq_vtime < min_vtime || min_vtime == 0) {
				min_vtime = p->scx.dsq_vtime;
				dsq_id = cpuc->affn_dsq;
			}
		}
		// LLC DSQ
		p = __COMPAT_scx_bpf_dsq_peek(cpuc->llc_dsq);
		if (p) {
			if (p->scx.dsq_vtime < min_vtime || min_vtime == 0) {
				min_vtime = p->scx.dsq_vtime;
				dsq_id = cpuc->llc_dsq;
			}
		}

		// Migration eligible
		if (topo_config.nr_llcs > 1) {
			if (p2dq_config.atq_enabled) {
				pid = scx_atq_peek(cpuc->mig_atq);
				if ((p = bpf_task_from_pid((s32)pid))) {
					if (p->scx.dsq_vtime < min_vtime ||
					    min_vtime == 0) {
						min_vtime = p->scx.dsq_vtime;
						min_atq = cpuc->mig_atq;
						/*
						 * Normally doing these peeks would be
						 * racy with scx_bpf_dsq_move_to_local.
						 * However, with ATQs we can peek and
						 * pop so we can check that the popped
						 * task is the same as the peeked task.
						 * This gives slightly better
						 * prioritization with the potential
						 * cost of having to reenqueue popped
						 * tasks.
						 */
						peeked_pid = p->pid;
					}
					bpf_task_release(p);
				}
			} else {
				p = __COMPAT_scx_bpf_dsq_peek(cpuc->mig_dsq);
				if (p) {
					if (p->scx.dsq_vtime < min_vtime ||
					    min_vtime == 0) {
						min_vtime = p->scx.dsq_vtime;
						dsq_id = cpuc->mig_dsq;
					}
				}
			}
		}
	}

	if (dsq_id != 0)
		trace("DISPATCH cpu[%d] min_vtime %llu dsq_id %llu atq %llu",
		      cpu, min_vtime, dsq_id, min_atq);

	// First try the DSQ with the lowest vtime for fairness.
	if (unlikely(min_atq)) {
		trace("ATQ dispatching %llu with min vtime %llu", min_atq, min_vtime);
		pid = scx_atq_pop(min_atq);
		if (likely((p = bpf_task_from_pid((s32)pid)))) {
			/*
			 * Need to ensure the peeked_pid is the pid popped off
			 * the ATQ. Otherwise there may be priority inversions.
			 * This probably needs to be done for the DSQs as well.
			 */
			if (unlikely(!(taskc = lookup_task_ctx(p)))) {
				bpf_task_release(p);
				scx_bpf_error("failed to get task ctx");
				return;
			}
			if (p->pid == peeked_pid) {
				scx_bpf_dsq_insert(p,
						   SCX_DSQ_LOCAL,
						   taskc->slice_ns,
						   taskc->enq_flags);
				bpf_task_release(p);
				return;
			} else {
				/*
				 * The task that was popped was already
				 * consumed. The next task that was popped
				 * might have a higher vtime so reenqueue it
				 * back to the LLC DSQ.
				 */
				scx_bpf_dsq_insert_vtime(p,
						   cpuc->llc_dsq,
						   taskc->slice_ns,
						   p->scx.dsq_vtime,
						   taskc->enq_flags);
				bpf_task_release(p);
				stat_inc(P2DQ_STAT_ATQ_REENQ);
			}
		}
	} else {
		if (likely(valid_dsq(dsq_id) && scx_bpf_dsq_move_to_local(dsq_id)))
			return;
	}

	// Try affinitized DSQ (less common, affinitized tasks are a minority)
	if (unlikely(dsq_id != cpuc->affn_dsq &&
	    scx_bpf_dsq_move_to_local(cpuc->affn_dsq)))
		return;

	// Handle sharded LLC DSQs, try to dispatch from all shards if sharding
	// is enabled (common on large systems)
	if (likely(p2dq_config.llc_shards > 1)) {
		// First try the current CPU's assigned shard
		if (dsq_id != cpuc->llc_dsq &&
		    scx_bpf_dsq_move_to_local(cpuc->llc_dsq))
			return;

		if ((llcx = lookup_llc_ctx(cpuc->llc_id)) && llcx->nr_shards > 1) {
			// Then try other shards in the LLC for work stealing
			u32 shard_idx;
			bpf_for(shard_idx, 0, llcx->nr_shards) {
				u32 offset = cpuc->id % llcx->nr_shards;
				shard_idx = wrap_index(offset + shard_idx, 0, llcx->nr_shards);
				// TODO: should probably take min vtime to be fair
				if (shard_idx < MAX_LLC_SHARDS && shard_idx < llcx->nr_shards) {
					u64 shard_dsq = *MEMBER_VPTR(llcx->shard_dsqs, [shard_idx]);
					if (shard_dsq != cpuc->llc_dsq && shard_dsq != dsq_id &&
					    scx_bpf_dsq_move_to_local(shard_dsq))
						return;
				}
			}
		}
	} else {
		if (dsq_id != cpuc->llc_dsq &&
		    scx_bpf_dsq_move_to_local(cpuc->llc_dsq))
			return;
	}

	if (unlikely(p2dq_config.atq_enabled)) {
		pid = scx_atq_pop(cpuc->mig_atq);
		if (likely((p = bpf_task_from_pid((s32)pid)))) {
			if (unlikely(!(taskc = lookup_task_ctx(p)))) {
				bpf_task_release(p);
				scx_bpf_error("failed to get task ctx");
				return;
			}
			scx_bpf_dsq_insert(p,
					   SCX_DSQ_LOCAL,
					   taskc->slice_ns,
					   taskc->enq_flags);
			bpf_task_release(p);
			return;
		}
	} else {
		if (likely(cpuc && dsq_id != cpuc->mig_dsq &&
		    scx_bpf_dsq_move_to_local(cpuc->mig_dsq)))
			return;
	}

	// Lookup LLC ctx (should never fail at this point)
	if (unlikely(p2dq_config.llc_shards <= 1 &&
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))) {
		scx_bpf_error("invalid llc id %u", cpuc->llc_id);
		return;
	}

	// Try to keep prev task running (optimization for low-latency tasks)
	if (unlikely(prev && keep_running(cpuc, llcx, prev)))
		return;

	dispatch_pick_two(cpu, llcx, cpuc);
}

void BPF_STRUCT_OPS(p2dq_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (p->cpus_ptr == &p->cpus_mask &&
	    p->nr_cpus_allowed == topo_config.nr_cpus)
		task_ctx_set_flag(taskc, TASK_CTX_F_ALL_CPUS);
	else
		task_ctx_clear_flag(taskc, TASK_CTX_F_ALL_CPUS);
}

void BPF_STRUCT_OPS(p2dq_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
}

void BPF_STRUCT_OPS(p2dq_update_idle, s32 cpu, bool idle)
{
	const struct cpumask *idle_cpumask, *idle_smtmask;
	struct llc_ctx __arena *llcx;
	u64 idle_score;
	int ret, priority;
	u32 percent_idle;

	idle_cpumask = scx_bpf_get_idle_cpumask();
	idle_smtmask = scx_bpf_get_idle_smtmask();

	percent_idle = idle_cpu_percent(idle_cpumask);
	saturated = percent_idle < p2dq_config.saturated_percent;

	if (saturated) {
		min_llc_runs_pick2 = min(2, lb_config.min_llc_runs_pick2);
	} else {
		u32 llc_scaler = log2_u32(topo_config.nr_llcs);
		min_llc_runs_pick2 = min(log2_u32(percent_idle) + llc_scaler, lb_config.min_llc_runs_pick2);
	}

	if (!(llcx = lookup_cpu_llc_ctx(cpu))) {
		scx_bpf_put_cpumask(idle_cpumask);
		scx_bpf_put_cpumask(idle_smtmask);
		return;
	}
	if (percent_idle == 0)
		overloaded = true;

	if (idle) {
		llc_ctx_clear_flag(llcx, LLC_CTX_F_SATURATED);
		overloaded = false;
	} else if (!idle && llcx->cpumask && idle_cpumask && llcx->tmp_cpumask) {
		scx_bitmap_and_cpumask(llcx->tmp_cpumask,
				llcx->cpumask,
				idle_cpumask);
		if (llcx->tmp_cpumask &&
		    scx_bitmap_empty(llcx->tmp_cpumask))
			llc_ctx_set_flag(llcx, LLC_CTX_F_SATURATED);
	}

	/*
	 * Update LLC's arena idle masks when arena tracking is enabled.
	 * Arena masks ARE the source of truth - kernel is just notified.
	 * Use helpers to keep idle_cpumask and idle_smtmask synchronized.
	 */
	if (p2dq_config.arena_idle_tracking) {
		if (idle)
			llc_set_idle_cpu(llcx, cpu);
		else
			llc_clear_idle_cpu(llcx, cpu);
	}

	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);

	if (!p2dq_config.cpu_priority)
		return;

	/*
	 * The idle_score factors relative CPU performance. It could also
	 * consider the last time the CPU went idle in the future.
	 */

	priority = cpu_priority(cpu);
	if (priority < 0)
		priority = 1;

	// Since we use a minheap convert the highest prio to lowest score.
	idle_score = scx_bpf_now() - ((1<<7) * (u64)priority);

	if ((ret = arena_spin_lock((void __arena *)&llcx->idle_lock)))
		return;

	scx_minheap_insert(llcx->idle_cpu_heap, (u64)cpu, idle_score);
	arena_spin_unlock((void __arena *)&llcx->idle_lock);

	return;
}

static s32 p2dq_init_task_impl(struct task_struct *p, struct scx_init_task_args *args)
{
	task_ctx *taskc;
	struct cpu_ctx __arena *cpuc;
	struct llc_ctx __arena *llcx;
	u64 slice_ns;

	s32 task_cpu = scx_bpf_task_cpu(p);

	taskc = scx_task_alloc(p);
	if (!taskc) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	// If task's CPU doesn't have topology, try to find a valid CPU
	cpuc = lookup_cpu_ctx(task_cpu);
	if (!cpuc) {
		// Try CPU 0 as fallback
		cpuc = lookup_cpu_ctx(0);
		if (!cpuc) {
			// No valid CPUs initialized - should not happen after init
			scx_bpf_error("no valid CPU contexts available");
			return -EINVAL;
		}
	}

	llcx = lookup_llc_ctx(cpuc->llc_id);
	if (!llcx) {
		scx_bpf_error("no LLC context for CPU %d", cpuc->id);
		return -EINVAL;
	}

	slice_ns = scale_by_task_weight(p,
					dsq_time_slice(p2dq_config.init_dsq_index));

	taskc->enq_flags = 0;
	taskc->llc_id = cpuc->llc_id;
	taskc->node_id = cpuc->node_id;
	// Adjust starting index based on niceness
	if (p->scx.weight == 100) {
		taskc->dsq_index = p2dq_config.init_dsq_index;
	} else if (p->scx.weight < 100) {
		taskc->dsq_index = 0;
	} else if (p->scx.weight > 100) {
		taskc->dsq_index = p2dq_config.nr_dsqs_per_llc - 1;
	}
	taskc->last_dsq_index = taskc->dsq_index;
	taskc->slice_ns = slice_ns;
	if (p->cpus_ptr == &p->cpus_mask &&
	    p->nr_cpus_allowed == topo_config.nr_cpus)
		task_ctx_set_flag(taskc, TASK_CTX_F_ALL_CPUS);
	else
		task_ctx_clear_flag(taskc, TASK_CTX_F_ALL_CPUS);

	if (is_interactive(taskc))
		task_ctx_set_flag(taskc, TASK_CTX_F_INTERACTIVE);
	else
		task_ctx_clear_flag(taskc, TASK_CTX_F_INTERACTIVE);

	p->scx.dsq_vtime = llcx->vtime;
	task_refresh_llc_runs(taskc);

	// When a task is initialized set the DSQ id to invalid. This causes
	// the task to be randomized on a LLC.
	if (task_ctx_test_flag(taskc, TASK_CTX_F_ALL_CPUS))
		taskc->dsq_id = SCX_DSQ_INVALID;
	else
		taskc->dsq_id = cpuc->llc_dsq;

	return 0;
}

void BPF_STRUCT_OPS(p2dq_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	scx_task_free(p);
}

static int init_llc(u32 llc_index)
{
	struct llc_ctx __arena *llcx;
	topo_ptr topo;
	u32 llc_id = llc_ids[llc_index];
	int i, ret;

	/* Explicit bounds checking for verifier */
	if (llc_id >= NR_CPUS) {
		scx_bpf_error("invalid llc_id %u (max %u)", llc_id, NR_CPUS);
		return -EINVAL;
	}
	llc_id &= (NR_CPUS - 1);  /* Mask for verifier bounds proof */

	/* Get topology node for this LLC */
	topo = (topo_ptr)topo_nodes[TOPO_LLC][llc_id];
	if (!topo) {
		scx_bpf_error("No topology node for LLC %u", llc_id);
		return -ENOENT;
	}
	cast_kern(topo);

	/* Allocate LLC context from arena */
	llcx = (struct llc_ctx __arena *)bpf_arena_alloc_pages(&arena, NULL, 1, -1, 0);
	if (!llcx) {
		scx_bpf_error("Failed to allocate arena for LLC %u", llc_id);
		return -ENOMEM;
	}
	cast_kern(llcx);

	/* Store LLC context in topology node's data pointer */
	topo->data = (void __arena *)llcx;
	cast_user(topo);

	/* Initialize LLC context fields */
	llcx->vtime = 0;
	llcx->id = *MEMBER_VPTR(llc_ids, [llc_index]);
	llcx->index = llc_index;
	llcx->nr_cpus = 0;

	ret = llc_create_atqs(llcx);
	if (ret) {
		return ret;
	}

	llcx->dsq = llcx->id | MAX_LLCS;
	ret = scx_bpf_create_dsq(llcx->dsq, llcx->node_id);
	if (ret) {
		scx_bpf_error("failed to create DSQ %llu", llcx->dsq);
		return -EINVAL;
	}

	llcx->mig_dsq = llcx->id | P2DQ_MIG_DSQ;
	ret = scx_bpf_create_dsq(llcx->mig_dsq, llcx->node_id);
	if (ret) {
		scx_bpf_error("failed to create DSQ %llu", llcx->mig_dsq);
		return -EINVAL;
	}

	ret = init_arena_bitmap_arena(&llcx->cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC cpumask");
		return ret;
	}

	ret = init_arena_bitmap_arena(&llcx->tmp_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC tmp_cpumask");
		return ret;
	}

	// big cpumask
	ret = init_arena_bitmap_arena(&llcx->big_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC big cpumask");
		return ret;
	}

	ret = init_arena_bitmap_arena(&llcx->little_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC little cpumask");
		return ret;
	}

	ret = init_arena_bitmap_arena(&llcx->node_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC node cpumask");
		return ret;
	}

	/*
	 * Idle masks allocated in init_idle_masks syscall program.
	 * The arena automatically zeros memory, so idle masks are already 0.
	 */

	// Initialize CPU sharding fields
	llcx->nr_shards = p2dq_config.llc_shards;

	if (p2dq_config.llc_shards > 1) {
		llcx->nr_shards = min(min(p2dq_config.llc_shards, llcx->nr_cpus), MAX_LLC_SHARDS);

		bpf_for(i, 0, llcx->nr_shards) {
			u64 shard_dsq = shard_dsq_id(llc_id, i);
			if (i < MAX_LLC_SHARDS) // verifier
				llcx->shard_dsqs[i] = shard_dsq;

			ret = scx_bpf_create_dsq(shard_dsq, llcx->node_id);
			if (ret) {
				scx_bpf_error("failed to create shard DSQ %llu for LLC %u shard %u",
					      shard_dsq, llc_id, i);
				return ret;
			}
		}
	}

	return 0;
}

static int init_node(u32 node_id)
{
	struct node_ctx __arena *nodec;
	topo_ptr topo;
	int ret;

	/* Get topology node for this NUMA node */
	topo = (topo_ptr)topo_nodes[TOPO_NODE][node_id];
	if (!topo) {
		/* NUMA node has no CPUs - skip it (e.g., memory-only NUMA nodes) */
		return 0;
	}
	cast_kern(topo);

	/* Allocate node context from arena */
	nodec = (struct node_ctx __arena *)bpf_arena_alloc_pages(&arena, NULL, 1, -1, 0);
	if (!nodec) {
		scx_bpf_error("Failed to allocate arena for NUMA node %u", node_id);
		return -ENOMEM;
	}
	cast_kern(nodec);

	/* Store node context in topology node's data pointer */
	topo->data = (void __arena *)nodec;
	cast_user(topo);

	/* Initialize node context fields */
	nodec->id = node_id;

	ret = init_arena_bitmap_arena(&nodec->cpumask);
	if (ret) {
		scx_bpf_error("failed to create node cpumask");
		return ret;
	}

	// big cpumask
	ret = init_arena_bitmap_arena(&nodec->big_cpumask);
	if (ret) {
		scx_bpf_error("failed to create node cpumask");
		return ret;
	}

	dbg("CFG NODE[%u] configured", node_id);

	return 0;
}

// Initializes per CPU data structures.
static s32 init_cpu(int cpu)
{
	struct node_ctx __arena *nodec;
	struct llc_ctx __arena *llcx;
	struct cpu_ctx __arena *cpuc;
	topo_ptr topo;

	/* Get topology node for this CPU */
	topo = (topo_ptr)topo_nodes[TOPO_CPU][cpu];
	if (!topo) {
		/* CPU doesn't exist in topology - skip initialization */
		return 0;
	}
	cast_kern(topo);

	/* Allocate CPU context from arena */
	cpuc = (struct cpu_ctx __arena *)bpf_arena_alloc_pages(&arena, NULL, 1, -1, 0);
	if (!cpuc) {
		scx_bpf_error("Failed to allocate arena for CPU %d", cpu);
		return -ENOMEM;
	}
	cast_kern(cpuc);

	/* Store CPU context in topology node's data pointer */
	topo->data = (void __arena *)cpuc;
	cast_user(topo);

	/* Initialize CPU context fields */
	cpuc->id = cpu;

	/* Only access CPU info arrays if within valid range */
	if (cpu < topo_config.nr_cpus) {
		cpuc->llc_id = cpu_llc_ids[cpu];
		cpuc->node_id = cpu_node_ids[cpu];
		cpuc->core_id = cpu_core_ids[cpu];
		if (big_core_ids[cpu] == 1)
			cpu_ctx_set_flag(cpuc, CPU_CTX_F_IS_BIG);
		else
			cpu_ctx_clear_flag(cpuc, CPU_CTX_F_IS_BIG);
	} else {
		/* Should not happen - CPU exists in topology but ID >= nr_cpus */
		scx_bpf_error("CPU %d beyond nr_cpus %u", cpu, topo_config.nr_cpus);
		return -EINVAL;
	}
	cpuc->slice_ns = 1;

	if (!(llcx = lookup_llc_ctx(cpuc->llc_id)) ||
	    !(nodec = lookup_node_ctx(cpuc->node_id))) {
		scx_bpf_error("failed to get ctxs for cpu %u", cpu);
		return -ENOENT;
	}

	// copy for each cpu, doesn't matter if it gets overwritten.
	llcx->nr_cpus += 1;
	llcx->id = cpu_llc_ids[cpu];
	llcx->node_id = cpu_node_ids[cpu];
	nodec->id = cpu_node_ids[cpu];
	cpuc->mig_atq = llcx->mig_atq;

	if (cpu_ctx_test_flag(cpuc, CPU_CTX_F_IS_BIG)) {
		trace("CPU[%d] is big", cpu);
		bpf_rcu_read_lock();
		if (big_cpumask)
			scx_bitmap_set_cpu(cpu, big_cpumask);
		if (nodec->big_cpumask)
			scx_bitmap_set_cpu(cpu, nodec->big_cpumask);
		if (llcx->big_cpumask)
			scx_bitmap_set_cpu(cpu, llcx->big_cpumask);
		bpf_rcu_read_unlock();
	} else {
		bpf_rcu_read_lock();
		if (llcx->little_cpumask)
			scx_bitmap_set_cpu(cpu, llcx->little_cpumask);
		bpf_rcu_read_unlock();
	}

	bpf_rcu_read_lock();
	if (all_cpumask)
		scx_bitmap_set_cpu(cpu, all_cpumask);
	if (nodec->cpumask)
		scx_bitmap_set_cpu(cpu, nodec->cpumask);
	if (llcx->cpumask)
		scx_bitmap_set_cpu(cpu, llcx->cpumask);
	bpf_rcu_read_unlock();

	trace("CFG CPU[%d]NODE[%d]LLC[%d] initialized",
	    cpu, cpuc->node_id, cpuc->llc_id);

	return 0;
}

static bool load_balance_timer(void)
{
	struct llc_ctx *llcx, *lb_llcx;
	int j;
	u64 ideal_sum, load_sum = 0, interactive_sum = 0;
	u32 llc_id, llc_index, lb_llc_index, lb_llc_id;
	topo_ptr topo;

	bpf_for(llc_index, 0, topo_config.nr_llcs) {
		// verifier
		if (llc_index >= MAX_LLCS)
			break;

		llc_id = *MEMBER_VPTR(llc_ids, [llc_index]);

		/* Inline lookup for timer callback - verifier needs this */
		if (llc_id >= NR_CPUS) {
			scx_bpf_error("invalid llc_id %u", llc_id);
			return false;
		}
		llc_id &= (NR_CPUS - 1);
		topo = (topo_ptr)topo_nodes[TOPO_LLC][llc_id];
		if (!topo) {
			scx_bpf_error("no topo node for llc %u", llc_id);
			return false;
		}
		cast_kern(topo);
		llcx = (struct llc_ctx *)topo->data;
		if (!llcx)
			return false;
		cast_kern(llcx);

		lb_llc_index = (llc_index + llc_lb_offset) % topo_config.nr_llcs;
		if (lb_llc_index < 0 || lb_llc_index >= MAX_LLCS) {
			scx_bpf_error("failed to lookup lb_llc");
			return false;
		}

		lb_llc_id = *MEMBER_VPTR(llc_ids, [lb_llc_index]);

		/* Inline lookup for timer callback - verifier needs this */
		if (lb_llc_id >= NR_CPUS) {
			scx_bpf_error("invalid llc_id %u", lb_llc_id);
			return false;
		}
		lb_llc_id &= (NR_CPUS - 1);
		topo = (topo_ptr)topo_nodes[TOPO_LLC][lb_llc_id];
		if (!topo) {
			scx_bpf_error("no topo node for llc %u", lb_llc_id);
			return false;
		}
		cast_kern(topo);
		lb_llcx = (struct llc_ctx *)topo->data;
		if (!lb_llcx)
			return false;
		cast_kern(lb_llcx);

		load_sum += llcx->load;
		interactive_sum += llcx->intr_load;

		s64 load_imbalance = 0;
		if(llcx->load > lb_llcx->load)
			load_imbalance = (100 * (llcx->load - lb_llcx->load)) / llcx->load;

		u32 lb_slack = (lb_config.slack_factor > 0 ?
				lb_config.slack_factor : LOAD_BALANCE_SLACK);

		if (load_imbalance > lb_slack)
			llcx->lb_llc_id = lb_llc_id;
		else
			llcx->lb_llc_id = MAX_LLCS;

		dbg("LB llcx[%u] %llu lb_llcx[%u] %llu imbalance %lli",
		    llc_id, llcx->load, lb_llc_id, lb_llcx->load, load_imbalance);
	}

	dbg("LB Total load %llu, Total interactive %llu",
	    load_sum, interactive_sum);

	llc_lb_offset = (llc_lb_offset % (topo_config.nr_llcs - 1)) + 1;

	if (!timeline_config.autoslice || load_sum == 0 || load_sum < interactive_sum)
		goto reset_load;

	if (interactive_sum == 0) {
		dsq_time_slices[0] = (11 * dsq_time_slices[0]) / 10;
		bpf_for(j, 1, p2dq_config.nr_dsqs_per_llc) {
			dsq_time_slices[j] = dsq_time_slices[0] << j << p2dq_config.dsq_shift;
		}
	} else {
		ideal_sum = (load_sum * p2dq_config.interactive_ratio) / 100;
		dbg("LB autoslice ideal/sum %llu/%llu", ideal_sum, interactive_sum);
		if (interactive_sum < ideal_sum) {
			dsq_time_slices[0] = (11 * dsq_time_slices[0]) / 10;

			bpf_for(j, 1, p2dq_config.nr_dsqs_per_llc) {
				dsq_time_slices[j] = dsq_time_slices[0] << j << p2dq_config.dsq_shift;
			}
		} else {
			dsq_time_slices[0] = max((10 * dsq_time_slices[0]) / 11, min_slice_ns);
			bpf_for(j, 1, p2dq_config.nr_dsqs_per_llc) {
				dsq_time_slices[j] = dsq_time_slices[0] << j << p2dq_config.dsq_shift;
			}
		}
	}


reset_load:

	bpf_for(llc_index, 0, topo_config.nr_llcs) {
		llc_id = *MEMBER_VPTR(llc_ids, [llc_index]);

		/* Inline lookup for timer callback - verifier needs this */
		if (llc_id >= NR_CPUS)
			return false;
		llc_id &= (NR_CPUS - 1);
		topo = (topo_ptr)topo_nodes[TOPO_LLC][llc_id];
		if (!topo)
			return false;
		cast_kern(topo);
		llcx = (struct llc_ctx *)topo->data;
		if (!llcx)
			return false;
		cast_kern(llcx);

		llcx->load = 0;
		llcx->intr_load = 0;
		llcx->affn_load = 0;
		llcx->last_period_ns = scx_bpf_now();
		bpf_for(j, 0, p2dq_config.nr_dsqs_per_llc) {
			llcx->dsq_load[j] = 0;
			if (llc_id == 0 && timeline_config.autoslice) {
				if (j > 0 && dsq_time_slices[j] < dsq_time_slices[j-1]) {
					dsq_time_slices[j] = dsq_time_slices[j-1] << p2dq_config.dsq_shift;
				}
				dbg("LB autoslice interactive slice %llu", dsq_time_slices[j]);
			}
		}
	}

	return true;
}

static bool run_timer_cb(int key)
{
	switch (key) {
	case EAGER_LOAD_BALANCER_TMR:
		return load_balance_timer();
	default:
		return false;
	}
}


static int timer_cb(void *map, int key, struct timer_wrapper *timerw)
{
	if (timerw->key < 0 || timerw->key > MAX_TIMERS) {
		return 0;
	}

	struct p2dq_timer *cb_timer = &p2dq_timers[timerw->key];
	bool resched = run_timer_cb(timerw->key);

	if (!resched || !cb_timer || cb_timer->interval_ns == 0) {
		trace("TIMER timer %d stopped", timerw->key);
		return 0;
	}

	bpf_timer_start(&timerw->timer,
			cb_timer->interval_ns,
			cb_timer->start_flags);

	return 0;
}


s32 static start_timers(void)
{
	struct timer_wrapper *timerw;
	int timer_id, err;

	bpf_for(timer_id, 0, MAX_TIMERS) {
		timerw = bpf_map_lookup_elem(&timer_data, &timer_id);
		if (!timerw || timer_id < 0 || timer_id > MAX_TIMERS) {
			scx_bpf_error("Failed to lookup timer");
			return -ENOENT;
		}

		struct p2dq_timer *new_timer = &p2dq_timers[timer_id];
		if (!new_timer) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}
		timerw->key = timer_id;

		err = bpf_timer_init(&timerw->timer, &timer_data, new_timer->init_flags);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_set_callback(&timerw->timer, &timer_cb);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}

		err = bpf_timer_start(&timerw->timer,
				      new_timer->interval_ns,
				      new_timer->start_flags);
		if (err < 0) {
			scx_bpf_error("can't happen");
			return -ENOENT;
		}
	}

	return 0;
}

static s32 p2dq_init_impl()
{
	int ret;

	ret = init_arena_bitmap(&all_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC cpumask");
		return ret;
	}
	ret = init_arena_bitmap(&big_cpumask);
	if (ret) {
		scx_bpf_error("failed to create LLC cpumask");
		return ret;
	}

	if (p2dq_config.init_dsq_index >= p2dq_config.nr_dsqs_per_llc) {
		scx_bpf_error("invalid init_dsq_index");
		return -EINVAL;
	}

	// LLCs initialized in syscall program init_llcs() to avoid verifier complexity
	// Nodes and CPUs initialized in syscall program init_cpus_and_nodes()
	// DSQs created in syscall program init_dsqs()

	min_slice_ns = 1000 * timeline_config.min_slice_us;

	if (start_timers() < 0)
		return -EINVAL;

	return 0;
}

/*
 * BPF test program to initialize all LLCs.
 * Called from userspace after p2dq_init to avoid verifier complexity.
 */
SEC("syscall")
int init_llcs(void *ctx)
{
	int i, ret;

	bpf_for(i, 0, topo_config.nr_llcs) {
		ret = init_llc(i);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * BPF test program to initialize CPUs and NUMA nodes.
 * Called from userspace after init_llcs, before init_idle_masks.
 */
SEC("syscall")
int init_cpus_and_nodes(void *ctx)
{
	int i, ret;

	// Initialize NUMA nodes
	bpf_for(i, 0, topo_config.nr_nodes) {
		ret = init_node(i);
		if (ret)
			return ret;
	}

	// Initialize ALL possible CPUs (not just nr_cpus, since CPU IDs may not be consecutive)
	// init_cpu() will skip CPUs that don't exist in topology
	bpf_for(i, 0, NR_CPUS) {
		ret = init_cpu(i);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * BPF test program to create DSQs and configure CPU contexts.
 * Called from userspace after init_cpus_and_nodes.
 */
SEC("syscall")
int init_dsqs(void *ctx)
{
	struct llc_ctx __arena *llcx;
	struct cpu_ctx __arena *cpuc;
	int i, ret;
	u64 dsq_id;

	/* Initialize arena for syscall program */
	scx_arena_subprog_init();

	// Create DSQs for ALL possible CPUs (CPU IDs may not be consecutive)
	bpf_for(i, 0, NR_CPUS) {
		cpuc = lookup_cpu_ctx(i);
		if (!cpuc)
			continue;  // Skip CPUs that don't exist

		llcx = lookup_llc_ctx(cpuc->llc_id);
		if (!llcx)
			return -EINVAL;

		if (cpuc &&
		    llcx->node_cpumask &&
		    llcx->node_id == cpuc->node_id) {
			bpf_rcu_read_lock();
			if (llcx->node_cpumask)
				scx_bitmap_set_cpu(cpuc->id, llcx->node_cpumask);
			bpf_rcu_read_unlock();
		}

		cpuc->llc_dsq = llcx->dsq;
		cpuc->mig_atq = llcx->mig_atq;

		if (p2dq_config.llc_shards > 1 && llcx->nr_shards > 1) {
			int shard_id = cpuc->core_id % llcx->nr_shards;
			if (shard_id >= 0 &&
			    shard_id < MAX_LLC_SHARDS &&
			    shard_id < llcx->nr_shards)
				cpuc->llc_dsq = *MEMBER_VPTR(llcx->shard_dsqs, [shard_id]);
		}

		dsq_id = cpu_dsq_id(i);
		ret = scx_bpf_create_dsq(dsq_id, llcx->node_id);
		if (ret < 0) {
			scx_bpf_error("failed to create DSQ %llu", dsq_id);
			return ret;
		}
		cpuc->affn_dsq = dsq_id;
		cpuc->mig_dsq = llcx->mig_dsq;
	}

	return 0;
}

/*
 * BPF test program to initialize idle masks for all LLCs.
 * Called from userspace after init_dsqs to allocate remaining structures.
 */
SEC("syscall")
int init_idle_masks(void *ctx)
{
	struct llc_ctx __arena *llcx;
	int i, ret;

	bpf_for(i, 0, topo_config.nr_llcs) {
		if (!(llcx = lookup_llc_ctx(i)))
			return -EINVAL;

		// Skip if already allocated
		if (llcx->idle_cpumask)
			continue;

		// Allocate idle masks for hot path optimization only if enabled
		if (p2dq_config.arena_idle_tracking) {
			ret = init_arena_bitmap_arena(&llcx->idle_cpumask);
			if (ret) {
				scx_bpf_error("failed to create LLC idle_cpumask");
				return ret;
			}

			if (topo_config.smt_enabled) {
				ret = init_arena_bitmap_arena(&llcx->idle_smtmask);
				if (ret) {
					scx_bpf_error("failed to create LLC idle_smtmask");
					return ret;
				}
			}
		}

		// Allocate idle CPU heap if cpu_priority is enabled
		if (p2dq_config.cpu_priority && !llcx->idle_cpu_heap) {
			llcx->idle_cpu_heap = scx_minheap_alloc(llcx->nr_cpus);
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(p2dq_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

#if P2DQ_CREATE_STRUCT_OPS
s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init)
{
	return p2dq_init_impl();
}

void BPF_STRUCT_OPS(p2dq_running, struct task_struct *p)
{
	p2dq_running_impl(p);
}

void BPF_STRUCT_OPS(p2dq_enqueue, struct task_struct *p __arg_trusted, u64 enq_flags)
{
	struct enqueue_promise pro;
	async_p2dq_enqueue(&pro, p, enq_flags);
	complete_p2dq_enqueue(&pro, p);
}

void BPF_STRUCT_OPS(p2dq_dispatch, s32 cpu, struct task_struct *prev)
{
	return p2dq_dispatch_impl(cpu, prev);
}

s32 BPF_STRUCT_OPS(p2dq_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return p2dq_select_cpu_impl(p, prev_cpu, wake_flags);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	return p2dq_init_task_impl(p, args);
}

SCX_OPS_DEFINE(p2dq,
	       .select_cpu		= (void *)p2dq_select_cpu,
	       .cpu_release		= (void *)p2dq_cpu_release,
	       .enqueue			= (void *)p2dq_enqueue,
	       .dispatch		= (void *)p2dq_dispatch,
	       .running			= (void *)p2dq_running,
	       .stopping		= (void *)p2dq_stopping,
	       .set_cpumask		= (void *)p2dq_set_cpumask,
	       .update_idle		= (void *)p2dq_update_idle,
	       .init_task		= (void *)p2dq_init_task,
	       .exit_task		= (void *)p2dq_exit_task,
	       .init			= (void *)p2dq_init,
	       .exit			= (void *)p2dq_exit,
	       .timeout_ms		= 20000,
	       .name			= "p2dq");
#endif
