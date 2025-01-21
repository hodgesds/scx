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
#include "../../../../include/scx/ravg_impl.bpf.h"
#else
#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#endif

#include "intf.h"

#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)


/*
 * Domains and cpus
 */
const volatile u32 nr_llcs = 32;	/* !0 for veristat, set during init */
const volatile u32 nr_nodes = 32;	/* !0 for veristat, set during init */
const volatile u32 nr_cpus = 64;	/* !0 for veristat, set during init */
const volatile u32 nr_dsqs_per_llc = 3;
const volatile u64 dsq_shift = 2;
const volatile u64 min_slice_us = 100;

const volatile u64 numa_cpumasks[MAX_NUMA_NODES][MAX_CPUS / 64];
const volatile u32 llc_numa_id_map[MAX_LLCS];
const volatile u32 cpu_llc_id_map[MAX_CPUS];

const volatile bool has_little_cores = true;
const volatile bool kthreads_local;
const volatile bool direct_greedy_numa;
const volatile u32 greedy_threshold;
const volatile u32 greedy_threshold_x_numa;
const volatile u32 debug = 2;

const u32 zero_u32 = 0;

u32 sched_mode = MODE_PERF;


u64 tune_params_gen;
private(A) struct bpf_cpumask __kptr *all_cpumask;
private(A) struct bpf_cpumask __kptr *big_cpumask;
private(A) struct bpf_cpumask __kptr *direct_greedy_cpumask;
private(A) struct bpf_cpumask __kptr *kick_greedy_cpumask;


struct bpfmask_wrapper {
	struct bpf_cpumask __kptr *mask;
};


struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctxs SEC(".maps");

static struct cpu_ctx *lookup_cpu_ctx(int cpu)
{
	struct cpu_ctx *cpuc;

	if (cpu < 0)
		cpuc = bpf_map_lookup_elem(&cpu_ctxs, &zero_u32);
	else
		cpuc = bpf_map_lookup_percpu_elem(&cpu_ctxs, &zero_u32, cpu);

	if (!cpuc) {
		scx_bpf_error("no cpu_ctx for cpu %d", cpu);
		return NULL;
	}

	return cpuc;
}

static __always_inline int cpu_dsq_id(int dsq_id, struct cpu_ctx *cpuc) {
	if (dsq_id < 0 || dsq_id > nr_dsqs_per_llc) {
		scx_bpf_error("invalid dsq index: %d", dsq_id);
		return 0;
	}
	return cpuc->dsqs[dsq_id];
}


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct llc_ctx);
	__uint(max_entries, MAX_LLCS);
} llc_ctxs SEC(".maps");

static struct llc_ctx *lookup_llc_ctx(u32 llc_id)
{
	struct llc_ctx *llcx;

	llcx = bpf_map_lookup_elem(&llc_ctxs, &llc_id);
	if (!llcx) {
		scx_bpf_error("no llc_ctx for llc %u", llc_id);
		return NULL;
	}

	return llcx;
}


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct node_ctx);
	__uint(max_entries, MAX_NUMA_NODES);
	__uint(map_flags, 0);
} node_ctxs SEC(".maps");

static struct node_ctx *lookup_node_ctx(u32 node_id)
{
	struct node_ctx *nodec;

	nodec = bpf_map_lookup_elem(&node_ctxs, &node_id);
	if (!nodec) {
		scx_bpf_error("no node_ctx for node %u", node_id);
		return NULL;
	}

	return nodec;
}


struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctxs SEC(".maps");

static struct task_ctx *lookup_task_ctx_may_fail(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctxs, p, 0, 0);
}

static struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *taskc = lookup_task_ctx_may_fail(p);

	if (!taskc)
		scx_bpf_error("task_ctx lookup failed");

	return taskc;
}


/*
 * Returns the slice for a given DSQ
 */
static u64 dsq_slice_ns(u64 dsq_id) {
	if (dsq_id == 0) {
		return (min_slice_us);
	} else {
		return min_slice_us << dsq_id << dsq_shift;
	}
}


s32 BPF_STRUCT_OPS(p2dq_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct task_ctx *taskc;
	bool is_idle = false;
	s32 cpu;

	if (!(taskc = lookup_task_ctx(p)))
		return prev_cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	if (is_idle) {
		u64 slice_ns = dsq_slice_ns(taskc->last_dsq_id);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
	}

	return cpu;
}


void BPF_STRUCT_OPS(p2dq_enqueue, struct task_struct *p __arg_trusted, u64 enq_flags)
{
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	u64 dsq_id;

	s32 task_cpu = scx_bpf_task_cpu(p);

	if (!(cpuc = lookup_cpu_ctx(task_cpu)) ||
	    !(taskc = lookup_task_ctx(p)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return;

	u64 vtime_now = llcx->vtime;
	u64 vtime = p->scx.dsq_vtime;
	u64 slice_ns = dsq_slice_ns(taskc->dsq_id);

	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice for the dsq.
	 */
	if (time_before(vtime, vtime_now - slice_ns))
		vtime = vtime_now - slice_ns;

	/*
	 * Push per-cpu kthreads at the head of local dsq's and preempt the
	 * corresponding CPU. This ensures that e.g. ksoftirqd isn't blocked
	 * behind other threads which is necessary for forward progress
	 * guarantee as we depend on the BPF timer which may run from ksoftirqd.
	 */
	if ((p->flags & PF_KTHREAD) && p->nr_cpus_allowed < nr_cpus) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns,
				   enq_flags | SCX_ENQ_PREEMPT);
		return;
	}

	/* 
	 * Affinitized tasks just get dispatched directly, need to handle this better 
	 */
	if ((!taskc->all_cpus)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
	}

	dsq_id = cpu_dsq_id(taskc->dsq_id, cpuc);
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice_ns, vtime, enq_flags);
}


void BPF_STRUCT_OPS(p2dq_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = scx_bpf_now();
	struct task_struct *waker;
	struct task_ctx *wakee_ctx, *waker_ctx;

	if (!(wakee_ctx = lookup_task_ctx(p)))
		return;

	wakee_ctx->is_kworker = p->flags & PF_WQ_WORKER;

	wakee_ctx->sum_runtime = 0;

	waker = bpf_get_current_task_btf();
	if (!(waker_ctx = lookup_task_ctx_may_fail(waker)))
		return;

	waker_ctx->last_woke_at = now;
}


void BPF_STRUCT_OPS(p2dq_running, struct task_struct *p)
{
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	s32 task_cpu = scx_bpf_task_cpu(p);

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (!(cpuc = lookup_cpu_ctx(task_cpu)) || !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return;

	taskc->last_run_at = scx_bpf_now();
	llcx->vtime = p->scx.dsq_vtime;
	cpuc->dsq_id = taskc->dsq_id;

	// In perf mode give interactive tasks a perf boost.
	if (sched_mode == MODE_PERF && cpuc->dsq_id <= 1) {
		cpuc->perf = 1024;
		scx_bpf_cpuperf_set(task_cpu, cpuc->perf);
	}
}


void BPF_STRUCT_OPS(p2dq_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	u64 used, last_dsq_slice_ns;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (!(cpuc = lookup_cpu_ctx(-1)) || !(llcx = lookup_llc_ctx(cpuc->llc_id)))
		return;

	u64 now = scx_bpf_now();
	last_dsq_slice_ns = dsq_slice_ns(taskc->dsq_id);
	used = now - taskc->last_run_at;
	taskc->last_run_at = now;
	taskc->last_dsq_id = taskc->dsq_id;
	cpuc->last_dsq_id = cpuc->dsq_id;

	// On stopping determine if the task can move to a longer DSQ by
	// comparing the used time to the scaled DSQ slice.
	if (used >= ((9 * last_dsq_slice_ns) / 10)) {
		if (taskc->dsq_id < nr_dsqs_per_llc) {
			taskc->dsq_id += 1;
			trace("%s[%p]: DSQ %u -> %u, slice %llu", p->comm, p,
			      taskc->last_dsq_id, taskc->dsq_id, dsq_slice_ns(taskc->dsq_id));
		}
	// If under half the slice was consumed move the task back down.
	} else if (used < last_dsq_slice_ns / 2) {
		if (taskc->dsq_id > 0) {
			taskc->dsq_id -= 1;
			trace("%s[%p]: DSQ %u -> %u slice %llu", p->comm, p,
			      taskc->last_dsq_id, taskc->dsq_id, dsq_slice_ns(taskc->dsq_id));
		}
	}
}


void BPF_STRUCT_OPS(p2dq_set_weight, struct task_struct *p, u32 weight)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	trace("%s[%p]: SET_WEIGHT %u -> %u", p->comm, p, taskc->weight, weight);
}


void BPF_STRUCT_OPS(p2dq_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cpuc;
	u64 slice_ns;
	int i;

	if (!(cpuc = lookup_cpu_ctx(cpu)))
		return;

	// In the dispatch path we first figure out the load factor for each dsq.
	int nr_queued = 0;
	int max_dsq = 0;
	u64 dsq_load = 0;
	u64 max_load = 0;
	bpf_for(i, 0, nr_dsqs_per_llc) {
		nr_queued = scx_bpf_dsq_nr_queued(cpuc->dsqs[i]);
		slice_ns = dsq_slice_ns(i);
		// We penalize non interactive DSQs
		dsq_load = i == 0 ? nr_queued * dsq_load : nr_queued * ( slice_ns/ i);
		if (dsq_load > max_load && dsq_load > 1) {
			max_load = dsq_load;
			max_dsq = i;
		}
	}

	// First try the last DSQ, this is to keep interactive tasks sticky.
	if (cpuc->last_dsq_id <= nr_dsqs_per_llc &&
	    scx_bpf_dsq_move_to_local(cpuc->dsqs[cpuc->last_dsq_id]))
		return;

	// Next try the DSQ with the most load.
	if (max_load > 0 && max_dsq > 0 &&
	    scx_bpf_dsq_move_to_local(cpuc->dsqs[max_dsq]))
		return;

	// Last ditch effort.
	bpf_for(i, 0, nr_dsqs_per_llc) {
		if (scx_bpf_dsq_move_to_local(cpuc->dsqs[nr_dsqs_per_llc - i]))
			return;
	}
}

void BPF_STRUCT_OPS(p2dq_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)) || !all_cpumask)
		return;

	taskc->all_cpus =
		bpf_cpumask_subset(cast_mask(all_cpumask), cpumask);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct bpf_cpumask *cpumask;
	struct task_ctx *taskc;

	taskc = bpf_task_storage_get(&task_ctxs, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	if (!(cpumask = bpf_cpumask_create())) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	if ((cpumask = bpf_kptr_xchg(&taskc->mask, cpumask))) {
		bpf_cpumask_release(cpumask);
		scx_bpf_error("task_ctx allocation failure");
		return -EINVAL;
	}

	// Start in the most interactive DSQ.
	taskc->dsq_id = 0;
	taskc->last_dsq_id = 0;
	taskc->runnable = true;

	if (!all_cpumask) {
		scx_bpf_error("NULL all_cpumask");
		return -EINVAL;
	}

	bpf_rcu_read_lock();
	if (p->cpus_ptr && all_cpumask)
		taskc->all_cpus = bpf_cpumask_subset(cast_mask(all_cpumask),
						     p->cpus_ptr);
	bpf_rcu_read_unlock();

	return 0;
}


static int init_llc(u32 llc_id)
{
	struct bpf_cpumask *cpumask, *big_cpumask;
	struct llc_ctx *llcx;
	int i, ret;
	u64 dsq_id;

	llcx = bpf_map_lookup_elem(&llc_ctxs, &llc_id);
	if (!llcx) {
		scx_bpf_error("No llc %u", llc_id);
		return -ENOENT;
	}

	llcx->vtime = 0;

	// Create DSQs for the LLC
	bpf_for(i, 0, nr_dsqs_per_llc) {
		dsq_id = (llc_id << nr_dsqs_per_llc) | i;
		dbg("CFG creating DSQ[%d][%llu] slice_us %llu for LLC[%u]",
		    i, dsq_id, dsq_slice_ns(dsq_id), llc_id);
		ret = scx_bpf_create_dsq(dsq_id, llcx->node_id);
		if (ret < 0) {
			scx_bpf_error("failed to create DSQ %llu", dsq_id);
			return ret;
		}

		llcx->dsqs[i] = dsq_id;
	}

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("failed to create cpumask");
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(&llcx->cpumask, cpumask);
	if (cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(cpumask);
	}

	// Topology related setup, first we assume all CPUs are big. When CPUs
	// initialize they will update this as needed.
	llcx->all_big = true;

	// big cpumask
	big_cpumask = bpf_cpumask_create();
	if (!big_cpumask) {
		scx_bpf_error("failed to create big cpumask");
		return -ENOMEM;
	}

	big_cpumask = bpf_kptr_xchg(&llcx->big_cpumask, big_cpumask);
	if (big_cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(big_cpumask);
	}

	return 0;
}

static int init_node(u32 node_id)
{
	struct bpf_cpumask *cpumask, *big_cpumask;
	struct node_ctx *nodec;

	nodec = bpf_map_lookup_elem(&node_ctxs, &node_id);
	if (!nodec) {
		scx_bpf_error("No node %u", node_id);
		return -ENOENT;
	}

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("failed to create cpumask for node %u", node_id);
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(&nodec->cpumask, cpumask);
	if (cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(cpumask);
	}

	// Topology related setup, first we assume all CPUs are big. When CPUs
	// initialize they will update this as needed.
	nodec->all_big = true;

	// big cpumask
	big_cpumask = bpf_cpumask_create();
	if (!big_cpumask) {
		scx_bpf_error("failed to create big cpumask");
		return -ENOMEM;
	}

	big_cpumask = bpf_kptr_xchg(&nodec->big_cpumask, big_cpumask);
	if (big_cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(big_cpumask);
	}
	dbg("CFG NODE[%u] configured", node_id);

	return 0;
}

// Initializes per CPU data structures.
static s32 init_cpu(int cpu)
{
	struct cpu_ctx *cpuc;
	struct llc_ctx *llcx;
	struct node_ctx *nodec;
	int i;

	if (!(cpuc = lookup_cpu_ctx(cpu)) ||
	    !(llcx = lookup_llc_ctx(cpuc->llc_id)) ||
	    !(nodec = lookup_node_ctx(cpuc->node_id))) {
		scx_bpf_error("failed to get ctxs for cpu %u", cpu);
		return -ENOENT;
	}

	if (cpuc->is_big) {
		bpf_rcu_read_lock();
		dbg("CPU[%d] is big", cpu);
		if (big_cpumask)
			bpf_cpumask_set_cpu(cpu, big_cpumask);
		if (nodec->big_cpumask)
			bpf_cpumask_set_cpu(cpu, nodec->big_cpumask);
		if (llcx->big_cpumask)
			bpf_cpumask_set_cpu(cpu, llcx->big_cpumask);
		bpf_rcu_read_unlock();
	} else {
		llcx->all_big = false;
		nodec->all_big = false;
	}

	bpf_for(i, 0, nr_dsqs_per_llc) {
		cpuc->dsqs[i] = llcx->dsqs[i];
	}

	bpf_rcu_read_lock();
	if (nodec->cpumask)
		bpf_cpumask_set_cpu(cpu, nodec->cpumask);
	if (llcx->cpumask)
		bpf_cpumask_set_cpu(cpu, llcx->cpumask);
	bpf_rcu_read_unlock();

	dbg("CPU[%d] initialized", cpu);

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(p2dq_init)
{
	int i, ret;
	struct bpf_cpumask *tmp_cpumask, *tmp_big_cpumask;

	tmp_big_cpumask = bpf_cpumask_create();
	if (!tmp_big_cpumask) {
		scx_bpf_error("failed to create big cpumask");
		return -ENOMEM;
	}

	tmp_big_cpumask = bpf_kptr_xchg(&big_cpumask, tmp_big_cpumask);
	if (tmp_big_cpumask)
		bpf_cpumask_release(tmp_big_cpumask);

	tmp_cpumask = bpf_cpumask_create();
	if (!tmp_cpumask) {
		scx_bpf_error("failed to create all cpumask");
		return -ENOMEM;
	}

	tmp_cpumask = bpf_kptr_xchg(&all_cpumask, tmp_cpumask);
	if (tmp_cpumask)
		bpf_cpumask_release(tmp_cpumask);

	// First we initialize LLCs because DSQs are created at the LLC level.
	bpf_for(i, 0, nr_llcs) {
		ret = init_llc(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_nodes) {
		ret = init_node(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_cpus) {
		ret = init_cpu(i);
		if (ret)
			return ret;
	}

	return 0;
}


SCX_OPS_DEFINE(p2dq,
	       .select_cpu		= (void *)p2dq_select_cpu,
	       .enqueue			= (void *)p2dq_enqueue,
	       .dispatch		= (void *)p2dq_dispatch,
	       .runnable		= (void *)p2dq_runnable,
	       .running			= (void *)p2dq_running,
	       .stopping		= (void *)p2dq_stopping,
	       .set_weight		= (void *)p2dq_set_weight,
	       .set_cpumask		= (void *)p2dq_set_cpumask,
	       .init_task		= (void *)p2dq_init_task,
	       .init			= (void *)p2dq_init,
	       .timeout_ms		= 20000,
	       .name			= "p2dq");
