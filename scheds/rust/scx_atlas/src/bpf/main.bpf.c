/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * scx_atlas - AI Training Latency-Aware Scheduler (prototype).
 *
 * Per-LLC dispatch queues with LLC-local dispatch and LLC-bounded work stealing
 * (topology foundation, see scx_atlas_design.md §4), plus per-class soft-affinity
 * domains (lib/soft_affinity.h) consulted in select_cpu. Idle CPUs get direct
 * dispatch; per-CPU kthreads are kept local for latency. Classification is still
 * a placeholder (everything is SYSTEM); per-class masks, GPU/cgroup matching and
 * tgid-home land in later phases.
 *
 * Struct fields are ordered largest-alignment-first to minimize padding.
 */
#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#include "../../../../include/lib/soft_affinity.h"
#else
#include <scx/common.bpf.h>
#include <lib/soft_affinity.h>
#endif

#include "intf.h"

#include <errno.h>

char _license[] SEC("license") = "GPL";

/* task_struct->flags bit for kernel threads (not exposed via vmlinux.h). */
#define PF_KTHREAD		0x00200000

UEI_DEFINE(uei);

/*
 * Host topology, populated by userspace before load (see init_open_skel! in
 * lib.rs). Read-only from BPF.
 */
const volatile struct {
	u32	nr_cpus;
	u32	nr_llcs;
	u32	nr_nodes;
	bool	smt_enabled;
} topo_config = {
	.nr_cpus	= 1,
	.nr_llcs	= 1,
	.nr_nodes	= 1,
	.smt_enabled	= false,
};

/*
 * Global scheduler behavior knobs (principle #7: keep this small).
 */
const volatile struct {
	u64	slice_us_default;	/* base time slice (cf. EEVDF base_slice) */
	u64	slice_us_latency;	/* time slice for the LATENCY class   */
	u64	min_slice_us;		/* minimum time slice floor (cf. CFS min_granularity) */
	u64	slice_lag_us;		/* max sleeper vtime credit (cf. EEVDF lag / CFS sleeper fairness) */
	u64	xnuma_mig_min_us;	/* min time since last NUMA migration to be
					 * eligible for a cross-NUMA steal       */
	bool	kthreads_local;		/* keep per-CPU kthreads on their CPU */
	bool	mempolicy_aware;	/* bias placement to the task's NUMA  */
	bool	preempt_latency;	/* LATENCY tasks preempt lower classes */
	bool	yield_ignore;		/* LATENCY tasks ignore sched_yield() */
} atlas_config = {
	.slice_us_default	= 5000,
	.slice_us_latency	= 1000,
	.min_slice_us		= 500,
	.slice_lag_us		= 5000,
	.xnuma_mig_min_us	= 1000,
	.kthreads_local		= true,
	.mempolicy_aware	= true,
	.preempt_latency	= true,
	.yield_ignore		= true,
};

/* Class currently running on each CPU (updated in ops.running). */
static u32 cpu_cur_class[MAX_CPUS];

/* NUMA memory-policy modes (uapi/linux/mempolicy.h). */
#define MPOL_PREFERRED		1
#define MPOL_BIND		2
#define MPOL_PREFERRED_MANY	5

/*
 * Per-class vtime weight: a task's vtime advances by used_time * 100 / weight,
 * so a higher weight => slower vtime growth => sorts ahead in the per-LLC
 * vtime-ordered queue. LATENCY is boosted; this static weight is the first cut
 * for the lavd latency-criticality score. Temporal priority lives here, not in
 * separate per-class queues.
 */
const volatile u32 class_weight[NR_ATLAS_CLASSES] = {
	[ATLAS_CLASS_LATENCY]	= 1000,
	[ATLAS_CLASS_PREP]	= 100,
	[ATLAS_CLASS_TRAINING]	= 100,
	[ATLAS_CLASS_SYSTEM]	= 50,
};

/* Per-LLC virtual-time clock for the per-LLC vtime-ordered DSQs. */
static u64 vtime_now[MAX_LLCS];

/* Representative LLC id for each NUMA node (for mempolicy queue routing). */
static u32 node_llc[MAX_NUMA_NODES];

/* Per-NUMA-node list of LLC ids, for tiered pick-2 load balancing. */
static u32 node_llcs[MAX_NUMA_NODES][MAX_LLCS];
static u32 node_nr_llcs[MAX_NUMA_NODES];
static u32 llc_node[MAX_LLCS];	/* LLC id -> NUMA node id */
static u32 llc_nr_cpus[MAX_LLCS];	/* CPUs per LLC, for load-aware slices */

/*
 * Whether a NUMA node has any CPUs. CXL / tiered-memory nodes are CPU-less:
 * a task's mempolicy may prefer such a node for its memory, but we must not try
 * to run it there. (Mapping a CXL node to its nearest CPU node is a follow-up.)
 */
static bool node_has_cpu[MAX_NUMA_NODES];

/* Per-CPU -> LLC / NUMA-node maps, populated by userspace from topology. */
const volatile u32 cpu_llc_ids[MAX_CPUS];
const volatile u32 cpu_node_ids[MAX_CPUS];

/* Per-task scheduler state. */
struct task_ctx {
	struct bpf_cpumask __kptr *eff;	/* scratch: domain mask & affinity */
	u64			last_mig_ns;	/* last NUMA migration timestamp     */
	u64			slice_ns;	/* slice assigned at last running()   */
	u64			avg_run_ns;	/* EWMA of per-run burst length      */
	u64			avg_gap_ns;	/* EWMA of gap between consecutive runs */
	u64			last_run_ns;	/* timestamp of last running()       */
	u32			class_id;	/* enum atlas_class */
	u32			lat_cri;	/* latency-criticality score [0,1024] */
	s32			pref_node;	/* mempolicy preferred NUMA, -1 none */
	s32			last_node;	/* last NUMA node it ran on, -1 none */
	bool			pref_bind;	/* MPOL_BIND: contain to pref_node */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctxs SEC(".maps");

/* Per-class soft-affinity domains (lib/soft_affinity.h). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct soft_affinity_domain);
	__uint(max_entries, NR_ATLAS_CLASSES);
} class_doms SEC(".maps");

/* Per-NUMA-node CPU masks, for mempolicy-biased placement. */
struct node_mask {
	struct bpf_cpumask __kptr *mask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct node_mask);
	__uint(max_entries, MAX_NUMA_NODES);
} node_cpumasks SEC(".maps");

/*
 * Per-LLC CPU masks, built from the real topology at init (so a non-contiguous
 * or SMT-split LLC is represented exactly). Consumed by per-tgid soft-affinity
 * homes (saf_resize), which OR a range of these together. struct node_mask is
 * reused as a generic mask holder.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct node_mask);
	__uint(max_entries, MAX_LLCS);
} llc_cpumasks SEC(".maps");

/*
 * tgid -> home class. Placement stickiness is keyed by thread-group id so all
 * threads of a process share one class/home (shared mm_struct => cache/TLB
 * locality). The first thread classifies the process; later threads inherit.
 * GPU detection (Phase 4) overrides an entry here so a process that starts using
 * a GPU is promoted to LATENCY and all its threads follow.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 16384);
} tgid_home SEC(".maps");

/* Sentinel for "GPU in use but its NUMA node is unknown". */
#define ATLAS_NODE_UNKNOWN	((u32)-1)

/*
 * tgid -> GPU NUMA node, populated by the userspace GPU poller (scans
 * /proc/<pid>/fd for open GPU device nodes). Presence means the process is using
 * a GPU; the value is the GPU's NUMA node (or ATLAS_NODE_UNKNOWN). Such processes
 * are classified LATENCY and biased toward the GPU's node.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 16384);
} gpu_tgid SEC(".maps");

/*
 * cgroup id -> class. cgroup path matching (substr/prefix/suffix/regex) is done
 * in userspace, which resolves matching cgroups to ids and maintains this map;
 * BPF reads the task's live cgroup id, so task cgroup-moves are handled
 * automatically. (BPF-side live path matching is on the backburner.)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u32);
	__uint(max_entries, 16384);
} cgroup_class SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, ATLAS_NR_STATS);
} stats SEC(".maps");

/*
 * Per-tgid soft-affinity group (saf_resize). The soft-affinity group is the
 * process (tgid): BPF accumulates the group's CPU runtime; userspace's LLC
 * allocator periodically assigns its "home" — a *set* of whole LLCs, one bit per
 * LLC id in @llc_mask — sized from its utilization and placed on the least-loaded
 * LLCs (demand-proportional, uniform shares). The home is expressed in LLCs, not
 * CPUs, so it stays cache-aligned: an LLC may be a non-contiguous / SMT-split set
 * of CPU ids (built from real topology at init), and ORing the home's LLC masks
 * keeps a process's threads on shared caches. A busy process spans more LLCs; an
 * idle one is packed into one. `llc_mask == 0` means "not yet sized" (no home).
 */
struct tgid_dom {
	u64	runtime;	/* accumulated CPU time (ns); BPF writes atomically */
	u64	llc_mask;	/* home = set of LLC ids (bit i = LLC i); userspace */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct tgid_dom);
	__uint(max_entries, 16384);
} tgid_dom SEC(".maps");

/*
 * Per-CPU IRQ load (hardirq+softirq), in per-mille of the last interval, written
 * by userspace from /proc/stat each interval. Cheap (kernel already accounts it;
 * no per-IRQ hot-path cost). Foundation for IRQ-aware placement: a CPU saturated
 * with IRQ work isn't really available for latency tasks.
 */
const volatile u32 irq_busy_thresh = 200;	/* per-mille; >= is "IRQ-heavy" */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_CPUS);
} cpu_irq_busy SEC(".maps");

static __always_inline u32 cpu_irq_load(s32 cpu)
{
	u32 key, *v;

	if (cpu < 0 || cpu >= MAX_CPUS)
		return 0;
	key = cpu;
	v = bpf_map_lookup_elem(&cpu_irq_busy, &key);
	return v ? *v : 0;
}

static __always_inline void stat_inc(u32 idx)
{
	u64 *cnt = bpf_map_lookup_elem(&stats, &idx);

	if (cnt)
		(*cnt)++;
}


static __always_inline struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctxs, p, 0, 0);
}

static __always_inline struct soft_affinity_domain *lookup_class_dom(u32 class_id)
{
	if (class_id >= NR_ATLAS_CLASSES)
		return NULL;
	return bpf_map_lookup_elem(&class_doms, &class_id);
}

static __always_inline bool is_percpu_kthread(const struct task_struct *p)
{
	return (p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1;
}

/*
 * Map a CPU to its LLC DSQ id. The DSQ id is simply the LLC id; an unknown or
 * out-of-range CPU falls back to LLC 0 (which always exists).
 */
static __always_inline u32 cpu_to_llc(s32 cpu, bool *fallback)
{
	u32 llc;

	if (cpu < 0 || cpu >= MAX_CPUS) {
		*fallback = true;
		return 0;
	}
	/* Mask keeps the index provably in-bounds for the verifier (MAX_CPUS is
	 * a power of two) even if the compiler reorders the bounds check. */
	llc = cpu_llc_ids[cpu & (MAX_CPUS - 1)];
	if (llc >= MAX_LLCS) {
		*fallback = true;
		return 0;
	}
	return llc;
}

static __always_inline s32 cpu_to_node(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS)
		return -1;
	return (s32)cpu_node_ids[cpu & (MAX_CPUS - 1)];
}

static __always_inline u64 task_slice_ns(const struct task_ctx *tctx)
{
	u64 slice = atlas_config.slice_us_default * NSEC_PER_USEC;
	u64 floor = atlas_config.min_slice_us * NSEC_PER_USEC;

	if (tctx && tctx->class_id == ATLAS_CLASS_LATENCY)
		slice = atlas_config.slice_us_latency * NSEC_PER_USEC;

	return slice < floor ? floor : slice;
}

/*
 * Load-aware time slice (lavd/cosmos-style). The class base slice is the *max*;
 * under saturation we scale it down toward the min floor so a full round of an
 * LLC's runqueue stays bounded (a head-of-queue task — including one pinned to a
 * busy CPU — is serviced within ~one base slice instead of nr_queued slices),
 * which prevents runnable-task stalls without giving anyone priority. With
 * @nr_q tasks queued on @llc's @ncpu CPUs, each runs base*ncpu/nr_q (so the round
 * ~= base), clamped to [min, base]. Light load (nr_q <= ncpu) keeps the full
 * slice for throughput.
 */
static __always_inline u64 calc_slice_ns(const struct task_ctx *tctx, u32 llc)
{
	u64 base = task_slice_ns(tctx);
	u64 floor = atlas_config.min_slice_us * NSEC_PER_USEC;
	u32 ncpu, nq;

	if (llc >= MAX_LLCS)
		return base;
	ncpu = llc_nr_cpus[llc];
	if (ncpu == 0)
		return base;

	nq = scx_bpf_dsq_nr_queued(llc);
	if (nq > ncpu) {
		base = base * ncpu / nq;
		if (base < floor)
			base = floor;
	}
	return base;
}

static __always_inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static __always_inline u32 cls_weight(u32 class_id)
{
	if (class_id >= NR_ATLAS_CLASSES || class_weight[class_id] == 0)
		return 100;
	return class_weight[class_id];
}

/*
 * Lightweight, lavd-shaped latency-criticality score in [0, ATLAS_LC_SCALE].
 * lavd's insight: a task is latency-critical when it runs in SHORT bursts and
 * wakes FREQUENTLY (short gap between runs). We capture just those two signals
 * with cheap EWMAs (avg_run_ns in stopping(), avg_gap_ns in running()) — no PELT
 * clock, perf_cri, or waker/wakee inheritance. Each factor maps a duration to
 * [0, SCALE] via SCALE*ref/(x+ref): shorter -> higher. Runtime dominates (2:1),
 * matching lavd's reverse-runtime factor being its primary term.
 */
#define ATLAS_LC_SCALE		1024u
#define ATLAS_LC_GAP_REF_NS	(10ULL * NSEC_PER_MSEC)	/* ~100Hz wake => mid */

static __always_inline u32 calc_lat_cri(const struct task_ctx *tctx)
{
	u64 run_ref, rf, gf;

	if (!tctx)
		return 0;

	/* Runtime factor: avg burst shorter than the base slice -> latency. */
	run_ref = atlas_config.slice_us_default * NSEC_PER_USEC;
	if (run_ref == 0)
		run_ref = NSEC_PER_MSEC;
	rf = (u64)ATLAS_LC_SCALE * run_ref / (tctx->avg_run_ns + run_ref);

	/* Wake-frequency factor: shorter gap between runs -> higher frequency. */
	gf = (u64)ATLAS_LC_SCALE * ATLAS_LC_GAP_REF_NS /
	     (tctx->avg_gap_ns + ATLAS_LC_GAP_REF_NS);

	return (u32)((rf * 2 + gf) / 3);
}

/*
 * Effective vtime weight, composed from three signals so each is respected:
 *   - @task_weight: the task's nice value as a load weight (kernel-supplied,
 *     100 == nice 0). This is the user's explicit priority.
 *   - the class weight: our policy prior (e.g. LATENCY boosted), folded in
 *     relative to the nice-0 unit (×cls_weight/100).
 *   - @lat_cri: dynamic latency-criticality, a 1x–2x refinement.
 * A higher weight grows vtime more slowly, so the task sorts ahead in the
 * per-LLC vtime queue. With nice 0 (@task_weight == 100) this reduces exactly to
 * the previous class×lat_cri behavior, so nice support is backward-compatible.
 */
static __always_inline u32 eff_weight(u32 class_id, u32 lat_cri, u32 task_weight)
{
	u32 w = task_weight ? task_weight : 100;
	u64 eff = (u64)w * cls_weight(class_id) / 100;

	eff = eff * (ATLAS_LC_SCALE + lat_cri) / ATLAS_LC_SCALE;
	return eff < 1 ? 1 : (u32)eff;
}

/* Exponential moving average with weight 1/8 (seeds on first sample). */
static __always_inline u64 ewma8(u64 avg, u64 sample)
{
	if (avg == 0)
		return sample;
	return (avg * 7 + sample) / 8;
}

static __always_inline bool task_is_gpu(struct task_struct *p)
{
	u32 tgid = p->tgid;

	return bpf_map_lookup_elem(&gpu_tgid, &tgid) != NULL;
}

static __always_inline s32 task_gpu_node(struct task_struct *p)
{
	u32 tgid = p->tgid;
	u32 *node = bpf_map_lookup_elem(&gpu_tgid, &tgid);

	if (!node || *node >= MAX_NUMA_NODES)
		return -1;
	return (s32)*node;
}

static __always_inline struct bpf_cpumask *lookup_node_mask(u32 node)
{
	struct node_mask *nm;

	if (node >= MAX_NUMA_NODES)
		return NULL;
	nm = bpf_map_lookup_elem(&node_cpumasks, &node);
	return nm ? nm->mask : NULL;
}

static __always_inline struct bpf_cpumask *lookup_llc_mask(u32 llc)
{
	struct node_mask *lm;

	if (llc >= MAX_LLCS)
		return NULL;
	lm = bpf_map_lookup_elem(&llc_cpumasks, &llc);
	return lm ? lm->mask : NULL;
}

/*
 * saf_resize: pick an idle CPU within the task's per-tgid "home" — the set of
 * whole LLCs in @llc_mask (bit i = LLC i) — intersected with the task's own
 * affinity. Userspace's LLC allocator sizes and places the home from the tgid's
 * recent CPU utilization, so a busy process spans more LLCs while an idle one is
 * packed into one, keeping a process's threads cache-warm. Because each LLC mask
 * is built from real topology, this is correct on SMT/non-contiguous layouts.
 * @scratch is a caller-owned bpf_cpumask (the task's eff mask) reused to
 * accumulate the LLC union. Returns a CPU id, or -1 if the tgid has no home yet
 * or none of its home CPUs are idle.
 */
static __always_inline s32 tgid_pick_idle_cpu(struct task_struct *p,
					      struct bpf_cpumask *scratch)
{
	u32 tgid = p->tgid;
	u32 nr_llcs = topo_config.nr_llcs;
	struct tgid_dom *g;
	u64 mask;
	u32 i;

	if (!scratch || nr_llcs == 0)
		return -1;
	g = bpf_map_lookup_elem(&tgid_dom, &tgid);
	mask = g ? g->llc_mask : 0;

	/*
	 * Heavy hitters: use the userspace-allocated home (a set of LLCs),
	 * intersected with the task's affinity. If it intersects, pick within it.
	 */
	if (mask) {
		bpf_cpumask_clear(scratch);
		bpf_for(i, 0, nr_llcs) {
			struct bpf_cpumask *lm;

			if (i >= MAX_LLCS)
				break;
			if (!(mask & (1ULL << i)))
				continue;
			lm = lookup_llc_mask(i);
			if (lm)
				bpf_cpumask_or(scratch, cast_mask(scratch),
					       cast_mask(lm));
		}
		bpf_cpumask_and(scratch, cast_mask(scratch), p->cpus_ptr);
		if (!bpf_cpumask_empty(cast_mask(scratch)))
			return scx_bpf_pick_idle_cpu(cast_mask(scratch), 0);
	}

	/*
	 * No (usable) allocated home: default to a single LLC chosen by a tgid
	 * hash. This gives every process stable per-process LLC stickiness for
	 * free and spreads processes across LLCs (tgid-keyed, so all threads of a
	 * process share one LLC — a random pick would scatter siblings and defeat
	 * cache locality).
	 */
	if (p->nr_cpus_allowed >= topo_config.nr_cpus) {
		/* Unrestricted task: the hashed LLC is always runnable. */
		struct bpf_cpumask *lm = lookup_llc_mask(tgid % nr_llcs);

		if (!lm)
			return -1;
		bpf_cpumask_and(scratch, cast_mask(lm), p->cpus_ptr);
	} else {
		/*
		 * Affinity-restricted task: scan circularly from a tgid-hashed
		 * start LLC and take the first one it can run on. The hashed start
		 * spreads restricted tasks across LLCs rather than piling them all
		 * onto the lowest-numbered allowed LLC. Single pass to keep the
		 * verifier's jump budget in check.
		 */
		u32 start = tgid % nr_llcs, k;
		bool found = false;

		bpf_for(k, 0, nr_llcs) {
			struct bpf_cpumask *lm;
			u32 cand = start + k;

			if (k >= MAX_LLCS)
				break;
			if (cand >= nr_llcs)
				cand -= nr_llcs;
			lm = lookup_llc_mask(cand);
			if (lm && bpf_cpumask_intersects(cast_mask(lm),
							 p->cpus_ptr)) {
				bpf_cpumask_and(scratch, cast_mask(lm),
						p->cpus_ptr);
				found = true;
				break;
			}
		}
		if (!found)
			return -1;
	}

	if (bpf_cpumask_empty(cast_mask(scratch)))
		return -1;

	return scx_bpf_pick_idle_cpu(cast_mask(scratch), 0);
}

/*
 * Return the task's preferred NUMA node from its mempolicy, or -1 if none.
 * Mirrors scx_rusty: honor MPOL_BIND/PREFERRED/PREFERRED_MANY, preferring the
 * home_node, else the first node set in the policy's nodemask. The scheduler
 * should follow where a task's memory lives.
 */
static __always_inline s32 task_pref_node(struct task_struct *p, bool *bind)
{
	struct mempolicy *mp;
	u64 bits = 0;
	s32 home;
	u16 mode;
	u32 n;

	*bind = false;

	if (!atlas_config.mempolicy_aware)
		return -1;

	mp = BPF_CORE_READ(p, mempolicy);
	if (!mp)
		return -1;

	mode = BPF_CORE_READ(mp, mode);
	if (!(mode & (MPOL_BIND | MPOL_PREFERRED | MPOL_PREFERRED_MANY)))
		return -1;

	/* MPOL_BIND contains the task to its node(s); others are a soft bias. */
	*bind = (mode & MPOL_BIND);

	home = BPF_CORE_READ(mp, home_node);
	if (home >= 0)
		return home;

	bits = BPF_CORE_READ(mp, nodes.bits[0]);
	if (!bits)
		return -1;

	bpf_for(n, 0, MAX_NUMA_NODES) {
		if (n >= 64)
			break;
		if (bits & (1ULL << n))
			return (s32)n;
	}
	return -1;
}

/* Recompute and cache a task's mempolicy preferred node into its ctx. */
static __always_inline void refresh_pref_node(struct task_struct *p,
					      struct task_ctx *tctx)
{
	bool bind = false;
	s32 node;

	if (!tctx)
		return;

	/*
	 * GPU tasks are biased toward their GPU's NUMA node (compute near the
	 * accelerator); this takes precedence over mempolicy. Falls through to
	 * mempolicy when the GPU node is unknown.
	 */
	node = task_gpu_node(p);
	if (node >= 0 && node < MAX_NUMA_NODES && node_has_cpu[node]) {
		tctx->pref_node = node;
		tctx->pref_bind = false;
		return;
	}

	node = task_pref_node(p, &bind);

	/*
	 * A CPU-less (CXL / tiered-memory) node can't run the task; treat it as
	 * "no preference" so we don't route compute to a node with no CPUs.
	 */
	if (node >= 0 && (node >= MAX_NUMA_NODES || !node_has_cpu[node])) {
		node = -1;
		bind = false;
	}

	tctx->pref_node = node;
	tctx->pref_bind = bind;
}

/*
 * Classify a task, live (no caching, so a process that starts using a GPU is
 * promoted promptly). GPU-using processes are LATENCY (detected by the GPU
 * probes/poller via gpu_tgid); a tgid_home entry is an explicit override (e.g.
 * future cgroup tagging); everything else is SYSTEM.
 */
/*
 * Look up a task's class by its live cgroup id. All cgroup path matching
 * (prefix/suffix/substr/regex) is done in userspace, which resolves matching
 * cgroups to ids in the cgroup_class map; BPF just reads the task's current
 * cgroup id, so task cgroup-moves are handled automatically.
 */
static __always_inline u32 cgroup_class_of(struct task_struct *p)
{
	u64 cgid = BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, id);
	u32 *cc = bpf_map_lookup_elem(&cgroup_class, &cgid);

	return cc ? *cc : NR_ATLAS_CLASSES;
}

static __always_inline u32 classify_task(struct task_struct *p)
{
	u32 tgid = p->tgid;
	u32 *home, cc;

	if (is_percpu_kthread(p))
		return ATLAS_CLASS_SYSTEM;

	/* Explicit override (e.g. set by tooling). */
	home = bpf_map_lookup_elem(&tgid_home, &tgid);
	if (home)
		return *home;

	/* GPU use makes a process latency-critical regardless of cgroup. */
	if (task_is_gpu(p))
		return ATLAS_CLASS_LATENCY;

	/* cgroup membership (matched live, robust to creation/migration). */
	cc = cgroup_class_of(p);
	if (cc < NR_ATLAS_CLASSES)
		return cc;

	return ATLAS_CLASS_SYSTEM;
}

/*
 * Override a process's home class. Called when a process is detected using a GPU
 * (Phase 4 kprobe/uprobe) so the whole tgid is promoted to LATENCY and all its
 * threads follow on their next classification.
 */
static __always_inline __maybe_unused void set_tgid_home(u32 tgid, u32 class)
{
	bpf_map_update_elem(&tgid_home, &tgid, &class, BPF_ANY);
}

/*
 * Recompute and cache a task's class. Called from the hot path so comm-based
 * matching sees the live (post-exec) comm; a tgid_home override (e.g. GPU)
 * always wins. Returns the class.
 */
static __always_inline u32 refresh_class(struct task_struct *p,
					 struct task_ctx *tctx)
{
	u32 class = classify_task(p);

	if (tctx)
		tctx->class_id = class;
	return class;
}

s32 BPF_STRUCT_OPS(atlas_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	struct soft_affinity_domain *dom;
	bool is_idle = false;
	u32 class;
	s32 cpu;

	/* Classify live (post-exec comm); a tgid_home override always wins. */
	class = refresh_class(p, tctx);

	/*
	 * Refresh the cached mempolicy node here too: mempolicy inherited at
	 * fork isn't visible at init_task time and no syscall fires for it, so
	 * the set_mempolicy tracepoint alone would miss inherited policies.
	 */
	refresh_pref_node(p, tctx);

	/*
	 * Try the task's soft-affinity domain first: an idle CPU from
	 * proximal -> preferred -> spill, intersected with the task's affinity.
	 * A direct dispatch here skips enqueue(), so count the class on this path.
	 */
	if (tctx && tctx->eff) {
		/*
		 * saf_resize: first try the task's per-tgid home range (the
		 * soft-affinity group sized by its utilization). This keeps a
		 * process's threads packed on a shared, right-sized CPU set for
		 * cache/TLB locality before falling back to the class domain.
		 */
		cpu = tgid_pick_idle_cpu(p, tctx->eff);
		if (cpu >= 0) {
			stat_inc(ATLAS_STAT_HOME);
			stat_inc(ATLAS_STAT_CLS_LATENCY + class);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
					   task_slice_ns(tctx), 0);
			return cpu;
		}

		dom = lookup_class_dom(class);
		if (dom) {
			struct bpf_cpumask *nmask;
			s32 pref_node = tctx->pref_node;	/* cached */

			/*
			 * Memory follows the task: if it has a preferred NUMA
			 * node (mempolicy), try an idle CPU on that node first,
			 * within its preferred domain and affinity.
			 */
			if (pref_node >= 0 &&
			    (nmask = lookup_node_mask((u32)pref_node))) {
				cpu = saf_pick_node(dom, p->cpus_ptr,
						    cast_mask(nmask), tctx->eff,
						    0);
				if (cpu >= 0) {
					stat_inc(ATLAS_STAT_MEMPOL);
					stat_inc(ATLAS_STAT_CLS_LATENCY + class);
					scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
							   task_slice_ns(tctx),
							   0);
					return cpu;
				}
			}

			/*
			 * MPOL_BIND tasks are contained to their node: skip the
			 * domain-wide (off-node) spill here and let dispatch keep
			 * them on a node-local queue. Others fall through to the
			 * normal proximal->preferred->spill search.
			 */
			if (!tctx->pref_bind) {
				cpu = saf_pick_idle_cpu(dom, p->cpus_ptr,
							tctx->eff, 0);
				if (cpu >= 0) {
					stat_inc(ATLAS_STAT_SAF);
					stat_inc(ATLAS_STAT_CLS_LATENCY + class);
					scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
							   task_slice_ns(tctx),
							   0);
					return cpu;
				}
			}
		}
	}

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(ATLAS_STAT_LOCAL);
		stat_inc(ATLAS_STAT_CLS_LATENCY + class);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice_ns(tctx), 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(atlas_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	bool fallback = false;
	u32 llc, class;
	u64 vtime;

	/* Classify live (post-exec comm) and count the enqueue per class. */
	class = refresh_class(p, tctx);
	stat_inc(ATLAS_STAT_CLS_LATENCY + class);

	/*
	 * LATENCY tasks that couldn't get an idle CPU preempt a lower-class task
	 * on their previous CPU rather than waiting in a queue (principle #2).
	 */
	if (class == ATLAS_CLASS_LATENCY && atlas_config.preempt_latency) {
		s32 tcpu = scx_bpf_task_cpu(p);

		if (tcpu >= 0 && tcpu < MAX_CPUS) {
			u32 c = cpu_cur_class[tcpu & (MAX_CPUS - 1)];

			if (c != ATLAS_CLASS_LATENCY && c < NR_ATLAS_CLASSES &&
			    bpf_cpumask_test_cpu(tcpu, p->cpus_ptr)) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | tcpu,
						   task_slice_ns(tctx),
						   SCX_ENQ_PREEMPT);
				scx_bpf_kick_cpu(tcpu, SCX_KICK_PREEMPT);
				stat_inc(ATLAS_STAT_PREEMPT);
				return;
			}
		}
	}

	/*
	 * Per-CPU kthreads (IRQ workers, etc.) are latency-sensitive and pinned
	 * to a single CPU; keep them local rather than routing through an LLC
	 * queue.
	 */
	if (atlas_config.kthreads_local && is_percpu_kthread(p)) {
		stat_inc(ATLAS_STAT_KTHREAD);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice_ns(tctx),
				   enq_flags);
		return;
	}

	{
		s32 tcpu = scx_bpf_task_cpu(p);

		llc = cpu_to_llc(tcpu, &fallback);

		/*
		 * Memory follows the task: if it has a preferred NUMA node and
		 * its current CPU is off that node, queue it on a node-local LLC
		 * so it gravitates back (containment for MPOL_BIND, bias for
		 * MPOL_PREFERRED). Dispatch stealing can still pull it under load.
		 *
		 * Stall-safety: only route to a node-local LLC the task can
		 * actually run on. We scan the preferred node's LLCs and pick the
		 * first whose CPUs intersect the task's affinity; if none do (an
		 * affinity-narrow task pinned off its preferred node), we leave it
		 * on its current CPU's LLC — which is always runnable — rather than
		 * stranding it on a DSQ no permitted CPU consumes.
		 */
		s32 pn = tctx ? tctx->pref_node : -1;

		if (pn >= 0 && pn < MAX_NUMA_NODES && cpu_to_node(tcpu) != pn) {
			u32 cnt = node_nr_llcs[pn & (MAX_NUMA_NODES - 1)];
			u32 li;

			bpf_for(li, 0, cnt) {
				u32 cand;
				struct bpf_cpumask *lmask;

				if (li >= MAX_LLCS)
					break;
				cand = node_llcs[pn & (MAX_NUMA_NODES - 1)]
						[li & (MAX_LLCS - 1)];
				lmask = lookup_llc_mask(cand);
				if (lmask &&
				    bpf_cpumask_intersects(cast_mask(lmask),
							   p->cpus_ptr)) {
					llc = cand;
					fallback = false;
					break;
				}
			}
		}
	}

	/* Keep the DSQ index in range for the verifier and array bounds. */
	if (llc >= MAX_LLCS)
		llc = 0;

	stat_inc(fallback ? ATLAS_STAT_FALLBACK : ATLAS_STAT_LLC);

	/*
	 * Insert into the LLC's vtime-ordered queue. Clamp the task's vtime so a
	 * long-sleeping task can't monopolize the CPU with a stale-low vtime, but
	 * still keeps a small sleeper credit (one slice).
	 */
	vtime = p->scx.dsq_vtime;
	{
		u64 lag = atlas_config.slice_lag_us * NSEC_PER_USEC;

		if (vtime_before(vtime, vtime_now[llc] - lag))
			vtime = vtime_now[llc] - lag;
	}

	scx_bpf_dsq_insert_vtime(p, llc, task_slice_ns(tctx), vtime, enq_flags);
}

/*
 * Tier 1: pick two random LLCs in @node and steal from the busier (more-queued)
 * one — cache-local, same-NUMA balancing. Returns true if a task was pulled.
 */
static __always_inline bool pick2_node(u32 node)
{
	u32 n, a, b, first, second;

	if (node >= MAX_NUMA_NODES)
		return false;
	node &= (MAX_NUMA_NODES - 1);
	n = node_nr_llcs[node];
	if (n == 0)
		return false;

	a = node_llcs[node][(bpf_get_prandom_u32() % n) & (MAX_LLCS - 1)];
	b = node_llcs[node][(bpf_get_prandom_u32() % n) & (MAX_LLCS - 1)];

	first = a;
	second = b;
	if (scx_bpf_dsq_nr_queued(b) > scx_bpf_dsq_nr_queued(a)) {
		first = b;
		second = a;
	}

	if (scx_bpf_dsq_move_to_local(first, 0)) {
		stat_inc(ATLAS_STAT_STEAL);
		return true;
	}
	if (second != first && scx_bpf_dsq_move_to_local(second, 0)) {
		stat_inc(ATLAS_STAT_STEAL);
		return true;
	}
	return false;
}

/*
 * Tier 2: cross-NUMA steal. Walk the other NUMA nodes' LLC queues and, from the
 * tail (least-urgent task), steal one that hasn't migrated NUMA recently — to
 * stay work-conserving without ping-ponging tasks across nodes. Skips CPU-less
 * (CXL) nodes.
 */
static __always_inline bool steal_xnuma(s32 cpu, u32 home_node)
{
	u64 now = scx_bpf_now();
	u64 min_ns = atlas_config.xnuma_mig_min_us * NSEC_PER_USEC;
	struct task_struct *p;
	u32 ni, li, cnt, dsq;

	bpf_for(ni, 0, topo_config.nr_nodes) {
		if (ni >= MAX_NUMA_NODES)
			break;
		if (ni == home_node || !node_has_cpu[ni])
			continue;

		cnt = node_nr_llcs[ni & (MAX_NUMA_NODES - 1)];
		bpf_for(li, 0, cnt) {
			if (li >= MAX_LLCS)
				break;
			dsq = node_llcs[ni & (MAX_NUMA_NODES - 1)][li & (MAX_LLCS - 1)];
			if (!scx_bpf_dsq_nr_queued(dsq))
				continue;

			bpf_for_each(scx_dsq, p, dsq, SCX_DSQ_ITER_REV) {
				struct task_ctx *tc = lookup_task_ctx(p);

				if (tc && now - tc->last_mig_ns < min_ns)
					continue;
				if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
						     SCX_DSQ_LOCAL_ON | cpu, 0)) {
					stat_inc(ATLAS_STAT_XNUMA_STEAL);
					return true;
				}
			}
		}
	}
	return false;
}

void BPF_STRUCT_OPS(atlas_dispatch, s32 cpu, struct task_struct *prev)
{
	bool fallback = false;
	u32 home = cpu_to_llc(cpu, &fallback);
	s32 home_node = cpu_to_node(cpu);

	/* Cache-local work always wins. */
	if (scx_bpf_dsq_move_to_local(home, 0))
		return;

	/* Don't pile stolen work onto an IRQ-saturated CPU (it isn't idle). */
	if (cpu_irq_load(cpu) >= irq_busy_thresh)
		return;

	if (home_node < 0)
		return;

	/* Tier 1: pick-2 within the local NUMA node. */
	if (pick2_node((u32)home_node))
		return;

	/* Tier 2: cross-NUMA steal of a non-recently-migrated tail task. */
	steal_xnuma(cpu, (u32)home_node);
}

void BPF_STRUCT_OPS(atlas_running, struct task_struct *p)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	s32 this_cpu = scx_bpf_task_cpu(p);
	bool fb = false;
	u32 llc = cpu_to_llc(this_cpu, &fb);
	s32 node = cpu_to_node(this_cpu);

	/* Advance the LLC clock so newly-woken tasks aren't unfairly ahead. */
	if (vtime_before(vtime_now[llc], p->scx.dsq_vtime))
		vtime_now[llc] = p->scx.dsq_vtime;

	/* Track NUMA migrations so cross-NUMA steals avoid recent migrants. */
	if (tctx) {
		u64 now = scx_bpf_now();

		if (tctx->last_node >= 0 && tctx->last_node != node)
			tctx->last_mig_ns = now;
		tctx->last_node = node;
		if (this_cpu >= 0 && this_cpu < MAX_CPUS)
			cpu_cur_class[this_cpu & (MAX_CPUS - 1)] = tctx->class_id;

		/*
		 * Latency-criticality signal: gap between consecutive runs. A
		 * short gap means the task wakes/runs frequently (interactive,
		 * e.g. a GPU-polling thread). EWMA so a few outliers don't swing
		 * it. (The complementary signal, burst length, is in stopping().)
		 */
		if (tctx->last_run_ns && now > tctx->last_run_ns)
			tctx->avg_gap_ns = ewma8(tctx->avg_gap_ns,
						 now - tctx->last_run_ns);
		tctx->last_run_ns = now;

		/*
		 * Set the load-aware slice for this run on the actual CPU/LLC
		 * (lavd-style): shrinks under saturation to bound runqueue latency.
		 * Remember it so stopping() charges the right consumed time.
		 */
		tctx->slice_ns = calc_slice_ns(tctx, llc);
		p->scx.slice = tctx->slice_ns;
	}
}

void BPF_STRUCT_OPS(atlas_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	u32 class = tctx ? tctx->class_id : ATLAS_CLASS_SYSTEM;
	/* Charge against the slice actually assigned in running() (load-aware), not
	 * the class base, so consumed time is accurate when slices are scaled. */
	u64 slice = (tctx && tctx->slice_ns) ? tctx->slice_ns : task_slice_ns(tctx);
	u64 used = slice > p->scx.slice ? slice - p->scx.slice : 0;
	struct tgid_dom *g;
	u32 tgid = p->tgid;

	/*
	 * Update the burst-length signal (shorter burst -> more latency-critical)
	 * and recompute the task's latency-criticality from it plus the wake-gap
	 * signal tracked in running().
	 */
	if (tctx) {
		tctx->avg_run_ns = ewma8(tctx->avg_run_ns, used);
		tctx->lat_cri = calc_lat_cri(tctx);
	}

	/*
	 * Charge consumed runtime scaled by the effective weight (nice/task weight
	 * × class prior × latency-criticality): a higher weight grows vtime more
	 * slowly, so higher-priority / latency-critical tasks sort ahead in the
	 * per-LLC vtime queue.
	 */
	p->scx.dsq_vtime += used * 100 /
		eff_weight(class, tctx ? tctx->lat_cri : 0, p->scx.weight);

	/* Accumulate the tgid soft-affinity group's CPU time for saf_resize. */
	g = bpf_map_lookup_elem(&tgid_dom, &tgid);
	if (!g) {
		struct tgid_dom init = {};

		bpf_map_update_elem(&tgid_dom, &tgid, &init, BPF_NOEXIST);
		g = bpf_map_lookup_elem(&tgid_dom, &tgid);
	}
	if (g)
		__sync_fetch_and_add(&g->runtime, used);
}

s32 BPF_STRUCT_OPS(atlas_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	struct bpf_cpumask *eff;

	tctx = bpf_task_storage_get(&task_ctxs, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	/* Per-task scratch mask used by saf_pick_idle_cpu(). */
	eff = bpf_cpumask_create();
	if (!eff)
		return -ENOMEM;
	eff = bpf_kptr_xchg(&tctx->eff, eff);
	if (eff)
		bpf_cpumask_release(eff);

	/*
	 * Default to SYSTEM; the real class is computed live in the hot path
	 * (refresh_class) since comm-based matching needs the post-exec comm,
	 * not the parent's comm at fork time.
	 */
	tctx->class_id = ATLAS_CLASS_SYSTEM;
	tctx->last_node = -1;

	/*
	 * mempolicy is inherited at fork and preserved across exec, so capturing
	 * it here is correct; the set_mempolicy tracepoint keeps it fresh.
	 */
	refresh_pref_node(p, tctx);
	return 0;
}

/*
 * Keep the cached mempolicy node fresh when a task changes its NUMA policy, so
 * the hot path never has to read task->mempolicy. Fires only on set_mempolicy
 * exits (rare), so overhead is negligible. (mbind / set_mempolicy_home_node
 * could be hooked similarly later.)
 */
SEC("tp/syscalls/sys_exit_set_mempolicy")
int atlas_set_mempolicy(void *ctx)
{
	struct task_struct *p = (struct task_struct *)bpf_get_current_task_btf();

	refresh_pref_node(p, lookup_task_ctx(p));
	return 0;
}

/*
 * GPU-process detection probes (enabled by default). Kprobes on rare nvidia
 * driver entry points stamp the calling process into gpu_tgid; the scheduler
 * then classifies it LATENCY. These are optional ("?"): on a host without the
 * nvidia driver the symbols are absent and the probes are skipped. nvidia_open
 * and _mmap fire at GPU setup (rare) so steady-state overhead is negligible.
 */
static __always_inline int atlas_note_gpu_current(void)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	u32 node = ATLAS_NODE_UNKNOWN;

	bpf_map_update_elem(&gpu_tgid, &tgid, &node, BPF_ANY);
	return 0;
}

SEC("?kprobe/nvidia_open")
int BPF_KPROBE(atlas_kp_nvidia_open)
{
	return atlas_note_gpu_current();
}

SEC("?kprobe/nvidia_mmap")
int BPF_KPROBE(atlas_kp_nvidia_mmap)
{
	return atlas_note_gpu_current();
}

void BPF_STRUCT_OPS(atlas_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	struct bpf_cpumask *eff;

	if (!tctx)
		return;

	eff = bpf_kptr_xchg(&tctx->eff, NULL);
	if (eff)
		bpf_cpumask_release(eff);

	/* Drop per-process state when the process (group leader) exits. */
	if (p->pid == p->tgid) {
		u32 tgid = p->tgid;

		bpf_map_delete_elem(&gpu_tgid, &tgid);
		bpf_map_delete_elem(&tgid_dom, &tgid);
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(atlas_init)
{
	struct soft_affinity_domain *dom;
	u32 c;
	s32 i, ret;

	/* Per-LLC dispatch queues. */
	bpf_for(i, 0, topo_config.nr_llcs) {
		if (i >= MAX_LLCS)
			break;
		ret = scx_bpf_create_dsq(i, -1);
		if (ret)
			return ret;
	}

	/*
	 * Per-class soft-affinity domains. For now every class's preferred set
	 * is all CPUs; Phase 2b narrows these per class (PREP -> its NUMA node,
	 * LATENCY -> its GPU's CPUs).
	 */
	bpf_for(c, 0, NR_ATLAS_CLASSES) {
		struct bpf_cpumask *m;

		dom = lookup_class_dom(c);
		if (!dom)
			return -EINVAL;

		m = bpf_cpumask_create();
		if (!m)
			return -ENOMEM;

		if (c == ATLAS_CLASS_PREP) {
			/*
			 * Placeholder confinement: PREP -> NUMA node 0. Real
			 * per-node PREP sub-domains land with the full match
			 * table; this proves classes get distinct masks.
			 */
			bpf_for(i, 0, topo_config.nr_cpus) {
				if (i >= MAX_CPUS)
					break;
				if (cpu_node_ids[i] == 0)
					bpf_cpumask_set_cpu(i, m);
			}
		} else {
			bpf_cpumask_setall(m);
		}

		m = bpf_kptr_xchg(&dom->preferred, m);
		if (m)
			bpf_cpumask_release(m);

		if ((ret = saf_mask_create(&dom->spill, false)))
			return ret;
		if ((ret = saf_mask_create(&dom->proximal, false)))
			return ret;
	}

	/* Per-NUMA-node CPU masks for mempolicy-biased placement. */
	bpf_for(c, 0, topo_config.nr_nodes) {
		struct node_mask *nm;
		struct bpf_cpumask *m;

		if (c >= MAX_NUMA_NODES)
			break;
		nm = bpf_map_lookup_elem(&node_cpumasks, &c);
		if (!nm)
			return -EINVAL;

		m = bpf_cpumask_create();
		if (!m)
			return -ENOMEM;
		bpf_for(i, 0, topo_config.nr_cpus) {
			if (i >= MAX_CPUS)
				break;
			if (cpu_node_ids[i] == c)
				bpf_cpumask_set_cpu(i, m);
		}
		m = bpf_kptr_xchg(&nm->mask, m);
		if (m)
			bpf_cpumask_release(m);
	}

	/*
	 * Per-LLC CPU masks for per-tgid soft-affinity homes (saf_resize). Built
	 * from the real cpu->LLC mapping, so an LLC that is non-contiguous in CPU
	 * id (e.g. SMT siblings, split ranges) is captured exactly — no layout
	 * assumption is made.
	 */
	bpf_for(c, 0, topo_config.nr_llcs) {
		struct node_mask *lm;
		struct bpf_cpumask *m;

		if (c >= MAX_LLCS)
			break;
		lm = bpf_map_lookup_elem(&llc_cpumasks, &c);
		if (!lm)
			return -EINVAL;

		m = bpf_cpumask_create();
		if (!m)
			return -ENOMEM;
		bpf_for(i, 0, topo_config.nr_cpus) {
			if (i >= MAX_CPUS)
				break;
			if (cpu_llc_ids[i] == c)
				bpf_cpumask_set_cpu(i, m);
		}
		m = bpf_kptr_xchg(&lm->mask, m);
		if (m)
			bpf_cpumask_release(m);
	}

	/* Representative LLC per node, for mempolicy queue routing. */
	bpf_for(i, 0, topo_config.nr_cpus) {
		u32 n, l;

		if (i >= MAX_CPUS)
			break;
		n = cpu_node_ids[i];
		l = cpu_llc_ids[i];
		if (n < MAX_NUMA_NODES && l < MAX_LLCS) {
			node_llc[n] = l;
			node_has_cpu[n] = true;
			llc_node[l] = n;
			llc_nr_cpus[l]++;
		}
	}

	/* Per-node LLC lists for tiered pick-2 (each LLC appears once). */
	bpf_for(i, 0, topo_config.nr_llcs) {
		u32 n, cnt;

		if (i >= MAX_LLCS)
			break;
		n = llc_node[i];
		if (n >= MAX_NUMA_NODES)
			continue;
		n &= (MAX_NUMA_NODES - 1);
		cnt = node_nr_llcs[n];
		if (cnt < MAX_LLCS) {
			node_llcs[n][cnt & (MAX_LLCS - 1)] = i;
			node_nr_llcs[n] = cnt + 1;
		}
	}

	return 0;
}

/*
 * Periodic tick on the running task. Re-evaluate the load-aware slice mid-run:
 * if this LLC got busier after running() set the slice, shrink (never extend) the
 * remaining slice so the task yields sooner — bounding latency when contention
 * arrives mid-slice. (lavd does this via shrink_slice_at_tick.)
 */
void BPF_STRUCT_OPS(atlas_tick, struct task_struct *p)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	bool fb = false;
	u32 llc;
	u64 cur;

	if (!tctx)
		return;
	llc = cpu_to_llc(cpu, &fb);
	cur = calc_slice_ns(tctx, llc);
	if (cur < p->scx.slice)
		p->scx.slice = cur;
}

/*
 * sched_yield() handling. Latency-critical / GPU tasks (e.g. CUDA/NCCL) often
 * yield inside busy-poll loops; honoring that hands away the CPU and adds
 * re-dispatch latency. When yield_ignore is set, ignore yield for LATENCY tasks
 * (return false = not yielded) so they stay on CPU. @to != NULL is a directed
 * yield_to(); leave that to the kernel default.
 */
bool BPF_STRUCT_OPS(atlas_yield, struct task_struct *from, struct task_struct *to)
{
	struct task_ctx *tctx;

	if (to)
		return true;

	tctx = lookup_task_ctx(from);
	if (atlas_config.yield_ignore && tctx &&
	    tctx->class_id == ATLAS_CLASS_LATENCY)
		return false;

	return true;
}

void BPF_STRUCT_OPS(atlas_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(atlas_ops,
	       .select_cpu	= (void *)atlas_select_cpu,
	       .enqueue		= (void *)atlas_enqueue,
	       .dispatch	= (void *)atlas_dispatch,
	       .running		= (void *)atlas_running,
	       .tick		= (void *)atlas_tick,
	       .yield		= (void *)atlas_yield,
	       .stopping	= (void *)atlas_stopping,
	       .init_task	= (void *)atlas_init_task,
	       .exit_task	= (void *)atlas_exit_task,
	       .init		= (void *)atlas_init,
	       .exit		= (void *)atlas_exit,
	       .timeout_ms	= 5000,
	       .name		= "atlas");
