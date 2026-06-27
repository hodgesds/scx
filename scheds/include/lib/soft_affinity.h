/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * soft_affinity: a reusable "prefer-then-spill" CPU-affinity primitive.
 *
 * A soft-affinity domain holds three CPU sets as bpf_cpumask kptrs: an optional
 * "proximal" set checked first (e.g. the CPUs nearest a GPU), a "preferred" set
 * (the soft-affinity home, grown/shrunk to fit a workload), and a "spill" set
 * used when preferred is busy. Idle-CPU selection walks proximal -> preferred ->
 * spill, each intersected with the task's own affinity mask. See
 * scx_atlas_design.md §3.
 *
 * The domain is meant to be embedded in a BPF map value (so its kptr masks are
 * managed by the map). Helpers are header-only and verifier-safe: the
 * task-affinity intersection uses bpf_cpumask_and(), which accepts a task's
 * kernel cpumask (p->cpus_ptr) natively.
 */
#pragma once

#ifdef __BPF__
#include <scx/common.bpf.h>

struct soft_affinity_domain {
	struct bpf_cpumask __kptr *preferred;
	struct bpf_cpumask __kptr *spill;
	struct bpf_cpumask __kptr *proximal;
};

/*
 * Create and install a fresh bpf_cpumask into @dst. If @setall, the mask is
 * filled (all CPUs) before being installed, so callers don't need to mutate the
 * map-held kptr afterward (which would require an RCU section). Returns 0 or
 * -ENOMEM.
 */
static __always_inline __maybe_unused
int saf_mask_create(struct bpf_cpumask __kptr **dst, bool setall)
{
	struct bpf_cpumask *m = bpf_cpumask_create();

	if (!m)
		return -ENOMEM;

	if (setall)
		bpf_cpumask_setall(m);

	m = bpf_kptr_xchg(dst, m);
	if (m)
		bpf_cpumask_release(m);

	return 0;
}

/* Release a domain's masks (e.g. on teardown). */
static __always_inline __maybe_unused
void saf_domain_free(struct soft_affinity_domain *dom)
{
	struct bpf_cpumask *m;

	if ((m = bpf_kptr_xchg(&dom->preferred, NULL)))
		bpf_cpumask_release(m);
	if ((m = bpf_kptr_xchg(&dom->spill, NULL)))
		bpf_cpumask_release(m);
	if ((m = bpf_kptr_xchg(&dom->proximal, NULL)))
		bpf_cpumask_release(m);
}

/*
 * Try one tier: scratch = tier & task_cpus, then pick an idle CPU from it.
 * Returns a CPU id or -1.
 */
static __always_inline s32 saf_pick_tier(struct bpf_cpumask *tier,
					 const struct cpumask *task_cpus,
					 struct bpf_cpumask *scratch, int flags)
{
	if (!tier)
		return -1;

	bpf_cpumask_and(scratch, cast_mask(tier), task_cpus);
	if (bpf_cpumask_empty(cast_mask(scratch)))
		return -1;

	return scx_bpf_pick_idle_cpu(cast_mask(scratch), flags);
}

/*
 * Pick an idle CPU within the preferred set AND a node mask (e.g. the task's
 * mempolicy node), intersected with @task_cpus. Used to keep compute on the
 * task's memory node. Returns a CPU id or -1.
 */
static __always_inline s32 saf_pick_node(struct soft_affinity_domain *dom,
					 const struct cpumask *task_cpus,
					 const struct cpumask *node_mask,
					 struct bpf_cpumask *scratch, int flags)
{
	struct bpf_cpumask *pref;

	if (!dom || !scratch || !node_mask)
		return -1;
	pref = dom->preferred;
	if (!pref)
		return -1;

	bpf_cpumask_and(scratch, cast_mask(pref), task_cpus);
	bpf_cpumask_and(scratch, cast_mask(scratch), node_mask);
	if (bpf_cpumask_empty(cast_mask(scratch)))
		return -1;

	return scx_bpf_pick_idle_cpu(cast_mask(scratch), flags);
}

/*
 * Pick an idle CPU for a task: proximal -> preferred -> spill, each intersected
 * with @task_cpus (the task's cpus_ptr). @scratch is a caller-owned bpf_cpumask
 * used to materialize the intersection. Returns a CPU id or -1.
 */
static __always_inline s32 saf_pick_idle_cpu(struct soft_affinity_domain *dom,
					     const struct cpumask *task_cpus,
					     struct bpf_cpumask *scratch,
					     int flags)
{
	s32 cpu;

	if (!dom || !scratch)
		return -1;

	cpu = saf_pick_tier(dom->proximal, task_cpus, scratch, flags);
	if (cpu >= 0)
		return cpu;

	cpu = saf_pick_tier(dom->preferred, task_cpus, scratch, flags);
	if (cpu >= 0)
		return cpu;

	return saf_pick_tier(dom->spill, task_cpus, scratch, flags);
}

#endif /* __BPF__ */
