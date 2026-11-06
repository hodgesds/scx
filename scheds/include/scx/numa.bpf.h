/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#ifndef __SCX_NUMA_BPF_H
#define __SCX_NUMA_BPF_H

#include "common.bpf.h"

/* Ordinary globals need not have BTF VAR entries. Resolve the address by name. */
extern const void sched_numa_balancing __ksym __weak;
extern const void nr_node_ids __ksym __weak;

static inline bool scx_numa_balancing_enabled(void)
{
	const struct static_key_false *key = (const void *)&sched_numa_balancing;

	if (!bpf_ksym_exists(&sched_numa_balancing))
		return false;

	/* A negative count means enabling is in progress, as in static_key_count(). */
	return BPF_CORE_READ(key, key.enabled.counter) != 0;
}

/* CONFIG_NUMA_BALANCING may be absent from the build's vmlinux.h. */
struct task_struct___numa {
	int numa_preferred_nid;
	unsigned long *numa_faults;
} __attribute__((preserve_access_index));

/* This is a NUMA-balancing hint and may not reflect current page residency. */
static inline s32 scx_task_preferred_numa_node(const struct task_struct *p)
{
	const struct task_struct___numa *task = (const void *)p;
	s32 node = NUMA_NO_NODE;

	if (!bpf_core_field_exists(task->numa_preferred_nid) ||
	    bpf_core_read(&node, sizeof(node), &task->numa_preferred_nid))
		return NUMA_NO_NODE;
	return node;
}

/* Sum shared and private memory samples, including the pending scan window. */
static inline s32 scx_task_memory_numa_node(const struct task_struct *p)
{
	const struct task_struct___numa *task = (const void *)p;
	unsigned long *faults;
	u64 max_faults = 0;
	u32 nr_nodes;
	s32 home = NUMA_NO_NODE;
	int node;

	if (!bpf_core_field_exists(task->numa_faults) ||
	    !bpf_ksym_exists(&nr_node_ids) ||
	    bpf_core_read(&faults, sizeof(faults), &task->numa_faults) ||
	    !faults ||
	    bpf_probe_read_kernel(&nr_nodes, sizeof(nr_nodes), &nr_node_ids))
		return NUMA_NO_NODE;

	bpf_for(node, 0, nr_nodes) {
		unsigned long mem[2], membuf[2];
		u64 count;

		/* task_faults_idx(): two fault types per node, NUMA_MEMBUF is 2. */
		if (bpf_probe_read_kernel(mem, sizeof(mem), &faults[2ULL * node]) ||
		    bpf_probe_read_kernel(membuf, sizeof(membuf),
					  &faults[4ULL * nr_nodes + 2ULL * node]))
			continue;
		count = (u64)mem[0] + mem[1] + membuf[0] + membuf[1];
		if (count > max_faults) {
			max_faults = count;
			home = node;
		}
	}
	return home;
}

/* Prefer the balancer's node, then the task's observed memory placement. */
static inline s32 scx_task_numa_node(const struct task_struct *p)
{
	s32 node = NUMA_NO_NODE;

	if (scx_numa_balancing_enabled())
		node = scx_task_preferred_numa_node(p);
	if (node < 0)
		node = scx_task_memory_numa_node(p);
	return node;
}

#endif /* __SCX_NUMA_BPF_H */
