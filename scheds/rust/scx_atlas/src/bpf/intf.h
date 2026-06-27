// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __ATLAS_INTF_H
#define __ATLAS_INTF_H

#include <stdbool.h>

#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;
#endif

enum atlas_consts {
	/* Must be a power of two (used as an index mask) and >= NR_CPU_IDS. */
	MAX_CPUS		= 1024,
	MAX_NUMA_NODES		= 64,
	MAX_LLCS		= 64,

	NSEC_PER_USEC		= 1000ULL,
	NSEC_PER_MSEC		= (1000ULL * NSEC_PER_USEC),
	MSEC_PER_SEC		= 1000ULL,
	NSEC_PER_SEC		= NSEC_PER_MSEC * MSEC_PER_SEC,
};

/*
 * Scheduling classes. See scx_atlas_design.md §2. Classification is still a
 * placeholder (everything is SYSTEM today); the enum and per-task class storage
 * are wired now so GPU/cgroup matching (Phase 4) and per-class policy slot in
 * without reshaping the base.
 */
enum atlas_class {
	ATLAS_CLASS_LATENCY,	/* PyTorch GPU-polling / kernel-launch threads */
	ATLAS_CLASS_PREP,	/* data-loading / transform workers            */
	ATLAS_CLASS_TRAINING,	/* training-stack support threads              */
	ATLAS_CLASS_SYSTEM,	/* everything else / unprivileged              */
	NR_ATLAS_CLASSES,
};

enum stat_idx {
	ATLAS_STAT_LOCAL,	/* dispatched directly to a local (idle) CPU  */
	ATLAS_STAT_SAF,		/* idle CPU chosen via a soft-affinity domain */
	ATLAS_STAT_LLC,		/* enqueued to the task's per-LLC DSQ         */
	ATLAS_STAT_KTHREAD,	/* per-CPU kthread kept local                */
	ATLAS_STAT_FALLBACK,	/* routed to LLC 0 (unknown CPU/LLC)         */
	ATLAS_STAT_STEAL,	/* pick-2 steal within the local NUMA node    */
	ATLAS_STAT_XNUMA_STEAL,	/* cross-NUMA steal of a non-recently-migrated task */
	ATLAS_STAT_PREEMPT,	/* LATENCY task preempted a lower-class task  */
	ATLAS_STAT_MEMPOL,	/* idle CPU chosen on the task's mempolicy node */
	ATLAS_STAT_HOME,	/* idle CPU chosen within the per-tgid home range */
	/* Per-class task classification counts (one per enum atlas_class). */
	ATLAS_STAT_CLS_LATENCY,
	ATLAS_STAT_CLS_PREP,
	ATLAS_STAT_CLS_TRAINING,
	ATLAS_STAT_CLS_SYSTEM,
	ATLAS_NR_STATS,
};

#endif /* __ATLAS_INTF_H */
