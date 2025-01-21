// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

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
#endif

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/ravg.bpf.h"
#else
#include <scx/ravg.bpf.h>
#endif

enum consts {
	MAX_CPUS		= 512,
	MAX_NUMA_NODES		= 64,
	MAX_LLCS		= 64,
	MAX_DSQS_PER_LLC	= 8,
	CACHELINE_SIZE		= 64,

	/* Time constants */
	MSEC_PER_SEC		= 1000LLU,
	USEC_PER_MSEC		= 1000LLU,
	NSEC_PER_USEC		= 1000LLU,
	NSEC_PER_MSEC           = USEC_PER_MSEC * NSEC_PER_USEC,
	USEC_PER_SEC            = USEC_PER_MSEC * MSEC_PER_SEC,
	NSEC_PER_SEC            = NSEC_PER_USEC * USEC_PER_SEC,

	/* Constants used for determining a task's deadline */
	DL_RUNTIME_SCALE	= 2, /* roughly scales average runtime to */
				     /* same order of magnitude as waker  */
				     /* and blocked frequencies */
	DL_MAX_LATENCY_NS	= (50 * NSEC_PER_MSEC),
	DL_FREQ_FT_MAX		= 100000,
	DL_MAX_LAT_PRIO		= 39,
};

enum scheduler_mode {
	MODE_PERF,
	MODE_POWERSAVE,
};

struct task_ctx {
	u64			dsq_id;
	bool			runnable;
	u32			weight;
	u64			deadline;
	u64			last_dsq_id;

	u64			sum_runtime;
	u64 			avg_runtime;
	u64 			last_run_at;

	/* frequency with which a task is blocked (consumer) */
	u64			blocked_freq;
	u64			last_blocked_at;

	/* frequency with which a task wakes other tasks (producer) */
	u64			waker_freq;
	u64			last_woke_at;

	/* The task is a workqueue worker thread */
	bool			is_kworker;

	/* Allowed on all CPUs and eligible for DIRECT_GREEDY optimization */
	bool			all_cpus;

	/* select_cpu() telling enqueue() to queue directly on the DSQ */
	bool			dispatch_local;
	struct bpf_cpumask __kptr *mask;
};

struct cpu_ctx {
	int			id;
	u32			llc_id;
	u32			node_id;
	u64			dsq_id;
	u64			last_dsq_id;
	u32			perf;
	u64			dsqs[MAX_DSQS_PER_LLC];
	u64			dsq_load[MAX_DSQS_PER_LLC];
	u64			max_load_dsq;
	bool			is_big;
};

struct llc_ctx {
	u32				id;
	u32				node_id;
	u64				vtime;
	bool				all_big;
	u64				dsqs[MAX_DSQS_PER_LLC];
	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
};

struct node_ctx {
	u32				id;
	bool				all_big;
	struct bpf_cpumask __kptr	*cpumask;
	struct bpf_cpumask __kptr	*big_cpumask;
};

#endif /* __INTF_H */
