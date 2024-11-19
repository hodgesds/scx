/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 */
#ifndef __SCHED_EXT_TRACE_H
#define __SCHED_EXT_TRACE_H

#define TASK_COMM_LEN	16
#define MAX_TAGS	8
#define MAX_TAG_LEN	16

enum trace_stat_idx {
	TRACE_STAT_DROPPED,
	NR_TRACE_STATS,
};

struct cpu_trace_ctx {
	u64	stats[NR_TRACE_STATS];
};

struct trace_event_meta {
	char		event[MAX_TAG_LEN];
	char		cat[MAX_TAG_LEN];
	char		tags[MAX_TAGS][MAX_TAG_LEN];
};

struct sched_switch_event {
	unsigned long long	ts;
	int			cpu;
	pid_t			pid;
	char			comm[TASK_COMM_LEN];
	int			running;
};

#endif /* __SCHED_EXT_TRACE_H */
