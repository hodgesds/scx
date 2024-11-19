/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 */
#ifndef __SCHED_EXT_TRACE_BPF_H
#define __SCHED_EXT_TRACE_BPF_H
#include "trace.h"
#include "common.bpf.h"

int on_sched_switch_prev(struct task_struct *prev, struct sched_switch_event *switche);
int on_sched_switch_next(struct task_struct *next, struct sched_switch_event *switche);
void emit_task_trace_event(struct task_struct *p, struct trace_event_meta *tracem);

#endif /* __SCHED_EXT_TRACE_BPF_H */
