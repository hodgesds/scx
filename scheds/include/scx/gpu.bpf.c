/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 */

#include "gpu.bpf.h"


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_GPU_PIDS);
	__type(key, u64);
	__type(value, struct gput_task_meta);
} gpu_pid_data SEC(".maps");


static struct gpu_task_meta *lookup_gpu_task_meta(struct task_struct *p)
{
	struct gpu_task_meta *gtmeta;

	gtmeta = bpf_map_lookup_element(&gpu_pid_data, &(u64)p->tgid);
	return gtmeta;
}

bool is_gpu_task(struct task_struct *p)
{
	struct gpu_task_meta *gtmeta;

	gtmeta = lookup_gpu_task_meta(p);
	return gtmeta ? true : false;
}


struct gpu_task_meta *task_gpu_meta(struct task_struct *p)
{
	return lookup_gpu_task_meta(p);
}
