/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#ifndef __GPU_BPF_H
#define __GPU_BPF_H

enum gpu_consts {
	MAX_GPU_PIDS = 2048,
};

enum gpu_proc_type {
	GPU_PROC_TYPE_COMPUTE,
	GPU_PROC_TYPE_GRAPHICS,
	GPU_PROC_TYPE_MAX,
};

/*
 * GPU task metadata, which can be used to associate a task to a GPU. In the
 * future this can be expanded to add more metadata from NVML/ROCM.
 */
struct gpu_task_meta {
	u32		node_idx; // NUMA node of the GPU
};


// Returns whether or not a task is associated with a GPU.
bool is_gpu_task(struct task_struct *p);

// Returns the gpu_task_meta for a task.
struct gpu_task_meta* task_gpu_meta(struct task_struct *p);

#endif /* __GPU_BPF_H */
