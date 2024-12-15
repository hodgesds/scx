/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#define LSP_INC
#include "../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include "intf.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

// dummy for generating types
struct bpf_event _event = {0};


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");


SEC("perf_event")
int profile(void *ctx)
{
	struct bpf_event *event;
	int pid = bpf_get_current_pid_tgid() >> 32;
	int cpu = bpf_get_smp_processor_id();

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;

	event->cpu = cpu;
	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("kprobe/scx_bpf_cpuperf_set")
int BPF_KPROBE(on_sched_cpu_perf, s32 cpu, u32 perf)
{
	struct bpf_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return 1;

	event->cpu = cpu;
	event->perf = perf;
	bpf_ringbuf_submit(event, 0);

	return 0;
}


// SEC("tp_btf/sched_wakeup_new")
// int handle__sched_wakeup_new(u64 *ctx)
// {
// 	/* TP_PROTO(struct task_struct *p) */
// 	struct task_struct *p = (void *)ctx[0];
// 
// 	return 0;
// }


// kprobe:scx_bpf_cpuperf_set
// {
// 	$cpu = arg0;
// 	$perf = arg1;
// 
// 	@freq[$cpu] = (uint32)$perf;
// }

// kprobe:scx_bpf_dsq_insert_vtime,
// kprobe:scx_bpf_dispatch_vtime,
// {
// 	$task = (struct task_struct *)arg0;
// 	$dsq = arg1;
// 	$vtime = arg3;
// 
// 	if ($dsq >= 0 && $dsq < 2<<14) {
// 		@task_lat[$task->pid] = nsecs;
// 		@task_dsqs[$task->pid] = $dsq;
// 		// HACK add 1 to the dsq for handling
// 		// zero values
// 		$dsq_id = $dsq + 1;
// 		if (!has_key(@vtime_dsqs, $dsq_id)) {
// 			@vtime_dsqs[$dsq_id] = 1;
// 		}
// 	}
// }
// 
// kprobe:scx_bpf_dsq_insert,
// kprobe:scx_bpf_dispatch,
// {
// 	$task = (struct task_struct *)arg0;
// 	$dsq = arg1;
// 
// 	if ($dsq >= 0 && $dsq < 2<<14) {
// 		@task_lat[$task->pid] = nsecs;
// 		@task_dsqs[$task->pid] = $dsq;
// 		$dsq_id = $dsq + 1;
// 		if (!has_key(@fifo_dsqs, $dsq_id)) {
// 			@fifo_dsqs[$dsq_id] = 1;
// 		}
// 	}
// }
// 
// rawtracepoint:sched_wakeup,
// rawtracepoint:sched_wakeup_new,
// {
// 	// on wakeup track the depth of the dsq
// 	$task = (struct task_struct *)arg0;
// 	$dsq = $task->scx.dsq->id;
// 
// 	if ($dsq >= 0 && $dsq < 2<<14) {
// 		$nr = $task->scx.dsq->nr;
// 		$weight = $task->scx.weight;
// 		// HACK: for all DSQs add 1
// 		// because of zero value map values
// 		$dsq_id = $dsq + 1;
// 		$max = @dsq_nr_max[$dsq_id];
// 		if ($nr > $max) {
// 			@dsq_nr_max[$dsq_id] = $nr;
// 		}
// 		@dsq_nr_avg[$dsq_id] = avg($nr);
// 		@dsq_weight_avg[$dsq_id] = avg($weight);
// 		@dsq_weight_max[$dsq_id] = max($weight);
// 		if (has_key(@vtime_dsqs, $dsq_id)) {
// 			$vtime = $task->scx.dsq_vtime;
// 			$max_vtime = @vtime_max[$dsq_id];
// 			if ($vtime > $max_vtime) {
// 				@vtime_max[$dsq_id] = $vtime;
// 			}
// 		}
// 	}
// }
// 
// rawtracepoint:sched_switch
// {
// 	$prev = (struct task_struct *)arg1;
// 	$next = (struct task_struct *)arg2;
// 	$prev_state = arg3;
// 
// 	$dsq = @task_dsqs[$next->pid];
// 	// Convert ns to us
// 	$lat = (nsecs - @task_lat[$next->pid]) / 1000;
// 	if ($lat > 1000) {
// 		$lat = $lat / 1000;
// 	} else {
// 		$lat = 0;
// 	}
// 	@cpu_dsqs[cpu, $dsq] = 1;
// 	@cpu_lat_avg_total[cpu] += $lat;
// 	@cpu_lat_avg_count[cpu] += 1;
// 	$max_lat = @cpu_lat_max[cpu];
// 	if ($lat > $max_lat) {
// 		@cpu_lat_max[cpu] = $lat;
// 	}
// 
// 	delete(@task_dsqs[$next->pid]);
// 	delete(@task_lat[$next->pid]);
// }
// 
