/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <scx/common.bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} sched_switch_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_trace_ctx);
	__uint(max_entries, 1);
} cpu_trace_ctxs SEC(".maps");

static struct cpu_trace_ctx *lookup_cpu_trace_ctx(int cpu)
{
	struct cpu_trace_ctx *ctctx;
	u32 zero = 0;

	if (cpu < 0)
		ctctx = bpf_map_lookup_elem(&cpu_trace_ctxs, &zero);
	else
		ctctx = bpf_map_lookup_percpu_elem(&cpu_trace_ctxs, &zero, cpu);

	if (!cctx) {
		scx_bpf_error("no cpu_trace_ctx for cpu %d", cpu);
		return NULL;
	}

	return ctctx;
}

static void tstat_add(enum trace_stat_idx idx, struct cpu_trace_ctx *ctctx, s64 delta)
{
	u64 *vptr;

	if ((vptr = MEMBER_VPTR(*ctctx, .stats[idx])))
		(*vptr) += delta;
	else
		scx_bpf_error("invalid layer or stat idxs: %d", idx);
}

static void tstat_inc(enum trace_stat_idx, struct cpu_trace_ctx *ctctx)
{
	tstat_add(idx, ctctx, 1);
}


SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct* prev, struct task_struct* next)
{
	pid_t prev_pid = prev->tgid;
	pid_t prev_tid = prev->pid;
	uint64_t ts = bpf_ktime_get_ns();
	struct cpu_trace_ctx *ctctx;

	if (!(ctctx = lookup_cpu_trace_ctx(-1)))
		return;

	struct sched_switch_event *switche;

	switche = bpf_ringbuf_reserve(&sched_switch_rb, sizeof(*switche), 0);
	if (e) {
		switche->ts = ts;
		switche->cpu = cpu;
		switche->pid = BPF_CORE_READ(prev, pid);
		switche->running = 0;
		BPF_CORE_READ_STR_INTO(&switche->comm, prev, comm);

		on_sched_switch_prev(prev, switche);
		bpf_ringbuf_submit(switche, 0);
	} else {
		tstat_inc(TRACE_STAT_DROPPED);
	}

	switche = bpf_ringbuf_reserve(&sched_switch_rb, sizeof(*switche), 0);
	if (e) {
		switche->ts = bpf_ktime_get_boot_ns();
		switche->cpu = cpu;
		switche->pid = BPF_CORE_READ(next, pid);
		switche->running = 1;
		BPF_CORE_READ_STR_INTO(&switche->comm, next, comm);

		on_sched_switch_next(next, switche);
		bpf_ringbuf_submit(switche, 0);
	} else {
		tstat_inc(TRACE_STAT_DROPPED);
	}

	return 0;
}
