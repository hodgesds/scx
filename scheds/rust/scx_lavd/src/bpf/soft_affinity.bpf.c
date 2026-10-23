/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <scx/common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "power.bpf.h"
#include <lib/spinlock.h>

const volatile bool enable_soft_partitioning;

_Static_assert(LAVD_SOFT_LLC_WORDS == 2, "home snapshots require two LLC words");

struct soft_affinity_group {
	u64 runtime;
	u64 llcs[LAVD_SOFT_LLC_WORDS];
	u64 id;
	u32 refs;
	u32 seq;
	struct soft_affinity_key key;
	u8 initial_llc;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LAVD_SOFT_GROUP_MAX_NR);
	__type(key, struct soft_affinity_key);
	__type(value, u64);
} soft_affinity_groups SEC(".maps");

/* Only membership and userspace commands take this lock, not CPU selection. */
static arena_spinlock_t __arena_global group_lock;
static u64 next_group_id;
static struct scx_urcu group_urcu;
static struct scx_allocator group_allocator;

__hidden int soft_affinity_init(void)
{
	return scx_alloc_init(&group_allocator,
			      sizeof(struct soft_affinity_group),
			      CACHELINE_SIZE);
}

static struct soft_affinity_group __arena *
lookup_group(struct soft_affinity_key *key)
{
	u64 *ptr = bpf_map_lookup_elem(&soft_affinity_groups, key);

	return ptr ? (struct soft_affinity_group __arena *)*ptr : NULL;
}

__hidden void soft_affinity_running(struct task_struct *p,
				    task_ctx __arg_arena *taskc,
				    struct cpu_ctx *cpuc)
{
	struct soft_affinity_group __arena *group, *new;
	struct soft_affinity_key key;
	u64 ptr;

	/* Use @p's CPU context: ops.running() can be invoked from a remote CPU. */
	if (taskc->home_numa_id < 0) {
		struct cpdom_ctx *cpdc =
			MEMBER_VPTR(cpdom_ctxs, [cpuc->cpdom_id]);

		if (!cpdc || !cpdc->is_valid)
			return;
		taskc->home_numa_id = cpdc->numa_id;
		taskc->home_llc_id = cpuc->llc_id;
	}
	if (taskc->soft_group)
		return;

	key.tgid = p->tgid;
	key.numa_id = taskc->home_numa_id;
	{
		guard(scx_spin_lock_irqsave)(&group_lock);
		group = lookup_group(&key);
		if (group) {
			group->refs++;
			taskc->soft_group = group;
			return;
		}
	}

	new = scx_alloc(&group_allocator);
	if (!new)
		return;
	new->runtime = 0;
	new->llcs[0] = new->llcs[1] = 0;
	new->refs = 0;
	new->seq = 0;
	new->key = key;
	new->initial_llc = taskc->home_llc_id;
	{
		guard(scx_spin_lock_irqsave)(&group_lock);
		/* Another thread may have published the group while we allocated. */
		group = lookup_group(&key);
		if (!group) {
			new->id = ++next_group_id;
			ptr = (u64)new;
			if (!bpf_map_update_elem(&soft_affinity_groups, &key,
						 &ptr, BPF_NOEXIST)) {
				group = new;
				new = NULL;
			}
		}
		if (group) {
			group->refs++;
			taskc->soft_group = group;
		}
	}
	/* Allocation failure or a full index only disables autosizing for this task. */
	if (new)
		scx_free(&group_allocator, new);
}

__hidden void soft_affinity_account(task_ctx __arg_arena *taskc, u64 runtime)
{
	struct soft_affinity_group __arena *group;

	bpf_rcu_read_lock();
	group = READ_ONCE(taskc->soft_group);
	if (group && runtime)
		__sync_fetch_and_add(&group->runtime, runtime);
	bpf_rcu_read_unlock();
}

__hidden void soft_affinity_exit(task_ctx __arg_arena *taskc)
{
	struct soft_affinity_group __arena *group;
	struct soft_affinity_key key;
	bool retire = false;

	bpf_rcu_read_lock();
	{
		guard(scx_spin_lock_irqsave)(&group_lock);
		group = taskc->soft_group;
		taskc->soft_group = NULL;
		if (group && !--group->refs) {
			key = group->key;
			if (bpf_map_delete_elem(&soft_affinity_groups, &key))
				scx_bpf_error(
					"Failed to remove soft-affinity group");
			else
				retire = true;
		}
	}
	/* Readers of taskc may still hold the cached group pointer. */
	if (retire)
		scx_urcu_free(&group_urcu, &group_allocator, group);
	bpf_rcu_read_unlock();
}

/* A racing resize falls back to the initial LLC, without retrying on a wakeup. */
static void home_llcs(task_ctx *taskc, u64 *lo, u64 *hi)
{
	struct soft_affinity_group __arena *group =
		READ_ONCE(taskc->soft_group);
	u32 seq;
	u8 initial = taskc->home_llc_id;

	*lo = *hi = 0;
	if (group) {
		initial = group->initial_llc;
		seq = smp_load_acquire(&group->seq);
		if (!(seq & 1)) {
			*lo = READ_ONCE(group->llcs[0]);
			*hi = READ_ONCE(group->llcs[1]);
			smp_rmb();
			if (seq != READ_ONCE(group->seq))
				*lo = *hi = 0;
		}
	}
	if (!(*lo | *hi)) {
		if (initial < 64)
			*lo = 1ULL << initial;
		else
			*hi = 1ULL << (initial - 64);
	}
}

__hidden bool soft_affinity_cpu_home(task_ctx __arg_arena *taskc, s32 cpu)
{
	struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
	struct cpdom_ctx *cpdc;
	u64 lo, hi;

	if (taskc->home_numa_id < 0 || !cpuc)
		return false;
	cpdc = MEMBER_VPTR(cpdom_ctxs, [cpuc->cpdom_id]);
	if (!cpdc || !cpdc->is_valid || cpdc->numa_id != taskc->home_numa_id)
		return false;
	home_llcs(taskc, &lo, &hi);
	return cpuc->llc_id < 64 ? lo & (1ULL << cpuc->llc_id) :
				   hi & (1ULL << (cpuc->llc_id - 64));
}

static s32 pick_home_idle_cpu(struct pick_ctx *ctx, struct bpf_cpumask *mask,
			      u64 scope)
{
	/* Preserve CPU warmth within a home, with the same SMT preference as LAVD. */
	if (ctx->prev_cpu >= 0 &&
	    bpf_cpumask_test_cpu(ctx->prev_cpu, cast_mask(mask))) {
		bool usable = true;

		if (scope && is_smt_active) {
			const struct cpumask *idle = scx_bpf_get_idle_smtmask();

			usable = bpf_cpumask_test_cpu(ctx->prev_cpu, idle);
			scx_bpf_put_idle_cpumask(idle);
		}
		if (usable && scx_bpf_test_and_clear_cpu_idle(ctx->prev_cpu))
			return ctx->prev_cpu;
	}
	return scx_bpf_pick_idle_cpu(cast_mask(mask), scope);
}

__hidden s32 soft_affinity_pick(struct pick_ctx *ctx)
{
	struct bpf_cpumask *home, *eligible, *scratch, *steady;
	struct cpdom_ctx *cpdc;
	u64 lo, hi;
	bool big, vulnerable;
	s32 cpu;
	int pass, dom, tier, scope;

	if (ctx->taskc->home_numa_id < 0 || !ctx->cpuc_cur)
		return -ENOENT;
	home = ctx->cpuc_cur->ia_mask;
	eligible = ctx->cpuc_cur->io_mask;
	scratch = ctx->cpuc_cur->temp_mask;
	steady = steady_cpumask;
	if (!home || !eligible || !scratch)
		return -ENOENT;
	home_llcs(ctx->taskc, &lo, &hi);
	big = is_perf_cri(ctx->taskc);
	cpdc = MEMBER_VPTR(cpdom_ctxs, [ctx->cpuc_cur->cpdom_id]);
	vulnerable = cpdc &&
		     preemption_vulnerability(ctx->taskc->normalized_lat_cri,
					      ctx->taskc->util_est) >=
			     cpdc->vuln_thresh;

	/* Prefer the matching core type, then allow the other type in the same home. */
	bpf_for(pass, 0, 2)
	{
		bpf_cpumask_clear(home);
		bpf_for(dom, 0, nr_cpdoms)
		{
			struct bpf_cpumask *mask;
			u8 llc;

			if (dom >= LAVD_CPDOM_MAX_NR)
				break;
			cpdc = MEMBER_VPTR(cpdom_ctxs, [dom]);
			mask = MEMBER_VPTR(cpdom_cpumask, [dom]);
			if (!cpdc || !mask || !cpdc->is_valid ||
			    cpdc->numa_id != ctx->taskc->home_numa_id ||
			    (!pass && cpdc->is_big != big))
				continue;
			llc = cpdc->llc_id;
			if (llc < 64 ? !(lo & (1ULL << llc)) :
				       !(hi & (1ULL << (llc - 64))))
				continue;
			bpf_cpumask_or(home, cast_mask(home), cast_mask(mask));
		}
		bpf_cpumask_and(home, cast_mask(home), ctx->p->cpus_ptr);
		bpf_cpumask_or(eligible, cast_mask(ctx->active),
			       cast_mask(ctx->ovrflw));
		bpf_cpumask_and(eligible, cast_mask(eligible), cast_mask(home));

		/* Fully idle cores precede SMT threads; steady CPUs precede turbulent ones. */
		bpf_for(scope, 0, 2)
		{
			bpf_for(tier, 0, 2)
			{
				if (!tier && vulnerable && steady)
					bpf_cpumask_and(scratch,
							cast_mask(eligible),
							cast_mask(steady));
				else if (!tier)
					bpf_cpumask_and(scratch,
							cast_mask(home),
							cast_mask(ctx->active));
				else
					bpf_cpumask_copy(scratch,
							 cast_mask(eligible));
				cpu = pick_home_idle_cpu(
					ctx, scratch,
					scope ? 0 : SCX_PICK_IDLE_CORE);
				if (cpu >= 0)
					return cpu;
			}
		}
	}
	return -ENOENT;
}

SEC("syscall")
int lavd_soft_affinity_cmd(struct soft_affinity_cmd *args)
{
	struct soft_affinity_key key = args->key;
	struct soft_affinity_group __arena *group;
	u64 lo = args->llcs[0], hi = args->llcs[1], valid_lo = 0, valid_hi = 0;
	u32 seq;
	int dom;

	if (!enable_soft_partitioning || args->op > LAVD_SOFT_APPLY)
		return -EINVAL;
	guard(scx_spin_lock_irqsave)(&group_lock);
	group = lookup_group(&key);
	if (!group)
		return -ENOENT;
	if (args->op == LAVD_SOFT_SAMPLE) {
		args->id = group->id;
		args->runtime = READ_ONCE(group->runtime);
		args->llcs[0] = READ_ONCE(group->llcs[0]);
		args->llcs[1] = READ_ONCE(group->llcs[1]);
		if (!(args->llcs[0] | args->llcs[1])) {
			if (group->initial_llc < 64)
				args->llcs[0] = 1ULL << group->initial_llc;
			else
				args->llcs[1] = 1ULL
						<< (group->initial_llc - 64);
		}
		return 0;
	}
	/* A process can exit and its PID be reused between sampling and applying. */
	if (args->id != group->id)
		return -ESTALE;
	bpf_for(dom, 0, nr_cpdoms)
	{
		struct cpdom_ctx *cpdc;

		if (dom >= LAVD_CPDOM_MAX_NR)
			break;
		cpdc = MEMBER_VPTR(cpdom_ctxs, [dom]);
		if (!cpdc || !cpdc->is_valid || cpdc->numa_id != key.numa_id)
			continue;
		if (cpdc->llc_id < 64)
			valid_lo |= 1ULL << cpdc->llc_id;
		else
			valid_hi |= 1ULL << (cpdc->llc_id - 64);
	}
	seq = group->seq;
	WRITE_ONCE(group->seq, seq + 1);
	smp_wmb();
	WRITE_ONCE(group->llcs[0], lo & valid_lo);
	WRITE_ONCE(group->llcs[1], hi & valid_hi);
	smp_store_release(&group->seq, seq + 2);
	return 0;
}

__hidden void soft_affinity_dump(task_ctx __arg_arena *taskc)
{
	u64 lo, hi;

	if (taskc->home_numa_id < 0) {
		scx_bpf_dump("  \\_ home_numa: not observed\n");
		return;
	}
	bpf_rcu_read_lock();
	home_llcs(taskc, &lo, &hi);
	scx_bpf_dump("  \\_ home_numa: %d   home_llcs: %llx:%016llx\n",
		     taskc->home_numa_id, hi, lo);
	bpf_rcu_read_unlock();
}

SEC("syscall")
int scx_urcu_soft_pending(void *ctx)
{
	return scx_urcu_pending(&group_urcu);
}

SEC("syscall")
int scx_urcu_soft_reclaim(void *ctx)
{
	return scx_urcu_reclaim(&group_urcu, &group_allocator);
}
