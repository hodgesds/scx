/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <scx/common.bpf.h>
#include <scx/numa.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "power.bpf.h"
#include "util.bpf.h"
#include <lib/spinlock.h>

const volatile bool enable_soft_partitioning;
const volatile u8 soft_affinity_slots;

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
static void home_llcs(task_ctx *taskc, u64 *lo, u64 *hi);

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

static __always_inline bool history_try_lock(struct soft_llc_state __arena *state)
{
	/* Advisory samples can be dropped instead of spinning under an rq lock. */
	return !READ_ONCE(state->lock) &&
	       __sync_bool_compare_and_swap(&state->lock, 0, 1);
}

static __always_inline void history_unlock(struct soft_llc_state __arena *state)
{
	smp_store_release(&state->lock, 0);
}

static __attribute__((noinline)) void
history_refresh(struct soft_llc_state __arena *history, u64 home_lo, u64 home_hi)
{
	soft_llc_refresh(history, home_lo, home_hi);
}

static s32 initial_home_llc(struct task_struct *p, s32 node, u8 *slots)
{
	u64 lo = 0, hi = 0, allowed_lo = 0, allowed_hi = 0;
	u32 nr, nr_lo, slot, base;
	int dom, llc, i;

	/* An LLC can have separate compute domains for different core types. */
	bpf_for(dom, 0, nr_cpdoms) {
		struct cpdom_ctx *cpdc;
		struct bpf_cpumask *mask;
		u64 bit;

		if (dom >= LAVD_CPDOM_MAX_NR)
			break;
		cpdc = MEMBER_VPTR(cpdom_ctxs, [dom]);
		mask = MEMBER_VPTR(cpdom_cpumask, [dom]);
		if (!cpdc || !mask || !cpdc->is_valid || cpdc->numa_id != node ||
		    cpdc->llc_id >= LAVD_CPDOM_MAX_NR ||
		    bpf_cpumask_empty(cast_mask(mask)))
			continue;
		llc = cpdc->llc_id;
		bit = 1ULL << (llc & 63);
		if (llc < 64)
			lo |= bit;
		else
			hi |= bit;
		if (!bpf_cpumask_intersects(cast_mask(mask), p->cpus_ptr))
			continue;
		if (llc < 64)
			allowed_lo |= bit;
		else
			allowed_hi |= bit;
	}
	if (allowed_lo | allowed_hi) {
		lo = allowed_lo;
		hi = allowed_hi;
	}
	nr_lo = soft_llc_count(lo);
	nr = nr_lo + soft_llc_count(hi);
	if (!nr || nr > LAVD_CPDOM_MAX_NR)
		return -ENOENT;
	if (!soft_affinity_slots)
		*slots = min(nr, LAVD_SOFT_TASK_SLOTS);
	/* Index the eligible LLCs, whose IDs can be sparse and span NUMA nodes. */
	slot = (u32)p->tgid % nr;
	if (slot < nr_lo) {
		base = 0;
	} else {
		base = 64;
		slot -= nr_lo;
		lo = hi;
	}
	if (slot >= 64)
		return -ENOENT;
	/* Clear only the set bits preceding the selected ordinal. */
	for (i = 0; i < 64 && can_loop; i++) {
		if (!lo)
			return -ENOENT;
		if (!slot)
			return base + ctzll(lo);
		lo &= lo - 1;
		slot--;
	}
	return -ENOENT;
}

/* Called from sleepable init_task, outside RCU and IRQ/preempt-disabled sections. */
__hidden void soft_affinity_init_task(struct task_struct *p,
				      task_ctx __arg_arena *taskc)
{
	struct soft_llc_state __arena *history = &taskc->llc_history;
	struct task_struct *identity = p;
	u64 address = 0;
	u8 slots = soft_affinity_slots ? : LAVD_SOFT_TASK_SLOTS;
	s32 node;
	s32 llc;

	/* Reset inherited history and retain only a hash of this task's address. */
	history->scored = 0;
	history->preferred_llcs[0] = 0;
	history->preferred_llcs[1] = 0;
	history->pending_runtime = 0;
	/* A probe read converts the pointer to a scalar the verifier can hash. */
	history->seed = bpf_probe_read_kernel(&address, sizeof(address), &identity) ?
			bpf_get_prandom_u32() : soft_llc_hash(address);
	history->epoch = bpf_ktime_get_ns() / LAVD_SOFT_EPOCH_NS;
	history->lock = 0;
	history->runtime_remainder = 0;
	history->last_waker = 0;
	history->last_wakee = 0;
	history->waker_changes = 0;
	history->wakee_changes = 0;
	history->slots = slots;
	history->preferred = LAVD_SOFT_LLC_UNSET;
	history->preferred_score = 0;

	/* Allocation failure leaves the initial LLC home usable without autosizing. */
	taskc->soft_group_spare = scx_alloc(&group_allocator);

	bpf_rcu_read_lock();
	node = scx_task_numa_node(p);
	if (node < 0)
		goto unlock_out;
	llc = initial_home_llc(p, node, &slots);
	/* An unavailable hint or a CPU-less node leaves the first-run fallback. */
	if (llc >= 0) {
		taskc->home_numa_id = node;
		taskc->home_llc_id = llc;
		history->slots = slots;
	}
unlock_out:
	bpf_rcu_read_unlock();
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
		s32 llc;
		u8 slots = taskc->llc_history.slots;

		if (!cpdc || !cpdc->is_valid)
			return;
		taskc->home_numa_id = cpdc->numa_id;
		llc = initial_home_llc(p, cpdc->numa_id, &slots);
		taskc->home_llc_id = llc >= 0 ? llc : cpuc->llc_id;
		taskc->llc_history.slots = slots;
	}
	if (taskc->soft_group)
		return;

	key.tgid = p->tgid;
	key.numa_id = taskc->home_numa_id;
	new = taskc->soft_group_spare;
	{
		guard(scx_spin_lock_irqsave)(&group_lock);
		group = lookup_group(&key);
		if (!group && new) {
			new->runtime = 0;
			new->llcs[0] = new->llcs[1] = 0;
			new->refs = 0;
			new->seq = 0;
			new->key = key;
			new->initial_llc = taskc->home_llc_id;
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
			taskc->soft_group_spare = NULL;
		}
	}
	/* A full index keeps the reservation for a later publication attempt. */
	if (!group)
		return;
	/* An unused reservation was never published and needs no grace period. */
	if (new)
		scx_free(&group_allocator, new);
}

__hidden void soft_affinity_account(task_ctx __arg_arena *taskc, u64 runtime)
{
	struct soft_affinity_group __arena *group;

	bpf_rcu_read_lock();
	group = READ_ONCE(taskc->soft_group);
	if (runtime) {
		if (group)
			__sync_fetch_and_add(&group->runtime, runtime);
		__sync_fetch_and_add(&taskc->llc_history.pending_runtime, runtime);
	}
	bpf_rcu_read_unlock();
}

__hidden void soft_affinity_learn(task_ctx __arg_arena *taskc,
				 struct cpu_ctx *cpuc)
{
	struct soft_llc_state __arena *history = &taskc->llc_history;
	u64 home_lo, home_hi;
	u64 runtime;
	u32 epoch = bpf_ktime_get_ns() / LAVD_SOFT_EPOCH_NS;

	bpf_rcu_read_lock();
	home_llcs(taskc, &home_lo, &home_hi);
	if (history_try_lock(history)) {
		runtime = __sync_lock_test_and_set(&history->pending_runtime, 0);
		if (history->preferred == LAVD_SOFT_LLC_UNSET)
			history_refresh(history, home_lo, home_hi);
		soft_llc_runtime(history, cpuc->llc_id, runtime, epoch);
		history_refresh(history, home_lo, home_hi);
		history_unlock(history);
	}
	bpf_rcu_read_unlock();
}

__hidden void soft_affinity_wake(struct task_struct *p,
				task_ctx __arg_arena *wakee,
				struct task_struct *waker)
{
	struct soft_llc_state __arena *from, *to;
	struct cpu_ctx *cpuc;
	task_ctx *waker_taskc;
	u32 from_llc, to_llc, from_seed, to_seed;
	u64 from_lo, from_hi, to_lo, to_hi;
	u32 epoch = bpf_ktime_get_ns() / LAVD_SOFT_EPOCH_NS;

	if (p == waker || is_kernel_task(p) || is_kernel_task(waker))
		return;
	bpf_rcu_read_lock();
	waker_taskc = find_task_ctx(waker);
	if (!waker_taskc)
		goto out;
	from = &waker_taskc->llc_history;
	to = &wakee->llc_history;
	from_seed = READ_ONCE(from->seed);
	to_seed = READ_ONCE(to->seed);
	home_llcs(waker_taskc, &from_lo, &from_hi);
	home_llcs(wakee, &to_lo, &to_hi);
	from_llc = READ_ONCE(from->preferred);
	to_llc = READ_ONCE(to->preferred);
	if (from_llc == LAVD_SOFT_LLC_UNSET) {
		cpuc = get_cpu_ctx_task(waker);
		if (!cpuc)
			goto out;
		from_llc = cpuc->llc_id;
	}
	if (to_llc == LAVD_SOFT_LLC_UNSET) {
		cpuc = get_cpu_ctx_task(p);
		if (!cpuc)
			goto out;
		to_llc = cpuc->llc_id;
	}
	/* Never nest task locks: reciprocal wakeups can arrive on different CPUs. */
	if (history_try_lock(to)) {
		soft_llc_wake(to, from_seed, from_llc, true, epoch);
		history_refresh(to, to_lo, to_hi);
		history_unlock(to);
	}
	if (history_try_lock(from)) {
		soft_llc_wake(from, to_seed, to_llc, false, epoch);
		history_refresh(from, from_lo, from_hi);
		history_unlock(from);
	}
out:
	bpf_rcu_read_unlock();
}

__hidden void soft_affinity_exit(task_ctx __arg_arena *taskc)
{
	struct soft_affinity_group __arena *group, *spare;
	struct soft_affinity_key key;
	bool retire = false;

	bpf_rcu_read_lock();
	{
		guard(scx_spin_lock_irqsave)(&group_lock);
		group = taskc->soft_group;
		taskc->soft_group = NULL;
		spare = taskc->soft_group_spare;
		taskc->soft_group_spare = NULL;
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
	/* The task can exit before running or while the group index is full. */
	if (spare)
		scx_free(&group_allocator, spare);
}

/* A racing resize falls back to the initial LLC, without retrying on a wakeup. */
static void home_llcs(task_ctx *taskc, u64 *lo, u64 *hi)
{
	struct soft_affinity_group __arena *group =
		READ_ONCE(taskc->soft_group);
	u32 seq;
	u8 initial = taskc->home_llc_id;

	*lo = *hi = 0;
	if (taskc->home_numa_id < 0)
		return;
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

static u32 task_llcs(task_ctx *taskc, u64 home_lo, u64 home_hi, u64 *lo, u64 *hi)
{
	struct soft_llc_state __arena *history = &taskc->llc_history;
	u32 preferred = READ_ONCE(history->preferred);

	/* Racing updates are advisory; affinity and active masks are checked below. */
	*lo = READ_ONCE(history->preferred_llcs[0]) & home_lo;
	*hi = READ_ONCE(history->preferred_llcs[1]) & home_hi;
	if (!(*lo | *hi)) {
		*lo = home_lo;
		*hi = home_hi;
	}
	return soft_llc_contains(*lo, *hi, preferred) ?
	       preferred : LAVD_SOFT_LLC_UNSET;
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
	task_llcs(taskc, lo, hi, &lo, &hi);
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

__hidden s32 soft_affinity_pick(struct pick_ctx *ctx, s32 *home_cpu)
{
	struct bpf_cpumask *home, *eligible, *scratch, *steady;
	struct cpdom_ctx *cpdc;
	u64 lo, hi, preferred_lo, preferred_hi, primary_lo, primary_hi;
	u32 primary;
	bool big, vulnerable;
	s32 cpu;
	int attempt, dom, tier, scope;

	if (ctx->taskc->home_numa_id < 0 || !ctx->cpuc_cur)
		return -ENOENT;
	home = ctx->cpuc_cur->ia_mask;
	eligible = ctx->cpuc_cur->io_mask;
	scratch = ctx->cpuc_cur->temp_mask;
	steady = steady_cpumask;
	if (!home || !eligible || !scratch)
		return -ENOENT;
	home_llcs(ctx->taskc, &lo, &hi);
	primary = task_llcs(ctx->taskc, lo, hi, &preferred_lo, &preferred_hi);
	primary_lo = primary < 64 ? 1ULL << primary : 0;
	primary_hi = primary >= 64 && primary < 128 ? 1ULL << (primary - 64) : 0;
	big = is_perf_cri(ctx->taskc);
	cpdc = MEMBER_VPTR(cpdom_ctxs, [ctx->cpuc_cur->cpdom_id]);
	vulnerable = cpdc &&
		     preemption_vulnerability(ctx->taskc->normalized_lat_cri,
					      ctx->taskc->util_est) >=
			     cpdc->vuln_thresh;

	/* Search the primary LLC, other preferences, then the group home per core type. */
	bpf_for(attempt, 0, 6)
	{
		bool other_type = attempt >= 3;
		u32 preference = attempt % 3;
		u64 search_lo = lo, search_hi = hi;

		if (!preference) {
			search_lo = primary_lo;
			search_hi = primary_hi;
		} else if (preference == 1) {
			if (preferred_lo == primary_lo && preferred_hi == primary_hi)
				continue;
			search_lo = preferred_lo;
			search_hi = preferred_hi;
		} else if (lo == preferred_lo && hi == preferred_hi) {
			continue;
		}

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
			    (!other_type && cpdc->is_big != big))
				continue;
			llc = cpdc->llc_id;
			if (llc < 64 ? !(search_lo & (1ULL << llc)) :
				       !(search_hi & (1ULL << (llc - 64))))
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
				/* Keep a busy home CPU as the anchor for overload balancing. */
				if (*home_cpu < 0) {
					if (ctx->prev_cpu >= 0 &&
					    bpf_cpumask_test_cpu(ctx->prev_cpu, cast_mask(scratch)))
						*home_cpu = ctx->prev_cpu;
					else {
						cpu = bpf_cpumask_any_distribute(cast_mask(scratch));
						if (cpu >= 0 && cpu < nr_cpu_ids)
							*home_cpu = cpu;
					}
				}
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
	struct soft_llc_state __arena *history = &taskc->llc_history;
	u64 lo, hi, preferred_lo, preferred_hi, scored;
	u32 preferred;

	if (taskc->home_numa_id < 0) {
		scx_bpf_dump("  \\_ home_numa: not observed\n");
		return;
	}
	bpf_rcu_read_lock();
	home_llcs(taskc, &lo, &hi);
	scx_bpf_dump("  \\_ home_numa: %d   home_llcs: %llx:%016llx\n",
		     taskc->home_numa_id, hi, lo);
	scored = READ_ONCE(history->scored);
	preferred = soft_llc_choose(scored, READ_ONCE(history->slots),
				    READ_ONCE(history->seed), READ_ONCE(history->preferred),
				    lo, hi);
	soft_llc_mask(scored, READ_ONCE(history->slots), preferred, lo, hi,
		      &preferred_lo, &preferred_hi);
	scx_bpf_dump("  \\_ preferred_llc: %u   preferred_llcs: %llx:%016llx\n",
		     preferred, preferred_hi, preferred_lo);
	scx_bpf_dump("  \\_ llc_scores: %016llx   slots: %u   waker_changes: %u   wakee_changes: %u\n",
		     scored, READ_ONCE(history->slots),
		     READ_ONCE(history->waker_changes), READ_ONCE(history->wakee_changes));
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
