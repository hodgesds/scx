/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __LAVD_SOFT_AFFINITY_H
#define __LAVD_SOFT_AFFINITY_H

#include "intf.h"

#ifdef __BPF__
#define SOFT_ARENA __arena
#else
#define SOFT_ARENA
#endif

enum {
	LAVD_SOFT_TASK_SLOTS = 4,
	LAVD_SOFT_LLC_BITS = 7,
	LAVD_SOFT_SCORE_MAX = 511,
	LAVD_SOFT_LLC_UNSET = 255,
	LAVD_SOFT_EPOCH_NS = 32000000,
	LAVD_SOFT_RUNTIME_UNIT_NS = 128000,
	LAVD_SOFT_WAKE_SCORE = 8,
};

/*
 * Each scored entry occupies 16 bits: seven for the LLC and nine for its
 * score. Zero scores denote empty entries. Partner changes approximate
 * fanin and fanout without retaining a graph or kernel task pointers.
 */
struct soft_llc_state {
	u64 scored;
	u64 preferred_llcs[2];
	u64 pending_runtime;
	u32 seed;
	u32 epoch;
	u32 lock;
	u32 runtime_remainder;
	u32 last_waker;
	u32 last_wakee;
	u16 waker_changes;
	u16 wakee_changes;
	u8 slots;
	u8 preferred;
	u16 preferred_score;
};

_Static_assert(sizeof(struct soft_llc_state) == 64,
	       "keep per-task LLC history bounded");

static __attribute__((always_inline)) inline u32 soft_llc_hash(u64 value)
{
	value ^= value >> 30;
	value *= 0xbf58476d1ce4e5b9ULL;
	value ^= value >> 27;
	value *= 0x94d049bb133111ebULL;
	value ^= value >> 31;
	return value ^ (value >> 32);
}

static __attribute__((always_inline)) inline u32 soft_llc_count(u64 mask)
{
	mask -= (mask >> 1) & 0x5555555555555555ULL;
	mask = (mask & 0x3333333333333333ULL) +
	       ((mask >> 2) & 0x3333333333333333ULL);
	mask = (mask + (mask >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
	return (mask * 0x0101010101010101ULL) >> 56;
}

static __attribute__((always_inline)) inline u32
soft_llc_contains(u64 lo, u64 hi, u32 llc)
{
	u64 mask;

	if (llc >= LAVD_CPDOM_MAX_NR)
		return false;
	mask = lo ^ ((lo ^ hi) & -(u64)(llc >> 6));
	return (mask >> (llc & 63)) & 1;
}

/* Operands are bounded scores or slot indices, so their difference fits s32. */
static __attribute__((always_inline)) inline u32
soft_llc_greater_mask(u32 a, u32 b)
{
	s32 difference = b - a;
	u32 mask;

	/* Keep LLVM from turning the packed scans back into branching selects. */
	asm volatile("" : "+r"(difference));
	mask = difference >> 31;
	asm volatile("" : "+r"(mask));
	return mask;
}

static __attribute__((always_inline)) inline u32
soft_llc_score(u64 scored, u32 llc, u32 slots)
{
	u32 score = 0;

	if (llc >= LAVD_CPDOM_MAX_NR)
		return 0;
	if (slots > LAVD_SOFT_TASK_SLOTS)
		slots = LAVD_SOFT_TASK_SLOTS;
	#pragma unroll
	for (u32 i = 0; i < LAVD_SOFT_TASK_SLOTS; i++) {
		u16 entry = scored >> (i * 16);

		u32 equal = soft_llc_greater_mask(1, (entry & 127) ^ llc);
		u32 active = soft_llc_greater_mask(slots, i);

		score |= (entry >> LAVD_SOFT_LLC_BITS) & equal & active;
	}
	return score;
}

static __attribute__((always_inline)) inline void
soft_llc_decay(struct soft_llc_state SOFT_ARENA *state, u32 epoch)
{
	u32 elapsed = epoch - state->epoch;
	u32 slots = state->slots;
	u64 scored = 0;

	/* Wake timestamps may arrive out of order on different CPUs. */
	if ((s32)elapsed <= 0)
		return;
	if (elapsed > 9)
		elapsed = 9;
	if (slots > LAVD_SOFT_TASK_SLOTS)
		slots = LAVD_SOFT_TASK_SLOTS;
	#pragma unroll
	for (u32 i = 0; i < LAVD_SOFT_TASK_SLOTS; i++) {
		u16 entry = state->scored >> (i * 16);
		u32 score = (entry >> LAVD_SOFT_LLC_BITS) >> elapsed;

		if (i < slots && score)
			scored |= (u64)((score << LAVD_SOFT_LLC_BITS) |
					(entry & 127)) << (i * 16);
	}
	state->scored = scored;
	state->waker_changes >>= elapsed;
	state->wakee_changes >>= elapsed;
	state->preferred_score >>= elapsed;
	state->epoch = epoch;
}

static __attribute__((always_inline)) inline void
soft_llc_add(struct soft_llc_state SOFT_ARENA *state, u32 llc, u32 amount)
{
	u32 slot = LAVD_SOFT_TASK_SLOTS, weakest = LAVD_SOFT_SCORE_MAX + 1;
	u32 slots = state->slots;
	u32 match = LAVD_SOFT_TASK_SLOTS, score, found;
	u64 scored = state->scored;

	if (llc >= LAVD_CPDOM_MAX_NR || !amount)
		return;
	if (slots > LAVD_SOFT_TASK_SLOTS)
		slots = LAVD_SOFT_TASK_SLOTS;
	#pragma unroll
	for (u32 i = 0; i < LAVD_SOFT_TASK_SLOTS; i++) {
		u16 entry = scored >> (i * 16);
		u32 current = entry >> LAVD_SOFT_LLC_BITS;
		u32 active = soft_llc_greater_mask(slots, i);
		u32 equal = active & soft_llc_greater_mask(current, 0) &
			    soft_llc_greater_mask(1, (entry & 127) ^ llc);
		u32 smaller = active & soft_llc_greater_mask(weakest, current);

		match = (match & ~equal) | (i & equal);
		slot = (slot & ~smaller) | (i & smaller);
		weakest = (weakest & ~smaller) | (current & smaller);
	}
	found = soft_llc_greater_mask(LAVD_SOFT_TASK_SLOTS, match);
	slot = (slot & ~found) | (match & found);
	if (slot >= LAVD_SOFT_TASK_SLOTS)
		return;
	score = (scored >> (slot * 16 + LAVD_SOFT_LLC_BITS)) & LAVD_SOFT_SCORE_MAX;
	/* Space-saving replacement lets repeated new locations enter a full set. */
	if (amount > LAVD_SOFT_SCORE_MAX - score)
		score = LAVD_SOFT_SCORE_MAX;
	else
		score += amount;
	state->scored = (scored & ~(0xffffULL << (slot * 16))) |
		((u64)((score << LAVD_SOFT_LLC_BITS) | llc) << (slot * 16));
}

static __attribute__((always_inline)) inline void
soft_llc_runtime(struct soft_llc_state SOFT_ARENA *state, u32 llc, u64 runtime,
		 u32 epoch)
{
	u64 total = runtime + state->runtime_remainder;
	u64 amount = total / LAVD_SOFT_RUNTIME_UNIT_NS;

	soft_llc_decay(state, epoch);
	state->runtime_remainder = total % LAVD_SOFT_RUNTIME_UNIT_NS;
	soft_llc_add(state, llc, amount > LAVD_SOFT_SCORE_MAX ?
		     LAVD_SOFT_SCORE_MAX : amount);
}

static __attribute__((always_inline)) inline void
soft_llc_wake(struct soft_llc_state SOFT_ARENA *state, u32 peer, u32 llc,
	      bool incoming, u32 epoch)
{
	u32 previous, changes;

	soft_llc_decay(state, epoch);
	previous = incoming ? state->last_waker : state->last_wakee;
	changes = incoming ? state->waker_changes : state->wakee_changes;
	if (!changes || previous != peer) {
		if (changes < 65535)
			changes++;
	}
	if (incoming) {
		state->last_waker = peer;
		state->waker_changes = changes;
	} else {
		state->last_wakee = peer;
		state->wakee_changes = changes;
	}
	/* Many partners weaken individual pulls, while common LLCs accumulate. */
	if (changes > LAVD_SOFT_WAKE_SCORE)
		changes = LAVD_SOFT_WAKE_SCORE;
	soft_llc_add(state, llc, LAVD_SOFT_WAKE_SCORE / changes);
}

static __attribute__((always_inline)) inline u32
soft_llc_seed_home(u32 seed, u64 lo, u64 hi)
{
	u32 low_count = soft_llc_count(lo);
	u32 count = low_count + soft_llc_count(hi), ordinal, base = 0;

	if (!count)
		return LAVD_SOFT_LLC_UNSET;
	if (count > LAVD_CPDOM_MAX_NR || low_count > 64)
		return LAVD_SOFT_LLC_UNSET;
	ordinal = seed % count;
	if (ordinal >= low_count) {
		ordinal -= low_count;
		lo = hi;
		base = 64;
	}
	if (ordinal >= 64)
		return LAVD_SOFT_LLC_UNSET;
	for (u32 i = 0; i < 64; i++) {
		if (!lo)
			return LAVD_SOFT_LLC_UNSET;
		if (!ordinal)
			return base + __builtin_ctzll(lo);
		lo &= lo - 1;
		ordinal--;
	}
	return LAVD_SOFT_LLC_UNSET;
}

static __attribute__((always_inline)) inline u32
soft_llc_choose(u64 scored, u32 slots, u32 seed, u32 preferred,
		u64 lo, u64 hi)
{
	u32 best = LAVD_SOFT_LLC_UNSET, best_score = 0, incumbent;

	if (slots > LAVD_SOFT_TASK_SLOTS)
		slots = LAVD_SOFT_TASK_SLOTS;
	if (!soft_llc_contains(lo, hi, preferred))
		preferred = soft_llc_seed_home(seed, lo, hi);
	incumbent = soft_llc_score(scored, preferred, slots);
	#pragma unroll
	for (u32 i = 0; i < LAVD_SOFT_TASK_SLOTS; i++) {
		u16 entry = scored >> (i * 16);
		u32 llc = entry & 127, score = entry >> LAVD_SOFT_LLC_BITS;

		/*
		 * Arithmetic selection avoids multiplying verifier states across
		 * the four independent packed entries.
		 */
		u32 take = soft_llc_greater_mask(slots, i) &
			   -(u32)soft_llc_contains(lo, hi, llc) &
			   soft_llc_greater_mask(score, best_score);

		best = (best & ~take) | (llc & take);
		best_score = (best_score & ~take) | (score & take);
	}
	/* Require sustained evidence before replacing the indexed or learned home. */
	if (best_score > 2 * incumbent + LAVD_SOFT_WAKE_SCORE)
		preferred = best;
	return preferred;
}

static __attribute__((always_inline)) inline void
soft_llc_mask(u64 scored, u32 slots, u32 preferred, u64 home_lo, u64 home_hi,
	      u64 *lo, u64 *hi)
{
	u32 threshold = soft_llc_score(scored, preferred, slots) / 2;

	if (slots > LAVD_SOFT_TASK_SLOTS)
		slots = LAVD_SOFT_TASK_SLOTS;
	*lo = *hi = 0;
	if (!soft_llc_contains(home_lo, home_hi, preferred))
		return;
	if (preferred < 64)
		*lo = 1ULL << preferred;
	else
		*hi = 1ULL << (preferred - 64);
	if (threshold < LAVD_SOFT_WAKE_SCORE)
		threshold = LAVD_SOFT_WAKE_SCORE;
	#pragma unroll
	for (u32 i = 0; i < LAVD_SOFT_TASK_SLOTS; i++) {
		u16 entry = scored >> (i * 16);
		u32 llc = entry & 127, score = entry >> LAVD_SOFT_LLC_BITS;

		u32 take = soft_llc_greater_mask(slots, i) &
			   soft_llc_greater_mask(score, threshold) &
			   -(u32)soft_llc_contains(home_lo, home_hi, llc);
		u64 bit = 1ULL << (llc & 63);

		*lo |= bit & -(u64)((take & 1) & ((llc >> 6) ^ 1));
		*hi |= bit & -(u64)((take & 1) & (llc >> 6));
	}
}

static __attribute__((always_inline)) inline void
soft_llc_refresh(struct soft_llc_state SOFT_ARENA *state, u64 home_lo, u64 home_hi)
{
	u64 lo, hi;
	u32 previous, preferred, score;

	if (state->preferred == LAVD_SOFT_LLC_UNSET) {
		state->preferred = soft_llc_seed_home(state->seed, home_lo, home_hi);
		/* Give the indexed starting point a small, decaying prior. */
		soft_llc_add(state, state->preferred, 2 * LAVD_SOFT_WAKE_SCORE);
	}
	previous = state->preferred;
	preferred = soft_llc_choose(state->scored, state->slots,
				   state->seed, previous, home_lo, home_hi);
	/*
	 * Space-saving replacement can evict the incumbent entry. Preserve its
	 * decaying score so a new observation cannot bypass hysteresis.
	 */
	score = soft_llc_score(state->scored, preferred, state->slots);
	if (soft_llc_contains(home_lo, home_hi, previous) && preferred != previous &&
	    score <= 2 * state->preferred_score + LAVD_SOFT_WAKE_SCORE)
		preferred = previous;
	score = soft_llc_score(state->scored, preferred, state->slots);
	if (preferred != previous || score)
		state->preferred_score = score;
	state->preferred = preferred;
	soft_llc_mask(state->scored, state->slots, state->preferred,
		      home_lo, home_hi, &lo, &hi);
	state->preferred_llcs[0] = lo;
	state->preferred_llcs[1] = hi;
}

#undef SOFT_ARENA
#endif /* __LAVD_SOFT_AFFINITY_H */
