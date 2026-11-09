/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include "../src/bpf/soft_affinity.h"

static struct soft_llc_state history(u8 slots)
{
	return (struct soft_llc_state) {
		.slots = slots,
		.preferred = LAVD_SOFT_LLC_UNSET,
	};
}

static void test_packed_entries(void)
{
	struct soft_llc_state state = history(4);
	u32 ids[] = { 0, 63, 64, 127 };

	for (u32 i = 0; i < 4; i++)
		soft_llc_add(&state, ids[i], 10 + i);
	for (u32 i = 0; i < 4; i++)
		assert(soft_llc_score(state.scored, ids[i], 4) == 10 + i);
	soft_llc_add(&state, 64, 1000);
	assert(soft_llc_score(state.scored, 64, 4) == 511);
	assert(soft_llc_score(state.scored, 63, 4) == 11);
	assert(soft_llc_score(state.scored, 127, 4) == 13);
	u64 before = state.scored;
	soft_llc_add(&state, 128, 100);
	assert(state.scored == before);
	assert(!soft_llc_contains(~0ULL, ~0ULL, 128));
	assert(!soft_llc_contains(~0ULL, ~0ULL, 255));
}

static void test_slot_limits_and_replacement(void)
{
	for (u32 slots = 1; slots <= 4; slots++) {
		struct soft_llc_state state = history(slots);

		for (u32 llc = 0; llc < 16; llc++)
			soft_llc_add(&state, llc, 1);
		if (slots < 4)
			assert(!(state.scored >> (slots * 16)));
		/* New repeated observations can enter even a full history. */
		for (u32 n = 0; n < 100; n++)
			soft_llc_add(&state, 100, 1);
		assert(soft_llc_score(state.scored, 100, slots) >= 100);
	}
}

static void test_runtime_and_decay(void)
{
	struct soft_llc_state state = history(4);

	for (u32 i = 0; i < 128; i++)
		soft_llc_runtime(&state, 7, 1000, 0);
	assert(soft_llc_score(state.scored, 7, 4) == 1);
	assert(state.runtime_remainder == 0);
	soft_llc_runtime(&state, 7, 128000 * 31, 0);
	soft_llc_decay(&state, 1);
	assert(soft_llc_score(state.scored, 7, 4) == 16);
	/* A delayed remote wakeup must not erase newer observations. */
	soft_llc_decay(&state, 0);
	assert(soft_llc_score(state.scored, 7, 4) == 16);
	soft_llc_decay(&state, 10);
	assert(!state.scored);
	state.epoch = (u32)-1;
	soft_llc_add(&state, 7, 32);
	soft_llc_decay(&state, 0);
	assert(soft_llc_score(state.scored, 7, 4) == 16);
}

static void test_dynamic_wake_preferences(void)
{
	struct soft_llc_state state = history(4);
	u32 preferred = 1;
	u64 lo, hi;

	soft_llc_add(&state, 1, 32);
	soft_llc_wake(&state, 42, 2, true, 0);
	assert(soft_llc_choose(state.scored, 4, 0, preferred, 6, 0) == 1);
	for (u32 i = 0; i < 10; i++)
		soft_llc_wake(&state, 42, 2, true, 0);
	preferred = soft_llc_choose(state.scored, 4, 0, preferred, 6, 0);
	assert(preferred == 2);
	assert(state.waker_changes == 1);
	soft_llc_mask(state.scored, 4, preferred, 6, 0, &lo, &hi);
	assert(lo & 4);
	assert(!(lo & ~6ULL) && !hi);
	/* Repeated execution on another LLC can supersede a wake preference. */
	for (u32 i = 0; i < 200; i++)
		soft_llc_runtime(&state, 1, LAVD_SOFT_RUNTIME_UNIT_NS, 0);
	assert(soft_llc_choose(state.scored, 4, 0, preferred, 6, 0) == 1);
}

static void test_fanin_and_fanout(void)
{
	struct soft_llc_state pair = history(4), many = history(4);

	for (u32 i = 0; i < 16; i++) {
		soft_llc_wake(&pair, 42, 3, true, 0);
		soft_llc_wake(&many, i + 1, 3, true, 0);
		soft_llc_wake(&many, i + 1, 3, false, 0);
	}
	assert(pair.waker_changes == 1);
	assert(many.waker_changes == 16 && many.wakee_changes == 16);
	assert(soft_llc_score(many.scored, 3, 4) <
	       soft_llc_score(pair.scored, 3, 4));
	/* Diverse partners in one LLC still provide a common locality signal. */
	assert(soft_llc_choose(many.scored, 4, 0, 1, 10, 0) == 3);
	soft_llc_decay(&many, 9);
	assert(!many.waker_changes && !many.wakee_changes && !many.scored);
}

static void test_sparse_homes_and_resize(void)
{
	struct soft_llc_state state = history(4);
	u64 lo, hi;

	assert(soft_llc_seed_home(0, 2, 1ULL << 63) == 1);
	assert(soft_llc_seed_home(1, 2, 1ULL << 63) == 127);
	assert(soft_llc_seed_home(0, 0, 0) == LAVD_SOFT_LLC_UNSET);
	soft_llc_add(&state, 65, 511);
	soft_llc_add(&state, 127, 64);
	assert(soft_llc_choose(state.scored, 4, 0, 1, 2, 1ULL << 63) == 127);
	/* Removing an LLC reindexes the task within the surviving home. */
	assert(soft_llc_choose(state.scored, 4, 0, 127, 2, 0) == 1);
	soft_llc_mask(state.scored, 4, 127, 2, 1ULL << 63, &lo, &hi);
	assert(!lo && hi == (1ULL << 63));
}

static void test_aligned_address_seeds(void)
{
	u32 buckets[4] = { 0 };

	for (u64 i = 0; i < 256; i++) {
		u64 address = 0xffff888000000000ULL + i * 64;
		u32 seed = soft_llc_hash(address);

		assert(seed == soft_llc_hash(address));
		buckets[soft_llc_seed_home(seed, 15, 0)]++;
	}
	for (u32 i = 0; i < 4; i++)
		assert(buckets[i] > 32);
}

static void test_cached_preferences(void)
{
	struct soft_llc_state state = history(4);

	state.seed = 1;
	soft_llc_refresh(&state, 3, 0);
	assert(state.preferred == 1 && state.preferred_llcs[0] == 2);
	assert(!state.preferred_llcs[1]);
	soft_llc_runtime(&state, 0, 8 * LAVD_SOFT_RUNTIME_UNIT_NS, 0);
	soft_llc_refresh(&state, 3, 0);
	assert(state.preferred == 1);
	for (u32 i = 0; i < 16; i++)
		soft_llc_wake(&state, 42, 0, true, 0);
	soft_llc_refresh(&state, 3, 0);
	assert(state.preferred == 0 && state.preferred_llcs[0] == 1);
	soft_llc_refresh(&state, 4, 0);
	assert(state.preferred == 2 && state.preferred_llcs[0] == 4);
	soft_llc_refresh(&state, 0, 0);
	assert(state.preferred == LAVD_SOFT_LLC_UNSET);
	assert(!state.preferred_llcs[0] && !state.preferred_llcs[1]);
}

static void test_evicted_incumbent_keeps_hysteresis(void)
{
	for (u32 slots = 1; slots <= 4; slots++) {
		struct soft_llc_state state = history(slots);

		state.preferred = 0;
		soft_llc_add(&state, 0, 511);
		soft_llc_refresh(&state, 31, 0);
		assert(state.preferred_score == 511);
		for (u32 llc = 1; llc < slots; llc++)
			soft_llc_add(&state, llc, 511);
		soft_llc_add(&state, 4, 1);
		assert(!soft_llc_score(state.scored, 0, slots));
		soft_llc_refresh(&state, 31, 0);
		assert(state.preferred == 0);
		assert(state.preferred_score == 511);
		/* Sustained new activity can win after the old evidence decays. */
		soft_llc_decay(&state, 2);
		soft_llc_add(&state, 4, 511);
		soft_llc_refresh(&state, 31, 0);
		assert(state.preferred == 4);
	}
}

int main(void)
{
	test_packed_entries();
	test_slot_limits_and_replacement();
	test_runtime_and_decay();
	test_dynamic_wake_preferences();
	test_fanin_and_fanout();
	test_sparse_homes_and_resize();
	test_aligned_address_seeds();
	test_cached_preferences();
	test_evicted_incumbent_keeps_hysteresis();
	puts("packed LLC history tests passed");
	return 0;
}
