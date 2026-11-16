/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <assert.h>
#include <stdio.h>
#include "../src/bpf/vtime.h"

#define MAX_VTIME (~0ULL)

static void test_clock_wrap(void)
{
	/* An earlier wrapped deadline must not send a small clock to U64_MAX. */
	assert(lavd_vtime_delta(100, MAX_VTIME) == 0);
	assert(lavd_vtime_delta(100, 100) == 0);
	assert(lavd_vtime_delta(100, 99) == 0);
	assert(lavd_vtime_delta(100, 104) == 4);
	/* A clock at the upper boundary can advance into the low range. */
	assert(lavd_vtime_delta(MAX_VTIME - 2, 1) == 4);
	assert((MAX_VTIME - 2) + lavd_vtime_delta(MAX_VTIME - 2, 1) == 1);
}

static void test_enabled_queue_at_max_vtime(void)
{
	struct dsq_entry a = { .dsq_id = 1, .vtime = 3, .enabled = true };
	struct dsq_entry b = { .dsq_id = 2, .vtime = MAX_VTIME, .enabled = true };
	struct dsq_entry c = { .dsq_id = 3, .vtime = 0, .enabled = false };

	lavd_sort_dsqs(&a, &b, &c);
	/* The queue at U64_MAX remains eligible and precedes post-wrap work. */
	assert(a.dsq_id == 2 && a.enabled && a.vtime == MAX_VTIME);
	assert(b.dsq_id == 1 && b.enabled);
	assert(c.dsq_id == 3 && !c.enabled);
}

static void test_ordering_and_ties(void)
{
	struct dsq_entry a = { .dsq_id = 1, .vtime = 30, .enabled = true };
	struct dsq_entry b = { .dsq_id = 2, .vtime = 10, .enabled = true };
	struct dsq_entry c = { .dsq_id = 3, .vtime = 20, .enabled = true };

	lavd_sort_dsqs(&a, &b, &c);
	assert(a.dsq_id == 2 && b.dsq_id == 3 && c.dsq_id == 1);
	b.vtime = a.vtime;
	lavd_sort_dsqs(&a, &b, &c);
	assert(a.dsq_id == 2 && b.dsq_id == 3 && c.dsq_id == 1);
}

int main(void)
{
	test_clock_wrap();
	test_enabled_queue_at_max_vtime();
	test_ordering_and_ties();
	puts("virtual-time regression tests passed");
	return 0;
}
