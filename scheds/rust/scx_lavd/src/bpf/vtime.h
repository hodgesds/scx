/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __LAVD_VTIME_H
#define __LAVD_VTIME_H

#include <stdbool.h>
#include "intf.h"

/* Compare within half the virtual-time range, as the kernel DSQ does. */
static __attribute__((always_inline)) inline bool
lavd_vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static __attribute__((always_inline)) inline u64
lavd_vtime_delta(u64 clock, u64 deadline)
{
	u64 delta = deadline - clock;

	return (s64)delta > 0 ? delta : 0;
}

struct dsq_entry {
	u64 dsq_id;
	u64 vtime;
	/* A deadline, including U64_MAX, does not determine eligibility. */
	bool enabled;
};

static __attribute__((always_inline)) inline bool
lavd_dsq_before(const struct dsq_entry *a, const struct dsq_entry *b)
{
	if (a->enabled != b->enabled)
		return a->enabled;
	return lavd_vtime_before(a->vtime, b->vtime);
}

static __attribute__((always_inline)) inline void
lavd_sort_dsqs(struct dsq_entry *a, struct dsq_entry *b, struct dsq_entry *c)
{
	struct dsq_entry t;

	if (lavd_dsq_before(b, a)) { t = *a; *a = *b; *b = t; }
	if (lavd_dsq_before(c, b)) { t = *b; *b = *c; *c = t; }
	if (lavd_dsq_before(b, a)) { t = *a; *a = *b; *b = t; }
}

#endif /* __LAVD_VTIME_H */
