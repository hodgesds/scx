/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

enum timer_consts {
	// kernel definitions
	CLOCK_BOOTTIME		= 7,
	// Increment when adding a timer
	MAX_TIMERS		= 1,
};

struct layered_timer {
	bool (*cb)(void);

	// if set to 0 the timer will only be scheduled once
	int interval_ns;
	u64 init_flags;
	u64 start_flags;
};

// Runs a timer once.
bool noop_timer(void) {
	return false;
}

struct layered_timer layered_timers[MAX_TIMERS] = {
	{noop_timer, 0, CLOCK_BOOTTIME, 0},
};
