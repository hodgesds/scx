// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
#endif

enum event_type {
	CPU_PERF_SET,
	SCHED_LOAD,
	SCHED_UNLOAD,
	EVENT_MAX,
};

struct bpf_event {
	int	type;
	u32	cpu;
	u32	perf;
};

#endif /* __INTF_H */
