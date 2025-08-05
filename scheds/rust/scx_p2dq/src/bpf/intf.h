// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __P2DQ_INTF_H
#define __P2DQ_INTF_H

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int s32;
#endif

enum consts {
  MAX_CPUS = 512,
  MAX_NUMA_NODES = 64,
  MAX_LLCS = 64,
  MAX_DSQS_PER_LLC = 8,
  MAX_TASK_PRIO = 39,
  MAX_TOPO_NODES = 1024,

  NSEC_PER_USEC = 1000ULL,
  NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
  MSEC_PER_SEC = 1000ULL,
  NSEC_PER_SEC = NSEC_PER_MSEC * MSEC_PER_SEC,

  MIN_SLICE_USEC = 10ULL,
  MIN_SLICE_NSEC = (10ULL * NSEC_PER_USEC),

  LOAD_BALANCE_SLACK = 20ULL,

  P2DQ_MIG_DSQ = 1LLU << 60,
  P2DQ_INTR_DSQ = 1LLU << 32,

  // kernel definitions
  CLOCK_BOOTTIME = 7,

  STATIC_ALLOC_PAGES_GRANULARITY = 8,
};

enum p2dq_timers_defs {
  EAGER_LOAD_BALANCER_TMR,
  MAX_TIMERS,
};

enum p2dq_lb_mode {
  PICK2_LOAD,
  PICK2_NR_QUEUED,
};

enum stat_idx {
  P2DQ_STAT_DIRECT,
  P2DQ_STAT_IDLE,
  P2DQ_STAT_KEEP,
  P2DQ_STAT_DSQ_CHANGE,
  P2DQ_STAT_DSQ_SAME,
  P2DQ_STAT_ENQ_CPU,
  P2DQ_STAT_ENQ_INTR,
  P2DQ_STAT_ENQ_LLC,
  P2DQ_STAT_ENQ_MIG,
  P2DQ_STAT_SELECT_PICK2,
  P2DQ_STAT_DISPATCH_PICK2,
  P2DQ_STAT_LLC_MIGRATION,
  P2DQ_STAT_NODE_MIGRATION,
  P2DQ_STAT_WAKE_PREV,
  P2DQ_STAT_WAKE_LLC,
  P2DQ_STAT_WAKE_MIG,
  P2DQ_STAT_ATQ_ENQ,
  P2DQ_STAT_ATQ_REENQ,
  P2DQ_NR_STATS,
};

// Arguments for the update_cpu_topology BPF program
struct update_cpu_topology_args {
  int cpu_id;
  u32 core_id;
  u32 package_id;
  s32 cluster_id;
  u32 smt_level;
  u32 cpu_capacity;
  u32 l2_id;
  u32 l3_id;
  u32 cache_size;
  u32 min_freq;
  u32 max_freq;
  u32 base_freq;
  u32 pm_qos_resume_latency_us;
  u32 trans_lat_ns;
};

// Arguments for the update_llc_topology BPF program
struct update_llc_topology_args {
  u32 llc_id;
  u32 kernel_id;
  u32 cache_level;
  u32 cache_size;
  u32 cache_line_size;
  u32 ways_of_associativity;
  u32 physical_line_partition;
  u32 coherency_line_size;
  u32 nr_cores;
  u32 nr_siblings;
};

// Arguments for the update_node_topology BPF program
struct update_node_topology_args {
  u32 node_id;
  u32 nr_nodes;
  u32 distance[MAX_NUMA_NODES];
};

enum scheduler_mode {
  MODE_PERFORMANCE,
};

#endif /* __P2DQ_INTF_H */
