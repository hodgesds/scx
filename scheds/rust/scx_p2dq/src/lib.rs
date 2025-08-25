// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
pub mod bpf_intf;
pub mod bpf_skel;
pub use bpf_skel::types;

pub use scx_utils::CoreType;
use scx_utils::Topology;
pub use scx_utils::NR_CPU_IDS;

use clap::Parser;
use clap::ValueEnum;

lazy_static::lazy_static! {
        pub static ref TOPO: Topology = Topology::new().unwrap();
}

fn get_default_greedy_disable() -> bool {
    TOPO.all_llcs.len() > 1
}

fn get_default_llc_runs() -> u64 {
    let n_llcs = TOPO.all_llcs.len() as f64;
    let llc_runs = n_llcs.log2();
    llc_runs as u64
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum LbMode {
    /// load of the LLC
    Load,
    /// number of tasks queued
    NrQueued,
}

impl LbMode {
    pub fn as_i32(&self) -> i32 {
        match self {
            LbMode::Load => bpf_intf::p2dq_lb_mode_PICK2_LOAD as i32,
            LbMode::NrQueued => bpf_intf::p2dq_lb_mode_PICK2_NR_QUEUED as i32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum SchedMode {
    /// Default mode for most workloads.
    Default,
    /// Performance mode prioritizes scheduling on Big cores.
    Performance,
    /// Efficiency mode prioritizes scheduling on little cores.
    Efficiency,
}

impl SchedMode {
    pub fn as_i32(&self) -> i32 {
        match self {
            SchedMode::Default => bpf_intf::scheduler_mode_MODE_DEFAULT as i32,
            SchedMode::Performance => bpf_intf::scheduler_mode_MODE_PERF as i32,
            SchedMode::Efficiency => bpf_intf::scheduler_mode_MODE_EFFICIENCY as i32,
        }
    }
}

#[derive(Debug, Parser)]
pub struct SchedulerOpts {
    /// Disables per-cpu kthreads directly dispatched into local dsqs.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    pub disable_kthreads_local: bool,

    /// Enables autoslice tuning
    #[clap(short = 'a', long, action = clap::ArgAction::SetTrue)]
    pub autoslice: bool,

    /// Ratio of interactive tasks for autoslice tuning, percent value from 1-99.
    #[clap(short = 'r', long, default_value = "10")]
    pub interactive_ratio: usize,

    /// Enables deadline scheduling
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub deadline: bool,

    /// ***DEPRECATED*** Disables eager pick2 load balancing.
    #[clap(short = 'e', long, help="DEPRECATED", action = clap::ArgAction::SetTrue)]
    pub eager_load_balance: bool,

    /// Enables CPU frequency control.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    pub freq_control: bool,

    /// ***DEPRECATED*** Disables greedy idle CPU selection, may cause better load balancing on
    /// multi-LLC systems.
    #[clap(short = 'g', long, default_value_t = get_default_greedy_disable(), action = clap::ArgAction::Set)]
    pub greedy_idle_disable: bool,

    /// Interactive tasks stay sticky to their CPU if no idle CPU is found.
    #[clap(short = 'y', long, action = clap::ArgAction::SetTrue)]
    pub interactive_sticky: bool,

    /// ***DEPRECATED*** Interactive tasks are FIFO scheduled
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub interactive_fifo: bool,

    /// Disables pick2 load balancing on the dispatch path.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    pub dispatch_pick2_disable: bool,

    /// Enables pick2 load balancing on the dispatch path when LLC utilization is under the
    /// specified utilization.
    #[clap(long, default_value = "75", value_parser = clap::value_parser!(u64).range(0..100))]
    pub dispatch_lb_busy: u64,

    /// Enables pick2 load balancing on the dispatch path for interactive tasks.
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub dispatch_lb_interactive: bool,

    /// Enable tasks to run beyond their timeslice if the CPU is idle.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub keep_running: bool,

    /// Use a arena based queues (ATQ) for task queueing.
    #[clap(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub atq_enabled: bool,

    /// Schedule based on preferred core values available on some x86 systems with the appropriate
    /// CPU frequency governor (ex: amd-pstate).
    #[clap(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub cpu_priority: bool,

    /// ***DEPRECATED*** Use a separate DSQ for interactive tasks
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub interactive_dsq: bool,

    /// *DEPRECATED* Minimum load for load balancing on the wakeup path, 0 to disable.
    #[clap(long, default_value = "0", help="DEPRECATED", value_parser = clap::value_parser!(u64).range(0..99))]
    pub wakeup_lb_busy: u64,

    /// Allow LLC migrations on the wakeup path.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub wakeup_llc_migrations: bool,

    /// Allow selecting idle in enqueue path.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub select_idle_in_enqueue: bool,

    /// Enables soft affinity to keep groups of tasks sticky
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub soft_affinity: bool,

    /// Allow queued wakeup.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub queued_wakeup: bool,

    /// Set idle QoS resume latency based in microseconds.
    #[clap(long)]
    pub idle_resume_us: Option<u32>,

    /// Only pick2 load balance from the max DSQ.
    #[clap(long, default_value="false", action = clap::ArgAction::Set)]
    pub max_dsq_pick2: bool,

    /// Task slice tracking, slices are automatically scaled based on utilization rather than the
    /// predetermined slice index.
    #[clap(long, default_value="false", action = clap::ArgAction::Set)]
    pub task_slice: bool,

    /// Scheduling min slice duration in microseconds.
    #[clap(short = 's', long, default_value = "100")]
    pub min_slice_us: u64,

    /// ***DEPRECATED*** Load balance mode
    #[arg(value_enum, long, default_value_t = LbMode::Load)]
    pub lb_mode: LbMode,

    /// Scheduler mode
    #[arg(value_enum, long, default_value_t = SchedMode::Default)]
    pub sched_mode: SchedMode,

    /// Slack factor for load balancing, load balancing is not performed if load is within slack
    /// factor percent.
    #[clap(long, default_value = "5", value_parser = clap::value_parser!(u64).range(0..99))]
    pub lb_slack_factor: u64,

    /// ***DEPRECATED** Number of runs on the LLC before a task becomes eligbile for pick2 migration on the wakeup
    /// path.
    #[clap(short = 'l', long, default_value_t = get_default_llc_runs())]
    pub min_llc_runs_pick2: u64,

    /// Saturated percent is the percent at which the system is considered saturated in terms of
    /// free CPUs.
    #[clap(long, default_value_t = 5)]
    pub saturated_percent: u32,

    /// Manual definition of slice intervals in microseconds for DSQs, must be equal to number of
    /// dumb_queues.
    #[clap(short = 't', long, value_parser = clap::value_parser!(u64), default_values_t = [0;0])]
    pub dsq_time_slices: Vec<u64>,

    /// DSQ scaling shift, each queue min timeslice is shifted by the scaling shift.
    #[clap(short = 'x', long, default_value = "4")]
    pub dsq_shift: u64,

    /// Minimum number of queued tasks to use pick2 balancing, 0 to always enabled.
    #[clap(short = 'm', long, default_value = "0")]
    pub min_nr_queued_pick2: u64,

    /// Number of dumb DSQs.
    #[clap(short = 'q', long, default_value = "3")]
    pub dumb_queues: usize,

    /// Initial DSQ for tasks.
    #[clap(short = 'i', long, default_value = "0")]
    pub init_dsq_index: usize,
}

pub fn dsq_slice_ns(dsq_index: u64, min_slice_us: u64, dsq_shift: u64) -> u64 {
    if dsq_index == 0 {
        1000 * min_slice_us
    } else {
        1000 * (min_slice_us << (dsq_index as u32) << dsq_shift)
    }
}

#[macro_export]
macro_rules! init_open_skel {
    ($skel: expr, $opts: expr, $verbose: expr) => {
        'block: {
            let skel = $skel;
            let opts: &$crate::SchedulerOpts = $opts;
            let verbose: u8 = $verbose;

            if opts.init_dsq_index > opts.dumb_queues - 1 {
                break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                    "Invalid init_dsq_index {}",
                    opts.init_dsq_index
                ));
            }
            if opts.dsq_time_slices.len() > 0 {
                if opts.dsq_time_slices.len() != opts.dumb_queues {
                    break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                        "Invalid number of dsq_time_slices, got {} need {}",
                        opts.dsq_time_slices.len(),
                        opts.dumb_queues,
                    ));
                }
                for vals in opts.dsq_time_slices.windows(2) {
                    if vals[0] >= vals[1] {
                        break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                            "DSQ time slices must be in increasing order"
                        ));
                    }
                }
                for (i, slice) in opts.dsq_time_slices.iter().enumerate() {
                    ::log::info!("DSQ[{}] slice_ns {}", i, slice * 1000);
                    skel.maps.bss_data.as_mut().unwrap().dsq_time_slices[i] = slice * 1000;
                }
            } else {
                for i in 0..=opts.dumb_queues - 1 {
                    let slice_ns =
                        $crate::dsq_slice_ns(i as u64, opts.min_slice_us, opts.dsq_shift);
                    ::log::info!("DSQ[{}] slice_ns {}", i, slice_ns);
                    skel.maps.bss_data.as_mut().unwrap().dsq_time_slices[i] = slice_ns;
                }
            }
            if opts.autoslice {
                if opts.interactive_ratio == 0 || opts.interactive_ratio > 99 {
                    break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                        "Invalid interactive_ratio {}, must be between 1-99",
                        opts.interactive_ratio
                    ));
                }
            }

            // topo config
            let rodata = skel.maps.rodata_data.as_mut().unwrap();
            rodata.topo_config.nr_cpus = *$crate::NR_CPU_IDS as u32;
            rodata.topo_config.nr_llcs = $crate::TOPO.all_llcs.clone().keys().len() as u32;
            rodata.topo_config.nr_nodes = $crate::TOPO.nodes.clone().keys().len() as u32;
            rodata.topo_config.smt_enabled = MaybeUninit::new($crate::TOPO.smt_enabled);
            rodata.topo_config.has_little_cores = MaybeUninit::new($crate::TOPO.has_little_cores());

            // timeline config
            rodata.timeline_config.min_slice_us = opts.min_slice_us;
            rodata.timeline_config.max_exec_ns =
                2 * skel.maps.bss_data.as_ref().unwrap().dsq_time_slices[opts.dumb_queues - 1];
            rodata.timeline_config.autoslice = MaybeUninit::new(opts.autoslice);
            rodata.timeline_config.deadline = MaybeUninit::new(opts.deadline);

            // load balance config
            rodata.lb_config.slack_factor = opts.lb_slack_factor;
            rodata.lb_config.min_nr_queued_pick2 = opts.min_nr_queued_pick2;
            rodata.lb_config.max_dsq_pick2 = MaybeUninit::new(opts.max_dsq_pick2);
            rodata.lb_config.eager_load_balance = MaybeUninit::new(!opts.eager_load_balance);
            rodata.lb_config.dispatch_pick2_disable = MaybeUninit::new(opts.dispatch_pick2_disable);
            rodata.lb_config.dispatch_lb_busy = opts.dispatch_lb_busy;
            rodata.lb_config.dispatch_lb_interactive =
                MaybeUninit::new(opts.dispatch_lb_interactive);
            rodata.lb_config.wakeup_lb_busy = opts.wakeup_lb_busy;
            rodata.lb_config.wakeup_llc_migrations = MaybeUninit::new(opts.wakeup_llc_migrations);

            // p2dq config
            rodata.p2dq_config.interactive_ratio = opts.interactive_ratio as u32;
            rodata.p2dq_config.dsq_shift = opts.dsq_shift as u64;
            rodata.p2dq_config.task_slice = MaybeUninit::new(opts.task_slice);
            rodata.p2dq_config.kthreads_local = MaybeUninit::new(!opts.disable_kthreads_local);
            rodata.p2dq_config.nr_dsqs_per_llc = opts.dumb_queues as u32;
            rodata.p2dq_config.init_dsq_index = opts.init_dsq_index as i32;
            rodata.p2dq_config.saturated_percent = opts.saturated_percent;
            rodata.p2dq_config.sched_mode = opts.sched_mode.clone() as u32;
            rodata.p2dq_config.soft_affinity = MaybeUninit::new(opts.soft_affinity);

            rodata.p2dq_config.atq_enabled = MaybeUninit::new(
                opts.atq_enabled && compat::ksym_exists("bpf_spin_unlock").unwrap_or(false),
            );
            rodata.p2dq_config.cpu_priority = MaybeUninit::new(opts.cpu_priority);
            rodata.p2dq_config.freq_control = MaybeUninit::new(opts.freq_control);
            rodata.p2dq_config.interactive_sticky = MaybeUninit::new(opts.interactive_sticky);
            rodata.p2dq_config.keep_running_enabled = MaybeUninit::new(opts.keep_running);
            rodata.p2dq_config.select_idle_in_enqueue =
                MaybeUninit::new(opts.select_idle_in_enqueue);

            rodata.debug = verbose as u32;
            rodata.nr_cpu_ids = *NR_CPU_IDS as u32;

            Ok(())
        }
    };
}

#[macro_export]
macro_rules! init_skel {
    ($skel: expr) => {
        for cpu in $crate::TOPO.all_cpus.values() {
            $skel.maps.bss_data.as_mut().unwrap().big_core_ids[cpu.id] =
                if cpu.core_type == ($crate::CoreType::Big { turbo: true }) {
                    1
                } else {
                    0
                };
            $skel.maps.bss_data.as_mut().unwrap().cpu_llc_ids[cpu.id] = cpu.llc_id as u64;
            $skel.maps.bss_data.as_mut().unwrap().cpu_node_ids[cpu.id] = cpu.node_id as u64;
        }
        for llc in $crate::TOPO.all_llcs.values() {
            $skel.maps.bss_data.as_mut().unwrap().llc_ids[llc.id] = llc.id as u64;
        }
    };
}
