// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub mod stats;
use stats::Metrics;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::import_enums;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Topology;
use scx_utils::UserExitInfo;

const SCHEDULER_NAME: &'static str = "scx_p2dq";

/// scx_p2dq: A pick 2 dumb queuing load balancing scheduler.
///
/// The BPF part does simple vtime or round robin scheduling in each domain
/// while tracking average load of each domain and duty cycle of each task.
///
#[derive(Debug, Parser)]
struct Opts {
    /// Put per-cpu kthreads directly into local dsq's.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    kthreads_local: bool,

    /// If specified, only tasks which have their scheduling policy set to
    /// SCHED_EXT using sched_setscheduler(2) are switched. Otherwise, all
    /// tasks are switched.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    partial: bool,

    /// Scheduling min slice duration in microseconds.
    #[clap(short = 's', long, default_value = "500")]
    min_slice_us: u64,

    /// DSQ scaling shift, each queue min timeslice is shifted by the scaling shift.
    #[clap(short = 'x', long, default_value = "2")]
    dsq_shift: u64,

    /// Number of dumb DSQs.
    #[clap(short = 'q', long, default_value = "3")]
    dumb_queues: usize,

    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Print version and exit.
    #[clap(long)]
    version: bool,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,

    stats_server: StatsServer<(), Metrics>,
    sched_interval: Duration,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 1);
        init_libbpf_logging(None);
        info!(
            "Running scx_p2dq (build ID: {})",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        let mut skel = scx_ops_open!(skel_builder, open_object, p2dq).unwrap();

        let topo = Topology::new()?;

        if opts.partial {
            skel.struct_ops.p2dq_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
        }

        skel.maps.rodata_data.min_slice_us = opts.min_slice_us;
        skel.maps.rodata_data.dsq_shift = opts.dsq_shift as u64;
        skel.maps.rodata_data.kthreads_local = opts.kthreads_local;
        skel.maps.rodata_data.debug = opts.verbose as u32;
        skel.maps.rodata_data.nr_cpus = topo.all_cpus.clone().keys().len() as u32;
        skel.maps.rodata_data.nr_llcs = topo.all_llcs.clone().keys().len() as u32;
        skel.maps.rodata_data.nr_nodes = topo.nodes.clone().keys().len() as u32;
        skel.maps.rodata_data.has_little_cores = topo.has_little_cores();

        let mut skel = scx_ops_load!(skel, p2dq, uei)?;

        let mut cpu_ctxs: Vec<bpf_intf::cpu_ctx> = vec![];
        let cpu_ctxs_vec = skel
            .maps
            .cpu_ctxs
            .lookup_percpu(&0u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY)?
            .unwrap();

        for (cpu_id, cpu_arc) in topo.all_cpus {
            let cpu = cpu_arc.clone();
            cpu_ctxs.push(*unsafe {
                &*(cpu_ctxs_vec[cpu_id].as_slice().as_ptr() as *const bpf_intf::cpu_ctx)
            });
            cpu_ctxs[cpu_id].id = cpu.id as i32;
            cpu_ctxs[cpu_id].node_id = cpu.node_id as u32;
            cpu_ctxs[cpu_id].llc_id = cpu.llc_id as u32;
            cpu_ctxs[cpu_id].is_big = cpu.core_type == CoreType::Big { turbo: true };
        }

        let struct_ops = Some(scx_ops_attach!(skel, p2dq)?);

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        info!("P2DQ scheduler started! Run `scx_p2dq --monitor` for metrics.");

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
            sched_interval: Duration::from_secs_f64(0.5),
        })
    }

    fn get_metrics(&self) -> Metrics {
        Metrics {
            sched_mode: self.skel.maps.bss_data.sched_mode,
        }
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let now = Instant::now();
        let mut next_sched_at = now + self.sched_interval;
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            let now = Instant::now();

            if now >= next_sched_at {
                next_sched_at += self.sched_interval;
                if next_sched_at < now {
                    next_sched_at = now + self.sched_interval;
                }
            }

            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "scx_p2dq: {}",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            match stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
                Ok(_) => {
                    debug!("stats monitor thread finished successfully")
                }
                Err(error_object) => {
                    warn!(
                        "stats monitor thread finished because of an error {}",
                        error_object
                    )
                }
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    Ok(())
}
