// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
//
// scx_atlas - AI Training Latency-Aware Scheduler (prototype). See
// scx_atlas_design.md for the design. Phase 0: minimal shared-DSQ FIFO with the
// config-struct and stats scaffolding in place.

mod stats;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::AsRawLibbpf as _;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::info;
use log::warn;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::cli::TopologyArgs;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;

use scx_atlas::bpf_intf::stat_idx_ATLAS_NR_STATS;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_CLS_LATENCY;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_CLS_PREP;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_CLS_SYSTEM;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_CLS_TRAINING;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_FALLBACK;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_HOME;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_KTHREAD;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_LLC;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_LOCAL;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_MEMPOL;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_PREEMPT;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_SAF;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_STEAL;
use scx_atlas::bpf_intf::stat_idx_ATLAS_STAT_XNUMA_STEAL;
use scx_atlas::bpf_skel::*;
use scx_atlas::SchedulerOpts;

use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_atlas";

/// How often (seconds) userspace recomputes per-tgid soft-affinity home sizes.
const SAF_RESIZE_SECS: u64 = 2;

/// Consecutive idle resize passes before a tgid's home entry is pruned from the
/// map (bounds map growth on hosts with thousands of mostly-idle processes).
const SAF_PRUNE_INTERVALS: u32 = 5;

#[derive(Debug, Parser)]
#[command(
    name = "scx_atlas",
    version,
    disable_version_flag = true,
    about = "AI Training Latency-Aware Scheduler (prototype)."
)]
struct CliOpts {
    /// Enable verbose libbpf/skeleton debug output.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,

    /// Print version and exit.
    #[clap(long)]
    pub version: bool,

    /// Enable stats monitoring with the specified interval (seconds).
    #[clap(long)]
    pub stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval (seconds).
    /// The scheduler is not launched.
    #[clap(long)]
    pub monitor: Option<f64>,

    /// Number of bytes to dump from the BPF exit info on error.
    #[clap(long, default_value = "32768")]
    pub exit_dump_len: u32,

    /// Detect GPU processes via nvidia-driver kprobes. On by default; a no-op on
    /// hosts without the nvidia driver (the kprobes are optional and skipped).
    #[clap(long, default_value = "true", action = clap::ArgAction::Set)]
    pub gpu_probes: bool,

    /// Also detect GPU processes with a userspace /proc poller. Off by default
    /// (the kprobes are the default detector).
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub enable_gpu_poller: bool,

    /// GPU poller interval in seconds (when --enable-gpu-poller is set).
    #[clap(long, default_value = "2")]
    pub gpu_poll_secs: u64,

    /// Account per-CPU IRQ/softirq load from /proc/stat (cheap, off the IRQ hot
    /// path) and avoid piling stolen work on IRQ-saturated CPUs. Off by default.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub irq_accounting: bool,

    /// Periodically resize each process's (tgid) soft-affinity home range from
    /// its recent CPU utilization (saf_resize): a busy process spreads over more
    /// CPUs, an idle one is packed tighter for cache/TLB locality. On by default.
    #[clap(long, default_value = "true", action = clap::ArgAction::Set)]
    pub autosize: bool,

    #[clap(flatten)]
    pub sched: SchedulerOpts,

    #[clap(flatten, next_help_heading = "Topology Options")]
    pub topology: TopologyArgs,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    gpu_poll: Option<Duration>,
    gpu_last_scan: std::time::Instant,
    gpu_tgids: std::collections::HashSet<u32>,
    irq_enabled: bool,
    irq_prev: Vec<(u64, u64)>,
    cgroup_regex: Vec<(regex::Regex, u32)>,
    cgroup_cgids: std::collections::HashSet<u64>,
    autosize: bool,
    nr_llcs: u64,
    saf_prev_runtime: std::collections::HashMap<u32, u64>,
    saf_idle: std::collections::HashMap<u32, u32>,
    saf_last_resize: std::time::Instant,
}

/// Parse per-CPU (irq+softirq, total) jiffies from /proc/stat contents. Index is
/// the CPU id. Pure (no IO) so it can be unit-tested.
fn parse_cpu_irq(content: &str) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for line in content.lines() {
        let mut it = line.split_whitespace();
        let Some(tag) = it.next() else { continue };
        if !tag.starts_with("cpu") || tag == "cpu" {
            continue; // skip non-cpu lines and the aggregate "cpu" line
        }
        let Ok(cpu) = tag[3..].parse::<usize>() else {
            continue;
        };
        let vals: Vec<u64> = it.filter_map(|x| x.parse::<u64>().ok()).collect();
        // user nice system idle iowait irq(5) softirq(6) steal ...
        if vals.len() < 7 {
            continue;
        }
        let total: u64 = vals.iter().sum();
        let irq = vals[5] + vals[6];
        if cpu >= out.len() {
            out.resize(cpu + 1, (0, 0));
        }
        out[cpu] = (irq, total);
    }
    out
}

/// Read per-CPU (irq+softirq, total) jiffies from /proc/stat. The kernel already
/// accounts this, so it's near-free — no per-IRQ cost.
fn read_proc_stat_irq() -> Vec<(u64, u64)> {
    match std::fs::read_to_string("/proc/stat") {
        Ok(content) => parse_cpu_irq(&content),
        Err(_) => Vec::new(),
    }
}

/// Recursively match cgroup directories under @root against regex specs,
/// mapping each match's inode (= cgroup v2 id) to its class. Handles new cgroups
/// since it re-walks live. (Future feature; inert when no patterns are set.)
fn walk_cgroup_regex(
    root: &std::path::Path,
    dir: &std::path::Path,
    specs: &[(regex::Regex, u32)],
    out: &mut std::collections::HashMap<u64, u32>,
) {
    use std::os::unix::fs::MetadataExt;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(md) = e.metadata() else { continue };
        if !md.is_dir() {
            continue;
        }
        let rel = p
            .strip_prefix(root)
            .ok()
            .and_then(|r| r.to_str())
            .unwrap_or("");
        for (re, class) in specs {
            if re.is_match(rel) {
                out.insert(md.ino(), *class);
                break;
            }
        }
        walk_cgroup_regex(root, &p, specs, out);
    }
}

fn scan_cgroup_regex(specs: &[(regex::Regex, u32)]) -> std::collections::HashMap<u64, u32> {
    let mut out = std::collections::HashMap::new();
    if !specs.is_empty() {
        let root = std::path::Path::new("/sys/fs/cgroup");
        walk_cgroup_regex(root, root, specs, &mut out);
    }
    out
}

/// Scan /proc for processes with an open GPU device node. Simple, dependency-free
/// detection; returns the set of GPU-using tgids.
fn scan_gpu_tgids() -> std::collections::HashSet<u32> {
    let mut set = std::collections::HashSet::new();
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return set;
    };
    for ent in proc.flatten() {
        let fname = ent.file_name();
        let Some(pid_s) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = pid_s.parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if let Some(t) = target.to_str() {
                    if t.starts_with("/dev/nvidia") || t.starts_with("/dev/dri/renderD") {
                        set.insert(pid);
                        break;
                    }
                }
            }
        }
    }
    set
}

/// Pure saf_resize LLC allocator. For each soft-affinity group (tgid) it (1)
/// sizes a home from the group's per-interval runtime delta — CPU-equivalents
/// busy (ceil, clamped to the machine) scaled to a whole-LLC count
/// (`ceil(cpus_busy * nr_llcs / nr_cpus)`, clamped to `[1, nr_llcs]`) — and (2)
/// *places* that home on the least-loaded LLCs, tracking a per-LLC load
/// accumulator so homes spread across the machine's caches and overlap evenly
/// when demand exceeds capacity (oversaturation). Shares are uniform here:
/// allocation is purely demand-proportional. Groups are placed heaviest-first
/// (ties by tgid) for determinism; each chosen LLC accrues the group's per-LLC
/// load (its CPU demand spread over the home, in milli-CPUs). Uses only machine
/// totals — no per-LLC size or CPU-id contiguity assumption (BPF maps each LLC to
/// its real CPU set). Returns (tgid, llc_mask) per group; bit i of the mask = LLC
/// i. No IO, so it can be unit-tested.
fn plan_saf_homes(
    groups: &[(u32, u64)],
    interval_ns: u64,
    nr_cpus: u64,
    nr_llcs: u64,
) -> Vec<(u32, u64)> {
    let interval_ns = interval_ns.max(1);
    let nr_cpus = nr_cpus.max(1);
    let nr_llcs = (nr_llcs.max(1)).min(64) as usize;

    // Size each group's home (LLC count) and its per-LLC load contribution.
    let mut reqs: Vec<(u32, usize, u64)> = groups
        .iter()
        .map(|&(tgid, delta)| {
            let cpus_busy = delta.div_ceil(interval_ns).clamp(1, nr_cpus);
            let want = (cpus_busy * nr_llcs as u64)
                .div_ceil(nr_cpus)
                .clamp(1, nr_llcs as u64) as usize;
            // Load this group puts on each home LLC, in milli-CPUs.
            let per_llc_load = (cpus_busy * 1000) / want as u64;
            (tgid, want, per_llc_load)
        })
        .collect();
    reqs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let mut load = vec![0u64; nr_llcs];
    let mut out = Vec::with_capacity(reqs.len());
    for (tgid, want, per_llc_load) in reqs {
        // Choose `want` least-loaded LLCs (ties by lowest index for determinism).
        let mut order: Vec<usize> = (0..nr_llcs).collect();
        order.sort_by(|&i, &j| load[i].cmp(&load[j]).then(i.cmp(&j)));

        let mut mask: u64 = 0;
        for &llc in order.iter().take(want) {
            mask |= 1u64 << llc;
            load[llc] += per_llc_load;
        }
        out.push((tgid, mask));
    }
    out
}

impl<'a> Scheduler<'a> {
    fn init(opts: &CliOpts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        init_libbpf_logging(None);

        info!(
            "Running {} (build ID: {})",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );

        // Build host topology, optionally splitting large LLCs into smaller
        // virtual LLCs (--virt-llc) to reduce per-LLC DSQ lock contention and
        // tighten scheduling/cache-affinity domains. The rest of the scheduler
        // (per-LLC DSQs, masks, the saf allocator) keys on the resulting LLC
        // ids, so virtual LLCs flow through transparently.
        opts.topology.validate()?;
        let topo = Topology::with_args(&opts.topology)?;
        let nr_llcs = topo.all_llcs.len();
        let max_llcs = scx_atlas::bpf_intf::atlas_consts_MAX_LLCS as usize;
        if nr_llcs > max_llcs {
            anyhow::bail!(
                "{} LLCs (after --virt-llc) exceeds MAX_LLCS ({}); widen the \
                 partition range or bump MAX_LLCS in intf.h",
                nr_llcs,
                max_llcs
            );
        }

        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut open_skel = scx_ops_open!(skel_builder, open_object, atlas_ops, open_opts)
            .context("Failed to open BPF object")?;

        open_skel.struct_ops.atlas_ops_mut().exit_dump_len = opts.exit_dump_len;

        scx_atlas::init_open_skel!(&mut open_skel, topo, &opts.sched)?;

        // GPU-detection kprobes: on by default, but only attach where the
        // nvidia driver symbols exist (auto-attach errors otherwise). This makes
        // them the default detector on GPU hosts and a clean no-op elsewhere.
        let nvidia_open = compat::ksym_exists("nvidia_open").unwrap_or(false);
        let nvidia_mmap = compat::ksym_exists("nvidia_mmap").unwrap_or(false);
        open_skel
            .progs
            .atlas_kp_nvidia_open
            .set_autoload(opts.gpu_probes && nvidia_open);
        open_skel
            .progs
            .atlas_kp_nvidia_mmap
            .set_autoload(opts.gpu_probes && nvidia_mmap);
        if opts.gpu_probes && (nvidia_open || nvidia_mmap) {
            info!("GPU detection: nvidia kprobes enabled");
        }

        // We attach the struct_ops manually via scx_ops_attach!(); disable
        // libbpf autoattach so it doesn't warn about the uninitialized link.
        unsafe {
            libbpf_rs::libbpf_sys::bpf_map__set_autoattach(
                open_skel.maps.atlas_ops.as_libbpf_object().as_ptr(),
                false,
            );
        }

        let skel = scx_ops_load!(open_skel, atlas_ops, uei)?;

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        let gpu_poll = if opts.enable_gpu_poller {
            Some(Duration::from_secs(opts.gpu_poll_secs.max(1)))
        } else {
            None
        };

        // cgroup classification (future feature): a regex per class matched
        // against the cgroup path in userspace -> cgroup_class map. Inert when
        // the patterns are empty (the default).
        let mut cgroup_regex: Vec<(regex::Regex, u32)> = Vec::new();
        for (pat, class) in [
            (
                &opts.sched.training_cgroup,
                scx_atlas::bpf_intf::atlas_class_ATLAS_CLASS_TRAINING,
            ),
            (
                &opts.sched.prep_cgroup,
                scx_atlas::bpf_intf::atlas_class_ATLAS_CLASS_PREP,
            ),
        ] {
            if !pat.is_empty() {
                match regex::Regex::new(pat) {
                    Ok(re) => cgroup_regex.push((re, class)),
                    Err(e) => warn!("invalid cgroup regex {:?}: {e}", pat),
                }
            }
        }

        Ok(Self {
            skel,
            struct_ops: None,
            stats_server,
            gpu_poll,
            gpu_last_scan: std::time::Instant::now(),
            gpu_tgids: std::collections::HashSet::new(),
            irq_enabled: opts.irq_accounting,
            irq_prev: Vec::new(),
            cgroup_regex,
            cgroup_cgids: std::collections::HashSet::new(),
            autosize: opts.autosize,
            nr_llcs: topo.all_llcs.len() as u64,
            saf_prev_runtime: std::collections::HashMap::new(),
            saf_idle: std::collections::HashMap::new(),
            saf_last_resize: std::time::Instant::now(),
        })
    }

    /// Refresh the regex cgroup-id -> class map (re-walked live, so new cgroups
    /// are picked up). prefix/suffix/substr matching is done in BPF.
    fn update_cgroup_regex(&mut self) {
        let cur = scan_cgroup_regex(&self.cgroup_regex);
        let map = &self.skel.maps.cgroup_class;
        for (&cgid, &class) in &cur {
            let _ = map.update(
                &cgid.to_ne_bytes(),
                &class.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            );
        }
        for &cgid in &self.cgroup_cgids {
            if !cur.contains_key(&cgid) {
                let _ = map.delete(&cgid.to_ne_bytes());
            }
        }
        self.cgroup_cgids = cur.keys().copied().collect();
    }

    /// Update per-CPU IRQ load (per-mille of the interval) into the cpu_irq_busy
    /// BPF map from /proc/stat deltas. Cheap; runs once per second.
    fn update_irq_load(&mut self) {
        let cur = read_proc_stat_irq();
        if self.irq_prev.len() < cur.len() {
            self.irq_prev.resize(cur.len(), (0, 0));
        }
        let map = &self.skel.maps.cpu_irq_busy;
        for (cpu, &(irq, total)) in cur.iter().enumerate() {
            let (pirq, ptotal) = self.irq_prev[cpu];
            let dt = total.saturating_sub(ptotal);
            let di = irq.saturating_sub(pirq);
            let permille = if dt > 0 {
                ((di.saturating_mul(1000)) / dt) as u32
            } else {
                0
            };
            let _ = map.update(
                &(cpu as u32).to_ne_bytes(),
                &permille.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            );
            self.irq_prev[cpu] = (irq, total);
        }
    }

    /// Refresh the gpu_tgid BPF map from a /proc scan: GPU-using processes are
    /// classified LATENCY by the BPF side. Node is left UNKNOWN for now (a uprobe
    /// can't resolve it either; NVML-based node resolution is a follow-up).
    fn update_gpu_tgids(&mut self) {
        const NODE_UNKNOWN: u32 = u32::MAX;
        let cur = scan_gpu_tgids();
        let map = &self.skel.maps.gpu_tgid;

        for tgid in cur.difference(&self.gpu_tgids) {
            let _ = map.update(
                &tgid.to_ne_bytes(),
                &NODE_UNKNOWN.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            );
        }
        for tgid in self.gpu_tgids.difference(&cur) {
            let _ = map.delete(&tgid.to_ne_bytes());
        }
        if cur.len() != self.gpu_tgids.len() {
            info!("GPU poller: {} GPU process(es)", cur.len());
        }
        self.gpu_tgids = cur;
    }

    /// saf_resize: allocate each *active* tgid's soft-affinity "home" (a set of
    /// LLCs) from its recent CPU utilization. BPF accumulates per-tgid runtime in
    /// the tgid_dom map; here we read each entry, and only tgids that use at least
    /// **one LLC's worth of CPU** over the interval get a sized home (via the
    /// least-loaded LLC allocator) — a process that can't fill an LLC has no need
    /// for a dedicated LLC home. This bounds the working set to the heavy hitters
    /// (the training jobs we care about), not every process on the host (which can
    /// be thousands). Idle tgids get their home cleared, and entries idle for
    /// `SAF_PRUNE_INTERVALS` consecutive passes are deleted to bound map growth
    /// (they're recreated for free if the process runs again).
    fn resize_saf_homes(&mut self) {
        let interval_ns = self.saf_last_resize.elapsed().as_nanos().max(1) as u64;
        self.saf_last_resize = std::time::Instant::now();

        let nr_cpus = (*scx_utils::NR_CPU_IDS).max(1) as u64;
        let nr_llcs = self.nr_llcs.max(1);
        // A tgid must use at least one LLC's worth of CPU over the interval to
        // warrant a sized cache home: cpus_per_llc CPUs fully busy. Smaller
        // processes get no home and fall back to the class soft-affinity domain.
        let cpus_per_llc = (nr_cpus / nr_llcs).max(1);
        let min_home_delta = interval_ns.saturating_mul(cpus_per_llc);
        let map = &self.skel.maps.tgid_dom;

        // Pass 1: read each entry; split into active (gets a home) vs. idle.
        let mut runtimes: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
        let mut active: Vec<(u32, u64)> = Vec::new();
        let mut idle: Vec<(u32, u64)> = Vec::new(); // (tgid, current_llc_mask)
        for key in map.keys() {
            let Ok(tgid_arr): Result<[u8; 4], _> = key.as_slice().try_into() else {
                continue;
            };
            let tgid = u32::from_ne_bytes(tgid_arr);
            let Ok(Some(val)) = map.lookup(&key, libbpf_rs::MapFlags::ANY) else {
                continue;
            };
            if val.len() < 16 {
                continue;
            }
            let runtime = u64::from_ne_bytes(val[0..8].try_into().unwrap());
            let cur_mask = u64::from_ne_bytes(val[8..16].try_into().unwrap());
            let prev = self.saf_prev_runtime.get(&tgid).copied().unwrap_or(runtime);
            let delta = runtime.saturating_sub(prev);
            runtimes.insert(tgid, runtime);
            if delta >= min_home_delta {
                active.push((tgid, delta));
            } else {
                idle.push((tgid, cur_mask));
            }
        }

        // Forget runtime baselines for processes that have exited.
        self.saf_prev_runtime
            .retain(|tgid, _| runtimes.contains_key(tgid));

        // Pass 2: allocate home LLC sets for active tgids, writing back the
        // bitmask while preserving the BPF-owned runtime field.
        for (tgid, llc_mask) in plan_saf_homes(&active, interval_ns, nr_cpus, nr_llcs) {
            self.saf_idle.remove(&tgid);
            let runtime = runtimes.get(&tgid).copied().unwrap_or(0);
            self.saf_prev_runtime.insert(tgid, runtime);

            let mut v = [0u8; 16];
            v[0..8].copy_from_slice(&runtime.to_ne_bytes());
            v[8..16].copy_from_slice(&llc_mask.to_ne_bytes());
            let _ = map.update(&tgid.to_ne_bytes(), &v, libbpf_rs::MapFlags::ANY);
        }

        // Pass 3: idle tgids — clear a stale home immediately, and prune the
        // entry once it's been idle long enough (bounds map size on big hosts).
        for (tgid, cur_mask) in idle {
            let strikes = self.saf_idle.entry(tgid).or_insert(0);
            *strikes += 1;
            if *strikes >= SAF_PRUNE_INTERVALS {
                let _ = map.delete(&tgid.to_ne_bytes());
                self.saf_idle.remove(&tgid);
                self.saf_prev_runtime.remove(&tgid);
            } else if cur_mask != 0 {
                let runtime = runtimes.get(&tgid).copied().unwrap_or(0);
                self.saf_prev_runtime.insert(tgid, runtime);
                let mut v = [0u8; 16];
                v[0..8].copy_from_slice(&runtime.to_ne_bytes());
                // llc_mask = 0 -> no home; hot path falls back to the class domain.
                let _ = map.update(&tgid.to_ne_bytes(), &v, libbpf_rs::MapFlags::ANY);
            }
        }
    }

    fn get_metrics(&self) -> Metrics {
        let mut stats = vec![0u64; stat_idx_ATLAS_NR_STATS as usize];
        let stats_map = &self.skel.maps.stats;
        for stat in 0..stat_idx_ATLAS_NR_STATS {
            let cpu_stat_vec: Vec<Vec<u8>> = stats_map
                .lookup_percpu(&stat.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .unwrap()
                .unwrap_or_default();
            let sum: u64 = cpu_stat_vec
                .iter()
                .map(|val| u64::from_ne_bytes(val.as_slice().try_into().unwrap()))
                .sum();
            stats[stat as usize] = sum;
        }
        Metrics {
            local: stats[stat_idx_ATLAS_STAT_LOCAL as usize],
            saf: stats[stat_idx_ATLAS_STAT_SAF as usize],
            mempol: stats[stat_idx_ATLAS_STAT_MEMPOL as usize],
            home: stats[stat_idx_ATLAS_STAT_HOME as usize],
            llc: stats[stat_idx_ATLAS_STAT_LLC as usize],
            kthread: stats[stat_idx_ATLAS_STAT_KTHREAD as usize],
            fallback: stats[stat_idx_ATLAS_STAT_FALLBACK as usize],
            steal: stats[stat_idx_ATLAS_STAT_STEAL as usize],
            xnuma_steal: stats[stat_idx_ATLAS_STAT_XNUMA_STEAL as usize],
            preempt: stats[stat_idx_ATLAS_STAT_PREEMPT as usize],
            cls_latency: stats[stat_idx_ATLAS_STAT_CLS_LATENCY as usize],
            cls_prep: stats[stat_idx_ATLAS_STAT_CLS_PREP as usize],
            cls_training: stats[stat_idx_ATLAS_STAT_CLS_TRAINING as usize],
            cls_system: stats[stat_idx_ATLAS_STAT_CLS_SYSTEM as usize],
        }
    }

    fn start(&mut self) -> Result<()> {
        // scx_ops_attach! attaches the struct_ops and all non-struct_ops
        // programs (including the set_mempolicy tracepoint).
        self.struct_ops = Some(scx_ops_attach!(self.skel, atlas_ops)?);
        info!("scx_atlas scheduler started! Run `scx_atlas --monitor 1` for metrics.");
        Ok(())
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            if let Some(poll) = self.gpu_poll {
                if self.gpu_last_scan.elapsed() >= poll {
                    self.update_gpu_tgids();
                    self.gpu_last_scan = std::time::Instant::now();
                }
            }
            if self.irq_enabled {
                self.update_irq_load();
            }
            if !self.cgroup_regex.is_empty() {
                self.update_cgroup_regex();
            }
            if self.autosize
                && self.saf_last_resize.elapsed() >= Duration::from_secs(SAF_RESIZE_SECS)
            {
                self.resize_saf_homes();
            }
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

fn main() -> Result<()> {
    let opts = CliOpts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    let llv = if opts.verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Info
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
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
                Ok(_) => {}
                Err(error_object) => {
                    warn!("stats monitor thread finished because of an error {error_object}")
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
        sched.start()?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_irq_basic() {
        // tag, user nice system idle iowait irq softirq steal
        let s = "cpu  1 1 1 1 1 1 1 1\n\
                 cpu0 10 0 5 100 1 2 3 0\n\
                 cpu1 20 0 5 200 1 4 6 0\n\
                 intr 123 4 5\n";
        let v = parse_cpu_irq(s);
        assert_eq!(v.len(), 2);
        // cpu0: irq+softirq = 2+3 = 5; total = 121
        assert_eq!(v[0], (5, 121));
        // cpu1: irq+softirq = 4+6 = 10; total = 236
        assert_eq!(v[1], (10, 236));
    }

    #[test]
    fn parse_cpu_irq_skips_aggregate_and_garbage() {
        let v = parse_cpu_irq("cpu 1 2 3\ngarbage\ncpuX bad\n");
        assert!(v.is_empty());
    }

    #[test]
    fn cgroup_regex_anchors() {
        // prefix via ^, suffix via $, substring unanchored (layered-style kinds).
        let prefix = regex::Regex::new("^workload.slice").unwrap();
        assert!(prefix.is_match("workload.slice/job1"));
        assert!(!prefix.is_match("system.slice/workload.slice"));

        let suffix = regex::Regex::new("job-[0-9]+$").unwrap();
        assert!(suffix.is_match("workload.slice/job-42"));
        assert!(!suffix.is_match("workload.slice/job-42/sub"));

        let substr = regex::Regex::new("dpp_worker").unwrap();
        assert!(substr.is_match("a/dpp_worker-7/b"));
    }

    #[test]
    fn plan_saf_homes_sizes_and_places_least_loaded() {
        let interval = 1_000_000_000u64; // 1s
                                         // 176-CPU, 11-LLC box (16 CPUs/LLC). tgid 3 ~48 CPUs busy -> 3 LLCs;
                                         // tgid 1 ~2 CPUs -> 1 LLC; tgid 2 idle -> 1 LLC.
        let groups = [(1u32, 2 * interval), (2u32, 0), (3u32, 48 * interval)];
        let plan = plan_saf_homes(&groups, interval, 176, 11);

        // Heaviest-first: tgid 3 takes the 3 least-loaded LLCs (0,1,2 -> bits
        // 0b111). The two size-1 groups then land on the next least-loaded LLCs
        // (3, then 4) — disjoint, spread across the machine.
        assert_eq!(plan[0], (3, 0b111));
        assert_eq!(plan[1], (1, 1 << 3));
        assert_eq!(plan[2], (2, 1 << 4));
    }

    #[test]
    fn plan_saf_homes_oversaturation_overlaps_evenly() {
        let interval = 1_000_000_000u64;
        // 32 CPUs / 2 LLCs, two groups each wanting the whole machine.
        let groups = [(10u32, 100 * interval), (11u32, 100 * interval)];
        let plan = plan_saf_homes(&groups, interval, 32, 2);
        // Each clamps to both LLCs; overlap is unavoidable and shared fully.
        assert_eq!(plan[0], (10, 0b11));
        assert_eq!(plan[1], (11, 0b11));
    }

    #[test]
    fn plan_saf_homes_zero_interval_is_safe() {
        // A degenerate (zero) interval must not divide-by-zero: it's clamped to
        // 1ns. 5ns delta -> 5 CPU-equivalents on an 8-CPU/2-LLC box ->
        // ceil(5*2/8) = 2 LLCs -> both bits set.
        let plan = plan_saf_homes(&[(7u32, 5)], 0, 8, 2);
        assert_eq!(plan, vec![(7, 0b11)]);
    }
}
