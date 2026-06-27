// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Tasks dispatched directly to an idle local CPU")]
    pub local: u64,
    #[stat(desc = "Idle CPU chosen via a soft-affinity domain")]
    pub saf: u64,
    #[stat(desc = "Tasks enqueued to their per-LLC DSQ")]
    pub llc: u64,
    #[stat(desc = "Per-CPU kthreads kept local")]
    pub kthread: u64,
    #[stat(desc = "Tasks routed to LLC 0 due to unknown CPU/LLC")]
    pub fallback: u64,
    #[stat(desc = "Pick-2 steal within the local NUMA node")]
    pub steal: u64,
    #[stat(desc = "Cross-NUMA steal of a non-recently-migrated task")]
    pub xnuma_steal: u64,
    #[stat(desc = "LATENCY task preempted a lower-class task")]
    pub preempt: u64,
    #[stat(desc = "Idle CPU chosen on the task's mempolicy node")]
    pub mempol: u64,
    #[stat(desc = "Idle CPU chosen within the per-tgid home range (saf_resize)")]
    pub home: u64,
    #[stat(desc = "Enqueues classified LATENCY")]
    pub cls_latency: u64,
    #[stat(desc = "Enqueues classified PREP")]
    pub cls_prep: u64,
    #[stat(desc = "Enqueues classified TRAINING")]
    pub cls_training: u64,
    #[stat(desc = "Enqueues classified SYSTEM")]
    pub cls_system: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "local/home/saf/mempol/llc/kthread/fallback/steal/xnuma {}/{}/{}/{}/{}/{}/{}/{}/{}",
            self.local,
            self.home,
            self.saf,
            self.mempol,
            self.llc,
            self.kthread,
            self.fallback,
            self.steal,
            self.xnuma_steal,
        )?;
        if self.preempt > 0 {
            writeln!(w, "\tlatency preempts {}", self.preempt)?;
        }
        writeln!(
            w,
            "\tclass lat/prep/train/sys {}/{}/{}/{}",
            self.cls_latency, self.cls_prep, self.cls_training, self.cls_system,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            local: self.local.saturating_sub(rhs.local),
            saf: self.saf.saturating_sub(rhs.saf),
            llc: self.llc.saturating_sub(rhs.llc),
            kthread: self.kthread.saturating_sub(rhs.kthread),
            fallback: self.fallback.saturating_sub(rhs.fallback),
            steal: self.steal.saturating_sub(rhs.steal),
            xnuma_steal: self.xnuma_steal.saturating_sub(rhs.xnuma_steal),
            preempt: self.preempt.saturating_sub(rhs.preempt),
            mempol: self.mempol.saturating_sub(rhs.mempol),
            home: self.home.saturating_sub(rhs.home),
            cls_latency: self.cls_latency.saturating_sub(rhs.cls_latency),
            cls_prep: self.cls_prep.saturating_sub(rhs.cls_prep),
            cls_training: self.cls_training.saturating_sub(rhs.cls_training),
            cls_system: self.cls_system.saturating_sub(rhs.cls_system),
        }
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
