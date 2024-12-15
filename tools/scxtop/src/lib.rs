// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod app;
pub mod bpf_intf;
pub mod bpf_skel;
mod cpudata;
mod perf_event;
mod stats;
mod tui;
mod util;

pub use app::App;
pub use app::AppState;
pub use bpf_skel::types::*;
pub use bpf_skel::*;
pub use cpudata::CpuData;
pub use perf_event::available_perf_events;
pub use perf_event::PerfEvent;
pub use stats::avg;
pub use stats::percentile;
pub use tui::Event;
pub use tui::Tui;
pub use util::read_file_string;

pub use plain::Plain;
// Generate serialization types for handling events from the bpf ring buffer.
unsafe impl Plain for crate::bpf_skel::types::bpf_event {}

pub const APP: &'static str = "scxtop";
pub const LICENSE: &'static str = "Copyright (c) Meta Platforms, Inc. and affiliates. 

This software may be used and distributed according to the terms of the 
GNU General Public License version 2.";
pub const SCHED_NAME_PATH: &'static str = "/sys/kernel/sched_ext/root/ops";

#[derive(Clone)]
pub enum Action {
    Tick,
    Increment,
    Decrement,
    NetworkRequestAndThenIncrement, // new
    NetworkRequestAndThenDecrement, // new
    Quit,
    Help,
    Event,
    ClearEvent,
    NextEvent,
    PrevEvent,
    ChangeTheme,
    Up,
    Down,
    Render,
    SchedLoad,
    SchedUnload,
    SchedCpuPerfSet { cpu: u32, perf: u32 },
    DecTickRate,
    IncTickRate,
    None,
}

#[derive(Clone)]
pub enum StatAggregation {
    Sum,
    Avg,
    Min,
    Max,
    P99,
    P95,
    P90,
    P75,
    P50,
    P25,
    P5,
}
