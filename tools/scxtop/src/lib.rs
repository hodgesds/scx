// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod app;
pub mod bpf_intf;
pub mod bpf_skel;
mod bpf_stats;
pub mod cli;
pub mod config;
mod cpu_data;
mod event_data;
mod keymap;
mod llc_data;
mod node_data;
mod perf_event;
mod perfetto_trace;
pub mod protos;
mod stats;
mod theme;
mod tui;
mod util;

pub use app::App;
pub use bpf_skel::*;
pub use cpu_data::CpuData;
pub use event_data::EventData;
pub use keymap::Key;
pub use keymap::KeyMap;
pub use llc_data::LlcData;
pub use node_data::NodeData;
pub use perf_event::available_perf_events;
pub use perf_event::PerfEvent;
pub use perfetto_trace::PerfettoTraceManager;
pub use protos::*;
pub use stats::StatAggregation;
pub use stats::VecStats;
pub use theme::AppTheme;
pub use tui::Event;
pub use tui::Tui;
pub use util::format_hz;
pub use util::read_file_string;

pub use plain::Plain;
// Generate serialization types for handling events from the bpf ring buffer.
unsafe impl Plain for crate::bpf_skel::types::bpf_event {}

pub const APP: &str = "scxtop";
pub const TRACE_FILE_PREFIX: &str = "scxtop_trace";
pub const STATS_SOCKET_PATH: &str = "/var/run/scx/root/stats";
pub const LICENSE: &str = "Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the 
GNU General Public License version 2.";
pub const SCHED_NAME_PATH: &str = "/sys/kernel/sched_ext/root/ops";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AppState {
    /// Application is in the default state.
    Default,
    /// Application is in the event state.
    Event,
    /// Application is in the help state.
    Help,
    /// Application is in the Llc state.
    Llc,
    /// Application is in the NUMA node state.
    Node,
    /// Application is in the scheduler state.
    Scheduler,
    /// Application is in the tracing  state.
    Tracing,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ViewState {
    Sparkline,
    BarChart,
}

impl ViewState {
    /// Returns the next ViewState.
    pub fn next(&self) -> Self {
        match self {
            ViewState::Sparkline => ViewState::BarChart,
            ViewState::BarChart => ViewState::Sparkline,
        }
    }
}

impl std::fmt::Display for ViewState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ViewState::Sparkline => write!(f, "sparkline"),
            ViewState::BarChart => write!(f, "barchart"),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedCpuPerfSetAction {
    pub cpu: u32,
    pub perf: u32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedSwitchAction {
    pub ts: u64,
    pub cpu: u32,
    pub preempt: bool,
    pub next_dsq_id: u64,
    pub next_dsq_lat_us: u64,
    pub next_dsq_nr_queued: u32,
    pub next_dsq_vtime: u64,
    pub next_slice_ns: u64,
    pub next_pid: u32,
    pub next_tgid: u32,
    pub next_prio: i32,
    pub next_comm: String,
    pub prev_dsq_id: u64,
    pub prev_used_slice_ns: u64,
    pub prev_slice_ns: u64,
    pub prev_pid: u32,
    pub prev_tgid: u32,
    pub prev_prio: i32,
    pub prev_comm: String,
    pub prev_state: u64,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedWakeActionCtx {
    pub ts: u64,
    pub cpu: u32,
    pub pid: u32,
    pub prio: i32,
    pub comm: String,
}

pub type SchedWakeupNewAction = SchedWakeActionCtx;
pub type SchedWakingAction = SchedWakeActionCtx;
pub type SchedWakeupAction = SchedWakeActionCtx;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SoftIRQAction {
    pub cpu: u32,
    pub pid: u32,
    pub entry_ts: u64,
    pub exit_ts: u64,
    pub softirq_nr: usize,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordTraceAction {
    pub immediate: bool,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IPIAction {
    pub ts: u64,
    pub cpu: u32,
    pub target_cpu: u32,
    pub pid: u32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Action {
    ChangeTheme,
    ClearEvent,
    DecBpfSampleRate,
    DecTickRate,
    Down,
    Enter,
    Event,
    Help,
    IncBpfSampleRate,
    IncTickRate,
    IPI(IPIAction),
    NextEvent,
    NextViewState,
    PageDown,
    PageUp,
    PrevEvent,
    Quit,
    RecordTrace(RecordTraceAction),
    ReloadStatsClient,
    Render,
    SaveConfig,
    SchedCpuPerfSet(SchedCpuPerfSetAction),
    SchedReg,
    SchedStats(String),
    SchedSwitch(SchedSwitchAction),
    SchedUnreg,
    SchedWakeupNew(SchedWakeupNewAction),
    SchedWakeup(SchedWakeupAction),
    SchedWaking(SchedWakingAction),
    SetState(AppState),
    SoftIRQ(SoftIRQAction),
    Tick,
    TickRateChange(std::time::Duration),
    ToggleCpuFreq,
    ToggleLocalization,
    ToggleUncoreFreq,
    Up,
    None,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Action::SetState(AppState::Default) => write!(f, "AppStateDefault"),
            Action::SetState(AppState::Event) => write!(f, "AppStateEvent"),
            Action::ToggleCpuFreq => write!(f, "ToggleCpuFreq"),
            Action::ToggleUncoreFreq => write!(f, "ToggleUncoreFreq"),
            Action::ToggleLocalization => write!(f, "ToggleLocalization"),
            Action::SetState(AppState::Help) => write!(f, "AppStateHelp"),
            Action::SetState(AppState::Llc) => write!(f, "AppStateLlc"),
            Action::SetState(AppState::Node) => write!(f, "AppStateNode"),
            Action::SetState(AppState::Scheduler) => write!(f, "AppStateScheduler"),
            Action::SaveConfig => write!(f, "SaveConfig"),
            Action::RecordTrace(RecordTraceAction { immediate: false }) => write!(f, "RecordTrace"),
            Action::RecordTrace(RecordTraceAction { immediate: true }) => {
                write!(f, "RecordTraceNow")
            }
            Action::ClearEvent => write!(f, "ClearEvent"),
            Action::PrevEvent => write!(f, "PrevEvent"),
            Action::NextEvent => write!(f, "NextEvent"),
            Action::Quit => write!(f, "Quit"),
            Action::ChangeTheme => write!(f, "ChangeTheme"),
            Action::DecTickRate => write!(f, "DecTickRate"),
            Action::IncTickRate => write!(f, "IncTickRate"),
            Action::DecBpfSampleRate => write!(f, "DecBpfSampleRate"),
            Action::IncBpfSampleRate => write!(f, "IncBpfSampleRate"),
            Action::NextViewState => write!(f, "NextViewState"),
            Action::Down => write!(f, "Down"),
            Action::Up => write!(f, "Up"),
            Action::PageDown => write!(f, "PageDown"),
            Action::PageUp => write!(f, "PageUp"),
            Action::Enter => write!(f, "Enter"),
            _ => write!(f, "{:?}", self),
        }
    }
}
