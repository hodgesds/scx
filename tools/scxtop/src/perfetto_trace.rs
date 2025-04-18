// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use protobuf::Message;
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use scx_utils::scx_enums;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::edm::ActionHandler;
use crate::{
    Action, CpuhpEnterAction, CpuhpExitAction, ExecAction, ExitAction, ForkAction, GpuMemAction,
    IPIAction, SchedSwitchAction, SchedWakeupAction, SchedWakingAction, SoftIRQAction,
};

use crate::protos_gen::perfetto_scx::clock_snapshot::Clock;
use crate::protos_gen::perfetto_scx::counter_descriptor::Unit::UNIT_COUNT;
use crate::protos_gen::perfetto_scx::trace_packet::Data::TrackDescriptor as DataTrackDescriptor;
use crate::protos_gen::perfetto_scx::track_event::Type as TrackEventType;
use crate::protos_gen::perfetto_scx::{
    BuiltinClock, ClockSnapshot, CounterDescriptor, CpuhpEnterFtraceEvent, CpuhpExitFtraceEvent,
    FtraceEvent, FtraceEventBundle, GpuMemTotalFtraceEvent, IpiRaiseFtraceEvent, ProcessDescriptor,
    SchedProcessExecFtraceEvent, SchedProcessExitFtraceEvent, SchedProcessForkFtraceEvent,
    SchedSwitchFtraceEvent, SchedWakeupFtraceEvent, SchedWakingFtraceEvent,
    SoftirqEntryFtraceEvent, SoftirqExitFtraceEvent, ThreadDescriptor, Trace, TracePacket,
    TrackDescriptor, TrackEvent,
};

/// Handler for perfetto traces. For details on data flow in perfetto see:
/// https://perfetto.dev/docs/concepts/buffers and
/// https://perfetto.dev/docs/reference/trace-packet-proto
pub struct PerfettoTraceManager {
    // proto fields
    trace: Trace,

    trace_id: u32,
    trusted_pid: i32,
    rng: StdRng,
    output_file_prefix: String,

    // per cpu ftrace events
    ftrace_events: BTreeMap<u32, Vec<FtraceEvent>>,
    dsq_lat_events: BTreeMap<u64, Vec<TrackEvent>>,
    dsq_lat_trusted_packet_seq_uuid: u32,
    dsq_nr_queued_events: BTreeMap<u64, Vec<TrackEvent>>,
    dsq_nr_queued_trusted_packet_seq_uuid: u32,
    dsq_uuids: BTreeMap<u64, u64>,
    processes: HashMap<u64, ProcessDescriptor>,
    threads: HashMap<u64, ThreadDescriptor>,
    process_uuids: HashMap<i32, u64>,
}

impl PerfettoTraceManager {
    /// Returns a PerfettoTraceManager that is ready to start tracing.
    pub fn new(output_file_prefix: String, seed: Option<u64>) -> Self {
        let trace_uuid = seed.unwrap_or(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
        );
        let mut rng = StdRng::seed_from_u64(trace_uuid);
        let trace = Trace::new();
        let dsq_lat_trusted_packet_seq_uuid = rng.next_u32();
        let dsq_nr_queued_trusted_packet_seq_uuid = rng.next_u32();

        Self {
            trace,
            trace_id: 0,
            trusted_pid: std::process::id() as i32,
            rng,
            output_file_prefix,
            ftrace_events: BTreeMap::new(),
            dsq_uuids: BTreeMap::new(),
            dsq_lat_events: BTreeMap::new(),
            dsq_lat_trusted_packet_seq_uuid,
            dsq_nr_queued_events: BTreeMap::new(),
            dsq_nr_queued_trusted_packet_seq_uuid,
            processes: HashMap::new(),
            threads: HashMap::new(),
            process_uuids: HashMap::new(),
        }
    }

    /// Starts a new perfetto trace.
    pub fn start(&mut self) -> Result<()> {
        self.clear();
        self.trace = Trace::new();
        self.snapshot_clocks();
        Ok(())
    }

    /// Clears all events.
    fn clear(&mut self) {
        self.ftrace_events.clear();
        self.dsq_lat_events.clear();
        self.dsq_uuids.clear();
    }

    /// Returns the trace file.
    pub fn trace_file(&self) -> String {
        format!("{}_{}.proto", self.output_file_prefix, self.trace_id)
    }

    /// Creates the TrackDescriptors for the trace.
    fn track_descriptors(&self) -> BTreeMap<u64, Vec<TrackDescriptor>> {
        let mut desc_map = BTreeMap::new();

        // First add DSQ descriptor tracks
        for (dsq, dsq_uuid) in &self.dsq_uuids {
            let mut descs = vec![];

            // DSQ latency
            let mut desc = TrackDescriptor::new();
            desc.set_uuid(*dsq_uuid);
            desc.set_name(format!("DSQ {} latency ns", *dsq));
            desc.set_static_name(format!("DSQ {} latency ns", *dsq));

            let mut counter_desc = CounterDescriptor::new();
            counter_desc.set_unit_name(format!("DSQ {} latency ns", *dsq));
            counter_desc.set_unit(UNIT_COUNT);
            counter_desc.set_is_incremental(false);
            desc.counter = Some(counter_desc).into();
            descs.push(desc);

            // DSQ nr_queued
            let mut desc = TrackDescriptor::new();
            desc.set_uuid(*dsq_uuid + 1);
            desc.set_name(format!("DSQ {} nr_queued", *dsq));
            desc.set_static_name(format!("DSQ {} nr_queued", *dsq));

            let mut counter_desc = CounterDescriptor::new();
            counter_desc.set_unit_name(format!("DSQ {} nr_queued", *dsq));
            counter_desc.set_unit(UNIT_COUNT);
            counter_desc.set_is_incremental(false);
            desc.counter = Some(counter_desc).into();
            descs.push(desc);

            desc_map.insert(*dsq_uuid, descs);
        }

        desc_map
    }

    fn get_clock_value(&mut self, clock_id: libc::c_int) -> u64 {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
            return 0;
        }
        (ts.tv_sec as u64 * 1_000_000_000) + ts.tv_nsec as u64
    }

    fn snapshot_clocks(&mut self) {
        let mut clock_snapshot = ClockSnapshot::new();
        let mut clock = Clock::new();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC as u32);
        clock.set_timestamp(self.get_clock_value(libc::CLOCK_MONOTONIC));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_BOOTTIME as u32);
        clock.set_timestamp(self.get_clock_value(libc::CLOCK_BOOTTIME));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_REALTIME as u32);
        clock.set_timestamp(self.get_clock_value(libc::CLOCK_REALTIME));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_REALTIME_COARSE as u32);
        clock.set_timestamp(self.get_clock_value(libc::CLOCK_REALTIME_COARSE));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC_COARSE as u32);
        clock.set_timestamp(self.get_clock_value(libc::CLOCK_MONOTONIC_COARSE));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC_RAW as u32);
        clock.set_timestamp(self.get_clock_value(libc::CLOCK_MONOTONIC_RAW));
        clock_snapshot.clocks.push(clock);

        let mut packet = TracePacket::new();
        packet.set_clock_snapshot(clock_snapshot);
        self.trace.packet.push(packet);
    }

    fn generate_key(&mut self, v1: u32, v2: u32) -> u64 {
        let v1_u32 = v1 as u64;
        let v2_u32 = v2 as u64;
        (v1_u32 << 32) | v2_u32
    }

    fn record_process_thread(&mut self, pid: u32, tid: u32, comm: String) {
        let key = self.generate_key(pid, tid);

        if pid == tid {
            self.processes
                .entry(key)
                .and_modify(|process| {
                    if process.process_name().is_empty() {
                        process.set_process_name(comm.clone());
                    }
                })
                .or_insert_with(|| {
                    let mut process = ProcessDescriptor::new();
                    process.set_pid(pid as i32);
                    process.set_process_name(comm);
                    process
                });
        } else {
            self.threads.entry(key).or_insert_with(|| {
                let mut thread = ThreadDescriptor::new();
                thread.set_tid(tid as i32);
                thread.set_pid(pid as i32);
                thread.set_thread_name(comm);
                thread
            });
            // Create a ProcessDescriptor with an empty comm if one doesn't
            // exist - if we ever see the main thread we populate the process
            // name field there (see above).
            let pkey = self.generate_key(pid, pid);
            self.processes.entry(pkey).or_insert_with(|| {
                let mut process = ProcessDescriptor::new();
                process.set_pid(pid as i32);
                process
            });
        }
    }

    /// Stops the trace and writes to configured output file.
    pub fn stop(
        &mut self,
        output_file: Option<String>,
        last_relevent_timestamp_ns: Option<u64>,
    ) -> Result<()> {
        // TracePacket is the root object of a Perfetto trace. A Perfetto trace is a linear
        // sequence of TracePacket(s). The tracing service guarantees that all TracePacket(s)
        // written by a given TraceWriter are seen in-order, without gaps or duplicates.
        // https://perfetto.dev/docs/reference/trace-packet-proto

        let trace_cpus: Vec<u32> = self.ftrace_events.keys().cloned().collect();
        let trace_dsqs: Vec<u64> = self.dsq_nr_queued_events.keys().cloned().collect();

        // remove any events >last_relevent_timestamp_ns
        if let Some(ns) = last_relevent_timestamp_ns {
            let signed_ns = ns as i64;
            self.dsq_lat_events
                .iter_mut()
                .for_each(|(_, v)| v.retain(|e| e.timestamp_absolute_us() * 1000 < signed_ns));
            self.dsq_nr_queued_events
                .iter_mut()
                .for_each(|(_, v)| v.retain(|e| e.timestamp_absolute_us() * 1000 < signed_ns));
            self.ftrace_events
                .iter_mut()
                .for_each(|(_, v)| v.retain(|e| e.timestamp() < ns));
        };

        for (_, process) in self.processes.iter() {
            let uuid = self.rng.next_u64();
            self.process_uuids.insert(process.pid(), uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.process = Some(process.clone()).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            self.trace.packet.push(packet);
        }

        for (_, thread) in self.threads.iter() {
            let uuid = self.rng.next_u64();

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.thread = Some(thread.clone()).into();

            let pid = desc.thread.pid();
            let puuid = self.process_uuids.get(&pid);
            if let Some(p) = puuid {
                desc.set_parent_uuid(*p);
            }

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            self.trace.packet.push(packet);
        }

        for trace_descs in self.track_descriptors().values() {
            for trace_desc in trace_descs {
                let mut packet = TracePacket::new();
                packet.data = Some(DataTrackDescriptor(trace_desc.clone()));
                self.trace.packet.push(packet);
            }
        }

        // dsq latency tracks
        for dsq in &trace_dsqs {
            if let Some(events) = self.dsq_lat_events.remove(dsq) {
                for dsq_lat_event in events {
                    let ts: u64 = dsq_lat_event.timestamp_absolute_us() as u64 / 1_000;
                    let mut packet = TracePacket::new();
                    packet.set_track_event(dsq_lat_event);
                    packet.set_trusted_packet_sequence_id(self.dsq_lat_trusted_packet_seq_uuid);
                    packet.set_timestamp(ts);
                    self.trace.packet.push(packet);
                }
            }
        }

        // dsq nr_queued tracks
        for dsq in &trace_dsqs {
            if let Some(events) = self.dsq_nr_queued_events.remove(dsq) {
                for dsq_lat_event in events {
                    let ts: u64 = dsq_lat_event.timestamp_absolute_us() as u64 / 1_000;
                    let mut packet = TracePacket::new();
                    packet.set_track_event(dsq_lat_event);
                    packet
                        .set_trusted_packet_sequence_id(self.dsq_nr_queued_trusted_packet_seq_uuid);
                    packet.set_timestamp(ts);
                    self.trace.packet.push(packet);
                }
            }
        }

        // ftrace events
        for cpu in &trace_cpus {
            let mut packet = TracePacket::new();
            let mut bundle = FtraceEventBundle::new();

            if let Some(mut events) = self.ftrace_events.remove(cpu) {
                // sort by timestamp just to make sure.
                events.sort_by_key(|event| event.timestamp());
                bundle.event = events;
            }
            bundle.set_cpu(*cpu);
            packet.set_ftrace_events(bundle);
            packet.trusted_pid = Some(self.trusted_pid);
            self.trace.packet.push(packet);
        }

        let out_bytes: Vec<u8> = self.trace.write_to_bytes()?;
        match output_file {
            Some(trace_file) => {
                fs::write(trace_file, out_bytes)?;
            }
            None => {
                fs::write(self.trace_file(), out_bytes)?;
            }
        }

        self.clear();
        self.trace_id += 1;
        Ok(())
    }

    pub fn on_exit(&mut self, action: &ExitAction) {
        let ExitAction {
            ts,
            cpu,
            pid,
            tgid,
            prio,
            comm,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            let mut ftrace_event = FtraceEvent::new();
            let mut exit_event = SchedProcessExitFtraceEvent::new();

            exit_event.set_comm(comm.to_string());
            exit_event.set_pid((*pid).try_into().unwrap());
            exit_event.set_tgid((*tgid).try_into().unwrap());
            exit_event.set_prio((*prio).try_into().unwrap());

            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_sched_process_exit(exit_event);
            ftrace_event.set_pid(*pid);

            ftrace_event
        });
        self.record_process_thread(*tgid, *pid, comm.to_string());
    }

    pub fn on_fork(&mut self, action: &ForkAction) {
        let ForkAction {
            ts,
            cpu,
            parent_pid,
            child_pid,
            parent_comm,
            child_comm,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            let mut ftrace_event = FtraceEvent::new();
            let mut fork_event = SchedProcessForkFtraceEvent::new();

            fork_event.set_parent_pid((*parent_pid).try_into().unwrap());
            fork_event.set_child_pid((*child_pid).try_into().unwrap());
            fork_event.set_parent_comm(parent_comm.to_string());
            fork_event.set_child_comm(child_comm.to_string());

            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_sched_process_fork(fork_event);
            ftrace_event.set_pid(*parent_pid);

            ftrace_event
        });
    }

    pub fn on_exec(&mut self, action: &ExecAction) {
        let ExecAction {
            ts,
            cpu,
            old_pid,
            pid,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            let mut ftrace_event = FtraceEvent::new();
            let mut exec_event = SchedProcessExecFtraceEvent::new();

            exec_event.set_old_pid((*old_pid).try_into().unwrap());
            exec_event.set_pid((*pid).try_into().unwrap());

            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_sched_process_exec(exec_event);
            ftrace_event.set_pid(*old_pid);

            ftrace_event
        });
    }
    /// Adds events for on sched_wakeup.
    pub fn on_sched_wakeup(&mut self, action: &SchedWakeupAction) {
        let SchedWakeupAction {
            ts,
            cpu,
            pid,
            tgid,
            prio,
            comm,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            let mut ftrace_event = FtraceEvent::new();
            let mut wakeup_event = SchedWakeupFtraceEvent::new();
            let pid = *pid;
            let cpu = *cpu as i32;

            wakeup_event.set_pid(pid.try_into().unwrap());
            wakeup_event.set_prio(*prio);
            wakeup_event.set_comm(comm.to_string());
            wakeup_event.set_target_cpu(cpu);

            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_sched_wakeup(wakeup_event);
            ftrace_event.set_pid(pid);

            ftrace_event
        });
        self.record_process_thread(*tgid, *pid, comm.to_string());
    }

    /// Adds events for on sched_wakeup_new.
    pub fn on_sched_wakeup_new(&mut self, _action: &Action) {
        // TODO
    }

    /// Adds events for on sched_waking.
    pub fn on_sched_waking(&mut self, action: &SchedWakingAction) {
        let SchedWakingAction {
            ts,
            cpu,
            pid,
            tgid,
            prio,
            comm,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            let mut ftrace_event = FtraceEvent::new();
            let mut waking_event = SchedWakingFtraceEvent::new();
            let pid = *pid;
            let cpu = *cpu as i32;

            waking_event.set_pid(pid.try_into().unwrap());
            waking_event.set_prio(*prio);
            waking_event.set_comm(comm.to_string());
            waking_event.set_target_cpu(cpu);

            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_sched_waking(waking_event);
            ftrace_event.set_pid(pid);

            ftrace_event
        });
        self.record_process_thread(*tgid, *pid, comm.to_string());
    }

    /// Adds events for the softirq entry/exit events.
    pub fn on_softirq(&mut self, action: &SoftIRQAction) {
        self.ftrace_events.entry(action.cpu).or_default().extend({
            let mut entry_ftrace_event = FtraceEvent::new();
            let mut exit_ftrace_event = FtraceEvent::new();
            let mut entry_event = SoftirqEntryFtraceEvent::new();
            let mut exit_event = SoftirqExitFtraceEvent::new();
            entry_event.set_vec(action.softirq_nr as u32);
            exit_event.set_vec(action.softirq_nr as u32);

            entry_ftrace_event.set_timestamp(action.entry_ts);
            entry_ftrace_event.set_softirq_entry(entry_event);
            entry_ftrace_event.set_pid(action.pid);
            exit_ftrace_event.set_timestamp(action.exit_ts);
            exit_ftrace_event.set_softirq_exit(exit_event);
            exit_ftrace_event.set_pid(action.pid);

            [entry_ftrace_event, exit_ftrace_event]
        });
    }

    /// Adds events for the IPI entry/exit events.
    pub fn on_ipi(&mut self, action: &IPIAction) {
        let IPIAction {
            ts,
            cpu,
            target_cpu,
            pid,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            let mut ftrace_event = FtraceEvent::new();
            let mut raise_event = IpiRaiseFtraceEvent::new();
            raise_event.set_reason("IPI raise".to_string());
            raise_event.set_target_cpus(*target_cpu);
            ftrace_event.set_pid(*pid);
            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_ipi_raise(raise_event);

            ftrace_event
        });
    }

    pub fn on_gpu_mem(&mut self, action: &GpuMemAction) {
        let GpuMemAction {
            ts,
            size,
            cpu,
            gpu,
            pid,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            let mut ftrace_event = FtraceEvent::new();
            let mut gpu_mem_event = GpuMemTotalFtraceEvent::new();
            gpu_mem_event.set_gpu_id(*gpu);
            gpu_mem_event.set_size(*size);
            gpu_mem_event.set_pid(*pid);
            ftrace_event.set_pid(*pid);
            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_gpu_mem_total(gpu_mem_event);

            ftrace_event
        });
    }

    pub fn on_cpu_hp_enter(&mut self, action: &CpuhpEnterAction) {
        let CpuhpEnterAction {
            ts,
            cpu,
            target,
            state,
            pid,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            let mut ftrace_event = FtraceEvent::new();
            let mut cpu_hp_event = CpuhpEnterFtraceEvent::new();
            cpu_hp_event.set_cpu(*cpu);
            cpu_hp_event.set_target(*target);
            cpu_hp_event.set_idx(*state);
            ftrace_event.set_pid(*pid);
            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_cpuhp_enter(cpu_hp_event);

            ftrace_event
        });
    }

    pub fn on_cpu_hp_exit(&mut self, action: &CpuhpExitAction) {
        let CpuhpExitAction {
            ts,
            cpu,
            state,
            idx,
            ret,
            pid,
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            let mut ftrace_event = FtraceEvent::new();
            let mut cpu_hp_event = CpuhpExitFtraceEvent::new();
            cpu_hp_event.set_cpu(*cpu);
            cpu_hp_event.set_state(*state);
            cpu_hp_event.set_idx(*idx);
            cpu_hp_event.set_ret(*ret);
            ftrace_event.set_pid(*pid);
            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_cpuhp_exit(cpu_hp_event);

            ftrace_event
        });
    }
    /// Adds events for the sched_switch event.
    pub fn on_sched_switch(&mut self, action: &SchedSwitchAction) {
        let SchedSwitchAction {
            ts,
            cpu,
            next_dsq_id,
            next_dsq_nr_queued,
            next_dsq_lat_us,
            next_pid,
            next_tgid,
            next_prio,
            next_comm,
            prev_pid,
            prev_tgid,
            prev_prio,
            prev_comm,
            prev_state,
            ..
        } = action;

        self.ftrace_events.entry(*cpu).or_default().push({
            let mut ftrace_event = FtraceEvent::new();
            let mut switch_event = SchedSwitchFtraceEvent::new();
            let prev_pid: i32 = *prev_pid as i32;
            let next_pid: i32 = *next_pid as i32;

            // XXX: On the BPF side the prev/next pid gets set to an invalid pid (0) if the
            // prev/next task is invalid.
            if next_pid > 0 {
                switch_event.set_next_pid(next_pid);
                switch_event.set_next_comm(next_comm.to_string());
                switch_event.set_next_prio(*next_prio);
            }

            if prev_pid > 0 {
                switch_event.set_prev_pid(prev_pid);
                switch_event.set_prev_prio(*prev_prio);
                switch_event.set_prev_comm(prev_comm.to_string());
                switch_event.set_prev_state(*prev_state as i64);
            }
            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_sched_switch(switch_event);
            ftrace_event.set_pid(prev_pid.try_into().unwrap());

            ftrace_event
        });

        if *next_pid > 0 {
            self.record_process_thread(*next_tgid, *next_pid, next_comm.to_string());
        }
        if *prev_pid > 0 {
            self.record_process_thread(*prev_tgid, *prev_pid, prev_comm.to_string());
        }

        // Skip handling DSQ data if the sched_switch event didn't have
        // any DSQ data.
        if *next_dsq_id == scx_enums.SCX_DSQ_INVALID {
            return;
        }

        let next_dsq_uuid = self
            .dsq_uuids
            .entry(*next_dsq_id)
            .or_insert_with(|| self.rng.next_u64());
        self.dsq_lat_events.entry(*next_dsq_id).or_default().push({
            let mut event = TrackEvent::new();
            let ts: i64 = (*ts).try_into().unwrap();
            event.set_type(TrackEventType::TYPE_COUNTER);
            event.set_track_uuid(*next_dsq_uuid);
            event.set_counter_value((*next_dsq_lat_us).try_into().unwrap());
            event.set_timestamp_absolute_us(ts / 1000);

            event
        });
        self.dsq_nr_queued_events
            .entry(*next_dsq_id)
            .or_default()
            .push({
                let mut event = TrackEvent::new();
                let ts: i64 = (*ts).try_into().unwrap();
                event.set_type(TrackEventType::TYPE_COUNTER);
                // Each track needs a separate unique UUID, so we'll add one to the dsq for
                // the nr_queued events.
                event.set_track_uuid(*next_dsq_uuid + 1);
                event.set_counter_value(*next_dsq_nr_queued as i64);
                event.set_timestamp_absolute_us(ts / 1000);

                event
            });
    }
}

impl ActionHandler for PerfettoTraceManager {
    fn on_action(&mut self, action: &Action) -> Result<()> {
        match action {
            Action::SchedSwitch(a) => {
                self.on_sched_switch(a);
            }
            Action::SchedWakeup(a) => {
                self.on_sched_wakeup(a);
            }
            Action::SchedWaking(a) => {
                self.on_sched_waking(a);
            }
            Action::SoftIRQ(a) => {
                self.on_softirq(a);
            }
            Action::IPI(a) => {
                self.on_ipi(a);
            }
            Action::Exec(a) => {
                self.on_exec(a);
            }
            Action::Fork(a) => {
                self.on_fork(a);
            }
            Action::GpuMem(a) => {
                self.on_gpu_mem(a);
            }
            Action::Exit(a) => {
                self.on_exit(a);
            }
            Action::CpuhpEnter(a) => {
                self.on_cpu_hp_enter(a);
            }
            Action::CpuhpExit(a) => {
                self.on_cpu_hp_exit(a);
            }
            _ => {}
        }

        Ok(())
    }
}
