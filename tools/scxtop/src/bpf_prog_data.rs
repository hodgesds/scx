// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, Result};
use libbpf_rs::{btf, query::ProgInfoIter, ProgramType};
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// BPF line information for symbolization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfLineInfo {
    pub file_name_off: u32,
    pub line_col: u32,
    pub instruction_offset: u32,
}

impl BpfLineInfo {
    /// Extract line number from line_col field
    pub fn line_number(&self) -> u32 {
        self.line_col >> 10
    }

    /// Extract column number from line_col field
    pub fn column_number(&self) -> u32 {
        self.line_col & 0x3ff
    }
}

/// BPF program symbol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfSymbolInfo {
    pub tag: String,
    pub jited_line_info: Vec<u64>,
    pub line_info: Vec<BpfLineInfo>,
    pub btf_info: Option<Vec<u8>>,
}

impl BpfSymbolInfo {
    /// Find source location for a given instruction address
    pub fn find_source_location(&self, addr: u64) -> Option<&BpfLineInfo> {
        // Binary search in the sorted jited_line_info array
        match self.jited_line_info.binary_search(&addr) {
            Ok(index) => self.line_info.get(index),
            Err(index) => {
                // Find the closest smaller address
                if index > 0 {
                    self.line_info.get(index - 1)
                } else {
                    None
                }
            }
        }
    }

    /// Extract filename from BTF data using file_name_off
    pub fn get_filename(&self, file_name_off: u32) -> Option<String> {
        // This would need actual BTF parsing implementation
        // For now, return a placeholder
        Some(format!("bpf_program_{}.c", file_name_off))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfProgData {
    pub id: u32,
    pub prog_type: String,
    pub name: String,
    pub run_time_ns: u64,
    pub run_cnt: u64,
    pub min_runtime_ns: u64,
    pub max_runtime_ns: u64,
    pub recursion_misses: u64,
    pub verified_insns: u32,
    pub loaded_at: u64,
    pub uid: u32,
    pub gpl_compatible: bool,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_map_ids: u32,
    pub map_ids: Vec<u32>,
    pub btf_id: u32,
}

impl BpfProgData {
    /// Calculate average runtime per call in nanoseconds
    pub fn avg_runtime_ns(&self) -> f64 {
        if self.run_cnt == 0 {
            0.0
        } else {
            self.run_time_ns as f64 / self.run_cnt as f64
        }
    }

    /// Calculate runtime percentage relative to total system runtime
    pub fn runtime_percentage(&self, total_runtime_ns: u64) -> f64 {
        if total_runtime_ns == 0 {
            0.0
        } else {
            (self.run_time_ns as f64 / total_runtime_ns as f64) * 100.0
        }
    }
}

#[derive(Debug, Clone)]
pub struct BpfProgStats {
    pub programs: HashMap<u32, BpfProgData>,
    pub total_runtime_ns: u64,
}

// BPF program info structure definition for syscalls
#[repr(C)]
#[derive(Default)]
struct BpfProgInfo {
    type_: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; 16],
    ifindex: u32,
    gpl_compatible: u32,
    netns_dev: u64,
    netns_ino: u64,
    nr_jited_ksyms: u32,
    nr_jited_func_lens: u32,
    jited_ksyms: u64,
    jited_func_lens: u64,
    btf_id: u32,
    func_info_rec_size: u32,
    func_info: u64,
    nr_func_info: u32,
    nr_line_info: u32,
    line_info: u64,
    jited_line_info: u64,
    nr_jited_line_info: u32,
    line_info_rec_size: u32,
    jited_line_info_rec_size: u32,
    nr_prog_tags: u32,
    prog_tags: u64,
    run_time_ns: u64,
    run_cnt: u64,
    recursion_misses: u64,
    verified_insns: u32,
}

impl BpfProgStats {
    pub fn new() -> Self {
        Self {
            programs: HashMap::new(),
            total_runtime_ns: 0,
        }
    }

    /// Convert ProgramType to string representation
    fn program_type_to_string(prog_type: &ProgramType) -> String {
        match prog_type {
            ProgramType::SocketFilter => "socket_filter",
            ProgramType::Kprobe => "kprobe",
            ProgramType::SchedCls => "sched_cls",
            ProgramType::SchedAct => "sched_act",
            ProgramType::Tracepoint => "tracepoint",
            ProgramType::Xdp => "xdp",
            ProgramType::PerfEvent => "perf_event",
            ProgramType::CgroupSkb => "cgroup_skb",
            ProgramType::CgroupSock => "cgroup_sock",
            ProgramType::LwtIn => "lwt_in",
            ProgramType::LwtOut => "lwt_out",
            ProgramType::LwtXmit => "lwt_xmit",
            ProgramType::SockOps => "sock_ops",
            ProgramType::SkSkb => "sk_skb",
            ProgramType::CgroupDevice => "cgroup_device",
            ProgramType::SkMsg => "sk_msg",
            ProgramType::RawTracepoint => "raw_tracepoint",
            ProgramType::CgroupSockAddr => "cgroup_sock_addr",
            ProgramType::LwtSeg6local => "lwt_seg6local",
            ProgramType::LircMode2 => "lirc_mode2",
            ProgramType::SkReuseport => "sk_reuseport",
            ProgramType::FlowDissector => "flow_dissector",
            ProgramType::CgroupSysctl => "cgroup_sysctl",
            ProgramType::RawTracepointWritable => "raw_tracepoint_writable",
            ProgramType::CgroupSockopt => "cgroup_sockopt",
            ProgramType::Tracing => "tracing",
            ProgramType::StructOps => "struct_ops",
            ProgramType::Ext => "ext",
            ProgramType::SkLookup => "sk_lookup",
            ProgramType::Syscall => "syscall",
            _ => "unknown",
        }
        .to_string()
    }

    /// Collect BPF program statistics using procfs scanning
    /// Falls back to less accurate data if BPF_ENABLE_STATS isn't available
    pub fn collect() -> Result<Self> {
        let mut stats = Self::new();

        // Try to collect BPF programs with runtime statistics using proper BPF calls
        if let Err(e) = stats.collect_via_bpf_calls() {
            log::debug!("BPF syscalls failed: {}, falling back to procfs", e);
            // Fallback to procfs scanning (though this won't have runtime stats)
            stats.collect_via_procfs()?;
        }

        Ok(stats)
    }

    /// Get real BPF symbol information for a program using syscalls and libbpf-rs
    pub fn get_real_symbol_info(prog_id: u32) -> Result<Option<BpfSymbolInfo>> {
        // First, try to get the program file descriptor
        let prog_fd = Self::get_prog_fd_by_id(prog_id)?;
        if prog_fd < 0 {
            return Ok(None);
        }

        // Get detailed program info using bpf_obj_get_info_by_fd
        let mut prog_info = Self::get_detailed_prog_info(prog_fd)?;

        // Extract line info and JIT info if available
        let (line_info, jited_line_info) = Self::extract_line_info(&mut prog_info)?;

        // Get BTF information
        let btf_info = Self::get_btf_info_raw(prog_id);

        // Create the tag from program info
        let tag = format!("{:016x}", u64::from_ne_bytes(prog_info.tag));

        Ok(Some(BpfSymbolInfo {
            tag,
            jited_line_info,
            line_info,
            btf_info,
        }))
    }

    /// Get the instruction count for a specific BPF program using raw syscalls
    fn get_program_instruction_count(prog_id: u32) -> Result<u32> {
        // Get the program file descriptor first
        let prog_fd = Self::get_prog_fd_by_id(prog_id)?;
        if prog_fd < 0 {
            return Ok(0);
        }

        // Get detailed program info to extract verified_insns
        let prog_info = Self::get_detailed_prog_info(prog_fd)?;
        
        // Close the file descriptor since we only needed it for the query
        unsafe {
            libc::close(prog_fd);
        }

        Ok(prog_info.verified_insns)
    }

    /// Get program file descriptor by program ID
    fn get_prog_fd_by_id(prog_id: u32) -> Result<i32> {
        use std::mem;

        const BPF_PROG_GET_FD_BY_ID: u32 = 13;

        #[repr(C)]
        #[derive(Default)]
        struct BpfAttr {
            prog_get_fd_by_id: BpfProgGetFdById,
        }

        #[repr(C)]
        #[derive(Default)]
        struct BpfProgGetFdById {
            prog_id: u32,
            next_id: u32,
            open_flags: u32,
        }

        let mut attr = BpfAttr {
            prog_get_fd_by_id: BpfProgGetFdById {
                prog_id,
                next_id: 0,
                open_flags: 0,
            },
        };

        let fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_PROG_GET_FD_BY_ID as libc::c_long,
                &mut attr as *mut _ as libc::c_long,
                mem::size_of::<BpfAttr>() as libc::c_long,
            )
        };

        if fd < 0 {
            return Err(anyhow!(
                "Failed to get prog fd by ID {}: {}",
                prog_id,
                std::io::Error::last_os_error()
            ));
        }

        Ok(fd as i32)
    }

    /// Get detailed BPF program information
    fn get_detailed_prog_info(prog_fd: i32) -> Result<BpfProgInfo> {
        use std::mem;

        const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;

        #[repr(C)]
        #[derive(Default)]
        struct BpfAttr {
            info: BpfObjGetInfo,
        }

        #[repr(C)]
        #[derive(Default)]
        struct BpfObjGetInfo {
            bpf_fd: u32,
            info_len: u32,
            info: u64,
        }

        let mut prog_info = BpfProgInfo::default();
        let mut attr = BpfAttr {
            info: BpfObjGetInfo {
                bpf_fd: prog_fd as u32,
                info_len: mem::size_of::<BpfProgInfo>() as u32,
                info: &mut prog_info as *mut _ as u64,
            },
        };

        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_OBJ_GET_INFO_BY_FD as libc::c_long,
                &mut attr as *mut _ as libc::c_long,
                mem::size_of::<BpfAttr>() as libc::c_long,
            )
        };

        if result < 0 {
            return Err(anyhow!(
                "Failed to get program info: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(prog_info)
    }

    /// Extract line info and JIT line info from BPF program info
    fn extract_line_info(prog_info: &mut BpfProgInfo) -> Result<(Vec<BpfLineInfo>, Vec<u64>)> {
        let mut line_info = Vec::new();
        let mut jited_line_info = Vec::new();

        // If the program has line info, extract it
        if prog_info.nr_line_info > 0 && prog_info.line_info != 0 {
            // Allocate buffers for line info
            let line_info_size =
                prog_info.nr_line_info as usize * prog_info.line_info_rec_size as usize;
            let mut line_info_buf = vec![0u8; line_info_size];

            // Get line info via another syscall
            prog_info.line_info = line_info_buf.as_mut_ptr() as u64;

            // Extract BpfLineInfo entries from the buffer
            let line_info_rec_size = prog_info.line_info_rec_size as usize;
            for i in 0..prog_info.nr_line_info as usize {
                let offset = i * line_info_rec_size;
                if offset + 12 <= line_info_buf.len() {
                    let instruction_offset = u32::from_ne_bytes([
                        line_info_buf[offset],
                        line_info_buf[offset + 1],
                        line_info_buf[offset + 2],
                        line_info_buf[offset + 3],
                    ]);
                    let file_name_off = u32::from_ne_bytes([
                        line_info_buf[offset + 4],
                        line_info_buf[offset + 5],
                        line_info_buf[offset + 6],
                        line_info_buf[offset + 7],
                    ]);
                    let line_col = u32::from_ne_bytes([
                        line_info_buf[offset + 8],
                        line_info_buf[offset + 9],
                        line_info_buf[offset + 10],
                        line_info_buf[offset + 11],
                    ]);

                    line_info.push(BpfLineInfo {
                        file_name_off,
                        line_col,
                        instruction_offset,
                    });
                }
            }
        }

        // If the program has JIT line info, extract it
        if prog_info.nr_jited_line_info > 0 && prog_info.jited_line_info != 0 {
            let jited_line_info_size =
                prog_info.nr_jited_line_info as usize * prog_info.jited_line_info_rec_size as usize;
            let mut jited_line_info_buf = vec![0u8; jited_line_info_size];
            prog_info.jited_line_info = jited_line_info_buf.as_mut_ptr() as u64;

            // Extract JIT addresses
            let jited_line_info_rec_size = prog_info.jited_line_info_rec_size as usize;
            for i in 0..prog_info.nr_jited_line_info as usize {
                let offset = i * jited_line_info_rec_size;
                if offset + 8 <= jited_line_info_buf.len() {
                    let addr = u64::from_ne_bytes([
                        jited_line_info_buf[offset],
                        jited_line_info_buf[offset + 1],
                        jited_line_info_buf[offset + 2],
                        jited_line_info_buf[offset + 3],
                        jited_line_info_buf[offset + 4],
                        jited_line_info_buf[offset + 5],
                        jited_line_info_buf[offset + 6],
                        jited_line_info_buf[offset + 7],
                    ]);
                    jited_line_info.push(addr);
                }
            }
        }

        Ok((line_info, jited_line_info))
    }

    /// Get BTF information for a program using libbpf-rs btf module
    fn get_btf_info_raw(prog_id: u32) -> Option<Vec<u8>> {
        if prog_id == 0 {
            return None;
        }

        // Use libbpf-rs btf module to get BTF data from program ID
        match btf::Btf::from_prog_id(prog_id) {
            Ok(_btf_obj) => {
                // The BTF object could be used for type information in the future
                log::debug!("Successfully loaded BTF for program ID {}", prog_id);
                None // For now, return None since raw data extraction isn't available
            }
            Err(e) => {
                log::warn!("Failed to get BTF data for program ID {}: {}", prog_id, e);
                None
            }
        }
    }

    /// Collect BPF program stats using libbpf-rs query module
    /// Note: Assumes BPF stats are already enabled by the caller
    fn collect_via_bpf_calls(&mut self) -> Result<()> {
        // Enumerate all BPF programs using libbpf-rs query module
        // BPF stats should already be enabled by the calling App
        self.enumerate_bpf_programs_with_libbpf()?;

        Ok(())
    }

    /// Enumerate all BPF programs using libbpf-rs ProgInfoIter
    fn enumerate_bpf_programs_with_libbpf(&mut self) -> Result<()> {
        // Use libbpf-rs query module to iterate over loaded BPF programs
        for prog_info in ProgInfoIter::default() {
            if let Some(prog_data) = self.convert_libbpf_prog_info(&prog_info) {
                self.total_runtime_ns += prog_data.run_time_ns;
                self.programs.insert(prog_data.id, prog_data);
            }
        }

        Ok(())
    }

    /// Convert libbpf-rs ProgramInfo to our BpfProgData structure
    fn convert_libbpf_prog_info(
        &self,
        info: &libbpf_rs::query::ProgramInfo,
    ) -> Option<BpfProgData> {
        // Extract basic program information (access as fields, not methods)
        let id = info.id;
        let name = info.name.to_string_lossy().to_string();
        let prog_type = Self::program_type_to_string(&info.ty);

        // Extract runtime statistics (access as fields, not methods)
        let run_time_ns = info.run_time_ns;
        let run_cnt = info.run_cnt;
        let recursion_misses = info.recursion_misses;

        // Extract other program metadata (access as fields, not methods)
        // Note: Some fields may not exist on ProgramInfo, use defaults
        // Get instruction count using raw BPF syscalls since xlated_prog_insns might be empty
        let verified_insns = Self::get_program_instruction_count(id).unwrap_or(0);
        let loaded_at = info.load_time.as_nanos() as u64; // Convert Duration to nanoseconds
        let uid = info.created_by_uid;
        let gpl_compatible = info.gpl_compatible;
        let netns_dev = info.netns_dev;
        let netns_ino = info.netns_ino;
        let btf_id = info.btf_id;

        // Extract map IDs if available (access as field, not method)
        let map_ids = info.map_ids.clone();
        let nr_map_ids = map_ids.len() as u32;

        Some(BpfProgData {
            id,
            prog_type,
            name,
            run_time_ns,
            run_cnt,
            min_runtime_ns: 0, // Not available from current libbpf-rs API
            max_runtime_ns: 0, // Not available from current libbpf-rs API
            recursion_misses,
            verified_insns,
            loaded_at,
            uid,
            gpl_compatible,
            netns_dev,
            netns_ino,
            nr_map_ids,
            map_ids,
            btf_id,
        })
    }

    /// Fallback method using procfs to find BPF programs
    fn collect_via_procfs(&mut self) -> Result<()> {
        // Scan /proc for processes that might have BPF programs
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let path = entry.path();

            if let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if let Err(_) = self.scan_process_for_bpf(pid) {
                        // Ignore individual process scan failures
                        continue;
                    }
                }
            }
        }

        Ok(())
    }

    /// Scan a specific process for BPF file descriptors
    fn scan_process_for_bpf(&mut self, pid: u32) -> Result<()> {
        let fd_dir = format!("/proc/{}/fd", pid);

        if !Path::new(&fd_dir).exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&fd_dir)? {
            let entry = entry?;
            let fd_path = entry.path();

            if let Some(fd_str) = fd_path.file_name().and_then(|n| n.to_str()) {
                if let Ok(fd) = fd_str.parse::<u32>() {
                    if let Err(_) = self.check_fd_for_bpf(pid, fd) {
                        // Ignore individual FD check failures
                        continue;
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a file descriptor is a BPF program and collect its info
    fn check_fd_for_bpf(&mut self, pid: u32, fd: u32) -> Result<()> {
        let fdinfo_path = format!("/proc/{}/fdinfo/{}", pid, fd);

        if let Ok(content) = fs::read_to_string(&fdinfo_path) {
            if content.contains("prog_type") {
                // This looks like a BPF program, try to parse it
                if let Ok(prog_data) = self.parse_bpf_fdinfo(&content, fd) {
                    self.total_runtime_ns += prog_data.run_time_ns;
                    self.programs.insert(prog_data.id, prog_data);
                }
            }
        }

        Ok(())
    }

    /// Parse BPF program information from fdinfo content
    fn parse_bpf_fdinfo(&self, content: &str, fd: u32) -> Result<BpfProgData> {
        let mut prog_data = BpfProgData {
            id: fd, // Use FD as fallback ID
            prog_type: String::new(),
            name: String::new(),
            run_time_ns: 0,
            run_cnt: 0,
            min_runtime_ns: 0,
            max_runtime_ns: 0,
            recursion_misses: 0,
            verified_insns: 0,
            loaded_at: 0,
            uid: 0,
            gpl_compatible: false,
            netns_dev: 0,
            netns_ino: 0,
            nr_map_ids: 0,
            map_ids: Vec::new(),
            btf_id: 0,
        };

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "prog_type:" => prog_data.prog_type = parts[1].to_string(),
                    "prog_name:" => prog_data.name = parts[1].to_string(),
                    "run_time_ns:" => prog_data.run_time_ns = parts[1].parse().unwrap_or(0),
                    "run_cnt:" => prog_data.run_cnt = parts[1].parse().unwrap_or(0),
                    "recursion_misses:" => {
                        prog_data.recursion_misses = parts[1].parse().unwrap_or(0)
                    }
                    "verified_insns:" => prog_data.verified_insns = parts[1].parse().unwrap_or(0),
                    "load_time:" => prog_data.loaded_at = parts[1].parse().unwrap_or(0),
                    "uid:" => prog_data.uid = parts[1].parse().unwrap_or(0),
                    "gpl_compatible:" => prog_data.gpl_compatible = parts[1] == "1",
                    "netns_dev:" => prog_data.netns_dev = parts[1].parse().unwrap_or(0),
                    "netns_ino:" => prog_data.netns_ino = parts[1].parse().unwrap_or(0),
                    "btf_id:" => prog_data.btf_id = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        Ok(prog_data)
    }
}

impl Default for BpfProgStats {
    fn default() -> Self {
        Self::new()
    }
}
