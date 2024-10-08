#![cfg(feature = "gpu-topology")]

use crate::misc::read_file_usize;
use nvml_wrapper::bitmasks::InitFlags;
use nvml_wrapper::enum_wrappers::device::Clock;
use nvml_wrapper::Nvml;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;


// global state if gpu pids are being monitored.
static MONITORING_GPU_PIDS: AtomicBool = AtomicBool::new(false);


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum GpuIndex {
    Nvidia { nvml_id: u32 },
}

#[derive(Debug, Clone)]
pub struct Gpu {
    pub index: GpuIndex,
    pub node_id: usize,
    pub max_graphics_clock: usize,
    // AMD uses CU for this value
    pub max_sm_clock: usize,
    pub memory: u64,
}

pub fn create_gpus() -> BTreeMap<usize, Vec<Gpu>> {
    let mut gpus: BTreeMap<usize, Vec<Gpu>> = BTreeMap::new();

    // Don't fail if the system has no NVIDIA GPUs.
    let Ok(nvml) = Nvml::init_with_flags(InitFlags::NO_GPUS) else {
        return BTreeMap::new();
    };
    match nvml.device_count() {
        Ok(nvidia_gpu_count) => {
            for i in 0..nvidia_gpu_count {
                let Ok(nvidia_gpu) = nvml.device_by_index(i) else {
                    continue;
                };
                let graphics_boost_clock = nvidia_gpu
                    .max_customer_boost_clock(Clock::Graphics)
                    .unwrap_or(0);
                let sm_boost_clock = nvidia_gpu.max_customer_boost_clock(Clock::SM).unwrap_or(0);
                let Ok(memory_info) = nvidia_gpu.memory_info() else {
                    continue;
                };
                let Ok(pci_info) = nvidia_gpu.pci_info() else {
                    continue;
                };
                let Ok(index) = nvidia_gpu.index() else {
                    continue;
                };

                // The NVML library doesn't return a PCIe bus ID compatible with sysfs. It includes
                // uppercase bus ID values and an extra four leading 0s.
                let bus_id = pci_info.bus_id.to_lowercase();
                let fixed_bus_id = bus_id.strip_prefix("0000").unwrap_or("");
                let numa_path = format!("/sys/bus/pci/devices/{}/numa_node", fixed_bus_id);
                let numa_node = read_file_usize(&Path::new(&numa_path)).unwrap_or(0);

                let gpu = Gpu {
                    index: GpuIndex::Nvidia { nvml_id: index },
                    node_id: numa_node as usize,
                    max_graphics_clock: graphics_boost_clock as usize,
                    max_sm_clock: sm_boost_clock as usize,
                    memory: memory_info.total,
                };
                if !gpus.contains_key(&numa_node) {
                    gpus.insert(numa_node, vec![gpu]);
                    continue;
                }
                if let Some(gpus) = gpus.get_mut(&numa_node) {
                    gpus.push(gpu);
                }
            }
        }
        _ => {}
    };

    gpus
}

fn update_monitor_pid_map(nvml: &Nvml) {
    let nvidia_gpu_count = nvml.device_count().unwrap();
    for i in 0..nvidia_gpu_count {
        let Ok(nvidia_gpu) = nvml.device_by_index(i) else {
            continue;
        };
        let Ok(compute_procs) = nvidia_gpu.running_compute_processes() else {
            continue;
        };
    }
    // TODO: iterate over the bpf map and remove any processes not in the compute processes and
    // update any missing processes with appropriate metadata.
}

/// Monitors NVIDIA GPUs and updates the bpf mapping of tasks to GPU metadata.
pub fn monitor_gpu_pids(interval: Duration, stop_flag: Arc<AtomicBool>) -> JoinHandle<()> {
    // TODO: This function needs to be passed a reference to the gpu pid metadata map.
    let handle = thread::spawn(move || {
        let Ok(nvml) = Nvml::init_with_flags(InitFlags::NO_GPUS) else {
            return;
        };
        let result = MONITORING_GPU_PIDS.compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed);
        match result {
            Ok(set) =>  {
                if !set {
                    // TODO: error handling
                    return;
                }
            }
            Err(_) => {
                // TODO: error handling
                return;
            }
        }
        loop {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(interval);
            update_monitor_pid_map(&nvml);
        }
        MONITORING_GPU_PIDS.store(false, Ordering::Relaxed);
    });
    handle
}
