extern crate libc;

use std::sync::atomic::{AtomicUsize, Ordering};
use libc::{sched_setaffinity, cpu_set_t, CPU_SET};

fn main() {
    let num_cpus = libbpf_rs::num_possible_cpus().unwrap();

    for cpu in 0..num_cpus {
        let mut cpu_set: cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { CPU_SET(cpu as usize, &mut cpu_set) };

        println!("setting affinity to {}", cpu);
        unsafe {
            sched_setaffinity(0, std::mem::size_of::<cpu_set_t>(), &cpu_set as *const cpu_set_t);
        }

        let counter = AtomicUsize::new(0);

        while counter.load(Ordering::Relaxed) < 500_000_000 {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}
