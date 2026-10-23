# scx_lavd

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_lavd` is a BPF scheduler that implements an `LAVD` (Latency-criticality Aware
Virtual Deadline) scheduling algorithm. While `LAVD` is new and still evolving,
its core ideas are 1) measuring how much a task is latency critical and 2)
leveraging the task's latency-criticality information in making various
scheduling decisions (e.g., task's deadline, time slice, etc.). As the name
implies, `LAVD` is based on the foundation of deadline scheduling. This scheduler
consists of the BPF part and the `Rust` part. The BPF part makes all the
scheduling decisions; the `Rust` part provides high-level information (e.g., CPU
topology) to the BPF code, loads the BPF code and conducts other chores (e.g.,
printing sampled scheduling decisions).

## Typical Use Case

`scx_lavd` is initially motivated by gaming workloads. It aims to improve
interactivity and reduce stuttering while playing games on Linux. Hence, this
scheduler's typical use case involves highly interactive applications, such as
gaming, which requires high throughput and low tail latencies.

## Production Ready?

Yes, `scx_lavd` should be performant across various CPU architectures. It creates
a separate scheduling domain per-LLC, per-core type (e.g., P or E core on
Intel, big or LITTLE on ARM), and per-NUMA domain, so the default balanced
profile or autopilot mode should be performant. It mainly targets single CCX
/ single-socket systems.

## Soft partitioning

`--soft-partitioning` enables experimental process CPU homes. Each task records
the NUMA node of the first CPU on which LAVD observes it running. Threads with
the same TGID and origin node share an LLC home. Threads of a process that
start on different nodes have separate homes. Forked tasks establish their
own origin when they first run. Exec and later migrations retain the origin.
For tasks already running when LAVD starts, this records the node observed at
scheduler activation, not their original allocation or execution node.

The mode requires the kernel's BPF local IRQ save/restore kfuncs to synchronize
group membership between scheduler callbacks and userspace commands.

Once a second, measured CPU runtime sizes each home to a set of whole LLCs on
its origin node. The allocator accounts for each LLC's CPU count, places homes
by relative load, and keeps existing homes when loads tie. Homes can overlap
under saturation. `--virt-llc` can give finer homes on machines with large LLCs.

Idle selection tries the home before normal LAVD placement, respecting task
affinity, active and overflow CPUs, core type, and latency headroom. A busy
home or an affinity mask that excludes it falls through to LAVD's normal CPU
selection and balancing. CPU affinity is never changed, and migration never
changes the origin node. Pinned and migration-disabled tasks keep their normal
placement. Scheduler task dumps report the origin node and home LLC mask.

Runtime counters and homes live in arenas. Tasks cache their group pointers;
userspace samples and resizes through BPF commands without dereferencing arena
pointers. The last thread removes its group from the index, and RCU defers
reclamation until outstanding readers finish. Group IDs reject resize commands
for exited groups after PID reuse. The index admits up to 16384 live groups;
tasks beyond that limit use their initial LLC home without autosizing.
