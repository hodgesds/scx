# scx_atlas

**A**I **T**raining **L**atency-**A**ware **S**cheduler (prototype).

A sched_ext scheduler purpose-built for GPU training hosts: latency-critical
PyTorch GPU-polling threads alongside isolated data-preprocessing pipelines on
large NUMA systems, with GPU-topology and IRQ awareness.

See [`scx_atlas_design.md`](../../../scx_atlas_design.md) at the repo root for the
full design and roadmap.

## Status

**Phase 0 (skeleton).** Every task is scheduled FIFO through a single shared
dispatch queue, with idle-CPU direct dispatch and per-CPU kthreads kept local.
The p2dq-style `const volatile` config structs, the scheduling-class enum, and
the stats framework are wired in so later phases slot in cleanly:

- Phase 1 — `lib/soft_affinity` reusable soft-affinity module (bpf_cpumask)
- Phase 2 — fixed scheduling classes + per-(class, LLC) DSQs
- Phase 3 — LLC/NUMA load balancing
- Phase 4 — GPU awareness (per-GPU LATENCY sub-domains, kprobe + uprobe detection)
- Phase 5 — IRQ accounting & affinitization
- Phase 6 — metrics, tuning, hardening

## Build & run

```bash
cargo build --release -p scx_atlas
sudo target/release/scx_atlas
sudo target/release/scx_atlas --monitor 1   # live stats
```
