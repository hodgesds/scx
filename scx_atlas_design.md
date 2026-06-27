# scx_atlas — Design Plan

**A**I **T**raining **L**atency-**A**ware **S**cheduler

A sched_ext scheduler purpose-built for GPU training hosts: large NUMA systems
running latency-critical PyTorch GPU-polling threads alongside isolated
data-preprocessing pipelines, with first-class GPU topology and IRQ awareness.

> Status: design proposal. Names are provisional (`scx_atlas`).

---

## 1. Why a new scheduler (and what we borrow)

`scx_layered` is the closest fit today because of its **soft-affinity layer
model**: a layer owns a dynamically grown cpumask, tasks *prefer* their layer's
CPUs but spill when saturated, and high-priority layers can preempt and be
"protected" from other layers. That is exactly the isolation-with-spill behavior
we want for "PyTorch vs. preprocessing vs. training stack vs. everything else."

What `scx_layered` does *not* give us, and `scx_atlas` adds:

| Need (principle) | layered today | scx_atlas |
|---|---|---|
| GPU-proximal CPU set per device (#6, #10) | GPU *pid* tracking + coarse NUMA affinitize only | per-GPU `bpf_cpumask` built from GPU↔NUMA/PCIe topology, layers steer to it |
| IRQ accounting + affinitization (#5) | `/proc/stat` irq *compensation* only; netdev affinity read in utils | per-CPU IRQ/softirq accounting in BPF + active IRQ steering off latency CPUs |
| Reusable soft-affinity primitive (#9) | logic baked into `main.bpf.c` + `alloc.rs` | extracted into a `lib/` module (`soft_affinity`, bpf_cpumask) reusable by any sched |
| p2dq-style config structs (#8) | huge per-layer JSON + bindgen structs | `const volatile` grouped config structs + compact layer-class table |
| Knob sprawl (#7) | very large surface (every layer field tunable) | small fixed set of *classes* + a few global knobs |

We **keep** layered's best ideas (growth algos, protected/preempt, per-(class,LLC)
DSQs, `cpus_node_aligned` auto-handling) and **drop** the config sprawl.

---

## Conventions

- **Struct layout:** all BPF and shared structs order fields largest-alignment-
  first to minimize padding (hot per-task/per-CPU structs especially). Keep
  `bool`/`u8` flags grouped at the tail.
- **Config:** grouped `const volatile` structs (p2dq-style), populated from
  userspace before load. Small knob surface (principle #7).
- **Reuse:** prefer extracting shared logic into `lib/` modules over
  per-scheduler copies (principle #9).

## 2. Core architecture

```
                    ┌─────────────────────── userspace (Rust) ───────────────────────┐
                    │  topology (scx_utils + gpu-topology)   IRQ map (/proc/irq)      │
                    │  class config -> const volatile structs    metrics (scx_stats)  │
                    └───────────────┬──────────────────────────────┬─────────────────┘
                                    │ load skel / rodata            │ periodic refresh
                                    ▼                               ▼
   ┌──────────────────────────────── BPF ──────────────────────────────────────────┐
   │  lib/soft_affinity (bpf_cpumask domains: proximal/preferred/spill)              │
   │                                                                                 │
   │  classify(task) -> class_id  ──►  soft_affinity_domain[class]                   │
   │       pick_idle: GPU-proximal mask ► preferred mask ► spill ► remote node       │
   │  DSQs: per-(class, LLC) + per-CPU affn DSQ + hi/lo fallback                     │
   │  IRQ accounting hooks  ──►  per-CPU irq_ns ► util compensation + steer hints    │
   └─────────────────────────────────────────────────────────────────────────────────┘
```

The scheduler is a **class-based** layered scheduler. Instead of arbitrary
user-defined layers, `scx_atlas` ships a small fixed set of **scheduling
classes** that map to the AI-training workload shape, each backed by a reusable
`soft_affinity_domain`.

### Scheduling classes (fixed, minimal — principle #7)

| Class | Role | Kind | Key behavior |
|---|---|---|---|
| `LATENCY` | PyTorch GPU-polling / kernel-launch threads | Grouped + `preempt` + `protected`, **one sub-domain per GPU** | each thread bound to its GPU's **proximal mask**, can preempt, low spill |
| `PREP` | data-loading / transform workers | Confined (per-NUMA) | hard-isolated to its NUMA node(s), never steals latency CPUs |
| `TRAINING` | training-stack support threads | Grouped | spills broadly, node-spread growth |
| `SYSTEM` | everything else / unprivileged | Open | runs on unprotected CPUs only |

This mirrors your example config (PyTorch / Local Data Loading per node /
Training Stack / Unprivileged) but as built-in classes rather than free-form
JSON, so the config surface stays maintainable. Per-node PREP "shards" are
generated automatically from topology (one Confined domain per NUMA node) rather
than hand-written per node.

**Scope (decided): strict classes are deferred; comm matching removed.** We do
NOT need a rigid taxonomy or layered's comm-prefix matching (brittle: 15-char
comm, not a stable identity, races fork/exec). **Classification is GPU-driven**:
a per-CPU-kthread → SYSTEM, a GPU-using process (via `gpu_tgid`) → LATENCY,
everything else → SYSTEM, computed **live** (no caching, so a process that starts
using a GPU is promoted promptly). The `tgid_home` map remains as an explicit
override hook.

**cgroup classification — FUTURE FEATURE (backburnered), minimal userspace
plumbing in place.** A `cgroup_class` BPF hash (`cgroup id -> class`) is consulted
by `classify_task` (BPF reads `BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, id)`), and
userspace can populate it by regex-matching cgroup paths (`--training-cgroup` /
`--prep-cgroup`, one regex each: `^x`=prefix, `x$`=suffix, unanchored=substr).
Inert by default (empty patterns). Task cgroup-moves are handled automatically
(live id read). Priority: kthread → SYSTEM; `tgid_home` override; GPU → LATENCY;
cgroup_class; else SYSTEM.

NOTE: layered-style *BPF-side* live path matching (`format_cgrp_path` + prefix/
suffix/substr) was attempted but the BPF verifier rejects the variable
offset+size path build when `__always_inline`d into `select_cpu` (`off`/`size`
tracked independently → `off+size > buf`). The fix is layered's: keep
`format_cgrp_path` a `__hidden` (non-inlined) subprog so it verifies in isolation
— deferred until cgroup matching is resumed.

**EEVDF/CFS-style knobs (added):** `--slice-us-default` (base slice, cf. EEVDF
`base_slice`), `--min-slice-us` (floor, cf. CFS `min_granularity`), `--slice-lag-us`
(max sleeper vtime credit, cf. EEVDF lag / CFS sleeper fairness — bounds how far
behind a waking task's vtime can be), plus `--slice-us-latency` for the LATENCY
class.

**Load-aware (regime-scaled) time slice — IMPLEMENTED (lavd/cosmos-style).** The
class base slice is the *maximum*; under saturation it scales **down** toward the
`--min-slice-us` floor so a full round of an LLC's runqueue stays bounded. In
`running()` (where the actual CPU/LLC is known) the slice is set to
`base × llc_nr_cpus / nr_queued(llc)`, clamped to `[min_slice, base]`: at light
load (`nr_queued ≤ ncpu`) it's the full base (throughput); when an LLC is N×
oversubscribed each task runs ≈ `base/N` so one round ≈ `base`. This is the fix
for **runnable-task stalls under saturation** (found via a 64-affinitized-process
oversaturation test: a task pinned to a single, saturated CPU sat at its DSQ head
but waited through too many full slices and tripped the watchdog). Shortening
slices services the head task — pinned or not — within ~one base slice **without
giving it any priority** (a deliberate choice: routing pinned tasks to a local
queue with a kick was rejected as over-prioritizing them). `task_ctx.slice_ns`
records the assigned slice so `stopping()` charges the true consumed time. A
per-CPU `nr_pinned_tasks` counter (lavd) to shrink slices *harder* when pinned
tasks wait is a possible future refinement; plain load scaling sufficed.

**Affinity safety (decided/verified).** Affinitized tasks can't be stranded: the
home idle-pick always intersects `p->cpus_ptr` (and an affinity-restricted task
with no usable allocated home falls back to a tgid-hashed scan over the LLCs it
*can* run on — spread by the hashed start, not piled on the first). The mempolicy
node override likewise only routes to a node-local LLC the task can run on. On an
affinity change the kernel either keeps `task_cpu` valid (its LLC stays
consumable) or `move_queued_task` dequeues the task from its DSQ and re-enqueues
it — so our enqueue (which routes by live `task_cpu`) always re-homes it; and
`consume_dispatch_q` skips non-runnable head tasks, so a pinned task never blocks a
DSQ.

**Spatial isolation vs. temporal priority (decided).** Two orthogonal
mechanisms, deliberately not conflated:
- *Spatial* — which CPUs a class may use — is the soft-affinity cpumask
  (proximal/preferred/spill). This keeps PREP off LATENCY/GPU CPUs.
- *Temporal* — who runs first under contention — is **per-class vtime scaling**
  (lavd-style), NOT separate per-class priority DSQs. Each LLC has one
  vtime-ordered DSQ; a task's vtime advances by `used_time * 100 / weight`, and
  LATENCY gets a high class weight so its vtime grows slowly and it sorts ahead.
  This avoids the starvation of strict priority draining (a starved task's vtime
  falls behind and eventually wins) and gives a continuous knob. The static
  per-class weight is later replaced by the per-task lavd latency-criticality
  score below.

  Keeping **one DSQ per LLC** (not per-(class,LLC)) is also a deliberate
  *fewer-queues* choice: less state, simpler dispatch/stealing, fewer empty
  queues to scan. Priority lives in the vtime ordering inside that single queue,
  not in queue structure.

**LATENCY prioritization — import scx_lavd's latency-criticality model.**
Rather than invent a priority signal, the LATENCY class borrows scx_lavd's
per-task *latency-criticality* scoring (derived from wait/run frequencies, sleep
behavior, and the IRQ-woken flags — `LAVD_FLAG_WOKEN_BY_HARDIRQ/SOFTIRQ`, which
also feed Phase 5 IRQ awareness). The score drives: (a) ordering within a
LATENCY sub-domain's DSQ (most latency-critical first), and (b) preemption
aggressiveness. This keeps GPU-polling/launch threads ahead of bulk work without
hand-tuned per-thread knobs. Ported as a small reusable helper (candidate for
`lib/`), not a fork of lavd.

**LATENCY is sharded one sub-domain per GPU** (decided): on an 8×GPU host we
allocate 8 `soft_affinity_domain`s, each with `proximal` = that GPU's near-CPU
set and its own per-LLC DSQs. A GPU-active thread is routed to the sub-domain of
the GPU it actually drives (§5), giving clean per-accelerator isolation and
keeping a thread's run CPU electrically close to its device. All LATENCY
sub-domains share the `protected`/`preempt` policy; they're sized independently
from per-GPU thread utilization.

---

## 2.1 Two affinity keys: cgroup selects the class, tgid selects the home (decided)

Soft affinity operates at two granularities:

- **Class assignment is keyed by cgroup / comm / gpu-pid.** Which *policy* a thread
  gets (LATENCY/PREP/TRAINING/SYSTEM) is decided by the match table — cgroup is
  the natural key (a workload is `workload.slice`; matches the example config's
  `CgroupPrefix`/`CommPrefix`).

- **Placement stickiness is keyed by tgid.** Which *home* a thread clusters on
  (per-GPU LATENCY sub-domain / LLC) is keyed by thread-group id, so all threads
  of one process stay together. Rationale — they share one `mm_struct`:
  - shared page tables / TLB / page-walk caches stay warm when clustered on one LLC;
  - **TLB shootdowns** shrink: an address-space change (`munmap`, THP collapse,
    CUDA pinned-memory maps) IPIs *every CPU running a thread of that mm*. Confining
    a process to its home LLC bounds the shootdown set instead of spraying IPIs
    across every LLC the process landed on — a real win for allocator-churny
    PyTorch processes.
  - tgid-home aligns with per-GPU LATENCY sub-domains: a trainer process maps to
    its GPU's sub-domain and its threads inherit that home.

Mechanism: a `tgid -> home` BPF hash (`tgid_home`, implemented), consulted on
each classification so all threads of a process share one class/home, with a
`set_tgid_home(tgid, class)` override. **GPU detection updates this map**: when a
process is detected using a GPU (Phase 4 kprobe/uprobe), it calls
`set_tgid_home(tgid, LATENCY)` (or the GPU's sub-domain), so the whole tgid — and
every thread that classifies afterward — is promoted to the GPU's home. cgroup is
the matcher; tgid is the locality key. Affinitized threads (§6) still override
when their CPU mask is narrower than the home.

**A home is a sized domain that may span multiple CPUs/LLCs (decided).** A process
with many threads cannot fit on one LLC, so its home is not a single LLC but a
`soft_affinity_domain` whose `preferred` mask is *grown to fit* the process's
thread count / utilization — spanning several LLCs when needed. Sizing policy:
keep the span **within one NUMA node** as long as it fits (bounds TLB-shootdown
IPIs and keeps page-table-walk traffic node-local), and only spill across nodes
for very large processes. So tgid-home ranges from "one LLC" (small process) to
"several LLCs within a node" (large trainer) to "multi-node" (giant), always the
smallest span that holds the threads. This is exactly what `saf_resize` provides —
the home grows/shrinks with the process's measured utilization.

**`saf_resize` — IMPLEMENTED (utilization-driven per-tgid LLC allocator).** Each
process (tgid) is the soft-affinity group, and its home is a **set of whole LLCs**
(a `u64` bitmask, one bit per LLC id). BPF accumulates the group's CPU runtime in
a `tgid_dom` map (`tgid -> {runtime, llc_mask}`): `atlas_stopping` does
`__sync_fetch_and_add(&g->runtime, used)`, `atlas_exit_task` deletes the entry
when the group leader exits.

*Topology, no assumptions.* Per-LLC CPU masks are built at `atlas_init` straight
from the real `cpu->LLC` mapping, so an LLC that is non-contiguous in CPU id
(SMT siblings, split ranges — e.g. this host's `0-7,88-95`) is captured exactly.
A home is therefore expressed in LLCs, never as a CPU-id range.

*The allocator* (`plan_saf_homes()`, pure + unit-tested; run by
`resize_saf_homes` every `SAF_RESIZE_SECS`, gated by `--autosize`): for each
*active* group it sizes the home as `ceil(cpus_busy * nr_llcs / nr_cpus)` LLCs
(clamped `[1, nr_llcs]`), then **places** it on the *least-loaded* LLCs, tracking
a per-LLC load accumulator so homes spread across the machine's caches and, under
oversaturation, overlap *evenly* rather than stacking. Shares are **uniform**
(demand-only) for now; class-weighted shares are a planned refinement. Overlap is
allowed by design — these are soft hints, never exclusive ownership (that would
starve processes on an N-LLC box with thousands of processes).

*Cost control (host can have thousands of processes).* Only groups using **≥ one
LLC's worth of CPU** per interval get an allocated home — the allocator's working
set is the heavy hitters (training jobs), not every process. Idle homes are
cleared and entries pruned after `SAF_PRUNE_INTERVALS` idle passes. Every other
process still gets **LLC stickiness for free**: when a tgid has no allocated home,
the hot path defaults it to a single LLC `1 << (tgid % nr_llcs)` — computed in
BPF, zero userspace cost, and tgid-keyed so all of a process's threads share one
LLC (a *random* pick would scatter siblings and defeat cache locality).

*Hot path.* `tgid_pick_idle_cpu()` (called first in `select_cpu`, before the
class domain) ORs the home's LLC masks into the task's `eff` scratch mask,
intersects with `p->cpus_ptr`, and `scx_bpf_pick_idle_cpu`s within it; hits are
the `home` stat. If the bitmask OR loop ever profiles hot, the planned
optimization is to cache the resolved cpumask per-task (kptr + a generation
counter bumped when the allocator changes the mask). The runtime field is
BPF-owned (atomic add); userspace preserves it on write-back (tiny lost-update
window accepted for the prototype).

## 3. Reusable module: `lib/soft_affinity` (principle #9) — IMPLEMENTED

The central reuse target: distill layered's "a domain owns a CPU set, tasks
prefer it but can spill" logic into a small, header-only, dependency-light module
any scheduler can include.

**Type — `bpf_cpumask` kptr masks, embedded in a BPF map value** (so the map
manages mask lifetime):

```c
// scheds/include/lib/soft_affinity.h
struct soft_affinity_domain {
    struct bpf_cpumask __kptr *preferred;  // the soft-affinity home (grown/shrunk)
    struct bpf_cpumask __kptr *spill;      // overflow set when preferred is busy
    struct bpf_cpumask __kptr *proximal;   // checked first (e.g. GPU-near CPUs)
};
```

**Why `bpf_cpumask`, not arena cpumasks:** the distinct masks are a *bounded*
set (classes × LLCs × GPU sub-domains), and tgid-home is just a `tgid -> u32`
id into that bounded pool — so no dynamic/unbounded mask allocation is needed.
`bpf_cpumask` also intersects natively and verifier-safely with a task's kernel
mask (`bpf_cpumask_and(scratch, preferred, p->cpus_ptr)`), which is the hot-path
operation. This keeps the module simple and dependency-free.

**API (header-only static-inline helpers):**
- `saf_mask_create(&dom->preferred, setall)` — create/install a mask (optionally
  filled); `saf_domain_free(dom)` — release.
- `saf_pick_idle_cpu(dom, task_cpus, scratch, flags)` — the soft-affinity search:
  `proximal ∩ task` → `preferred ∩ task` → `spill ∩ task` → -1, using a
  caller-owned `scratch` bpf_cpumask to materialize each intersection and
  `scx_bpf_pick_idle_cpu`. This is the reusable distillation of layered's
  `pick_idle_cpu()` (`scx_layered/.../main.bpf.c:1350`).
- `saf_resize` is IMPLEMENTED at the scheduler level via the per-tgid `tgid_dom`
  map + `tgid_pick_idle_cpu()` + userspace `plan_saf_homes()` (see §2), rather
  than as a mask-growth helper inside this module. A future refinement could port
  layered's growth orderings (Sticky, Reverse, NodeSpread*, Topo…) to align home
  `base` to NUMA/LLC boundaries; `saf_set_proximal` for GPU masks is still TODO.

**Wiring in scx_atlas:** per-class domains live in a `class_doms` BPF array map
(one per scheduling class), created in `init`. Each task carries a per-task
`eff` scratch bpf_cpumask (allocated in `init_task`, freed in `exit_task`).
`select_cpu` calls `saf_pick_idle_cpu(dom, p->cpus_ptr, taskc->eff, 0)` as the
primary idle-CPU selector, falling back to `scx_bpf_select_cpu_dfl`. Verified on
the live kernel: the soft-affinity path is the dominant idle selector.

**Win:** layered itself could later be refactored onto this module; it lives
under `lib/` so it's importable by any scheduler.

---

## 4. Topology model (principles #11, #12)

Reuse `lib/topology` (BPF) + `scx_utils::Topology` (Rust). Hierarchy:
**NODE → LLC → CORE → CPU**, with each CPU resolvable to LLC id and NUMA id.

**Placement input — NUMA mempolicy (steal from scx_rusty).** A task's NUMA
memory policy (`task->mempolicy` nodemask, as rusty reads) tells us where its
memory actually lives — a strong placement signal for training (tensors/pinned
buffers bound to nodes). Fold the mempolicy nodemask into soft-affinity: bias a
task's `preferred`/home toward CPUs on its mempolicy nodes so compute follows
memory (fewer cross-node accesses, fewer remote-page faults). For an mbind/
`MPOL_BIND` task this is effectively a hard node constraint we should honor;
for `MPOL_PREFERRED` it's a soft bias layered under the existing
proximal→preferred→spill search.

**IMPLEMENTED.** Mechanism (from rusty `task_set_preferred_mempolicy_dom_mask`):
`mp = BPF_CORE_READ(p, mempolicy)`; if non-NULL and
`mp->mode & (MPOL_BIND|MPOL_PREFERRED|MPOL_PREFERRED_MANY)`, use `mp->home_node`
when `>= 0`, else the first node set in `mp->nodes.bits`. In atlas:
- Per-node `bpf_cpumask`s are built in `init` (from `cpu_node_ids`).
- The preferred node + a `pref_bind` flag are **cached in `task_ctx`**, refreshed
  live in `select_cpu` and updated by a `tp/syscalls/sys_exit_set_mempolicy`
  tracepoint. NOTE: a live refresh is required because **inherited** mempolicy
  (parent sets policy, children inherit at fork) is visible *neither* at
  `init_task` (runs before the child's mempolicy is dup'd) *nor* via the
  tracepoint (no syscall fires for inheritance) — same fork-timing trap as comm.
- **CXL / tiered-memory guard:** a preferred node with no CPUs (CXL memory node)
  resolves to "no preference" (`node_has_cpu[]` check in `refresh_pref_node`), so
  we never route compute to a CPU-less node. (Mapping a CXL node to its nearest
  CPU node by NUMA distance is a follow-up.) Caveat: some machines are 2-NUMA
  where node 1 is CXL-only.
- `select_cpu` tries an idle CPU on the preferred node first (`saf_pick_node`,
  `mempol` stat); `enqueue` routes the task to a node-local LLC when its CPU is
  off-node. **MPOL_BIND contains** (skips the off-node soft-affinity spill);
  MPOL_PREFERRED is a soft bias falling through to proximal→preferred→spill.
- The `set_mempolicy` tracepoint is attached by `scx_ops_attach!` (it links
  non-struct_ops progs too — don't attach it manually, that double-attaches).
- Verified on the live kernel (single CPU node): `numactl --preferred=0` workers
  drive the `mempol` path. Gated by `--mempolicy-aware` (default on).

**DSQ layout** (combining layered + p2dq patterns):
- **Per-(class, LLC) DSQ** — `dsq_id = (class_id << SHIFT) | llc_id`. Keeps work
  cache-local and lets us shard a class across LLCs (principle #11).
- **Per-CPU "affinitized" DSQ** — for tasks pinned tighter than a NUMA node
  (principle #13, see §6).
- **hi / lo fallback DSQ per LLC** — for tasks that can't safely sit on a class
  DSQ, and for kthreads / high-priority escapes (layered's `hi_fb`/`lo_fb`).
- Optional **per-LLC shards** for very large LLCs (p2dq's `llc_shards`) — split a
  class DSQ into `core_id % nr_shards` sub-queues to cut enqueue contention.

**Load balancing across LLC/NUMA (principle #12):** two complementary layers,
matching what the codebase already proves out:
1. **Soft, continuous (BPF):** p2dq-style **pick-2** on dispatch — sample two
   LLCs, steal from the more-loaded one past a slack threshold, gated by a
   cross-NUMA token bucket so we don't thrash memory locality.
2. **Coarse, periodic (userspace):** every interval, recompute per-class CPU
   targets from measured utilization and `saf_resize()` each domain — this is
   layered's `unified_alloc()` water-fill, weight-aware. For training-wide
   fairness we can optionally fold in the `infeasible` crate (as scx_rusty does)
   so a class's weight is capped by its real duty cycle.

NodeSpread growth is the default for `TRAINING`/`LATENCY` (predictable per-node
CPU counts — good for bandwidth-bound replicated work); per-node Confined for `PREP`.

---

## 5. GPU awareness & GPU-proximal mask (principles #6, #10)

**BPF consumption side — IMPLEMENTED.** A `gpu_tgid` BPF hash (`tgid -> GPU NUMA
node`, or `ATLAS_NODE_UNKNOWN`) is the interface the detector populates. The
scheduler reads it: a GPU tgid is classified **LATENCY** (`classify_comm`), and
its placement is **biased to the GPU's NUMA node** (`refresh_pref_node`, takes
precedence over mempolicy; reuses the per-node masks + `node_has_cpu` CXL guard).
This is verified to load/run; with an empty map it's a no-op. Everything below
(the detector that *fills* `gpu_tgid`) is deferred — it can't be verified without
a GPU — and `gpu_tgid` can be populated externally (even by hand) for testing.

**Detector — IMPLEMENTED. Two mechanisms; probes are the default.**

*Probes (default on, `--gpu-probes`, default true):* optional `?kprobe`s on rare
nvidia driver entry points (`nvidia_open`, `nvidia_mmap`) stamp the calling
process into `gpu_tgid`. They fire at GPU setup (rare) so steady-state overhead is
negligible — no per-launch cost, so the detach-when-stable dance isn't needed for
these. KEY: a `?`/optional SEC does **not** make auto-attach non-fatal under
`scx_ops_attach!` — attaching a kprobe whose symbol is absent fails with
`-ENOENT`. So userspace **gates autoload on `ksym_exists("nvidia_open"/"…mmap")`**:
default-on on hosts with the nvidia driver, a clean no-op everywhere else.
`gpu_tgid` is cleaned up in `exit_task` when the process (group leader) exits.

*Poller (opt-in, `--enable-gpu-poller`, off by default):* the run loop every
`--gpu-poll-secs` (default 2) diffs a `/proc/<pid>/fd` scan for open
`/dev/nvidia*` / `/dev/dri/renderD*` and updates `gpu_tgid`. Useful where probes
can't attach, or for non-nvidia accelerators.

Both currently write node `UNKNOWN` → GPU tgids get LATENCY classification but no
node bias yet. Verified on this (GPU-less) box: probes default-on load cleanly
(symbols absent → skipped), poller runs and finds 0; end-to-end GPU classification
needs a GPU host.
- TODO node resolution (enables GPU-node placement bias): **NVML**
  `nvmlDeviceGetComputeRunningProcesses` per GPU → `gpu_tgid[pid] = node_of(gpu)`;
  or parse `/dev/nvidia<N>` minor → GPU index → sysfs `numa_node`.
- TODO (only if short-lived GPU tasks ever matter): CUDA/NCCL uprobes + ring
  buffer + detach-when-`gpu_pids == num_gpus`.

**Ring buffer / probes — deferred (only if sub-second detection of short-lived
GPU tasks is ever needed).** "Ring buffer" and "probes" are the same decision: a
ring buffer only earns its keep when a high-frequency uprobe (`cudaLaunchKernel`
fires thousands/sec) needs to push events — which we're not doing. If added
later: the uprobe pushes a **deduped, once-per-new-tgid** event via ringbuffer
(never per-launch), and **detaches once `detected_gpu_pids == num_gpus`** (every
GPU has its owning process; `num_gpus` from GPU-topology) for zero steady-state
overhead, re-attaching only on churn. `--gpu-detect-mode` selects poll vs. probe.

**Discovery (userspace):** use `scx_utils` `gpu-topology` feature
(`Node.gpus`, `create_gpus()`) to build a `GpuIndex → NUMA node` map (and
`num_gpus`), extended where possible with PCIe/NVLink locality so "closest CPUs"
is sharper than "same NUMA node."

**GPU-proximal cpumask (principle #10):** for each GPU, build a `bpf_cpumask`
`gpu_proximal[gpu]` = CPUs on the GPU's NUMA node (refined by PCIe distance).
Install it as the `proximal` set of the GPU's `LATENCY` sub-domain.
`saf_pick_idle_cpu` checks
`proximal` *first*, so a GPU-polling thread lands on a core electrically close to
the device it drives.

**PID/TID awareness (principle #6):** two complementary probe sources populate
the `gpu_tgid` / `gpu_tid` BPF maps; classification matches
`UsedGpuPid`/`UsedGpuTid` to route a thread into `LATENCY` and to the right
per-GPU sub-domain. Userspace periodically refreshes the pid→gpu→node mapping
(`GpuTaskAffinitizer` pattern).

1. **kprobes on GPU driver entry points** — layered's existing mechanism, catches
   GPU activity at the kernel boundary (coarse, driver-version sensitive).
2. **uprobes on userspace CUDA/NCCL launch APIs** (NEW) — catch the launch at the
   application level, which is the most precise signal that *this TID* is a
   kernel-launching thread. A shared `handle_cuda_launch_common()` stamps
   `gpu_tid`/`gpu_tgid`:

   ```c
   SEC("uprobe/libcudart.so/cudaLaunchKernel")
   int BPF_KPROBE(handle_cuda_launch)      { return handle_cuda_launch_common(); }

   SEC("uprobe/libnccl.so/cudaLaunchKernelExC")
   int BPF_KPROBE(handle_cuda_launch_exc)  { return handle_cuda_launch_common(); }
   ```

   `handle_cuda_launch_common()` records the calling TID + TGID and a timestamp;
   membership expires after a configurable window so threads that stop launching
   drift back out of `LATENCY`. The uprobe targets (lib path + symbol) are
   resolved in userspace at attach time and made configurable
   (`--cuda-lib`, `--nccl-lib`) since paths vary by container image; kprobes
   remain the fallback when the libs can't be located. Attaching uprobes to the
   right GPU device for sub-domain routing uses the same pid→gpu map as the
   kprobe path — the launch event tells us *which* thread is hot; the GPU it
   targets comes from the userspace pid→device discovery.

**Reducing hot-path cost — detection modes (`--gpu-detect-mode`, principle #7):**
A uprobe on `cudaLaunchKernel` fires on *every* kernel launch — potentially
thousands/sec on precisely the latency threads we want to shield. Detection is
therefore decoupled from the launch hot path and made configurable:

- **`uprobe-light` (default):** the uprobe does the *minimum possible* work — a
  single store of `now()` into the **calling task's own task ctx**
  (`taskc->last_gpu_launch_ns`), which is already cache-hot in the launching
  thread. No global map write, no spinlock, no classification on the hot path.
  A periodic **`bpf_timer`** (e.g. every 50–100 ms) does the expensive part off
  the hot path: scan task ctxs, **promote** threads whose `last_gpu_launch_ns` is
  recent into `gpu_tid`/`gpu_tgid` + assign the per-GPU sub-domain, and **expire**
  stale ones. Per-launch cost collapses to one store; map churn and routing
  happen at timer cadence.
- **`fd-scan` (zero hot-path):** no uprobe at all. A **userspace timer** walks
  `/proc/<pid>/task/*/fd` for open `/dev/nvidia*` / accel handles to seed
  `gpu_tgid`, and uses the existing pid→device map for sub-domain routing.
  Coarser (an open FD ≠ actively launching) but adds *nothing* to the hot path —
  good for the most latency-sensitive deployments or where uprobe attach is
  blocked (stripped/missing libs, locked-down containers).
- **`uprobe-precise` (opt-in):** the original behavior — uprobe stamps the global
  maps directly on each launch. Highest fidelity, highest overhead; for debugging
  or short-lived profiling, not steady-state.

The timer cadence and membership-expiry window are the same knob
(`--gpu-membership-ms`) reused across modes, so the surface stays small.

---

## 6. Affinitized PyTorch threads (principle #13)

PyTorch commonly pins worker/comm threads. The key live mechanism (verified):
`allow_node_aligned` is **deprecated**; the scheduler now computes
`cpus_node_aligned` automatically — true when a task's CPU affinity covers
*whole NUMA nodes* (`main.bpf.c:3813`, `:2115`). Such tasks can always be served
from class (per-LLC) DSQs because per-node allocation guarantees the class will
have CPUs on those nodes.

`scx_atlas` policy:
- **Node-aligned affinity** (covers whole node(s)) → stays on its class's
  per-(class, LLC) DSQs. Full soft-affinity + load-balancing benefits.
- **Sub-node affinity** (pinned to specific cores, narrower than a node) →
  routed to the **per-CPU affinitized DSQ** so it is never starved by class CPU
  reshaping, and is excluded from cross-LLC stealing.
- A small named-thread fast path (layered's `hi_fb_thread_name`) lets us pin one
  known ultra-latency thread (e.g. the CUDA submission thread) to the hi
  fallback DSQ for minimal queueing delay.

This means hard-affinitized training threads "just work" without per-thread
config.

---

## 7. IRQ accounting & affinitization (principle #5)

**Accounting — cheap /proc/stat read, IMPLEMENTED (off by default).** We
deliberately do **not** measure IRQ time with `irq_handler_*`/`softirq_*`
tracepoints: those fire on every IRQ/softirq (potentially millions/sec on a
NIC-heavy host) and would add cost to the very IRQ hot path we're protecting
latency from — and we don't need per-IRQ precision for placement. Instead, a
userspace reader parses **`/proc/stat`** per-CPU `irq`+`softirq` each interval
(the kernel already accounts it — near-free, off the hot path), deltas it, and
writes per-CPU load (per-mille) into the `cpu_irq_busy` BPF array. The scheduler
reads it: `dispatch` won't pile *stolen* work onto a CPU whose IRQ load is over
`irq_busy_thresh` (it isn't really idle). Gated by `--irq-accounting` (off by
default; when off the array stays 0 → no behavior change). Verified to load/run.
Next: also use it in `select_cpu` to deprioritize IRQ-heavy CPUs for LATENCY, and
optionally subtract IRQ load from class utilization for `saf_resize`.

**Affinitization (userspace):** reuse `scx_utils::netdev` `/proc/irq/*/smp_affinity`
read/write. Policy:
- Steer NIC/NVMe IRQs **off** `LATENCY`/GPU-proximal CPUs (protect GPU pollers
  from IRQ jitter).
- Optionally **co-locate** storage/decode IRQs **onto** `PREP` CPUs (data loaders
  are already the consumers; cache-warm).
- Expose as a global on/off knob (`--manage-irq-affinity`) — off by default,
  since rewriting IRQ affinity is intrusive.

Per-CPU IRQ pressure also feeds the pick-2 balancer as a tie-breaker (avoid
CPUs with high recent IRQ load for latency-class steals).

---

## 8. Configuration (principle #8 — p2dq-style structs)

Follow p2dq's **grouped `const volatile` structs in `.rodata`**, populated from
clap args via an `init_open_skel!` macro. Keep the knob count small (principle #7).

```c
const volatile struct { u32 nr_cpus, nr_llcs, nr_nodes; bool smt; } topo_config;

const volatile struct {                 // global behavior
    u64 slice_us_latency, slice_us_default;
    u32 saturated_percent;              // when to allow class spill
    u64 xnuma_slack_pct;               // cross-NUMA steal gate
    u32 llc_shards;                    // 0 = auto
    bool manage_irq_affinity;
    bool enable_gpu_support;
} atlas_config;

const volatile struct {                 // per-class tunables, indexed by class_id
    u32  kind;                          // GROUPED/CONFINED/OPEN
    u32  growth_algo;
    u32  weight;
    u32  util_lo_pct, util_hi_pct;     // grow/shrink band
    bool preempt, protected;
    s32  node;                          // for per-node CONFINED shards (PREP)
} class_config[NR_CLASSES];
```

Classification rules (which thread → which class) live in a compact, ordered
match table — reusing layered's match kinds (`UsedGpuPid`, `CommPrefix`,
`PcommPrefix`, `CgroupPrefix`, `NumaNode`, `IsGroupLeader`) so your existing
config semantics carry over — but the *set of classes* is fixed, so operators
tune ~4 classes + a handful of globals, not N free-form layers.

---

## 9. Metrics & observability (principle #14)

Use the `scx_stats` framework (like every Rust sched). Emit:
- **Per class:** nr_cpus owned, util (owned vs. spilled), DSQ depth & latency,
  preemptions issued/received, affinity violations.
- **Per LLC/NUMA:** queue depth, cross-LLC steals, cross-NUMA migrations,
  load imbalance.
- **GPU:** per-GPU proximal-hit rate (latency threads that landed on a proximal
  CPU vs. spilled), pid→gpu mapping size.
- **IRQ:** per-CPU hardirq/softirq ns, IRQ-affinity changes applied.
- **Latency SLO:** wakeup→run latency histogram for `LATENCY` class (the headline
  metric for GPU-polling responsiveness).

Wire into `scxtop` (the repo's MCP/analyzer tooling already understands DSQ
latency, IRQ, LLC locality, preemptions) for live drill-down.

---

## 10. Implementation roadmap

**Phase 0 — skeleton & config.** New crate `scheds/rust/scx_atlas`. p2dq-style
`const volatile` config + `init_open_skel!`. Topology load into `lib/topology`.
Boots, runs everything as one Open class. *Exit:* loads & schedules a busy loop.

**Phase 1 — `lib/soft_affinity` module.** *(DONE: header-only `bpf_cpumask`
module at `scheds/include/lib/soft_affinity.h`; per-class domains in a
`class_doms` map; per-task `eff` scratch; `saf_pick_idle_cpu` wired as the
primary idle selector in `select_cpu` and verified the dominant path on the live
kernel.)* Remaining: port growth orderings from `layer_core_growth.rs`
(userspace-driven `saf_resize`) and scxtest unit coverage.

**Phase 2 — fixed classes + DSQs.** *(2a DONE: per-LLC DSQs + LLC-local dispatch
+ per-task class storage. 2b DONE: live (post-exec) comm-prefix classification,
process-consistent via a `tgid_home` map with a `set_tgid_home()` override hook
for GPU detection, distinct per-class `preferred` masks — PREP confined to NUMA
node 0 as a placeholder — and per-class enqueue/dispatch counters. Verified:
`sleep`→LATENCY, `stress`→PREP on the live kernel.)* Remaining: per-(class,LLC)
DSQs, per-CPU affn DSQ + `cpus_node_aligned` routing (§6), real per-node PREP sub-domains, and LATENCY DSQ ordering via the lavd
latency-criticality score. **cgroup classification DONE** (TRAINING/PREP via
`--training-cgroup`/`--prep-cgroup`, see §2.1). **LATENCY preemption DONE**: a LATENCY task with no
idle CPU preempts a lower-class task on its previous CPU (`SCX_ENQ_PREEMPT` +
`scx_bpf_kick_cpu`, per-CPU running-class tracked in `running`), gated by
`--preempt-latency`; `preempt` stat. **comm matching removed** (see §2.1).
*Exit:* PREP isolated to its NUMA node, LATENCY preempts, SYSTEM on open CPUs.

**Temporal priority — DONE.** Per-LLC DSQs are vtime-ordered; `running`/`stopping`
maintain the per-LLC vtime clock and charge `used*100/weight`, with a high
LATENCY class weight. Verified on the live kernel. (Replaces the per-class
priority-DSQ idea — fewer queues, no starvation.)

**Phase 3 — load balancing.** *(DONE: tiered pick-2 in dispatch — local LLC
first, then Tier 1 pick-2 among LLCs in the local NUMA node (steal from the
busier of two random LLCs), then Tier 2 cross-NUMA steal from the **tail**
(`SCX_DSQ_ITER_REV`, least-urgent) of a remote LLC, skipping tasks that migrated
NUMA within `--xnuma-mig-min-us` (default 1ms) and CPU-less CXL nodes. NUMA
migrations tracked in `running`; `steal`/`xnuma_steal` stats. Verified: Tier-1
steals fire; Tier-2 loads (single-node box → 0, as expected).)* Remaining:
periodic userspace `saf_resize` from utilization; optional infeasible weights.

*Exit:* imbalance metric converges under skewed load.

**Phase 4 — GPU awareness.** *(DONE: `gpu_tgid` map → LATENCY class + GPU-node
placement bias (CXL-guarded); detectors implemented — nvidia-driver kprobes
default-on gated on `ksym_exists`, plus an opt-in `/proc` poller; map cleanup on
exit. Verified to load/run on a GPU-less box.)* Remaining (needs a GPU host):
node resolution (NVML / sysfs) to activate the placement bias; optional per-GPU
LATENCY sub-domains + proximal masks; CUDA/NCCL uprobes only if short-lived GPU
tasks ever need sub-second detection. *Exit:* GPU processes land on their GPU's
node.

**Phase 5 — IRQ awareness.** *(First cut DONE: cheap /proc/stat per-CPU IRQ load
→ `cpu_irq_busy` map → dispatch avoids stealing onto IRQ-saturated CPUs; behind
`--irq-accounting`, off by default. Rejected per-IRQ tracepoints as too costly.)*
Remaining: select_cpu deprioritization + util compensation; optional
IRQ affinitization off latency CPUs. *Exit:* IRQ ns visible per-CPU; latency-class
wakeup latency improves with steering on.

**Phase 6 — metrics, tuning, hardening.** Full `scx_stats` surface, scxtop
integration, latency SLO histogram, soak under a real training + preprocessing mix.

---

## 11. Open questions / decisions to confirm

1. ~~Many-GPU hosts: one LATENCY domain or per-GPU sub-domains?~~ **DECIDED:
   one LATENCY sub-domain per GPU** (§2, §3). Revisit only if per-GPU DSQ count
   becomes a scaling problem on very-high-GPU hosts.
2. **PREP isolation strength:** strict Confined (never spill) vs. layered's
   `idle_confined` hybrid (confine until system-saturated, then spill)?
3. **PCIe/NVLink locality:** is per-NUMA "proximal" good enough, or do we need
   sysfs PCIe-distance parsing for sharper GPU↔CPU sets?
4. **Refactor target:** ship `lib/soft_affinity` standalone now, or also port
   `scx_layered` onto it (bigger blast radius, more reuse payoff)?
5. **IRQ steering default:** keep off-by-default given how intrusive rewriting
   `smp_affinity` is on shared hosts?

---

## Appendix: key code references grounding this design

- Soft affinity / pick-idle: `scx_layered/src/bpf/main.bpf.c:1350` (`pick_idle_cpu`),
  growth algos `scx_layered/src/layer_core_growth.rs`, alloc `…/alloc.rs:366` (`unified_alloc`).
- `cpus_node_aligned` (affinitized tasks): `main.bpf.c:3813`, `:2115`; deprecation
  `main.rs:350`.
- p2dq config pattern: `scx_p2dq/src/bpf/main.bpf.c:61-178` (const volatile structs),
  `scx_p2dq/src/lib.rs` `init_open_skel!`; LLC shards `shard_dsq_id` `main.bpf.c:259`.
- Soft affinity: `scheds/include/lib/soft_affinity.h` (this repo); idle-pick
  idiom from layered `main.bpf.c` (per-task effective mask, `bpf_cpumask_and`
  with `p->cpus_ptr`, `scx_bpf_pick_idle_cpu`).
- GPU: `scx_layered` `gpu_tgid`/`gpu_tid` maps + `GpuTaskAffinitizer`;
  `scx_utils/src/topology.rs` `gpu-topology` (`Node.gpus`, `create_gpus`).
  NEW: uprobes on `libcudart.so:cudaLaunchKernel` / `libnccl.so:cudaLaunchKernelExC`
  feeding a shared `handle_cuda_launch_common()` into the same gpu_tid maps.
- IRQ: lavd `bpf_in_hardirq()`/`bpf_in_serving_softirq()`;
  `scx_utils/src/netdev.rs` `/proc/irq/*/smp_affinity`.
- Cross-domain balancing: scx_rusty `load_balance.rs` (`balance_between_nodes`,
  infeasible weights `scx_utils/src/infeasible.rs`); p2dq pick-2 `main.bpf.c`.
</content>
</invoke>
