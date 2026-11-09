// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

use std::collections::{BTreeMap, HashMap};
use std::mem::size_of;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, ProgramInput};

use crate::BpfSkel;
use crate::bpf_intf::{
    LAVD_CPDOM_MAX_NR, LAVD_SOFT_APPLY, LAVD_SOFT_GROUP_MAX_NR, LAVD_SOFT_LLC_WORDS,
    LAVD_SOFT_SAMPLE, soft_affinity_cmd, soft_affinity_key,
};
use crate::cpu_order::CpuOrder;

type LlcMask = [u64; LAVD_SOFT_LLC_WORDS as usize];

#[derive(Clone, Debug)]
struct Llc {
    id: usize,
    node: u32,
    cpus: u64,
}

#[derive(Clone, Debug)]
struct Group {
    tgid: u32,
    node: u32,
    id: u64,
    delta: u64,
    home: LlcMask,
}

fn contains(mask: &LlcMask, llc: usize) -> bool {
    mask[llc / 64] & (1 << (llc % 64)) != 0
}

/// Keep a home that can serve the group's demand, and allocate whole LLCs on
/// the fixed NUMA node when it cannot. Account for unequal LLC sizes.
fn plan_homes(groups: &[Group], llcs: &[Llc], interval_ns: u64) -> Vec<(u64, LlcMask)> {
    let interval_ns = interval_ns.max(1);
    let mut groups: Vec<_> = groups.iter().collect();
    groups.sort_by_key(|group| (std::cmp::Reverse(group.delta), group.tgid, group.node));
    let mut load = vec![0u128; llcs.len()];
    let mut homes = Vec::with_capacity(groups.len());

    for group in groups {
        let mut candidates: Vec<_> = llcs
            .iter()
            .enumerate()
            .filter(|(_, llc)| llc.node == group.node && llc.cpus > 0)
            .map(|(i, _)| i)
            .collect();
        let capacity: u64 = candidates.iter().map(|&i| llcs[i].cpus).sum();
        if capacity == 0 {
            continue;
        }
        let want = group.delta.div_ceil(interval_ns).clamp(1, capacity);
        // Use fractional CPU demand for placement, including sleeping groups.
        let demand = (u128::from(group.delta) * 1000 / u128::from(interval_ns)).max(1);
        let fits_home = |i: usize| {
            contains(&group.home, llcs[i].id) && load[i] + demand <= u128::from(llcs[i].cpus) * 1000
        };
        candidates.sort_by(|&i, &j| {
            fits_home(j)
                .cmp(&fits_home(i))
                .then_with(|| {
                    (load[i] * u128::from(llcs[j].cpus)).cmp(&(load[j] * u128::from(llcs[i].cpus)))
                })
                .then_with(|| {
                    contains(&group.home, llcs[j].id).cmp(&contains(&group.home, llcs[i].id))
                })
                .then(llcs[i].id.cmp(&llcs[j].id))
        });

        let mut home = [0; LAVD_SOFT_LLC_WORDS as usize];
        let mut home_capacity = 0;
        let mut chosen = Vec::new();
        for i in candidates {
            home[llcs[i].id / 64] |= 1 << (llcs[i].id % 64);
            home_capacity += llcs[i].cpus;
            chosen.push(i);
            if home_capacity >= want {
                break;
            }
        }
        for i in chosen {
            load[i] += demand * u128::from(llcs[i].cpus) / u128::from(home_capacity);
        }
        homes.push((group.id, home));
    }
    homes
}

pub struct SoftAffinity {
    llcs: Vec<Llc>,
    previous: HashMap<u64, u64>,
    last_resize: Instant,
}

impl SoftAffinity {
    pub fn new(order: &CpuOrder) -> Result<Self> {
        anyhow::ensure!(
            order.nr_llcs <= LAVD_CPDOM_MAX_NR as usize,
            "Too many LLCs for soft partitioning"
        );
        let mut llcs = BTreeMap::new();
        for cpu in &order.cpuids {
            let llc = llcs.entry(cpu.llc_adx).or_insert(Llc {
                id: cpu.llc_adx,
                node: cpu.numa_adx as u32,
                cpus: 0,
            });
            anyhow::ensure!(
                llc.id < LAVD_CPDOM_MAX_NR as usize && llc.node == cpu.numa_adx as u32,
                "Invalid LLC topology for soft partitioning"
            );
            llc.cpus += 1;
        }
        Ok(Self {
            llcs: llcs.into_values().collect(),
            previous: HashMap::new(),
            last_resize: Instant::now(),
        })
    }

    fn command(skel: &mut BpfSkel<'_>, cmd: &mut soft_affinity_cmd) -> Result<bool> {
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    cmd as *mut _ as *mut u8,
                    size_of::<soft_affinity_cmd>(),
                )
            }),
            ..Default::default()
        };
        let result = skel.progs.lavd_soft_affinity_cmd.test_run(input)?;
        match result.return_value as i32 {
            0 => Ok(true),
            // The last thread can exit, or its PID be reused, during a resize.
            rc if rc == -libc::ENOENT || rc == -libc::ESTALE => Ok(false),
            rc => Err(std::io::Error::from_raw_os_error(-rc)).context("Soft-affinity command"),
        }
    }

    pub fn resize(&mut self, skel: &mut BpfSkel<'_>) -> Result<()> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_resize);
        if elapsed < Duration::from_secs(1) {
            return Ok(());
        }

        // Bound iteration because deleting a hash key can restart GET_NEXT_KEY.
        let keys: Vec<_> = skel
            .maps
            .soft_affinity_groups
            .keys()
            .take(LAVD_SOFT_GROUP_MAX_NR as usize)
            .collect();
        let mut samples = HashMap::new();
        let mut previous = HashMap::new();
        for key in keys {
            let mut cmd = soft_affinity_cmd {
                key: soft_affinity_key {
                    tgid: u32::from_ne_bytes(key[..4].try_into()?),
                    numa_id: u32::from_ne_bytes(key[4..8].try_into()?),
                },
                op: LAVD_SOFT_SAMPLE,
                __pad: 0,
                id: 0,
                runtime: 0,
                llcs: [0; LAVD_SOFT_LLC_WORDS as usize],
            };
            if !Self::command(skel, &mut cmd)? {
                continue;
            }
            let delta = self
                .previous
                .get(&cmd.id)
                .map_or(0, |prev| cmd.runtime.wrapping_sub(*prev));
            previous.insert(cmd.id, cmd.runtime);
            samples.insert(
                cmd.id,
                Group {
                    tgid: cmd.key.tgid,
                    node: cmd.key.numa_id,
                    id: cmd.id,
                    delta,
                    home: cmd.llcs,
                },
            );
        }
        let groups: Vec<_> = samples.values().cloned().collect();
        for (id, home) in plan_homes(&groups, &self.llcs, elapsed.as_nanos() as u64) {
            let group = &samples[&id];
            if home == group.home {
                continue;
            }
            let mut cmd = soft_affinity_cmd {
                key: soft_affinity_key {
                    tgid: group.tgid,
                    numa_id: group.node,
                },
                op: LAVD_SOFT_APPLY,
                __pad: 0,
                id,
                runtime: 0,
                llcs: home,
            };
            Self::command(skel, &mut cmd)?;
        }
        self.previous = previous;
        self.last_resize = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: u64 = 1_000_000_000;

    fn group(id: u64, node: u32, cpus: u64, home: LlcMask) -> Group {
        Group {
            tgid: id as u32,
            node,
            id,
            delta: cpus * SECOND,
            home,
        }
    }

    fn llc(id: usize, node: u32, cpus: u64) -> Llc {
        Llc { id, node, cpus }
    }

    #[test]
    fn homes_stay_on_origin_node_even_when_it_is_overloaded() {
        let llcs = [llc(1, 2, 4), llc(65, 2, 4), llc(3, 7, 32)];
        let groups = [group(1, 2, 100, [0, 0]), group(2, 7, 1, [0, 0])];
        assert_eq!(
            plan_homes(&groups, &llcs, SECOND),
            vec![(1, [2, 2]), (2, [8, 0])]
        );
    }

    #[test]
    fn homes_grow_and_shrink_with_demand() {
        let llcs = [llc(0, 0, 4), llc(1, 0, 4), llc(2, 0, 4)];
        assert_eq!(
            plan_homes(&[group(1, 0, 5, [1, 0])], &llcs, SECOND),
            vec![(1, [3, 0])]
        );
        assert_eq!(
            plan_homes(&[group(1, 0, 0, [4, 0])], &llcs, SECOND),
            vec![(1, [4, 0])]
        );
    }

    #[test]
    fn an_idle_neighbor_does_not_move_a_home_with_spare_capacity() {
        let llcs = [llc(0, 0, 4), llc(1, 0, 4)];
        let groups = [group(1, 0, 2, [2, 0]), group(2, 0, 1, [2, 0])];
        assert_eq!(
            plan_homes(&groups, &llcs, SECOND),
            vec![(1, [2, 0]), (2, [2, 0])]
        );
    }

    #[test]
    fn a_home_moves_when_the_current_llc_cannot_serve_its_demand() {
        let llcs = [llc(0, 0, 4), llc(1, 0, 4)];
        let groups = [group(1, 0, 3, [1, 0]), group(2, 0, 2, [1, 0])];
        assert_eq!(
            plan_homes(&groups, &llcs, SECOND),
            vec![(1, [1, 0]), (2, [2, 0])]
        );
    }

    #[test]
    fn fractional_demand_keeps_a_home_despite_rounded_cpu_requests() {
        let llcs = [llc(0, 0, 4), llc(1, 0, 4)];
        let mut groups = [group(1, 0, 0, [1, 0]), group(2, 0, 0, [1, 0])];
        groups[0].delta = SECOND * 38 / 10;
        groups[1].delta = SECOND / 10;
        assert_eq!(
            plan_homes(&groups, &llcs, SECOND),
            vec![(1, [1, 0]), (2, [1, 0])]
        );
    }

    #[test]
    fn unequal_llcs_are_sized_by_cpu_capacity() {
        let llcs = [llc(0, 0, 2), llc(1, 0, 8), llc(2, 0, 2)];
        assert_eq!(
            plan_homes(&[group(1, 0, 6, [2, 0])], &llcs, SECOND),
            vec![(1, [2, 0])]
        );
        assert_eq!(
            plan_homes(&[group(1, 0, 9, [2, 0])], &llcs, SECOND),
            vec![(1, [3, 0])]
        );
    }

    #[test]
    fn groups_spread_and_overlap_under_saturation() {
        let llcs = [llc(0, 0, 4), llc(1, 0, 4)];
        let groups = [
            group(1, 0, 3, [0, 0]),
            group(2, 0, 3, [0, 0]),
            group(3, 0, 3, [0, 0]),
        ];
        assert_eq!(
            plan_homes(&groups, &llcs, SECOND),
            vec![(1, [1, 0]), (2, [2, 0]), (3, [1, 0])]
        );
    }

    #[test]
    fn equal_load_keeps_existing_home_and_input_order_does_not_matter() {
        let llcs = [llc(0, 0, 4), llc(1, 0, 4)];
        let mut groups = [group(1, 0, 1, [2, 0]), group(2, 0, 1, [1, 0])];
        let homes = plan_homes(&groups, &llcs, SECOND);
        groups.reverse();
        assert_eq!(homes, plan_homes(&groups, &llcs, SECOND));
        assert_eq!(homes, vec![(1, [2, 0]), (2, [1, 0])]);
    }

    #[test]
    fn cpu_less_nodes_have_no_home() {
        assert!(plan_homes(&[group(1, 7, 1, [0, 0])], &[llc(1, 2, 4)], 0).is_empty());
    }
}
