// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{Context, Result};

/// Returns the percentile of a vec.
pub fn percentile(data: &Vec<u64>, p: f64) -> Result<u64> {
    if data.is_empty() {
        return Ok(0);
    }

    if !(0.0..=100.0).contains(&p) {
        return Err(anyhow::anyhow!("Percentile must be between 0 and 100"));
    }

    let mut sorted = data.clone();
    sorted.sort_unstable();

    let n = sorted.len();
    let rank = (p / 100.0) * (n as f64 - 1.0);

    let rank_floor = rank.floor();
    let rank_ceil = rank.ceil();

    let value = if rank_floor == rank_ceil {
        sorted[rank as usize]
    } else {
        let d0 = sorted[rank_floor as usize];
        let d1 = sorted[rank_ceil as usize];
        d0 + (rank - rank_floor) as u64 * (d1 - d0)
    };

    Ok(value)
}

/// Returns the avg of a vec.
pub fn avg(data: &Vec<u64>) -> u64 {
    let sum: u64 = data.iter().sum();
    sum / data.len() as u64
}
