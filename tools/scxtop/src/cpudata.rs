// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;

/// Container for per CPU data.
#[derive(Clone, Debug)]
pub struct CpuData {
    pub cpu: usize,
    pub event_data: BTreeMap<String, Vec<u64>>,
    pub max_size: usize,
}

impl CpuData {
    /// Creates a new CpuData.
    pub fn new(cpu: usize, max_size: usize) -> CpuData {
        let mut event_data = BTreeMap::new();
        event_data.insert("cpu".to_string(), vec![cpu as u64]);
        Self {
            cpu: cpu,
            event_data: event_data,
            max_size: max_size,
        }
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data(&mut self, event: String) -> &Vec<u64> {
        self.event_data
            .entry(event)
            .or_insert(vec![0, self.max_size.try_into().unwrap()])
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data_immut(&self, event: String) -> Vec<u64> {
        if self.event_data.contains_key(&event.clone()) {
            self.event_data.get(&event.clone()).unwrap().to_vec()
        } else {
            vec![0, self.max_size.try_into().unwrap()]
        }
    }

    /// Adds data for an event.
    pub fn add_event_data(&mut self, event: String, val: u64) {
        let size = self.max_size - 1;
        self.event_data
            .entry(event.clone())
            .or_insert(vec![0, size.try_into().unwrap()])
            .push(val);
        // XXX: make this efficient
        if let Some(values) = self.event_data.get_mut(&event.clone()) {
            if values.len() >= self.max_size {
                values.remove(0);
            }
        }
    }
}
