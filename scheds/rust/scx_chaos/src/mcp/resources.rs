// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::protocol::{McpResource, McpResourceContent, McpReadResourceResult};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type ResourceHandler = Box<dyn Fn() -> Result<Value> + Send + Sync>;

pub struct McpResources {
    handlers: Arc<Mutex<HashMap<String, ResourceHandler>>>,
}

impl Default for McpResources {
    fn default() -> Self {
        Self::new()
    }
}

impl McpResources {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_handler<F>(&self, uri: String, handler: F)
    where
        F: Fn() -> Result<Value> + Send + Sync + 'static,
    {
        let mut handlers = self.handlers.lock().unwrap();
        handlers.insert(uri, Box::new(handler));
    }

    pub fn list(&self) -> Vec<McpResource> {
        let handlers = self.handlers.lock().unwrap();
        let mut resources: Vec<McpResource> = handlers
            .keys()
            .map(|uri| {
                let (name, description) = match uri.as_str() {
                    "chaos://config/current" => (
                        "Current Chaos Configuration",
                        Some("Current active chaos configuration including all trait parameters"),
                    ),
                    "chaos://config/schema" => (
                        "Chaos Configuration Schema",
                        Some("Available configuration options with validation ranges and descriptions"),
                    ),
                    "chaos://stats/traits" => (
                        "Chaos Trait Statistics",
                        Some("Per-trait application counts and metrics"),
                    ),
                    "chaos://stats/processes" => (
                        "Process Chaos Statistics",
                        Some("Per-process chaos impact and distribution"),
                    ),
                    "chaos://stats/kprobes" => (
                        "Kprobe Statistics",
                        Some("Per-kprobe hit counts and delay triggers"),
                    ),
                    "chaos://kprobes/available" => (
                        "Available Kprobes",
                        Some("Metadata about available kernel functions for kprobe attachment"),
                    ),
                    "chaos://targets/active" => (
                        "Active Chaos Targets",
                        Some("Currently targeted processes for chaos injection"),
                    ),
                    _ => ("Unknown Resource", None),
                };

                McpResource {
                    uri: uri.clone(),
                    name: name.to_string(),
                    description: description.map(|s| s.to_string()),
                    mime_type: Some("application/json".to_string()),
                }
            })
            .collect();

        resources.sort_by(|a, b| a.uri.cmp(&b.uri));
        resources
    }

    pub fn read(&self, uri: &str) -> Result<McpReadResourceResult> {
        let handlers = self.handlers.lock().unwrap();
        let handler = handlers
            .get(uri)
            .ok_or_else(|| anyhow!("Resource not found: {}", uri))?;

        let data = handler()?;
        let text = serde_json::to_string_pretty(&data)?;

        Ok(McpReadResourceResult {
            contents: vec![McpResourceContent {
                uri: uri.to_string(),
                mime_type: Some("application/json".to_string()),
                text: Some(text),
                blob: None,
            }],
        })
    }

    pub fn setup_chaos_resources(&self) {
        // chaos://config/current - Current chaos configuration
        self.register_handler("chaos://config/current".to_string(), || {
            Ok(json!({
                "note": "This is a static resource. Use tools to modify configuration.",
                "traits": {
                    "random_delays": {
                        "enabled": true,
                        "frequency": 0.0,
                        "min_delay_us": 0,
                        "max_delay_us": 0
                    },
                    "cpu_freq": {
                        "enabled": false,
                        "frequency": 0.0,
                        "min_freq": 0,
                        "max_freq": 0
                    },
                    "degradation": {
                        "enabled": false,
                        "frequency": 0.0,
                        "frac7": 0
                    },
                    "kprobe_delays": {
                        "enabled": false,
                        "frequency": 0.0,
                        "min_delay_us": 0,
                        "max_delay_us": 0,
                        "functions": []
                    }
                },
                "targeting": {
                    "ppid": null,
                    "inclusive": false
                }
            }))
        });

        // chaos://config/schema - Configuration schema and validation
        self.register_handler("chaos://config/schema".to_string(), || {
            Ok(json!({
                "traits": {
                    "random_delays": {
                        "description": "Introduces random delays to task scheduling",
                        "parameters": {
                            "frequency": {
                                "type": "float",
                                "range": [0.0, 1.0],
                                "description": "Probability of applying delay (0.0-1.0)"
                            },
                            "min_delay_us": {
                                "type": "integer",
                                "range": [0, 1000000],
                                "description": "Minimum delay in microseconds"
                            },
                            "max_delay_us": {
                                "type": "integer",
                                "range": [0, 1000000],
                                "description": "Maximum delay in microseconds"
                            }
                        }
                    },
                    "cpu_freq": {
                        "description": "Randomly limits CPU performance",
                        "parameters": {
                            "frequency": {
                                "type": "float",
                                "range": [0.0, 1.0],
                                "description": "Probability of frequency scaling"
                            },
                            "min_freq": {
                                "type": "integer",
                                "description": "Minimum CPU frequency"
                            },
                            "max_freq": {
                                "type": "integer",
                                "description": "Maximum CPU frequency"
                            }
                        }
                    },
                    "degradation": {
                        "description": "Reduces task time slice and virtual time scheduling",
                        "parameters": {
                            "frequency": {
                                "type": "float",
                                "range": [0.0, 1.0],
                                "description": "Probability of degradation"
                            },
                            "frac7": {
                                "type": "integer",
                                "range": [0, 128],
                                "description": "7-bit degradation fraction"
                            }
                        }
                    },
                    "kprobe_delays": {
                        "description": "Attaches to kernel functions and applies delays when hit",
                        "parameters": {
                            "functions": {
                                "type": "array",
                                "description": "List of kernel function names to attach to"
                            },
                            "frequency": {
                                "type": "float",
                                "range": [0.0, 1.0],
                                "description": "Probability of applying delay on kprobe hit"
                            },
                            "min_delay_us": {
                                "type": "integer",
                                "range": [0, 1000000],
                                "description": "Minimum delay in microseconds"
                            },
                            "max_delay_us": {
                                "type": "integer",
                                "range": [0, 1000000],
                                "description": "Maximum delay in microseconds"
                            }
                        }
                    }
                }
            }))
        });

        // chaos://stats/traits - Per-trait statistics
        self.register_handler("chaos://stats/traits".to_string(), || {
            Ok(json!({
                "note": "Static placeholder. Real implementation requires BPF stats integration.",
                "trait_random_delays": 0,
                "trait_cpu_freq": 0,
                "trait_degradation": 0,
                "kprobe_random_delays": 0,
                "chaos_excluded": 0,
                "chaos_skipped": 0,
                "timer_kicks": 0
            }))
        });

        // chaos://stats/processes - Per-process statistics
        self.register_handler("chaos://stats/processes".to_string(), || {
            Ok(json!({
                "note": "Static placeholder. Real implementation requires BPF hash map.",
                "processes": []
            }))
        });

        // chaos://stats/kprobes - Kprobe statistics
        self.register_handler("chaos://stats/kprobes".to_string(), || {
            Ok(json!({
                "note": "Static placeholder. Real implementation requires kprobe tracking.",
                "kprobes": []
            }))
        });

        // chaos://kprobes/available - Available kprobes metadata
        self.register_handler("chaos://kprobes/available".to_string(), || {
            // Count available functions
            let total_available = std::fs::read_to_string(
                "/sys/kernel/debug/tracing/available_filter_functions"
            )
            .map(|content| content.lines().count())
            .unwrap_or(0);

            Ok(json!({
                "total_available": total_available,
                "note": "Use search and discovery tools to find functions",
                "tools": {
                    "search": "chaos_search_kprobes - Search for specific functions",
                    "discover": "chaos_list_kprobe_subsystems - Browse by subsystem",
                    "recommend": "chaos_get_kprobe_recommendations - Get scenario-based suggestions"
                },
                "common_subsystems": ["sched", "mm", "net", "fs", "vfs", "tcp", "udp", "do_", "sys_"],
                "recommended_functions": [
                    "schedule",
                    "do_fork",
                    "vfs_read",
                    "vfs_write",
                    "tcp_sendmsg",
                    "tcp_recvmsg"
                ],
                "source": "/sys/kernel/debug/tracing/available_filter_functions"
            }))
        });

        // chaos://targets/active - Active process targeting
        self.register_handler("chaos://targets/active".to_string(), || {
            Ok(json!({
                "note": "Static placeholder. Real implementation requires reading scheduler state.",
                "targeting_enabled": false,
                "ppid": null,
                "inclusive": false,
                "matched_processes": []
            }))
        });
    }
}
