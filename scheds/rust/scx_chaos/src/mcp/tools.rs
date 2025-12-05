// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::protocol::McpTool;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::HashSet;

pub struct McpTools {
    // Future: Add references to scheduler state, BPF maps, etc.
}

impl Default for McpTools {
    fn default() -> Self {
        Self::new()
    }
}

impl McpTools {
    pub fn new() -> Self {
        Self {}
    }

    pub fn list(&self) -> Vec<McpTool> {
        vec![
            // Kprobe discovery tools
            McpTool {
                name: "chaos_search_kprobes".to_string(),
                description: "Search for kernel functions available for kprobe attachment. Use this to find specific functions before attaching kprobes.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query - supports regex patterns (e.g., 'schedule', 'vfs_.*', 'tcp_.*msg')"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results to return (default: 50, max: 500)",
                            "default": 50,
                            "minimum": 1,
                            "maximum": 500
                        },
                        "subsystem_hint": {
                            "type": "string",
                            "description": "Optional subsystem hint to narrow search (e.g., 'sched', 'mm', 'net', 'fs')"
                        }
                    },
                    "required": ["query"]
                }),
            },
            McpTool {
                name: "chaos_list_kprobe_subsystems".to_string(),
                description: "List common kernel subsystem prefixes to help narrow kprobe searches".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            McpTool {
                name: "chaos_get_kprobe_recommendations".to_string(),
                description: "Get recommended kprobe functions for common chaos testing scenarios".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "scenario": {
                            "type": "string",
                            "enum": ["scheduling", "io", "network", "memory", "locks", "all"],
                            "description": "Testing scenario to get recommendations for",
                            "default": "all"
                        }
                    }
                }),
            },
            McpTool {
                name: "chaos_validate_kprobes".to_string(),
                description: "Validate that kernel function names are available for kprobe attachment".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "functions": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "List of kernel function names to validate"
                        }
                    },
                    "required": ["functions"]
                }),
            },
            // Configuration tools
            McpTool {
                name: "chaos_configure_trait".to_string(),
                description: "Enable/disable or modify chaos trait parameters".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trait": {
                            "type": "string",
                            "enum": ["random_delays", "cpu_freq", "degradation", "kprobe_delays"],
                            "description": "Chaos trait to configure"
                        },
                        "enabled": {
                            "type": "boolean",
                            "description": "Enable or disable this trait"
                        },
                        "frequency": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Probability of applying this trait (0.0-1.0)"
                        },
                        "min_delay_us": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Minimum delay in microseconds (for delay traits)"
                        },
                        "max_delay_us": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Maximum delay in microseconds (for delay traits)"
                        }
                    },
                    "required": ["trait"]
                }),
            },
            McpTool {
                name: "chaos_set_kprobes".to_string(),
                description: "Configure kprobe-based chaos injection".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "functions": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "List of kernel functions to attach kprobes to"
                        },
                        "frequency": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Probability of triggering delay on kprobe hit"
                        },
                        "min_delay_us": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Minimum delay in microseconds"
                        },
                        "max_delay_us": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Maximum delay in microseconds"
                        }
                    },
                    "required": ["functions"]
                }),
            },
            // Query tools
            McpTool {
                name: "chaos_get_stats".to_string(),
                description: "Query real-time chaos statistics".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "stat_type": {
                            "type": "string",
                            "enum": ["traits", "processes", "kprobes", "all"],
                            "description": "Type of statistics to retrieve",
                            "default": "all"
                        }
                    }
                }),
            },
        ]
    }

    pub fn call(&mut self, name: &str, args: &Value) -> Result<Value> {
        match name {
            "chaos_search_kprobes" => self.tool_search_kprobes(args),
            "chaos_list_kprobe_subsystems" => self.tool_list_kprobe_subsystems(),
            "chaos_get_kprobe_recommendations" => self.tool_get_kprobe_recommendations(args),
            "chaos_validate_kprobes" => self.tool_validate_kprobes(args),
            "chaos_configure_trait" => self.tool_configure_trait(args),
            "chaos_set_kprobes" => self.tool_set_kprobes(args),
            "chaos_get_stats" => self.tool_get_stats(args),
            _ => Err(anyhow!("Unknown tool: {}", name)),
        }
    }

    fn tool_search_kprobes(&self, args: &Value) -> Result<Value> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("query parameter is required"))?;

        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(50)
            .min(500) as usize;

        let subsystem_hint = args.get("subsystem_hint").and_then(|v| v.as_str());

        let start = std::time::Instant::now();

        // Build regex from query
        let regex = regex::RegexBuilder::new(query)
            .case_insensitive(true)
            .build()
            .map_err(|e| anyhow!("Invalid search query: {}", e))?;

        // Read and search available functions
        let functions_file = std::fs::read_to_string(
            "/sys/kernel/debug/tracing/available_filter_functions",
        )
        .map_err(|e| anyhow!("Failed to read available_filter_functions: {}. Note: This requires root access and debugfs mounted.", e))?;

        let total_scanned = functions_file.lines().count();

        let matches: Vec<String> = functions_file
            .lines()
            .filter_map(|line| {
                // Parse format: "function_name [module]" or just "function_name"
                let func_name = line.split_whitespace().next()?;

                // Apply subsystem hint if provided
                if let Some(subsystem) = subsystem_hint {
                    if !func_name.starts_with(subsystem) {
                        return None;
                    }
                }

                // Apply regex search
                if regex.is_match(func_name) {
                    Some(func_name.to_string())
                } else {
                    None
                }
            })
            .take(limit)
            .collect();

        let match_count = matches.len();
        let execution_time_ms = start.elapsed().as_millis();

        // Generate suggestions based on results
        let related_subsystems = self.extract_subsystems_from_matches(&matches);

        Ok(json!({
            "matches": matches,
            "match_count": match_count,
            "total_scanned": total_scanned,
            "query": query,
            "subsystem_hint": subsystem_hint,
            "execution_time_ms": execution_time_ms,
            "suggestions": {
                "related_subsystems": related_subsystems,
            }
        }))
    }

    fn tool_list_kprobe_subsystems(&self) -> Result<Value> {
        let subsystems = vec![
            json!({
                "prefix": "sched",
                "description": "Scheduler functions",
                "examples": ["schedule", "scheduler_tick", "sched_fork"]
            }),
            json!({
                "prefix": "vfs",
                "description": "Virtual filesystem functions",
                "examples": ["vfs_read", "vfs_write", "vfs_open"]
            }),
            json!({
                "prefix": "mm",
                "description": "Memory management functions",
                "examples": ["mm_init", "mmap_region", "munmap_region"]
            }),
            json!({
                "prefix": "tcp",
                "description": "TCP protocol functions",
                "examples": ["tcp_sendmsg", "tcp_recvmsg", "tcp_connect"]
            }),
            json!({
                "prefix": "udp",
                "description": "UDP protocol functions",
                "examples": ["udp_sendmsg", "udp_recvmsg"]
            }),
            json!({
                "prefix": "do_",
                "description": "Core kernel operations",
                "examples": ["do_fork", "do_exit", "do_syscall_64"]
            }),
            json!({
                "prefix": "sys_",
                "description": "System call handlers",
                "examples": ["sys_read", "sys_write", "sys_open"]
            }),
            json!({
                "prefix": "net",
                "description": "Network stack functions",
                "examples": ["net_rx_action", "netif_receive_skb"]
            }),
            json!({
                "prefix": "fs",
                "description": "Filesystem operations",
                "examples": ["fs_lookup", "fsnotify"]
            }),
        ];

        Ok(json!({ "subsystems": subsystems }))
    }

    fn tool_get_kprobe_recommendations(&self, args: &Value) -> Result<Value> {
        let scenario = args
            .get("scenario")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        let (recommendations, warnings) = match scenario {
            "scheduling" => (
                vec![
                    json!({
                        "function": "schedule",
                        "impact": "high",
                        "description": "Core scheduler entry point - affects all task switches",
                        "suggested_delay_range_us": [10, 500],
                        "suggested_frequency": 0.1
                    }),
                    json!({
                        "function": "scheduler_tick",
                        "impact": "medium",
                        "description": "Periodic scheduler tick - runs frequently on each CPU",
                        "suggested_delay_range_us": [1, 100],
                        "suggested_frequency": 0.05
                    }),
                    json!({
                        "function": "wake_up_new_task",
                        "impact": "medium",
                        "description": "Task creation wakeup path",
                        "suggested_delay_range_us": [50, 1000],
                        "suggested_frequency": 0.2
                    }),
                ],
                vec![
                    "High frequency on 'schedule' can severely impact system performance",
                    "Consider starting with frequency < 0.1 for production-like testing",
                ],
            ),
            "io" => (
                vec![
                    json!({
                        "function": "vfs_read",
                        "impact": "medium",
                        "description": "File read operations - affects all file reads",
                        "suggested_delay_range_us": [100, 5000],
                        "suggested_frequency": 0.2
                    }),
                    json!({
                        "function": "vfs_write",
                        "impact": "medium",
                        "description": "File write operations - affects all file writes",
                        "suggested_delay_range_us": [100, 5000],
                        "suggested_frequency": 0.2
                    }),
                    json!({
                        "function": "vfs_open",
                        "impact": "low",
                        "description": "File open operations",
                        "suggested_delay_range_us": [50, 2000],
                        "suggested_frequency": 0.15
                    }),
                ],
                vec!["I/O delays can cause application timeouts"],
            ),
            "network" => (
                vec![
                    json!({
                        "function": "tcp_sendmsg",
                        "impact": "high",
                        "description": "TCP send path - affects all TCP sends",
                        "suggested_delay_range_us": [50, 2000],
                        "suggested_frequency": 0.15
                    }),
                    json!({
                        "function": "tcp_recvmsg",
                        "impact": "high",
                        "description": "TCP receive path - affects all TCP receives",
                        "suggested_delay_range_us": [50, 2000],
                        "suggested_frequency": 0.15
                    }),
                    json!({
                        "function": "udp_sendmsg",
                        "impact": "medium",
                        "description": "UDP send path",
                        "suggested_delay_range_us": [10, 1000],
                        "suggested_frequency": 0.1
                    }),
                ],
                vec![
                    "Network delays can trigger retransmissions and timeouts",
                    "Consider impact on real-time applications",
                ],
            ),
            "memory" => (
                vec![
                    json!({
                        "function": "handle_mm_fault",
                        "impact": "high",
                        "description": "Page fault handler - affects memory access patterns",
                        "suggested_delay_range_us": [100, 5000],
                        "suggested_frequency": 0.1
                    }),
                    json!({
                        "function": "do_mmap",
                        "impact": "medium",
                        "description": "Memory mapping operations",
                        "suggested_delay_range_us": [50, 2000],
                        "suggested_frequency": 0.15
                    }),
                ],
                vec!["Memory operation delays can cause severe performance degradation"],
            ),
            "locks" => (
                vec![
                    json!({
                        "function": "mutex_lock",
                        "impact": "high",
                        "description": "Mutex lock acquisition",
                        "suggested_delay_range_us": [10, 500],
                        "suggested_frequency": 0.05
                    }),
                ],
                vec![
                    "Lock delays can cause deadlocks and severe contention",
                    "Use very low frequencies to avoid system hangs",
                ],
            ),
            _ => (vec![], vec![]),
        };

        Ok(json!({
            "scenario": scenario,
            "recommendations": recommendations,
            "warnings": warnings
        }))
    }

    fn tool_validate_kprobes(&self, args: &Value) -> Result<Value> {
        let functions = args
            .get("functions")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("functions parameter is required and must be an array"))?;

        let function_names: Vec<&str> = functions
            .iter()
            .filter_map(|v| v.as_str())
            .collect();

        // Read available functions into a set for fast lookup
        let functions_file = std::fs::read_to_string(
            "/sys/kernel/debug/tracing/available_filter_functions",
        )
        .map_err(|e| anyhow!("Failed to read available_filter_functions: {}", e))?;

        let available: HashSet<&str> = functions_file
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .collect();

        let mut valid = Vec::new();
        let mut invalid = Vec::new();
        let mut validation_errors = serde_json::Map::new();

        for func in function_names {
            if available.contains(func) {
                valid.push(func);
            } else {
                invalid.push(func);
                validation_errors.insert(
                    func.to_string(),
                    json!("Not found in available_filter_functions"),
                );
            }
        }

        Ok(json!({
            "valid": valid,
            "invalid": invalid,
            "validation_errors": validation_errors
        }))
    }

    fn tool_configure_trait(&self, _args: &Value) -> Result<Value> {
        // TODO: Implement actual configuration via BPF maps
        Ok(json!({
            "status": "not_implemented",
            "message": "Trait configuration requires BPF map integration"
        }))
    }

    fn tool_set_kprobes(&self, _args: &Value) -> Result<Value> {
        // TODO: Implement kprobe attachment
        Ok(json!({
            "status": "not_implemented",
            "message": "Kprobe attachment requires runtime integration"
        }))
    }

    fn tool_get_stats(&self, _args: &Value) -> Result<Value> {
        // TODO: Implement stats reading from BPF maps
        Ok(json!({
            "status": "not_implemented",
            "message": "Stats collection requires BPF map integration"
        }))
    }

    fn extract_subsystems_from_matches(&self, matches: &[String]) -> Vec<String> {
        let mut subsystems = HashSet::new();
        for func in matches.iter().take(20) {
            if let Some(prefix) = func.split('_').next() {
                if prefix.len() >= 2 {
                    subsystems.insert(prefix.to_string());
                }
            }
        }
        subsystems.into_iter().take(5).collect()
    }
}
