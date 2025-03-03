// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use crate::APP;
use crate::STATS_SOCKET_PATH;
use crate::TRACE_FILE_PREFIX;

use anyhow::Result;
use clap::{Command, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::fs::File;
use std::io;

use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[clap(flatten)]
    pub tui: TuiArgs,
}

#[derive(Clone, Parser, Debug)]
#[command(about = APP)]
pub struct TuiArgs {
    /// App tick rate in milliseconds.
    #[arg(short = 'r', long, default_missing_value = "250")]
    pub tick_rate_ms: Option<usize>,
    /// Extra verbose output.
    #[arg(short, long, default_missing_value = "false")]
    pub debug: Option<bool>,
    /// Exclude bpf event tracking.
    #[arg(short, long, default_missing_value = "false")]
    pub exclude_bpf: Option<bool>,
    /// Stats unix socket path.
    #[arg(short, long, default_missing_value = STATS_SOCKET_PATH.to_string())]
    pub stats_socket_path: Option<String>,
    /// Trace file prefix for perfetto traces.
    #[arg(short, long, default_missing_value = TRACE_FILE_PREFIX.to_string())]
    pub trace_file_prefix: Option<String>,
    /// Number of ticks for traces.
    #[arg(long, default_missing_value = "5")]
    pub trace_ticks: Option<usize>,
    /// Number of worker threads.
    #[arg(long, default_missing_value = "4", value_parser = clap::value_parser!(u16).range(2..128))]
    pub worker_threads: Option<u16>,
    /// Number of ticks to warmup before collecting traces.
    #[arg(long, default_missing_value = "3")]
    pub trace_tick_warmup: Option<usize>,
    /// Process to monitor or all.
    #[arg(long, default_value_t = -1)]
    pub process_id: i32,
    /// Custom perf events colon delimited (ex: "<event_name>:<event and umask ex: 0x023>:<event_type ex: 4>")
    #[arg(long)]
    pub perf_events: Vec<String>,

    /// Automatically start a trace when a function takes too long to return.
    #[arg(
        long,
        default_value_t = false,
        requires("experimental_long_tail_tracing_symbol"),
        requires("experimental_long_tail_tracing_binary")
    )]
    pub experimental_long_tail_tracing: bool,
    /// Symbol to automatically trace the long tail of.
    #[arg(long)]
    pub experimental_long_tail_tracing_symbol: Option<String>,
    /// Binary to attach the uprobe and uretprobe to.
    #[arg(long)]
    pub experimental_long_tail_tracing_binary: Option<String>,
    /// Minimum latency to trigger a trace.
    #[arg(long, default_value_t = 100000000)]
    pub experimental_long_tail_tracing_min_latency_ns: u64,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Runs the scxtop TUI.
    Tui(TuiArgs),

    #[clap(hide = true)]
    GenerateCompletions {
        /// The shell type
        #[clap(short, long, default_value = "bash")]
        shell: Shell,
        /// Output file, stdout if not present
        #[arg(long, value_parser(clap::value_parser!(PathBuf)))]
        output: Option<PathBuf>,
    },
}

/// Generates clap completions
pub fn generate_completions(mut app: Command, shell: Shell, output: Option<PathBuf>) -> Result<()> {
    let mut file: Box<dyn io::Write> = match output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout()),
    };

    generate(shell, &mut app, "scxtop", &mut file);
    Ok(())
}
