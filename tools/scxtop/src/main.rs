// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;
use scxtop::bpf_intf::*;
use scxtop::bpf_skel::types::bpf_event;
use scxtop::bpf_skel::*;
use scxtop::read_file_string;
use scxtop::Action;
use scxtop::App;
use scxtop::Event;
use scxtop::Tui;
use scxtop::APP;
use scxtop::SCHED_NAME_PATH;
use std::mem::MaybeUninit;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crossterm::event::KeyCode;
use ratatui::crossterm::event::KeyCode::Char;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(about = APP)]
struct Args {
    /// App tick rate
    #[arg(short, long, default_value_t = 250)]
    tick_rate_ms: usize,
    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

fn get_action(_app: &App, event: Event) -> Action {
    match event {
        Event::Error => Action::None,
        Event::Tick => Action::Tick,
        Event::Render => Action::Render,
        Event::Key(key) => {
            match key.code {
                KeyCode::Down => Action::Down,
                KeyCode::Up => Action::Up,
                Char('e') => Action::Event,
                Char('j') => Action::Down,
                Char('k') => Action::Up,
                Char('n') => Action::NextEvent,
                Char('p') => Action::PrevEvent,
                Char('c') => Action::ClearEvent,
                Char('J') => Action::NetworkRequestAndThenIncrement, // new
                Char('K') => Action::NetworkRequestAndThenDecrement, // new
                Char('q') => Action::Quit,
                Char('h') => Action::Help,
                Char('t') => Action::ChangeTheme,
                Char('-') => Action::DecTickRate,
                Char('+') => Action::IncTickRate,
                _ => Action::None,
            }
        }
        _ => Action::None,
    }
}

async fn run() -> Result<()> {
    let (action_tx, mut action_rx) = mpsc::unbounded_channel();

    let args = Args::parse();

    let mut open_object = MaybeUninit::uninit();
    let mut builder = BpfSkelBuilder::default();
    if args.debug {
        builder.obj_builder.debug(true);
    }
    let mut open_skel = builder.open(&mut open_object)?;
    open_skel.progs.on_sched_cpu_perf.set_autoload(true);
    let skel = open_skel.load()?;

    // Attach probes
    let _kprobe = skel
        .progs
        .on_sched_cpu_perf
        .attach_kprobe(false, "scx_bpf_cpuperf_set")?;

    let tui = Tui::new()?;
    let arc_tui = Arc::new(RwLock::new(tui));
    let mut rbb = RingBufferBuilder::new();
    let tx = action_tx.clone();
    rbb.add(&skel.maps.events, move |data: &[u8]| {
        let mut event = bpf_event::default();
        // This works because the plain types were created in lib.rs
        plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
        let event_type = event.r#type as u32;
        match event_type {
            event_type_SCHED_LOAD => {
                tx.send(Action::SchedLoad.clone()).ok();
            }
            event_type_SCHED_UNLOAD => {
                tx.send(Action::SchedUnload.clone()).ok();
            }
            event_type_CPU_PERF_SET => {
                let action = Action::SchedCpuPerfSet {
                    cpu: event.cpu,
                    perf: event.perf as u32,
                };
                tx.send(action).ok();
            }
            _ => {}
        }
        0
    })?;
    let rb = rbb.build()?;
    let scheduler = read_file_string(SCHED_NAME_PATH).unwrap_or("".to_string());

    let mut app = App::new(
        scheduler,
        100,
        100,
        action_tx.clone(),
        Arc::new(RwLock::new(skel)),
        arc_tui.clone(),
    )?;

    let main_tui = arc_tui.clone();
    main_tui.write().unwrap().enter()?;

    tokio::spawn(async move {
        loop {
            let _ = rb.poll(Duration::from_millis(1));
        }
    });

    loop {
        let loop_tui = arc_tui.clone();
        let e = loop_tui.write().unwrap().next().await?;
        match e {
            Event::Quit => action_tx.send(Action::Quit)?,
            Event::Tick => action_tx.send(Action::Tick)?,
            Event::Render => action_tx.send(Action::Render)?,
            Event::Key(_) => {
                let action = get_action(&app, e);
                action_tx.send(action.clone())?;
            }
            _ => {}
        };

        while let Ok(action) = action_rx.try_recv() {
            app.handle_action(action.clone())?;
            if let Action::Render = action {
                loop_tui
                    .write()
                    .unwrap()
                    .draw(|f| app.render(f).expect("failed to render application"))?;
            }
        }

        if app.should_quit {
            break;
        }
    }
    main_tui.write().unwrap().exit()?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let result = run().await;

    result?;

    Ok(())
}
