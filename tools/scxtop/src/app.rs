// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::available_perf_events;
use crate::avg;
use crate::bpf_skel::BpfSkel;
use crate::read_file_string;
use crate::Action;
use crate::CpuData;
use crate::PerfEvent;
use crate::StatAggregation;
use crate::Tui;
use crate::APP;
use crate::LICENSE;
use crate::SCHED_NAME_PATH;
use anyhow::Result;
use ratatui::{
    crossterm::event::KeyCode::Char,
    layout::{
        Alignment,
        Constraint::{self, Length, Max, Min, Percentage, Ratio},
        Layout,
    },
    prelude::Rect,
    style::{Color, Modifier, Style, Stylize},
    symbols::{scrollbar, Marker},
    text::{Line, Span, Text},
    widgets::{
        Axis, Bar, BarChart, BarGroup, Block, BorderType, Borders, Chart, Dataset, Paragraph,
        RenderDirection, Scrollbar, ScrollbarOrientation, ScrollbarState, Sparkline,
        StatefulWidget, Widget,
    },
    Frame,
};
use scx_utils::Cpu;
use scx_utils::Topology;
use serde;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AppTheme {
    /// Default theme.
    Default,
    /// Dark theme with green text.
    MidnightGreen,
}

impl AppTheme {
    /// Returns the default text color for the theme.
    pub fn text_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Green,
            _ => Color::White,
        }
    }

    /// Returns the title text color for the theme.
    pub fn text_title_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::White,
            _ => Color::Green,
        }
    }

    /// Returns the default text enabled color for the theme.
    pub fn text_enabled_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Green,
            _ => Color::Green,
        }
    }

    /// Returns the default text disabled color for the theme.
    pub fn text_disabled_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Green,
            _ => Color::Red,
        }
    }

    /// Returns the sparkline color for the theme.
    pub fn sparkline_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Blue,
            _ => Color::Yellow,
        }
    }

    /// Returns the next theme.
    pub fn next(&self) -> Self {
        match self {
            AppTheme::Default => AppTheme::MidnightGreen,
            _ => AppTheme::Default,
        }
    }
}

#[derive(Clone)]
pub enum AppState {
    /// Application is in the default state.
    Default,
    /// Application is in the help state.
    Help,
    /// Application is in the event state.
    Event,
}

/// App is the struct for scxtop application state.
pub struct App<'a> {
    scheduler: String,
    max_cpu_events: usize,
    state: AppState,
    theme: AppTheme,
    pub counter: i64,
    pub tick_rate_ms: usize,
    pub should_quit: bool,
    pub action_tx: UnboundedSender<Action>,
    pub skel: Arc<RwLock<BpfSkel<'a>>>,
    topo: Arc<RwLock<Topology>>,
    tui: Arc<RwLock<Tui>>,
    active_scheduler: String,
    event_scroll_state: ScrollbarState,
    event_scroll: u16,

    active_event: PerfEvent,
    active_event_id: usize,
    active_perf_events: BTreeMap<usize, PerfEvent>,
    available_events: Vec<PerfEvent>,

    active_stat_agg: StatAggregation,

    available_perf_events: BTreeMap<String, HashSet<String>>,
    cpu_data: BTreeMap<usize, CpuData>,

    // XXX temp stuff
    chart_data: Vec<(f64, f64)>,
}

impl<'a> App<'a> {
    /// Creates a new appliation.
    pub fn new(
        scheduler: String,
        max_cpu_events: usize,
        tick_rate_ms: usize,
        action_tx: UnboundedSender<Action>,
        skel: Arc<RwLock<BpfSkel<'a>>>,
        tui: Arc<RwLock<Tui>>,
    ) -> Result<Self> {
        let topo = Topology::new()?;
        let mut cpu_data = BTreeMap::new();
        let mut active_perf_events = BTreeMap::new();
        for cpu_id in topo.all_cpus.keys() {
            let mut event = PerfEvent::new("hw".to_string(), "cycles".to_string(), *cpu_id);
            event.attach()?;
            active_perf_events.insert(*cpu_id, event);
            cpu_data.insert(*cpu_id, CpuData::new(*cpu_id, max_cpu_events));
        }
        let perf_events = available_perf_events()?;
        let active_event = PerfEvent::new("hw".to_string(), "cycles".to_string(), 0);

        let app = Self {
            scheduler: scheduler,
            max_cpu_events: max_cpu_events,
            theme: AppTheme::Default,
            state: AppState::Default,
            counter: 0,
            tick_rate_ms: tick_rate_ms,
            should_quit: false,
            action_tx: action_tx,
            skel: skel,
            topo: Arc::new(RwLock::new(topo)),
            tui: tui,
            cpu_data: cpu_data,
            active_scheduler: "none".to_string(),
            active_stat_agg: StatAggregation::Max,
            event_scroll_state: ScrollbarState::new(perf_events.len()).position(0),
            event_scroll: 0,
            active_event_id: 0,
            active_event: active_event,
            available_perf_events: perf_events,
            active_perf_events: active_perf_events,
            available_events: PerfEvent::default_events(),

            chart_data: vec![(1.0, 2.0)],
        };

        Ok(app)
    }

    /// Returns the state of the application.
    pub fn state(&self) -> AppState {
        self.state.clone()
    }

    /// Sets the state of the application.
    pub fn set_state(&mut self, state: AppState) {
        self.state = state
    }

    /// Returns the current theme of the application
    pub fn theme(&self) -> AppTheme {
        self.theme.clone()
    }

    /// Sets the theme of the application.
    pub fn set_theme(&mut self, theme: AppTheme) {
        self.theme = theme
    }

    /// Stop all active perf events.
    fn stop_perf_events(&mut self) {
        self.active_perf_events.clear();
        for cpu_data in self.cpu_data.values_mut() {
            cpu_data.event_data.clear();
        }
    }

    /// Activates the next event.
    fn next_event(&mut self) -> Result<()> {
        self.active_perf_events.clear();
        if self.active_event_id == self.available_events.len() - 1 {
            self.active_event_id = 0;
        } else {
            self.active_event_id += 1;
        }
        let perf_event = &self.available_events[self.active_event_id].clone();

        self.active_event = perf_event.clone();
        self.activate_perf_event(&perf_event)
    }

    /// Activates the previous event.
    fn prev_event(&mut self) -> Result<()> {
        self.active_perf_events.clear();
        if self.active_event_id == 0 {
            self.active_event_id = self.available_events.len() - 1;
        } else {
            self.active_event_id -= 1;
        }
        let perf_event = &self.available_events[self.active_event_id].clone();

        self.active_event = perf_event.clone();
        self.activate_perf_event(&perf_event)
    }

    /// Activates a perf event, stopping any active perf events.
    fn activate_perf_event(&mut self, perf_event: &PerfEvent) -> Result<()> {
        if !self.active_perf_events.is_empty() {
            self.stop_perf_events();
        }
        for cpu_id in self.topo.read().unwrap().all_cpus.keys() {
            let mut event = PerfEvent::new(
                perf_event.subsystem.clone(),
                perf_event.event.clone(),
                *cpu_id,
            );
            event.attach()?;
            self.active_perf_events.insert(*cpu_id, event);
        }
        Ok(())
    }

    /// Runs callbacks to update application state on tick.
    fn on_tick(&mut self) -> Result<()> {
        for (cpu, event) in &mut self.active_perf_events {
            let val = event.value(true)?;
            let cpu_data = self
                .cpu_data
                .entry(*cpu)
                .or_insert(CpuData::new(*cpu, self.max_cpu_events));
            cpu_data.add_event_data(event.event.clone(), val);
        }
        Ok(())
    }

    /// Returns the stats chart.
    fn stats_chart(&self) -> Chart {
        let default_style = Style::default().fg(self.theme.text_color());
        let window = [0.0, 20.0];
        let x_labels = vec![
            Span::styled(
                format!("foo"),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("bar"),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ];
        let datasets = vec![
            Dataset::default()
                .name("data2")
                .marker(Marker::Dot)
                .style(Style::default().fg(Color::Cyan))
                .data(&self.chart_data),
            Dataset::default()
                .name("data3")
                .marker(Marker::Braille)
                .style(Style::default().fg(Color::Yellow))
                .data(&self.chart_data),
        ];
        Chart::new(datasets)
            .block(Block::bordered().style(default_style))
            .x_axis(
                Axis::default()
                    .title("Period")
                    .style(default_style)
                    .labels(x_labels)
                    .bounds(window),
            )
            .y_axis(
                Axis::default()
                    .title("Count")
                    .style(default_style)
                    .labels(["0".bold(), "0".into(), "20".bold()])
                    .bounds([0.0, 20.0]),
            )
    }

    fn cpu_vertical_bar(&self, cpu: usize) -> Bar {
        Bar::default()
            .value(cpu as u64)
            .label(Line::from(format!("{}", cpu)))
            .text_value(format!("{}", cpu))
    }

    fn cpus_barchart(&self) -> BarChart {
        let topo = self.topo.read().unwrap();
        let bars: Vec<Bar> = topo
            .all_cpus
            .keys()
            .map(|cpu_id| self.cpu_vertical_bar(*cpu_id))
            .collect();
        let title = Line::from("CPUs").centered();
        BarChart::default()
            .data(BarGroup::default().bars(&bars))
            .block(Block::new().title(title))
            .bar_width(5)
    }

    /// Creates a sparkline for a cpu.
    fn cpu_sparkline(&self, cpu: usize, bottom_border: bool) -> Sparkline {
        let default_style = Style::default().fg(self.theme.text_color());
        let mut perf: u64 = 0;
        let data = if self.cpu_data.contains_key(&cpu) {
            let cpu_data = self.cpu_data.get(&cpu).unwrap();
            perf = cpu_data
                .event_data_immut("perf".to_string())
                .first()
                .copied()
                .unwrap_or(0);
            cpu_data.event_data_immut(self.active_event.event.clone())
        } else {
            Vec::new()
        };
        let max = data.iter().max().unwrap_or(&0);
        Sparkline::default()
            .data(&data)
            .max(*max)
            .direction(RenderDirection::RightToLeft)
            .block(
                Block::new()
                    .borders(if bottom_border {
                        Borders::LEFT | Borders::RIGHT | Borders::BOTTOM
                    } else {
                        Borders::LEFT | Borders::RIGHT
                    })
                    .style(default_style)
                    .title_alignment(Alignment::Left)
                    .title(format!(
                        "C{}{}",
                        cpu,
                        if perf == 0 {
                            "".to_string()
                        } else {
                            format!("  {}", perf)
                        }
                    )),
            )
            .style(Style::default().fg(self.theme.sparkline_color()))
    }

    /// Renders the default application state.
    fn render_default(&mut self, frame: &mut Frame) -> Result<()> {
        let theme = self.theme();
        let default_style = Style::default().fg(self.theme.text_color());
        let topo = self.topo.read().unwrap();
        let num_cpus = topo.all_cpus.len();

        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(frame.area());
        let [top_left, bottom_left] = Layout::vertical([Constraint::Fill(1); 2]).areas(left);

        // The first entry is for the block layout
        let mut cpus_constraints = vec![Constraint::Length(1)];
        for _ in 1..num_cpus + 1 {
            cpus_constraints.push(Constraint::Ratio(1, num_cpus as u32));
        }
        let cpus_verticle = Layout::vertical(cpus_constraints).split(right);

        // let cpus_chart = self.cpus_barchart();
        // frame.render_widget(cpus_chart, right);

        let cpu_sparklines: Vec<Sparkline> = topo
            .all_cpus
            .keys()
            .map(|cpu_id| self.cpu_sparkline(cpu_id.clone(), *cpu_id == num_cpus - 1))
            .collect();

        // XXX: make more efficient
        let cpu_last_period = self
            .cpu_data
            .values()
            .map(|cpu_data| {
                cpu_data
                    .event_data_immut(self.active_event.event.clone())
                    .last()
                    .copied()
                    .unwrap_or(0)
            })
            .collect::<Vec<u64>>();
        let cpu_avg = avg(&cpu_last_period);
        let cpu_max = cpu_last_period.iter().max().copied().unwrap_or(0);
        let cpu_min = cpu_last_period.iter().min().copied().unwrap_or(0);

        let cpu_block = Block::bordered()
            .title(format!(
                "CPUs ({}) avg {} max {} min {}",
                self.active_event.event, cpu_avg, cpu_max, cpu_min
            ))
            .title_style(Style::default().fg(self.theme.text_title_color()))
            .title_alignment(Alignment::Center)
            .style(default_style);

        frame.render_widget(cpu_block, cpus_verticle[0]);
        let _ = cpu_sparklines
            .iter()
            .enumerate()
            .for_each(|(i, cpu_sparkline)| {
                frame.render_widget(cpu_sparkline, cpus_verticle[i + 1]);
            });

        let stats_chart = self.stats_chart();
        frame.render_widget(stats_chart, top_left);
        frame.render_widget(
            Block::bordered()
                .title(format!("Scheduler ({})", self.scheduler))
                .title_alignment(Alignment::Center)
                .title_style(Style::default().fg(self.theme.text_title_color()))
                .style(default_style),
            bottom_left,
        );
        Ok(())
    }

    /// Renders the help TUI.
    fn render_help(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        let theme = self.theme();
        let text = vec![
            Line::from(Span::styled(
                LICENSE,
                Style::default().add_modifier(Modifier::ITALIC),
            )),
            "\n".into(),
            "\n".into(),
            Line::from(Span::styled("Key Bindings:", Style::default())),
            Line::from(Span::styled("h: help (h to exit help)", Style::default())),
            Line::from(Span::styled(
                format!(
                    "t: change theme ({})",
                    serde_json::to_string_pretty(&theme)?
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!("e: show CPU event menu ({})", self.active_event.event),
                Style::default(),
            )),
            Line::from(Span::styled("c: clear active perf event", Style::default())),
            Line::from(Span::styled("n: next perf event", Style::default())),
            Line::from(Span::styled("p: previous perf event", Style::default())),
        ];
        frame.render_widget(
            Paragraph::new(text)
                .block(
                    Block::default()
                        .title(APP)
                        .title_alignment(Alignment::Center)
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded),
                )
                .style(Style::default().fg(theme.text_color()))
                .alignment(Alignment::Left),
            area,
        );
        Ok(())
    }

    /// Renders the event TUI.
    fn render_event(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        let default_style = Style::default().fg(self.theme.text_color());
        let chunks = Layout::vertical([Constraint::Min(1), Constraint::Percentage(99)]).split(area);

        let events: Vec<Line> = self
            .available_perf_events
            .iter()
            .flat_map(|(subsystem, events)| {
                events
                    .iter()
                    .map(|event| Line::from(format!("{}:{}", subsystem.clone(), event)))
            })
            .collect();

        let title = Block::new()
            .style(default_style)
            .title_alignment(Alignment::Center)
            .title("Use j k or ◄ ▲ ▼ ► to scroll ".bold());
        frame.render_widget(title, chunks[0]);

        let paragraph = Paragraph::new(events.clone())
            .style(default_style)
            .scroll((self.event_scroll, 0));
        frame.render_widget(paragraph, chunks[1]);

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            chunks[1],
            &mut self.event_scroll_state,
        );

        Ok(())
    }

    /// Renders the application to the frame.
    pub fn render(&mut self, frame: &mut Frame) -> Result<()> {
        match self.state {
            AppState::Help => self.render_help(frame),
            AppState::Event => self.render_event(frame),
            _ => self.render_default(frame),
        }
    }

    /// Updates app state when the down arrow or mapped key is pressed.
    fn on_down(&mut self) {
        match self.state {
            AppState::Event => {
                self.event_scroll += 1;
            }
            _ => {}
        }
    }

    /// Updates app state when the up arrow or mapped key is pressed.
    fn on_up(&mut self) {
        match self.state {
            AppState::Event => {
                if self.event_scroll > 1 {
                    self.event_scroll -= 1;
                }
            }
            _ => {}
        }
    }

    /// Updates the app when a scheduler is unloaded.
    fn on_scheduler_unload(&mut self) {
        self.scheduler = "".to_string();
    }

    /// Updates the app when a scheduler is loaded.
    fn on_scheduler_load(&mut self) -> Result<()> {
        self.scheduler = read_file_string(SCHED_NAME_PATH)?;
        Ok(())
    }

    /// Updates the app when a CPUs performance is changed by the scheduler
    fn on_cpu_perf(&mut self, cpu: u32, perf: u32) {
        let cpu_data = self
            .cpu_data
            .entry(cpu as usize)
            .or_insert(CpuData::new(cpu as usize, self.max_cpu_events));
        cpu_data.add_event_data("perf".to_string(), perf as u64);
    }

    /// Handles the action and updates application states.
    pub fn handle_action(&mut self, action: Action) -> Result<()> {
        match action {
            Action::Tick => {
                self.on_tick()?;
            }
            Action::Increment => {
                self.counter += 1;
            }
            Action::Decrement => {
                self.counter -= 1;
            }
            Action::Down => self.on_down(),
            Action::Up => self.on_up(),
            Action::Help => match self.state {
                AppState::Help => self.set_state(AppState::Default),
                _ => self.set_state(AppState::Help),
            },
            Action::NextEvent => {
                if let Err(_) = self.next_event() {
                    // XXX handle error
                }
            }
            Action::PrevEvent => {
                if let Err(_) = self.prev_event() {
                    // XXX handle error
                }
            }
            Action::SchedLoad => {
                self.on_scheduler_load()?;
            }
            Action::SchedUnload => {
                self.on_scheduler_unload();
            }
            Action::SchedCpuPerfSet { cpu, perf } => {
                self.on_cpu_perf(cpu, perf);
            }
            Action::ClearEvent => self.stop_perf_events(),
            Action::Event => match self.state {
                AppState::Event => self.set_state(AppState::Default),
                _ => self.set_state(AppState::Event),
            },
            Action::ChangeTheme => {
                self.set_theme(self.theme().next());
            }
            Action::DecTickRate => {
                if self.tick_rate_ms > 200 {
                    self.tick_rate_ms -= 100;
                } else {
                    self.tick_rate_ms = self.tick_rate_ms.saturating_div(2);
                }
                let tui = Arc::clone(&self.tui);
                tui.write().unwrap().tick_rate_ms = self.tick_rate_ms;
            }
            Action::IncTickRate => {
                if self.tick_rate_ms >= 100 {
                    self.tick_rate_ms += 100;
                } else {
                    self.tick_rate_ms *= 2;
                }
                let tui = Arc::clone(&self.tui);
                tui.write().unwrap().tick_rate_ms = self.tick_rate_ms;
            }
            Action::NetworkRequestAndThenIncrement => {
                let tx = self.action_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await; // simulate network request
                    tx.send(Action::Increment).unwrap();
                });
            }
            Action::NetworkRequestAndThenDecrement => {
                let tx = self.action_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await; // simulate network request
                    tx.send(Action::Decrement).unwrap();
                });
            }
            Action::Quit => self.should_quit = true,
            _ => {}
        };
        Ok(())
    }
}
