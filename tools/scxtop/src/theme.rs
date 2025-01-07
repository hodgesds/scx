// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use rand::Rng;
use ratatui::style::{Color, Style};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AppTheme {
    /// Default theme.
    Default,
    /// Dark theme with green text.
    MidnightGreen,
    /// IAmBlue
    IAmBlue,
    // Random colors
    Random,
}

/// Returns a random Color.
fn rand_color() -> Color {
    let mut rng = rand::thread_rng();
    let rand_n: u8 = rng.gen_range(0..=255);
    Color::Indexed(rand_n)
}

impl AppTheme {
    /// Returns the default text color for the theme.
    pub fn text_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Green,
            AppTheme::IAmBlue => Color::Blue,
            AppTheme::Default => Color::White,
            AppTheme::Random => rand_color(),
        }
    }

    /// Returns the title text color for the theme.
    pub fn title_style(&self) -> Style {
        match self {
            AppTheme::MidnightGreen => Style::default().fg(Color::White),
            AppTheme::IAmBlue => Style::default().fg(Color::Blue),
            AppTheme::Random => Style::default().fg(rand_color()),
            AppTheme::Default => Style::default().fg(Color::Green),
        }
    }

    /// Returns the border color for the theme.
    pub fn border_style(&self) -> Style {
        match self {
            AppTheme::MidnightGreen => Style::default().fg(Color::Green),
            AppTheme::IAmBlue => Style::default().fg(Color::Cyan),
            AppTheme::Random => Style::default().fg(rand_color()),
            AppTheme::Default => Style::default().fg(Color::White),
        }
    }

    /// Returns the default text enabled color for the theme.
    pub fn text_enabled_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Green,
            AppTheme::IAmBlue => Color::Blue,
            AppTheme::Random => rand_color(),
            AppTheme::Default => Color::Green,
        }
    }

    /// Returns the default text disabled color for the theme.
    pub fn text_disabled_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Green,
            AppTheme::IAmBlue => Color::Red,
            AppTheme::Random => rand_color(),
            AppTheme::Default => Color::Red,
        }
    }

    /// Returns the default text important color for the theme.
    pub fn text_important_color(&self) -> Color {
        match self {
            AppTheme::MidnightGreen => Color::Red,
            AppTheme::IAmBlue => Color::White,
            AppTheme::Random => rand_color(),
            AppTheme::Default => Color::Red,
        }
    }

    /// Returns the sparkline style for the theme.
    pub fn sparkline_style(&self) -> Style {
        match self {
            AppTheme::MidnightGreen => Style::default().fg(Color::Green),
            AppTheme::IAmBlue => Style::default().fg(Color::Blue),
            AppTheme::Random => Style::default().fg(rand_color()),
            AppTheme::Default => Style::default().fg(Color::Yellow),
        }
    }

    /// Returns the next theme.
    pub fn next(&self) -> Self {
        match self {
            AppTheme::Default => AppTheme::MidnightGreen,
            AppTheme::MidnightGreen => AppTheme::IAmBlue,
            AppTheme::IAmBlue => AppTheme::Random,
            _ => AppTheme::Default,
        }
    }
}
