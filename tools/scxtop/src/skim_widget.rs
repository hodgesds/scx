// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use skim::prelude::*;

pub struct SkimWidget<'a> {
    opts: &SkimOptions<'a>,
}

impl Widget for SkimWidget {
    fn render(self, area: Rect, buf: &mut Buffer) {
        buf.set_string(
            area.left(),
            area.top(),
            &self.content,
            Style::default().fg(Color::Green),
        );
    }
}

impl<'a> SkimWidget<'a> {
    fn new(opts: &SkimOptions) -> Self {
        Self { opts }
    }
}
