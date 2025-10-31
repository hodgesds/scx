// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    // Rebuild directives
    println!("cargo:rerun-if-changed=../../lib/scxtest");
}
