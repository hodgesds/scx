// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scx_utils::Builder;

fn main() {
    protobuf_codegen::Codegen::new()
        .pure()
        .cargo_out_dir("protos_gen/")
        .input("src/protos/perfetto_scx.proto")
        .include("src/protos")
        .run_from_script();
    Builder::new().build()
}
