// Copyright (C) 2025 Ellie Fisher
//
// This file is part of the Peg source code. It may be used under the BSD 3-Clause License.
//
// For full terms, see the LICENSE file or visit https://spdx.org/licenses/BSD-3-Clause.html

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("peg", .{
        .root_source_file = b.path("src/peg.zig"),
        .target = target,
    });

    const exe = b.addExecutable(.{
        .name = "peg",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "peg", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);

    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
}
