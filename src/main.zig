// Copyright (C) 2025 Ellie Fisher
//
// This file is part of the Peg source code. It may be used under the BSD 3-Clause License.
//
// For full terms, see the LICENSE file or visit https://spdx.org/licenses/BSD-3-Clause.html

const std = @import("std");
const peg = @import("peg.zig");

pub fn main() !void {
    const file = try std.fs.cwd().openFile("./test.exe", .{ .mode = .read_only });
    defer file.close();

    const stat = try file.stat();
    const size = stat.size;

    const buffer = try std.heap.page_allocator.alloc(u8, size);
    defer std.heap.page_allocator.free(buffer);

    _ = try file.readAll(buffer);
    var reader = peg.PEReader{ .byte_reader = peg.ByteReader{ .index = 0, .bytes = buffer } };

    if (reader.check_signature()) {
        std.debug.print("{}\n\n", .{try reader.read_coff_header()});

        const optional = try reader.read_optional_header();

        std.debug.print("{}\n\n", .{optional});
        std.debug.print("{any}\n\n", .{try reader.read_optional_data_dirs(std.heap.page_allocator, optional.num_rvas_and_sizes)});
    }
}
