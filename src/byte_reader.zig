// Copyright (C) 2025 Ellie Fisher
//
// This file is part of the Peg source code. It may be used under the BSD 3-Clause License.
//
// For full terms, see the LICENSE file or visit https://spdx.org/licenses/BSD-3-Clause.html

pub const U32orU64 = union {
    u32: u32,
    u64: u64,
};

const FileReadError = error{
    EOF,
};

pub const ByteReader = struct {
    index: usize,
    bytes: []u8,

    pub fn is_eof(self: *ByteReader) bool {
        return self.index >= self.bytes.len;
    }

    pub fn read_u8(self: *ByteReader) FileReadError!u8 {
        if (self.index >= self.bytes.len) {
            return FileReadError.EOF;
        } else {
            const byte = self.bytes[self.index];
            self.index += 1;
            return byte;
        }
    }

    pub fn read_u16(self: *ByteReader) FileReadError!u16 {
        const low = try self.read_u8();
        const high = try self.read_u8();

        return @as(u16, low) | (@as(u16, high) << 8);
    }

    pub fn read_u32(self: *ByteReader) FileReadError!u32 {
        const low = try self.read_u16();
        const high = try self.read_u16();

        return @as(u32, low) | (@as(u32, high) << 16);
    }

    pub fn read_u64(self: *ByteReader) FileReadError!u64 {
        const low = try self.read_u32();
        const high = try self.read_u32();

        return @as(u64, low) | (@as(u64, high) << 32);
    }

    pub fn read_u32_or_u64(self: *ByteReader, @"u64": bool) FileReadError!U32orU64 {
        return if (@"u64") U32orU64{ .u64 = try self.read_u64() } else U32orU64{ .u32 = try self.read_u32() };
    }

    pub fn seek(self: *ByteReader, index: usize) FileReadError!void {
        if (index < self.bytes.len) {
            self.index = index;
        } else {
            return FileReadError.EOF;
        }
    }
};
