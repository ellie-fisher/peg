// Copyright (C) 2025 Ellie Fisher
//
// This file is part of the Peg source code. It may be used under the BSD 3-Clause License.
//
// For full terms, see the LICENSE file or visit https://spdx.org/licenses/BSD-3-Clause.html

const std = @import("std");
const ByteReader = @import("byte_reader.zig").ByteReader;
const pe = @import("pe_structs.zig");

pub const PE_OFFSET: u8 = 0x3C;
pub const PE_SIGNATURE = [_]u8{ 'P', 'E', '\x00', '\x00' };

pub const PEReader = struct {
    byte_reader: ByteReader,

    pub fn check_signature(self: *PEReader) bool {
        // Read PE header offset at `PE_OFFSET`.
        self.byte_reader.seek(PE_OFFSET) catch return false;
        self.byte_reader.seek(self.byte_reader.read_u32() catch return false) catch return false;

        // Check file has PE signature.
        for (PE_SIGNATURE) |ch| {
            const read_ch = self.byte_reader.read_u8() catch return false;

            if (read_ch != ch) {
                return false;
            }
        }

        return true;
    }

    pub fn read_coff_header(self: *PEReader) !pe.CoffHeader {
        return pe.CoffHeader{
            .machine = @enumFromInt(try self.byte_reader.read_u16()),
            .num_sections = try self.byte_reader.read_u16(),
            .time_date_stamp = try self.byte_reader.read_u32(),
            .symbol_table_ptr = try self.byte_reader.read_u32(),
            .num_symbols = try self.byte_reader.read_u32(),
            .size_of_optional_header = try self.byte_reader.read_u16(),
            .characteristics = try self.byte_reader.read_u16(),
        };
    }

    pub fn read_optional_header(self: *PEReader) !pe.OptionalHeader {
        const magic = try self.byte_reader.read_u16();
        const is_pe64 = magic == pe.PE64_MAGIC;

        return pe.OptionalHeader{
            // Standard COFF fields

            .magic = magic,
            .major_linker_version = try self.byte_reader.read_u8(),
            .minor_linker_version = try self.byte_reader.read_u8(),
            .size_of_code = try self.byte_reader.read_u32(),
            .size_of_init_data = try self.byte_reader.read_u32(),
            .size_of_uninit_data = try self.byte_reader.read_u32(),
            .entry_point_addr = try self.byte_reader.read_u32(),
            .base_of_code_addr = try self.byte_reader.read_u32(),

            // Windows-only fields

            .base_of_data_addr = if (is_pe64) try self.byte_reader.read_u32() else 0,
            .image_base = try self.byte_reader.read_u32_or_u64(is_pe64),
            .section_alignment = try self.byte_reader.read_u32(),
            .file_alignment = try self.byte_reader.read_u32(),
            .major_os_version = try self.byte_reader.read_u16(),
            .minor_os_version = try self.byte_reader.read_u16(),
            .major_image_version = try self.byte_reader.read_u16(),
            .minor_image_version = try self.byte_reader.read_u16(),
            .major_subsystem_version = try self.byte_reader.read_u16(),
            .minor_subsystem_version = try self.byte_reader.read_u16(),
            .win32_version_value = try self.byte_reader.read_u32(),
            .size_of_image = try self.byte_reader.read_u32(),
            .size_of_headers = try self.byte_reader.read_u32(),
            .checksum = try self.byte_reader.read_u32(),
            .subsystem = @enumFromInt(try self.byte_reader.read_u16()),
            .dll_characteristics = try self.byte_reader.read_u16(),
            .size_of_stack_reserve = try self.byte_reader.read_u32_or_u64(is_pe64),
            .size_of_stack_commit = try self.byte_reader.read_u32_or_u64(is_pe64),
            .size_of_heap_reserve = try self.byte_reader.read_u32_or_u64(is_pe64),
            .size_of_heap_commit = try self.byte_reader.read_u32_or_u64(is_pe64),
            .loader_flags = try self.byte_reader.read_u32(),
            .num_rvas_and_sizes = try self.byte_reader.read_u32(),
        };
    }

    pub fn read_data_directory(self: *PEReader) !pe.DataDirectory {
        return pe.DataDirectory{
            .virtual_addr = try self.byte_reader.read_u32(),
            .size = try self.byte_reader.read_u32(),
        };
    }

    pub fn read_optional_data_dirs(self: *PEReader) !pe.OptionalDataDirectories {
        return pe.OptionalDataDirectories{
            .export_table = try self.read_data_directory(),
            .import_table = try self.read_data_directory(),
            .resource_table = try self.read_data_directory(),
            .exception_table = try self.read_data_directory(),
            .certificate_table = try self.read_data_directory(),
            .base_reloc_table = try self.read_data_directory(),
            .debug = try self.read_data_directory(),
            .architecture = try self.read_data_directory(),
            .global_ptr = try self.read_data_directory(),
            .tls_table = try self.read_data_directory(),
            .load_config_table = try self.read_data_directory(),
            .bound_import = try self.read_data_directory(),
            .import_addr_table = try self.read_data_directory(),
            .delay_import_descriptor = try self.read_data_directory(),
            .clr_runtime_header = try self.read_data_directory(),
            ._reserved = try self.read_data_directory(),
        };
    }
};
