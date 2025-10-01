// Copyright (C) 2025 Ellie Fisher
//
// This file is part of the Peg source code. It may be used under the BSD 3-Clause License.
//
// For full terms, see the LICENSE file or visit https://spdx.org/licenses/BSD-3-Clause.html

const U32orU64 = @import("byte_reader.zig").U32orU64;

pub const MS_DOS_SIGNATURE: u16 = 0x5A4D;

pub const PE_HEADER_OFFSET: u16 = 0x3C;
pub const PE_SIGNATURE = [_]u8{ 'P', 'E', '\x00', '\x00' };

pub const PE32_MAGIC: u16 = 0x10B;
pub const PE64_MAGIC: u16 = 0x20B;
pub const ROM_MAGIC: u16 = 0x107;

pub const CoffHeader = struct {
    machine: MachineType,
    num_sections: u16,
    time_date_stamp: u32,
    symbol_table_ptr: u32,
    num_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
};

pub const OptionalHeader = struct {
    // Standard COFF header fields

    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_init_data: u32,
    size_of_uninit_data: u32,
    entry_point_addr: u32,
    base_of_code_addr: u32,

    // Windows-only fields

    base_of_data_addr: u32,
    image_base: U32orU64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: Subsystem,
    dll_characteristics: u16,
    size_of_stack_reserve: U32orU64,
    size_of_stack_commit: U32orU64,
    size_of_heap_reserve: U32orU64,
    size_of_heap_commit: U32orU64,
    loader_flags: u32,
    num_rvas_and_sizes: u32,
};

pub const DataDirectory = struct {
    virtual_addr: u32,
    size: u32,
};

pub const OptionalDataDirectories = struct {
    export_table: DataDirectory,
    import_table: DataDirectory,
    resource_table: DataDirectory,
    exception_table: DataDirectory,
    certificate_table: DataDirectory,
    base_reloc_table: DataDirectory,
    debug: DataDirectory,
    architecture: DataDirectory,
    global_ptr: DataDirectory,
    tls_table: DataDirectory,
    load_config_table: DataDirectory,
    bound_import: DataDirectory,
    import_addr_table: DataDirectory,
    delay_import_descriptor: DataDirectory,
    clr_runtime_header: DataDirectory,
    _reserved: DataDirectory,
};

pub const SectionTableEntry = struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_addr: u32,
    raw_data_size: u32,
    raw_data_ptr: u32,
    relocs_ptr: u32,
    line_numbers_ptr: u32,
    num_relocs: u16,
    num_line_numbers: u16,
    characters: SectionFlags,
};

/// The CPU type this program is meant to run on.
pub const MachineType = enum(u16) {
    /// The content of this field is assumed to be applicable to any machine type.
    UNKNOWN = 0x0,

    /// Alpha AXP, 32-bit address space
    ALPHA = 0x184,

    /// Alpha 64, 64-bit address space
    ALPHA64 = 0x284,

    /// Matsushita AM33
    AM33 = 0x1D3,

    /// x64
    AMD64 = 0x8664,

    /// ARM little endian
    ARM = 0x1C0,

    /// ARM64 little endian
    ARM64 = 0xAA64,

    /// ABI that enables interoperability between native ARM64 and emulated x64 code.
    ARM64EC = 0xA641,

    /// Binary format that allows both native ARM64 and ARM64EC code to coexist in the same file.
    ARM64X = 0xA64E,

    /// ARM Thumb-2 little endian
    ARMNT = 0x1C4,

    /// EFI byte code
    EBC = 0xEBC,

    /// Intel 386 or later processors and compatible processors
    I386 = 0x14C,

    /// Intel Itanium processor family
    IA64 = 0x200,

    /// LoongArch 32-bit processor family
    LOONGARCH32 = 0x6232,

    /// LoongArch 64-bit processor family
    LOONGARCH64 = 0x6264,

    /// Mitsubishi M32R little endian
    M32R = 0x9041,

    /// MIPS16
    MIPS16 = 0x266,

    /// MIPS with FPU
    MIPSFPU = 0x366,

    /// MIPS16 with FPU
    MIPSFPU16 = 0x466,

    /// Power PC little endian
    POWERPC = 0x1F0,

    /// Power PC with floating point support
    POWERPCFP = 0x1F1,

    /// MIPS I compatible 32-bit big endian
    R3000BE = 0x160,

    /// MIPS I compatible 32-bit little endian
    R3000 = 0x162,

    /// MIPS III compatible 64-bit little endian
    R4000 = 0x166,

    /// MIPS IV compatible 64-bit little endian
    R10000 = 0x168,

    /// RISC-V 32-bit address space
    RISCV32 = 0x5032,

    /// RISC-V 64-bit address space
    RISCV64 = 0x5064,

    /// RISC-V 128-bit address space
    RISCV128 = 0x5128,

    /// Hitachi SH3
    SH3 = 0x1A2,

    /// Hitachi SH3 DSP
    SH3DSP = 0x1A3,

    /// Hitachi SH4
    SH4 = 0x1A6,

    /// Hitachi SH5
    SH5 = 0x1A8,

    /// Thumb
    THUMB = 0x1C2,

    /// MIPS little-endian WCE v2
    WCEMIPSV2 = 0x169,
};

pub const Characteristics = enum(u16) {
    /// Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain
    /// base relocations and must therefore be loaded at its preferred base address. If the base address is not
    /// available, the loader reports an error. The default behavior of the linker is to strip base relocations from
    /// executable (EXE) files.
    RELOCS_STRIPPED = 0x0001,

    /// Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a
    /// linker error.
    EXECUTABLE_IMAGE = 0x0002,

    /// COFF line numbers have been removed. This flag is deprecated and should be zero.
    LINE_NUMS_STRIPPED = 0x0004,

    /// COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    LOCAL_SYMS_STRIPPED = 0x0008,

    /// Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    AGGRESSIVE_WS_TRIM = 0x0010,

    /// Application can handle > 2-GB addresses.
    LARGE_ADDRESS_AWARE = 0x0020,

    /// This flag is reserved for future use.
    _RESERVED = 0x0040,

    /// Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is
    /// deprecated and should be zero.
    BYTES_REVERSED_LO = 0x0080,

    /// Machine is based on a 32-bit-word architecture.
    @"32BIT_MACHINE" = 0x0100,

    /// Debugging information is removed from the image file.
    DEBUG_STRIPPED = 0x0200,

    /// If the image is on removable media, fully load it and copy it to the swap file.
    REMOVABLE_RUN_FROM_SWAP = 0x0400,

    /// If the image is on network media, fully load it and copy it to the swap file.
    NET_RUN_FROM_SWAP = 0x0800,

    /// The image file is a system file, not a user program.
    SYSTEM = 0x1000,

    /// The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all
    /// purposes, although they cannot be directly run.
    DLL = 0x2000,

    /// The file should be run only on a uniprocessor machine.
    UP_SYSTEM_ONLY = 0x4000,

    /// Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    BYTES_REVERSED_HI = 0x8000,
};

pub const Subsystem = enum(u16) {
    /// An unknown subsystem
    UNKNOWN = 0,

    /// Device drivers and native Windows processes
    NATIVE = 1,

    /// The Windows graphical user interface (GUI) subsystem
    WINDOWS_GUI = 2,

    /// The Windows character subsystem
    WINDOWS_CUI = 3,

    /// The OS/2 character subsystem
    OS2_CUI = 5,

    /// The Posix character subsystem
    POSIX_CUI = 7,

    /// Native Win9x driver
    NATIVE_WINDOWS = 8,

    /// Windows CE
    WINDOWS_CE_GUI = 9,

    /// An Extensible Firmware Interface (EFI) application
    EFI_APPLICATION = 10,

    /// An EFI driver with boot services
    EFI_BOOT_SERVICE_DRIVER = 11,

    /// An EFI driver with run-time services
    EFI_RUNTIME_DRIVER = 12,

    /// An EFI ROM image
    EFI_ROM = 13,

    /// XBOX
    XBOX = 14,

    /// Windows boot application.
    WINDOWS_BOOT_APPLICATION = 16,
};

pub const DllCharacteristics = enum(u16) {
    _RESERVED_1 = 0x0001,
    _RESERVED_2 = 0x0002,
    _RESERVED_3 = 0x0004,
    _RESERVED_4 = 0x0008,

    /// Image can handle a high entropy 64-bit virtual address space.
    HIGH_ENTROPY_VA = 0x0020,

    /// DLL can be relocated at load time.
    DYNAMIC_BASE = 0x0040,

    /// Code Integrity checks are enforced.
    FORCE_INTEGRITY = 0x0080,

    /// Image is NX compatible.
    NX_COMPAT = 0x0100,

    /// Isolation aware, but do not isolate the image.
    NO_ISOLATION = 0x0200,

    /// Does not use structured exception (SE) handling. No SE handler may be called in this image.
    NO_SEH = 0x0400,

    /// Do not bind the image.
    NO_BIND = 0x0800,

    /// Image must execute in an AppContainer.
    APPCONTAINER = 0x1000,

    /// A WDM driver.
    WDM_DRIVER = 0x2000,

    /// Image supports Control Flow Guard.
    GUARD_CF = 0x4000,

    /// Terminal Server aware.
    TERMINAL_SERVER_AWARE = 0x8000,
};

pub const SectionFlags = enum(u32) {
    /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by ALIGN_1BYTES. This is valid only for object files.
    TYPE_NO_PAD = 0x00000008,

    /// Reserved for future use.
    _RESERVED_1 = 0x00000010,

    /// The section contains executable code.
    CNT_CODE = 0x00000020,

    /// The section contains initialized data.
    CNT_INITIALIZED_DATA = 0x00000040,

    /// The section contains uninitialized data.
    CNT_UNINITIALIZED_DATA = 0x00000080,

    /// Reserved for future use.
    LNK_OTHER = 0x00000100,

    /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    LNK_INFO = 0x00000200,

    /// Reserved for future use.
    _RESERVED_2 = 0x00000400,

    /// The section will not become part of the image. This is valid only for object files.
    LNK_REMOVE = 0x00000800,

    /// The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    LNK_COMDAT = 0x00001000,

    /// The section contains data referenced through the global pointer (GP).
    GPREL = 0x00008000,

    /// Reserved for future use.
    MEM_PURGEABLE = 0x00020000,

    /// Reserved for future use.
    MEM_LOCKED = 0x00040000,

    /// Reserved for future use.
    MEM_PRELOAD = 0x00080000,

    /// Align data on a 1-byte boundary. Valid only for object files.
    ALIGN_1BYTES = 0x00100000,

    /// Align data on a 2-byte boundary. Valid only for object files.
    ALIGN_2BYTES = 0x00200000,

    /// Align data on a 4-byte boundary. Valid only for object files.
    ALIGN_4BYTES = 0x00300000,

    /// Align data on an 8-byte boundary. Valid only for object files.
    ALIGN_8BYTES = 0x00400000,

    /// Align data on a 16-byte boundary. Valid only for object files.
    ALIGN_16BYTES = 0x00500000,

    /// Align data on a 32-byte boundary. Valid only for object files.
    ALIGN_32BYTES = 0x00600000,

    /// Align data on a 64-byte boundary. Valid only for object files.
    ALIGN_64BYTES = 0x00700000,

    /// Align data on a 128-byte boundary. Valid only for object files.
    ALIGN_128BYTES = 0x00800000,

    /// Align data on a 256-byte boundary. Valid only for object files.
    ALIGN_256BYTES = 0x00900000,

    /// Align data on a 512-byte boundary. Valid only for object files.
    ALIGN_512BYTES = 0x00A00000,

    /// Align data on a 1024-byte boundary. Valid only for object files.
    ALIGN_1024BYTES = 0x00B00000,

    /// Align data on a 2048-byte boundary. Valid only for object files.
    ALIGN_2048BYTES = 0x00C00000,

    /// Align data on a 4096-byte boundary. Valid only for object files.
    ALIGN_4096BYTES = 0x00D00000,

    /// Align data on an 8192-byte boundary. Valid only for object files.
    ALIGN_8192BYTES = 0x00E00000,

    /// The section contains extended relocations.
    LNK_NRELOC_OVFL = 0x01000000,

    /// The section can be discarded as needed.
    MEM_DISCARDABLE = 0x02000000,

    /// The section cannot be cached.
    MEM_NOT_CACHED = 0x04000000,

    /// The section is not pageable.
    MEM_NOT_PAGED = 0x08000000,

    /// The section can be shared in memory.
    MEM_SHARED = 0x10000000,

    /// The section can be executed as code.
    MEM_EXECUTE = 0x20000000,

    /// The section can be read.
    MEM_READ = 0x40000000,

    /// The section can be written to.
    MEM_WRITE = 0x80000000,
};
