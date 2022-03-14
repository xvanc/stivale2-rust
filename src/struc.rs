/*
 * Copyright (c) 2022 xvanc <xvancm@gmail.com> and contributors
 * SPDX-License-Identifier: BSD-2-Clause
 */

use crate::{StivaleTag, StructTag, Tag, Guid};
use core::{ptr::NonNull, sync::atomic::{AtomicU64, Ordering}};

/// Stivale Struct
///
/// This structure is used by the bootloader to pass information to the kernel.
#[repr(C)]
pub struct StivaleStruct {
    bootloader_brand: [u8; 64],
    bootloader_version: [u8; 64],
    tags: Option<NonNull<Tag>>,
}

impl StivaleStruct {
    /// Returns the bootloader brand string
    pub fn bootloader_brand(&self) -> &str {
        let len = self.bootloader_brand.partition_point(|c| *c == 0);
        unsafe { core::str::from_utf8_unchecked(&self.bootloader_brand[..len]) }
    }

    /// Returns the bootloader's version as a string
    pub fn bootloader_version(&self) -> &str {
        let len = self.bootloader_version.partition_point(|c| *c == 0);
        unsafe { core::str::from_utf8_unchecked(&self.bootloader_version[..len]) }
    }

    pub fn find_tag<T: StivaleTag + StructTag>(&self) -> Option<&T> {
        let mut tags = self.tags;

        while let Some(ptr) = tags {
            let tag = unsafe { ptr.as_ref() };

            if let Some(tag) = tag.into_type() {
                return Some(tag);
            }

            tags = tag.next;
        }

        None
    }
}

macro_rules! struct_tag {
    (
        $(#[$m:meta])*
        struct $name:ident : $id:literal;
    ) => {
        struct_tag! {
            $(#[$m])*
            struct $name : $id {}
        }
    };

    (
        $(#[$m:meta])*
        struct $name:ident : $id:literal {
            $(
                $(#[$fm:meta])*
                $field:ident: $t:ty
            ),*$(,)?
        }
    ) => {
        $(#[$m])*
        #[repr(C)]
        pub struct $name {
            tag: Tag,
            $(
                $(#[$fm])*
                $field: $t
            ),*
        }

        #[allow(deprecated)]
        impl crate::private::Sealed for $name {}

        #[allow(deprecated)]
        unsafe impl Send for $name {}
        #[allow(deprecated)]
        unsafe impl Sync for $name {}
        #[allow(deprecated)]
        impl StructTag for $name {}

        #[allow(deprecated)]
        impl const StivaleTag for $name {
            const IDENT: u64 = $id;

            fn as_non_null_tag_ptr(&self) -> NonNull<Tag> {
                NonNull::new(&self.tag as *const _ as _).unwrap()
            }

            fn tag_for() -> Tag {
                Tag {
                    ident: Self::IDENT,
                    next: None,
                }
            }
        }
    };
}

struct_tag! {
    /// Physical Memory Ranges
    ///
    /// This tag is returned to the kernel when the bootloader has recognized the [`ENABLE_PMRS`]
    /// flag and has mapped the kernel as specified by its ELF segments.
    struct PmrsTag : 0x5df266a64047b6bd {
        len: u64,
        pmrs: [Pmr; 0],
    }
}

impl core::fmt::Debug for PmrsTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmrsTag")
            .field("tag", &self.tag)
            .field("len", &self.len)
            .field("pmrs", &core::ops::Deref::deref(self))
            .finish()
    }
}

impl core::ops::Deref for PmrsTag {
    type Target = [Pmr];

    fn deref(&self) -> &Self::Target {
        self.pmrs()
    }
}

impl PmrsTag {
    /// Returns the [`Pmr`] entries as a slice
    pub fn pmrs(&self) -> &[Pmr] {
        unsafe { core::slice::from_raw_parts(self.pmrs.as_ptr(), self.len as usize) }
    }
}

bitflags::bitflags! {
    pub struct PmrFlags : u64 {
        const EXEC = 1 << 0;
        const WRITE = 1 << 1;
        const READ = 1 << 2;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Pmr {
    base: u64,
    size: u64,
    flags: u64,
}

impl Pmr {
    /// Returns the virtual base address of the segment
    pub fn base(&self) -> usize {
        self.base as _
    }

    /// Returns the size of the segment in bytes
    pub fn size(&self) -> usize {
        self.size as _
    }

    pub fn flags(&self) -> PmrFlags {
        PmrFlags::from_bits_truncate(self.flags)
    }

    /// Returns `true` if the segment is readable
    pub fn is_readable(&self) -> bool {
        self.flags().contains(PmrFlags::READ)
    }

    /// Returns `true` if the segment is writable
    pub fn is_writable(&self) -> bool {
        self.flags().contains(PmrFlags::WRITE)
    }

    /// Returns `true` if the segment is executable
    pub fn is_executable(&self) -> bool {
        self.flags().contains(PmrFlags::EXEC)
    }
}

struct_tag! {
    /// Kernel Base Address
    ///
    /// This tag returns the physical and virtual load addresses of the kernel image. This tag is
    /// only returned when PMRs are enabled ([`ENABLE_PMR`]) with fully-virtual mappings
    /// ([`V`]), and the bootloader supports the feature.
    #[derive(Debug)]
    struct KernelBaseTag : 0x060d78874a2a8af0 {
        phys_base: u64,
        virt_base: u64,
    }
}

impl KernelBaseTag {
    /// Returns the physical base address of the kernel image
    pub fn phys_base(&self) -> u64 {
        self.phys_base
    }

    /// Returns the virtual base address of the kernel image
    pub fn virt_base(&self) -> u64 {
        self.virt_base
    }
}

struct_tag! {
    /// Kernel Command Line
    ///
    /// This tag returns the kernel command line passed from the bootloader.
    #[derive(Debug)]
    struct CmdlineTag : 0xe5e76a1b4597a781 {
        cmdline: Option<NonNull<u8>>,
    }
}

impl CmdlineTag {
    pub fn as_ptr(&self) -> *const u8 {
        self.cmdline.map_or(core::ptr::null(), |p| p.as_ptr() as _)
    }
}

struct_tag! {
    /// Physical Memory Map
    ///
    /// The map entries are guaranteed to be sorted from lowest to highest based on the base
    /// address of the region. Additionally, usable and bootloader-reclaimable regions are
    /// guaranteed to be page-aligned (base and size), and to not overlap with any other regions.
    struct MmapTag : 0x2187f79e8612de07 {
        len: u64,
        entries: [MmapEntry; 0],
    }
}

impl core::fmt::Debug for MmapTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MmapTag")
            .field("tag", &self.tag)
            .field("len", &self.len)
            .field("entries", &core::ops::Deref::deref(self))
            .finish()
    }
}

impl core::ops::Deref for MmapTag {
    type Target = [MmapEntry];

    fn deref(&self) -> &Self::Target {
        unsafe { core::slice::from_raw_parts(self.entries.as_ptr(), self.len as usize) }
    }
}

/// A memory region in the [Physical Memory Map](MmapTag)
///
/// Each entry describes the base, size, and [kind](MmapKind) of a memory region.
/// [`Usable`](MmapKind::Usable) and [`BootloaderReclaim`](MmapKind::BootloaderReclaim) regions
/// are guaranteed to have both their base and size aligned to the smallest page size.
#[repr(C)]
#[derive(Debug)]
pub struct MmapEntry {
    base: u64,
    size: u64,
    kind: u32,
    _unused: u32,
}

impl MmapEntry {
    /// Returns the physical base address of the region
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Returns the size of the region in bytes
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the type of the memory region
    pub fn kind(&self) -> MmapKind {
        use MmapKind::*;

        match self.kind {
            0x0001 => Usable,
            0x0002 => Reserved,
            0x0003 => AcpiReclaim,
            0x0004 => AcpiReserved,
            0x0005 => BadMemory,
            0x1000 => BootloaderReclaim,
            0x1001 => KernelModules,
            0x1002 => Framebuffer,
            0x1003 => EfiReclaim,
            0x1004 => EfiBootServices,
            n => Unknown(n),
        }
    }

    /// Returns `true` if the region is usable memory
    pub fn is_usable(&self) -> bool {
        self.kind() == MmapKind::Usable
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MmapKind {
    /// Usable Memory
    ///
    /// These regions of memory can be freely used by the kernel.
    Usable,
    /// Reserved Memory
    ///
    /// These regions are reserved by the system and *may not* be used by the kernel.
    Reserved,
    /// ACPI Reclaimable Memory
    ///
    /// These regions are used by certain ACPI structures. The kernel may reclaim these regions
    /// as usable once it has finished parsing the structures within them.
    AcpiReclaim,
    /// ACPI Reserved Memory
    ///
    /// These regions are reserved by the ACPI firmware and *may not* be used by the kernel.
    AcpiReserved,
    /// Bad Memory
    ///
    /// These regions have been reported bad by the system or bootloader and shouldn't be used
    /// by the kernel.
    BadMemory,
    /// Bootloader Reclaimable Memory
    ///
    /// These regions are used by certain bootloader structures. The kernel may reclaim these
    /// regions as usable once it has finished parsing the structures within them.
    BootloaderReclaim,
    /// Kernel Modules
    ///
    /// These regions contain modules loaded by the bootloader on behalf of the kernel. The kernel
    /// image itself is reported in one of these regions.
    KernelModules,
    /// Graphical Framebuffer
    Framebuffer,
    /// EFI Reclaimable Memory
    ///
    /// These regions are used by certain EFI structures. The kernel may reclaim these regions
    /// as usable once it has finished parsing the structures within them.
    EfiReclaim,
    EfiBootServices,
    Unknown(u32),
}

struct_tag! {
    /// Framebuffer Tag
    ///
    /// This tag is returned when the bootloader has set up a graphical framebuffer for the kernel
    /// to use.
    #[derive(Debug)]
    struct FramebufferTag : 0x506461d2950408fa {
        addr: u64,
        width: u16,
        height: u16,
        pitch: u16,
        bpp: u16,
        format: u8,
        rmask_size: u8,
        rmask_shift: u8,
        gmask_size: u8,
        gmask_shift: u8,
        bmask_size: u8,
        bmask_shift: u8,
        _unused: u8,
    }
}

pub enum PixelFormat {
    Rgb,
    Unknown(u8),
}

impl FramebufferTag {
    pub const fn addr(&self) -> u64 {
        self.addr
    }

    /// Returns the width of the framebuffer in pixels
    pub const fn width(&self) -> usize {
        self.width as _
    }

    /// Returns the height of the framebuffer in pixels
    pub const fn height(&self) -> usize {
        self.height as _
    }

    /// Returns the pitch of the framebuffer in bytes
    pub const fn pitch(&self) -> usize {
        self.pitch as _
    }

    /// Returns the number of bits per pixel
    pub const fn bits_per_pixel(&self) -> usize {
        self.bpp as _
    }

    pub const fn pixel_format(&self) -> PixelFormat {
        match self.format {
            1 => PixelFormat::Rgb,
            _ => PixelFormat::Unknown(self.format),
        }
    }

    pub const fn red_mask_size(&self) -> usize {
        self.rmask_size as _
    }

    pub const fn red_mask_shift(&self) -> usize {
        self.rmask_shift as _
    }

    pub const fn green_mask_size(&self) -> usize {
        self.gmask_size as _
    }

    pub const fn green_mask_shift(&self) -> usize {
        self.gmask_shift as _
    }

    pub const fn blue_mask_size(&self) -> usize {
        self.bmask_size as _
    }

    pub const fn blue_mask_shift(&self) -> usize {
        self.bmask_shift as _
    }
}

struct_tag! {
    /// Text Mode Tag
    ///
    /// This tag is returned when the bootloader has set up a GCA text mode buffer for the kernel
    /// to use.
    #[derive(Debug)]
    struct TextModeTag : 0x38d74c23e0dca893 {
        addr: u64,
        _unused: u16,
        rows: u16,
        cols: u16,
        bytes_per_char: u16,
    }
}

impl TextModeTag {
    pub const fn addr(&self) -> u64 {
        self.addr
    }

    /// Returns the number of rows in the text mode buffer
    pub const fn rows(&self) -> usize {
        self.rows as _
    }
    /// Returns the number of columns in the text mode buffer
    pub const fn cols(&self) -> usize {
        self.cols as _
    }
    /// Returns the number bytes per character
    pub const fn bytes_per_char(&self) -> usize {
        self.bytes_per_char as _
    }
}

struct_tag! {
    /// EDID Information Tag
    ///
    /// This tag reports the EDID information structure, if one was provided by the firmware.
    struct EdidInfoTag : 0x968609d7af96b845 {
        len: u64,
        data: [u8; 0]
    }
}

impl core::fmt::Debug for EdidInfoTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EdidInfoTag")
            .field("tag", &self.tag)
            .field("len", &self.len)
            .field("data", &self.data.as_ptr()).finish()
    }
}

impl EdidInfoTag {
    /// Returns the EDID information data as a slice
    pub fn data(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(self.data.as_ptr(), self.len as _)
        }
    }
}

struct_tag! {
    /// Framebuffer MTRR
    ///
    /// This tag is returns when the bootloader has successfully set up MTRR write-combining for
    /// the framebuffer.
    #[derive(Debug)]
    #[deprecated = concat!(
        "This tag has been deprecated by the stivale2 protocol",
        " and may not be supported by more recent bootloaders."
    )]
    struct FramebufferMtrrTag : 0x6bc1a78ebe871172;
}

struct_tag! {
    #[derive(Debug)]
    struct TerminalTag : 0xc2b3f4c3233b0974 {
        flags: u32,
        cols: u16,
        rows: u16,
        term_write: u64,
        max_len: u64,
    }
}

bitflags::bitflags! {
    pub struct TerminalFlags : u32 {
        const COLS_ROWS_VALID  = 1 << 0;
        const MAX_LEN_VALID    = 1 << 1;
        const CALLBACK_SUPPORT = 1 << 2;
        const CONTEXT_CONTROL  = 1 << 3;
    }
}

/// Terminal Write Function
///
/// This function is neither thread-safe nor re-entrant.
pub type TermWriteFn = extern "C" fn(*const u8, u64);

impl TerminalTag {
    pub const fn rows(&self) -> Option<usize> {
        if self.flags().contains(TerminalFlags::COLS_ROWS_VALID) {
            Some(self.rows as _)
        } else {
            None
        }
    }

    pub const fn cols(&self) -> Option<usize> {
        if self.flags().contains(TerminalFlags::COLS_ROWS_VALID) {
            Some(self.cols as _)
        } else {
            None
        }
    }

    pub const fn max_len(&self) -> Option<usize> {
        if self.flags().contains(TerminalFlags::MAX_LEN_VALID) {
            Some(self.max_len as _)
        } else {
            None
        }
    }

    pub const fn flags(&self) -> TerminalFlags {
        TerminalFlags::from_bits_truncate(self.flags)
    }
}

struct_tag! {
    /// Modules Tag
    ///
    /// This tag enumerates any modules that were loaded on behalf of the kernel.
    #[derive(Debug)]
    struct ModulesTag : 0x4b6fe466aade04ce {
        len: u64,
        mods: [Module; 0],
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Module {
    start: u64,
    end: u64,
    string: [u8; 128],
}

impl Module {
    /// Returns the string that was passed to the module
    pub fn string(&self) -> &[u8] {
        &self.string
    }

    /// Returns the start address of the module
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Returns the end address of the module
    pub const fn end(&self) -> u64 {
        self.end
    }
}

struct_tag! {
    /// ACPI Root System Description Pointer (RSDP) Tag
    ///
    /// This tag returns the location of the RSDP structure.
    #[derive(Debug)]
    struct RsdpTag : 0x9e1786930a375e78 {
        addr: u64,
    }
}

impl RsdpTag {
    /// Returns the address of the RSDP structure
    pub const fn addr(&self) -> u64 {
        self.addr
    }
}

struct_tag! {
    /// SMBIOS Tag
    ///
    /// This tag returns the location of the SMBIOS entry point.
    #[derive(Debug)]
    struct SmBiosTag : 0x274bd246c62bf7d1 {
        flags: u64,
        entry32: u64,
        entry64: u64,
    }
}

bitflags::bitflags! {
    pub struct SmBiosFlags : u64 {
        /* no flags currently defined */
    }
}

impl SmBiosTag {
    pub const fn flags(&self) -> SmBiosFlags {
        SmBiosFlags::from_bits_truncate(self.flags)
    }

    /// Returns the 32-bit SMBIOS entry point
    pub const fn entry32(&self) -> u64 {
        self.entry32
    }

    /// Returns the 64-bit SMBIOS entry point
    pub const fn entry64(&self) -> u64 {
        self.entry64
    }
}

struct_tag! {
    /// Epoch Tag
    ///
    /// This tag returns the current UNIX epoch as reported by the RTC, if any.
    #[derive(Debug)]
    struct EpochTag : 0x566a7bed888e1407 {
        epoch: u64,
    }
}

impl EpochTag {
    /// Returns the UNIX epoch at boot
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

struct_tag! {
    /// Firmware Tag
    ///
    /// This tag reports information about the firmware.
    #[derive(Debug)]
    struct FirmwareTag : 0x359d837855e3858c {
        flags: u64,
    }
}

struct_tag! {
    /// EFI System Table Tag
    ///
    /// This tag returns a pointer to the EFI system table, if available.
    #[derive(Debug)]
    struct EfiSystemTableTag : 0x4bc5ec15845b558e {
        addr: u64,
    }
}

impl EfiSystemTableTag {
    pub const fn addr(&self) -> u64 {
        self.addr
    }
}

struct_tag! {
    /// Kernel File Tag
    #[derive(Debug)]
    struct KernelFileTag : 0xe599d90c2975584a {
        addr: u64,
    }
}

impl KernelFileTag {
    pub const fn data(&self) -> *const u8 {
        self.addr as _
    }
}

struct_tag! {
    /// Kernel File v2 Tag
    #[derive(Debug)]
    struct KernelFileV2Tag : 0x37c13018a02c6ea2 {
        addr: u64,
        len: u64,
    }
}

impl KernelFileV2Tag {
    pub fn data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.addr as *const _, self.len as _) }
    }
}

struct_tag! {
    /// Boot Volume Tag
    ///
    /// This tag returns the GUID of the volume and partition from which the kernel was loaded.
    #[derive(Debug)]
    struct BootVolumeTag : 0x9b4358364c19ee62 {
        flags: u64,
        guid: Guid,
        part_guid: Guid,
    }
}

bitflags::bitflags! {
    pub struct BootVolumeFlags : u64 {
        /// Volume GUID Valid
        ///
        /// The volume GUID returned by the tag is valid.
        const GUID_VALID        = 1 << 0;
        /// Partition GUID Valid
        ///
        /// The partition GUID returned by the tag is valid.
        const PART_GUID_VALID   = 1 << 1;
    }
}

impl BootVolumeTag {
    pub const fn flags(&self) -> BootVolumeFlags {
        BootVolumeFlags::from_bits_truncate(self.flags)
    }

    pub const fn volume_guid(&self) -> Option<Guid> {
        if self.flags().contains(BootVolumeFlags::GUID_VALID) {
            Some(self.guid)
        } else {
            None
        }
    }

    pub const fn partition_guid(&self) -> Option<Guid> {
        if self.flags().contains(BootVolumeFlags::PART_GUID_VALID) {
            Some(self.part_guid)
        } else {
            None
        }
    }
}

struct_tag! {
    /// Kernel Slide Tag
    ///
    /// This tag returns the slide that was applied by the bootloader to the kernel's load address.
    #[derive(Debug)]
    struct KernelSlideTag : 0xee80847d01506c57 {
        slide: u64,
    }
}

impl KernelSlideTag {
    /// Returns the kernel slide as a positive offset from the kernel's load address
    pub const fn slide(&self) -> u64 {
        self.slide
    }
}

struct_tag! {
    #[derive(Debug)]
    struct SmpTag : 0x34d1d96339647025 {
        flags: u64,
        bsp_lapic_id: u32,
        _unused: u32,
        num_cpu: u64,
        smp_info: [SmpInfo; 0],
    }
}

impl SmpTag {
    /// Returns the APIC ID of the bootstrap processor
    pub fn bsp_lapic_id(&self) -> u32 {
        self.bsp_lapic_id
    }

    /// Returns the array of [`SmpInfo`] describing each processor
    pub fn smp_info(&self) -> &[SmpInfo] {
        unsafe { core::slice::from_raw_parts(self.smp_info.as_ptr(), self.num_cpu as usize) }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct SmpInfo {
    puid: u32,
    lapic_id: u32,
    stack_ptr: AtomicU64,
    instr_ptr: AtomicU64,
    func_arg: AtomicU64,
}

impl SmpInfo {
    /// Returns the processor UID as specified in the ACPI MADT
    pub const fn processor_uid(&self) -> u32 {
        self.puid
    }

    /// Returns the processor's LAPIC ID as specified in the ACPI MADT
    pub const fn lapic_id(&self) -> u32 {
        self.lapic_id
    }

    /// Start up the application processor described by this entry
    ///
    /// # Safety
    ///
    /// - `stack` must point to a 16-byte aligned stack with at least 256 bytes available
    /// - `addr` must point to executable code for the AP to execute
    pub unsafe fn start(&self, stack: *mut u8, addr: u64, arg: u64) {
        self.stack_ptr.store(stack as _, Ordering::SeqCst);
        self.func_arg.store(arg, Ordering::SeqCst);

        // The bootloader sets up the APs to poll this field for an atomic write.
        self.instr_ptr.store(addr, Ordering::SeqCst);
    }
}

struct_tag! {
    /// PXE Server Tag
    ///
    /// This tag reports the IP address of the PXE server from which the kernel was booted.
    #[derive(Debug)]
    struct PxeServerTag : 0x29d1e96239247032 {
        server_ipv4: u32,
    }
}

impl PxeServerTag {
    /// Returns the IPv4 address of the boot PXE server
    pub const fn server_ipv4(&self) -> u32 {
        self.server_ipv4
    }
}

struct_tag! {
    #[derive(Debug)]
    struct Mmio32UartTag : 0xb813f9b8dbc78797 {
        addr: u64,
    }
}

impl Mmio32UartTag {
    pub const fn addr(&self) -> u64 {
        self.addr
    }
}

struct_tag! {
    /// Device Tree Blob Tag
    #[derive(Debug)]
    struct DtbTag : 0xabb29bd49a2833fa {
        addr: u64,
        len: u64,
    }
}

impl DtbTag {
    pub fn data(&self) -> &[u8] {
        let ptr = self.addr as *const u8;
        assert!(!ptr.is_null());
        unsafe {
            core::slice::from_raw_parts(self.addr as _, self.len as _)
        }
    }
}

struct_tag! {
    /// Higher Half Direct Map Tag
    ///
    /// This tag reports the address of the Higher Half Direct Map (HHDM).
    #[derive(Debug)]
    struct HhdmTag : 0xb0ed257db18cb58f {
        addr: u64,
    }
}

impl HhdmTag {
    /// Returns the address of the HHDM
    pub const fn addr(&self) -> u64 {
        self.addr
    }
}
