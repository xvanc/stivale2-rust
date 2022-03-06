use crate::{StivaleTag, StructTag, Tag};
use core::ptr::NonNull;

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

        impl crate::private::Sealed for $name {}

        unsafe impl Send for $name {}
        unsafe impl Sync for $name {}

        impl StructTag for $name {}

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
        entries: [Pmr; 0],
    }
}

impl PmrsTag {
    /// Returns the [`Pmr`] entries as a slice
    pub fn pmrs(&self) -> &[Pmr] {
        unsafe { core::slice::from_raw_parts(self.entries.as_ptr(), self.len as usize) }
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
#[derive(Clone, Copy)]
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

impl core::ops::Deref for MmapTag {
    type Target = [MmapEntry];

    fn deref(&self) -> &Self::Target {
        unsafe { core::slice::from_raw_parts(self.entries.as_ptr(), self.len as usize) }
    }
}

/// A memory region in the [Physical Memory Map](MmapTag)
#[repr(C)]
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
