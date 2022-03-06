/*
 * Copyright (c) 2022 xvanc <xvancm@gmail.com> and contributors
 * SPDX-License-Identifier: BSD-2-Clause
 */
//! Stivale2 Header
//!
//! # Tags
//!
//! The kernel attaches to the [`StivaleHeader`] a linked list of tags in order to request various
//! features defined by the stivale2 protocol. Compliant bootloaders are free to ignore any tags
//! which they don't recognize; it is the kernel's responsiblilty to verify that the bootloader has
//! processed the tags provided to it, either by the tags returned to the kernel in the
//! [`StivaleStruct`] structure, or other means provided by the protocol.

use crate::{struc::StivaleStruct, HeaderTag, StivaleTag, Tag};
use core::ptr::NonNull;

/// Kernel Entry Point
///
/// The kernel entry point must be a function conforming to the C calling convention for the target
/// platform. It is required to never return.
pub type EntryPointFn = extern "C" fn(&'static StivaleStruct) -> !;

bitflags::bitflags! {
    /// Header Flags
    ///
    /// Certain stivale2 features are enabled via flags in the [`StivaleHeader`] rather than the
    /// linked list of header tags.
    pub struct HeaderFlags : u64 {
        /// Provide all pointers in the HHDM
        ///
        /// When this flag is specified, all physical pointers (not explicity defined as physical
        /// addresses) are offset into the Higher Half Direct Map.
        const HHDM_POINTERS = 1 << 1;
        /// Enable Protected Memory Ranges
        ///
        /// This flag instructs the bootloader to load the kernel as specified by its ELF segments,
        /// rather than mapping the high 2 GiB of the linear address space as one single, RWX
        /// segment. Only higher-half, 64-bit, ELF (non-anchored) kernels can use this feature.
        const PMR_ENABLE    = 1 << 2;
        /// Fully-virtual PMRs
        ///
        /// When this flag is set along with [`PMR_ENABLE`], indicates to the bootloader that the
        /// kernel does not require a strict `phys = virt - 0xffffffff80000000` correspondence for
        /// kernel segment addresses.
        const PMR_VIRTUAL   = 1 << 3;
        /// Don't require low memory to boot
        ///
        /// When this flag is set, the bootloader will not fail to boot if it cannot allocate
        /// memory below 1 MiB.
        const NO_REQ_LOWMEM = 1 << 4;
    }
}

/// Kernel Header
///
/// The kernel uses this structure to provide information to the bootloader about how it wants to
/// be booted.
#[repr(C)]
pub struct StivaleHeader {
    entry_point: Option<EntryPointFn>,
    stack_ptr: Option<NonNull<u8>>,
    flags: HeaderFlags,
    tags: Option<NonNull<Tag>>,
}

// SAFETY: We don't provide any way for the values to be modified after initialization.
unsafe impl Send for StivaleHeader {}
unsafe impl Sync for StivaleHeader {}

impl StivaleHeader {
    pub const fn new(flags: HeaderFlags) -> StivaleHeader {
        Self {
            entry_point: None,
            stack_ptr: None,
            flags,
            tags: None,
        }
    }

    /// Sets the entry point called by the bootloader
    ///
    /// This value will be used instead of the entry point in the kernel's ELF.
    pub const fn entry_point(mut self, entry_point: EntryPointFn) -> Self {
        self.entry_point = Some(entry_point);
        self
    }

    /// Sets the stack pointer loaded before control is passed to the kernel
    ///
    /// The stack is required to be at 256 bytes in size, aligned to at least 16 bytes.
    ///
    /// ## Panics
    ///
    /// This function panics if `stack_ptr` is not properly aligned.
    pub const fn stack_ptr(mut self, stack_ptr: NonNull<u8>) -> Self {
        assert!(stack_ptr.as_ptr().align_offset(16) == 0);
        self.stack_ptr = Some(stack_ptr);
        self
    }

    /// Sets the head of the linked list of header tags
    ///
    /// Additional tags can be chained via the `link()` method on each tag.
    pub const fn tags<T>(mut self, tags: &T) -> Self
    where
        T: HeaderTag + ~const StivaleTag,
    {
        self.tags = Some(tags.as_non_null_tag_ptr());
        self
    }
}

macro_rules! header_tag {
    (
        $(#[$m:meta])*
        struct $name:ident : $id:literal;
    ) => {
        header_tag! {
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

        impl HeaderTag for $name {}

        impl $name {
            /// Links another header tag to this tag
            ///
            /// ## Panics
            ///
            /// This function panics if it is called more than once.
            pub const fn link<T>(mut self, next: &T) -> Self
            where
                T: ~const StivaleTag + HeaderTag,
            {
                assert!(self.tag.next.is_none(), "the `link()` method may only be called once");
                self.tag.next = Some(next.as_non_null_tag_ptr());
                self
            }
        }

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

header_tag! {
    struct AnyVideoHeaderTag : 0xc75c9fa92a44c4db {
        pref: VideoPreference,
    }
}

#[repr(u64)]
pub enum VideoPreference {
    Linear = 0,
    NoLinear = 1,
}

impl AnyVideoHeaderTag {
    pub const fn new(pref: VideoPreference) -> AnyVideoHeaderTag {
        Self {
            tag: Self::tag_for(),
            pref,
        }
    }
}

header_tag! {
    struct FramebufferHeaderTag : 0x3ecc1bc43d0f7971 {
        width: u16,
        height: u16,
        bpp: u16,
        _unused: u16,
    }
}

impl FramebufferHeaderTag {
    pub const fn new() -> FramebufferHeaderTag {
        Self {
            tag: Self::tag_for(),
            width: 0,
            height: 0,
            bpp: 0,
            _unused: 0,
        }
    }

    pub const fn width(mut self, width: u16) -> Self {
        self.width = width;
        self
    }

    pub const fn height(mut self, height: u16) -> Self {
        self.height = height;
        self
    }

    pub const fn bpp(mut self, bpp: u16) -> Self {
        self.bpp = bpp;
        self
    }
}

header_tag! {
    struct TerminalHeaderTag : 0xa85d499b1823be72 {
        flags: TerminalHeaderFlags,
        callback: Option<TerminalCallbackFn>,
    }
}

pub type TerminalCallbackFn = extern "C" fn() -> i32;

bitflags::bitflags! {
    pub struct TerminalHeaderFlags : u64 {
        const CALLBACK = 1 << 0;
    }
}

impl TerminalHeaderTag {
    pub const fn new() -> TerminalHeaderTag {
        Self {
            tag: Self::tag_for(),
            flags: TerminalHeaderFlags::empty(),
            callback: None,
        }
    }

    pub const fn callback(mut self, callback: TerminalCallbackFn) -> Self {
        self.callback = Some(callback);
        self.flags = self.flags.union(TerminalHeaderFlags::CALLBACK);
        self
    }
}

header_tag! {
    struct HhdmSlideHeaderTag : 0xdc29269c2af53d1d {
        flags: HhdmSlideHeaderFlags,
        align: u64,
    }
}

bitflags::bitflags! {
    pub struct HhdmSlideHeaderFlags : u64 {
        /* no flags are currently defined */
    }
}

impl HhdmSlideHeaderTag {
    pub const fn new() -> HhdmSlideHeaderTag {
        Self {
            tag: Self::tag_for(),
            flags: HhdmSlideHeaderFlags::empty(),
            align: 0,
        }
    }

    pub const fn flags(mut self, flags: HhdmSlideHeaderFlags) -> Self {
        self.flags = flags;
        self
    }

    pub const fn align(mut self, align: u64) -> Self {
        assert!(
            align >= 0x20_0000,
            "The HHDM must be aligned to at least 2 MiB"
        );
        self.align = align;
        self
    }
}

header_tag! {
    struct UnmapNullHeaderTag : 0x92919432b16fe7e7;
}

impl UnmapNullHeaderTag {
    pub const fn new() -> UnmapNullHeaderTag {
        Self {
            tag: Self::tag_for(),
        }
    }
}

header_tag! {
    struct SmpHeaderTag : 0x1ab015085f3273df {
        flags: SmpHeaderFlags,
    }
}

bitflags::bitflags! {
    pub struct SmpHeaderFlags : u64 {
        const X2APIC = 1 << 0;
    }
}

impl SmpHeaderTag {
    pub const fn new() -> SmpHeaderTag {
        Self {
            tag: Self::tag_for(),
            flags: SmpHeaderFlags::empty(),
        }
    }

    pub const fn flags(mut self, flags: SmpHeaderFlags) -> Self {
        self.flags = flags;
        self
    }
}
