/*
 * Copyright (c) 2022 xvanc <xvancm@gmail.com> and contributors
 * SPDX-License-Identifier: BSD-2-Clause
 */
#![no_std]
#![feature(
    const_align_offset,
    const_fn_fn_ptr_basics,     // https://github.com/rust-lang/rust/issues/57563
    const_fn_trait_bound,       // https://github.com/rust-lang/rust/issues/93706
    const_nonnull_new,
    const_option,
    const_trait_impl            // https://github.com/rust-lang/rust/issues/67792
)]

#[cfg(not(target_pointer_width = "64"))]
compile_error!("This crate is only designed for 64-bit targets.");

use core::ptr::NonNull;

pub mod header;
pub mod struc;

mod private {
    pub trait Sealed {}
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Tag {
    pub(crate) ident: u64,
    pub(crate) next: Option<NonNull<Tag>>,
}

impl Tag {
    pub const fn null() -> Tag {
        Self {
            ident: 0,
            next: None,
        }
    }

    pub fn into_type<T: StivaleTag>(&self) -> Option<&T> {
        (self.ident == T::IDENT).then(|| unsafe { core::mem::transmute(self) })
    }
}

pub trait StivaleTag {
    const IDENT: u64;

    fn as_non_null_tag_ptr(&self) -> NonNull<Tag>;
    fn tag_for() -> Tag;
}

/// Stivale Header Tag
pub trait HeaderTag {}

/// Stivale Struct Tag
pub trait StructTag {}
