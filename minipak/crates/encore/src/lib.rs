//! A utility library built on top of `libcore` that provides a safe interface
//! over pesky stuff like system calls.

#![no_std]
#![feature(asm)]
#![feature(lang_items)]
#![feature(core_intrinsics)]

// Bring in heap-allocated types:
extern crate alloc;

pub mod error;
pub mod fs;
pub mod items;
pub mod memmap;
pub mod prelude;
pub mod syscall;
pub mod utils;
