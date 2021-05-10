#![no_std]
#![feature(asm)]
#![feature(default_alloc_error_handler)]
#![feature(naked_functions)]

extern crate alloc;

use encore::prelude::*;
use pixie::{Manifest, MappedObject, Object};

macro_rules! info {
    ($($tokens: tt)*) => {
        println!("[stage1] {}", alloc::format!($($tokens)*));
    };
}

/// # Safety
/// Has caused the downfall of empires. Do not call.
///
/// Uses inline assembly so it can behave as the entry point of a static executable.
#[no_mangle]
#[naked]
pub unsafe extern "C" fn entry() {
    asm!("mov rdi, rsp", "call premain", options(noreturn))
}

/// # Safety
/// Initializes the allocator.
#[no_mangle]
#[inline(never)]
unsafe fn premain(stack_top: *mut u8) -> ! {
    init_allocator();
    crate::main(stack_top)
}

/// # Safety
/// Maps and calls into another ELF object.
#[inline(never)]
unsafe fn main(stack_top: *mut u8) -> ! {
    info!("Stack top: {:?}", stack_top);

    // Open ourselves and read the manifest
    let file = File::open("/proc/self/exe").unwrap();
    let map = file.map().unwrap();
    let slice = map.as_ref();
    let manifest = Manifest::read_from_full_slice(slice).unwrap();

    // Load stage2 anywhere in memory.
    let s2_slice = &slice[manifest.stage2.as_range()];
    let s2_obj = Object::new(s2_slice).unwrap();
    let mut s2_mapped = MappedObject::new(&s2_obj, None).unwrap();
    info!(
        "Mapped stage2 at base 0x{:x} (offset 0x{:x})",
        s2_mapped.base(),
        s2_mapped.base_offset(),
    );
    info!("Relocating stage2...");
    s2_mapped.relocate(s2_mapped.base_offset()).unwrap();
    info!("Relocating stage2... done!");

    // Find stage2's entry function and call it.
    let s2_entry = s2_mapped.lookup_sym("entry").unwrap();
    info!("Found entry_sym {:?}", s2_entry);
    let entry: unsafe extern "C" fn(*mut u8) -> ! =
        core::mem::transmute(s2_mapped.base_offset() + s2_entry.value);

    entry(stack_top)
}
