#![no_std]
#![feature(asm)]
#![feature(default_alloc_error_handler)]
#![feature(naked_functions)]

extern crate alloc;

use encore::prelude::*;
use pixie::{Manifest, MappedObject, Object, ObjectHeader, SegmentType};

macro_rules! info {
    ($($tokens: tt)*) => {
        println!("[stage2] {}", alloc::format!($($tokens)*));
    };
}

/// # Safety
/// Initializes the allocator. Does a raw syscall.
#[no_mangle]
#[inline(never)]
unsafe extern "C" fn entry(stack_top: *mut u8) -> ! {
    init_allocator();
    crate::main(stack_top)
}

/// # Safety
/// Maps and jmps to another ELF object.
#[inline(never)]
unsafe fn main(stack_top: *mut u8) -> ! {
    info!("Stack top: {:?}", stack_top);

    let mut stack = Env::read(stack_top as _);

    // Open ourselves and read the manifest.
    let file = File::open("/proc/self/exe").unwrap();
    info!("Mapping self...");
    let map = file.map().unwrap();
    info!("Mapping self... done!");
    let slice = map.as_ref();
    let manifest = Manifest::read_from_full_slice(slice).unwrap();

    info!("Decompressing guest...");
    let compressed_guest = &slice[manifest.guest.as_range()];
    let guest = lz4_flex::decompress_size_prepended(compressed_guest).unwrap();
    info!("Decompressing guest... done!");
    let guest_obj = Object::new(guest.as_ref()).unwrap();
    let guest_hull = guest_obj.segments().load_convex_hull().unwrap();

    let at = if guest_hull.start == 0 {
        // Guest is relocatable. Load it with the same base as ourselves.
        let elf_header_address = stack.find_vector(AuxvType::PHDR).value;
        let self_base = elf_header_address - ObjectHeader::SIZE as u64;
        Some(self_base)
    } else {
        // Guest is non-relocatable. Load it at its preferred offset.
        None
    };
    let base_offset = at.unwrap_or_default();

    let guest_mapped = MappedObject::new(&guest_obj, at).unwrap();
    info!("Mapped guest at 0x{:x}", guest_mapped.base());

    // Set phdr auxiliary vector.
    let at_phdr = stack.find_vector(AuxvType::PHDR);
    at_phdr.value = guest_mapped.base() + guest_obj.header().ph_offset;

    // Set phnum auxiliary vector
    let at_phnum = stack.find_vector(AuxvType::PHNUM);
    at_phnum.value = guest_obj.header().ph_count as _;

    // Set entry auxiliary vector
    let at_entry = stack.find_vector(AuxvType::ENTRY);
    at_entry.value = base_offset + guest_obj.header().entry_point;

    match guest_obj.segments().find(SegmentType::Interp) {
        Ok(interp) => {
            let interp = core::str::from_utf8(interp.slice()).unwrap();
            info!("Should load interpreter {}!", interp);

            let interp_file = File::open(interp).unwrap();
            let interp_map = interp_file.map().unwrap();
            let interp_obj = Object::new(interp_map.as_ref()).unwrap();
            let interp_hull = interp_obj.segments().load_convex_hull().unwrap();
            if interp_hull.start != 0 {
                panic!("Expected interpreter to be relocatable!");
            }

            // Map interprester anywhere
            let interp_mapped = MappedObject::new(&interp_obj, None).unwrap();

            // Adjust base
            let at_base = stack.find_vector(AuxvType::BASE);
            at_base.value = interp_mapped.base();

            let entry_point = interp_mapped.base() + interp_obj.header().entry_point;
            info!("Jumping to intepreter's entry point (0x{:x})", entry_point);
            pixie::launch(stack_top, entry_point);
        }

        Err(_) => {
            let entry_point = base_offset + guest_obj.header().entry_point;
            info!("Jumping to guest's entry point (0x{:x})", entry_point);
            pixie::launch(stack_top, entry_point);
        }
    }
}
