//! A portable executable packer.

#![no_std]
#![no_main]
#![feature(default_alloc_error_handler)]
#![feature(naked_functions)]
#![feature(asm)]
#![feature(link_args)]

use encore::prelude::*;

/// Don't link any glibc stuff, and make this executable static.
#[allow(unused_attributes)]
#[link_args = "-nostartfiles -nodefaultlibs -static"]
extern "C" {}

/// Our entry point.
#[naked]
#[no_mangle]
unsafe extern "C" fn _start() {
    asm!("mov rdi, rsp", "call pre_main", options(noreturn))
}

#[no_mangle]
unsafe fn pre_main(_stack_top: *mut u8) {
    init_allocator();
    main().unwrap();
    syscall::exit(0);
}

fn main() -> Result<(), EncoreError> {
    let file = File::open("/etc/lsb-release")?;
    let map = file.map()?;

    let s = core::str::from_utf8(&map[..]).unwrap();
    for l in s.lines() {
        println!("> {}", l);
    }

    let an_executable = File::open("/lib64/ld-linux-x86-64.so.2")?;
    let exe_map = an_executable.map()?;

    let there_you_go = core::str::from_utf8(&exe_map[1..4]).unwrap();
    println!("\n{}", there_you_go);

    Ok(())
}
