#![no_std]
#![no_main]
#![feature(default_alloc_error_handler)]
#![feature(naked_functions)]
#![feature(asm)]
#![feature(link_args)]

extern crate alloc;

use encore::prelude::*;
use pixie::{Manifest, PixieError};

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
unsafe fn pre_main(stack_top: *mut u8) {
    init_allocator();
    main(Env::read(stack_top)).unwrap();
    syscall::exit(0);
}

#[allow(clippy::unnecessary_wraps)]
fn main(env: Env) -> Result<(), PixieError> {
    println!("Hello from stage1!");

    let host = File::open("/proc/self/exe")?;
    let host = host.map()?;
    let host = host.as_ref();
    let manifest = Manifest::read_from_full_slice(host)?;

    let guest_range = manifest.guest.as_range();
    println!("The guest is at {:x?}", guest_range);

    let guest_slice = &host[guest_range];
    let uncompressed_guest =
        lz4_flex::decompress_size_prepended(guest_slice).expect("invalid lz4 payload");

    let tmp_path = "/tmp/minipak-guest";
    {
        let mut guest = File::create(tmp_path, 0o755)?;
        guest.write_all(&uncompressed_guest[..])?;
    }

    {
        // Make sure the path to execute is null-terminated
        let tmp_path_nullter = format!("{}\0", tmp_path);

        // Foward arguments and environment
        let argv: Vec<*const u8> = env
            .args
            .iter()
            .copied()
            .map(str::as_ptr)
            .chain(core::iter::once(core::ptr::null()))
            .collect();
        let envp: Vec<*const u8> = env
            .vars
            .iter()
            .copied()
            .map(str::as_ptr)
            .chain(core::iter::once(core::ptr::null()))
            .collect();

        unsafe {
            asm!(
                "syscall",
                in("rax") 59, // `execve` syscall
                in("rdi") tmp_path_nullter.as_ptr(), // `filename`
                in("rsi") argv.as_ptr(), // `argv`
                in("rdx") envp.as_ptr(), // `envp`
                options(noreturn),
            )
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}
