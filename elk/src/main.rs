//! # `elk` - Executable and Linker Kit

mod name;
mod process;

use anyhow::Context;
use std::env;

fn main() -> anyhow::Result<()> {
    let input_path = env::args().nth(1).context("usage: elk FILE")?;

    let mut proc = process::Process::new();
    let exe_index = proc.load_object_and_dependencies(input_path)?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;

    let exe_obj = &proc.objects[exe_index];
    let entry_point = exe_obj.file.entry_point + exe_obj.base;
    unsafe { jmp(entry_point.as_ptr()) };

    Ok(())
}

/// Jump to some random memory address
///
/// # Safety
/// Look, this should be obvious, but you're in for some real crazy shit if
/// if you're trying to jump to random instructions in memory.
unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}
