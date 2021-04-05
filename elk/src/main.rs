//! # `elk` - Executable and Linker Kit

use anyhow::{bail, Context};
use region::{protect, Protection};
use std::{
    env, fs,
    io::Write,
    process::{Command, Stdio},
};

fn main() -> anyhow::Result<()> {
    let input_path = env::args().nth(1).context("usage: elk FILE")?;
    let input = fs::read(&input_path)?;

    println!("Analyzing {}...", input_path);

    let file = delf::File::parse(&input[..])?;
    println!("{:#?}", file);

    println!("\nExecuting {}...", input_path);
    let status = Command::new(input_path.clone()).status()?;
    if !status.success() {
        bail!("Process did not exit successfully.");
    }

    println!("\nDisassembling {}...", input_path);
    let code_ph = file
        .program_headers
        .iter()
        .find(|ph| ph.mem_range().contains(&file.entry_point))
        .expect("Segment with entry point not found");

    ndisasm(&code_ph.data[..], file.entry_point)?;

    println!("\nExecuting {} in memory...", input_path);

    let code = &code_ph.data;
    unsafe {
        protect(code.as_ptr(), code.len(), Protection::READ_WRITE_EXECUTE)?;
    }

    let entry_offset = file.entry_point - code_ph.vaddr;
    let entry_point = unsafe { code.as_ptr().add(entry_offset.into()) };
    println!("        code @ {:?}", code.as_ptr());
    println!("entry offset @ {:?}", entry_offset);
    println!("entry point  @ {:?}", entry_point);
    unsafe {
        jmp(entry_point);
    }

    Ok(())
}

fn ndisasm(code: &[u8], offset: delf::Addr) -> anyhow::Result<()> {
    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o")
        .arg(format!("{}", offset.0))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all(code)?;

    let output = child.wait_with_output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}
