//! # `elk` - Executable and Linker Kit

use anyhow::{bail, Context};
use mmap::{MapOption, MemoryMap};
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

    // Picked by fair, 4KiB-aligned dice roll.
    let base = 0x400000_usize;

    println!("Mapping {} in memory...", input_path);

    // Make sure to store our memory maps in a vector so they don't actually get
    // dropped by Rust and unmapped:
    let mut mappings = Vec::new();

    // We're only interested in "Load" segments:
    for ph in file
        .program_headers
        .iter()
        .filter(|ph| ph.typ == delf::SegmentType::Load)
        // ignore zero-length segments:
        .filter(|ph| ph.mem_range().end > ph.mem_range().start)
    {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);

        // mmap-ing would fail if the segments weren't aligned to pages, but they
        // already are with the file (on purpose!).
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        // Map each segment "base" higher than the program header says, and page
        // align it.
        let start = mem_range.start.0 as usize + base;
        let aligned_start = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding;

        // Get a raw pointer to the start of the memory range:
        let addr = aligned_start as *mut u8;
        println!("Addr: {:p}, Padding: {:08x}", addr, padding);

        // We want the memory range to be writeable so we can copy to it.
        // We'll set the right permissions later.
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        println!("Copying segment data...");
        {
            let dst = unsafe { std::slice::from_raw_parts_mut(addr.add(padding), ph.data.len()) };
            dst.copy_from_slice(&ph.data[..]);
        }

        println!("Adjusting permissions...");

        let mut protection = Protection::NONE;

        for flag in ph.flags.iter() {
            protection |= match flag {
                delf::SegmentFlag::Read => Protection::READ,
                delf::SegmentFlag::Write => Protection::WRITE,
                delf::SegmentFlag::Execute => Protection::EXECUTE,
            };
        }

        unsafe {
            protect(addr, len, protection)?;
        }

        mappings.push(map);
    }

    println!("Jumping to entry point @ {:?}...", file.entry_point);
    pause("jmp")?;
    unsafe {
        jmp((file.entry_point.0 as usize + base) as _);
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

fn pause(reason: &str) -> anyhow::Result<()> {
    println!("Press Enter to {}...", reason);

    {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }

    Ok(())
}

/// Truncates a [`usize`] value to the left-aligned (low) 4 KiB boundary.
fn align_lo(x: usize) -> usize {
    x & !0xFFF
}
