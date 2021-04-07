//! # `elk` - Executable and Linker Kit

use anyhow::{bail, Context};
use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};
use std::{env, fs, mem::transmute, ptr::copy_nonoverlapping};

fn main() -> anyhow::Result<()> {
    let input_path = env::args().nth(1).context("usage: elk FILE")?;
    let input = fs::read(&input_path)?;

    println!("Analyzing {}...", input_path);

    let file = delf::File::parse(&input[..])?;
    println!("{:#?}", file);

    // println!("\nDisassembling {}...", input_path);
    // let code_ph = file
    //     .program_headers
    //     .iter()
    //     .find(|ph| ph.mem_range().contains(&file.entry_point))
    //     .expect("Segment with entry point not found");

    // ndisasm(&code_ph.data[..], file.entry_point)?;

    println!("Dynamic entries:");
    if let Some(ds) = file
        .program_headers
        .iter()
        .find(|ph| ph.typ == delf::SegmentType::Dynamic)
    {
        if let delf::SegmentContents::Dynamic(ref table) = ds.contents {
            for entry in table {
                println!("\t- {:?}", entry);
            }
        }
    }

    println!("\nRela entries:");

    let rela_entries = match file.read_rela_entries() {
        Ok(ents) => ents,
        Err(e @ delf::ReadRelaError::RelaNotFound) => {
            println!("\t- Could not read relocations: {:?}", e);
            Default::default()
        }
        e => return e.map(|_| ()).context("Reading Rela entries failed"),
    };

    for ent in &rela_entries {
        println!("\t- {:?}", ent);
        if let Some(seg) = file.segment_at(ent.offset) {
            println!("\t  ... for {:?}", seg);
        }
    }

    // Picked by fair, 4KiB-aligned dice roll.
    let base = 0x400000_usize;

    println!("Loading with base address @ 0x{:x}", base);

    // We're only interested in "Load" segments:
    let non_empty_code_segments = file
        .program_headers
        .iter()
        .filter(|ph| ph.typ == delf::SegmentType::Load)
        // ignore zero-length segments
        .filter(|ph| ph.mem_range().end > ph.mem_range().start);

    // Make sure to store our memory maps in a vector so they don't actually get
    // dropped by Rust and unmapped:
    let mut mappings = Vec::new();

    for ph in non_empty_code_segments {
        println!("Mapping {:?} - {:?}", ph.mem_range(), ph.flags);

        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        // Map each segment "base" higher than the program header says, and page
        // align it.
        let start = mem_range.start.0 as usize + base;
        let aligned_start = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding;

        if padding > 0 {
            println!("\t- With 0x{:x} bytes of padding at the start", padding);
        }

        // Get a raw pointer to the start of the memory range:
        let addr: *mut u8 = unsafe { transmute(aligned_start) };

        // We want the memory range to be writeable so we can copy to it.
        // We'll set the right permissions later.
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        // Copy segment data:
        unsafe {
            copy_nonoverlapping(ph.data.as_ptr(), addr.add(padding), len);
        }

        // Apply relocations:
        let mut num_relocs = 0;
        for reloc in &rela_entries {
            if mem_range.contains(&reloc.offset) {
                num_relocs += 1;

                let real_segment_start = unsafe { addr.add(padding) };
                let offset_into_segment = reloc.offset - mem_range.start;
                let reloc_addr = unsafe { real_segment_start.add(offset_into_segment.into()) };

                match reloc.typ {
                    delf::RelType::Relative => {
                        // This assumes `reloc_addr` is 8-byte aligned. If this
                        // wasn't the case, we could crash, and so would the
                        // target executable.
                        let reloc_addr = reloc_addr as *mut u64;
                        let reloc_value = reloc.addend + delf::Addr(base as u64);
                        unsafe {
                            *reloc_addr = reloc_value.0;
                        }
                    }

                    typ => {
                        bail!("Unsupported relocation type {:?}", typ);
                    }
                }
            }
        }

        if num_relocs > 0 {
            println!("\t- Applied {} relocations", num_relocs);
        }

        // Adjust memory segment permissions
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
    // pause("jmp")?;
    unsafe {
        jmp((file.entry_point.0 as usize + base) as _);
    }

    Ok(())
}

// fn ndisasm(code: &[u8], offset: delf::Addr) -> anyhow::Result<()> {
//     use std::{io::Write, process::{Command, Stdio}};
//
//     let mut child = Command::new("ndisasm")
//         .arg("-b")
//         .arg("64")
//         .arg("-o")
//         .arg(format!("{}", offset.0))
//         .arg("-")
//         .stdin(Stdio::piped())
//         .stdout(Stdio::piped())
//         .spawn()?;

//     child.stdin.as_mut().unwrap().write_all(code)?;

//     let output = child.wait_with_output()?;
//     println!("{}", String::from_utf8_lossy(&output.stdout));

//     Ok(())
// }

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}

// fn pause(reason: &str) -> anyhow::Result<()> {
//     println!("Press Enter to {}...", reason);

//     {
//         let mut s = String::new();
//         std::io::stdin().read_line(&mut s)?;
//     }

//     Ok(())
// }

/// Truncates a [`usize`] value to the left-aligned (low) 4 KiB boundary.
fn align_lo(x: usize) -> usize {
    x & !0xFFF
}
