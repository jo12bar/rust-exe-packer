//! A portable executable packer.

#![no_std]
#![no_main]
#![feature(default_alloc_error_handler)]
#![feature(naked_functions)]
#![feature(asm)]

mod cli;
mod error;

use core::ops::Range;
use encore::prelude::*;
use error::Error;
use pixie::{
    align_hull, ElfMachine, ElfType, EndMarker, Endianness, Manifest, MappedObject, Object,
    ObjectHeader, OsAbi, ProgramHeader, Resource, SegmentType, Writer,
};

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
fn main(env: Env) -> Result<(), Error> {
    let args = cli::Args::parse(&env);

    println!("Packing guest {:?}", args.input);
    let guest_file = File::open(args.input)?;
    let guest_map = guest_file.map()?;
    let guest_obj = Object::new(guest_map.as_ref())?;

    let guest_hull = guest_obj.segments().load_convex_hull()?;
    let mut output = Writer::new(&args.output, 0o755)?;
    relink_stage1(guest_hull, &mut output)?;

    let stage2_slice = include_bytes!(concat!(env!("OUT_DIR"), "/embeds/libstage2.so"));

    let stage2_offset = output.offset();
    println!("Copying stage2 at 0x{:x}", stage2_offset);
    output.write_all(stage2_slice)?;
    output.align(0x8)?;

    println!("Compressing guest...");
    let compressed_guest = lz4_flex::compress_prepend_size(guest_map.as_ref());
    let guest_offset = output.offset();
    println!("Copying compressed guest at 0x{:x}", guest_offset);
    output.write_all(&compressed_guest)?;
    output.align(0x8)?;

    let manifest_offset = output.offset();
    println!("Writing manifest at 0x{:x}", manifest_offset);
    let manifest = Manifest {
        stage2: Resource {
            offset: stage2_offset as _,
            len: stage2_slice.len(),
        },
        guest: Resource {
            offset: guest_offset as _,
            len: compressed_guest.len(),
        },
    };
    output.write_deku(&manifest)?;
    output.align(0x8)?;

    println!("Writing end marker");
    let end_marker = EndMarker {
        manifest_offset: manifest_offset as _,
    };
    output.write_deku(&end_marker)?;

    println!("Written to {:?}", args.output);

    Ok(())
}

fn relink_stage1(guest_hull: Range<u64>, writer: &mut Writer) -> Result<(), Error> {
    println!("Guest hull: {:0x?}", guest_hull);

    let obj = Object::new(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/embeds/libstage1.so",
    )))?;

    let hull = obj.segments().load_convex_hull()?;
    assert_eq!(hull.start, 0, "libstage1.so must be relocatable!");

    // Pick a base offset. If our guest is a relocatable executable, pick a
    // "random" one. Otherwise, pick theirs.
    let base_offset = if guest_hull.start == 0 {
        0x00800000
    } else {
        guest_hull.start
    };
    println!("Picked base_offset 0x{:x}", base_offset);

    let hull = (hull.start + base_offset)..(hull.end + base_offset);
    println!("stage1 hull: {:x?}", hull);
    println!("guest hull:  {:x?}", guest_hull);

    // Map stage1 anywhere...
    let mut mapped = MappedObject::new(&obj, None)?;
    println!("Loaded stage1");

    // ...but relocate it as if it was mapped at `base_offset`.
    mapped.relocate(base_offset)?;
    println!("Relocated stage1");

    println!("Looking for `entry` in stage1...");
    let entry_sym = mapped.lookup_sym("entry")?;
    let entry_point = base_offset + entry_sym.value;

    // Collect all the load segments.
    let mut load_segs = obj
        .segments()
        .of_type(SegmentType::Load)
        .collect::<Vec<_>>();

    // Write out an ELF file!
    let out_header = ObjectHeader {
        class: pixie::ElfClass::Elf64,
        endianness: Endianness::Little,
        version: 1,
        os_abi: OsAbi::SysV,
        typ: ElfType::Exec,
        machine: ElfMachine::X86_64,
        version_bis: 1,
        entry_point,

        flags: 0,
        hdr_size: ObjectHeader::SIZE,
        // Two additional segments: one for `brk` alignment, and GNU_STACK.
        ph_count: load_segs.len() as u16 + 2,
        ph_offset: ObjectHeader::SIZE as _,
        ph_entsize: ProgramHeader::SIZE,
        // We're not adding any sections, our object will be opaque to debuggers
        sh_count: 0,
        sh_entsize: 0,
        sh_nidx: 0,
        sh_offset: 0,
    };
    writer.write_deku(&out_header)?;

    let static_headers = load_segs.iter().map(|seg| {
        let mut ph = seg.header().clone();
        ph.vaddr += base_offset;
        ph.paddr += base_offset;
        ph
    });

    for ph in static_headers {
        writer.write_deku(&ph)?;
    }

    // Insert dummy segment to offset the `brk` to its original position
    // for the guest, if we can.
    {
        let current_hull = align_hull(hull);
        let desired_hull = align_hull(guest_hull);

        let pad_size = if current_hull.end > desired_hull.end {
            println!("WARNING: Guest executable is too small. The `brk` will be wrong.");
            0x0
        } else {
            desired_hull.end - current_hull.end
        };

        let ph = ProgramHeader {
            paddr: current_hull.end,
            vaddr: current_hull.end,
            memsz: pad_size,
            filesz: 0,
            offset: 0,
            align: 0x1000,
            typ: SegmentType::Load,
            flags: ProgramHeader::WRITE | ProgramHeader::READ,
        };

        writer.write_deku(&ph)?;
    }

    // Add a GNU_STACK program header for alignment and to make it non-executable.
    {
        let ph = ProgramHeader {
            paddr: 0,
            vaddr: 0,
            memsz: 0,
            filesz: 0,
            offset: 0,
            align: 0x10,
            typ: SegmentType::GnuStack,
            flags: ProgramHeader::WRITE | ProgramHeader::READ,
        };
        writer.write_deku(&ph)?;
    }

    // Sort load segments by file offset and copy them.
    {
        load_segs.sort_by_key(|&seg| seg.header().offset);

        println!("Copying stage1 segments...");
        let copy_start_offset = writer.offset();
        println!("copy_start_offset = 0x{:x}", copy_start_offset);
        let copied_segments = load_segs
            .into_iter()
            .filter(move |seg| seg.header().offset > copy_start_offset);

        for cp_seg in copied_segments {
            let ph = cp_seg.header();
            println!("Copying {:?}", ph);

            // Pad space between segment with zeros:
            writer.pad(ph.offset - writer.offset())?;

            // Then copy:
            let start = ph.vaddr;
            let len = ph.filesz;
            let end = start + len;

            writer.write_all(mapped.vaddr_slice(start..end))?;
        }
    }

    // Pad the end of the last segment with zeros.
    writer.align(0x1000)?;

    Ok(())
}
