//! # `elk` - Executable and Linker Kit

#![feature(asm)]

mod name;
mod process;
mod procfs;

use anyhow::{bail, Context};
use argh::FromArgs;
use std::ffi::CString;

#[derive(FromArgs, PartialEq, Debug)]
/// Top-level command
struct Args {
    #[argh(subcommand)]
    nested: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Autosym(AutosymArgs),
    Run(RunArgs),
    Dig(DigArgs),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "autosym")]
/// Given a PID, spit out GDB commands to load all `.so` files mapped in memory.
struct AutosymArgs {
    #[argh(positional)]
    /// the PID of the process to examine
    pid: u32,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "run")]
/// Load and run an ELF executable
struct RunArgs {
    #[argh(positional)]
    /// the absolute path of an executable file to load and run
    exec_path: String,

    #[argh(positional)]
    /// arguments for the executable file
    args: Vec<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "dig")]
/// Shows information about an address in a process' address space.
struct DigArgs {
    #[argh(option)]
    /// the PID of the process whose memory space is to be examined
    pid: u32,
    #[argh(option)]
    /// the address to look for,
    addr: u64,
}

fn main() -> anyhow::Result<()> {
    // Parse command line:
    let args: Args = argh::from_env();
    match args.nested {
        SubCommand::Run(args) => cmd_run(args),
        SubCommand::Autosym(args) => cmd_autosym(args),
        SubCommand::Dig(args) => cmd_dig(args),
    }
}

#[derive(thiserror::Error, Debug)]
enum WithMappingsError {
    #[error("parsing failed: {0}")]
    Parse(String),
}

/// Run a function with a bunch of memory mappings.
fn with_mappings<F, T>(pid: u32, f: F) -> anyhow::Result<T>
where
    F: Fn(&Vec<procfs::Mapping<'_>>) -> anyhow::Result<T>,
{
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))?;

    match procfs::mappings(&maps) {
        Ok((_, maps)) => f(&maps),
        Err(e) => {
            // parsing errors borrow the input, so we wouldn't be able
            // to return it. to prevent that, format it early.
            bail!(WithMappingsError::Parse(format!("{}", e)))
        }
    }
}

fn cmd_run(args: RunArgs) -> anyhow::Result<()> {
    let mut proc = process::Process::new();
    let exe_index = proc.load_object_and_dependencies(&args.exec_path)?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;

    let exec = &proc.objects[exe_index];

    // the first argument is typically the path to the executable itself.
    // that's not something `argh` gives us, so let's add it ourselves:
    let args = std::iter::once(CString::new(args.exec_path.as_bytes()).unwrap())
        .chain(
            args.args
                .iter()
                .map(|s| CString::new(s.as_bytes()).unwrap()),
        )
        .collect();

    let opts = process::StartOptions {
        exec,
        args,
        // on the stack, environment variables are null-terminated `K=V` strings.
        // the Rust API gives us key-value pairs, so we need to build those strings
        // ourselves
        env: std::env::vars()
            .map(|(k, v)| CString::new(format!("{}={}", k, v).as_bytes()).unwrap())
            .collect(),
        // right now we pass all *our* auxiliary vectors to the underlying process.
        // note that some of those aren't quite correct - there's a `Base` auxiliary
        // vector, for example, which is set to `elk`'s base address, not `echidna`'s!
        auxv: process::Auxv::get_known(),
    };

    proc.start(&opts);

    Ok(())
}

fn cmd_autosym(args: AutosymArgs) -> anyhow::Result<()> {
    with_mappings(args.pid, |mappings| {
        let xmappings = mappings.iter().filter(|m| m.perms.x && m.source.is_file());

        for mapping in xmappings {
            autosym_analyze_proc_mapping(mapping)
                .context("Error generating gdb add-symbol-file commands")?;
        }

        Ok(())
    })
}

fn autosym_analyze_proc_mapping(mapping: &procfs::Mapping) -> anyhow::Result<()> {
    // Skip deleted mappings
    if mapping.deleted {
        return Ok(());
    }

    let path = match mapping.source {
        procfs::Source::File(path) => path,
        _ => return Ok(()),
    };

    let contents = std::fs::read(path)?;
    let file = delf::File::parse(&contents)?;

    let section = match file
        .section_headers
        .iter()
        .find(|sh| file.shstrtab_entry(sh.name) == b".text")
    {
        Some(section) => section,
        _ => return Ok(()),
    };

    let textaddress = mapping.addr_range.start - mapping.offset + section.offset;
    println!("add-symbol-file {:?} 0x{:?}", path, textaddress);

    Ok(())
}

fn cmd_dig(args: DigArgs) -> anyhow::Result<()> {
    let addr = delf::Addr(args.addr);

    with_mappings(args.pid, |mappings| {
        if let Some(mapping) = mappings.iter().find(|m| m.addr_range.contains(&addr)) {
            println!("Mapped {:?} from {:?}", mapping.perms, mapping.source);
            println!(
                "(Map range: {:?}, {:?} total",
                mapping.addr_range,
                Size(mapping.addr_range.end - mapping.addr_range.start)
            );

            let path = match mapping.source {
                procfs::Source::File(path) => path,
                _ => return Ok(()),
            };

            let contents = std::fs::read(path)?;
            let file = delf::File::parse(&contents)?;

            let offset = addr + mapping.offset - mapping.addr_range.start;

            // Segments (loader view, `delf::ProgramHeader` type) determine what parts
            // of the ELF file get mapped where, so we try to determine which
            // segment this mapping corresponds to.
            let segment = match file
                .program_headers
                .iter()
                .find(|ph| ph.file_range().contains(&offset))
            {
                Some(s) => s,
                None => return Ok(()),
            };

            // This is the main thing I wanted `elk dig` to do - display
            // the virtual address *for this ELF object*, so that it matches
            // up with the output from `objdump` and `readelf`
            let vaddr = offset + segment.vaddr - segment.offset;
            println!("Object virtual address: {:?}", vaddr);

            // But we can go a bit further: we can find to which section
            // this corresponds, and show *where* in this section the
            // dug address was.
            let section = match file
                .section_headers
                .iter()
                .find(|sh| sh.mem_range().contains(&vaddr))
            {
                Some(s) => s,
                None => return Ok(()),
            };

            let name = file.shstrtab_entry(section.name);
            let sect_offset = vaddr - section.addr;
            println!(
                "At section {:?} + {} (0x{:x})",
                String::from_utf8_lossy(name),
                sect_offset.0,
                sect_offset.0
            );

            // And, even further, we can try to map it to a symbol. This is all
            // stuff GDB does in its `info addr 0xABCD` command, but isn't it
            // satisfying to re-implement it ourselves?
            match file.read_symtab_entries() {
                Ok(syms) => {
                    for sym in &syms {
                        let sym_range = sym.value..(sym.value + delf::Addr(sym.size));
                        // the first check is for zero-sized symbols, since `sym_range`
                        // ends up being a 0-sized range.
                        if sym.value == vaddr || sym_range.contains(&vaddr) {
                            let sym_offset = vaddr - sym.value;
                            let sym_name = String::from_utf8_lossy(file.strtab_entry(sym.name));

                            println!(
                                "At symbol {:?} + {} (0x{:x})",
                                sym_name, sym_offset.0, sym_offset.0
                            );
                        }
                    }
                }

                Err(e) => println!("Could not read syms: {}", e),
            }
        }

        Ok(())
    })
}

/// Allows formatting a [`delf::Addr`] as a size in bytes.
struct Size(pub delf::Addr);

use std::fmt;
impl fmt::Debug for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KIB: u64 = 1024;
        const MIB: u64 = 1024 * KIB;

        let x = (self.0).0;
        #[allow(overlapping_range_endpoints)]
        #[allow(clippy::clippy::match_overlapping_arm)]
        match x {
            0..=KIB => write!(f, "{} B", x),
            KIB..=MIB => write!(f, "{} KiB", x / KIB),
            _ => write!(f, "{} MiB", x / MIB),
        }
    }
}
