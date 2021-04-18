//! Defines a dependency graph encompassing the whole program.

use crate::name::Name;
use anyhow::Context;
use custom_debug_derive::Debug as CustomDebug;
use enumflags2::BitFlags;
use mmap::{MapOption, MemoryMap};
use multimap::MultiMap;
use std::{
    cmp::{max, min},
    collections::HashMap,
    ffi::CString,
    io::Read,
    ops::Range,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    sync::Arc,
    usize,
};

/// Computes the minimal range that contains two ranges.
fn convex_hull<T: std::cmp::Ord>(a: Range<T>, b: Range<T>) -> Range<T> {
    (min(a.start, b.start))..(max(a.end, b.end))
}

/// Jump to some random memory address
///
/// # Safety
/// Look, this should be obvious, but you're in for some real crazy shit if
/// if you're trying to jump to random instructions in memory.
#[inline(never)]
unsafe fn jmp(entry_point: *const u8, stack_contents: *const u64, qword_count: usize) -> ! {
    asm!(
        // allocate (qword_count * 8) bytes
        "mov {tmp}, {qword_count}",
        "sal {tmp}, 3",
        "sub rsp, {tmp}",

        ".l1:",
        // start at i = (n-1)
        "sub {qword_count}, 1",
        // copy qwords to the stack
        "mov {tmp}, QWORD PTR [{stack_contents}+{qword_count}*8]",
        "mov QWORD PTR [rsp+{qword_count}*8], {tmp}",
        // loop if i isn't zero, break otherwise
        "test {qword_count}, {qword_count}",
        "jnz .l1",

        "jmp {entry_point}",

        entry_point = in(reg) entry_point,
        stack_contents = in(reg) stack_contents,
        qword_count = in(reg) qword_count,
        tmp = out(reg) _,
    );

    // Tell LLVM we never return. Will throw a SIGILL if we somehow end up
    // executing this code.
    asm!("ud2", options(noreturn));
}

/// Set the `fs` register to something.
///
/// # Safety
/// After calling this there are a *lot* of things you should avoid doing. For
/// example:
///
/// - Calling `println!` will lock stdout, and locks use thread-local storage,
///   so that will crash now.
/// - Allocating memory on the heap will call `malloc`, and malloc uses
///   thread-local storage, so that will also crash.
/// - etc, etc... just don't do lots of stuff after calling this!
#[inline(never)]
unsafe fn set_fs(addr: u64) {
    let syscall_number: u64 = 158;
    let arch_set_fs: u64 = 0x1002;

    asm!(
        "syscall",
        inout("rax") syscall_number => _,
        in("rdi") arch_set_fs,
        in("rsi") addr,
        lateout("rcx") _, lateout("r11") _,
    )
}

/// Defines something as being a possible state for a [`Process`]. No matter
/// what state, the process is in, it always has a [`Loader`], which includes
/// several common fields that the process basically always has.
pub trait ProcessState {
    /// Returns the process' loader, which contains a bunch of data common to
    /// all process states.
    fn loader(&self) -> &Loader;
}

/// Contains the state used by a process loader to do its work.
pub struct Loader {
    /// The objects within this process graph.
    pub objects: Vec<Object>,
    /// A map from object paths to their indices in [`Process::objects`].
    pub objects_by_path: HashMap<PathBuf, usize>,
    /// Our search path for libraries.
    pub search_path: Vec<PathBuf>,
}

/// A [`ProcessState`]. When a [`Process`] is `Loading`, it's currently busy
/// loading all of its ELF objects. This is the state you get when you call
/// [`Process::new`].
pub struct Loading {
    pub loader: Loader,
}

impl ProcessState for Loading {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

/// A [`ProcessState`]. When a [`Process`] is in the `TLSAllocated` state, it
/// means that thread-local storage has successully been _allocated_ and is
/// available to the process to use.
pub struct TLSAllocated {
    loader: Loader,
    /// The thread-local storage.
    pub tls: TLS,
}

impl ProcessState for TLSAllocated {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

/// A [`ProcessState`] for when we've finished applying memory relocations to
/// a [`Process`].
pub struct Relocated {
    loader: Loader,
    tls: TLS,
}

impl ProcessState for Relocated {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

/// A [`ProcessState`] for when we've finished _initializing_ thread-local storage.
pub struct TLSInitialized {
    loader: Loader,
    tls: TLS,
}

impl ProcessState for TLSInitialized {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

/// A [`ProcessState`] for after we've adjusted protections for our memory segments.
pub struct Protected {
    loader: Loader,
    tls: TLS,
}

impl ProcessState for Protected {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

/// Startup options to pass to a child process.
pub struct StartOptions {
    pub exec_index: usize,
    pub args: Vec<CString>,
    pub env: Vec<CString>,
    pub auxv: Vec<Auxv>,
}

/// A sub-process, executed in memory.
#[derive(Debug)]
pub struct Process<S: ProcessState> {
    /// The current state of the process.
    pub state: S,
}

/// Methods callable when the process graph is in any state at all.
impl<S: ProcessState> Process<S> {
    /// Lookup a symbol.
    pub fn lookup_symbol(&self, wanted: &ObjectSym, ignore_self: bool) -> ResolvedSym {
        for obj in &self.state.loader().objects {
            if ignore_self && std::ptr::eq(wanted.obj, obj) {
                continue;
            }

            if let Some(syms) = obj.sym_map.get_vec(&wanted.sym.name) {
                if let Some(sym) = syms.iter().find(|sym| !sym.sym.shndx.is_undef()) {
                    return ResolvedSym::Defined(ObjectSym { obj, sym });
                }
            }
        }

        ResolvedSym::Undefined
    }
}

/// Methods callable only when the process graph is loading.
impl Process<Loading> {
    /// Start loading a new process graph.
    pub fn new() -> Self {
        Self {
            state: Loading {
                loader: Loader {
                    objects: Vec::new(),
                    objects_by_path: HashMap::new(),
                    search_path: vec!["/usr/lib".into(), "/lib/x86_64-linux-gnu".into()],
                },
            },
        }
    }

    /// Returns the path to an object by searching the entire search_path.
    pub fn object_path(&self, name: &str) -> anyhow::Result<PathBuf, LoadError> {
        self.state
            .loader
            .search_path
            .iter()
            .filter_map(|prefix| prefix.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }

    /// Given an object name, this will either
    ///
    /// - Return the index in `Process.state.loader.objects` of an already-loaded object, or
    /// - Load the object and return its fresh index.
    pub fn get_object(&mut self, name: &str) -> anyhow::Result<GetResult> {
        let path = self.object_path(name)?;
        self.state
            .loader
            .objects_by_path
            .get(&path)
            .map(|&i| Ok(GetResult::Cached(i)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }

    /// Load an ELF object, by path. Returns the index
    /// into the `Process.state.loader.objects` vector where the object is stored.
    pub fn load_object<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<usize> {
        let path = path
            .as_ref()
            .canonicalize()
            .map_err(|e| LoadError::Io(path.as_ref().to_path_buf(), e))?;

        let mut fs_file = std::fs::File::open(&path).map_err(|e| LoadError::Io(path.clone(), e))?;
        let mut input = Vec::new();
        fs_file
            .read_to_end(&mut input)
            .map_err(|e| LoadError::Io(path.clone(), e))?;

        println!("Loading {:?}", path);
        let file =
            delf::File::parse(input).map_err(|fpe| LoadError::ParseError(path.clone(), fpe))?;

        let origin = path
            .parent()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
            .to_str()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;

        self.state.loader.search_path.extend(
            file.dynamic_entry_strings(delf::DynamicTag::RPath)
                .chain(file.dynamic_entry_strings(delf::DynamicTag::RunPath))
                .map(|path| String::from_utf8_lossy(path))
                .map(|path| path.replace("$ORIGIN", &origin))
                .inspect(|path| println!("\t- RPath entry found: {:?}", path))
                .map(PathBuf::from),
        );

        // A helper function for getting an iterator over the load segments
        let load_segments = || {
            file.program_headers
                .iter()
                .filter(|ph| ph.typ == delf::SegmentType::Load)
        };

        let mem_range = load_segments()
            .map(|ph| ph.mem_range())
            .fold(None, |acc, range| match acc {
                None => Some(range),
                Some(acc) => Some(convex_hull(acc, range)),
            })
            .ok_or(LoadError::NoLoadSegments)?;

        let mem_size: usize = (mem_range.end - mem_range.start).into();
        let mem_map = std::mem::ManuallyDrop::new(MemoryMap::new(
            mem_size,
            &[MapOption::MapReadable, MapOption::MapWritable],
        )?);
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        println!("Mapping memory segments");
        let segments = load_segments()
            // First, filter out zero-sized segments:
            .filter(|ph| ph.memsz.0 > 0)
            // Then, map the remaining ones!
            .map(|ph| -> anyhow::Result<_, LoadError> {
                println!("\t- Mapping {:#?}", ph);

                let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                let padding = ph.vaddr - vaddr;
                let offset = ph.offset - padding;
                let memsz = ph.memsz + padding;
                let filesz = ph.filesz + padding;

                println!(
                    "\t  └──> to file {:?} | mem {:?} | filesz {:?}",
                    offset..(offset + memsz),
                    vaddr..(vaddr + memsz),
                    filesz
                );

                let map = MemoryMap::new(
                    // The mapping only geos up to filesz...
                    filesz.into(),
                    &[
                        // Set up temporary permissions for mapping and relocations.
                        // Permissions get correctly-set later.
                        MapOption::MapReadable,
                        MapOption::MapWritable,
                        MapOption::MapExecutable,
                        MapOption::MapFd(fs_file.as_raw_fd()),
                        MapOption::MapOffset(offset.into()),
                        MapOption::MapAddr((base + vaddr).as_ptr()),
                    ],
                )?;

                // But if there's some bytes left over...
                if ph.memsz > ph.filesz {
                    // ...then we zero them!
                    // NOTE: This works becuase we already reserved the *convex hull*
                    // of all segments in memory in our initial `MemoryMap::new` call,
                    // so that memory is there.
                    let mut zero_start = base + ph.mem_range().start + ph.filesz;
                    let zero_len = ph.memsz - ph.filesz;

                    unsafe {
                        // This will probably get optimized to something good later.
                        for i in zero_start.as_mut_slice(zero_len.into()) {
                            *i = 0u8;
                        }
                    }
                }

                Ok(Segment {
                    map: Arc::new(map),
                    vaddr_range: vaddr..(ph.vaddr + ph.memsz),
                    padding,
                    flags: ph.flags,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let syms = file.read_dynsym_entries().map_err(LoadError::from)?;

        let syms: Vec<_> = if syms.is_empty() {
            vec![]
        } else {
            let dynstr = file
                .get_dynamic_entry(delf::DynamicTag::StrTab)
                .with_context(|| format!("String table not found in {:?}", path.clone()))?;

            // FInd the right `MemoryMap` to refer to.
            let segment = segments
                .iter()
                .find(|seg| seg.vaddr_range.contains(&dynstr))
                .with_context(|| {
                    format!("Segment not found for string table in {:?}", path.clone())
                })?;

            syms.into_iter()
                .map(|sym| -> anyhow::Result<_> {
                    let name = Name::mapped(
                        &segment.map,
                        (dynstr + sym.name - segment.vaddr_range.start).into(),
                    )
                    .context("Could not find name for symbol")?;
                    Ok(NamedSym { sym, name })
                })
                .collect::<Result<_, _>>()
                .context("Could not read symbol during load")?
        };

        let mut sym_map = MultiMap::new();
        for sym in &syms {
            sym_map.insert(sym.name.clone(), sym.clone());
        }

        let mut rels = file.read_rela_entries().map_err(LoadError::from)?;
        rels.extend(file.read_jmp_rel_entries().map_err(LoadError::from)?);

        let obj = Object {
            path: path.clone(),
            base,
            segments,
            mem_range,
            file,
            syms,
            sym_map,
            rels,
        };

        let idx = self.state.loader.objects.len();
        self.state.loader.objects.push(obj);
        self.state.loader.objects_by_path.insert(path, idx);

        Ok(idx)
    }

    /// Load an object *and* all its dependencies, traversing the dependency graph
    /// breadth-first the way LD does. Return the index of the loaded main object
    /// in the [`Process::objects`] vector.
    pub fn load_object_and_dependencies<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> anyhow::Result<usize> {
        let index = self.load_object(path)?;

        let mut a = vec![index];
        while !a.is_empty() {
            a = a
                .into_iter()
                .map(|index| &self.state.loader.objects[index].file)
                .flat_map(|file| file.dynamic_entry_strings(delf::DynamicTag::Needed))
                .map(|s| String::from_utf8_lossy(s).to_string()) // FIXME: hacky
                .collect::<Vec<_>>()
                .into_iter()
                .map(|dep| self.get_object(&dep))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(GetResult::fresh)
                .collect();
        }

        Ok(index)
    }

    /// Allocate thread-local storage. This must be done once loading is complete.
    pub fn allocate_tls(mut self) -> Process<TLSAllocated> {
        let mut offsets = HashMap::new();

        // Total space needed for all thread-local variables of all ELF objects:
        let mut storage_space = 0;

        for obj in &mut self.state.loader.objects {
            let needed = obj
                .file
                .segment_of_type(delf::SegmentType::TLS)
                .map(|ph| ph.memsz.0)
                .unwrap_or_default() as u64;

            // If we have a non-empty TLS segment for this object...
            if needed > 0 {
                // Compute a "backwards offset", going left from tcb_addr.
                let offset = delf::Addr(storage_space + needed);
                offsets.insert(obj.base, offset);
                storage_space += needed;
            }
        }

        let storage_space = storage_space as usize;
        let tcbhead_size = 704; // per our GDB session
        let total_size = storage_space + tcbhead_size;

        // Allocate the whole capacity upfront so the vector doesn't get resized
        // and `tcb_addr` doesn't get invalidated.
        let mut block = Vec::with_capacity(total_size);
        // This is what we'll be setting `%fs` to.
        let tcb_addr = delf::Addr(block.as_ptr() as u64 + storage_space as u64);
        #[allow(clippy::same_item_push)]
        for _ in 0..storage_space {
            // For now, zero out storage.
            block.push(0u8);
        }

        // Build a "somewhat fake" tcbhead structure
        block.extend(&tcb_addr.0.to_le_bytes()); // tcb
        block.extend(&0_u64.to_le_bytes()); // dtv
        block.extend(&tcb_addr.0.to_le_bytes()); // thread pointer
        block.extend(&0_u32.to_le_bytes()); // multiple_threads
        block.extend(&0_u32.to_le_bytes()); // gscope_flag
        block.extend(&0_u64.to_le_bytes()); // sysinfo
        block.extend(&0xDEADBEEF_u64.to_le_bytes()); // stack guard
        block.extend(&0xFEEDFACE_u64.to_le_bytes()); // pointer guard
        while block.len() < block.capacity() {
            // We don't care about the other fields, just pad out with zeros
            block.push(0u8);
        }

        let tls = TLS {
            offsets,
            block,
            tcb_addr,
        };

        Process {
            state: TLSAllocated {
                loader: self.state.loader,
                tls,
            },
        }
    }
}

/// Methods callable only when the thread-local storage has been _allocated_.
impl Process<TLSAllocated> {
    /// Apply memory relocations to all loaded objects.
    pub fn apply_relocations(self) -> anyhow::Result<Process<Relocated>, RelocationError> {
        let rels = self
            .state
            .loader
            .objects
            .iter()
            .rev()
            .map(|obj| obj.rels.iter().map(move |rel| ObjectRel { obj, rel }))
            .flatten()
            .collect::<Vec<_>>();

        for rel in rels {
            self.apply_relocation(rel)?
        }

        Ok(Process {
            state: Relocated {
                loader: self.state.loader,
                tls: self.state.tls,
            },
        })
    }

    /// Apply a single relocation.
    fn apply_relocation(&self, objrel: ObjectRel) -> anyhow::Result<(), RelocationError> {
        use delf::RelType as RT;

        // Destructure a bit, for convenience:
        let ObjectRel { obj, rel } = objrel;
        let reltype = rel.typ;
        let addend = rel.addend;

        // This is the symbol we're looking for. Note that it may be symbol 0, which
        // has an empty name - that's fine.
        let wanted = ObjectSym {
            obj,
            sym: &obj.syms[rel.sym as usize],
        };

        // When doing a lookup, only ifnore the relocation's object if we're
        // performing a Copy relocation.
        let ignore_self = matches!(reltype, RT::Copy);

        // Perform symbol lookup early:
        let found = match rel.sym {
            // The relocation isn't bound to any symbol - go with undef:
            0 => ResolvedSym::Undefined,

            // The relocation is actually bound to a symbol! Look it up.
            _ => match self.lookup_symbol(&wanted, ignore_self) {
                undef @ ResolvedSym::Undefined => match wanted.sym.sym.bind {
                    // Undefined symbols are fine if our local symbol is weak.
                    delf::SymBind::Weak => undef,

                    // Otherwise, error out now.
                    _ => return Err(RelocationError::UndefinedSymbol(wanted.sym.clone().into())),
                },

                // Defined symbols are always fine.
                x => x,
            },
        };

        match reltype {
            RT::_64 => unsafe {
                objrel.addr().set(found.value() + addend);
            },

            RT::Copy => unsafe {
                objrel.addr().write(found.value().as_slice(found.size()));
            },

            RT::Relative => unsafe {
                objrel.addr().set(obj.base + addend);
            },

            RT::IRelative => unsafe {
                // Call the indirect selector at loadtime, *before* performing
                // the relocation and jumping to the entry point.
                // This is hella unsafe.
                type Selector = unsafe extern "C" fn() -> delf::Addr;
                let selector: Selector = std::mem::transmute(obj.base + addend);
                objrel.addr().set(selector());
            },

            RT::GlobDat | RT::JumpSlot => unsafe {
                objrel.addr().set(found.value());
            },

            RT::TpOff64 => unsafe {
                if let ResolvedSym::Defined(sym) = found {
                    let obj_offset =
                        self.state
                            .tls
                            .offsets
                            .get(&sym.obj.base)
                            .unwrap_or_else(|| {
                                panic!(
                                    "No thread-local storage allocated for object {:?}",
                                    sym.obj.file
                                )
                            });
                    let obj_offset = -(obj_offset.0 as i64);
                    let offset =
                        obj_offset + sym.sym.sym.value.0 as i64 + objrel.rel.addend.0 as i64;
                    objrel.addr().set(offset);
                }
            },

            _ => {
                return Err(RelocationError::UnimplementedRelocation(
                    obj.path.clone(),
                    reltype,
                ))
            }
        }

        Ok(())
    }
}

/// Methods callable only when the ELF object's have had their memory addresses
/// relocated.
impl Process<Relocated> {
    /// Initialize thread-local storage.
    pub fn initialize_tls(self) -> Process<TLSInitialized> {
        let tls = &self.state.tls;

        for obj in &self.state.loader.objects {
            if let Some(ph) = obj.file.segment_of_type(delf::SegmentType::TLS) {
                if let Some(offset) = tls.offsets.get(&obj.base).cloned() {
                    unsafe {
                        (tls.tcb_addr - offset)
                            .write((ph.vaddr + obj.base).as_slice(ph.filesz.into()));
                    }
                }
            }
        }

        Process {
            state: TLSInitialized {
                loader: self.state.loader,
                tls: self.state.tls,
            },
        }
    }
}

/// Methods callable only after thread-local storage has already been initialized.
impl Process<TLSInitialized> {
    /// Adjust protections on mapped memory ranges to be what they're supposed
    /// to be.
    pub fn adjust_protections(self) -> Result<Process<Protected>, region::Error> {
        use region::{protect, Protection};

        for obj in &self.state.loader.objects {
            for seg in &obj.segments {
                let mut protection = Protection::NONE;

                for flag in seg.flags.iter() {
                    protection |= match flag {
                        delf::SegmentFlag::Read => Protection::READ,
                        delf::SegmentFlag::Write => Protection::WRITE,
                        delf::SegmentFlag::Execute => Protection::EXECUTE,
                    }
                }

                unsafe {
                    protect(seg.map.data(), seg.map.len(), protection)?;
                }
            }
        }

        Ok(Process {
            state: Protected {
                loader: self.state.loader,
                tls: self.state.tls,
            },
        })
    }
}

/// Methods callable only after the process's memory segments have been protected.
impl Process<Protected> {
    /// Start a process! Note that this function never returns.
    pub fn start(self, opts: &StartOptions) -> ! {
        let exec = &self.state.loader.objects[opts.exec_index];
        let entry_point = exec.file.entry_point + exec.base;
        let stack = Self::build_stack(opts);

        unsafe {
            set_fs(self.state.tls.tcb_addr.0);
            jmp(entry_point.as_ptr(), stack.as_ptr(), stack.len())
        };
    }

    /// Sets up the stack for jumping to a subprocess, according to the SystemV C ABI.
    fn build_stack(opts: &StartOptions) -> Vec<u64> {
        let mut stack = Vec::new();

        let null = 0_u64;

        macro_rules! push {
            ($x:expr) => {
                stack.push($x as u64)
            };
        }

        // NOTE: everything is pushed in reverse order

        // argc
        push!(opts.args.len());

        // argv
        for v in &opts.args {
            push!(v.as_ptr());
        }
        push!(null);

        // envp
        for v in &opts.env {
            push!(v.as_ptr());
        }
        push!(null);

        // auxv
        for v in &opts.auxv {
            push!(v.typ);
            push!(v.value);
        }
        push!(AuxType::Null);
        push!(null);

        // Align stack to 16-byte boundary:
        if stack.len() % 2 == 1 {
            push!(0);
        }

        stack
    }
}

/*impl Process {







}*/

/// The result of running [`Process::get_object`].
pub enum GetResult {
    Cached(usize),
    Fresh(usize),
}

impl GetResult {
    /// Similar to [`Result::ok`].
    pub fn fresh(self) -> Option<usize> {
        if let Self::Fresh(index) = self {
            Some(index)
        } else {
            None
        }
    }
}

/// A node in a process graph. Could be an executable, a library, or a fantastical
/// unicorn that will eat all your children and laugh.
#[derive(CustomDebug)]
pub struct Object {
    /// The ELF file associated with this object.
    /// Skipped in debug output because it can get *really* verbose.
    #[debug(skip)]
    pub file: delf::File<Vec<u8>>,

    /// The path this ELF object was loaded from.
    pub path: PathBuf,

    /// The base address for mapping this ELF object to memory.
    pub base: delf::Addr,

    /// The memory range associated with this object.
    pub mem_range: Range<delf::Addr>,

    /// The memory segments associated with this object.
    pub segments: Vec<Segment>,

    /// The symbols associated with this object.
    #[debug(skip)]
    pub syms: Vec<NamedSym>,

    /// A map from symbol names to named symbols
    #[debug(skip)]
    pub sym_map: MultiMap<Name, NamedSym>,

    /// Relocations associated with this object
    #[debug(skip)]
    pub rels: Vec<delf::Rela>,
}

/// A memory segment.
#[derive(CustomDebug)]
pub struct Segment {
    #[debug(skip)]
    pub map: Arc<MemoryMap>,
    pub vaddr_range: Range<delf::Addr>,
    pub padding: delf::Addr,
    pub flags: BitFlags<delf::SegmentFlag>,
}

/// A named ELF symbol.
#[derive(Debug, Clone)]
pub struct NamedSym {
    sym: delf::Sym,
    name: Name,
}

/// A named ELF symbol where `name` has already been run through [`std::fmt::Debug::fmt`].
/// This is useful for getting a `Send + Sync` version of [`NamedSym`].
#[derive(Debug, Clone)]
pub struct PreformattedDebugNamedSym {
    sym: delf::Sym,
    name: String,
}

impl From<NamedSym> for PreformattedDebugNamedSym {
    fn from(val: NamedSym) -> Self {
        Self {
            sym: val.sym,
            name: format!("{:?}", val.name),
        }
    }
}

/// Pretty much just teis together an object and a symbol.
#[derive(Debug, Clone)]
pub struct ObjectSym<'a> {
    obj: &'a Object,
    sym: &'a NamedSym,
}

impl ObjectSym<'_> {
    /// Returns the re-based address of the object/symbol combo.
    fn value(&self) -> delf::Addr {
        self.obj.base + self.sym.sym.value
    }
}

/// Let's us know the result of looking up a symbol.
#[derive(Debug, Clone)]
pub enum ResolvedSym<'a> {
    Defined(ObjectSym<'a>),
    Undefined,
}

impl ResolvedSym<'_> {
    /// Get the re-based address of the resolved symbol, or just `0x0` if the
    /// symbol was not resolved.
    fn value(&self) -> delf::Addr {
        match self {
            Self::Defined(sym) => sym.value(),
            Self::Undefined => delf::Addr(0x0),
        }
    }

    /// Get the size of the resolved symbol, or `0` if it isn't resolved.
    fn size(&self) -> usize {
        match self {
            Self::Defined(sym) => sym.sym.sym.size as usize,
            Self::Undefined => 0,
        }
    }
}

/// Groups an object and its relocation so that its easier to get the address
/// of a relocation pre-adjusted to its base address.
#[derive(Debug, Clone)]
struct ObjectRel<'a> {
    obj: &'a Object,
    rel: &'a delf::Rela,
}

impl ObjectRel<'_> {
    /// Get the address of a relocation, pre-adjusted to its associated `Object`'s
    /// base address.
    fn addr(&self) -> delf::Addr {
        self.obj.base + self.rel.offset
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u64)]
#[allow(dead_code)]
pub enum AuxType {
    /// End of vector
    Null = 0,
    /// Entry should be ignored
    Ignore = 1,
    /// File descriptor of program
    ExecFd = 2,
    /// Program headers for program
    PHdr = 3,
    /// Size of program header entry
    PhEnt = 4,
    /// Number of program headers
    PhNum = 5,
    /// System page size
    PageSz = 6,
    /// Base address of interpreter
    Base = 7,
    /// Flags
    Flags = 8,
    /// Entry point of program
    Entry = 9,
    /// Program is not ELF
    NotElf = 10,
    /// Real uid
    Uid = 11,
    /// Effective uid
    EUid = 12,
    /// Real gid
    Gid = 13,
    /// Effective gid
    EGid = 14,
    /// String identifying CPU for optimizations
    Platform = 15,
    /// Arch-dependent hints at CPU capabilities
    HwCap = 16,
    /// Frequency at which times() increments
    ClkTck = 17,
    /// Secure mode boolean
    Secure = 23,
    /// String identifying real platform, may differ from Platform
    BasePlatform = 24,
    /// Address of 16 random bytes
    Random = 25,
    // Extension of HwCap
    HwCap2 = 26,
    /// Filename of program
    ExecFn = 31,

    SysInfo = 32,
    SysInfoEHdr = 33,
}

/// Represents an auxiliary vector.
pub struct Auxv {
    typ: AuxType,
    value: u64,
}

impl Auxv {
    /// A list of all the auxiliary types we know (and care) about
    const KNOWN_TYPES: &'static [AuxType] = &[
        AuxType::ExecFd,
        AuxType::PHdr,
        AuxType::PhEnt,
        AuxType::PhNum,
        AuxType::PageSz,
        AuxType::Base,
        AuxType::Flags,
        AuxType::Entry,
        AuxType::NotElf,
        AuxType::Uid,
        AuxType::EUid,
        AuxType::Gid,
        AuxType::EGid,
        AuxType::Platform,
        AuxType::HwCap,
        AuxType::ClkTck,
        AuxType::Secure,
        AuxType::BasePlatform,
        AuxType::Random,
        AuxType::HwCap2,
        AuxType::ExecFn,
        AuxType::SysInfo,
        AuxType::SysInfoEHdr,
    ];

    /// Get an auxiliary vector value with the help of libc.
    pub fn get(typ: AuxType) -> Option<Self> {
        extern "C" {
            /// From libc
            fn getauxval(typ: u64) -> u64;
        }

        unsafe {
            match getauxval(typ as u64) {
                0 => None,
                value => Some(Self { typ, value }),
            }
        }
    }

    /// Returns a list of all aux vectors passed to us _that we know about_.
    pub fn get_known() -> Vec<Self> {
        Self::KNOWN_TYPES
            .iter()
            .copied()
            .filter_map(Self::get)
            .collect()
    }
}

/// Represents thread-local storage.
#[derive(Debug)]
pub struct TLS {
    offsets: HashMap<delf::Addr, delf::Addr>,
    block: Vec<u8>,
    tcb_addr: delf::Addr,
}

/// Errors that may occur when loading an ELF object.
#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("ELF object not found: {0}")]
    NotFound(String),
    #[error("An invalid or unsupported path was encountered")]
    InvalidPath(PathBuf),
    #[error("I/O error when accessing {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("ELF object could not be parsed: {0}\n{1}")]
    ParseError(PathBuf, delf::FileParseError),
    #[error("ELF object has no load segments")]
    NoLoadSegments,
    #[error("ELF object could not be mapped in memory: {0}")]
    MapError(#[from] mmap::MapError),
    #[error("Could not read symbols from ELF object: {0}")]
    ReadSymsError(#[from] delf::ReadSymsError),
    #[error("Could not read relocations from ELF object: {0}")]
    ReadRelaError(#[from] delf::ReadRelaError),
}

/// Errors that may occur when performing memory relocations on an ELF object.
#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("{0:?}: Unimplemented relocation: {1:?}")]
    UnimplementedRelocation(PathBuf, delf::RelType),
    #[error("Unknown symbol number: {0}")]
    UnknownSymbolNumber(u32),
    #[error("Undefined symbol: {0:?}")]
    UndefinedSymbol(PreformattedDebugNamedSym),
}
