//! Defines a dependency graph encompassing the whole program.

use custom_debug_derive::Debug as CustomDebug;
use enumflags2::BitFlags;
use mmap::{MapOption, MemoryMap};
use std::{
    cmp::{max, min},
    collections::HashMap,
    io::Read,
    ops::Range,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    usize,
};

/// Computes the minimal range that contains two ranges.
fn convex_hull<T: std::cmp::Ord>(a: Range<T>, b: Range<T>) -> Range<T> {
    (min(a.start, b.start))..(max(a.end, b.end))
}

/// A sub-process, executed in memory.
#[derive(Debug)]
pub struct Process {
    /// The objects within this process graph.
    pub objects: Vec<Object>,
    /// A map from object paths to their indices in [`Process::objects`].
    pub objects_by_path: HashMap<PathBuf, usize>,
    /// Our search path for libraries.
    pub search_path: Vec<PathBuf>,
}

impl Process {
    /// Create a new process graph.
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            objects_by_path: HashMap::new(),
            search_path: vec!["/lib/x86_64-linux-gnu".into()],
        }
    }

    /// Load an ELF object, by path. Returns the index
    /// into the [`Process::objects`] vector where the object is stored.
    pub fn load_object<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<usize, LoadError> {
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
        let file = delf::File::parse(&input[..])
            .map_err(|fpe| LoadError::ParseError(path.clone(), fpe))?;

        let origin = path
            .parent()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
            .to_str()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;

        self.search_path.extend(
            file.dynamic_entry_strings(delf::DynamicTag::RPath)
                .chain(file.dynamic_entry_strings(delf::DynamicTag::RunPath))
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
        let mem_map = std::mem::ManuallyDrop::new(MemoryMap::new(mem_size, &[])?);
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        println!("Mapping memory segments");
        let segments = load_segments()
            .filter_map(|ph| {
                if ph.memsz.0 > 0 {
                    println!("\t- Mapping {:#?}", ph);

                    let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                    let padding = ph.vaddr - vaddr;
                    let offset = ph.offset - padding;
                    let memsz = ph.memsz + padding;

                    println!(
                        "\t  └──> to file {:?} | mem {:?}",
                        offset..(offset + memsz),
                        vaddr..(vaddr + memsz)
                    );

                    let map_res = MemoryMap::new(
                        memsz.into(),
                        &[
                            MapOption::MapReadable,
                            MapOption::MapWritable,
                            MapOption::MapFd(fs_file.as_raw_fd()),
                            MapOption::MapOffset(offset.into()),
                            MapOption::MapAddr(unsafe { (base + vaddr).as_ptr() }),
                        ],
                    );

                    Some(map_res.map(|map| Segment {
                        map,
                        padding,
                        flags: ph.flags,
                    }))
                } else {
                    None
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let syms = file.read_syms()?;

        let obj = Object {
            path: path.clone(),
            base,
            segments,
            mem_range,
            file,
            syms,
        };

        // TODO: REMOVE ME

        if path.to_str().unwrap().ends_with("libmsg.so") {
            let msg_addr: *const u8 = unsafe { (base + delf::Addr(0x2000)).as_ptr() };
            dbg!(base);
            dbg!(msg_addr);
            let msg_slice = unsafe { std::slice::from_raw_parts(msg_addr, 0x26) };
            let msg = std::str::from_utf8(msg_slice).unwrap();
            dbg!(msg);
        }

        // /TODO

        let idx = self.objects.len();
        self.objects.push(obj);
        self.objects_by_path.insert(path, idx);

        Ok(idx)
    }

    /// Load an object *and* all its dependencies, traversing the dependency graph
    /// breadth-first the way LD does. Return the index of the loaded main object
    /// in the [`Process::objects`] vector.
    pub fn load_object_and_dependencies<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<usize, LoadError> {
        let index = self.load_object(path)?;

        let mut a = vec![index];
        while !a.is_empty() {
            a = a
                .into_iter()
                .map(|index| &self.objects[index].file)
                .flat_map(|file| file.dynamic_entry_strings(delf::DynamicTag::Needed))
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

    /// Returns the path to an object by searching the entire search_path.
    pub fn object_path(&self, name: &str) -> anyhow::Result<PathBuf, LoadError> {
        self.search_path
            .iter()
            .filter_map(|prefix| prefix.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }

    /// Given an object name, this will either
    ///
    /// - Return the index in [`Process::objects`] of an already-loaded object, or
    /// - Load the object and return its fresh index.
    pub fn get_object(&mut self, name: &str) -> anyhow::Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.objects_by_path
            .get(&path)
            .map(|&i| Ok(GetResult::Cached(i)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }

    /// Apply memory relocations to all loaded objects.
    pub fn apply_relocations(&self) -> Result<(), RelocationError> {
        for obj in self.objects.iter().rev() {
            println!("Applying relocations for {:?}", obj.path);

            match obj.file.read_rela_entries() {
                Ok(rels) => {
                    for rel in rels {
                        println!("\t- Found {:?}", rel);

                        match rel.typ {
                            delf::RelType::Known(t) => match t {
                                delf::KnownRelType::_64 => {
                                    let name = obj.sym_name(rel.sym)?;
                                    println!("\t  ├──> Looking up {:?}", name);

                                    let (lib, sym) = self
                                        .lookup_symbol(&name, None)?
                                        .ok_or(RelocationError::UndefinedSymbol(name))?;

                                    println!("\t  ├──> Found at {:?} in {:?}", sym.value, lib.path);

                                    let offset = obj.base + rel.offset;
                                    let value = sym.value + lib.base + rel.addend;
                                    println!("\t  ├──> Value: {:?}", value);

                                    unsafe {
                                        let ptr: *mut u64 = offset.as_mut_ptr();
                                        println!("\t  └──> Applying reloc @ {:?}", ptr);
                                        *ptr = value.0;
                                    }
                                }

                                delf::KnownRelType::Copy => {
                                    let name = obj.sym_name(rel.sym)?;
                                    let (lib, sym) =
                                        self.lookup_symbol(&name, Some(obj))?.ok_or_else(|| {
                                            RelocationError::UndefinedSymbol(name.clone())
                                        })?;

                                    println!(
                                        "\t  ├──> Found {:?} at {:?} (size {:?}) in {:?}",
                                        name, sym.value, sym.size, lib.path
                                    );

                                    unsafe {
                                        let src = (sym.value + lib.base).as_ptr();
                                        let dst = (rel.offset + obj.base).as_mut_ptr();

                                        println!(
                                            "\t  └──> Copying {} bytes from {:?} to {:?}",
                                            sym.size, src, dst
                                        );
                                        std::ptr::copy_nonoverlapping::<u8>(
                                            src,
                                            dst,
                                            sym.size as usize,
                                        );
                                    }
                                }

                                _ => return Err(RelocationError::UnimplementedRelocation(t)),
                            },

                            delf::RelType::Unknown(num) => {
                                return Err(RelocationError::UnknownRelocation(num))
                            }
                        }
                    }
                }

                Err(e) => println!("\t- Nevermind: {:?}", e),
            }
        }

        Ok(())
    }

    /// Lookup a symbol by name. Returns the object containing the symbol and
    /// the symbol itself, if found, or `None` otherwise.
    /// Also allows you to optionally ignore a specific object - useful for Copy
    /// relocations, for instance.
    pub fn lookup_symbol(
        &self,
        name: &str,
        ignore: Option<&Object>,
    ) -> Result<Option<(&Object, &delf::Sym)>, RelocationError> {
        for obj in &self.objects {
            if let Some(ignored) = ignore {
                if std::ptr::eq(ignored, obj) {
                    continue;
                }
            }

            for (i, sym) in obj.syms.iter().enumerate() {
                if obj.sym_name(i as u32)? == name {
                    return Ok(Some((obj, sym)));
                }
            }
        }

        Ok(None)
    }

    /// Adjust protections on mapped memory ranges to be what they're supposed
    /// to be.
    pub fn adjust_protections(&self) -> Result<(), region::Error> {
        use region::{protect, Protection};

        for obj in &self.objects {
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

        Ok(())
    }
}

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
    pub file: delf::File,

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
    pub syms: Vec<delf::Sym>,
}

impl Object {
    /// Get the name of the symbol at some index in `Object::syms`.
    pub fn sym_name(&self, index: u32) -> Result<String, RelocationError> {
        self.file
            .get_string(self.syms[index as usize].name)
            .map_err(|_| RelocationError::UnknownSymbolNumber(index))
    }
}

/// A memory segment.
#[derive(CustomDebug)]
pub struct Segment {
    #[debug(skip)]
    pub map: MemoryMap,
    pub padding: delf::Addr,
    pub flags: BitFlags<delf::SegmentFlag>,
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
}

/// Errors that may occur when performing memory relocations on an ELF object.
#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("Unknown relocation: {0}")]
    UnknownRelocation(u32),
    #[error("Unimplemented relocation: {0:?}")]
    UnimplementedRelocation(delf::KnownRelType),
    #[error("Unknown symbol number: {0}")]
    UnknownSymbolNumber(u32),
    #[error("Undefined symbol: {0}")]
    UndefinedSymbol(String),
}
