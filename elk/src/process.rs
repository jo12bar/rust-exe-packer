//! Defines a dependency graph encompassing the whole program.

use custom_debug_derive::Debug as CustomDebug;
use mmap::MemoryMap;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

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
        let input = fs::read(&path).map_err(|e| LoadError::Io(path.clone(), e))?;

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

        // let deps = file
        //     .dynamic_entry_strings(delf::DynamicTag::Needed)
        //     .collect::<Vec<_>>();

        let obj = Object {
            path: path.clone(),
            base: delf::Addr(0x400000),
            maps: Vec::new(),
            file,
        };

        let idx = self.objects.len();
        self.objects.push(obj);
        self.objects_by_path.insert(path, idx);

        // for dep in deps {
        //     self.get_object(&dep)?;
        // }

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

    /// The memory mappings associated with this object.
    /// [`mmap::MemoryMap`] does not implement `Debug`, so this has to be skipped
    /// when outputting debug info.
    #[debug(skip)]
    pub maps: Vec<MemoryMap>,

    /// The path this ELF object was loaded from.
    pub path: PathBuf,

    /// The base address for mapping this ELF object to memory.
    pub base: delf::Addr,
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
    #[error("ELF object could not be parsed: {0}\n{1:?}")]
    ParseError(PathBuf, delf::FileParseError),
}
