//! This module contains abstractations for mapping memory that are *way* safer
//! than [`syscall::mmap`].

use crate::{
    error::EncoreError,
    syscall::{self, FileDescriptor, MmapFlags, MmapProt},
};

/// Options for memory mapping.
pub struct MmapOptions {
    /// Memory protections to apply.
    prot: MmapProt,
    /// Flags to pass to the `mmap` syscall.
    flags: MmapFlags,
    /// The length of the memory region to map.
    len: u64,
    /// The file to be mapped.
    file: Option<FileOpts>,
    /// Where to map the file.
    at: Option<u64>,
}

/// Options for mapping a file.
#[derive(Default, Clone)]
pub struct FileOpts {
    /// An open file descriptor.
    pub fd: FileDescriptor,
    /// The offset at which to map the file.
    pub offset: u64,
}

impl MmapOptions {
    /// Create a new set of mmap options, given the length of data to be mapped.
    pub fn new(len: u64) -> Self {
        Self {
            prot: MmapProt::READ | MmapProt::WRITE,
            flags: MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
            len,
            file: None,
            at: None,
        }
    }

    /// Specify a file that should be mapped.
    pub fn file(&mut self, file: FileOpts) -> &mut Self {
        self.file = Some(file);
        self
    }

    /// Sets protections - defaults to `READ` + `WRITE`.
    pub fn prot(&mut self, prot: MmapProt) -> &mut Self {
        self.prot = prot;
        self
    }

    /// Sets flags to pass to the `mmap` syscall. Note that `ANONYMOUS` and
    /// `PRIVATE` are the default, and this overwrites them. If `at` is set,
    /// `FIXED` is also used.
    pub fn flags(&mut self, flags: MmapFlags) -> &mut Self {
        self.flags = flags;
        self
    }

    /// Specify a fixed address for this mapping (sets the `FIXED` flag).
    pub fn at(&mut self, at: u64) -> &mut Self {
        self.at = Some(at);
        self
    }

    /// Create the memory mapping. This should be called last.
    pub fn map(&mut self) -> Result<u64, EncoreError> {
        let mut flags = self.flags;

        if let Some(at) = &self.at {
            if !is_aligned(*at) {
                return Err(EncoreError::MmapMemUnaligned(*at));
            }
            flags.insert(MmapFlags::FIXED);
        }

        if let Some(file) = &self.file {
            if !is_aligned(file.offset) {
                return Err(EncoreError::MmapFileUnaligned(file.offset));
            }
            flags.remove(MmapFlags::ANONYMOUS);
        }

        let file = self.file.clone().unwrap_or_default();
        let addr = self.at.unwrap_or_default();

        let res = unsafe { syscall::mmap(addr, self.len, self.prot, flags, file.fd, file.offset) };
        if res as i64 == -1 {
            return Err(EncoreError::MmapFailed);
        }

        Ok(res)
    }
}

fn is_aligned(x: u64) -> bool {
    x & 0xFFF == 0
}
