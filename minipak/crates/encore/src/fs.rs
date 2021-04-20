//! Utilities for reading from and writing to files.

use crate::{
    error::EncoreError,
    memmap::{FileOpts, MmapOptions},
    syscall::{self, FileDescriptor, MmapProt, OpenFlags, Stat},
};
use alloc::{format, string::String};
use core::{
    mem::MaybeUninit,
    ops::{Index, Range, RangeFull},
};

/// A read-only file.
pub struct File {
    path: String,
    fd: FileDescriptor,
}

#[allow(clippy::len_without_is_empty)]
impl File {
    /// Opens a file (read-only)
    pub fn open(path: &str) -> Result<Self, EncoreError> {
        Self::raw_open(path, OpenFlags::RDONLY, 0)
    }

    /// Creates a file (for writing)
    pub fn create(path: &str, mode: u64) -> Result<Self, EncoreError> {
        Self::raw_open(
            path,
            OpenFlags::RDWR | OpenFlags::CREAT | OpenFlags::TRUNC,
            mode,
        )
    }

    /// Internal: open a file with given flags and mode.
    fn raw_open(path: &str, flags: OpenFlags, mode: u64) -> Result<Self, EncoreError> {
        let null_path = format!("{}\0", path);
        let fd = unsafe { syscall::open(null_path.as_ptr(), flags, mode) };
        if (fd.0 as i64) < 0 {
            return Err(EncoreError::Open(path.into()));
        }

        Ok(Self {
            path: path.into(),
            fd,
        })
    }

    /// Write a whole buffer to this file, or fail. This may involve multiple
    /// syscalls.
    pub fn write_all(&mut self, mut buf: &[u8]) -> Result<(), EncoreError> {
        while !buf.is_empty() {
            let written = unsafe { syscall::write(self.fd, buf.as_ptr(), buf.len() as u64) };
            if written as i64 == -1 {
                return Err(EncoreError::Write(self.path.clone()));
            }
            buf = &buf[written as usize..];
        }

        Ok(())
    }

    /// Returns the length of the file, in bytes.
    pub fn len(&self) -> Result<u64, EncoreError> {
        let mut stat = MaybeUninit::<Stat>::uninit();
        let ret = unsafe { syscall::fstat(self.fd(), stat.as_mut_ptr()) };
        if ret != 0 {
            return Err(EncoreError::Stat(self.path.clone()));
        }
        let stat = unsafe { stat.assume_init() };
        Ok(stat.size)
    }

    /// Returns the file descriptor.
    pub fn fd(&self) -> FileDescriptor {
        self.fd
    }

    /// Map this file in memory (read-only)
    pub fn map(&self) -> Result<Map<'_>, EncoreError> {
        let self_data = MmapOptions::new(self.len()?)
            .file(FileOpts {
                fd: self.fd,
                offset: 0,
            })
            .prot(MmapProt::READ)
            .map()? as *const u8;

        let data = unsafe { core::slice::from_raw_parts(self_data, self.len()? as _) };

        Ok(Map { file: self, data })
    }
}

/// The file will be closed on drop.
impl Drop for File {
    fn drop(&mut self) {
        unsafe { syscall::close(self.fd) };
    }
}

/// A memory-mapped file.
pub struct Map<'a> {
    /// This file reference exists so that the file isn't closed until the
    /// mapping is dropped.
    #[allow(unused)]
    file: &'a File,

    data: &'a [u8],
}

/// Unmap the file from memory on drop.
impl<'a> Drop for Map<'a> {
    fn drop(&mut self) {
        unsafe { syscall::munmap(self.data.as_ptr(), self.data.len() as _) };
    }
}

/// Allows referencing the memory map's underlying data.
impl<'a> AsRef<[u8]> for Map<'a> {
    fn as_ref(&self) -> &[u8] {
        self.data
    }
}

/// Allows indexing into the memory map's underlying data.
impl<'a> Index<Range<usize>> for Map<'a> {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.data[index]
    }
}

/// Allows indexing into the memory map's underlying data.
impl<'a> Index<RangeFull> for Map<'a> {
    type Output = [u8];

    fn index(&self, _index: RangeFull) -> &Self::Output {
        self.data
    }
}
