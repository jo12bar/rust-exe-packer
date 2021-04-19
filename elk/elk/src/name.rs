use anyhow::Context;
use mmap::MemoryMap;
use std::{
    fmt,
    hash::{Hash, Hasher},
    ops::Range,
    sync::Arc,
};

/// Adds a method to [`mmap::MemoryMap`] that lets us work with slices instead of
/// pointers.
trait MemoryMapExt {
    fn as_slice(&self) -> &[u8];
}

impl MemoryMapExt for MemoryMap {
    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data(), self.len()) }
    }
}

/// Known names for symbols in the ELF file.
#[derive(Clone)]
pub enum Name {
    /// For names that come stright from an ELF file mapped in memory.
    Mapped {
        map: Arc<MemoryMap>,
        range: Range<usize>,
    },
    /// For names that we own. For example, maybe we want to look up a specific
    /// symbol from a Rust string literal - this will be useful for that.
    Owned(Vec<u8>),
}

impl Name {
    /// Get a name from an offset somewhere in a memory map.
    pub fn mapped(map: &Arc<MemoryMap>, offset: usize) -> anyhow::Result<Self> {
        let len = map
            .as_slice()
            .iter()
            .skip(offset)
            .position(|&c| c == 0)
            .context("Scanned 2048 bytes without finding null-terminator for name.")?;

        Ok(Self::Mapped {
            map: map.clone(),
            range: offset..offset + len,
        })
    }

    /// Construct an owned name.
    pub fn owned<T: Into<Vec<u8>>>(value: T) -> Self {
        Self::Owned(value.into())
    }

    /// Get the name as a slice into memory.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Mapped { map, range } => &map.as_slice()[range.clone()],
            Self::Owned(vec) => &vec[..],
        }
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.as_slice();

        if let Ok(s) = std::str::from_utf8(s) {
            // This only succeeds if the name is valid utf-8:
            fmt::Display::fmt(s, f)
        } else {
            fmt::Debug::fmt(s, f)
        }
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(self.as_slice(), other.as_slice())
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(self.as_slice(), state)
    }
}
