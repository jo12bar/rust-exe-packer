use anyhow::Context;
use std::{
    fmt,
    hash::{Hash, Hasher},
};

/// Known names for symbols in the ELF file.
#[derive(Clone)]
pub enum Name {
    /// For names that come stright from an ELF file mapped in memory.
    FromAddr { addr: delf::Addr, len: usize },
    /// For names that we own. For example, maybe we want to look up a specific
    /// symbol from a Rust string literal - this will be useful for that.
    Owned(Vec<u8>),
}

impl Name {
    /// Get a name from a null-terminated string somewhere in memory.
    ///
    /// For "safety" (to avoid segfaults), name size is limited to 2048 bytes.
    /// Hopefully the *actual* limit for ELF symbol size is way lower, so we won't
    /// ever run into that.
    ///
    /// # Safety
    ///
    /// `addr` must point to a null-terminated string. Otherwise, you'll have an
    /// UB party with a bunch of depressed clowns.
    pub unsafe fn from_addr(addr: delf::Addr) -> anyhow::Result<Self> {
        let len = addr
            .as_slice::<u8>(2048)
            .iter()
            .position(|&c| c == 0)
            .context("Scanned 2048 bytes without finding a null-terminator for a name")?;

        Ok(Self::FromAddr { addr, len })
    }

    /// Get the name as a slice into memory.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::FromAddr { addr, len } => unsafe { addr.as_slice(*len) },
            Self::Owned(vec) => &vec[..],
        }
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(s) = std::str::from_utf8(self.as_slice()) {
            // This only succeeds if the name is valid utf-8:
            fmt::Display::fmt(s, f)
        } else {
            fmt::Debug::fmt(self.as_slice(), f)
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
