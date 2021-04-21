use super::prelude::*;

/// An ELF program header (loader view, segment mapped into memory).
#[derive(Derivative, DekuRead, DekuWrite, Clone)]
#[derivative(Debug)]
pub struct ProgramHeader {
    pub typ: SegmentType,

    #[derivative(Debug(format_with = "hex_fmt"))]
    pub flags: u32,

    #[derivative(Debug(format_with = "hex_fmt"))]
    pub offset: u64,

    #[derivative(Debug(format_with = "hex_fmt"))]
    pub vaddr: u64,

    #[derivative(Debug(format_with = "hex_fmt"))]
    pub paddr: u64,

    #[derivative(Debug(format_with = "hex_fmt"))]
    pub filesz: u64,

    #[derivative(Debug(format_with = "hex_fmt"))]
    pub memsz: u64,

    #[derivative(Debug(format_with = "hex_fmt"))]
    pub align: u64,
}

impl ProgramHeader {
    /// The size of a fully-serialized program header.
    pub const SIZE: u16 = 56;

    /// The Execute permission for a memory segment.
    pub const EXECUTE: u32 = 1;
    /// The Write permission for a memory segment.
    pub const WRITE: u32 = 2;
    /// The Read permission for a memory segment.
    pub const READ: u32 = 4;

    /// Returns a range that spans from offset to offset+filesz.
    pub fn file_range(&self) -> core::ops::Range<usize> {
        let start = self.offset as usize;
        let len = self.filesz as usize;
        let end = start + len;
        start..end
    }

    /// Returns a range that spans from vaddr to vaddr+memsz.
    pub fn mem_range(&self) -> core::ops::Range<u64> {
        let start = self.vaddr;
        let len = self.memsz;
        let end = start + len;
        start..end
    }
}

/// The type of an ELF memory segment.
#[derive(Debug, DekuRead, DekuWrite, Clone, Copy, PartialEq)]
#[deku(type = "u32")]
pub enum SegmentType {
    #[deku(id = "0x0")]
    Null,
    #[deku(id = "0x1")]
    Load,
    #[deku(id = "0x2")]
    Dynamic,
    #[deku(id = "0x3")]
    Interp,
    #[deku(id = "0x7")]
    Tls,
    #[deku(id = "0x6474e551")]
    GnuStack,
    #[deku(id_pat = "_")]
    Other(u32),
}
