use super::prelude::*;

/// An ELF object header.
#[derive(Derivative, Clone, PartialEq, DekuRead, DekuWrite)]
#[derivative(Debug)]
#[deku(magic = b"\x7FELF")]
pub struct ObjectHeader {
    #[derivative(Debug = "ignore")]
    pub class: ElfClass,
    pub endianness: Endianness,
    /// Always 1
    pub version: u8,
    #[deku(pad_bytes_after = "8")]
    pub os_abi: OsAbi,
    pub typ: ElfType,
    pub machine: ElfMachine,
    /// Always 1
    pub version_bis: u32,
    #[derivative(Debug(format_with = "hex_fmt"))]
    pub entry_point: u64,

    #[derivative(Debug(format_with = "hex_fmt"))]
    pub ph_offset: u64,
    #[derivative(Debug(format_with = "hex_fmt"))]
    pub sh_offset: u64,

    #[derivative(Debug(format_with = "hex_fmt"))]
    pub flags: u32,
    pub hdr_size: u16,

    pub ph_entsize: u16,
    pub ph_count: u16,

    pub sh_entsize: u16,
    pub sh_count: u16,
    pub sh_nidx: u16,
}

impl ObjectHeader {
    /// The complete, serialized size of the ELF object header.
    pub const SIZE: u16 = 64;
}

/// The class of ELF object. Either 32-bit, 64-bit, or some other (invalid)
/// number.
#[derive(Clone, Copy, DekuRead, DekuWrite, Debug, PartialEq)]
#[deku(type = "u8")]
pub enum ElfClass {
    #[deku(id = "1")]
    Elf32,
    #[deku(id = "2")]
    Elf64,
    #[deku(id_pat = "_")]
    Other(u8),
}

/// The type of ELF object - either executable or dynamic, or an invalid value.
#[derive(Clone, Copy, DekuRead, DekuWrite, Debug, PartialEq)]
#[deku(type = "u16")]
pub enum ElfType {
    #[deku(id = "0x2")]
    Exec,
    #[deku(id = "0x3")]
    Dyn,
    #[deku(id_pat = "_")]
    Other(u16),
}

/// The endianess of the file. Little, Big, or some other (invalid) number.
#[derive(Clone, Copy, DekuRead, DekuWrite, Debug, PartialEq)]
#[deku(type = "u8")]
pub enum Endianness {
    #[deku(id = "0x1")]
    Little,
    #[deku(id = "0x2")]
    Big,
    #[deku(id_pat = "_")]
    Other(u8),
}

/// The architecture of the underlying code. x86, x86-64, or something that's
/// unsupported.
#[derive(Clone, Copy, DekuRead, DekuWrite, Debug, PartialEq)]
#[deku(type = "u16")]
pub enum ElfMachine {
    #[deku(id = "0x03")]
    X86,
    #[deku(id = "0x3e")]
    X86_64,
    #[deku(id_pat = "_")]
    Other(u16),
}

/// The version of the ABI. Expected to be version 1 of the SysV ABI, but we
/// allow for other values to be parsed too so we can deal with them gracefully
/// later on.
#[derive(Clone, Copy, DekuRead, DekuWrite, Debug, PartialEq)]
#[deku(type = "u8")]
pub enum OsAbi {
    #[deku(id = "0x0")]
    SysV,
    #[deku(id_pat = "_")]
    Other(u8),
}
