use super::prelude::*;

#[derive(Debug, DekuRead, DekuWrite, Clone, Copy)]
pub struct Sym {
    pub name: u32,

    pub bind: SymBind,
    #[deku(pad_bytes_after = "1")]
    pub typ: SymType,

    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}

#[derive(Debug, DekuRead, DekuWrite, Clone, Copy, PartialEq)]
#[deku(type = "u8", bits = 4)]
pub enum SymBind {
    #[deku(id = "0")]
    Local,
    #[deku(id = "1")]
    Global,
    #[deku(id = "2")]
    Weak,
    #[deku(id_pat = "_")]
    Other(u8),
}

#[derive(Debug, DekuRead, DekuWrite, Clone, Copy, PartialEq)]
#[deku(type = "u8", bits = 4)]
pub enum SymType {
    #[deku(id = "0")]
    None,
    #[deku(id = "1")]
    Object,
    #[deku(id = "2")]
    Func,
    #[deku(id = "3")]
    Section,
    #[deku(id = "4")]
    File,
    #[deku(id = "6")]
    Tls,
    #[deku(id = "10")]
    IFunc,
    #[deku(id_pat = "_")]
    Other(u8),
}
