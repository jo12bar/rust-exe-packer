use super::prelude::*;

#[derive(Debug, Clone, DekuRead, DekuWrite)]
pub struct DynamicTag {
    pub typ: DynamicTagType,
    pub addr: u64,
}

#[derive(Debug, DekuRead, DekuWrite, Clone, Copy, PartialEq)]
#[deku(type = "u64")]
pub enum DynamicTagType {
    #[deku(id = "0")]
    Null,
    #[deku(id = "2")]
    PltRelSz,
    #[deku(id = "5")]
    StrTab,
    #[deku(id = "6")]
    SymTab,
    #[deku(id = "7")]
    Rela,
    #[deku(id = "8")]
    RelaSz,
    #[deku(id = "11")]
    SymEnt,
    #[deku(id = "23")]
    JmpRel,
    #[deku(id_pat = "_")]
    Other(u64),
}
