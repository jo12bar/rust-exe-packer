//! # `delf` - Demystify ELF

mod parse;

use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::*;
use std::{convert::TryFrom, fmt, ops::Range};

/// The _actual_ fields parsed from a 64-bit, little-endian ELF file.
#[derive(Debug)]
pub struct FileContents {
    pub typ: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
    /// The index of the section table entry that contains the section names
    /// in [`File::section_headers`].
    pub shstrndx: usize,
}

impl FileContents {
    /// Magic bytes expected to be found at the beginning of an ELF file.
    /// `0x7c`, `'E'`, `'L'`, `'F'`.
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    /// Parse an ELF file from a buffer of bytes.
    fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            bytes::complete::{tag, take},
            combinator::{map, verify},
            error::context,
            number::complete::{le_u16, le_u32},
            sequence::tuple,
        };

        let full_input = i;

        let (i, _) = tuple((
            // --------
            context("Magic", tag(Self::MAGIC)),
            context("Class", tag(&[0x2])),      // Only support 64-bit
            context("Endianness", tag(&[0x1])), // Only support little-endian
            context("Version", tag(&[0x1])),
            context("OS ABI", nom::branch::alt((tag(&[0x0]), tag(&[0x3])))),
            // --------
            context("Padding", take(8_usize)),
        ))(i)?;

        let (i, (typ, machine)) = tuple((Type::parse, Machine::parse))(i)?;

        // The 32-bit Version integer should always be set to 1 in the current
        // version of ELF. We don't *have* to check it, but we do anyways.
        let (i, _) = context("Version (bis)", verify(le_u32, |&x| x == 1))(i)?;

        let (i, entry_point) = Addr::parse(i)?;

        // Some values are stored as u16's in the ELF file to save storage, but
        // they're actually file offsets or counts. So, in Rust, we want to store
        // them as `usize`.
        let u16_usize = map(le_u16, |x| x as usize);

        // ph == program header.
        // sh == section header.
        let (i, (ph_offset, sh_offset)) = tuple((Addr::parse, Addr::parse))(i)?;
        let (i, (_flags, _hdr_size)) = tuple((le_u32, le_u16))(i)?;
        let (i, (ph_entsize, ph_count)) = tuple((&u16_usize, &u16_usize))(i)?;
        let (i, (sh_entsize, sh_count, sh_nidx)) = tuple((&u16_usize, &u16_usize, &u16_usize))(i)?;

        // Parse each program header:
        let ph_slices = (&full_input[ph_offset.into()..]).chunks(ph_entsize);
        let mut program_headers = Vec::with_capacity(ph_count);
        for ph_slice in ph_slices.take(ph_count) {
            let (_, ph) = ProgramHeader::parse(full_input, ph_slice)?;
            program_headers.push(ph);
        }

        // Parse each section header, in a similar manner:
        let sh_slices = (&full_input[sh_offset.into()..]).chunks(sh_entsize);
        let mut section_headers = Vec::with_capacity(sh_count);
        for sh_slice in sh_slices.take(sh_count) {
            let (_, sh) = SectionHeader::parse(sh_slice)?;
            section_headers.push(sh);
        }

        Ok((
            i,
            Self {
                typ,
                machine,
                entry_point,
                program_headers,
                section_headers,
                shstrndx: sh_nidx as _,
            },
        ))
    }

    /// Gets the first ELF segment matching a [`SegmentType`].
    pub fn segment_of_type(&self, typ: SegmentType) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|ph| ph.typ == typ)
    }

    /// Gets the first ELF section of a given type.
    pub fn section_of_type(&self, typ: SectionType) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|sh| sh.typ == typ)
    }

    /// Attempts to find a Load segment whose memory range contains the given virtual address
    pub fn segment_containing(&self, addr: Addr) -> Option<&ProgramHeader> {
        self.program_headers
            .iter()
            .find(|ph| ph.typ == SegmentType::Load && ph.mem_range().contains(&addr))
    }

    /// Get the dynamic table, consisting of a slice of [`DynamicEntry`]'s, or
    /// `None` if the dynamic table was not found.
    pub fn dynamic_table(&self) -> Option<&[DynamicEntry]> {
        match self.segment_of_type(SegmentType::Dynamic) {
            Some(ProgramHeader {
                contents: SegmentContents::Dynamic(entries),
                ..
            }) => Some(entries),
            _ => None,
        }
    }

    /// Returns an iterator over all dynamic table entries matching a [`DynamicTag`]
    /// contained in this ELF file.
    pub fn dynamic_entries(&self, tag: DynamicTag) -> impl Iterator<Item = Addr> + '_ {
        self.dynamic_table()
            .unwrap_or_default()
            .iter()
            .filter(move |e| e.tag == tag)
            .map(|e| e.addr)
    }

    /// Get the address to a dynamic entry with some [`DynamicTag`].
    pub fn dynamic_entry(&self, tag: DynamicTag) -> Option<Addr> {
        self.dynamic_entries(tag).next()
    }

    /// Like [`File::dynamic_entry`], except it returns a `Result<_, GetDynamicEntryError>`
    /// instead of just an `Option<_>`.
    pub fn get_dynamic_entry(&self, tag: DynamicTag) -> Result<Addr, GetDynamicEntryError> {
        self.dynamic_entry(tag)
            .ok_or(GetDynamicEntryError::NotFound(tag))
    }
}

/// Fields parsed from a 64-bit, little-endian ELF file.
#[derive(Debug)]
pub struct File<I>
where
    I: AsRef<[u8]>,
{
    pub input: I,
    pub contents: FileContents,
}

impl<I> File<I>
where
    I: AsRef<[u8]>,
{
    /// Parse an ELF file from a buffer of bytes.
    pub fn parse(input: I) -> Result<Self, FileParseError> {
        match FileContents::parse(input.as_ref()) {
            Ok((_, contents)) => Ok(Self { input, contents }),

            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(FileParseError::new(input.as_ref(), err))
            }

            Err(_) => panic!("Unexpected nom error"),
        }
    }

    /// Returns an iterator over the strings associated with a dynamic entry.
    pub fn dynamic_entry_strings(&self, tag: DynamicTag) -> impl Iterator<Item = &[u8]> + '_ {
        self.dynamic_entries(tag)
            .map(move |addr| self.dynstr_entry(addr))
    }

    fn read_relocations(
        &self,
        addr_tag: DynamicTag,
        size_tag: DynamicTag,
    ) -> Result<Vec<Rela>, ReadRelaError> {
        use nom::multi::many_m_n;
        use ReadRelaError as E;

        let addr = match self.dynamic_entry(addr_tag) {
            Some(addr) => addr,
            None => return Ok(vec![]),
        };

        let len = self.get_dynamic_entry(size_tag)?;
        let i = self
            .mem_slice(addr, len.into())
            .ok_or(E::RelaSegmentNotFound)?;

        let n = len.0 as usize / Rela::SIZE;

        match many_m_n(n, n, Rela::parse)(i) {
            Ok((_, rela_entries)) => Ok(rela_entries),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(E::ParsingError(format!("{}", err)))
            }
            Err(nom::Err::Incomplete(_)) => unreachable!(),
        }
    }

    /// Read relocation entries from the table pointed to by [`DynamicTag::Rela`].
    pub fn read_rela_entries(&self) -> Result<Vec<Rela>, ReadRelaError> {
        self.read_relocations(DynamicTag::Rela, DynamicTag::RelaSz)
    }

    /// Read relocation entries from the table pointed to by [`DynamicTag::JmpRel`].
    pub fn read_jmp_rel_entries(&self) -> Result<Vec<Rela>, ReadRelaError> {
        self.read_relocations(DynamicTag::JmpRel, DynamicTag::PltRelSz)
    }

    /// Returns a slice of the input, indexed by file offsets.
    pub fn file_slice(&self, addr: Addr, len: usize) -> &[u8] {
        &self.input.as_ref()[addr.into()..len]
    }

    /// Returns a slice of the input corresponding to the given section.
    pub fn section_slice(&self, section: &SectionHeader) -> &[u8] {
        self.file_slice(section.file_range().start, section.file_range().end.into())
    }

    /// Returns a slice of the input corresponding to the given segment
    pub fn segment_slice(&self, segment: &ProgramHeader) -> &[u8] {
        self.file_slice(segment.file_range().start, segment.file_range().end.into())
    }

    /// Returns a slice of the input, indexed by virtual addresses
    pub fn mem_slice(&self, addr: Addr, len: usize) -> Option<&[u8]> {
        self.segment_containing(addr).map(|segment| {
            let start: usize = (addr - segment.mem_range().start).into();
            &self.segment_slice(segment)[start..start + len]
        })
    }

    // /// Returns a slice containing the contents of the relevant `Load` segment
    // /// starting at `mem_addr` until the end of that segment, or `None` if no
    // /// suitable segment can be found.
    // pub fn slice_at(&self, mem_addr: Addr) -> Option<&[u8]> {
    //     self.segment_at(mem_addr)
    //         .map(|seg| &seg.data[(mem_addr - seg.mem_range().start).into()..])
    // }

    /// Read symbols from the given section (internal)
    fn read_symbol_table(&self, section_type: SectionType) -> Result<Vec<Sym>, ReadSymsError> {
        use nom::multi::many_m_n;

        let section = match self.section_of_type(section_type) {
            Some(section) => section,
            None => return Ok(vec![]),
        };

        let i = self.section_slice(section);
        let n = i.len() / section.entsize.0 as usize;

        match many_m_n(n, n, Sym::parse)(i) {
            Ok((_, syms)) => Ok(syms),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(ReadSymsError::ParsingError(format!("{}", err)))
            }
            _ => unreachable!(),
        }
    }

    /// Read symbols from the ".dynsym" section (loader view)
    pub fn read_dynsym_entries(&self) -> Result<Vec<Sym>, ReadSymsError> {
        self.read_symbol_table(SectionType::DynSym)
    }

    /// Read symbols from the ".symtab" section (linker view)
    pub fn read_symtab_entries(&self) -> Result<Vec<Sym>, ReadSymsError> {
        self.read_symbol_table(SectionType::SymTab)
    }

    /// Returns a null-terminated "string" from the ".shstrtab" section as an u8 slice
    pub fn shstrtab_entry(&self, offset: Addr) -> &[u8] {
        let section = &self.contents.section_headers[self.contents.shstrndx];
        let slice = &self.section_slice(section)[offset.into()..];
        slice.split(|&c| c == 0).next().unwrap_or_default()
    }

    /// Get a section by name
    pub fn section_by_name<N>(&self, name: N) -> Option<&SectionHeader>
    where
        N: AsRef<[u8]>,
    {
        self.section_headers
            .iter()
            .find(|sh| self.shstrtab_entry(sh.name) == name.as_ref())
    }

    /// Returns an entry from a string table contained in the section with a given name
    fn string_table_entry<N>(&self, name: N, offset: Addr) -> &[u8]
    where
        N: AsRef<[u8]>,
    {
        self.section_by_name(name)
            .map(|section| {
                let slice = &self.section_slice(section)[offset.into()..];
                slice.split(|&c| c == 0).next().unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Returns a null-terminated "string" from the ".strtab" section as an u8 slice
    pub fn strtab_entry(&self, offset: Addr) -> &[u8] {
        self.string_table_entry(b".strtab", offset)
    }

    /// Returns a null-terminated "string" from the ".dynstr" section as an u8 slice
    pub fn dynstr_entry(&self, offset: Addr) -> &[u8] {
        self.string_table_entry(b".dynstr", offset)
    }
}

impl<I> std::ops::Deref for File<I>
where
    I: AsRef<[u8]>,
{
    type Target = FileContents;
    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

/// The type of parsed ELF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
    None = 0x0,
    Rel = 0x1,
    Exec = 0x2,
    Dyn = 0x3,
    Core = 0x4,
}

impl_parse_for_enum!(Type, le_u16);

/// The machine architecture that the ELF file is compiled for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

impl_parse_for_enum!(Machine, le_u16);

/// The type of a program memory segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
#[allow(clippy::upper_case_acronyms)]
pub enum SegmentType {
    Null = 0x0,
    Load = 0x1,
    Dynamic = 0x2,
    Interp = 0x3,
    Note = 0x4,
    ShLib = 0x5,
    PHdr = 0x6,
    TLS = 0x7,
    LoOS = 0x6000_0000,
    HiOS = 0x6FFF_FFFF,
    LoProc = 0x7000_0000,
    HiProc = 0x7FFF_FFFF,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelRo = 0x6474_E552,
    GnuProperty = 0x6474_E553,
}

impl_parse_for_enum!(SegmentType, le_u32);

/// The permissions set on a program memory segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BitFlags)]
#[repr(u32)]
pub enum SegmentFlag {
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
}

impl_parse_for_enumflags!(SegmentFlag, le_u32);

/// An ELF program header. A program can have many of these headers.
pub struct ProgramHeader {
    pub typ: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: Addr,
    pub memsz: Addr,
    pub align: Addr,
    pub contents: SegmentContents,
}

impl ProgramHeader {
    /// Range where the segment is stored in the file.
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.filesz
    }

    /// Memory range where the segment is mapped.
    pub fn mem_range(&self) -> Range<Addr> {
        self.vaddr..self.vaddr + self.memsz
    }

    fn parse<'a>(full_input: parse::Input<'a>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        use nom::{
            combinator::{map, verify},
            multi::many_till,
            sequence::tuple,
        };

        let (i, (typ, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;

        let (i, (offset, vaddr, paddr, filesz, memsz, align)) = tuple((
            Addr::parse,
            Addr::parse,
            Addr::parse,
            Addr::parse,
            Addr::parse,
            Addr::parse,
        ))(i)?;

        let slice = &full_input[offset.into()..][..filesz.into()];
        let (_, contents) = match typ {
            SegmentType::Dynamic => map(
                many_till(
                    DynamicEntry::parse,
                    verify(DynamicEntry::parse, |e| e.tag == DynamicTag::Null),
                ),
                |(entries, _last)| SegmentContents::Dynamic(entries),
            )(slice)?,

            _ => (slice, SegmentContents::Unknown),
        };

        Ok((
            i,
            Self {
                typ,
                flags,
                offset,
                vaddr,
                paddr,
                filesz,
                memsz,
                align,
                contents,
            },
        ))
    }
}

impl fmt::Debug for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file {:?} | mem {:?} | align {:?} | {} {:?}",
            self.file_range(),
            self.mem_range(),
            self.align,
            &[
                (SegmentFlag::Read, "R"),
                (SegmentFlag::Write, "W"),
                (SegmentFlag::Execute, "X"),
            ]
            .iter()
            .map(|&(flag, letter)| {
                if self.flags.contains(flag) {
                    letter
                } else {
                    "."
                }
            })
            .collect::<Vec<_>>()
            .join(""),
            self.typ,
        )
    }
}

/// An ELF section header, which defines various attributes of and important
/// addresses within a section.
#[derive(Debug)]
pub struct SectionHeader {
    /// An offset into the dynamic string table for the section's name.
    pub name: Addr,
    pub typ: SectionType,
    pub flags: u64,
    pub addr: Addr,
    pub offset: Addr,
    pub size: Addr,
    pub link: u32,
    pub info: u32,
    pub addralign: Addr,
    pub entsize: Addr,
}

impl SectionHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            combinator::map,
            number::complete::{le_u32, le_u64},
            sequence::tuple,
        };

        let (i, (name, typ, flags, addr, offset, size, link, info, addralign, entsize)) =
            tuple((
                map(le_u32, |x| Addr(x as u64)),
                SectionType::parse,
                le_u64,
                Addr::parse,
                Addr::parse,
                Addr::parse,
                le_u32,
                le_u32,
                Addr::parse,
                Addr::parse,
            ))(i)?;

        Ok((
            i,
            Self {
                name,
                typ,
                flags,
                addr,
                offset,
                size,
                link,
                info,
                addralign,
                entsize,
            },
        ))
    }

    /// File range where the section is stored.
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.size
    }

    /// Memory range where the section is mapped.
    pub fn mem_range(&self) -> Range<Addr> {
        self.addr..self.addr + self.size
    }
}

/// The type of the ELF section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SectionType {
    Null = 0,
    ProgBits = 1,
    SymTab = 2,
    StrTab = 3,
    Rela = 4,
    Hash = 5,
    Dynamic = 6,
    Note = 7,
    NoBits = 8,
    Rel = 9,
    ShLib = 10,
    DynSym = 11,
    InitArray = 14,
    FiniArray = 15,
    PreinitArray = 16,
    Group = 17,
    SymTabShndx = 18,
    Num = 19,
    GnuAttributes = 0x6ffffff5,
    GnuHash = 0x6ffffff6,
    GnuLiblist = 0x6ffffff7,
    Checksum = 0x6ffffff8,
    GnuVerdef = 0x6ffffffd,
    GnuVerneed = 0x6ffffffe,
    GnuVersym = 0x6fffffff,
    X8664Unwind = 0x70000001,
}

impl_parse_for_enum!(SectionType, le_u32);

/// The contents of an ELF segment.
pub enum SegmentContents {
    Dynamic(Vec<DynamicEntry>),
    Unknown,
}

/// A `Dynamic` segment entry.
#[derive(Debug)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub addr: Addr,
}

impl DynamicEntry {
    fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::sequence::tuple;

        let (i, (tag, addr)) = tuple((DynamicTag::parse, Addr::parse))(i)?;
        Ok((i, Self { tag, addr }))
    }
}

/// A tag for a [`DynamicEntry`].
#[derive(Debug, TryFromPrimitive, PartialEq, Eq, Clone, Copy)]
#[repr(u64)]
#[allow(clippy::upper_case_acronyms)]
pub enum DynamicTag {
    Null = 0,
    Needed = 1,
    PltRelSz = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSz = 8,
    RelaEnt = 9,
    StrSz = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    RPath = 15,
    Symbolic = 16,
    Rel = 17,
    RelSz = 18,
    RelEnt = 19,
    PltRel = 20,
    Debug = 21,
    TextRel = 22,
    JmpRel = 23,
    BindNow = 24,
    InitArray = 25,
    FiniArray = 26,
    InitArraySz = 27,
    FiniArraySz = 28,
    RunPath = 0x1d,
    Flags = 0x1e,
    LoOs = 0x60000000,
    LoProc = 0x70000000,
    HiProc = 0x7fffffff,
    GnuHash = 0x6ffffef5,
    VerSym = 0x6ffffff0,
    RelaCount = 0x6ffffff9,
    Flags1 = 0x6ffffffb,
    VerDef = 0x6ffffffc,
    VerDefNum = 0x6ffffffd,
    VerNeed = 0x6ffffffe,
    VerNeedNum = 0x6fffffff,
}

impl_parse_for_enum!(DynamicTag, le_u64);

/// An ELF relocation descriptor.
#[derive(Debug)]
pub struct Rela {
    /// Address of reference
    pub offset: Addr,
    /// Relocation type
    pub typ: RelType,
    /// Symbol type
    pub sym: u32,
    /// Constant part of expression
    pub addend: Addr,
}

impl Rela {
    pub const SIZE: usize = 24;

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{combinator::map, number::complete::le_u32, sequence::tuple};

        map(
            tuple((Addr::parse, RelType::parse, le_u32, Addr::parse)),
            |(offset, typ, sym, addend)| Self {
                offset,
                typ,
                sym,
                addend,
            },
        )(i)
    }
}

/// The possible relocation types.
///
/// ## Calculations
///
/// - __`A`__ represents the addend used to compute the value of the relocatable field.
/// - __`B`__ represents the base address at which a shared object has been loaded
///   into memory during execution.
/// - __`G`__ represents the offset into the global offset table at which the
///   relocation entry's symbol will reside during execution.
/// - __`GOT`__ represents the address of the global offset table.
/// - __`L`__ represents the place (section offset or address) of the Procedure
///   Linkage Table entry for a symbol.
/// - __`P`__ represents the place (section offset or address) of the storage
///   unit being relocated.
/// - __`S`__ represents the value of the symbol whose index resides in the
///   relocation entry.
/// - __`Z`__ represents the size of the symbol whose index resides in the
///   relocation entry.
#[derive(Debug, TryFromPrimitive, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RelType {
    /// Calculation: none
    None = 0,
    /// Calculation: `S + A`
    _64 = 1,
    /// Calculation: `S + A - P`
    Pc32 = 2,
    /// Calculation: `G + A`
    Got32 = 3,
    /// Calculation: `L + A - P`
    Plt32 = 4,
    /// Calculation: none
    Copy = 5,
    /// Calculation: `S`
    GlobDat = 6,
    /// Calculation: `S`
    JumpSlot = 7,
    /// Calculation: `B + A`
    Relative = 8,
    /// Calculation: `G + GOT + A - P`
    GotPcRel = 9,
    /// Calculation: `S + A`
    _32 = 10,
    /// Calculation: `S + A`
    _32S = 11,
    /// Calculation: `S + A`
    _16 = 12,
    /// Calculation: `S + A - P`
    Pc16 = 13,
    /// Calculation: `S + A`
    _8 = 14,
    /// Calculation: `S + A - P`
    Pc8 = 15,
    DtpMod64 = 16,
    DtpOff64 = 17,
    TpOff64 = 18,
    TlsGd = 19,
    TlsLd = 20,
    DtpOff32 = 21,
    GotTpOff = 22,
    TpOff32 = 23,
    /// Calculation: `S + A - P`
    Pc64 = 24,
    /// Calculation: `S + A - GOT`
    GotOff64 = 25,
    /// Calculation: `GOT + A - GOT`
    GotPc32 = 26,
    /// Calculation: `Z + A`
    Size32 = 32,
    /// Calculation: `Z + A`
    Size64 = 33,
    GotPc32TlsDesc = 34,
    TlsDescCall = 35,
    TlsDesc = 36,
    /// Calculation: `indirect (B + A)`
    IRelative = 37,
}

impl_parse_for_enum!(RelType, le_u32);

/// An ELF symbol.
#[derive(Debug, Clone, Copy)]
pub struct Sym {
    /// An offset into the dynamic string table giving the symbol's name.
    pub name: Addr,
    /// The symbol's binding attributes. A 4-bit value.
    pub bind: SymBind,
    /// The symbol's type. A 4-bit value.
    pub typ: SymType,
    /// The section of the file in which the symbol is defined.
    pub shndx: SectionIndex,
    /// The address of the symbol. For defined symbols, this corresponds to the
    /// virtual memory (i.e. where it's mapped once the executable is loaded and
    /// adjusted for base address).
    pub value: Addr,
    /// The size of the symbol. For variables, this is the size of the variable.
    /// For functions, this is the size of all of the function's instructions.
    pub size: u64,
}

impl Sym {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            bits::bits,
            combinator::map,
            number::complete::{le_u16, le_u32, le_u64, le_u8},
            sequence::tuple,
        };

        let (i, (name, (bind, typ), _reserved, shndx, value, size)) = tuple((
            map(le_u32, |x| Addr(x as u64)),
            bits(tuple((SymBind::parse, SymType::parse))),
            le_u8,
            map(le_u16, SectionIndex),
            Addr::parse,
            le_u64,
        ))(i)?;

        Ok((
            i,
            Self {
                name,
                bind,
                typ,
                shndx,
                value,
                size,
            },
        ))
    }
}

/// The possible symbol binding attributes. Each value is 4 bits.
#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymBind {
    Local = 0,
    Global = 1,
    Weak = 2,
}

impl_parse_for_bitenum!(SymBind, 4_usize);

/// The possible symbol types. Each value is 4 bits.
#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymType {
    None = 0,
    Object = 1,
    Func = 2,
    Section = 3,
    File = 4,
    TLS = 6,
    IFunc = 10,
}

impl_parse_for_bitenum!(SymType, 4_usize);

/// A section index, primarily used for ELF symbols.
#[derive(Clone, Copy)]
pub struct SectionIndex(pub u16);

impl SectionIndex {
    pub fn is_undef(&self) -> bool {
        self.0 == 0
    }

    pub fn is_special(&self) -> bool {
        self.0 >= 0xff00
    }

    pub fn get(&self) -> Option<usize> {
        if self.is_undef() || self.is_special() {
            None
        } else {
            Some(self.0 as usize)
        }
    }
}

impl fmt::Debug for SectionIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_special() {
            write!(f, "Special({:04x})", self.0)
        } else if self.is_undef() {
            write!(f, "Undef")
        } else {
            write!(f, "{:?}", self.0)
        }
    }
}

/// Wraps a `u64` memory address, and adds some nice, automatic `Display` and
/// `Debug` formats. Also adds a nice method for parsing `u64` memory addresses
/// from a buffer of `u8`'s using `nom`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub, Hash)]
pub struct Addr(pub u64);

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{combinator::map, number::complete::le_u64};
        map(le_u64, From::from)(i)
    }

    /// Convert into an actual pointer to a spot in memory.
    ///
    /// # Safety
    /// This can create dangling pointers and all sorts of eldritch horrors.
    pub fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    /// Convert into a *mutable* pointer to a spot in memory.
    ///
    /// # Safety
    /// Mutable pointers are a wonderful way to create unspeakable mistakes.
    /// Programs that will segfault, but only on random Thursdays. I hope you
    /// enjoy gdb and nasm.
    ///
    /// Viewer discretion strongly advised.
    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    /// Convert to a slice over a spot in memory.
    ///
    /// # Safety
    /// You're trying to access memory that Rust has minimal control over and/or
    /// guarantees about. Bloody anarachist.
    pub unsafe fn as_slice<T>(&self, len: usize) -> &[T] {
        std::slice::from_raw_parts(self.as_ptr(), len)
    }

    /// Convert to a *mutable* slice over a spot in memory.
    ///
    /// # Safety
    /// Ah, I see. Not only do you want to come into my house, take all my stuff,
    /// *most* of which you don't even know what it is, and then change it?
    /// Pscychopath.
    pub unsafe fn as_mut_slice<T>(&mut self, len: usize) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }

    /// Write a completely arbritrary set of bytes to a completely arbritrary
    /// spot in memory. The source and destination must not overlap.
    ///
    /// # Safety
    /// If it isn't obvious to you why this is unsafe, go suck on an egg.
    pub unsafe fn write(&self, src: &[u8]) {
        std::ptr::copy_nonoverlapping(src.as_ptr(), self.as_mut_ptr(), src.len());
    }

    /// Write anything at all to any memory address.
    ///
    /// # Safety
    /// <sub>mummy make the bad man go away pls</sub>
    pub unsafe fn set<T>(&self, src: T) {
        *self.as_mut_ptr() = src;
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Useful for parsing.
impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

/// Useful for serialization.
#[allow(clippy::from_over_into)]
impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0
    }
}

/// Useful for indexing / sub-slicing slices.
#[allow(clippy::from_over_into)]
impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

/// Wraps byte buffers so they can be formatted with [`std::fmt::Debug`].
pub struct HexDump<'a>(&'a [u8]);

impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x} ", x)?;
        }

        Ok(())
    }
}

/// For when `nom` encountered some error while parsing an ELF file. Allows access
/// to the underlying [`nom::error::VerboseError`], and provides a method for
/// nicely printing out the error.
#[derive(Debug)]
pub struct FileParseError(String);

impl FileParseError {
    fn new(original_input: parse::Input, nom_err: parse::Error<parse::Input>) -> Self {
        use nom::Offset;

        let mut out = vec!["Parsing failed:".to_string()];

        for (input, err) in nom_err.errors {
            let offset = original_input.offset(input);

            out.push(format!(
                "\t{0:?} at position {1}:\n\t\t{1:>08x}: {2:?}",
                err,
                offset,
                HexDump(input)
            ));
        }

        Self(out.join("\n"))
    }
}

impl fmt::Display for FileParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.0)
    }
}

impl std::error::Error for FileParseError {}

/// Errors that may occur when reading an ELF `Rela`.
#[derive(thiserror::Error, Debug)]
pub enum ReadRelaError {
    #[error("{0}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),
    #[error("Rela segment not found")]
    RelaSegmentNotFound,
    #[error("Parsing error")]
    ParsingError(String),
}

/// Errors that may occur when trying to access the global string table.
#[derive(thiserror::Error, Debug)]
pub enum GetStringError {
    #[error("StrTab dynamic entry not found")]
    StrTabNotFound,
    #[error("StrTab segment not found")]
    StrTabSegmentNotFound,
    #[error("String not found")]
    StringNotFound,
}

/// Errors that may occur when reading symbols.
#[derive(thiserror::Error, Debug)]
pub enum ReadSymsError {
    #[error("{0:?}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),
    #[error("SymTab section not found")]
    SymTabSectionNotFound,
    #[error("SymTab segment not found")]
    SymTabSegmentNotFound,
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

/// Errors that may occur when getting dynamic table entries.
#[derive(thiserror::Error, Debug)]
pub enum GetDynamicEntryError {
    #[error("Dynamic entry {0:?} not found.")]
    NotFound(DynamicTag),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn try_enums() {
        assert_eq!(Type::Dyn as u16, 0x3);
        assert_eq!(Type::try_from(0x1), Ok(Type::Rel));
        assert_eq!(Type::try_from(0x5), Err(0x5));

        assert_eq!(Machine::X86_64 as u16, 0x3E);
        assert_eq!(Machine::try_from(0x3E), Ok(Machine::X86_64));
        assert_eq!(Machine::try_from(0xFA), Err(0xFA));
    }

    #[test]
    fn try_bitflags() {
        let flags_integer = 6_u32;

        let flags = BitFlags::<SegmentFlag>::from_bits(flags_integer).unwrap();
        assert_eq!(flags, SegmentFlag::Read | SegmentFlag::Write);
        assert_eq!(flags.bits(), flags_integer);

        assert!(BitFlags::<SegmentFlag>::from_bits(1992).is_err());
    }
}
