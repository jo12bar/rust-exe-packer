//! # `delf` - Demystify ELF

mod parse;

use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::*;
use std::{convert::TryFrom, fmt, ops::Range};

/// Fields parsed from a 64-bit, little-endian ELF file.
#[derive(Debug)]
pub struct File {
    pub typ: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
}

impl File {
    /// Magic bytes expected to be found at the beginning of an ELF file.
    /// `0x7c`, `'E'`, `'L'`, `'F'`.
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    /// Parse an ELF file from a buffer of bytes.
    fn try_parse_from(i: parse::Input) -> parse::Result<Self> {
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
        let (i, (ph_offset, _sh_offset)) = tuple((Addr::parse, Addr::parse))(i)?;
        let (i, (_flags, _hdr_size)) = tuple((le_u32, le_u16))(i)?;
        let (i, (ph_entsize, ph_count)) = tuple((&u16_usize, &u16_usize))(i)?;
        let (i, (_sh_entsize, _sh_count, _sh_nidx)) =
            tuple((&u16_usize, &u16_usize, &u16_usize))(i)?;

        let ph_slices = (&full_input[ph_offset.into()..]).chunks(ph_entsize);
        let mut program_headers = Vec::with_capacity(ph_count);

        for ph_slice in ph_slices.take(ph_count) {
            let (_, ph) = ProgramHeader::parse(full_input, ph_slice)?;
            program_headers.push(ph);
        }

        Ok((
            i,
            Self {
                typ,
                machine,
                entry_point,
                program_headers,
            },
        ))
    }

    /// Parse an ELF file from a buffer of bytes.
    pub fn parse(i: parse::Input) -> Result<Self, FileParseError> {
        match Self::try_parse_from(i) {
            Ok((_, file)) => Ok(file),

            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(FileParseError::new(i, err))
            }

            Err(_) => panic!("Unexpected nom error"),
        }
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
    pub data: Vec<u8>,
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

    fn parse<'a>(full_input: parse::Input<'_>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        use nom::sequence::tuple;

        let (i, (typ, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;

        let (i, (offset, vaddr, paddr, filesz, memsz, align)) = tuple((
            Addr::parse,
            Addr::parse,
            Addr::parse,
            Addr::parse,
            Addr::parse,
            Addr::parse,
        ))(i)?;

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
                // `to_vec()` turns a slice into an owned Vec (which works because
                // u8 is Clone + Copy).
                data: full_input[offset.into()..][..filesz.into()].to_vec(),
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

/// Wraps a `u64` memory address, and adds some nice, automatic `Display` and
/// `Debug` formats. Also adds a nice method for parsing `u64` memory addresses
/// from a buffer of `u8`'s using `nom`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{combinator::map, number::complete::le_u64};
        map(le_u64, From::from)(i)
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.0)
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
    fn new(original_input: parse::Input, nom_err: nom::error::VerboseError<parse::Input>) -> Self {
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
