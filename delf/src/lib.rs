//! # `delf` - Demystify ELF

mod parse;

use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;
use std::{convert::TryFrom, fmt};

/// Fields parsed from a 64-bit, little-endian ELF file.
#[derive(Debug)]
pub struct File {
    pub typ: Type,
    pub machine: Machine,
    pub entry_point: Addr,
}

impl File {
    /// Magic bytes expected to be found at the beginning of an ELF file.
    /// `0x7c`, `'E'`, `'L'`, `'F'`.
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    /// Parse an ELF file from a buffer of bytes.
    fn try_parse_from(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            bytes::complete::{tag, take},
            combinator::verify,
            error::context,
            number::complete::le_u32,
            sequence::tuple,
        };

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

        Ok((
            i,
            Self {
                typ,
                machine,
                entry_point,
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
}
