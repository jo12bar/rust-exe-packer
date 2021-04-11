//! Utilities for parsing little-endian, 64-bit ELF files via [`nom`].

use nom::{ErrorConvert, Slice};
use std::{fmt, ops::RangeFrom};

/// Implements a parse method for an enum, allowing you to parse some number
/// value into an enum type.
///
/// The first argument, `$type`, should be the enum to implement `::parse()` on.
/// The enum should implement [`std::convert::TryFrom`] to convert from the
/// target numeric type to an enum value.
///
/// The second argument, `$number_parser`, should be the name of one of the
/// parser functions provided by `nom` in `nom::number::complete::{..}`.
///
/// For example, if you want to parse little-endian [`u16`] values to one of your
/// enum values, then pass in "`le_u16`" for `$number_parser`. The macro will
/// then parse a `u16` from a buffer of `u8` values using
/// [`nom::number::complete::le_u16`]. It will then convert to the enum value
/// using `std::convert::TryFrom`, assuming that `TryFrom<u16>` is implemented
/// for the enum.
#[macro_export]
macro_rules! impl_parse_for_enum {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            doc_comment::doc_comment! {
                concat!(
                    "Parse a number into a [`",
                    stringify!($type),
                    "`] using [`nom::number::complete::",
                    stringify!($number_parser),
                    "`].",
                ),
                pub fn parse(full_input: $crate::parse::Input) -> $crate::parse::Result<Self> {
                    use nom::number::complete::$number_parser;

                    let (i, val) = $number_parser(full_input)?;
                    match Self::try_from(val) {
                        Ok(val) => Ok((i, val)),
                        Err(_) => Err(nom::Err::Failure($crate::parse::Error::from_string(
                            full_input,
                            format!("Unknown {} {} (0x{:x})", stringify!($type), val, val),
                        ))),
                    }
                }
            }
        }
    };
}

/// Like [`impl_parse_for_enum`], but for enums that use the `enumflags2` `BitFlags`
/// proc macro.
#[macro_export]
macro_rules! impl_parse_for_enumflags {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            doc_comment::doc_comment! {
                concat!(
                    "Parse a bitflag-built number into a [`",
                    stringify!($type),
                    "`] using [`nom::number::complete::",
                    stringify!($number_parser),
                    "`].",
                ),
                pub fn parse(i: $crate::parse::Input) -> $crate::parse::Result<enumflags2::BitFlags<Self>> {
                    use nom::{
                        combinator::map_res,
                        error::{context, ErrorKind},
                        number::complete::$number_parser,
                    };

                    let parser = map_res($number_parser, |x| {
                        enumflags2::BitFlags::<Self>::from_bits(x).map_err(|_| ErrorKind::Alt)
                    });

                    context(stringify!($type), parser)(i)
                }
            }
        }
    }
}

#[macro_export]
macro_rules! impl_parse_for_bitenum {
    ($type: ident, $bits: expr) => {
        impl $type {
            pub fn parse(full_input: $crate::parse::BitInput) -> $crate::parse::BitResult<Self> {
                use nom::bits::complete::take;

                let (i, val): (_, u8) = take($bits)(full_input)?;
                match Self::try_from(val) {
                    Ok(val) => Ok((i, val)),
                    Err(_) => Err(nom::Err::Failure($crate::parse::Error::from_string(
                        full_input,
                        format!("Unknown {} {} (0x{:x})", stringify!($type), val, val),
                    ))),
                }
            }
        }
    };
}

/// The type of parsing error.
#[derive(Debug, Clone)]
pub enum ErrorKind {
    Nom(nom::error::ErrorKind),
    Context(&'static str),
    String(String),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nom(n) => fmt::Display::fmt(n.description(), f),
            Self::Context(c) => fmt::Display::fmt(c, f),
            Self::String(s) => fmt::Display::fmt(s, f),
        }
    }
}

/// A parsing error.
pub struct Error<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl<I> Error<I> {
    pub fn from_string<S: Into<String>>(input: I, s: S) -> Self {
        let errors = vec![(input, ErrorKind::String(s.into()))];
        Self { errors }
    }
}

impl<I> nom::error::ParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }

    fn append(input: I, kind: nom::error::ErrorKind, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Nom(kind)));
        other
    }

    fn add_context(input: I, ctx: &'static str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx)));
        other
    }
}

impl<I> ErrorConvert<Error<I>> for Error<(I, usize)>
where
    I: Slice<RangeFrom<usize>>,
{
    fn convert(self) -> Error<I> {
        let errors = self
            .errors
            .into_iter()
            .map(|((rest, offset), err)| (rest.slice(offset / 8..), err))
            .collect();

        Error { errors }
    }
}

impl fmt::Debug for Error<&[u8]> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (input, err) in &self.errors {
            writeln!(f, "{:?}:", err)?;
            writeln!(f, "\t└──> input: {:?}", crate::HexDump(input))?;
        }

        Ok(())
    }
}

impl fmt::Display for Error<&[u8]> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (input, err) in &self.errors {
            writeln!(f, "{}:", err)?;
            writeln!(f, "\t└──> input: {:?}", crate::HexDump(input))?;
        }

        Ok(())
    }
}

/// We expect to recieve a buffer of bytes as our input to our parsers.
pub type Input<'a> = &'a [u8];

/// We want to be consistent with our parsing error type throughout this library.
/// So, we define a custom result type that we should return everywhere.
pub type Result<'a, O> = nom::IResult<Input<'a>, O, Error<Input<'a>>>;

/// If we're expecting a buffer of bits, use this type for input.
pub type BitInput<'a> = (&'a [u8], usize);

/// If we're expecting a buffer of bits, use this type for output.
pub type BitResult<'a, O> = nom::IResult<BitInput<'a>, O, Error<BitInput<'a>>>;
