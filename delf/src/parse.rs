//! Utilities for parsing little-endian, 64-bit ELF files via [`nom`].

/// We expect to recieve a buffer of bytes as our input to our parsers.
pub type Input<'a> = &'a [u8];

/// We want to make `nom` output verbose errors whenever possible. So, for
/// convenience, we define our own result type. `O` is the parsed output type.
pub type Result<'a, O> = nom::IResult<Input<'a>, O, nom::error::VerboseError<Input<'a>>>;

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
                pub fn parse(i: $crate::parse::Input) -> $crate::parse::Result<Self> {
                    use nom::{
                        combinator::map_res,
                        error::{context, ErrorKind},
                        number::complete::$number_parser,
                    };

                    let parser = map_res($number_parser, |x| {
                        Self::try_from(x).map_err(|_| ErrorKind::Alt)
                    });

                    context(stringify!($type), parser)(i)
                }
            }
        }
    };
}
