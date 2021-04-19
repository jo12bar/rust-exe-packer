use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while1},
    combinator::{all_consuming, map, opt, value},
    error::ParseError,
    multi::many0,
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult, InputTakeAtPosition,
};
use std::fmt;

/// Returns true if a character is a (lower-case) hexadecimal digit
pub fn is_hex_digit(c: char) -> bool {
    ('0'..='9').contains(&c) || ('a'..='f').contains(&c)
}

/// Parses 0 or more spaces and tabs.
fn whitespace<I, E>(i: I) -> IResult<I, I, E>
where
    I: InputTakeAtPosition<Item = char>,
    E: ParseError<I>,
{
    take_while(|c| " \t".contains(c))(i)
}

/// Execute and return the child parser's result, ignoring leading and trailing
/// spaces and tabs.
fn spaced<I, O, E>(f: impl Fn(I) -> IResult<I, O, E>) -> impl Fn(I) -> IResult<I, O, E>
where
    I: InputTakeAtPosition<Item = char> + Clone + PartialEq,
    E: ParseError<I>,
{
    preceded(whitespace, terminated(f, whitespace))
}

/// Parses a lower-case hexadecimal number as a [`delf::Addr`].
fn hex_addr(i: &str) -> IResult<&str, delf::Addr> {
    // Use `take_while1` to require at least one character:
    let (i, num) = take_while1(is_hex_digit)(i)?;

    // FIXME: Reckless use of expect.
    let u = u64::from_str_radix(num, 16).expect("Our hex parser is wrong.");
    Ok((i, u.into()))
}

/// Parses a [`delf::Addr`] range in the form `0000-FFFF`.
fn hex_addr_range(i: &str) -> IResult<&str, std::ops::Range<delf::Addr>> {
    let (i, (start, end)) = separated_pair(hex_addr, tag("-"), hex_addr)(i)?;
    Ok((i, start..end))
}

/// Memory mapping permission bits.
pub struct Perms {
    // Readable
    pub r: bool,
    /// Writable
    pub w: bool,
    /// Executable
    pub x: bool,
    /// True for private (copy-on-write), false for shared
    pub p: bool,
}

impl fmt::Debug for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bit = |val, display| {
            if val {
                display
            } else {
                '-'
            }
        };

        write!(
            f,
            "{}{}{}{}",
            bit(self.r, 'r'),
            bit(self.w, 'w'),
            bit(self.x, 'x'),
            if self.p { 'p' } else { 's' },
        )
    }
}

/// Parses a single permission bit. For example, the readable bit can be either
/// "r" or "-", and the private bit can either be "p" or "s".
fn bit(on: &'static str, off: &'static str) -> impl Fn(&str) -> IResult<&str, bool> {
    move |i: &str| -> IResult<&str, bool> { alt((value(false, tag(off)), value(true, tag(on))))(i) }
}

/// Parses mapping permissions as seen in `/proc/:pid/maps`.
#[allow(clippy::many_single_char_names)]
fn perms(i: &str) -> IResult<&str, Perms> {
    let (i, (r, w, x, p)) = tuple((bit("r", "-"), bit("w", "-"), bit("x", "-"), bit("p", "s")))(i)?;
    Ok((i, Perms { r, w, x, p }))
}

/// Parses a decimal number as an [`u64`].
fn dec_number(i: &str) -> IResult<&str, u64> {
    let (i, s) = take_while1(|c| ('0'..='9').contains(&c))(i)?;

    // FIXME: reckless use of expect.
    let num: u64 = s.parse().expect("Our decimal parser is wrong.");
    Ok((i, num))
}

/// A Linux device number.
pub struct Dev {
    pub major: u64,
    pub minor: u64,
}

impl fmt::Debug for Dev {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

/// Parses a Linux device number in form `major:minor`, where major and minor
/// are decimal numbers.
fn dev(i: &str) -> IResult<&str, Dev> {
    let (i, (major, minor)) = separated_pair(dec_number, tag(":"), dec_number)(i)?;
    Ok((i, Dev { major, minor }))
}

/// Source for a mapping. Could be
///
/// - special (stack, vdso, etc.),
/// - a file, or
/// - an anonymous mapping.
#[derive(Debug)]
pub enum Source<'a> {
    /// Not backed by a file.
    Anonymous,
    /// Not backed by a file, *and* special-purpose.
    Special(&'a str),
    /// Backed by a file.
    File(&'a str),
}

impl Source<'_> {
    /// Returns true if the mapping source is backed by a file.
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }
}

/// Parse the source of a mapping.
fn source(i: &str) -> IResult<&str, Source<'_>> {
    /// FIXME: Make this work with paths that contain spaces!
    fn is_path_character(c: char) -> bool {
        c != ']' && !c.is_whitespace()
    }

    /// Parse a path.
    fn path(i: &str) -> IResult<&str, &str> {
        take_while(is_path_character)(i)
    }

    alt((
        map(delimited(tag("["), path, tag("]")), Source::Special),
        map(path, |s| {
            if s.is_empty() {
                Source::Anonymous
            } else {
                Source::File(s)
            }
        }),
    ))(i)
}

/// A memory mapping.
#[derive(Debug)]
pub struct Mapping<'a> {
    pub addr_range: std::ops::Range<delf::Addr>,
    pub perms: Perms,
    pub offset: delf::Addr,
    pub dev: Dev,
    pub len: u64,
    pub source: Source<'a>,
    pub deleted: bool,
}

/// Parse a memory mapping.
fn mapping(i: &str) -> IResult<&str, Mapping> {
    let (i, (addr_range, perms, offset, dev, len, source, deleted)) = tuple((
        spaced(hex_addr_range),
        spaced(perms),
        spaced(hex_addr),
        spaced(dev),
        spaced(dec_number),
        spaced(source),
        spaced(map(opt(tag("(deleted)")), |o| o.is_some())),
    ))(i)?;

    Ok((
        i,
        Mapping {
            addr_range,
            perms,
            offset,
            dev,
            len,
            source,
            deleted,
        },
    ))
}

/// Parse a set of newline-delimited memory mappings in the format found in
/// `/proc/:pid/maps`.
pub fn mappings(i: &str) -> IResult<&str, Vec<Mapping>> {
    all_consuming(many0(terminated(spaced(mapping), tag("\n"))))(i)
}
