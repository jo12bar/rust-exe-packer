pub(crate) use alloc::{format, vec::Vec};
pub(crate) use deku::{prelude::*, DekuContainerRead, DekuRead};
pub(crate) use derivative::*;

/// Format a field as lowercase hexadecimal, with the `0x` prefix.
pub fn hex_fmt<T>(t: &T, f: &mut core::fmt::Formatter) -> core::fmt::Result
where
    T: core::fmt::LowerHex,
{
    write!(f, "0x{:x}", t)
}
