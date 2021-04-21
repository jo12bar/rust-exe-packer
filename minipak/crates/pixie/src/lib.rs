#![no_std]

extern crate alloc;

mod manifest;
mod writer;

use deku::prelude::*;
use encore::prelude::*;
pub use manifest::*;
pub use writer::*;

/// Re-export [`deku`] for downstream crates.
pub use deku;

/// A pixie error.
#[derive(displaydoc::Display, Debug)]
pub enum PixieError {
    /// `{0}`
    Deku(DekuError),
    /// `{0}`
    Encore(EncoreError),
}

impl From<DekuError> for PixieError {
    fn from(e: DekuError) -> Self {
        Self::Deku(e)
    }
}

impl From<EncoreError> for PixieError {
    fn from(e: EncoreError) -> Self {
        Self::Encore(e)
    }
}
