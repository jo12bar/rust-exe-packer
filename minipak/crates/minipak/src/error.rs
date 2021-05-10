use encore::prelude::*;
use pixie::{deku::DekuError, PixieError};

/// A combination of all the errors that `minipak` might encounter.
#[derive(displaydoc::Display, Debug)]
pub enum Error {
    /// `{0}`
    Encore(EncoreError),
    /// deku error: `{0}`
    Deku(DekuError),
    /// pixie error: `{0}`
    Pixie(PixieError),
}

impl From<EncoreError> for Error {
    fn from(e: EncoreError) -> Self {
        Self::Encore(e)
    }
}

impl From<DekuError> for Error {
    fn from(e: DekuError) -> Self {
        Self::Deku(e)
    }
}

impl From<PixieError> for Error {
    fn from(e: PixieError) -> Self {
        Self::Pixie(e)
    }
}
