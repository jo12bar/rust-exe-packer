use crate::PixieError;
use alloc::{format, vec::Vec};
use core::ops::Range;
use deku::prelude::*;

/// The Pixie manifest.
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(magic = b"piximani")]
pub struct Manifest {
    pub stage2: Resource,
    pub guest: Resource,
}

impl Manifest {
    pub fn read_from_full_slice(slice: &[u8]) -> Result<Self, PixieError> {
        let (_, endmarker) = EndMarker::from_bytes((&slice[slice.len() - 16..], 0))?;

        let (_, manifest) = Manifest::from_bytes((&slice[endmarker.manifest_offset..], 0))?;
        Ok(manifest)
    }
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(magic = b"pixiendm")]
pub struct EndMarker {
    #[deku(bytes = 8)]
    pub manifest_offset: usize,
}

#[derive(Debug, DekuRead, DekuWrite)]
pub struct Resource {
    #[deku(bytes = 8)]
    pub offset: usize,
    #[deku(bytes = 8)]
    pub len: usize,
}

impl Resource {
    pub fn as_range(&self) -> Range<usize> {
        self.offset..self.offset + self.len
    }
}
