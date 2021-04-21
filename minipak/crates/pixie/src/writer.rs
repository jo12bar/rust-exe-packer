use crate::PixieError;
use core::cmp::min;
use deku::DekuContainerWrite;
use encore::prelude::*;

const PAD_BUF: [u8; 1024] = [0u8; 1024];

/// Writes to a file, maintaining a current offset.
pub struct Writer {
    pub file: File,
    pub offset: u64,
}

impl Writer {
    pub fn new(path: &str, mode: u64) -> Result<Self, PixieError> {
        let file = File::create(path, mode)?;
        Ok(Self { file, offset: 0 })
    }

    /// Writes an entire buffer.
    pub fn write_all(&mut self, buf: &[u8]) -> Result<(), PixieError> {
        self.file.write_all(buf)?;
        self.offset += buf.len() as u64;
        Ok(())
    }

    /// Writes `n` bytes of padding.
    pub fn pad(&mut self, mut n: u64) -> Result<(), PixieError> {
        while n > 0 {
            let m = min(n, 1024);
            n -= m;
            self.write_all(&PAD_BUF[..m as _])?;
        }

        Ok(())
    }

    /// Aligns to `n` bytes.
    pub fn align(&mut self, n: u64) -> Result<(), PixieError> {
        let next_offset = ceil(self.offset, n);
        self.pad((next_offset - self.offset) as _)
    }

    /// Writes a Deku container.
    pub fn write_deku<T>(&mut self, t: &T) -> Result<(), PixieError>
    where
        T: DekuContainerWrite,
    {
        self.write_all(&t.to_bytes()?)
    }

    /// Returns the current write offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

fn ceil(i: u64, n: u64) -> u64 {
    if i % n == 0 {
        i
    } else {
        (i + n) & !(n - 1)
    }
}
