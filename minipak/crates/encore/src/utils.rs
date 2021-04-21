use core::fmt;

/// A basic println shim.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {
        {
            use ::core::fmt::Write;
            ::core::writeln!($crate::utils::Stdout, $($arg)*).ok();
        }
    }
}

/// A basic print shim.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        {
            use ::core::fmt::Write;
            ::core::write!($crate::utils::Stdout, $($arg)*).ok();
        }
    }
}

/// A stdout device for `::core::writeln!` (and therefore `println!`) to write
/// to.
pub struct Stdout;
impl fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        unsafe {
            crate::syscall::write(
                crate::syscall::FileDescriptor::STDOUT,
                s.as_ptr(),
                s.len() as _,
            );
        }
        Ok(())
    }
}

/// A trait for null-terminated things, like C strings and null-terminated byte
/// slices.
pub trait NullTerminated
where
    Self: Sized,
{
    /// Turns a pointer into a byte slice, assuming it finds a null terminator.
    ///
    /// # Safety
    /// Dereferences an arbitrary pointer, and then reads memory until it finds
    /// a null terminator. If you aren't careful, this could end up reading
    /// garbage from memory or cause a segfault.
    unsafe fn null_terminated(self) -> &'static [u8];

    /// Turns self into a string. Will panic if [`NullTerminated::null_terminated`]
    /// does not return a valid UTF-8 string.
    ///
    /// # Safety
    /// Dereferences an arbritrary pointer. In general, this has the same safety
    /// concerns as [`NullTerminated::null_terminated`].
    unsafe fn cstr(self) -> &'static str {
        core::str::from_utf8(self.null_terminated()).unwrap()
    }
}

/// Allows us to read null-terminated byte sequences and strings from
/// arbritrary spots in memory.
impl NullTerminated for *const u8 {
    unsafe fn null_terminated(self) -> &'static [u8] {
        let mut j = 0;
        while *self.add(j) != 0 {
            j += 1;
        }
        core::slice::from_raw_parts(self, j)
    }
}
