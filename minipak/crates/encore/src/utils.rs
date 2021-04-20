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
