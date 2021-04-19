pub const STDOUT_FILENO: u32 = 1;

/// Exit the program.
pub unsafe fn exit(code: i32) -> ! {
    let syscall_number = 60_u64;
    asm!(
        "syscall",
        in("rax") syscall_number,
        in("rdi") code,
        options(noreturn)
    );
}

/// Write to stdout.
pub unsafe fn write(fd: u32, buf: *const u8, count: usize) {
    let syscall_number: u64 = 1;
    asm!(
        "syscall",
        inout("rax") syscall_number => _,
        in("rdi") fd,
        in("rsi") buf,
        in("rdx") count,
        lateout("rcx") _,
        lateout("r11") _,
        // Linux syscalls don't touch the stack, so we don't care about its
        // alignment.
        options(nostack)
    );
}

/// Get the length of a null-terminated string in memory.
pub unsafe fn strlen(mut s: *const u8) -> usize {
    let mut count = 0;
    while *s != b'\0' {
        count += 1;
        s = s.add(1);
    }
    count
}

/// Print a string.
pub fn print_str(s: &[u8]) {
    unsafe {
        write(STDOUT_FILENO, s.as_ptr(), s.len());
    }
}

/// Print a number.
pub fn print_num(n: usize) {
    if n > 9 {
        print_num(n / 10);
    }

    let c = b'0' + (n % 10) as u8;
    print_str(&[c]);
}

/// Print a hexadecimal number.
pub fn print_hex(n: usize) {
    if n > 15 {
        print_hex(n / 16);
    }

    let u = (n % 16) as u8;
    let c = match u {
        0..=9 => b'0' + u,
        _ => b'a' + u - 10,
    };
    print_str(&[c]);
}

pub enum PrintArg<'a> {
    String(&'a [u8]),
    Number(usize),
    Hex(usize),
}

impl<'a> From<usize> for PrintArg<'a> {
    fn from(v: usize) -> Self {
        PrintArg::Number(v)
    }
}

impl<'a> From<&'a [u8]> for PrintArg<'a> {
    fn from(v: &'a [u8]) -> Self {
        PrintArg::String(v)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for PrintArg<'a> {
    fn from(v: &'a [u8; N]) -> Self {
        PrintArg::String(v.as_ref())
    }
}

/// Print out a `PrintArg` slice.
pub fn print(args: &[PrintArg]) {
    for arg in args {
        match arg {
            PrintArg::String(s) => print_str(s),
            PrintArg::Number(n) => print_num(*n),
            PrintArg::Hex(n) => {
                print_str(b"0x");
                print_hex(*n);
            }
        }
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:expr),+ $(,)?) => {
        $crate::support::print(&[
            $($arg.into()),+
        ]);
    };
}

#[macro_export]
macro_rules! println {
    ($($arg:expr),+ $(,)?) => {
        $crate::print!($($arg),+ , b"\n");
    };
}
