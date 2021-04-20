use crate::memmap::MmapOptions;
use linked_list_allocator::LockedHeap;

/// Panic handler. Just aborts entirely.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::println!("{}", info);
    core::intrinsics::abort();
}

/// Exception-handling personality. Doesn't actually do anything at the moment.
#[lang = "eh_personality"]
fn eh_personality() {}

/// Provides memset, memcpy
extern crate rlibc;

/// Used by parts of libcore that aren't panic=abort.
#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn _Unwind_Resume() {}

/// Provides bcmp (aliased below)
extern crate compiler_builtins;

#[no_mangle]
unsafe extern "C" fn bcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    compiler_builtins::mem::bcmp(s1, s2, n)
}

// Set a global allocator
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Heap size, in megabytes
const HEAP_SIZE_MB: u64 = 128;

/// Initialize a global allocator that only uses `mmap`, with a fixed heap size.
///
/// # Safety
/// Calling this too late (or not at all) and doing a heap allocation will fail.
/// The `mmap` syscall can also fail, which would be disastrous.
pub unsafe fn init_allocator() {
    let heap_size = HEAP_SIZE_MB * 1024 * 1024;
    let heap_bottom = MmapOptions::new(heap_size).map().unwrap();
    ALLOCATOR.lock().init(heap_bottom as _, heap_size as _);
}
