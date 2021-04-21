use crate::syscall;

/// Launch a program by jumping to it's entry point.
///
/// # Safety
/// nothing about this is safe
#[inline(never)]
pub unsafe fn launch(stack_top: *mut u8, entry_point: u64) -> ! {
    // Handy for breakpoints
    syscall::dup(0);

    asm!(
        //////////////////////////////////
        //// Clear some of the stack. ////
        //////////////////////////////////

        // Use rsi as a counter
        "mov rsi, r12",
        "sub rsi, 0x1000",
        // Loop label:
        "$clear_stack:",
            "cmp rsi, r12",
            // If we reach rdi, we're done.
            "je $clear_stack_done",
            // Otherwise, clear 8 bytes at once.
            "mov qword ptr [rsi], 0",
            // Then add 8 bytes to the counter.
            "add rsi, 0x8",
            // Otherwise, loop.
            "jmp $clear_stack",

        "$clear_stack_done:",

        ///////////////////////////////////
        //// Set up the stack pointer. ////
        ///////////////////////////////////
        "mov rsp, r12",


        //////////////////////////////////
        //// Jump to the entry point. ////
        //////////////////////////////////

        // Clear everything that isn't r13, like the kernel does.
        // (see https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/elf.h#L170)
        "xor bx, bx",
        "xor cx, cx",
        "xor dx, dx",
        "xor si, si",
        "xor di, di",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "xor r12, r12",
        // skip r13, we have the entry point in there
        "xor r14, r14",
        "xor r15, r15",

        // Now we can actually jump to the entry point.
        "jmp r13",

        in("r12") stack_top,
        in("r13") entry_point,
        options(noreturn)
    )
}
