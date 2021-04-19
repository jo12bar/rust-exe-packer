// gcc -nostartfiles -nodefaultlibs hello-nolibc.c -o hello-nolibc

/**
 * This mimics libc's `exit` function, but has a different name, because *even*
 * with -nostartfiles and -nodefaultlibs, and no #include directives, GCC will
 * complain that `exit`, which is declared *somewhere* as "noreturn", does in
 * fact return.
 */
void ftl_exit(int code) {
    __asm__(
        " \
        mov     %[code], %%edi \n\t\
        mov     $60, %%rax \n\t\
        syscall"
        : // no outputs
        : [code] "r" (code)
    );
}

void ftl_print(char *msg) {
    // Little ad-hoc `strlen()`:
    int len = 0;
    while (msg[len]) {
        len++;
    }

    __asm__(
        " \
        mov     $1, %%rdi \n\t\
        mov     %[msg], %%rsi \n\t\
        mov     %[len], %%edx \n\t\
        mov     $1, %%rax \n\t\
        syscall"
        : // no outputs
        : [msg] "r" (msg), [len] "r" (len)
    );
}

int main() {
    ftl_print("Hello from C!\n");
    return 0;
}

void _start() {
    ftl_exit(main());
}
