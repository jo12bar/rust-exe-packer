// gcc -nostartfiles -nodefaultlibs ifunc-nolibc.c -o ifunc-nolibc

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

int ftl_strlen(char *s) {
    int len = 0;
    while (s[len]) {
        len++;
    }
    return  len;
}

void ftl_print(char *msg) {
    __asm__(
        " \
        mov     $1, %%rdi \n\t\
        mov     %[msg], %%rsi \n\t\
        mov     %[len], %%edx \n\t\
        mov     $1, %%rax \n\t\
        syscall"
        : // no outputs
        : [msg] "r" (msg), [len] "r" (ftl_strlen(msg))
    );
}

/**
 * Implementation of `get_msg` for the root user
 */
char *get_msg_root() {
    return "Hello, root!\n";
}

/**
 * Implementation of `get_msg` for a regular user
 */
char *get_msg_user() {
    return "Hello, regular user!\n";
}

/** Typedef for our function pointers */
typedef char *(*get_msg_t)();

/**
 * Our selector for `get_msg`. Returns the right implementation based on the
 * current user ID.
 */
static get_msg_t resolve_get_msg() {
    int uid;

    // Make a `getuid` syscall. It has no parameters, and returns in the %rax
    // register.
    __asm__(
        " \
        mov     $102, %%rax \n\t\
        syscall \n\t\
        mov     %%eax, %[uid]"
        : [uid] "=r" (uid)
        : // No outputs
    );

    if (uid == 0) {
        // UID 0 is root
        return get_msg_root;
    } else {
        // Otherwise, it's a regular user
        return get_msg_user;
    }
}

/**
 * Displays a user-specific message using the GCC-specific `ifunc` attribute.
 */
char *get_msg() __attribute__ ((ifunc ("resolve_get_msg")));

int main() {
    ftl_print(get_msg());
    return 0;
}

void _start() {
    ftl_exit(main());
}
