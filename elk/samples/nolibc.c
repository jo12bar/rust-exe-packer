// gcc -nostartfiles -nodefaultlibs nolibc.c -o nolibc

int _start() {
    __asm__(
        "movq $42,%rdi\n\t"
        "mov $60,%rax\n\t"
        "syscall"
    );
}
