// ╺┳╸┏━┓┏━┓╺┳╸╻ ╻┏━┓┏━╸
//  ┃ ┃ ┃┣┳┛ ┃ ┃ ┃┣┳┛┣╸
//  ╹ ┗━┛╹┗╸ ╹ ┗━┛╹┗╸┗━╸

void jmb_exit(int code) {
    __asm__(
        " \
        mov %[code], %%edi \n\
        mov $60, %%rax \n\
        syscall"
        :
        : [code] "r" (code)
    );
}

extern int number;
extern void change_number(void);

void _start(void) {
    change_number();
    change_number();
    change_number();
    jmb_exit(number);
}
