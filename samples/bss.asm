        global _start

        section .text

_start: ; Load address of `zero`, for debugging purposes
        lea rax, [rel zero]

        ; then just exit
        xor rdi, rdi
        mov rax, 60
        syscall

        section .bss

; Reserves 16 64-bit values:
zero:   resq 16
