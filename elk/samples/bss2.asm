        global _start

        section .text

_start: lea rax, [rel zero]
        mov rax, [rax]

        xor rdi, rdi    ; return code 0
        mov rax, 60     ; exit syscall
        syscall

        section .bss

pad:    resq 65536
zero:   resq 16
