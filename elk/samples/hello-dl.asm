        global _start
        extern msg

        section .text

_start: mov rdi, 1      ; stdout file descriptor
        mov rsi, msg
        mov rdx, 38     ; 37 chars + newline
        mov rax, 1      ; write syscall
        syscall

        xor rdi, rdi    ; return code 0
        mov rax, 60     ; exit syscall
        syscall
