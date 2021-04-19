;
; Various fake glibc stubbed functions.
;

; A fake _dl_addr implementation.
_dl_addr:
    ; Just return 0.
    xor rax, rax
    ret

; A fake exit implementation.
exit:
    ; Always exits with code 0.
    xor rdi, rdi
    mov rax, 60
    syscall
