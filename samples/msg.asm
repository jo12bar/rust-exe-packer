; NASM's syntax for exporting global is a bit funky,
; but everything has a purpose.

        ; here we declare `msg` as a global, and we say it's of type
        ; `data` (as opposed to `function`). We also have to specify
        ; its length, which is `end-start`.
        global msg:data msg.end-msg

        ; We only have a data section for this file
        section .data

; `msg` is a label:
msg:    db "this is way longer than sixteen bytes", 10
        ; local label that belongs to `msg`  and can be referred to using `msg.end`:
        .end:
