    .global _start
    .text
_start:
    mov x0, #1
    adr x1, msg
    mov x2, #11
    mov x8, #64
    svc #0
    mov x0, #0
    mov x8, #93
    svc #0
    .data
msg:
    .ascii "qiling ok\n"
