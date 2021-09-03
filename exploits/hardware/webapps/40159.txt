Compal CH7465LG-LC modem/router multiple vulnerabilities
--------------------------------------------------------

The following vulnerabilities are the result of a quick check (~3 hours)
of the Mercury modem. We performed a systematic and deeper evaluation of
this device also, which result will be described in a separate report [2] and advisory.

Platforms / Firmware confirmed affected:
- Compal CH7465LG-LC, CH7465LG-NCIP-4.50.18.13-NOSH

Vulnerabilities
---------------
Insecure session management

The web interface uses cookies, but is not verified. Thus, if admin
login is successful, the IP address and the browser type of the admin
user are stored and everybody can access the management interface with
the same IP and the same user-agent.

Information leakage

Some information requests can be performed without authentication. For
example an attacker can obtain the following information pieces:
-    Global settings (SW version, vendor name, etc.)
-    CSRF token
-    Event log
-    LAN user table
-    Ping response

Unauthenticated deny of service attack

Factory reset can be initiated without authentication with a simple POST
request to the getter.xml.

Unauthenticated configuration changes
Some settings modification can be performed without authentication, for
example the first install flag and the ping command.

Unauthenticated command injection

The ping diagnostic function is vulnerable to system command injection,
because parameters are checked only at the client side. Using the
following ping target, the attacker can gain local root access to the
device:

“token=<csrf_token>&fun=126&Type=0&Target_IP=127.0.0.1&Ping_Size=64;nc
-l -p 1337 -e /bin/sh;&Num_Ping=3&Ping_Interval=1”

Timeline
--------
- 2015.10.21: SEARCH-LAB received two sample boxes from the Compal Mercury devices from UPC Magyarorszag
- 2015.10.21: Within three hours we reported a remotely exploitable vulnerability on the device
- 2015.10.21: Liberty Global asked for a commercial proposal on executing an overall security evaluation of the Compal device.
- 2015.10.24: A proposal was sent to Liberty Global.
- 2015.11.09: Liberty Global asked to execute the evaluation as a pilot project without financial compensation.
- 2015.12.07: End Use Certificate for Dual-Use Items was asked from Liberty Global as the developer of the device is located in China.
- 2016.01.07: The 99-page-long Evaluation Report on Compal Mercury modem was sent to Liberty Global with the restriction that they are not allowed to forward it outside of the European Union until a signed End Use Certificate is received.
- 2016.01.07: First reaction to the report said: “Bloody hell, that is not a small document ;)”
- 2016.01.11: Liberty Global sent the signed End Use Certificate for Dual-Use Items to SEARCH-LAB
- 2016.01.27: UPC Magyarorszag send out a repeated warning to its end users about the importance of the change of the default passphrases.
- 2016.02.16: Face to face meeting with Liberty Global security personnel in Amsterdam headquarters
- 2016.02.18: A proposal was sent to Liberty Global suggesting a wardriving experiment in Budapest, Hungary to measure the rate of end users who are still using the default passphrases.

Recommendations
---------------
We do not know about any possible solution. Firmware update should install the ISP after the fix will be ready.

Credits
-------
This vulnerability was discovered and researched by Gergely Eberhardt from SEARCH-LAB Ltd. (www.search-lab.hu)

References
----------
[1] http://www.search-lab.hu/advisories/secadv-20160720
[2] http://www.search-lab.hu/media/Compal_CH7465LG_Evaluation_Report_1.1.pdf