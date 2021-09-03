Multiple D-­Link routers suffer from insecure implementations of the Home Network Administration
Protocol which allow un­authenticated and/or un­privileged users to view and configure administrative
settings on the router.

Further, the mere existence of HNAP allows attackers to completely bypass the CAPTCHA login
features that D-­Link has made available in recent firmware releases.

It is suspected that most, if not all, D­-Link routers manufactured since 2006 have HNAP support and
are vulnerable to one of the below described vulnerabilities. However, only the following routers and
firmware versions have been confirmed to date:

         1) DI­524 hardware version C1, firmware version 3.23
         2) DIR­628 hardware version B2, firmware versions 1.20NA and 1.22NA
         3) DIR­655 hardware version A1, firmware version 1.30EA

Detailed description available here:
http://www.sourcesec.com/Lab/dlink_hnap_captcha.pdf

POC code available here: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/11101.tar.gz (hnap0wn.tar.gz)