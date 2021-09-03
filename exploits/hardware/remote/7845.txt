Digital Security Research Group [DSecRG] Advisory       #DSECRG-09-004
AXIS 70U Network Document Server - Privilege Escalation and XSS

http://dsecrg.com/pages/vul/show.php?id=60


Application:                    AXIS 70U Network Document Server (Web Interface)
Versions Affected:              3.0
Vendor URL:                     http://www.axis.com/
Bug:                            Local File Include and Privilege Escalation, Multiple Linked XSS
Exploits:                       YES
Reported:                       20.10.2008
Vendor response:                20.10.2008
Last response:                  02.01.2009
Vendor Case ID:                 143027
Solution:                       NONE
Date of Public Advisory:        19.01.2009
Authors:                        Digital Security Research Group [DSecRG] (research [at] dsec [dot] ru)



Description
***********

Vulnerabilities found in Web Interface of device AXIS 70U Network Document Server.

1. Local File Include and Privilege Escalation.

Standard user can escalate privileges to administrator.

2. Multiple Linked XSS vulnerabilities



Details
*******

1. Local File Include and Privilege Escalation.

Local File Include vulnerability found in script user/help/help.shtml

User can unclude any local files even in admin folder.

Example:

http://[server]/user/help/help.shtml?/admin/this_server/this_server.shtml


2. Multiple Linked XSS vulnerabilities

Linked XSS vulnerability found in scripts:

user/help/help.shtml
user/help/general_help_user.shtml

Attacker can inject XSS script in URL.

Example:

http://[server]/user/help/help.shtml?<script>alert('DSecRG XSS')</script>
http://[server]/user/help/general_help_user.shtml?<script>alert('DSecRG XSS')</script>



Solution
********

Vendor decided that this vulnerability is not critical and there is no
patches for this firmware. But maybe  he will patch issues on the next firmware release


Vendore response:

[13.01.2009]: "We don't see any major vulnerability issues with the current firmware of Axis 70U but we will consider the mentioned issues on the next firmware release."



About
*****

Digital Security is leading IT security company in Russia, providing information security consulting, audit and penetration testing services, risk analysis and ISMS-related services and certification for ISO/IEC 27001:2005 and PCI DSS standards. Digital Security Research Group focuses on web application and database security problems with vulnerability reports, advisories and whitepapers posted regularly on our website.

Contact:    research [at] dsec [dot] ru
            http://www.dsecrg.com
            http://www.dsec.ru

# milw0rm.com [2009-01-21]