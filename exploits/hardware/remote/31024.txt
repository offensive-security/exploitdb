source: https://www.securityfocus.com/bid/27272/info

F5 BIG-IP is prone to multiple cross-site scripting vulnerabilities because it fails to properly sanitize user-supplied input.

An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker to steal cookie-based authentication credentials and to launch other attacks.

BIG-IP firmware version 9.4.3 is vulnerable; other versions may also be affected.

https://www.example.com?SearchString=%22%20type=%22hidden%22%3E%3Cscript%3Ealert(%22list-xss%22)%3C/script%3E%3Cinput%20type=%22hidden%22%20value=%22