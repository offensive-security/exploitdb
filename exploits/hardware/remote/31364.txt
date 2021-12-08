source: https://www.securityfocus.com/bid/28151/info

F5 BIG-IP Web Management Interface is prone to a HTML-injection vulnerability because the web management interface fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected device. This may help the attacker steal cookie-based authentication credentials and launch other attacks.

The vulnerability affects F5 BIG-IP 9.4.3; other versions may be also affected.

https://(target)/dms/policy/rep_request.php?report_type=%22%3E%3Cbody+onload=alert(%26quot%3BXSS%26quot%3B)%3E%3Cfoo+